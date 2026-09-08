//! Server-fed drilldown (Phase 4b) — mounts the previously-orphaned
//! [`crate::drilldown::DrilldownPanel`] with REAL data from the node instead of
//! a browser-side store the portal does not have.
//!
//! The correlate join is already served: `POST /portal/obs/live/query` runs
//! `psl_correlate` over the live store and emits, alongside the matched
//! `SIGNAL <id> KIND <kind> PAYLOAD …` lines, one `GROUP <anchor> MEMBERS
//! <id,id,…>` line per correlated anchor. This module parses that response and
//! reconstructs a [`Drilldown`] per anchor — resolving each member's kind from
//! the `SIGNAL` lines and its content address from the hex id — so the existing
//! panel renders the node's real correlated logs/traces/profiles/metadata. No
//! client-side fabrication, no stub, no redundant endpoint.

use crate::drilldown::{Drilldown, DRILLDOWN_ANCHOR_KIND};
use pillar_observability::{SignalId, SignalKind};
use std::collections::BTreeMap;

/// Map a wire kind tag (the exact strings `signal_kind_tag` emits) back to a
/// [`SignalKind`]. Unknown tags yield `None` rather than a fabricated default.
#[must_use]
pub fn kind_from_tag(tag: &str) -> Option<SignalKind> {
    match tag {
        "metric" => Some(SignalKind::Metric),
        "log" => Some(SignalKind::Log),
        "trace" => Some(SignalKind::TraceSpan),
        "profile" => Some(SignalKind::ProfileSample),
        "metadata" => Some(SignalKind::MetadataSample),
        _ => None,
    }
}

/// The two things a drilldown needs out of a `live/query` response: the
/// id-hex → kind map (from `SIGNAL` lines) and the `(anchor, members)` groups
/// (from `GROUP` lines), both by hex id.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CorrelateResponse {
    /// Every returned signal's content-address hex → its kind.
    pub kinds: BTreeMap<String, SignalKind>,
    /// One `(anchor_hex, member_hexes)` per correlate group.
    pub groups: Vec<(String, Vec<String>)>,
}

/// Parse a `POST /portal/obs/live/query` response body into a
/// [`CorrelateResponse`]. `SIGNAL <id> KIND <tag> PAYLOAD <payload>` lines
/// populate the kind map (payload ignored); `GROUP <anchor> MEMBERS <a,b,c>`
/// lines populate the groups. Malformed lines are skipped.
#[must_use]
pub fn parse_correlate_response(body: &str) -> CorrelateResponse {
    let mut resp = CorrelateResponse::default();
    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("SIGNAL ") {
            // `<id> KIND <tag> [TICK <n> LABELS <k=v;…>] PAYLOAD <payload>` — the
            // kind tag is the first whitespace token after `KIND `, so this
            // tolerates the optional TICK/LABELS fields between the tag and the
            // payload without mistaking them for part of the tag.
            let Some((id, after)) = rest.split_once(" KIND ") else {
                continue;
            };
            let tag = after.split_whitespace().next().unwrap_or("").trim();
            if let Some(kind) = kind_from_tag(tag) {
                resp.kinds.insert(id.trim().to_owned(), kind);
            }
        } else if let Some(rest) = line.strip_prefix("GROUP ") {
            // `<anchor> MEMBERS <a,b,c>`
            let Some((anchor, members)) = rest.split_once(" MEMBERS ") else {
                continue;
            };
            let member_ids: Vec<String> = members
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            resp.groups.push((anchor.trim().to_owned(), member_ids));
        }
    }
    resp
}

/// Reconstruct one [`Drilldown`] per correlate group. A member is included only
/// when its kind is known (present in the `SIGNAL` lines) AND is a real
/// drilldown target — the anchor kind ([`DRILLDOWN_ANCHOR_KIND`], metrics) is
/// excluded, exactly as the server-side `drilldown_from` join does. An anchor
/// whose hex is not a valid content address, or that has no qualifying members,
/// yields no drilldown (never a fabricated placeholder).
#[must_use]
pub fn build_drilldowns(resp: &CorrelateResponse) -> Vec<Drilldown> {
    let mut out = Vec::new();
    for (anchor_hex, members) in &resp.groups {
        let Some(anchor) = SignalId::from_hex(anchor_hex) else {
            continue;
        };
        let mut by_kind: BTreeMap<SignalKind, Vec<SignalId>> = BTreeMap::new();
        for member_hex in members {
            let Some(kind) = resp.kinds.get(member_hex).copied() else {
                continue; // kind unknown → cannot place it honestly
            };
            if kind == DRILLDOWN_ANCHOR_KIND {
                continue; // drill OUT to the other kinds, never back to metrics
            }
            let Some(id) = SignalId::from_hex(member_hex) else {
                continue;
            };
            by_kind.entry(kind).or_default().push(id);
        }
        if by_kind.is_empty() {
            continue; // no correlated peer of a target kind → no drilldown
        }
        out.push(Drilldown { anchor, by_kind });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // A valid even-length lowercase-hex content address per seed (SignalId's
    // from_hex accepts any even-length hex; distinct seeds → distinct ids).
    fn hex(seed: u64) -> String {
        format!("{seed:064x}")
    }

    #[test]
    fn kind_tags_round_trip_the_wire_strings() {
        assert_eq!(kind_from_tag("metric"), Some(SignalKind::Metric));
        assert_eq!(kind_from_tag("log"), Some(SignalKind::Log));
        assert_eq!(kind_from_tag("trace"), Some(SignalKind::TraceSpan));
        assert_eq!(kind_from_tag("profile"), Some(SignalKind::ProfileSample));
        assert_eq!(kind_from_tag("metadata"), Some(SignalKind::MetadataSample));
        assert_eq!(kind_from_tag("bogus"), None);
    }

    #[test]
    fn parse_reads_signal_kinds_and_groups() {
        let a = hex(1);
        let l = hex(2);
        let body = format!(
            "SIGNAL {a} KIND metric PAYLOAD cpu spike\n\
             SIGNAL {l} KIND log PAYLOAD oom killed\n\
             GROUP {a} MEMBERS {l}\n"
        );
        let resp = parse_correlate_response(&body);
        assert_eq!(resp.kinds.get(&a), Some(&SignalKind::Metric));
        assert_eq!(resp.kinds.get(&l), Some(&SignalKind::Log));
        assert_eq!(resp.groups, vec![(a, vec![l])]);
    }

    #[test]
    fn build_excludes_metric_anchor_and_unknown_members() {
        let a = hex(10); // metric anchor
        let log = hex(11);
        let metric_peer = hex(12);
        let unknown = hex(13);
        let body = format!(
            "SIGNAL {a} KIND metric PAYLOAD spike\n\
             SIGNAL {log} KIND log PAYLOAD err\n\
             SIGNAL {metric_peer} KIND metric PAYLOAD other-metric\n\
             GROUP {a} MEMBERS {log},{metric_peer},{unknown}\n"
        );
        let resp = parse_correlate_response(&body);
        let drills = build_drilldowns(&resp);
        assert_eq!(drills.len(), 1);
        // the log peer is the only qualifying drilldown target.
        assert_eq!(drills[0].kind(SignalKind::Log).len(), 1);
        // the metric peer is excluded (anchor kind), the unknown-kind id too.
        assert!(drills[0].kind(SignalKind::Metric).is_empty());
        assert_eq!(drills[0].by_kind.values().map(Vec::len).sum::<usize>(), 1);
    }

    #[test]
    fn group_with_no_target_members_yields_no_drilldown() {
        let a = hex(20);
        let m = hex(21);
        let body = format!(
            "SIGNAL {a} KIND metric PAYLOAD x\n\
             SIGNAL {m} KIND metric PAYLOAD y\n\
             GROUP {a} MEMBERS {m}\n"
        );
        let drills = build_drilldowns(&parse_correlate_response(&body));
        assert!(drills.is_empty());
    }

    #[test]
    fn invalid_anchor_hex_is_skipped_not_fabricated() {
        let log = hex(30);
        let body = format!("SIGNAL {log} KIND log PAYLOAD e\nGROUP not-hex MEMBERS {log}\n");
        assert!(build_drilldowns(&parse_correlate_response(&body)).is_empty());
    }
}
