//! Web-portal / CLI **surface parity** — the machine-checked assertion, driven
//! entirely off the REAL surface inventory this crate emits, that every CLI
//! action pillar serves has an equivalent portal (HTTP-route) counterpart and
//! vice versa.
//!
//! This is NOT a hand-maintained checklist of "the portal should do X": it
//! reads the SAME live registries the rest of this crate emits from
//! ([`pillar_cli::cli_surface::verb_table`] and
//! [`pillar_cli::web_serve::http_routes`], via [`crate::cli_verb_entries`] /
//! [`crate::http_route_entries`]) and pairs them through ONE declarative
//! [`PARITY_MAP`]. A parity gap is therefore a REAL detected diff — a CLI verb
//! or an HTTP route that currently exists in the served tables but has no
//! declared, present counterpart — never a checklist that silently rots as the
//! surfaces evolve. The RED/GREEN contract:
//!
//! * RED — [`parity_gaps`] returns a non-empty list — iff some served CLI verb
//!   has no portal counterpart (or its declared counterpart route is absent),
//!   OR some served portal route family has no CLI counterpart (or its declared
//!   counterpart verb is absent), OR the map itself references a surface that is
//!   no longer served (a stale mapping).
//! * GREEN — [`parity_gaps`] is empty — iff every served CLI verb and every
//!   served portal route family pairs, by construction, against a counterpart
//!   that is ALSO currently served (or is explicitly, with a recorded reason,
//!   declared to have no counterpart on the other surface).
//!
//! Because the map pairs against LIVE tables, adding a new CLI verb without a
//! portal route (or a portal route without a CLI verb, or without recording it
//! as intentionally single-surface) turns the check RED automatically — exactly
//! the "a parity gap is a real detected diff, not a hand-maintained checklist"
//! the `pillar-integration` portal-cli-parity scenario asserts against a real
//! running node.

use crate::{cli_verb_entries, http_route_entries, SurfaceEntry, SurfaceKind};

/// Which surface(s) a [`ParityRule`] pairs, and — for a surface deliberately
/// served on only ONE side — WHY it has no counterpart on the other. Every
/// rule names its CLI verb and/or its portal route family; a
/// single-surface rule records a human reason so a reviewer can judge that the
/// asymmetry is intentional (a purely-local CLI tool, or a machine-only portal
/// endpoint) rather than a real missing feature.
#[derive(Clone, Copy, Debug)]
pub enum ParityRule {
    /// A CLI verb and a portal route family that are counterparts: the CLI
    /// `verb` drives the same action the portal serves under the route-path
    /// `route_prefix` (matched against `http:<METHOD> <path>` entry ids by the
    /// path portion starting with `route_prefix`).
    Paired {
        /// The served CLI verb name (as it appears in `verb_table()`).
        verb: &'static str,
        /// The portal route-path prefix that is this verb's counterpart (e.g.
        /// `"/portal/identity"`). At least one served route's path must start
        /// with it, else the pairing is a stale/broken mapping (RED).
        route_prefix: &'static str,
    },
    /// A CLI verb with NO portal counterpart, by design — a purely local
    /// developer/operator tool that serves nothing over HTTP.
    CliOnly {
        /// The served CLI verb name.
        verb: &'static str,
        /// Why this verb has no portal route (recorded for reviewer judgement).
        reason: &'static str,
    },
    /// A portal route family with NO CLI counterpart, by design — a
    /// machine/browser-only endpoint with no operator CLI verb.
    PortalOnly {
        /// The portal route-path prefix (e.g. `"/nonce"`).
        route_prefix: &'static str,
        /// Why this route has no CLI verb.
        reason: &'static str,
    },
}

/// The single declarative parity map. Every rule pairs a real served CLI verb
/// with a real served portal route family, or records a deliberate
/// single-surface exception with a reason. [`parity_gaps`] cross-checks this
/// map against the LIVE served tables, so a served surface missing from this
/// map — or a mapped surface no longer served — is a detected gap.
pub static PARITY_MAP: &[ParityRule] = &[
    // --- paired CLI verb <-> portal route family ---------------------------
    ParityRule::Paired { verb: "surface-inventory", route_prefix: "/surface-inventory" },
    ParityRule::Paired { verb: "bootstrap", route_prefix: "/bootstrap" },
    ParityRule::Paired { verb: "webauthn", route_prefix: "/webauthn" },
    ParityRule::Paired { verb: "login", route_prefix: "/login" },
    ParityRule::Paired { verb: "session", route_prefix: "/portal/sessions" },
    ParityRule::Paired { verb: "identity", route_prefix: "/portal/identity" },
    ParityRule::Paired { verb: "user", route_prefix: "/portal/members" },
    ParityRule::Paired { verb: "domain", route_prefix: "/portal/domains" },
    ParityRule::Paired { verb: "attest", route_prefix: "/portal/attestations" },
    ParityRule::Paired { verb: "trust", route_prefix: "/portal/trust-graph" },
    ParityRule::Paired { verb: "obs", route_prefix: "/portal/obs" },
    ParityRule::Paired { verb: "key", route_prefix: "/portal/custody" },
    // The kubectl-parity resource plane: the CLI `apply`/`get`/`describe` verb
    // family (and the create/delete/patch/label/scale/diff verbs that route
    // through the SAME resource dispatch) is the counterpart of the whole
    // `/portal/resource/*` route family (get/describe/dry-run/logs/exec/
    // forward/replicas/apply/edit/scale/rollout/cronjob). One prefix pairs the
    // family; `get`/`describe` are additionally recorded CLI-only below since
    // the `apply` rule already claims the shared portal family.
    ParityRule::Paired { verb: "apply", route_prefix: "/portal/resource" },
    ParityRule::CliOnly {
        verb: "get",
        reason: "kubectl-parity resource read; served in the portal under the shared /portal/resource/* family (paired via `apply`)",
    },
    ParityRule::CliOnly {
        verb: "describe",
        reason: "kubectl-parity resource describe; served in the portal under the shared /portal/resource/* family (paired via `apply`)",
    },
    ParityRule::Paired { verb: "space", route_prefix: "/portal/topology" },
    ParityRule::Paired { verb: "request", route_prefix: "/bootstrap/request" },

    // --- CLI verbs deliberately without a portal route ---------------------
    ParityRule::CliOnly {
        verb: "--web",
        reason: "serves the portal itself (the HTTP surface); it is not a portal action",
    },
    ParityRule::CliOnly {
        verb: "node",
        reason: "boots the node process (`pillar node run`); a lifecycle command with no in-portal action",
    },
    ParityRule::CliOnly {
        verb: "offer",
        reason: "operational-key offer seal/resolve is a library/CLI custody surface; the portal exposes custody via /portal/custody, not raw offers",
    },
    ParityRule::CliOnly {
        verb: "grant",
        reason: "explicit grant add/rm/can-i is a CLI authorization surface; portal authorization is via /portal/attestations",
    },
    ParityRule::CliOnly {
        verb: "caps",
        reason: "effective-capability view is a CLI-only diagnostic; no dedicated portal endpoint",
    },
    ParityRule::CliOnly {
        verb: "revoke",
        reason: "authority-reducing acts are a CLI-only administrative surface today",
    },
    ParityRule::CliOnly {
        verb: "audit",
        reason: "proof-chain audit render is a CLI-only diagnostic surface",
    },
    ParityRule::CliOnly {
        verb: "cell",
        reason: "cell status/rotate is a CLI cluster surface; the portal creates cells via /bootstrap, not a cell-admin view",
    },
    ParityRule::CliOnly {
        verb: "peer",
        reason: "peer ls/dial/ping is a CLI cluster-diagnostic surface with no portal action",
    },
    ParityRule::CliOnly {
        verb: "lease",
        reason: "coordination lease admin is a CLI-only cluster surface",
    },
    ParityRule::CliOnly {
        verb: "stream",
        reason: "streamdb ls/tip/log/verify is a CLI data-plane surface with no portal action",
    },
    ParityRule::CliOnly {
        verb: "render",
        reason: "manifest text templating (helm/kustomize) is a purely local render helper",
    },
    ParityRule::CliOnly {
        verb: "onboard",
        reason: "the in-process keygen->trust->policy self-test rig; a local diagnostic, not a served action",
    },
    ParityRule::CliOnly {
        verb: "secrets-audit-rotation-mfa",
        reason: "an in-process seal/rotate/MFA self-test rig; a local diagnostic, not a served action",
    },
    ParityRule::CliOnly {
        verb: "explain",
        reason: "PSL query AST/plan explainer; a local developer tool",
    },
    ParityRule::CliOnly {
        verb: "completion",
        reason: "shell-completion script generator; a local developer tool",
    },

    // --- portal route families deliberately without a CLI verb -------------
    ParityRule::PortalOnly {
        route_prefix: "/nonce",
        reason: "the login-nonce challenge endpoint is a browser handshake step of `login`, not a standalone operator verb",
    },
    ParityRule::PortalOnly {
        route_prefix: "/portal/status",
        reason: "portal session/status probe consumed by the browser SPA; the CLI equivalent is `whoami`/`status` on `login`",
    },
    ParityRule::PortalOnly {
        route_prefix: "/portal/layout",
        reason: "per-user portal dashboard layout persistence; a browser-only UI-state endpoint",
    },
    ParityRule::PortalOnly {
        route_prefix: "/",
        reason: "the portal landing page (GET /) is the login HTML itself, not an operator action",
    },
];

/// A single detected parity gap: a served surface with no present counterpart,
/// or a mapping that no longer matches the served tables. Its [`Display`] is a
/// terse, greppable one-liner an external harness prints as a RED diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParityGap {
    /// A served CLI verb that no rule in [`PARITY_MAP`] covers.
    CliVerbUnmapped(String),
    /// A served portal route family that no rule in [`PARITY_MAP`] covers.
    PortalRouteUnmapped(String),
    /// A [`ParityRule::Paired`]/`CliOnly` verb the map names that is no longer
    /// in the served CLI table (a stale mapping).
    MappedVerbNotServed(String),
    /// A [`ParityRule::Paired`]/`PortalOnly` route prefix the map names that no
    /// served route path starts with (a stale mapping).
    MappedRouteNotServed(String),
}

impl core::fmt::Display for ParityGap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParityGap::CliVerbUnmapped(v) => write!(
                f,
                "parity-gap: CLI verb `{v}` has no portal counterpart (no rule pairs it and it is not recorded CLI-only)"
            ),
            ParityGap::PortalRouteUnmapped(p) => write!(
                f,
                "parity-gap: portal route `{p}` has no CLI counterpart (no rule pairs it and it is not recorded portal-only)"
            ),
            ParityGap::MappedVerbNotServed(v) => write!(
                f,
                "parity-gap: parity map names CLI verb `{v}` but it is not in the served verb table (stale mapping)"
            ),
            ParityGap::MappedRouteNotServed(p) => write!(
                f,
                "parity-gap: parity map names portal route prefix `{p}` but no served route path starts with it (stale mapping)"
            ),
        }
    }
}

/// The portal route-path of an `http:<METHOD> <path>` inventory entry — i.e.
/// the `<path>` after the method. Returns `None` for a non-HTTP entry.
fn route_path(entry: &SurfaceEntry) -> Option<&str> {
    if entry.kind != SurfaceKind::HttpRoute {
        return None;
    }
    // signature is "<METHOD> <path>"; split once on the first space.
    entry.signature.split_once(' ').map(|(_method, path)| path)
}

/// Does any served portal route path start with `prefix`? A `/` prefix matches
/// ONLY the exact landing path `/` (so it does not spuriously match every
/// route), every other prefix matches by `starts_with`.
fn any_route_under(routes: &[SurfaceEntry], prefix: &str) -> bool {
    routes.iter().any(|r| match route_path(r) {
        Some(path) if prefix == "/" => path == "/",
        Some(path) => path.starts_with(prefix),
        None => false,
    })
}

/// Compute the parity gaps between the CURRENTLY-served CLI verb table and
/// portal route table, driven off [`PARITY_MAP`]. An empty result is GREEN;
/// any element is a RED, human-readable detected diff. This is the core the
/// portal-cli-parity scenario and the acceptance test both assert on.
#[must_use]
pub fn parity_gaps() -> Vec<ParityGap> {
    parity_gaps_of(&cli_verb_entries(), &http_route_entries())
}

/// Like [`parity_gaps`], but over caller-supplied CLI-verb and HTTP-route
/// inventory slices — so a test can feed a reduced/augmented table and prove
/// the detector reacts (RED on an injected gap), exactly as the emitter tests
/// prove the inventory reflects the registry it is given.
#[must_use]
pub fn parity_gaps_of(cli: &[SurfaceEntry], routes: &[SurfaceEntry]) -> Vec<ParityGap> {
    let mut gaps = Vec::new();

    // 1. Every mapping the map declares must still match the served tables.
    for rule in PARITY_MAP {
        match rule {
            ParityRule::Paired { verb, route_prefix } => {
                if !cli.iter().any(|e| e.id == format!("cli:{verb}")) {
                    gaps.push(ParityGap::MappedVerbNotServed((*verb).to_owned()));
                }
                if !any_route_under(routes, route_prefix) {
                    gaps.push(ParityGap::MappedRouteNotServed((*route_prefix).to_owned()));
                }
            }
            ParityRule::CliOnly { verb, .. } => {
                if !cli.iter().any(|e| e.id == format!("cli:{verb}")) {
                    gaps.push(ParityGap::MappedVerbNotServed((*verb).to_owned()));
                }
            }
            ParityRule::PortalOnly { route_prefix, .. } => {
                if !any_route_under(routes, route_prefix) {
                    gaps.push(ParityGap::MappedRouteNotServed((*route_prefix).to_owned()));
                }
            }
        }
    }

    // 2. Every served CLI verb must be covered by some rule (paired or
    //    recorded CLI-only) — else it is an unmapped verb (a CLI action with
    //    no declared portal counterpart).
    for entry in cli {
        if entry.kind != SurfaceKind::CliVerb {
            continue;
        }
        let verb = entry.id.strip_prefix("cli:").unwrap_or(&entry.id);
        let covered = PARITY_MAP.iter().any(|rule| match rule {
            ParityRule::Paired { verb: v, .. } | ParityRule::CliOnly { verb: v, .. } => *v == verb,
            ParityRule::PortalOnly { .. } => false,
        });
        if !covered {
            gaps.push(ParityGap::CliVerbUnmapped(verb.to_owned()));
        }
    }

    // 3. Every served portal route must be covered by some rule (paired or
    //    recorded portal-only) — else it is an unmapped route (a portal action
    //    with no declared CLI counterpart).
    for entry in routes {
        let Some(path) = route_path(entry) else {
            continue;
        };
        let covered = PARITY_MAP.iter().any(|rule| match rule {
            ParityRule::Paired { route_prefix, .. }
            | ParityRule::PortalOnly { route_prefix, .. } => {
                if *route_prefix == "/" {
                    path == "/"
                } else {
                    path.starts_with(route_prefix)
                }
            }
            ParityRule::CliOnly { .. } => false,
        });
        if !covered {
            gaps.push(ParityGap::PortalRouteUnmapped(path.to_owned()));
        }
    }

    gaps
}

/// `true` iff [`parity_gaps`] is empty — the GREEN condition.
#[must_use]
pub fn parity_holds() -> bool {
    parity_gaps().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_is_green_against_the_real_served_surfaces() {
        let gaps = parity_gaps();
        assert!(
            gaps.is_empty(),
            "expected GREEN parity, found gaps: {}",
            gaps.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
        assert!(parity_holds());
    }

    #[test]
    fn an_added_cli_verb_without_a_route_is_a_gap() {
        let mut cli = cli_verb_entries();
        cli.push(SurfaceEntry {
            id: "cli:frobnicate".to_owned(),
            kind: SurfaceKind::CliVerb,
            signature: "pillar frobnicate".to_owned(),
        });
        let gaps = parity_gaps_of(&cli, &http_route_entries());
        assert!(gaps.contains(&ParityGap::CliVerbUnmapped("frobnicate".to_owned())));
    }

    #[test]
    fn an_added_route_without_a_verb_is_a_gap() {
        let mut routes = http_route_entries();
        routes.push(SurfaceEntry {
            id: "http:GET /zzz-orphan".to_owned(),
            kind: SurfaceKind::HttpRoute,
            signature: "GET /zzz-orphan".to_owned(),
        });
        let gaps = parity_gaps_of(&cli_verb_entries(), &routes);
        assert!(gaps.contains(&ParityGap::PortalRouteUnmapped("/zzz-orphan".to_owned())));
    }

    #[test]
    fn a_stale_mapping_is_a_gap() {
        // An empty CLI table makes every mapped verb "not served".
        let gaps = parity_gaps_of(&[], &http_route_entries());
        assert!(gaps
            .iter()
            .any(|g| matches!(g, ParityGap::MappedVerbNotServed(_))));
    }
}
