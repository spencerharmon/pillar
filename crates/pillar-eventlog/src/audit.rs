//! Tamper-evident, signed AUDIT VIEW — a first-class MATERIALIZED VIEW over the
//! append-only, ed25519-signed event log (ROI P0 "synergy everywhere",
//! security & availability, Tier 2).
//!
//! "Who did what, when, to what" is not a separate, bespoke store: it is a pure
//! projection of the SAME [`EventLog`] the rest of Pillar already replicates,
//! signs, and gap-fills. Each audit-bearing event's payload is a canonically
//! serialized [`AuditRecord`] (actor, action, timestamp, target); the view
//! ([`EventLog::audit_view`]) materializes those records IN the log's own
//! deterministic causal order (per-author sequence, authors interleaved by
//! their content-addressed tip order — the same order two converged replicas
//! agree on), so every replica renders the identical audit trail.
//!
//! Tamper-evidence is inherited from the log, NOT re-invented: an entry is
//! surfaced as [`AuditEntry::Verified`] ONLY when its event's real ed25519
//! signature ([`crate::Signature::verifies`]) covers its content. An event
//! whose signature does not verify — a forged signature, or a payload/link
//! rewritten after signing — is surfaced as [`AuditEntry::Rejected`] and is
//! NEVER rendered as a legitimate audit line. So a forged or tampered "log
//! entry" cannot masquerade as a real one: the audit view exposes it as
//! rejected, exactly as the ingest path would refuse it.
//!
//! Because the projection reuses the log's existing content-addressed,
//! materialized-view mechanism (the events are the durable, replicated store;
//! the view is a deterministic function of them), there is no separate audit
//! blob store to persist, snapshot, or reconcile.

use serde::{Deserialize, Serialize};

use crate::{Author, EventId, EventLog};

/// One audit fact carried in an event's payload: WHO ([`Self::actor`]) did WHAT
/// ([`Self::action`]) WHEN ([`Self::timestamp`]) to WHICH target
/// ([`Self::target`]).
///
/// The record is the event PAYLOAD, so it is inside the signed, hashed
/// [`crate::EventContent`]: rewriting any field after signing breaks the
/// event's ed25519 signature and the audit view surfaces the entry as
/// [`AuditEntry::Rejected`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// The subject that performed the action (a user / service identity).
    pub actor: String,
    /// The action performed (a verb / operation name).
    pub action: String,
    /// A logical timestamp of the action (e.g. unix millis). Its meaning is the
    /// caller's; the view preserves and orders by the log's causal order, not
    /// this field, so a forged timestamp cannot reorder the trail.
    pub timestamp: u64,
    /// The object the action was performed on (a resource / target id).
    pub target: String,
}

impl AuditRecord {
    /// Construct an audit record.
    #[must_use]
    pub fn new(
        actor: impl Into<String>,
        action: impl Into<String>,
        timestamp: u64,
        target: impl Into<String>,
    ) -> Self {
        AuditRecord {
            actor: actor.into(),
            action: action.into(),
            timestamp,
            target: target.into(),
        }
    }

    /// The canonical, deterministic payload bytes for this record — what an
    /// event's payload must be for the audit view to surface it. Stable across
    /// runs/platforms so two replicas agree on both the event's content address
    /// and the decoded record.
    #[must_use]
    pub fn to_payload(&self) -> Vec<u8> {
        // A fixed field order with length-prefixed strings — canonical and
        // dependency-free (no serde-format ambiguity), so the payload bytes are
        // reproducible and thus content-address-stable.
        let mut b = Vec::new();
        for s in [&self.actor, &self.action, &self.target] {
            b.extend_from_slice(&(s.len() as u64).to_le_bytes());
            b.extend_from_slice(s.as_bytes());
        }
        b.extend_from_slice(&self.timestamp.to_le_bytes());
        b
    }

    /// Decode a record from an event payload produced by [`Self::to_payload`],
    /// or `None` if the payload is not a well-formed audit record (a non-audit
    /// event, or a truncated/garbage payload).
    #[must_use]
    pub fn from_payload(bytes: &[u8]) -> Option<Self> {
        fn take_str(bytes: &[u8], off: &mut usize) -> Option<String> {
            let len_end = off.checked_add(8)?;
            let len = u64::from_le_bytes(bytes.get(*off..len_end)?.try_into().ok()?) as usize;
            let s_end = len_end.checked_add(len)?;
            let s = std::str::from_utf8(bytes.get(len_end..s_end)?)
                .ok()?
                .to_string();
            *off = s_end;
            Some(s)
        }
        let mut off = 0usize;
        let actor = take_str(bytes, &mut off)?;
        let action = take_str(bytes, &mut off)?;
        let target = take_str(bytes, &mut off)?;
        let ts_end = off.checked_add(8)?;
        let timestamp = u64::from_le_bytes(bytes.get(off..ts_end)?.try_into().ok()?);
        // Reject trailing garbage: a canonical payload is consumed exactly.
        if ts_end != bytes.len() {
            return None;
        }
        Some(AuditRecord {
            actor,
            action,
            timestamp,
            target,
        })
    }
}

/// One row of the materialized audit view: either a signature-VERIFIED audit
/// record, or a REJECTED event that claimed to be one but whose signature does
/// not authenticate its content (forged/tampered).
///
/// A rejected entry is deliberately surfaced (not silently dropped) so the
/// trail is auditable end to end — a consumer can SEE that a forged/tampered
/// entry was present and refused, rather than it vanishing. It is never
/// rendered as a legitimate ([`Self::Verified`]) line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditEntry {
    /// A legitimate audit fact: its event's ed25519 signature verifies its
    /// content, so this is authentic "who did what, when."
    Verified {
        /// The content-addressed id of the underlying event.
        event: EventId,
        /// The authenticated author of the event.
        author: Author,
        /// The decoded, authenticated audit record.
        record: AuditRecord,
    },
    /// An event that FAILED authentication (forged signature, or content
    /// rewritten after signing) — flagged, never surfaced as legitimate.
    Rejected {
        /// The content-addressed id of the underlying (rejected) event.
        event: EventId,
        /// The author the event claimed.
        author: Author,
    },
}

impl AuditEntry {
    /// The authenticated audit record if this entry is [`Self::Verified`],
    /// else `None`.
    #[must_use]
    pub fn verified(&self) -> Option<&AuditRecord> {
        match self {
            AuditEntry::Verified { record, .. } => Some(record),
            AuditEntry::Rejected { .. } => None,
        }
    }

    /// Whether this entry authenticated.
    #[must_use]
        pub fn is_verified(&self) -> bool {
        matches!(self, AuditEntry::Verified { .. })
    }

    /// The content-addressed id of the underlying event.
    #[must_use]
    pub fn event(&self) -> &EventId {
        match self {
            AuditEntry::Verified { event, .. } | AuditEntry::Rejected { event, .. } => event,
        }
    }
}

impl EventLog {
    /// The materialized AUDIT VIEW over this log: every audit-bearing event, in
    /// the log's own deterministic causal order (per author by ascending
    /// sequence; authors interleaved by their tip's content-addressed order),
    /// projected to an [`AuditEntry`].
    ///
    /// Only events whose payload decodes as an [`AuditRecord`] appear. Each such
    /// event's real ed25519 signature is re-verified against its content: it is
    /// surfaced [`AuditEntry::Verified`] iff it authenticates, else
    /// [`AuditEntry::Rejected`] — so a forged/tampered entry is detected and
    /// flagged rather than rendered as legitimate.
    ///
    /// The order is stable and replica-independent: it is derived purely from
    /// the content-addressed log, so two converged replicas produce the
    /// identical view.
    #[must_use]
    pub fn audit_view(&self) -> Vec<AuditEntry> {
        let mut out = Vec::new();
        // Deterministic order: iterate authors in Author (name) order, each
        // chain by ascending seq. `NoGaps` guarantees a contiguous 0..height
        // per author, so this visits every held event exactly once, stably.
        let mut authors: Vec<Author> = self.chain_authors();
        authors.sort();
        for author in &authors {
            let height = self.chain_height(author);
            for seq in 0..height {
                let Some(event) = self.event_at(author, seq) else {
                    continue;
                };
                let Some(record) = AuditRecord::from_payload(event.content().payload()) else {
                    // Not an audit event — skip.
                    continue;
                };
                let id = event.id();
                let ev_author = event.content().author().clone();
                if event.is_authentic() {
                    out.push(AuditEntry::Verified {
                        event: id,
                        author: ev_author,
                        record,
                    });
                } else {
                    out.push(AuditEntry::Rejected {
                        event: id,
                        author: ev_author,
                    });
                }
            }
        }
        out
    }

    /// The verified-only audit trail: [`Self::audit_view`] with every
    /// [`AuditEntry::Rejected`] excluded — the legitimate "who did what, when"
    /// lines alone, in causal order.
    #[must_use]
    pub fn audit_trail(&self) -> Vec<AuditEntry> {
        self.audit_view()
            .into_iter()
            .filter(AuditEntry::is_verified)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, EventContent, Signature};

    fn author(name: &str) -> Author {
        Author(name.to_string())
    }

    fn audit_payload(actor: &str, action: &str, ts: u64, target: &str) -> Vec<u8> {
        AuditRecord::new(actor, action, ts, target).to_payload()
    }

    /// The audit view surfaces EVERY signed event as a verified audit line —
    /// actor, action, timestamp, target — from a real multi-author eventlog
    /// fixture, in the log's deterministic causal order.
    #[test]
    fn audit_view_surfaces_every_signed_event_in_order() {
        let alice = author("alice");
        let bob = author("bob");
        let mut log = EventLog::new();

        // A real fixture: two authors each appending signed audit events.
        log.append(&alice, audit_payload("alice", "login", 1, "session-1"));
        log.append(&bob, audit_payload("bob", "create", 2, "resource-x"));
        log.append(&alice, audit_payload("alice", "delete", 3, "resource-x"));

        let view = log.audit_view();
        assert_eq!(view.len(), 3, "every audit event must be surfaced");
        assert!(
            view.iter().all(AuditEntry::is_verified),
            "every genuinely signed event must verify"
        );

        // Each field round-trips exactly.
        let records: Vec<&AuditRecord> = view.iter().filter_map(AuditEntry::verified).collect();
        assert!(records
            .iter()
            .any(|r| **r == AuditRecord::new("alice", "login", 1, "session-1")));
        assert!(records
            .iter()
            .any(|r| **r == AuditRecord::new("bob", "create", 2, "resource-x")));
        assert!(records
            .iter()
            .any(|r| **r == AuditRecord::new("alice", "delete", 3, "resource-x")));

        // Deterministic order: authors by name, each chain by ascending seq.
        // alice's two events precede in relative order (login before delete);
        // bob's single event appears once.
        let alice_actions: Vec<&str> = view
            .iter()
            .filter_map(AuditEntry::verified)
            .filter(|r| r.actor == "alice")
            .map(|r| r.action.as_str())
            .collect();
        assert_eq!(
            alice_actions,
            vec!["login", "delete"],
            "an author's audit lines appear in chain (seq) order"
        );

        // Rebuilding the view is stable (same order twice).
        assert_eq!(log.audit_view(), view);
    }

    /// A tampered / forged event entry is DETECTED and excluded from the
    /// legitimate trail (surfaced as Rejected in the full view), rather than
    /// silently rendered as a real audit line — exercising the REAL ed25519
    /// signature check, not a stand-in.
    #[test]
    fn forged_entry_is_flagged_not_rendered_as_legitimate() {
        let alice = author("alice");
        let mallory = author("mallory");
        let mut log = EventLog::new();

        // A genuine audit event.
        log.append(&alice, audit_payload("alice", "login", 1, "session-1"));

        // Forge #1: a well-formed audit payload, "signed" by a DIFFERENT key
        // (mallory) but relabelled as alice — the classic impersonation. The
        // content id is genuine, but the signature is not alice's.
        let content = EventContent {
            author: alice.clone(),
            seq: 1,
            prev: log.tip(&alice),
            parents: Default::default(),
            payload: audit_payload("alice", "escalate-privilege", 999, "root"),
        };
        let forged_sig = Signature::sign(&mallory, &content);
        let forged = Event::stamped(
            content.clone(),
            Signature {
                author: alice.clone(),
                signature: forged_sig.signature,
            },
        );
        // Sanity: the log's own ingest would refuse it.
        assert!(!forged.is_authentic());

        // Forge #2: tamper the payload of a genuinely-signed event AFTER
        // signing (rewrite the target), keeping the original signature.
        let genuine = EventContent {
            author: alice.clone(),
            seq: 2,
            prev: log.tip(&alice),
            parents: Default::default(),
            payload: audit_payload("alice", "read", 5, "public-doc"),
        };
        let sig = Signature::sign(&alice, &genuine);
        let mut tampered = Event::stamped(genuine, sig);
        tampered.content.payload = audit_payload("alice", "read", 5, "secret-doc");
        assert!(!tampered.is_authentic());

        // Build a fixture log that HOLDS the forged/tampered events so the view
        // must judge them. We construct the view over a log whose events map
        // directly includes them (bypassing ingest, which would reject — the
        // point is that even if a forged event slips into a replica's store,
        // the audit view still refuses to render it as legitimate).
        let mut fixture = EventLog::new();
        let g = fixture.append(&alice, audit_payload("alice", "login", 1, "session-1"));
        fixture.insert_unchecked_for_test(forged.clone());
        fixture.insert_unchecked_for_test(tampered.clone());

        let view = fixture.audit_view();

        // The genuine login is verified.
        assert!(view.iter().any(|e| matches!(
            e,
            AuditEntry::Verified { record, .. }
            if *record == AuditRecord::new("alice", "login", 1, "session-1")
        )));
        assert!(view.iter().any(|e| e.event() == &g && e.is_verified()));

        // Neither forgery is ever surfaced as a legitimate (Verified) record.
        assert!(
            view.iter().filter_map(AuditEntry::verified).all(|r| {
                r.action != "escalate-privilege" && r.target != "secret-doc"
            }),
            "a forged/tampered entry must NOT be rendered as a legitimate audit line"
        );

        // They ARE surfaced as Rejected (detected, flagged) — not silently
        // dropped.
        let rejected = view.iter().filter(|e| !e.is_verified()).count();
        assert_eq!(rejected, 2, "both forgeries must be detected and flagged");

        // The verified-only trail excludes every rejected entry entirely.
        let trail = fixture.audit_trail();
        assert!(trail.iter().all(AuditEntry::is_verified));
        assert!(trail
            .iter()
            .filter_map(AuditEntry::verified)
            .all(|r| r.action != "escalate-privilege" && r.target != "secret-doc"));
    }

    /// Non-audit events (payloads that are not audit records) are simply not
    /// projected into the view — the view is a clean audit projection.
    #[test]
    fn non_audit_events_are_not_projected() {
        let alice = author("alice");
        let mut log = EventLog::new();
        log.append(&alice, b"not-an-audit-record".to_vec());
        log.append(&alice, audit_payload("alice", "login", 1, "s"));
        let view = log.audit_view();
        assert_eq!(view.len(), 1);
        assert_eq!(
            view[0].verified().unwrap(),
            &AuditRecord::new("alice", "login", 1, "s")
        );
    }

    /// The payload codec round-trips and rejects malformed bytes.
    #[test]
    fn payload_codec_roundtrips_and_rejects_garbage() {
        let r = AuditRecord::new("a", "b", 7, "c");
        assert_eq!(AuditRecord::from_payload(&r.to_payload()), Some(r));
        assert_eq!(AuditRecord::from_payload(b""), None);
        assert_eq!(AuditRecord::from_payload(b"\x03\x00\x00"), None);
        // Trailing garbage is refused.
        let mut p = AuditRecord::new("a", "b", 7, "c").to_payload();
        p.push(0xFF);
        assert_eq!(AuditRecord::from_payload(&p), None);
    }
}
