//! Anti-entropy sync over the content-addressed event DAG — the Rust
//! refinement of `specs/AntiEntropy.tla`.
//!
//! Gossipsub ([`pillar_net`]'s event-log topic) is a best-effort broadcast: a
//! partitioned or newly-joined peer misses arbitrary messages, leaving GAPS in
//! its Merkle-DAG log. Anti-entropy is the range-based set-reconciliation
//! background process that FILLS those gaps (ROI P1, "Event order &
//! integrity", method #1): two peers compare compact per-author digests and the
//! holder ships ONLY the events the other is missing, in causal order, until
//! both converge to the identical reachable event set.
//!
//! This mirrors the hypercore / Secure-Scuttlebutt EBT replication discipline
//! the spec models. Concretely, the reconciliation is:
//!
//! * **content-addressed** — an event is identified by its [`EventId`] (a pure
//!   function of its content), so a re-transferred event that a peer already
//!   holds is a dedup no-op ([`EventLog::ingest`] is idempotent) and a peer can
//!   never be fed the wrong bytes for an id;
//! * **range-based / gap-filling** — a peer advertises, per author, the height
//!   of the contiguous prefix it holds ([`LogDigest`]); the holder sends
//!   exactly the tail each author's chain is missing beyond that height
//!   ([`EventLog::events_missing_from`]) — never the whole log, only the gap;
//! * **causally ordered** — the missing events are delivered in a topological
//!   order of the DAG's `prev`/`parents` hash-links, so every event's causal
//!   predecessors are ingested first and [`EventLog::ingest`]'s `NoGaps` /
//!   `ParentsCrossAuthorAndExist` guards always admit them (never a
//!   `GapOrBrokenPrev`/`DanglingParent` mid-transfer).
//!
//! The TLC-proven property this refines is `Completeness`
//! (`<>[]AllConverged`): after a sync round a peer with gaps holds the SAME
//! reachable event set as the peer it synced from
//! ([`tests::peer_with_gaps_converges_after_one_sync_round`]), and the log
//! stays causally closed at every step (`CausallyClosed`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{Author, Event, EventId, EventLog};

/// A compact, per-author summary of the contiguous prefix a replica holds — the
/// message a peer advertises to drive range-based reconciliation.
///
/// For each author `a`, `heights[a]` is the number of contiguous events the
/// replica holds for `a`'s chain, i.e. its next unheld sequence number
/// (`height[a]` in `AntiEntropy.tla`). Because the log enforces `NoGaps`, the
/// replica holds exactly `a`'s events at seq `0 .. heights[a] - 1`, so this one
/// integer per author fully describes what the peer has of that chain — the
/// holder only needs to send seq `heights[a] ..` to fill the gap.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogDigest {
    heights: BTreeMap<Author, u64>,
}

impl LogDigest {
    /// The advertised contiguous height the digest holds for `author` (0 if the
    /// digest names that author's chain not at all).
    #[must_use]
    pub fn height(&self, author: &Author) -> u64 {
        self.heights.get(author).copied().unwrap_or(0)
    }

    /// The authors this digest names.
    pub fn authors(&self) -> impl Iterator<Item = &Author> {
        self.heights.keys()
    }
}

impl EventLog {
    /// This replica's [`LogDigest`]: the contiguous height held for every author
    /// the replica has any events of. This is the summary a peer advertises to
    /// start a range-based anti-entropy round.
    #[must_use]
    pub fn digest(&self) -> LogDigest {
        LogDigest {
            heights: self.height.clone(),
        }
    }

    /// The event at chain position `(author, seq)`, if held.
    #[must_use]
    pub fn event_at(&self, author: &Author, seq: u64) -> Option<&Event> {
        let id = self.by_seq.get(&(author.clone(), seq))?;
        self.events.get(id)
    }

    /// The events THIS replica holds that a peer advertising `digest` is
    /// missing, returned in a causal (topological) order such that ingesting
    /// them in sequence never hits a gap: every returned event's `prev` and
    /// cross-author `parents` are either already held by the peer or appear
    /// earlier in the returned slice.
    ///
    /// This is the "holder's" half of a sync round: for every author, it takes
    /// exactly the tail of the chain beyond the peer's advertised height
    /// (`digest.height(a) .. self.height(a)`) — the gap gossip left — never the
    /// whole log. Only genuinely missing events are transferred (range-based,
    /// content-addressed reconciliation).
    #[must_use]
    pub fn events_missing_from(&self, digest: &LogDigest) -> Vec<Event> {
        // Collect the ids the peer lacks: for each author, its chain tail beyond
        // the advertised contiguous height.
        let mut missing: BTreeSet<EventId> = BTreeSet::new();
        for (author, &local_height) in &self.height {
            let peer_height = digest.height(author);
            for seq in peer_height..local_height {
                if let Some(id) = self.by_seq.get(&(author.clone(), seq)) {
                    missing.insert(id.clone());
                }
            }
        }

        // Emit them in a topological order of the DAG's hash-links restricted to
        // the missing set: an event is emitted only after every missing event it
        // links to (prev / parents). Links to events the peer already holds are
        // satisfied by definition and need no ordering.
        let mut ordered: Vec<Event> = Vec::with_capacity(missing.len());
        let mut emitted: BTreeSet<EventId> = BTreeSet::new();
        let mut visiting: BTreeSet<EventId> = BTreeSet::new();
        for id in &missing {
            self.emit_in_causal_order(id, &missing, &mut emitted, &mut visiting, &mut ordered);
        }
        ordered
    }

    /// Post-order DFS helper for [`Self::events_missing_from`]: emit `id` only
    /// after every missing event it links to. `visiting` guards against
    /// re-entry (the DAG is acyclic, so it never actually cycles, but the guard
    /// keeps the walk linear).
    fn emit_in_causal_order(
        &self,
        id: &EventId,
        missing: &BTreeSet<EventId>,
        emitted: &mut BTreeSet<EventId>,
        visiting: &mut BTreeSet<EventId>,
        ordered: &mut Vec<Event>,
    ) {
        if emitted.contains(id) || !visiting.insert(id.clone()) {
            return;
        }
        if let Some(event) = self.events.get(id) {
            // Recurse into causal predecessors that are themselves in the
            // missing set, so they are emitted first.
            if let Some(prev) = event.content().prev() {
                if missing.contains(&prev) {
                    self.emit_in_causal_order(&prev, missing, emitted, visiting, ordered);
                }
            }
            for parent in event.content().parents() {
                if missing.contains(parent) {
                    self.emit_in_causal_order(parent, missing, emitted, visiting, ordered);
                }
            }
            if emitted.insert(id.clone()) {
                ordered.push(event.clone());
            }
        }
        visiting.remove(id);
    }

    /// Apply one anti-entropy sync round: pull from `sender` every event this
    /// replica is missing and ingest them in causal order, returning the number
    /// of events newly admitted.
    ///
    /// This is the composed round: `self` advertises its [`LogDigest`], `sender`
    /// computes the gap ([`Self::events_missing_from`]), and `self` ingests the
    /// transferred events. Because they arrive causally ordered, every
    /// [`EventLog::ingest`] succeeds (or dedups); after the round, for the set
    /// of authors `sender` holds, `self` holds a superset of what it held before
    /// and matches `sender` on every synced chain.
    pub fn sync_from(&mut self, sender: &EventLog) -> usize {
        let wanted = sender.events_missing_from(&self.digest());
        let before = self.len();
        for event in wanted {
            // A causally-ordered, content-addressed transfer only ever yields
            // admissible events; a dedup (already held) is a harmless no-op.
            let _ = self.ingest(event);
        }
        self.len() - before
    }
}

/// Reconcile two replicas to convergence by pulling in BOTH directions until
/// neither has anything the other lacks, returning the total number of events
/// transferred across all rounds. On return `a` and `b` hold the identical
/// reachable event set (the `AllConverged` fixed point).
///
/// Each direction is a single [`EventLog::sync_from`]; because every transfer
/// is causally ordered and the combined event set is finite, the loop reaches a
/// fixed point in a bounded number of rounds.
pub fn reconcile(a: &mut EventLog, b: &mut EventLog) -> usize {
    let mut transferred = 0;
    loop {
        let a_pulled = a.sync_from(b);
        let b_pulled = b.sync_from(a);
        transferred += a_pulled + b_pulled;
        if a_pulled == 0 && b_pulled == 0 {
            return transferred;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn author(name: &str) -> Author {
        Author(name.to_string())
    }

    /// Every id a replica holds, for asserting two logs hold the identical
    /// reachable event set (`AllConverged`).
    fn id_set(log: &EventLog) -> BTreeSet<EventId> {
        log.events.keys().cloned().collect()
    }

    /// `CausallyClosed`: a replica never holds `(a, seq)` without also holding
    /// `(a, seq-1)`, and every parent link resolves to a held event.
    fn assert_causally_closed(log: &EventLog) {
        for event in log.events.values() {
            let c = event.content();
            if let Some(prev) = c.prev() {
                assert!(
                    log.contains(&prev),
                    "held event missing its prev (causal predecessor)"
                );
            }
            for parent in c.parents() {
                assert!(log.contains(parent), "held event missing a parent link");
            }
        }
    }

    /// The digest advertises exactly the contiguous per-author height held, and
    /// `events_missing_from` returns exactly the tail beyond a peer's height —
    /// the range-based gap, nothing more.
    #[test]
    fn digest_and_missing_range_describe_only_the_gap() {
        let alice = author("alice");
        let mut full = EventLog::new();
        let _a0 = full.append(&alice, b"a0".to_vec());
        let _a1 = full.append(&alice, b"a1".to_vec());
        let _a2 = full.append(&alice, b"a2".to_vec());

        // A peer that already holds a0, a1 (height 2) is missing only a2.
        let mut peer = EventLog::new();
        let missing_all = full.events_missing_from(&peer.digest());
        assert_eq!(
            missing_all.len(),
            3,
            "empty peer is missing the whole chain"
        );
        // Bring the peer up to height 2 by syncing, then advertise again.
        assert_eq!(peer.sync_from(&full), 3);

        assert_eq!(peer.digest().height(&alice), 3);
        let missing_now = full.events_missing_from(&peer.digest());
        assert!(
            missing_now.is_empty(),
            "a caught-up peer is missing nothing"
        );

        // A peer stuck at height 1 is missing exactly a1, a2 (the tail).
        let mut behind = EventLog::new();
        behind.sync_from_first_n(&full, &alice, 1);
        assert_eq!(behind.digest().height(&alice), 1);
        let tail = full.events_missing_from(&behind.digest());
        assert_eq!(
            tail.len(),
            2,
            "behind peer missing exactly the 2-event tail"
        );
        assert!(tail.iter().all(|e| e.content().author() == &alice));
    }

    /// The headline `Completeness` property: a peer with GAPS in a real
    /// cross-author DAG converges to the full reachable event set after a single
    /// sync round, and its log is causally closed throughout.
    #[test]
    fn peer_with_gaps_converges_after_one_sync_round() {
        let alice = author("alice");
        let bob = author("bob");

        // Build a full replica with an interleaved cross-author DAG:
        // a0 <- b0(parent a0) <- a1(parent b0) <- b1(parent a1) <- a2(parent b1)
        let mut full = EventLog::new();
        full.append(&alice, b"a0".to_vec());
        full.append(&bob, b"b0".to_vec());
        full.append(&alice, b"a1".to_vec());
        full.append(&bob, b"b1".to_vec());
        full.append(&alice, b"a2".to_vec());
        let total = full.len();
        assert_eq!(total, 5);

        // A gapped peer that gossip left with only alice's genesis (height 1 for
        // alice, nothing for bob) — a classic partition gap.
        let mut gapped = EventLog::new();
        gapped.sync_from_first_n(&full, &alice, 1);
        assert_eq!(gapped.len(), 1);
        assert_ne!(id_set(&gapped), id_set(&full));

        // One anti-entropy round fills every gap.
        let pulled = gapped.sync_from(&full);
        assert_eq!(
            pulled,
            total - 1,
            "the round transfers exactly the missing events"
        );
        assert_eq!(
            id_set(&gapped),
            id_set(&full),
            "peer converges to the identical reachable event set (AllConverged)"
        );
        assert_causally_closed(&gapped);

        // Re-running the round is a pure dedup no-op (idempotent / content-addressed).
        assert_eq!(gapped.sync_from(&full), 0);
    }

    /// Bidirectional convergence: two peers that each hold a DISJOINT part of
    /// the DAG (each authored its own chain, neither has the other's)
    /// reconcile to the identical full set — `<>[]AllConverged` under mutual
    /// anti-entropy.
    #[test]
    fn two_partitioned_peers_reconcile_to_identical_sets() {
        let alice = author("alice");
        let bob = author("bob");

        // Peer A authored alice's chain; peer B authored bob's chain. Neither
        // has seen the other (a network partition).
        let mut a = EventLog::new();
        a.append(&alice, b"a0".to_vec());
        a.append(&alice, b"a1".to_vec());

        let mut b = EventLog::new();
        b.append(&bob, b"b0".to_vec());
        b.append(&bob, b"b1".to_vec());
        b.append(&bob, b"b2".to_vec());

        assert_ne!(id_set(&a), id_set(&b));

        let transferred = reconcile(&mut a, &mut b);
        assert_eq!(transferred, 5, "a pulls bob's 3, b pulls alice's 2");
        assert_eq!(
            id_set(&a),
            id_set(&b),
            "both peers hold the identical reachable event set after reconcile"
        );
        assert_eq!(a.len(), 5);
        assert_causally_closed(&a);
        assert_causally_closed(&b);
    }

    // Test-only helper: sync only the first `n` events of one author's chain
    // from `sender`, to construct a deliberately-gapped peer.
    impl EventLog {
        fn sync_from_first_n(&mut self, sender: &EventLog, author: &Author, n: u64) {
            for seq in 0..n {
                if let Some(event) = sender.event_at(author, seq) {
                    let _ = self.ingest(event.clone());
                }
            }
        }
    }
}
