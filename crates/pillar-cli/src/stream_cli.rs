//! `pillar stream {ls|describe|tip|log|get|verify|snapshot|sync|sub|unsub|head|append|create}`
//! — the data-plane family of the `cli-cluster-stream-impl` task, against
//! [`docs/cli-surface.md`](../../../docs/cli-surface.md) § "Data plane:
//! `pillar stream`". Built directly over the proven
//! [`pillar_streamdb`] CRDT op-log (`streamdb-impl`,
//! [`specs/StreamingDB.tla`](../../../specs/StreamingDB.tla)) — no private
//! storage or hashing of its own.
//!
//! # Views vs. acts
//!
//! `ls`, `describe`, `tip`, `log`/`read`, `get`, `head`, and `verify` are
//! VIEWS: every one of them takes `&self` and cannot append an op. `append`
//! and `create` are the acts (`create` installs a fresh, empty stream;
//! `append` is the raw signed-append every higher CLI verb composes, per the
//! surface doc). `sync` merges verified ops from a peer — a bounded act that
//! either accepts a fully-verified batch or refuses the whole batch,
//! never a partial, silently-corrupt merge.

use std::collections::{BTreeMap, BTreeSet};

use pillar_core::{SideEffect, ViewPolicy};
use pillar_streamdb::{content_address, Op, OpId, PolicyViolation, Snapshot, Stream};

/// Why a `pillar stream` command was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamCliError {
    /// `create` of a stream name already in use.
    AlreadyExists(String),
    /// `describe`/`append`/`get`/... of a stream that was never created.
    NoSuchStream(String),
    /// `append` refused by the stream's [`ViewPolicy`] (an exclusive effect on
    /// a relaxed-policy stream).
    Policy(PolicyViolation),
    /// `get <cid>` of a content address the stream does not hold.
    NoSuchOp(OpId),
}

impl From<PolicyViolation> for StreamCliError {
    fn from(e: PolicyViolation) -> Self {
        StreamCliError::Policy(e)
    }
}

/// One entry a `sync`/gossip batch carries: a peer's CLAIMED content address
/// plus the payload bytes it says that address names. [`verify_ops`] proves
/// (or disproves) the claim before anything is merged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimedOp {
    /// The content address the peer claims for `payload`.
    pub claimed_id: OpId,
    /// The op payload bytes.
    pub payload: Vec<u8>,
}

impl ClaimedOp {
    /// An honestly-addressed claim: `claimed_id` is derived correctly from
    /// `payload`, exactly as a well-behaved peer would send.
    #[must_use]
    pub fn honest(payload: impl Into<Vec<u8>>) -> Self {
        let payload = payload.into();
        let claimed_id = OpId(content_address(&payload));
        ClaimedOp {
            claimed_id,
            payload,
        }
    }
}

/// A single tampered/mismatched claim `verify_ops` rejected: the address a
/// peer claimed versus the address its payload actually hashes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TamperedOp {
    /// The address the peer claimed.
    pub claimed_id: OpId,
    /// The address the payload actually content-hashes to.
    pub actual_id: OpId,
}

/// Verify a batch of [`ClaimedOp`]s against the SAME
/// [`pillar_streamdb::content_address`] function every stream uses for its
/// own [`OpId`]s — no private/second hash. A pure function: it reads nothing,
/// mutates nothing, and detects a tampered entry (payload bytes that do not
/// hash to their claimed content address) by construction, since an honest
/// claim can only ever be honest by recomputing the identical hash.
///
/// # Errors
/// The first [`TamperedOp`] found, naming the claimed vs. actual address.
pub fn verify_ops(candidates: &[ClaimedOp]) -> Result<(), TamperedOp> {
    for c in candidates {
        let actual = OpId(content_address(&c.payload));
        if actual != c.claimed_id {
            return Err(TamperedOp {
                claimed_id: c.claimed_id,
                actual_id: actual,
            });
        }
    }
    Ok(())
}

/// One materialized stream plus the operator-facing metadata `describe`
/// surfaces (retention is display-only bookkeeping here; enforcing it against
/// wall-clock/compaction belongs to `streamdb-impl`'s durable backend).
#[derive(Clone, Debug, Default)]
struct StreamEntry {
    stream: Stream,
    retention: Option<String>,
    subscribers: BTreeSet<String>,
}

/// The `pillar stream` engine: a name -> [`Stream`] registry. Every method is
/// a thin, unit-tested pass-through to the proven [`pillar_streamdb`] engine
/// (or, for `sync`, to [`verify_ops`] plus [`Stream::merge`]) — same
/// discipline as [`crate::session_cli::SessionCli`] and
/// [`crate::cluster::LeaseCli`].
#[derive(Clone, Debug, Default)]
pub struct StreamCli {
    streams: BTreeMap<String, StreamEntry>,
}

impl StreamCli {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        StreamCli::default()
    }

    fn entry(&self, name: &str) -> Result<&StreamEntry, StreamCliError> {
        self.streams
            .get(name)
            .ok_or_else(|| StreamCliError::NoSuchStream(name.to_owned()))
    }

    fn entry_mut(&mut self, name: &str) -> Result<&mut StreamEntry, StreamCliError> {
        self.streams
            .get_mut(name)
            .ok_or_else(|| StreamCliError::NoSuchStream(name.to_owned()))
    }

    // ---- acts ----

    /// `pillar stream create <name> [--retention <dur>] [--policy strict|relaxed]`.
    ///
    /// # Errors
    /// [`StreamCliError::AlreadyExists`] if `name` is already registered.
    pub fn create(
        &mut self,
        name: impl Into<String>,
        retention: Option<String>,
        policy: ViewPolicy,
    ) -> Result<(), StreamCliError> {
        let name = name.into();
        if self.streams.contains_key(&name) {
            return Err(StreamCliError::AlreadyExists(name));
        }
        self.streams.insert(
            name,
            StreamEntry {
                stream: Stream::with_policy(policy),
                retention,
                subscribers: BTreeSet::new(),
            },
        );
        Ok(())
    }

    /// `pillar stream append <name> -f <file>` — sign + append one event to
    /// `name`. Exactly [`Stream::try_append`]; refused per the stream's
    /// policy for an [`SideEffect::Exclusive`] act on a relaxed stream.
    ///
    /// # Errors
    /// [`StreamCliError::NoSuchStream`] / [`StreamCliError::Policy`].
    pub fn append(
        &mut self,
        name: &str,
        payload: impl Into<Vec<u8>>,
        effect: SideEffect,
    ) -> Result<OpId, StreamCliError> {
        Ok(self.entry_mut(name)?.stream.try_append(payload, effect)?)
    }

    /// `pillar stream sync <name>` — merge a batch of [`ClaimedOp`]s claimed
    /// to originate from a peer. Verifies EVERY claim with [`verify_ops`]
    /// FIRST; on any tampered entry the WHOLE batch is refused (nothing
    /// merged) rather than silently accepting the honest prefix.
    ///
    /// # Errors
    /// [`StreamCliError::NoSuchStream`] if `name` is unregistered; the
    /// [`TamperedOp`] wrapped as [`StreamCliError::Policy`]-adjacent is
    /// surfaced directly via the `Err` variant's [`TamperedOp`] (see return
    /// type) so a caller can report exactly which entry was mangled.
    pub fn sync(&mut self, name: &str, candidates: &[ClaimedOp]) -> Result<usize, SyncError> {
        let entry = self
            .streams
            .get_mut(name)
            .ok_or_else(|| SyncError::NoSuchStream(name.to_owned()))?;
        verify_ops(candidates).map_err(SyncError::Tampered)?;
        // Every candidate is now PROVEN to hash to its claimed address, so
        // re-appending its payload (which re-derives the identical id via
        // `Op::new`) is exactly the CRDT merge/gossip join — idempotent by
        // construction, hence always admitted as `Convergent` regardless of
        // the stream's declared policy (a `Strict` stream admits everything;
        // a `Relaxed` one admits `Convergent`).
        let before = entry.stream.log().len();
        for c in candidates {
            entry
                .stream
                .try_append(c.payload.clone(), SideEffect::Convergent)
                .expect("a verified, content-addressed merge is always Convergent-admitted");
        }
        Ok(entry.stream.log().len() - before)
    }

    // ---- views ----

    /// `pillar stream ls` — every registered stream name, sorted.
    #[must_use]
    pub fn ls(&self) -> Vec<&str> {
        self.streams.keys().map(String::as_str).collect()
    }

    /// `pillar stream describe <name>` — retention/compaction policy, head
    /// CID, op count.
    ///
    /// # Errors
    /// [`StreamCliError::NoSuchStream`].
    pub fn describe(&self, name: &str) -> Result<StreamDescription, StreamCliError> {
        let entry = self.entry(name)?;
        Ok(StreamDescription {
            retention: entry.retention.clone(),
            policy: entry.stream.policy(),
            len: entry.stream.log().len(),
            head: entry.stream.log().root(),
        })
    }

    /// `pillar stream tip <name>` — the current Merkle root (the
    /// materialized-view "tip" a peer compares to detect divergence). A pure
    /// function of the op set, per `pillar_streamdb`'s `Root`.
    ///
    /// # Errors
    /// [`StreamCliError::NoSuchStream`].
    pub fn tip(&self, name: &str) -> Result<u64, StreamCliError> {
        Ok(self.entry(name)?.stream.log().root())
    }

    /// `pillar stream log <name> [--from CID]` — the materialized,
    /// content-ordered ops, optionally starting after `from`.
    ///
    /// # Errors
    /// [`StreamCliError::NoSuchStream`].
    pub fn log(&self, name: &str, from: Option<OpId>) -> Result<Vec<&Op>, StreamCliError> {
        let order = self.entry(name)?.stream.log().order();
        Ok(match from {
            None => order,
            Some(cid) => {
                let mut skipping = true;
                order
                    .into_iter()
                    .filter(|op| {
                        if skipping {
                            if op.id() == cid {
                                skipping = false;
                            }
                            false
                        } else {
                            true
                        }
                    })
                    .collect()
            }
        })
    }

    /// `pillar stream get <name> <cid>` — the payload at content address
    /// `cid`.
    ///
    /// # Errors
    /// [`StreamCliError::NoSuchStream`] / [`StreamCliError::NoSuchOp`].
    pub fn get(&self, name: &str, cid: OpId) -> Result<&[u8], StreamCliError> {
        self.entry(name)?
            .stream
            .log()
            .order()
            .into_iter()
            .find(|op| op.id() == cid)
            .map(Op::payload)
            .ok_or(StreamCliError::NoSuchOp(cid))
    }

    /// `pillar stream head <name>` — the most-recently-content-ordered op
    /// (the highest content address), if any.
    ///
    /// # Errors
    /// [`StreamCliError::NoSuchStream`].
    pub fn head(&self, name: &str) -> Result<Option<&Op>, StreamCliError> {
        Ok(self.entry(name)?.stream.log().order().into_iter().last())
    }

    /// `pillar stream verify <name>` — a pure VIEW proving this stream's own
    /// stored ops are internally consistent: every stored op's [`OpId`] is
    /// exactly [`content_address`] of its own payload. Since every accepted
    /// append derives its id via [`Op::new`], this always holds for ops
    /// admitted through [`Self::append`]/[`Self::sync`] — the interesting
    /// case, an actually-tampered candidate, is caught by [`verify_ops`]
    /// (exercised directly by `sync`, and by the unit tests below) BEFORE it
    /// would ever land here.
    ///
    /// # Errors
    /// [`StreamCliError::NoSuchStream`], or the first [`TamperedOp`] found
    /// (surfaced via [`StreamCliError::Policy`]-free direct return — see
    /// return type) if internal storage were ever corrupted.
    pub fn verify(&self, name: &str) -> Result<(), VerifyError> {
        let entry = self
            .streams
            .get(name)
            .ok_or_else(|| VerifyError::NoSuchStream(name.to_owned()))?;
        let claims: Vec<ClaimedOp> = entry
            .stream
            .log()
            .order()
            .into_iter()
            .map(|op| ClaimedOp {
                claimed_id: op.id(),
                payload: op.payload().to_vec(),
            })
            .collect();
        verify_ops(&claims).map_err(VerifyError::Tampered)
    }

    /// `pillar stream snapshot <name>` — a content-addressed compaction, per
    /// [`Stream::log`] / [`pillar_streamdb::OpLog::compact`].
    ///
    /// # Errors
    /// [`StreamCliError::NoSuchStream`].
    pub fn snapshot(&self, name: &str) -> Result<Snapshot, StreamCliError> {
        Ok(self.entry(name)?.stream.log().compact())
    }

    /// `pillar stream sub <name> <subscriber>` — record a subscriber. Purely
    /// local bookkeeping (no push-delivery mechanism here); `unsub` is the
    /// exact inverse.
    ///
    /// # Errors
    /// [`StreamCliError::NoSuchStream`].
    pub fn subscribe(
        &mut self,
        name: &str,
        subscriber: impl Into<String>,
    ) -> Result<(), StreamCliError> {
        self.entry_mut(name)?.subscribers.insert(subscriber.into());
        Ok(())
    }

    /// `pillar stream unsub <name> <subscriber>`.
    ///
    /// # Errors
    /// [`StreamCliError::NoSuchStream`].
    pub fn unsubscribe(&mut self, name: &str, subscriber: &str) -> Result<(), StreamCliError> {
        self.entry_mut(name)?.subscribers.remove(subscriber);
        Ok(())
    }

    /// `pillar stream describe <name>`'s subscriber roster, for completeness
    /// (also reachable in [`StreamDescription`] if extended later).
    ///
    /// # Errors
    /// [`StreamCliError::NoSuchStream`].
    pub fn subscribers(&self, name: &str) -> Result<Vec<&str>, StreamCliError> {
        Ok(self
            .entry(name)?
            .subscribers
            .iter()
            .map(String::as_str)
            .collect())
    }
}

/// `pillar stream describe <name>` projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamDescription {
    /// Display-only retention window, if any was set on `create`.
    pub retention: Option<String>,
    /// The stream's effective (declared-or-defaulted) [`ViewPolicy`].
    pub policy: ViewPolicy,
    /// Number of ops currently held.
    pub len: usize,
    /// The current Merkle root ("head CID").
    pub head: u64,
}

/// Why `pillar stream sync` refused a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncError {
    /// The target stream is unregistered.
    NoSuchStream(String),
    /// A claim in the batch did not hash to its claimed content address — the
    /// WHOLE batch is refused, nothing merged.
    Tampered(TamperedOp),
}

/// Why `pillar stream verify` failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The target stream is unregistered.
    NoSuchStream(String),
    /// A stored op's id did not match its content-hashed payload.
    Tampered(TamperedOp),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_ls_describe_append_are_consistent() {
        let mut cli = StreamCli::new();
        cli.create("logs-app", Some("7d".into()), ViewPolicy::Strict)
            .unwrap();
        assert_eq!(cli.ls(), vec!["logs-app"]);

        let id1 = cli
            .append("logs-app", b"line one".to_vec(), SideEffect::Convergent)
            .unwrap();
        let id2 = cli
            .append("logs-app", b"line two".to_vec(), SideEffect::Convergent)
            .unwrap();
        assert_ne!(id1, id2);

        let desc = cli.describe("logs-app").unwrap();
        assert_eq!(desc.len, 2);
        assert_eq!(desc.retention.as_deref(), Some("7d"));
        assert_eq!(desc.head, cli.tip("logs-app").unwrap());
    }

    #[test]
    fn create_is_refused_on_a_duplicate_name() {
        let mut cli = StreamCli::new();
        cli.create("s", None, ViewPolicy::Strict).unwrap();
        assert_eq!(
            cli.create("s", None, ViewPolicy::Strict),
            Err(StreamCliError::AlreadyExists("s".into()))
        );
    }

    /// `log`/`tip`/`get` are pure VIEWS: calling them repeatedly never
    /// changes the stream (same op count, same tip/root, same payloads).
    #[test]
    fn log_tip_get_are_pure_views() {
        let mut cli = StreamCli::new();
        cli.create("s", None, ViewPolicy::Strict).unwrap();
        let id = cli
            .append("s", b"payload".to_vec(), SideEffect::Convergent)
            .unwrap();

        let tip_before = cli.tip("s").unwrap();
        let len_before = cli.describe("s").unwrap().len;

        for _ in 0..5 {
            let _ = cli.log("s", None).unwrap();
            let _ = cli.tip("s").unwrap();
            let _ = cli.get("s", id).unwrap();
            let _ = cli.head("s").unwrap();
        }

        assert_eq!(cli.tip("s").unwrap(), tip_before, "tip is a pure view");
        assert_eq!(
            cli.describe("s").unwrap().len,
            len_before,
            "views never append an op"
        );
        assert_eq!(cli.get("s", id).unwrap(), b"payload");
        assert_eq!(cli.head("s").unwrap().unwrap().id(), id);
    }

    #[test]
    fn get_of_unknown_cid_is_refused() {
        let mut cli = StreamCli::new();
        cli.create("s", None, ViewPolicy::Strict).unwrap();
        assert_eq!(
            cli.get("s", OpId(999)),
            Err(StreamCliError::NoSuchOp(OpId(999)))
        );
    }

    /// `verify` is a pure view over a stream's own (always-honest, since it
    /// only ever ingests via `append`/`sync`) storage: it must PASS for any
    /// ordinary stream.
    #[test]
    fn verify_passes_for_an_honestly_appended_stream() {
        let mut cli = StreamCli::new();
        cli.create("s", None, ViewPolicy::Strict).unwrap();
        cli.append("s", b"a".to_vec(), SideEffect::Convergent)
            .unwrap();
        cli.append("s", b"b".to_vec(), SideEffect::Convergent)
            .unwrap();
        assert_eq!(cli.verify("s"), Ok(()));
    }

    /// The core tamper-detection property: `verify_ops` (the SAME check
    /// `sync` runs before merging, and `verify` runs over stored ops) detects
    /// a tampered event — a claimed content address that does not match what
    /// its payload actually hashes to — and names exactly which.
    #[test]
    fn verify_ops_detects_a_tampered_event() {
        let honest = ClaimedOp::honest(b"original payload".to_vec());
        let tampered = ClaimedOp {
            claimed_id: honest.claimed_id,        // stale address...
            payload: b"mutated payload".to_vec(), // ...for DIFFERENT bytes
        };

        let err = verify_ops(&[honest.clone(), tampered.clone()]).unwrap_err();
        assert_eq!(err.claimed_id, tampered.claimed_id);
        assert_ne!(
            err.actual_id, err.claimed_id,
            "a tampered payload's real hash differs from its stale claim"
        );

        // An all-honest batch verifies clean.
        let other_honest = ClaimedOp::honest(b"another payload".to_vec());
        assert_eq!(verify_ops(&[honest, other_honest]), Ok(()));
    }

    /// `sync` refuses a batch containing even one tampered claim, merging
    /// NOTHING — not even the honest entries in the same batch.
    #[test]
    fn sync_refuses_the_whole_batch_on_any_tampered_claim() {
        let mut cli = StreamCli::new();
        cli.create("s", None, ViewPolicy::Strict).unwrap();

        let honest = ClaimedOp::honest(b"good op".to_vec());
        let tampered = ClaimedOp {
            claimed_id: OpId(42),
            payload: b"bad op".to_vec(),
        };

        let err = cli.sync("s", &[honest, tampered]).unwrap_err();
        assert!(matches!(err, SyncError::Tampered(_)));
        assert_eq!(
            cli.describe("s").unwrap().len,
            0,
            "a refused batch merges nothing, not even the honest entries"
        );
    }

    /// `sync` with an all-honest batch merges every op — the round-trip a
    /// real gossip/bootstrap peer relies on.
    #[test]
    fn sync_merges_a_fully_honest_batch() {
        let mut cli = StreamCli::new();
        cli.create("s", None, ViewPolicy::Strict).unwrap();
        cli.append("s", b"local".to_vec(), SideEffect::Convergent)
            .unwrap();

        let peer_ops = vec![
            ClaimedOp::honest(b"peer-op-1".to_vec()),
            ClaimedOp::honest(b"peer-op-2".to_vec()),
        ];
        let merged = cli.sync("s", &peer_ops).unwrap();
        assert_eq!(merged, 2);
        assert_eq!(cli.describe("s").unwrap().len, 3);
    }

    #[test]
    fn snapshot_summarizes_the_current_op_set() {
        let mut cli = StreamCli::new();
        cli.create("s", None, ViewPolicy::Strict).unwrap();
        cli.append("s", b"a".to_vec(), SideEffect::Convergent)
            .unwrap();
        cli.append("s", b"b".to_vec(), SideEffect::Convergent)
            .unwrap();
        let snap = cli.snapshot("s").unwrap();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.root(), cli.tip("s").unwrap());
    }

    #[test]
    fn append_is_refused_by_an_exclusive_effect_on_a_relaxed_stream() {
        let mut cli = StreamCli::new();
        cli.create("s", None, ViewPolicy::Relaxed).unwrap();
        let err = cli
            .append("s", b"x".to_vec(), SideEffect::Exclusive)
            .unwrap_err();
        assert!(matches!(err, StreamCliError::Policy(_)));
    }

    #[test]
    fn subscribe_unsubscribe_round_trip() {
        let mut cli = StreamCli::new();
        cli.create("s", None, ViewPolicy::Strict).unwrap();
        cli.subscribe("s", "watcher-1").unwrap();
        cli.subscribe("s", "watcher-2").unwrap();
        assert_eq!(
            cli.subscribers("s").unwrap(),
            vec!["watcher-1", "watcher-2"]
        );
        cli.unsubscribe("s", "watcher-1").unwrap();
        assert_eq!(cli.subscribers("s").unwrap(), vec!["watcher-2"]);
    }

    #[test]
    fn log_from_cid_skips_up_to_and_including_that_op() {
        let mut cli = StreamCli::new();
        cli.create("s", None, ViewPolicy::Strict).unwrap();
        let id1 = cli
            .append("s", b"a".to_vec(), SideEffect::Convergent)
            .unwrap();
        let _id2 = cli
            .append("s", b"b".to_vec(), SideEffect::Convergent)
            .unwrap();
        let after = cli.log("s", Some(id1)).unwrap();
        assert_eq!(after.len(), 1);
    }

    #[test]
    fn operations_on_an_unregistered_stream_are_refused() {
        let cli = StreamCli::new();
        assert_eq!(
            cli.describe("ghost"),
            Err(StreamCliError::NoSuchStream("ghost".into()))
        );
        assert_eq!(
            cli.tip("ghost"),
            Err(StreamCliError::NoSuchStream("ghost".into()))
        );
    }
}
