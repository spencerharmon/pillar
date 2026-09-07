//! Anti-entropy sync of the **durable streaming-DB op set** over libp2p — the
//! catch-up channel that reconverges a node whose gossipsub feed had a gap.
//!
//! `pillar node run` persists every event-log op it hears into a
//! [`pillar_streamdb::PersistentStream`], a content-addressed **grow-only
//! set**: each op is a file named by [`pillar_streamdb::content_address`] of its
//! own payload bytes. Gossipsub ([`crate::EVENT_LOG_TOPIC`]) is best-effort, so
//! a node that was PARTITIONED (or joined late) during a publish permanently
//! misses that op — gossip only ever delivers to peers subscribed AT PUBLISH
//! TIME and never re-delivers. Anti-entropy is the background repair channel:
//! the lagging node advertises the op-ids it already holds, and a peer answers
//! with exactly the op payloads it is missing (the gap, never the whole log),
//! which the lagging node persists into its OWN durable store.
//!
//! This is the durable-layer twin of [`crate::antientropy`] (which reconciles
//! the signed [`pillar_eventlog::EventLog`] DAG): here the reconciled objects
//! are the raw content-addressed streamdb ops the running peer actually stores,
//! so a reconverged node ends up with the **identical content-addressed CID**
//! its peers hold for the same op — the exact black-box property
//! `pillar-integration-scenarios-chaos-fault` gates on (a partition heal leaves
//! no split-brain; the cell reconverges to one consistent state).
//!
//! Modelled exactly on [`crate::blob`] / [`crate::antientropy`]: a libp2p
//! request/response protocol carrying [`OpSyncRequest`]/[`OpSyncResponse`],
//! CBOR-encoded. Because every transferred op is content-addressed, the
//! receiver re-derives each op's address from its bytes and only admits a
//! payload whose address it actually still lacks — a peer can never inject an
//! op under a CID that does not hash to its bytes.

use libp2p::{request_response, StreamProtocol};
use pillar_streamdb::{content_address, OpId, OpLog};
use serde::{Deserialize, Serialize};

/// libp2p protocol name for the streaming-DB op-set anti-entropy exchange.
pub const OP_SYNC_PROTOCOL_NAME: &str = "/pillar/op-sync/1.0.0";

/// A sync request: the requester advertises the content-addressed ids (lowercase
/// hex, [`OpId::to_hex`]) of every op it already holds, so the answerer can send
/// back exactly the ones it is missing — the gap, never the whole log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpSyncRequest {
    /// The hex content-addresses of every op the requester already holds.
    pub have: Vec<String>,
}

/// The answer to an [`OpSyncRequest`]: exactly the raw op payloads the requester
/// is missing. Each payload is self-verifying — the receiver re-derives its
/// content address, so the wire carries no separate (forgeable) id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpSyncResponse {
    /// The missing ops' raw payload bytes.
    pub ops: Vec<Vec<u8>>,
}

/// Build the request advertising exactly the ops `log` currently holds.
#[must_use]
pub fn op_sync_request(log: &OpLog) -> OpSyncRequest {
    OpSyncRequest {
        have: log.ids().map(|id| id.to_hex()).collect(),
    }
}

/// Compute the answer to `request` from `log`: exactly the op payloads `log`
/// holds that the requester (per its advertised `have` set) is missing. Pure —
/// the answering half of a sync round, factored out so it is unit-testable
/// without a live swarm.
#[must_use]
pub fn answer_op_sync(log: &OpLog, request: &OpSyncRequest) -> OpSyncResponse {
    let have: std::collections::BTreeSet<String> = request.have.iter().cloned().collect();
    OpSyncResponse {
        ops: log
            .order()
            .into_iter()
            .filter(|op| !have.contains(&op.id().to_hex()))
            .map(|op| op.payload().to_vec())
            .collect(),
    }
}

/// Ingest a received [`OpSyncResponse`] into the durable `stream`, persisting
/// each transferred op under its content address and returning the number newly
/// admitted. Each payload is content-verified implicitly: it is stored under
/// [`content_address`] of its own bytes (idempotent for an op already held), so
/// an op can never land under a CID that does not hash to it. Ops are appended
/// as [`SideEffect::Convergent`] — the same effect `pillar node run` uses for
/// gossiped ops (see `run.rs`).
pub fn apply_op_sync<S: pillar_streamdb::OpSyncTarget>(
    stream: &mut S,
    response: OpSyncResponse,
) -> usize {
    let before = stream.log().len();
    for payload in response.ops {
        let id = OpId(content_address(&payload));
        if stream.log().contains(&id) {
            continue;
        }
        // A relaxed/strict policy that refuses this op leaves the set unchanged
        // (a convergent op is admitted by the default Strict policy).
        stream.append_convergent(payload);
    }
    stream.log().len() - before
}

/// The request/response behaviour half a node runs for streaming-DB op-set
/// anti-entropy — a single `/pillar/op-sync/1.0.0` protocol carrying
/// [`OpSyncRequest`]/[`OpSyncResponse`] pairs, CBOR-encoded on the wire. This is
/// the constructor folded into [`crate::EventBehaviour`] so op-sync multiplexes
/// over the SAME connections as gossipsub/kademlia/identify.
#[must_use]
pub fn op_sync_behaviour() -> request_response::cbor::Behaviour<OpSyncRequest, OpSyncResponse> {
    request_response::cbor::Behaviour::new(
        [(
            StreamProtocol::new(OP_SYNC_PROTOCOL_NAME),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_core::SideEffect;
    use pillar_streamdb::PersistentStream;

    fn tmp_root(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "pillar-opsync-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p
    }

    /// The pure answer/apply halves reconcile a lagging durable store in one
    /// round: it ends holding the identical content-addressed op set (identical
    /// CIDs) as the peer that had the ops.
    #[test]
    fn answer_then_apply_reconverges_the_durable_store() {
        let full_root = tmp_root("full");
        let gap_root = tmp_root("gap");

        // The "peer that had the ops": a full durable store.
        let mut full = PersistentStream::open(&full_root).unwrap();
        let a = full
            .append(b"op-a".to_vec(), SideEffect::Convergent)
            .unwrap();
        let b = full
            .append(b"op-b".to_vec(), SideEffect::Convergent)
            .unwrap();
        let c = full
            .append(b"op-c".to_vec(), SideEffect::Convergent)
            .unwrap();

        // The lagging node: holds only op-a (missed op-b and op-c while
        // partitioned).
        let mut gapped = PersistentStream::open(&gap_root).unwrap();
        gapped
            .append(b"op-a".to_vec(), SideEffect::Convergent)
            .unwrap();
        assert!(!gapped.stream().log().contains(&b));
        assert!(!gapped.stream().log().contains(&c));

        // One round: the lagging node advertises what it has, the peer answers
        // the gap, the lagging node applies it into its OWN durable store.
        let request = op_sync_request(gapped.stream().log());
        let response = answer_op_sync(full.stream().log(), &request);
        let admitted = apply_op_sync(&mut gapped, response);

        assert_eq!(admitted, 2, "exactly the two missing ops were transferred");
        for id in [&a, &b, &c] {
            assert!(
                gapped.stream().log().contains(id),
                "reconverged store holds every op the peer had"
            );
        }
        // The durable Merkle root now matches the peer's — one consistent state,
        // identical CIDs, no split-brain.
        assert_eq!(
            gapped.stream().log().root(),
            full.stream().log().root(),
            "the lagging node reconverged to the identical durable op set"
        );

        // The transferred ops are durable: reopening the store reloads them.
        drop(gapped);
        let reopened = PersistentStream::open(&gap_root).unwrap();
        assert_eq!(reopened.stream().log().len(), 3);

        std::fs::remove_dir_all(&full_root).ok();
        std::fs::remove_dir_all(&gap_root).ok();
    }

    /// Only the gap crosses the wire — an already-held op is never re-sent, and
    /// re-applying is a dedup no-op.
    #[test]
    fn only_the_gap_is_transferred_and_apply_is_idempotent() {
        let full_root = tmp_root("full2");
        let gap_root = tmp_root("gap2");
        let mut full = PersistentStream::open(&full_root).unwrap();
        full.append(b"x".to_vec(), SideEffect::Convergent).unwrap();
        full.append(b"y".to_vec(), SideEffect::Convergent).unwrap();
        let mut gapped = PersistentStream::open(&gap_root).unwrap();
        gapped
            .append(b"x".to_vec(), SideEffect::Convergent)
            .unwrap();

        let response = answer_op_sync(full.stream().log(), &op_sync_request(gapped.stream().log()));
        assert_eq!(response.ops.len(), 1, "only the missing op y is sent");

        assert_eq!(apply_op_sync(&mut gapped, response.clone()), 1);
        // Re-applying the same response admits nothing new.
        assert_eq!(apply_op_sync(&mut gapped, response), 0);

        std::fs::remove_dir_all(&full_root).ok();
        std::fs::remove_dir_all(&gap_root).ok();
    }
}
