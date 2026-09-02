//! DoD acceptance: a fresh/restarted node with an EMPTY local disk rehydrates
//! the streaming DB from IPFS-pinned sealed segments + its custody-held node
//! key ALONE — reconverging to exactly the continuously-gossiped view, never
//! from a local `ops/` directory.

use pillar_core::SideEffect;
use pillar_crypto::seal::sealing_keypair_from_seed;
use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::Seed;
use pillar_streamdb::{Cid, IpfsPersistentStream, SignedSegment, Visibility};

fn seed(label: &str) -> Seed {
    Seed::from_bytes(format!("rehydrate-from-ipfs::{label}").into_bytes())
}

/// A closure-based [`pillar_streamdb::SegmentSource`] backed by another node's
/// content store — the stand-in for the private swarm's backfill substrate a
/// real libp2p/IPFS transport provides.
fn source_from<'a>(remote: &'a pillar_streamdb::ContentStore) -> impl Fn(&Cid) -> Option<SignedSegment> + 'a {
    move |cid: &Cid| remote.get_local(cid)
}

#[test]
fn fresh_node_rehydrates_from_ipfs_pinned_segments_not_local_disk() {
    let (owner_pk, owner_sk) = signing_keypair_from_seed(&seed("stream-owner")).expect("keygen");

    // Node A: the original, continuously-writing node. Every append durably
    // pins a signed segment + advances the IPNS-format head — this IS the
    // "swarm" state (no local filesystem involved anywhere in this module).
    let mut node_a = IpfsPersistentStream::genesis(owner_pk.clone(), owner_sk, Visibility::Public);
    let ids = [
        node_a.append(b"alpha".to_vec(), SideEffect::Exclusive).unwrap(),
        node_a.append(b"bravo".to_vec(), SideEffect::Convergent).unwrap(),
        node_a.append(b"charlie".to_vec(), SideEffect::Exclusive).unwrap(),
    ];

    let root_before = node_a.stream().log().root();
    let order_before: Vec<_> = node_a
        .stream()
        .log()
        .order()
        .iter()
        .map(|op| op.id())
        .collect();

    // The head is resolved out of band (as a real node would resolve it via
    // the private swarm's IPNS/pubsub) — never read from any local file.
    let head = node_a
        .store()
        .resolve_head(&owner_pk)
        .cloned()
        .expect("node A published a head");
    assert_eq!(head.seq(), 3, "one head advance per append");

    // Node B: a FRESH/RESTARTED node with an EMPTY local disk. It never opens
    // any directory and never touches node A's `ContentStore` directly —
    // it only reaches node A's pinned segments through the private-swarm
    // `SegmentSource` abstraction, exactly like a real backfill over libp2p.
    let source = source_from(node_a.store());
    let node_b = IpfsPersistentStream::rehydrate(owner_pk.clone(), &head, &source)
        .expect("rehydrate purely from IPFS-pinned segments");

    // Reconverges to EXACTLY the continuously-gossiped view: same op set,
    // same materialized order, same Merkle root — never lost a write.
    for id in &ids {
        assert!(node_b.stream().log().contains(id), "rehydrated set holds every op");
    }
    assert_eq!(node_b.stream().log().len(), 3);
    let order_after: Vec<_> = node_b
        .stream()
        .log()
        .order()
        .iter()
        .map(|op| op.id())
        .collect();
    assert_eq!(order_after, order_before, "materialized order reconverges");
    assert_eq!(
        node_b.stream().log().root(),
        root_before,
        "Merkle root reconverges purely from IPFS, not a local ops/ directory"
    );
}

/// The node's own private (custody) key is NEVER put in the store — only a
/// SEALED envelope wrapping the segment-signing secret is pinned to IPFS.
/// A restarting node recovers full write capability using ONLY its
/// custody-held node secret plus that IPFS-pinned sealed segment.
#[test]
fn restarting_node_recovers_write_capability_via_custody_key_and_sealed_ipfs_segment() {
    let (owner_pk, owner_sk) = signing_keypair_from_seed(&seed("cell-owner")).expect("keygen");
    let (node_pub, node_secret) = sealing_keypair_from_seed(&seed("node-custody")).expect("keygen");

    let mut node_a = IpfsPersistentStream::genesis(owner_pk.clone(), owner_sk, Visibility::Public);
    node_a.append(b"pre-restart-op".to_vec(), SideEffect::Exclusive).unwrap();

    // Seal the signing secret to the restarting node's custody public key and
    // pin the envelope to IPFS (Sealed visibility — never reaches the DHT).
    let sealed_cid = node_a
        .seal_signing_key(&[node_pub])
        .expect("seal + pin signing key");
    assert!(
        !node_a.store().is_provided(&sealed_cid),
        "a sealed segment must never be advertised to the public DHT"
    );

    let head = node_a
        .store()
        .resolve_head(&owner_pk)
        .cloned()
        .expect("head published");

    // Fresh node, empty disk: rehydrate read-only from IPFS...
    let source = source_from(node_a.store());
    let mut node_b = IpfsPersistentStream::rehydrate(owner_pk.clone(), &head, &source)
        .expect("rehydrate");
    assert!(
        node_b.append(b"should fail".to_vec(), SideEffect::Exclusive).is_err(),
        "a purely rehydrated handle holds no signing secret yet"
    );

    // ...then recover write capability using ONLY its custody-held node
    // secret (never itself present on IPFS) plus the IPFS-pinned sealed
    // segment.
    node_b
        .unseal_signing_key(&sealed_cid, &node_secret, &source)
        .expect("unseal recovers the segment-signing secret");

    let id = node_b
        .append(b"post-restart-op".to_vec(), SideEffect::Convergent)
        .expect("write capability recovered");
    assert!(node_b.stream().log().contains(&id));
}
