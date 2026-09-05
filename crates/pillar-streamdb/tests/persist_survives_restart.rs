//! Acceptance: a durable, disk-backed `IpfsPersistentStream` survives a process
//! restart on a SOLO node (no peers) — the gap that made a bootstrapped cell
//! re-bootstrap on every redeploy.
//!
//! Unlike `rehydrate_from_ipfs.rs` (which proves a FRESH node reconverges from a
//! PEER's in-memory store over a `SegmentSource`), this proves the case a solo
//! seed node actually hits in production: it is the only node, has no peer to
//! backfill from, and must come back from its OWN local PVC-backed pin store
//! after the process dies. The store is opened by `IpfsPersistentStream::open`
//! against an on-disk root; ops are appended; the handle is dropped (simulating
//! the process exiting); a NEW handle is opened against the SAME root and must
//! observe every op, the advanced head sequence, and remain writable.

use pillar_core::SideEffect;
use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::{Seed, SigningPublicKey, SigningSecretKey};
use pillar_streamdb::{ContentStore, IpfsPersistentStream, Visibility};

fn node_keys(label: &str) -> (SigningPublicKey, SigningSecretKey) {
    let seed = Seed::from_bytes(format!("persist-survives-restart::{label}").into_bytes());
    signing_keypair_from_seed(&seed).expect("keygen")
}

/// The op payloads a materialized view currently holds, in order — the thing a
/// restarted node must observe unchanged.
fn view_payloads(s: &IpfsPersistentStream) -> Vec<Vec<u8>> {
    s.stream()
        .log()
        .order()
        .into_iter()
        .map(|op| op.payload().to_vec())
        .collect()
}

/// The op-set as a sorted multiset. `OpLog` is a grow-only CRDT whose `order()`
/// is a deterministic CONTENT-addressed order (not insertion order), so a
/// restart-survival check compares the SET of ops, not the append sequence.
fn op_set(s: &IpfsPersistentStream) -> Vec<Vec<u8>> {
    let mut v = view_payloads(s);
    v.sort();
    v
}

fn sorted(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    v.sort();
    v
}

#[test]
fn durable_stream_survives_a_solo_node_restart_from_local_disk() {
    let root = std::env::temp_dir().join(format!(
        "pillar-streamdb-restart-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (owner, secret) = node_keys("node-a");

    // --- Boot 1: first boot, genesis on disk, append three ops. ---
    {
        let mut node =
            IpfsPersistentStream::open(&root, owner.clone(), secret.clone(), Visibility::Cell)
                .expect("open (first boot)");
        assert!(node.head_cid().is_none(), "first boot starts with no head");
        node.append(b"cell-genesis".to_vec(), SideEffect::Convergent)
            .expect("append 1");
        node.append(b"user:alice".to_vec(), SideEffect::Convergent)
            .expect("append 2");
        node.append(b"grant:alice:admin".to_vec(), SideEffect::Convergent)
            .expect("append 3");
        assert_eq!(node.stream().log().len(), 3);
        // handle dropped here == process exit; nothing else flushed.
    }

    // --- Boot 2: a NEW handle against the SAME on-disk root (the redeploy). ---
    let expected = sorted(vec![
        b"cell-genesis".to_vec(),
        b"user:alice".to_vec(),
        b"grant:alice:admin".to_vec(),
    ]);
    {
        let mut node =
            IpfsPersistentStream::open(&root, owner.clone(), secret.clone(), Visibility::Cell)
                .expect("open (restart)");
        assert_eq!(
            op_set(&node),
            expected,
            "every op survives the restart — NOT re-bootstrapped"
        );
        assert!(
            node.head_cid().is_some(),
            "the head was reloaded from disk, not reset"
        );

        // Still WRITABLE after a durable reopen (secret re-supplied), and the
        // new op also persists.
        node.append(b"user:bob".to_vec(), SideEffect::Convergent)
            .expect("append after restart must work (writable)");
        assert_eq!(node.stream().log().len(), 4);
    }

    // --- Boot 3: prove the 4th op also persisted across another restart. ---
    {
        let node =
            IpfsPersistentStream::open(&root, owner.clone(), secret.clone(), Visibility::Cell)
                .expect("open (second restart)");
        let mut want = expected.clone();
        want.push(b"user:bob".to_vec());
        assert_eq!(
            op_set(&node),
            sorted(want),
            "the post-restart append also survived"
        );
    }

    // --- Prove durability is on DISK, not in the handle: a bare ContentStore
    //     opened on the same root independently holds the pinned segments. ---
    {
        let store = ContentStore::open(&root).expect("reopen bare store");
        assert!(
            store.resolve_head(&owner).is_some(),
            "the IPNS head is persisted on disk"
        );
        assert!(store.is_durable(), "opened store is disk-backed");
    }

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn a_different_owner_sees_an_empty_stream_on_the_same_root() {
    // Durability is per-owner-head: a node whose identity does not match the
    // persisted head starts empty (it never mis-attributes another owner's
    // chain as its own).
    let root = std::env::temp_dir().join(format!(
        "pillar-streamdb-restart-owner-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (owner_a, secret_a) = node_keys("owner-a");
    {
        let mut node =
            IpfsPersistentStream::open(&root, owner_a.clone(), secret_a, Visibility::Cell)
                .expect("open a");
        node.append(b"a-op".to_vec(), SideEffect::Convergent)
            .expect("append");
    }
    let (owner_b, secret_b) = node_keys("owner-b");
    let node_b =
        IpfsPersistentStream::open(&root, owner_b, secret_b, Visibility::Cell).expect("open b");
    assert_eq!(
        node_b.stream().log().len(),
        0,
        "owner B has no head here → empty"
    );

    std::fs::remove_dir_all(&root).ok();
}
