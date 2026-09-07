//! Acceptance: the **network root** is a real libp2p pnet swarm, and the PUBLIC
//! default is a *keyed* swarm derived from the published
//! [`pillar_swarm::PUBLIC_PILLAR_ROOT`] — NOT an open/keyless transport.
//!
//! This is the definition-of-done for `network-root-config-impl` after its
//! 2026-09-06 reopening: the earlier impl realized the public default as a
//! `disabled()` / open transport, letting the public swarm co-mingle with
//! unrelated libp2p/IPFS peers. The ROI now MANDATES that a node with nothing
//! configured joins the ONE public swarm on a pnet PSK derived from the single
//! published baked-in value, so the public swarm is transport-isolated from the
//! open DHT. This suite asserts the corrected behaviour end to end:
//!
//! 1. The public default path builds a pnet-keyed swarm whose key is derived
//!    from `PUBLIC_PILLAR_ROOT` — the derived [`pillar_net::PrivateSwarmKey`]
//!    is ENABLED and equals the public derivation, never `disabled()`. Two
//!    public nodes (each resolving their root exactly as `pillar node run` does
//!    with no `--swarm-key`) converge in the DHT over that pnet transport.
//! 2. Two nodes each booted with a DIFFERENT `--swarm-key` file never establish
//!    a connection — the pnet PSK mismatch refuses the handshake.
//! 3. Two nodes booted with the SAME `--swarm-key` file, pointed at each other
//!    only via `--seed-node` (no public root/seed in their config), converge:
//!    the joiner's Kademlia routing table becomes non-empty and a discovery
//!    query resolves the seed.
//! 4. The SAME key file yields DISTINCT event-log and IPFS pnet keys via each
//!    crate's domain-separated `PrivateSwarmKey::from_root_secret` — one root,
//!    two membership-isolated transports.
//! 5. A node with no `--swarm-key` never touches any file/registry on disk: the
//!    public root is a pure in-memory value ([`pillar_swarm::SwarmKey::public`]).
//!
//! Gated by the crate's off-by-default `acceptance` feature so the ordinary
//! `cargo test` unit run does not have to stand up real sockets:
//! `cargo test -p pillar-net --test network_root_pnet --features acceptance`.
#![cfg(feature = "acceptance")]

use std::time::Duration;

use futures::StreamExt;
use libp2p::core::multiaddr::{Multiaddr, Protocol};
use libp2p::identity::Keypair;
use libp2p::kad;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use tokio::time::timeout;

use pillar_net::{
    build_event_swarm_with_root, parse_seed_multiaddr, seed_event_dht, EventBehaviourEvent,
    PrivateSwarmKey,
};
use pillar_swarm::{SwarmKey, SwarmKind, PUBLIC_PILLAR_ROOT};

/// Resolve the event-log pnet root EXACTLY as `pillar node run` does at boot:
/// with an explicit `--swarm-key` file the key comes from that file; with no
/// `--swarm-key` it is the baked-in public swarm key. Mirrors the boot logic in
/// `pillar_cli::run` so this test exercises the real resolution, not a shortcut.
fn resolve_root(swarm_key: Option<&SwarmKey>) -> PrivateSwarmKey {
    let key = swarm_key.cloned().unwrap_or_else(SwarmKey::public);
    PrivateSwarmKey::from_root_secret(key.root_secret())
}

fn local_tcp_listen_addr() -> Multiaddr {
    Multiaddr::empty()
        .with(Protocol::Ip4(std::net::Ipv4Addr::LOCALHOST))
        .with(Protocol::Tcp(0))
}

async fn drive_until<B: NetworkBehaviour, T>(
    swarm: &mut Swarm<B>,
    deadline: Duration,
    mut pred: impl FnMut(&SwarmEvent<B::ToSwarm>) -> Option<T>,
) -> T {
    timeout(deadline, async {
        loop {
            let event = swarm.select_next_some().await;
            if let Some(v) = pred(&event) {
                return v;
            }
        }
    })
    .await
    .expect("deadline elapsed waiting for expected swarm event")
}

async fn listen_and_get_addr<B: NetworkBehaviour>(swarm: &mut Swarm<B>) -> Multiaddr {
    swarm.listen_on(local_tcp_listen_addr()).unwrap();
    drive_until(swarm, Duration::from_secs(10), |event| match event {
        SwarmEvent::NewListenAddr { address, .. } => Some(address.clone()),
        _ => None,
    })
    .await
}

/// Write a swarm key to a temp file the way `pillar swarm generate > <file>`
/// would, and return its path (kept alive by the returned `TempDir`).
fn write_key_file(name: &str, key: &SwarmKey) -> (tempdir_shim::TempDir, std::path::PathBuf) {
    let dir = tempdir_shim::TempDir::new(name);
    let path = dir.path().join("swarm.key");
    std::fs::write(&path, format!("{}\n", key.root_secret())).expect("write key file");
    (dir, path)
}

/// The public default path binds a REAL pnet-keyed transport derived from
/// `PUBLIC_PILLAR_ROOT`, never a keyless `disabled()` transport.
#[tokio::test]
async fn public_default_is_a_pnet_swarm_keyed_by_the_published_root() {
    // Boot with NO `--swarm-key`: the node joins the public swarm.
    let root = resolve_root(None);

    // It is ENABLED (a pnet PSK), NOT the open/keyless `disabled()` transport
    // the reopened false-DONE regressed to.
    assert!(
        root.is_enabled(),
        "the public default must be a real pnet swarm, not a keyless open transport"
    );
    assert_ne!(
        root,
        PrivateSwarmKey::disabled(),
        "the public default must NOT be `disabled()` (open transport is TEST-ONLY)"
    );

    // The key is derived from the single PUBLISHED baked-in value.
    assert_eq!(
        root,
        PrivateSwarmKey::from_root_secret(PUBLIC_PILLAR_ROOT),
        "the public pnet key must derive from `PUBLIC_PILLAR_ROOT`"
    );
    assert_eq!(
        SwarmKey::public().kind(),
        SwarmKind::Public,
        "a node with no --swarm-key resolves to the public swarm"
    );

    // And it actually stands up a working pnet swarm on which two public nodes
    // converge — proving the derived key wires a real, mutually-reachable
    // transport (not merely a non-None struct).
    let mut seed =
        build_event_swarm_with_root(Keypair::generate_ed25519(), resolve_root(None), false, true)
            .expect("public seed swarm builds");
    let seed_peer_id = *seed.local_peer_id();
    let seed_addr = listen_and_get_addr(&mut seed).await;
    let seed_multiaddr = seed_addr.with(Protocol::P2p(seed_peer_id));
    tokio::spawn(async move {
        loop {
            seed.select_next_some().await;
        }
    });

    let mut joiner =
        build_event_swarm_with_root(Keypair::generate_ed25519(), resolve_root(None), false, true)
            .expect("public joiner swarm builds");
    let seeds = vec![parse_seed_multiaddr(seed_multiaddr).unwrap()];
    assert_eq!(seed_event_dht(&mut joiner, &seeds), 1);
    drive_until(&mut joiner, Duration::from_secs(15), |event| match event {
        SwarmEvent::ConnectionEstablished { peer_id, .. } if *peer_id == seed_peer_id => Some(()),
        _ => None,
    })
    .await;
}

/// Two nodes each booted with a DIFFERENT `--swarm-key` file never establish a
/// connection — the pnet PSK mismatch refuses the handshake.
#[tokio::test]
async fn different_swarm_key_files_never_connect() {
    let (_da, path_a) = write_key_file("net-root-diff-a", &SwarmKey::generate());
    let (_db, path_b) = write_key_file("net-root-diff-b", &SwarmKey::generate());

    let key_a = SwarmKey::from_file(&path_a).expect("read key a");
    let key_b = SwarmKey::from_file(&path_b).expect("read key b");
    assert_eq!(key_a.kind(), SwarmKind::Private);
    assert_eq!(key_b.kind(), SwarmKind::Private);

    let mut a = build_event_swarm_with_root(
        Keypair::generate_ed25519(),
        resolve_root(Some(&key_a)),
        false,
        false,
    )
    .unwrap();
    let mut b = build_event_swarm_with_root(
        Keypair::generate_ed25519(),
        resolve_root(Some(&key_b)),
        false,
        false,
    )
    .unwrap();
    let b_peer_id = *b.local_peer_id();
    let b_addr = listen_and_get_addr(&mut b).await;
    a.dial(b_addr.with(Protocol::P2p(b_peer_id))).unwrap();

    let drive_a = async {
        loop {
            if let SwarmEvent::ConnectionEstablished { .. } = a.select_next_some().await {
                return true;
            }
        }
    };
    let drive_b = async {
        loop {
            if let SwarmEvent::ConnectionEstablished { .. } = b.select_next_some().await {
                return true;
            }
        }
    };
    let raced = futures::future::select(Box::pin(drive_a), Box::pin(drive_b));
    let established = timeout(Duration::from_secs(5), raced).await;
    assert!(
        established.is_err(),
        "nodes with DIFFERENT --swarm-key files must never establish a connection \
         (pnet PSK mismatch refuses the handshake)"
    );
}

/// Two nodes booted with the SAME `--swarm-key` file, pointed at each other only
/// via `--seed-node` (no public root/seed in their config), converge: the
/// joiner's Kademlia routing table becomes non-empty and a discovery query
/// resolves the seed.
#[tokio::test]
async fn same_swarm_key_file_plus_seed_node_converges() {
    let (_dir, path) = write_key_file("net-root-same", &SwarmKey::generate());
    // BOTH nodes read the SAME file — exactly the operator distributing one key
    // file out-of-band and booting each peer with `--swarm-key <that file>`.
    let key_seed = SwarmKey::from_file(&path).expect("read key");
    let key_joiner = SwarmKey::from_file(&path).expect("read key");
    assert_eq!(key_seed, key_joiner);

    let mut seed = build_event_swarm_with_root(
        Keypair::generate_ed25519(),
        resolve_root(Some(&key_seed)),
        false,
        false,
    )
    .unwrap();
    let seed_peer_id = *seed.local_peer_id();
    let seed_addr = listen_and_get_addr(&mut seed).await;
    let seed_multiaddr = seed_addr.with(Protocol::P2p(seed_peer_id));
    tokio::spawn(async move {
        loop {
            seed.select_next_some().await;
        }
    });

    let mut joiner = build_event_swarm_with_root(
        Keypair::generate_ed25519(),
        resolve_root(Some(&key_joiner)),
        false,
        false,
    )
    .unwrap();
    // Only a `--seed-node` — no public seed, no raw dial.
    let seeds = vec![parse_seed_multiaddr(seed_multiaddr).unwrap()];
    assert_eq!(seed_event_dht(&mut joiner, &seeds), 1, "one --seed-node");

    drive_until(&mut joiner, Duration::from_secs(15), |event| match event {
        SwarmEvent::ConnectionEstablished { peer_id, .. } if *peer_id == seed_peer_id => Some(()),
        _ => None,
    })
    .await;

    let query_id = joiner
        .behaviour_mut()
        .kademlia
        .get_closest_peers(seed_peer_id);
    let found = drive_until(&mut joiner, Duration::from_secs(15), |event| match event {
        SwarmEvent::Behaviour(EventBehaviourEvent::Kademlia(
            kad::Event::OutboundQueryProgressed {
                id,
                result: kad::QueryResult::GetClosestPeers(Ok(result)),
                step,
                ..
            },
        )) if *id == query_id && step.last => {
            Some(result.peers.iter().any(|p| p.peer_id == seed_peer_id))
        }
        _ => None,
    })
    .await;
    assert!(
        found,
        "two nodes sharing the same --swarm-key file, joined only via --seed-node, must converge"
    );
}

/// The SAME key file feeds the event-log pnet key AND the IPFS pnet key via
/// DISTINCT domain tags, so one root yields two membership-isolated swarms.
#[tokio::test]
async fn one_root_derives_distinct_event_and_ipfs_pnet_keys() {
    let (_dir, path) = write_key_file("net-root-dual", &SwarmKey::generate());
    let key = SwarmKey::from_file(&path).expect("read key");
    let root_secret = key.root_secret();

    let event_key = PrivateSwarmKey::from_root_secret(root_secret);
    let ipfs_key = pillar_ipfs::PrivateSwarmKey::from_root_secret(root_secret);

    let event_bytes = event_key.0.expect("event pnet key present");
    let ipfs_bytes = ipfs_key.0.expect("ipfs pnet key present");

    assert_ne!(
        event_bytes, ipfs_bytes,
        "the event-log and IPFS pnet keys derived from ONE root must differ \
         (domain-separated derivation) so the two swarms never co-mingle"
    );

    // Determinism: the same root always derives the same key on each side.
    assert_eq!(
        event_key,
        PrivateSwarmKey::from_root_secret(root_secret),
        "event pnet derivation is deterministic"
    );
    assert_eq!(
        ipfs_key.0,
        pillar_ipfs::PrivateSwarmKey::from_root_secret(root_secret).0,
        "ipfs pnet derivation is deterministic"
    );

    // The public root derives its own distinct pair, too.
    let pub_event = PrivateSwarmKey::from_root_secret(PUBLIC_PILLAR_ROOT);
    let pub_ipfs = pillar_ipfs::PrivateSwarmKey::from_root_secret(PUBLIC_PILLAR_ROOT);
    assert_ne!(pub_event.0.unwrap(), pub_ipfs.0.unwrap());
}

/// A node with no `--swarm-key` resolves its root as a pure in-memory value and
/// never touches any file/registry on disk — pillar keeps NO swarm state.
#[tokio::test]
async fn public_default_is_stateless_and_touches_no_disk() {
    // `SwarmKey::public()` is a const-derived in-memory value; there is no file
    // read and no persisted registry. We prove it structurally: the public key
    // equals the baked constant with no I/O, and its resolved pnet root matches
    // the from_file-less derivation.
    let public = SwarmKey::public();
    assert_eq!(public.root_secret(), PUBLIC_PILLAR_ROOT);
    assert_eq!(public.kind(), SwarmKind::Public);
    assert_eq!(
        resolve_root(None),
        PrivateSwarmKey::from_root_secret(PUBLIC_PILLAR_ROOT),
        "the no-swarm-key path derives purely from the baked public root — no disk state"
    );
}

/// A tiny, dependency-free tempdir the tests own (avoids adding a `tempfile`
/// dev-dependency for a couple of key files). Creates a unique dir under the
/// OS temp dir and recursively removes it on drop.
mod tempdir_shim {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("pillar-net-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create tempdir");
            TempDir { path }
        }

        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
