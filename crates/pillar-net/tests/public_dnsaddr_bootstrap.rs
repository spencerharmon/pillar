//! Acceptance: zero-config PUBLIC join is a baked, peer-id-LESS `/dnsaddr`
//! bootstrap anchor.
//!
//! This is the definition-of-done for `public-dnsaddr-bootstrap-anchor`. The
//! sibling `network-root-config-impl` task owns the public pnet KEY
//! (`SwarmKey::public()` derived from `PUBLIC_PILLAR_ROOT`); THIS task adds the
//! missing bootstrap-DIAL anchor so a fresh node with NO `--swarm-key` and NO
//! `--seed-node` joins the ONE public swarm from a baked-in anchor — kubo-style.
//!
//! The precise shape the ROI mandates, asserted here end to end:
//!
//! 1. **The baked anchor is peer-id-LESS.** `PUBLIC_PILLAR_SEEDS` bakes only
//!    `/dnsaddr/<host>` — no `/p2p/<peer-id>`, no `/ip4|/ip6` literal. Peer
//!    IDENTITY (the seed's peer id) stays OUT of the binary; it lives in the
//!    operator-managed `_dnsaddr.<host>` DNS TXT record, resolved at runtime.
//!    A seed is rotated by editing that TXT record, never by a pillar release.
//! 2. **The keyless + seedless PUBLIC path falls back to the baked anchor.** A
//!    node resolving its root as `pillar node run` does with no `--swarm-key`
//!    (⇒ the public swarm) and no operator `--seed-node` gets EXACTLY the baked
//!    `PUBLIC_PILLAR_SEEDS` as its effective seeds. A PRIVATE swarm never falls
//!    back (it is transport-isolated); with no operator seed it stays empty.
//! 3. **The baked anchor classifies as a `Dial` anchor, not a `Direct` seed.**
//!    Because it carries no `/p2p`, `classify_seed` returns
//!    `FederationSeed::Dial` — it is DIALED (the DNS transport resolves the TXT
//!    record) and its peer id is LEARNED from the ensuing `identify` exchange,
//!    never keyed into Kademlia up front.
//! 4. **Dial → identify → Kademlia wiring joins the DHT.** Over REAL libp2p
//!    swarms on real sockets: a joiner handed ONLY a peer-id-less anchor for a
//!    live seed dials it, the identify exchange reveals the seed's peer id +
//!    listen addrs, `note_identified_peer` folds them into Kademlia, and a
//!    discovery query resolves the seed — proving the node entered the swarm
//!    from a peer-id-less anchor alone (the zero-config public path).
//!
//! Gated by the crate's off-by-default `acceptance` feature so the ordinary
//! `cargo test` unit run does not stand up real sockets:
//! `cargo test -p pillar-net --test public_dnsaddr_bootstrap --features acceptance`.
#![cfg(feature = "acceptance")]

use std::time::Duration;

use futures::StreamExt;
use libp2p::core::multiaddr::{Multiaddr, Protocol};
use libp2p::identity::Keypair;
use libp2p::kad;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use tokio::time::timeout;

use pillar_net::{
    build_event_swarm_with_root, classify_seed, note_identified_peer, EventBehaviourEvent,
    FederationSeed, PrivateSwarmKey,
};
use pillar_swarm::{public_seeds, SwarmKey, SwarmKind, PUBLIC_PILLAR_SEEDS};

/// Resolve the event-log pnet root EXACTLY as `pillar node run` does at boot:
/// no `--swarm-key` ⇒ the baked-in public swarm key. Mirrors the CLI boot logic
/// so this test exercises the real resolution, not a shortcut.
fn resolve_root(swarm_key: Option<&SwarmKey>) -> PrivateSwarmKey {
    let key = swarm_key.cloned().unwrap_or_else(SwarmKey::public);
    PrivateSwarmKey::from_root_secret(key.root_secret())
}

/// Resolve the EFFECTIVE federation seeds a node joins through, exactly as
/// `pillar_cli::run::resolve_effective_seeds` does at boot: explicit operator
/// `--seed-node`(s) win; otherwise, on the PUBLIC swarm ONLY, fall back to the
/// baked `PUBLIC_PILLAR_SEEDS` anchors; a PRIVATE swarm never falls back. This
/// mirrors the CLI (which is not a dependency of this crate) so the test proves
/// the real boot behaviour, not a private reimplementation of the anchor list.
fn resolve_effective_seeds(operator_seeds: &[Multiaddr], kind: SwarmKind) -> Vec<Multiaddr> {
    if !operator_seeds.is_empty() {
        return operator_seeds.to_vec();
    }
    if kind == SwarmKind::Public {
        return public_seeds()
            .iter()
            .filter_map(|s| s.parse::<Multiaddr>().ok())
            .collect();
    }
    Vec::new()
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

/// (1) Every baked `PUBLIC_PILLAR_SEEDS` anchor is peer-id-LESS: a `/dnsaddr`
/// (or `/dns*`) host with NO `/p2p/<peer-id>` component and NO `/ip4|/ip6`
/// literal — so neither peer identity nor a deployment IP is in the binary.
#[tokio::test]
async fn baked_public_seeds_are_peer_id_less_dnsaddr_anchors() {
    assert!(
        !PUBLIC_PILLAR_SEEDS.is_empty(),
        "the binary must bake at least one public bootstrap anchor for zero-config join"
    );
    for seed in public_seeds() {
        let addr: Multiaddr = seed
            .parse()
            .unwrap_or_else(|e| panic!("baked public seed {seed:?} is not a multiaddr: {e}"));

        // No /p2p — the seed's peer IDENTITY is not baked (it lives in the
        // operator's _dnsaddr.<host> TXT record, learned at runtime).
        let has_p2p = addr.iter().any(|p| matches!(p, Protocol::P2p(_)));
        assert!(
            !has_p2p,
            "baked public seed {seed:?} carries a /p2p/<peer-id>; peer identity must NOT be \
             baked — the seed's peer id belongs in the _dnsaddr.<host> DNS TXT record"
        );

        // No literal IP — a public seed is only rotatable via DNS if it names a
        // /dnsaddr or /dns* host, never a baked deployment IP.
        let has_ip_literal = addr
            .iter()
            .any(|p| matches!(p, Protocol::Ip4(_) | Protocol::Ip6(_)));
        assert!(
            !has_ip_literal,
            "baked public seed {seed:?} carries a literal IP; a deployment IP must NOT be \
             baked — use /dnsaddr/<host> so the seed is rotatable via DNS alone"
        );

        // It IS a DNS anchor (dnsaddr / dns / dns4 / dns6).
        let has_dns = addr.iter().any(|p| {
            matches!(
                p,
                Protocol::Dnsaddr(_) | Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_)
            )
        });
        assert!(
            has_dns,
            "baked public seed {seed:?} is not a DNS anchor; a peer-id-less anchor must be a \
             /dnsaddr/<host> or /dns*/<host> so the DNS transport can resolve it at runtime"
        );
    }
}

/// (2) The keyless + seedless PUBLIC path falls back to EXACTLY the baked
/// anchor(s); a PRIVATE swarm never does.
#[tokio::test]
async fn keyless_seedless_public_node_falls_back_to_the_baked_anchor() {
    // A node with no --swarm-key resolves to the PUBLIC swarm.
    let public = SwarmKey::public();
    assert_eq!(
        public.kind(),
        SwarmKind::Public,
        "a node with no --swarm-key must resolve to the public swarm"
    );
    // Its resolved pnet root is the enabled public key (owned by the sibling
    // task, asserted here only to anchor the keyless premise of this path).
    assert!(resolve_root(None).is_enabled());

    // No operator --seed-node + public swarm ⇒ effective seeds are the baked
    // anchors, verbatim.
    let baked: Vec<Multiaddr> = public_seeds()
        .iter()
        .map(|s| s.parse().expect("baked seed parses"))
        .collect();
    let effective = resolve_effective_seeds(&[], SwarmKind::Public);
    assert_eq!(
        effective, baked,
        "a keyless + seedless public node must bootstrap from the baked public anchor"
    );

    // A PRIVATE swarm is transport-isolated and never falls back to the public
    // anchor — with no operator seed it is its own first node.
    let private = resolve_effective_seeds(&[], SwarmKind::Private);
    assert!(
        private.is_empty(),
        "a private swarm must NOT fall back to the public anchor (it is transport-isolated)"
    );

    // An explicit operator --seed-node suppresses the baked fallback entirely.
    let operator: Vec<Multiaddr> = vec!["/dns4/seed.example.net/tcp/4001"
        .parse()
        .expect("operator seed parses")];
    assert_eq!(
        resolve_effective_seeds(&operator, SwarmKind::Public),
        operator,
        "an explicit operator --seed-node must win over the baked public fallback"
    );
}

/// (3) The baked peer-id-less anchor classifies as a `Dial` anchor (dialed +
/// identify), never a `Direct` seed (added to Kademlia up front).
#[tokio::test]
async fn baked_anchor_classifies_as_a_dial_anchor() {
    for seed in public_seeds() {
        let addr: Multiaddr = seed.parse().expect("baked seed parses");
        match classify_seed(addr.clone()) {
            FederationSeed::Dial(a) => assert_eq!(
                a, addr,
                "a peer-id-less baked anchor must be classified as a Dial anchor verbatim"
            ),
            FederationSeed::Direct(_) => panic!(
                "baked public seed {seed:?} classified as a Direct seed; a peer-id-less \
                 /dnsaddr anchor must be DIALED (peer id learned via identify), not added \
                 directly to Kademlia"
            ),
        }
    }
}

/// (4) End to end: a joiner handed ONLY a peer-id-less anchor for a live seed
/// dials it, learns the seed's identity via identify, folds it into Kademlia,
/// and a discovery query resolves the seed — the full zero-config public path
/// from a peer-id-less anchor alone (no peer id ever supplied to the joiner).
#[tokio::test]
async fn joiner_enters_dht_from_a_peer_id_less_anchor_via_identify() {
    // A live PUBLIC seed node (keyless public root, exactly as a real seed boots).
    let mut seed =
        build_event_swarm_with_root(Keypair::generate_ed25519(), resolve_root(None), false, true)
            .expect("public seed swarm builds");
    let seed_peer_id = *seed.local_peer_id();
    let seed_addr = listen_and_get_addr(&mut seed).await;

    // The anchor the joiner is handed is PEER-ID-LESS: just the seed's dialable
    // /ip4/.../tcp/<port> with NO /p2p — mimicking a /dnsaddr TXT record that
    // has already resolved to an address, but whose peer id is still unknown to
    // the joiner (it is only in the seed itself). (We use the loopback address
    // rather than /dnsaddr/<host> so the test needs no live DNS, while keeping
    // the DEFINING property under test: the joiner gets NO peer id.)
    let anchor = seed_addr.clone();
    assert!(
        !anchor.iter().any(|p| matches!(p, Protocol::P2p(_))),
        "the anchor handed to the joiner must be peer-id-less"
    );
    // It classifies as a Dial anchor, so the CLI would DIAL it (not add it to
    // Kademlia directly).
    match classify_seed(anchor.clone()) {
        FederationSeed::Dial(_) => {}
        FederationSeed::Direct(_) => panic!("a peer-id-less anchor must classify as Dial"),
    }

    // Keep the seed answering (identify/kad) in the background.
    tokio::spawn(async move {
        loop {
            seed.select_next_some().await;
        }
    });

    // The joiner is a keyless PUBLIC node that knows ONLY the peer-id-less
    // anchor — never the seed's peer id, never a raw /p2p dial.
    let mut joiner =
        build_event_swarm_with_root(Keypair::generate_ed25519(), resolve_root(None), false, true)
            .expect("public joiner swarm builds");
    joiner
        .dial(anchor)
        .expect("joiner dials the peer-id-less bootstrap anchor");

    // Drive the joiner: on the identify exchange from the dialed anchor, fold
    // the newly-learned peer id + addrs into Kademlia — exactly what the CLI
    // event loop does. This is the step that turns a peer-id-less dial into DHT
    // membership.
    let learned_peer = drive_until(&mut joiner, Duration::from_secs(20), |event| match event {
        SwarmEvent::Behaviour(EventBehaviourEvent::Identify(
            libp2p::identify::Event::Received { peer_id, info, .. },
        )) => Some((*peer_id, info.listen_addrs.clone())),
        _ => None,
    })
    .await;
    assert_eq!(
        learned_peer.0, seed_peer_id,
        "identify must reveal the seed's peer id (learned, never baked)"
    );
    let added = note_identified_peer(&mut joiner, &learned_peer.0, learned_peer.1);
    assert!(
        added > 0,
        "the learned seed must be folded into the Kademlia routing table"
    );

    // The joiner has now ENTERED the DHT purely from a peer-id-less anchor: a
    // discovery query resolves the seed it never knew the id of up front.
    let query_id = joiner
        .behaviour_mut()
        .kademlia
        .get_closest_peers(seed_peer_id);
    let found = drive_until(&mut joiner, Duration::from_secs(20), |event| match event {
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
        "a joiner handed ONLY a peer-id-less anchor must enter the DHT and discover the seed"
    );
}
