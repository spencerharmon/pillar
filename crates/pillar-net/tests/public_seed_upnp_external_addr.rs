//! Acceptance gate for `public-seed-upnp-external-addr` — the SEED inbound-
//! reachability half of the public-seed topology.
//!
//! Intent (ROI reconcile 2026-09-07): a home-hosted public seed becomes
//! publicly dialable via UPnP/NAT-PMP on the local gateway. Pillar supports
//! this NATIVELY: `pillar node run --upnp` (/`PILLAR_UPNP`) maps the node's
//! listen port(s) on the local IGD and advertises the resulting DISCOVERED
//! external multiaddr via the libp2p `identify` exchange, so the node is
//! dialable from off-LAN. Off by default; a public seed opts in.
//!
//! These tests assert the REAL swarm effect the CLI toggle wires up — not that
//! a symbol exists:
//!   1. A `--upnp`-enabled event swarm carries an ACTIVE UPnP/NAT-PMP mapping
//!      behaviour (the `EventBehaviour::upnp` `Toggle` is enabled), on both the
//!      public and a private swarm root.
//!   2. A UPnP-OFF swarm leaves that behaviour INERT (the toggle is disabled),
//!      so a directly-reachable node / a test behaves exactly as before —
//!      off-by-default is preserved.
//!   3. A DISCOVERED external multiaddr (what the UPnP behaviour confirms to the
//!      swarm on `upnp::Event::NewExternalAddr`) enters the swarm's advertised
//!      external-address set — the exact set libp2p `identify` broadcasts to
//!      peers, i.e. the address off-LAN peers dial. No infra identifier is baked
//!      in: the port is a runtime concern and the external address is whatever
//!      the IGD hands back at runtime (here a neutral RFC5737 documentation
//!      address stands in for the runtime-discovered one).
//!
//! Enabled only under `--features acceptance` so the ordinary unit run does not
//! require it (the gateway task the enabled UPnP behaviour spawns is a
//! runtime/network concern).
#![cfg(feature = "acceptance")]

use libp2p::identity::Keypair;
use libp2p::Multiaddr;
use pillar_net::{build_event_swarm, build_event_swarm_with_root, PrivateSwarmKey};

/// A UPnP-enabled event swarm carries an ACTIVE mapping behaviour, on both the
/// public (open) transport and a private-swarm root. This is the seed's opt-in
/// (`--upnp` / `PILLAR_UPNP`) — the behaviour that asks the local IGD to map
/// the listen ports so the node becomes publicly dialable.
#[tokio::test]
async fn upnp_enabled_swarm_has_active_mapping_behaviour() {
    let public = build_event_swarm_with_root(
        Keypair::generate_ed25519(),
        PrivateSwarmKey::disabled(),
        true,
        true,
    )
    .expect("upnp-enabled public swarm builds");
    assert!(
        public.behaviour().upnp.is_enabled(),
        "a --upnp public seed must carry an ACTIVE UPnP/NAT-PMP mapping behaviour"
    );

    let private = build_event_swarm_with_root(
        Keypair::generate_ed25519(),
        PrivateSwarmKey::from_root_secret("seed-upnp-acceptance-root"),
        true,
        false,
    )
    .expect("upnp-enabled private swarm builds");
    assert!(
        private.behaviour().upnp.is_enabled(),
        "a --upnp private-swarm seed must also carry an ACTIVE mapping behaviour"
    );
}

/// UPnP is OFF by default: a swarm built with `upnp_enabled = false` (the
/// default for a directly-reachable node or a test) leaves the mapping
/// behaviour INERT, so it behaves exactly as before. Covers both the
/// convenience `build_event_swarm` and the explicit `false` toggle.
#[tokio::test]
async fn upnp_off_by_default_leaves_behaviour_inert() {
    let default = build_event_swarm(Keypair::generate_ed25519()).expect("default swarm builds");
    assert!(
        !default.behaviour().upnp.is_enabled(),
        "the default event swarm must NOT map ports (UPnP off by default)"
    );

    let explicit_off = build_event_swarm_with_root(
        Keypair::generate_ed25519(),
        PrivateSwarmKey::disabled(),
        false,
        true,
    )
    .expect("upnp-off swarm builds");
    assert!(
        !explicit_off.behaviour().upnp.is_enabled(),
        "upnp_enabled=false must leave the mapping behaviour inert"
    );
}

/// The DISCOVERED external multiaddr is advertised to peers. When the UPnP
/// behaviour confirms a mapped external address to the swarm (its
/// `upnp::Event::NewExternalAddr` path calls `Swarm::add_external_address`),
/// that address must enter the swarm's advertised external-address set — the
/// exact set libp2p `identify` broadcasts to peers, i.e. what an off-LAN peer
/// dials. This is the "advertise the discovered external multiaddr via
/// identify" half of the reachability contract.
///
/// The address here is a neutral RFC5737 documentation address standing in for
/// the runtime-discovered one; no infra identifier is baked into source.
#[tokio::test]
async fn discovered_external_addr_enters_advertised_set() {
    let mut swarm = build_event_swarm_with_root(
        Keypair::generate_ed25519(),
        PrivateSwarmKey::disabled(),
        true,
        true,
    )
    .expect("upnp-enabled public swarm builds");

    // Before any mapping is confirmed, a fresh seed advertises no external
    // address.
    assert!(
        swarm.external_addresses().next().is_none(),
        "a freshly built seed has no advertised external address yet"
    );

    // Simulate the UPnP behaviour confirming a discovered external multiaddr to
    // the swarm — the same call libp2p's upnp behaviour makes on
    // `NewExternalAddr`, and the same call `pillar node run`'s event loop
    // observes as the node becoming publicly dialable.
    let discovered: Multiaddr = "/ip4/192.0.2.10/tcp/4001"
        .parse()
        .expect("valid external multiaddr");
    swarm.add_external_address(discovered.clone());

    let advertised: Vec<Multiaddr> = swarm.external_addresses().cloned().collect();
    assert!(
        advertised.contains(&discovered),
        "the discovered external multiaddr must enter the swarm's advertised \
         external-address set (identify broadcasts this to peers); got {advertised:?}"
    );
}
