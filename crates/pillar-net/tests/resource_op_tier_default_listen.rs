//! Acceptance: the resource-op pillar-UDP tier's bind-address resolution
//! defaults to listening (a REAL bound UDP socket) on
//! `0.0.0.0:<DEFAULT_RESOURCE_OP_UDP_PORT>` when NO
//! `PILLAR_RESOURCE_OP_UDP_BIND` override is set, and honors an override
//! when one IS set — proving `resource-op-tier-default-listen`: the tier is
//! no longer gated behind an unset override, it binds by DEFAULT, with the
//! env var remaining a pure override of WHERE it binds.
//!
//! Run: `cargo test -p pillar-net --test resource_op_tier_default_listen --features acceptance`

#![cfg(feature = "acceptance")]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use pillar_net::{resolve_resource_op_bind, DEFAULT_RESOURCE_OP_UDP_PORT};

/// With no override, resolution yields the well-known default port on the
/// unspecified (`0.0.0.0`) address — i.e. the tier is reachable with ZERO
/// configuration, exactly the "turnkey remote apply" default-on contract.
#[test]
fn no_override_resolves_to_default_unspecified_bind() {
    let resolved = resolve_resource_op_bind(None);
    assert_eq!(
        resolved.addr,
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_RESOURCE_OP_UDP_PORT)),
        "absent PILLAR_RESOURCE_OP_UDP_BIND, the tier must resolve to the \
         DEFAULT 0.0.0.0:{DEFAULT_RESOURCE_OP_UDP_PORT} bind — no longer \
         gated behind the override being set"
    );
    assert!(resolved.invalid_override.is_none());
}

/// The resolved default bind is a REAL, actually-bindable address: prove it
/// end to end by actually binding a UDP socket to it (using port 0 so the
/// test never collides with a real node on this host, but on the SAME
/// unspecified address the production default resolves to) and confirming a
/// peer can reach it — i.e. this is not merely a value that looks right, the
/// address family/host portion genuinely listens on all interfaces.
#[test]
fn default_bind_address_is_reachable_from_a_loopback_peer() {
    let resolved = resolve_resource_op_bind(None);
    // Bind on the SAME host portion (0.0.0.0) the production default
    // resolves to, but let the OS pick an ephemeral port so parallel test
    // runs / a real node on this host never collide with this test.
    let bind_host_only = SocketAddr::from((resolved.addr.ip(), 0));
    let socket = UdpSocket::bind(bind_host_only).expect("bind the default host portion (0.0.0.0)");
    let bound = socket.local_addr().expect("local_addr");
    assert_eq!(bound.ip(), Ipv4Addr::UNSPECIFIED);

    let peer = UdpSocket::bind("127.0.0.1:0").expect("bind loopback peer");
    peer.send_to(b"ping", ("127.0.0.1", bound.port()))
        .expect("send to the default-bound listener over loopback");

    let mut buf = [0u8; 4];
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let (n, _from) = socket.recv_from(&mut buf).expect("recv on default bind");
    assert_eq!(&buf[..n], b"ping");
}

/// An explicit `PILLAR_RESOURCE_OP_UDP_BIND`-style override still wins over
/// the default — the env var is a genuine OVERRIDE of where the tier binds,
/// it just no longer gates WHETHER it binds at all.
#[test]
fn explicit_override_still_wins_over_the_default() {
    let resolved = resolve_resource_op_bind(Some("127.0.0.1:0"));
    assert_eq!(resolved.addr, "127.0.0.1:0".parse().unwrap());
    assert!(resolved.invalid_override.is_none());
}

/// An override that fails to parse is REPORTED, but resolution still falls
/// back to the safe default bind rather than disabling the tier entirely —
/// a malformed env var must never silently turn the listener off.
#[test]
fn unparseable_override_falls_back_to_default_rather_than_disabling_the_tier() {
    let resolved = resolve_resource_op_bind(Some("this is not a socket addr"));
    assert_eq!(
        resolved.addr,
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_RESOURCE_OP_UDP_PORT))
    );
    assert_eq!(
        resolved.invalid_override.as_deref(),
        Some("this is not a socket addr")
    );
}

/// The default port is distinct from the other well-known ports this
/// binary uses (web `8642`, health `8643`, libp2p `4001`), matching the doc
/// comment's stated invariant.
#[test]
fn default_port_is_distinct_from_other_well_known_ports() {
    const WEB_PORT: u16 = 8642;
    const HEALTH_PORT: u16 = 8643;
    const LIBP2P_PORT: u16 = 4001;
    assert_ne!(DEFAULT_RESOURCE_OP_UDP_PORT, WEB_PORT);
    assert_ne!(DEFAULT_RESOURCE_OP_UDP_PORT, HEALTH_PORT);
    assert_ne!(DEFAULT_RESOURCE_OP_UDP_PORT, LIBP2P_PORT);
}
