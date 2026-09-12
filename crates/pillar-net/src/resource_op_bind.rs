//! The resource-op pillar-UDP tier's DEFAULT bind address resolution
//! (`resource-op-tier-default-listen`, 2026-09-12 ROI HEAD).
//!
//! Lives in `pillar-net` (the transport substrate) rather than `pillar-cli`
//! so the "bind by default, override via env" policy is a single testable,
//! pure function shared by whatever tier consumes it — never re-derived ad
//! hoc at each call site. This is a **default-on** listener: unlike the
//! opt-in `psl-message-api` tiers ([`crate::pillarmsg_udp`]'s callers, gated
//! entirely behind an env var being SET), the resource-op tier binds on
//! `0.0.0.0:<DEFAULT_RESOURCE_OP_UDP_PORT>` with NO env var required, so a
//! fresh node is mutable via `pillar apply` with zero configuration.
//! `PILLAR_RESOURCE_OP_UDP_BIND` remains a pure OVERRIDE of that default; it
//! no longer gates whether the tier listens at all.
//!
//! The default port is a single declared constant, documented alongside this
//! binary's other well-known ports: the web UI `8642`
//! (`pillar_cli::run::DEFAULT_WEB_PORT`), the TCP health probe `8643`
//! (`pillar_cli::health::DEFAULT_HEALTH_PORT`), and the libp2p peer `4001`.
//! `8644` is distinct from all three.
//!
//! Every op received on this tier is sealed + signed + RBAC-checked before
//! it can mutate anything (see `pillar_cli::resource_op_udp_server`), so a
//! `0.0.0.0` default bind exposes only an authenticated mutation surface —
//! it is not an open door. The interim solo-node cell-group-key derivation is
//! correct for a single-member cell today; multi-member group-key
//! coordination is a separate follow-up and must NOT block default-on.

use std::net::{Ipv4Addr, SocketAddr};

/// The well-known default UDP port the resource-op pillar-UDP tier binds
/// when no [`RESOURCE_OP_UDP_BIND_ENV`] override is set — chosen distinct
/// from web `8642`, the health probe `8643`, and the libp2p peer `4001`.
pub const DEFAULT_RESOURCE_OP_UDP_PORT: u16 = 8644;

/// The environment variable that OVERRIDES the resource-op pillar-UDP tier's
/// default bind address/port. Absent (the normal, zero-config case), the
/// tier binds on `0.0.0.0:{DEFAULT_RESOURCE_OP_UDP_PORT}` by DEFAULT — this
/// var is no longer required to make the tier listen at all, only to change
/// where it listens.
pub const RESOURCE_OP_UDP_BIND_ENV: &str = "PILLAR_RESOURCE_OP_UDP_BIND";

/// Resolve the socket address the resource-op pillar-UDP tier should bind:
/// the value of `override_value` (normally `std::env::var(RESOURCE_OP_UDP_BIND_ENV).ok()`)
/// if present and it parses as a [`SocketAddr`], else the DEFAULT
/// `0.0.0.0:{DEFAULT_RESOURCE_OP_UDP_PORT}` — never "no bind at all". An
/// override value that fails to parse is reported back (so the caller can
/// warn) but resolution still falls back to the default rather than
/// disabling the tier.
#[must_use]
pub fn resolve_resource_op_bind(override_value: Option<&str>) -> ResolvedBind {
    let default_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_RESOURCE_OP_UDP_PORT));
    match override_value {
        None => ResolvedBind {
            addr: default_addr,
            invalid_override: None,
        },
        Some(raw) => match raw.parse::<SocketAddr>() {
            Ok(addr) => ResolvedBind {
                addr,
                invalid_override: None,
            },
            Err(_) => ResolvedBind {
                addr: default_addr,
                invalid_override: Some(raw.to_string()),
            },
        },
    }
}

/// The result of [`resolve_resource_op_bind`]: the address to bind, plus the
/// raw override string if one was supplied but failed to parse (so the
/// caller can log a warning while still falling back safely to the default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBind {
    /// The socket address to bind — always a real address, never absent.
    pub addr: SocketAddr,
    /// `Some(raw)` when an override was supplied but did not parse as a
    /// `SocketAddr`; resolution fell back to the default in that case.
    pub invalid_override: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_override_defaults_to_unspecified_default_port() {
        let resolved = resolve_resource_op_bind(None);
        assert_eq!(
            resolved.addr,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_RESOURCE_OP_UDP_PORT))
        );
        assert!(resolved.invalid_override.is_none());
    }

    #[test]
    fn valid_override_wins() {
        let resolved = resolve_resource_op_bind(Some("127.0.0.1:9999"));
        assert_eq!(resolved.addr, "127.0.0.1:9999".parse().unwrap());
        assert!(resolved.invalid_override.is_none());
    }

    #[test]
    fn invalid_override_falls_back_to_default_with_a_report() {
        let resolved = resolve_resource_op_bind(Some("not-an-addr"));
        assert_eq!(
            resolved.addr,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, DEFAULT_RESOURCE_OP_UDP_PORT))
        );
        assert_eq!(resolved.invalid_override.as_deref(), Some("not-an-addr"));
    }
}
