//! `pillar ingress-lb-udp serve <manifest.json>` — the REAL external surface
//! that wires [`pillar_net::UdpDataplane`] (a real UDP ingress LB dataplane
//! over real `tokio::net::UdpSocket`s) into the published `pillar` binary.
//!
//! Before this module existed, `UdpDataplane` was reachable ONLY from
//! `#[cfg(feature = "acceptance")]` Rust integration tests that link
//! `pillar-net` directly and spawn the dataplane in-process — there was no
//! CLI verb, HTTP route, or listening port a black-box container harness
//! could dial to exercise it, per the ROI's absolute mandate that
//! `pillar-integration` drive every forcing function through pillar's real
//! external surfaces only (never link a pillar crate, never reach into
//! process memory).
//!
//! This verb closes that gap: it reads a small JSON manifest naming a VIP,
//! a set of real backend `ip:port`s, and an LB policy (algorithm / affinity /
//! active health), constructs the real backend address list, and calls
//! [`pillar_net::UdpDataplane::bind`] — the exact same engine the acceptance
//! tests already exercise in-process. The bound VIP address is printed to
//! stdout as `LISTENING <ip:port>\n` (flushed immediately) so a harness that
//! bound an ephemeral port (`"...:0"`, or a container-runtime `-p` publish)
//! can resolve the concrete socket the same way
//! `scripts/pillar-integration/lib/topology.sh` resolves the existing
//! readiness-probe port. The process then blocks forever (Ctrl-C / SIGINT to
//! stop), exactly like `pillar node run`.
//!
//! ## Manifest format
//!
//! ```json
//! {
//!   "vip": "127.0.0.1:0",
//!   "backends": [
//!     {"id": "b0", "addr": "127.0.0.1:9001"},
//!     {"id": "b1", "addr": "127.0.0.1:9002"}
//!   ],
//!   "algorithm": "round_robin",
//!   "affinity": "none",
//!   "active_health": true,
//!   "health_interval_ms": 250
//! }
//! ```
//!
//! `algorithm` is one of `round_robin` | `least_conn` | `consistent_hash`
//! (matching [`pillar_manifest::ingress::Algorithm`]); `affinity` is one of
//! `none` | `sticky` (matching
//! [`pillar_manifest::ingress::Affinity`]).

use std::net::SocketAddr;

use pillar_manifest::ingress::{Affinity, Algorithm, HealthCheck, LoadBalancerPolicy};
use pillar_net::UdpDataplane;
use serde::Deserialize;

/// The on-disk JSON shape this verb parses. Deliberately independent of the
/// full `Frontend`/`Route`/WoT-attestation manifest model (which carries no
/// backend socket addresses): this is the concrete address-bearing manifest a
/// deployment or test harness hands the dataplane to actually bind and
/// forward with.
#[derive(Debug, Deserialize)]
struct DataplaneManifest {
    /// The VIP `ip:port` to bind (`"...:0"` binds an ephemeral port).
    vip: String,
    /// The real backend addresses to forward to.
    backends: Vec<BackendSpec>,
    /// `"round_robin" | "least_conn" | "consistent_hash"`.
    #[serde(default = "default_algorithm")]
    algorithm: String,
    /// `"none" | "sticky"`.
    #[serde(default = "default_affinity")]
    affinity: String,
    /// Whether to run active health probing (dead backends are dropped).
    #[serde(default = "default_active_health")]
    active_health: bool,
    /// Active health probe interval, in milliseconds.
    #[serde(default = "default_health_interval_ms")]
    health_interval_ms: u32,
}

fn default_algorithm() -> String {
    "round_robin".to_owned()
}
fn default_affinity() -> String {
    "none".to_owned()
}
fn default_active_health() -> bool {
    true
}
fn default_health_interval_ms() -> u32 {
    1000
}

#[derive(Debug, Deserialize)]
struct BackendSpec {
    id: String,
    addr: String,
}

/// Parse `text` (the manifest file's contents) into the real backend address
/// list and [`LoadBalancerPolicy`] `UdpDataplane::bind` needs.
fn parse_manifest(text: &str) -> Result<(String, Vec<(String, SocketAddr)>, LoadBalancerPolicy), String> {
    let manifest: DataplaneManifest =
        serde_json::from_str(text).map_err(|e| format!("invalid manifest JSON: {e}"))?;

    if manifest.backends.is_empty() {
        return Err("manifest must name at least one backend".to_owned());
    }

    let mut backends = Vec::with_capacity(manifest.backends.len());
    for b in &manifest.backends {
        let addr: SocketAddr = b
            .addr
            .parse()
            .map_err(|e| format!("backend `{}` has invalid addr `{}`: {e}", b.id, b.addr))?;
        backends.push((b.id.clone(), addr));
    }

    let algorithm = match manifest.algorithm.as_str() {
        "round_robin" => Algorithm::RoundRobin,
        "least_conn" => Algorithm::LeastConn,
        "consistent_hash" => Algorithm::ConsistentHash,
        other => return Err(format!("unknown algorithm `{other}`")),
    };
    let affinity = match manifest.affinity.as_str() {
        "none" => Affinity::None,
        "sticky" => Affinity::Sticky,
        other => return Err(format!("unknown affinity `{other}`")),
    };

    let policy = LoadBalancerPolicy {
        algorithm,
        affinity,
        locality_tier: None,
        health: HealthCheck {
            active: manifest.active_health,
            interval_ms: manifest.health_interval_ms,
        },
        consistency_class: pillar_core::SideEffect::Convergent,
    };

    Ok((manifest.vip, backends, policy))
}

/// `pillar ingress-lb-udp serve <manifest.json>`: bind the real
/// [`UdpDataplane`] the manifest describes and block until interrupted.
/// Prints `LISTENING <ip:port>` on stdout the instant the VIP socket is
/// bound (before blocking), so a harness driving this process can resolve
/// the concrete bound address (including an ephemeral `:0` VIP).
pub async fn serve(manifest_path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(manifest_path)
        .map_err(|e| format!("cannot read manifest `{manifest_path}`: {e}"))?;
    let (vip, backends, policy) = parse_manifest(&text)?;

    let dataplane = UdpDataplane::bind(&vip, &backends, policy)
        .await
        .map_err(|e| format!("failed to bind VIP `{vip}`: {e}"))?;

    // Emit the concrete bound address immediately and flush so a harness
    // reading this process's stdout line-by-line never blocks on buffering.
    println!("LISTENING {}", dataplane.vip_addr());
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

    // Block forever (Ctrl-C / SIGINT stops the process, dropping the
    // dataplane and its forwarding/health tasks), exactly like `pillar node
    // run`.
    match tokio::signal::ctrl_c().await {
        Ok(()) => {}
        Err(_) => {
            // No ctrl-c signal available (non-interactive harness): park the
            // task forever instead of exiting, so the dataplane keeps
            // forwarding until the process is killed.
            std::future::pending::<()>().await;
        }
    }
    drop(dataplane);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_manifest() {
        let text = r#"{
            "vip": "127.0.0.1:0",
            "backends": [
                {"id": "b0", "addr": "127.0.0.1:9001"},
                {"id": "b1", "addr": "127.0.0.1:9002"}
            ],
            "algorithm": "least_conn",
            "affinity": "sticky",
            "active_health": false,
            "health_interval_ms": 250
        }"#;
        let (vip, backends, policy) = parse_manifest(text).expect("parses");
        assert_eq!(vip, "127.0.0.1:0");
        assert_eq!(backends.len(), 2);
        assert_eq!(backends[0].0, "b0");
        assert_eq!(policy.algorithm, Algorithm::LeastConn);
        assert_eq!(policy.affinity, Affinity::Sticky);
        assert!(!policy.health.active);
        assert_eq!(policy.health.interval_ms, 250);
    }

    #[test]
    fn defaults_apply_when_fields_are_absent() {
        let text = r#"{
            "vip": "127.0.0.1:0",
            "backends": [{"id": "b0", "addr": "127.0.0.1:9001"}]
        }"#;
        let (_, _, policy) = parse_manifest(text).expect("parses");
        assert_eq!(policy.algorithm, Algorithm::RoundRobin);
        assert_eq!(policy.affinity, Affinity::None);
        assert!(policy.health.active);
        assert_eq!(policy.health.interval_ms, 1000);
    }

    #[test]
    fn rejects_empty_backends() {
        let text = r#"{"vip": "127.0.0.1:0", "backends": []}"#;
        assert!(parse_manifest(text).is_err());
    }

    #[test]
    fn rejects_bad_backend_addr() {
        let text = r#"{"vip": "127.0.0.1:0", "backends": [{"id": "b0", "addr": "not-an-addr"}]}"#;
        assert!(parse_manifest(text).is_err());
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let text = r#"{"vip": "127.0.0.1:0", "backends": [{"id": "b0", "addr": "127.0.0.1:9001"}], "algorithm": "bogus"}"#;
        assert!(parse_manifest(text).is_err());
    }
}
