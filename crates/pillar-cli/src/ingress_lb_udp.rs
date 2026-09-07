//! `pillar ingress-lb-udp serve <manifest>` — the REAL external surface that
//! stands the [`UdpDataplane`](pillar_net::UdpDataplane) up on the published
//! image so a black-box harness can drive it with real client packets.
//!
//! The library `UdpDataplane` (a real LB dataplane over real
//! [`tokio::net::UdpSocket`]s: RoundRobin/LeastConn/ConsistentHash + affinity +
//! active health + failover) was previously reachable ONLY from in-crate
//! acceptance tests that link the crate and bind it in-process. This module is
//! the missing external drive point: a CLI verb (and a
//! `PILLAR_INGRESS_LB_UDP_MANIFEST` env var read by `node run`) that parses a
//! `Frontend` + `Route` + `LoadBalancerPolicy` manifest naming a VIP:port and a
//! set of backend `ip:port`s, binds the real dataplane, and PUBLISHES the bound
//! VIP address on stdout — so a container-runtime `-p` mapping (or
//! `docker/podman port`) can resolve it exactly like the health-probe port.
//!
//! The manifest text format is deliberately line-oriented and drivable from a
//! shell harness (no signing/authority pipeline needed to stand up a dataplane
//! a packet oracle observes) — it maps directly onto the manifest model's
//! [`Frontend`]/[`Route`]/[`LoadBalancerPolicy`]/[`Algorithm`]/[`Affinity`]
//! types, never a parallel schema:
//!
//! ```text
//! # comments and blank lines ignored
//! frontend <name> <vip-ip>
//! listen <port>
//! algorithm round-robin | least-conn | consistent-hash
//! affinity none | sticky
//! health active <interval-ms> | health none
//! backend <id> <ip:port>
//! backend <id> <ip:port>
//! ...
//! ```
//!
//! `serve` binds the dataplane and blocks forever (until the process is
//! signalled), so the node stays reachable. It first prints exactly one
//! machine-readable line to stdout:
//!
//! ```text
//! ingress-lb-udp listening vip=<ip:port> backends=<n>
//! ```
//!
//! A harness reads that line to learn the concrete bound port (an ephemeral
//! `:0` listen resolves here), then sends real client datagrams to it.

use std::net::SocketAddr;

use pillar_core::SideEffect;
use pillar_manifest::ingress::{
    Affinity, Algorithm, HealthCheck, LoadBalancerPolicy,
};
use pillar_net::UdpDataplane;

/// A parsed ingress-lb-udp manifest: the VIP the dataplane binds, the concrete
/// backend `(id, addr)` table it forwards to, and the LB policy that governs
/// selection — all lowered from the manifest model's own types.
#[derive(Clone, Debug)]
pub struct IngressLbUdpManifest {
    /// The VIP `ip:port` the dataplane binds (`port` 0 = ephemeral).
    pub vip: String,
    /// The backend id + real UDP socket address table.
    pub backends: Vec<(String, SocketAddr)>,
    /// The load-balancer policy governing backend selection.
    pub policy: LoadBalancerPolicy,
}

/// A manifest parse/serve failure with a human-readable reason.
#[derive(Debug)]
pub struct IngressLbUdpError(pub String);

impl std::fmt::Display for IngressLbUdpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for IngressLbUdpError {}

impl IngressLbUdpManifest {
    /// Parse the line-oriented manifest text (see the module docs for the
    /// grammar) into a bindable manifest.
    ///
    /// # Errors
    /// Returns [`IngressLbUdpError`] on any malformed directive, a missing
    /// `frontend`/`listen`, an unparseable backend address, or an unknown
    /// algorithm/affinity keyword.
    pub fn parse(text: &str) -> Result<Self, IngressLbUdpError> {
        let mut frontend_ip: Option<String> = None;
        let mut listen_port: Option<u16> = None;
        let mut algorithm = Algorithm::RoundRobin;
        let mut affinity = Affinity::None;
        let mut health = HealthCheck {
            active: true,
            interval_ms: 1000,
        };
        let mut backends: Vec<(String, SocketAddr)> = Vec::new();

        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.split_whitespace();
            let directive = it.next().unwrap_or("");
            let err = |m: String| IngressLbUdpError(format!("line {}: {m}", lineno + 1));
            match directive {
                "frontend" => {
                    let _name = it
                        .next()
                        .ok_or_else(|| err("`frontend` needs <name> <vip-ip>".into()))?;
                    let ip = it
                        .next()
                        .ok_or_else(|| err("`frontend` needs a <vip-ip>".into()))?;
                    frontend_ip = Some(ip.to_owned());
                }
                "listen" => {
                    let p = it
                        .next()
                        .ok_or_else(|| err("`listen` needs a <port>".into()))?;
                    listen_port = Some(
                        p.parse()
                            .map_err(|_| err(format!("bad listen port `{p}`")))?,
                    );
                }
                "algorithm" => {
                    let a = it
                        .next()
                        .ok_or_else(|| err("`algorithm` needs a value".into()))?;
                    algorithm = match a {
                        "round-robin" | "roundrobin" | "rr" => Algorithm::RoundRobin,
                        "least-conn" | "leastconn" | "lc" => Algorithm::LeastConn,
                        "consistent-hash" | "consistenthash" | "ch" => Algorithm::ConsistentHash,
                        other => return Err(err(format!("unknown algorithm `{other}`"))),
                    };
                }
                "affinity" => {
                    let a = it
                        .next()
                        .ok_or_else(|| err("`affinity` needs a value".into()))?;
                    affinity = match a {
                        "none" => Affinity::None,
                        "sticky" => Affinity::Sticky,
                        other => return Err(err(format!("unknown affinity `{other}`"))),
                    };
                }
                "health" => {
                    let mode = it
                        .next()
                        .ok_or_else(|| err("`health` needs `active <ms>` or `none`".into()))?;
                    match mode {
                        "none" => {
                            health = HealthCheck {
                                active: false,
                                interval_ms: 1000,
                            };
                        }
                        "active" => {
                            let ms = it.next().ok_or_else(|| {
                                err("`health active` needs an <interval-ms>".into())
                            })?;
                            health = HealthCheck {
                                active: true,
                                interval_ms: ms
                                    .parse()
                                    .map_err(|_| err(format!("bad health interval `{ms}`")))?,
                            };
                        }
                        other => return Err(err(format!("unknown health mode `{other}`"))),
                    }
                }
                "backend" => {
                    let id = it
                        .next()
                        .ok_or_else(|| err("`backend` needs <id> <ip:port>".into()))?;
                    let addr_s = it
                        .next()
                        .ok_or_else(|| err("`backend` needs an <ip:port>".into()))?;
                    let addr: SocketAddr = addr_s
                        .parse()
                        .map_err(|_| err(format!("bad backend address `{addr_s}`")))?;
                    backends.push((id.to_owned(), addr));
                }
                other => return Err(err(format!("unknown directive `{other}`"))),
            }
        }

        let ip = frontend_ip
            .ok_or_else(|| IngressLbUdpError("manifest missing a `frontend <name> <vip-ip>`".into()))?;
        let port = listen_port
            .ok_or_else(|| IngressLbUdpError("manifest missing a `listen <port>`".into()))?;
        if backends.is_empty() {
            return Err(IngressLbUdpError(
                "manifest names no `backend <id> <ip:port>`".into(),
            ));
        }

        let policy = LoadBalancerPolicy {
            algorithm,
            affinity,
            locality_tier: None,
            health,
            consistency_class: if affinity == Affinity::Sticky {
                SideEffect::Exclusive
            } else {
                SideEffect::Convergent
            },
        };

        Ok(IngressLbUdpManifest {
            vip: format!("{ip}:{port}"),
            backends,
            policy,
        })
    }

    /// Bind the real [`UdpDataplane`] for this manifest and return it (the
    /// caller keeps it alive to keep the dataplane serving). The concrete bound
    /// VIP is [`UdpDataplane::vip_addr`].
    ///
    /// # Errors
    /// Propagates any VIP bind error.
    pub async fn bind(&self) -> std::io::Result<UdpDataplane> {
        UdpDataplane::bind(&self.vip, &self.backends, self.policy.clone()).await
    }
}

/// Read a manifest file, bind the dataplane, print the machine-readable
/// listening line, and block until the process is signalled — the real
/// externally-reachable ingress-lb-udp surface.
///
/// # Errors
/// Returns a boxed error on a missing/unreadable manifest file, a parse error,
/// or a VIP bind failure.
pub async fn serve(manifest_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(manifest_path)
        .map_err(|e| IngressLbUdpError(format!("reading manifest `{manifest_path}`: {e}")))?;
    let manifest = IngressLbUdpManifest::parse(&text)?;
    serve_manifest(&manifest).await
}

/// Bind an already-parsed manifest and block, publishing the listening line.
/// Split out so `node run`'s env-var path and the CLI verb share one body.
///
/// # Errors
/// Propagates the VIP bind failure.
pub async fn serve_manifest(
    manifest: &IngressLbUdpManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    let dataplane = manifest.bind().await?;
    // The single machine-readable line a harness parses to learn the concrete
    // bound port (an ephemeral `:0` listen resolves here).
    println!(
        "ingress-lb-udp listening vip={} backends={}",
        dataplane.vip_addr(),
        manifest.backends.len()
    );
    use std::io::Write;
    let _ = std::io::stdout().flush();

    // Keep the dataplane alive and the VIP bound until the process is
    // signalled; dropping `dataplane` would abort the forwarding task.
    let _ = tokio::signal::ctrl_c().await;
    drop(dataplane);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_manifest() {
        let m = IngressLbUdpManifest::parse(
            "# an ingress-lb-udp manifest\n\
             frontend udp-fe 127.0.0.1\n\
             listen 0\n\
             algorithm consistent-hash\n\
             affinity sticky\n\
             health active 250\n\
             backend b1 127.0.0.1:9001\n\
             backend b2 127.0.0.1:9002\n",
        )
        .expect("parse");
        assert_eq!(m.vip, "127.0.0.1:0");
        assert_eq!(m.backends.len(), 2);
        assert_eq!(m.backends[0].0, "b1");
        assert_eq!(m.policy.algorithm, Algorithm::ConsistentHash);
        assert_eq!(m.policy.affinity, Affinity::Sticky);
        assert!(m.policy.health.active);
        assert_eq!(m.policy.health.interval_ms, 250);
        assert_eq!(m.policy.consistency_class, SideEffect::Exclusive);
    }

    #[test]
    fn round_robin_default_policy() {
        let m = IngressLbUdpManifest::parse(
            "frontend f 127.0.0.1\nlisten 55000\nbackend only 127.0.0.1:1\n",
        )
        .expect("parse");
        assert_eq!(m.vip, "127.0.0.1:55000");
        assert_eq!(m.policy.algorithm, Algorithm::RoundRobin);
        assert_eq!(m.policy.affinity, Affinity::None);
        assert_eq!(m.policy.consistency_class, SideEffect::Convergent);
    }

    #[test]
    fn health_none_disables_active_probes() {
        let m = IngressLbUdpManifest::parse(
            "frontend f 127.0.0.1\nlisten 0\nhealth none\nbackend b 127.0.0.1:2\n",
        )
        .expect("parse");
        assert!(!m.policy.health.active);
    }

    #[test]
    fn rejects_missing_frontend() {
        let e = IngressLbUdpManifest::parse("listen 0\nbackend b 127.0.0.1:2\n").unwrap_err();
        assert!(e.0.contains("frontend"), "{}", e.0);
    }

    #[test]
    fn rejects_missing_listen() {
        let e =
            IngressLbUdpManifest::parse("frontend f 127.0.0.1\nbackend b 127.0.0.1:2\n").unwrap_err();
        assert!(e.0.contains("listen"), "{}", e.0);
    }

    #[test]
    fn rejects_no_backends() {
        let e = IngressLbUdpManifest::parse("frontend f 127.0.0.1\nlisten 0\n").unwrap_err();
        assert!(e.0.contains("backend"), "{}", e.0);
    }

    #[test]
    fn rejects_bad_backend_addr() {
        let e = IngressLbUdpManifest::parse(
            "frontend f 127.0.0.1\nlisten 0\nbackend b not-an-addr\n",
        )
        .unwrap_err();
        assert!(e.0.contains("bad backend address"), "{}", e.0);
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let e = IngressLbUdpManifest::parse(
            "frontend f 127.0.0.1\nlisten 0\nalgorithm bogus\nbackend b 127.0.0.1:2\n",
        )
        .unwrap_err();
        assert!(e.0.contains("unknown algorithm"), "{}", e.0);
    }
}
