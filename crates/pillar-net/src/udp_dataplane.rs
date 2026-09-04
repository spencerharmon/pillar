//! A REAL UDP ingress load-balancer dataplane.
//!
//! This is acceptance-narrative step 5 made executable: a client sends UDP
//! datagrams to a [`Frontend`](pillar_manifest::ingress::Frontend) VIP:port,
//! the dataplane BINDS that VIP with a real [`tokio::net::UdpSocket`], SELECTS
//! a backend per the [`Route`](pillar_manifest::ingress::Route)'s
//! [`Algorithm`](pillar_manifest::ingress::Algorithm) + affinity, honours
//! active health checks (a dead backend is dropped and never selected), and
//! FORWARDS each datagram to a real backend — with the backend's reply relayed
//! back to the originating client. No modelled `forward`: every hop is a real
//! socket send/recv.
//!
//! The dataplane rides the same LB *policy* types the manifest model already
//! ships ([`LoadBalancerPolicy`](pillar_manifest::ingress::LoadBalancerPolicy),
//! [`Algorithm`], [`Affinity`]) so backend selection is the manifest's own
//! decision, not a parallel one. It adds the STATEFUL parts a live dataplane
//! needs and a pure schema cannot carry: a round-robin cursor, per-backend
//! outstanding-connection counts for least-connections, a sticky affinity
//! table, and live health state.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pillar_manifest::ingress::{Affinity, Algorithm, LoadBalancerPolicy};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// One live backend the dataplane forwards to: a real UDP socket address plus
/// the live health / load state the selection algorithms read.
#[derive(Debug)]
struct LiveBackend {
    /// The backend's own load-balancer id (matches the manifest
    /// [`Backend`](pillar_manifest::ingress::Backend) id).
    id: String,
    /// The real UDP socket address the dataplane forwards datagrams to.
    addr: SocketAddr,
    /// Whether the backend is currently healthy. A failed active health probe
    /// clears this and the selector skips the backend entirely (failover).
    healthy: AtomicBool,
    /// Outstanding-connection counter for [`Algorithm::LeastConn`].
    outstanding: AtomicUsize,
}

impl LiveBackend {
    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }
}

/// A running UDP dataplane: it OWNS a bound VIP socket and a background task
/// that reads client datagrams, selects a healthy backend per the policy, and
/// relays the datagram to the backend and the backend's reply back to the
/// client. Dropping the handle stops the dataplane.
#[derive(Debug)]
pub struct UdpDataplane {
    vip_addr: SocketAddr,
    backends: Arc<Vec<Arc<LiveBackend>>>,
    forward_task: JoinHandle<()>,
    health_task: Option<JoinHandle<()>>,
}

/// Per-request selection state shared with the forwarding loop.
#[derive(Debug, Default)]
struct SelectState {
    /// Round-robin cursor.
    rr_cursor: AtomicU64,
    /// Sticky affinity: client key → backend id last chosen for it.
    sticky: Mutex<HashMap<String, String>>,
}

impl UdpDataplane {
    /// Bind the `Frontend` VIP and start forwarding datagrams to `backends`
    /// per `policy`.
    ///
    /// `vip` is the `ip:port` string of the listener (the acceptance test binds
    /// a loopback `127.0.0.1:0` VIP so it can drive it with a real client
    /// socket); `backends` pairs each manifest backend id with the real UDP
    /// address that backend listens on.
    ///
    /// # Errors
    /// Propagates any bind error on the VIP socket.
    pub async fn bind(
        vip: &str,
        backends: &[(String, SocketAddr)],
        policy: LoadBalancerPolicy,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(vip).await?;
        let vip_addr = socket.local_addr()?;
        let socket = Arc::new(socket);

        let live: Vec<Arc<LiveBackend>> = backends
            .iter()
            .map(|(id, addr)| {
                Arc::new(LiveBackend {
                    id: id.clone(),
                    addr: *addr,
                    healthy: AtomicBool::new(true),
                    outstanding: AtomicUsize::new(0),
                })
            })
            .collect();
        let backends = Arc::new(live);

        let health_task = if policy.health.active {
            Some(spawn_health_checks(
                Arc::clone(&backends),
                Duration::from_millis(u64::from(policy.health.interval_ms).max(1)),
            ))
        } else {
            None
        };

        let forward_task = spawn_forwarding(
            Arc::clone(&socket),
            Arc::clone(&backends),
            policy.algorithm,
            policy.affinity,
        );

        Ok(UdpDataplane {
            vip_addr,
            backends,
            forward_task,
            health_task,
        })
    }

    /// The concrete `ip:port` the VIP socket actually bound (an ephemeral test
    /// port resolves here). A client sends its datagrams to this address.
    #[must_use]
    pub fn vip_addr(&self) -> SocketAddr {
        self.vip_addr
    }

    /// Force a backend (by id) UNHEALTHY immediately — the acceptance test's
    /// deterministic "kill a backend" hook, equivalent to an active health
    /// probe failing. The selector drops it at once; traffic continues to the
    /// survivors.
    pub fn mark_unhealthy(&self, backend_id: &str) {
        for b in self.backends.iter() {
            if b.id == backend_id {
                b.healthy.store(false, Ordering::SeqCst);
            }
        }
    }

    /// The set of backend ids currently healthy.
    #[must_use]
    pub fn healthy_ids(&self) -> Vec<String> {
        self.backends
            .iter()
            .filter(|b| b.is_healthy())
            .map(|b| b.id.clone())
            .collect()
    }
}

impl Drop for UdpDataplane {
    fn drop(&mut self) {
        self.forward_task.abort();
        if let Some(h) = &self.health_task {
            h.abort();
        }
    }
}

/// Select a healthy backend for `key` per `algorithm` + `affinity`. Returns the
/// chosen backend (already accounting for affinity stickiness and skipping
/// unhealthy backends), or `None` if every backend is unhealthy.
async fn select_backend<'a>(
    backends: &'a [Arc<LiveBackend>],
    state: &SelectState,
    algorithm: Algorithm,
    affinity: Affinity,
    key: &str,
) -> Option<&'a Arc<LiveBackend>> {
    let healthy: Vec<&Arc<LiveBackend>> = backends.iter().filter(|b| b.is_healthy()).collect();
    if healthy.is_empty() {
        return None;
    }

    // Sticky affinity: reuse the last healthy choice for this key if still
    // healthy; otherwise fall through to the algorithm and re-pin.
    if affinity == Affinity::Sticky {
        let sticky = state.sticky.lock().await;
        if let Some(pinned_id) = sticky.get(key) {
            if let Some(b) = healthy.iter().find(|b| &b.id == pinned_id) {
                return Some(*b);
            }
        }
    }

    let chosen = match algorithm {
        Algorithm::RoundRobin => {
            let idx = state.rr_cursor.fetch_add(1, Ordering::SeqCst) as usize % healthy.len();
            healthy[idx]
        }
        Algorithm::LeastConn => *healthy
            .iter()
            .min_by_key(|b| b.outstanding.load(Ordering::SeqCst))
            .expect("healthy is non-empty"),
        Algorithm::ConsistentHash => {
            let idx = consistent_hash(key, healthy.len());
            healthy[idx]
        }
    };

    if affinity == Affinity::Sticky {
        let mut sticky = state.sticky.lock().await;
        sticky.insert(key.to_owned(), chosen.id.clone());
    }
    Some(chosen)
}

/// A deterministic, dependency-free hash of `key` into `[0, len)` — the same
/// stable projection the manifest model's consistent-hash uses.
fn consistent_hash(key: &str, len: usize) -> usize {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    key.hash(&mut h);
    (h.finish() as usize) % len
}

/// The background forwarding loop: read a client datagram off the VIP socket,
/// select a healthy backend, relay the datagram to it over a fresh ephemeral
/// socket, await the backend's reply, and relay that reply back to the client.
fn spawn_forwarding(
    vip: Arc<UdpSocket>,
    backends: Arc<Vec<Arc<LiveBackend>>>,
    algorithm: Algorithm,
    affinity: Affinity,
) -> JoinHandle<()> {
    let state = Arc::new(SelectState::default());
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (len, client) = match vip.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let datagram = buf[..len].to_vec();
            // Affinity/hash key: the client's address string. A real
            // consistent-hash / sticky LB keys on the client endpoint.
            let key = client.to_string();

            let Some(backend) =
                select_backend(&backends, &state, algorithm, affinity, &key).await
            else {
                continue; // every backend down: drop (nothing to forward to)
            };

            let backend = Arc::clone(backend);
            let vip = Arc::clone(&vip);
            backend.outstanding.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let _guard = OutstandingGuard(&backend);
                if let Some(reply) = relay(&backend.addr, &datagram).await {
                    let _ = vip.send_to(&reply, client).await;
                }
            });
        }
    })
}

/// Decrements a backend's outstanding-connection count when the relay finishes.
struct OutstandingGuard<'a>(&'a LiveBackend);
impl Drop for OutstandingGuard<'_> {
    fn drop(&mut self) {
        self.0.outstanding.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Forward `datagram` to `backend_addr` over a fresh ephemeral socket and
/// return the backend's reply (bounded by a short timeout so a silent backend
/// never wedges the relay task).
async fn relay(backend_addr: &SocketAddr, datagram: &[u8]) -> Option<Vec<u8>> {
    let bind = if backend_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect(backend_addr).await.ok()?;
    sock.send(datagram).await.ok()?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(buf[..n].to_vec())
}

/// Active health probes: every `interval` a probe datagram is sent to each
/// backend; a backend that fails to answer within the probe deadline is marked
/// unhealthy (dropped from selection); one that answers is marked healthy again
/// (recovery). This is the real active-health mechanism the acceptance test's
/// failover relies on — a killed backend stops answering and is dropped.
fn spawn_health_checks(
    backends: Arc<Vec<Arc<LiveBackend>>>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            for b in backends.iter() {
                let ok = probe(&b.addr).await;
                b.healthy.store(ok, Ordering::SeqCst);
            }
            tokio::time::sleep(interval).await;
        }
    })
}

/// A single active health probe: send a well-known probe datagram and require
/// an answer within a short deadline.
async fn probe(addr: &SocketAddr) -> bool {
    let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let Ok(sock) = UdpSocket::bind(bind).await else {
        return false;
    };
    if sock.connect(addr).await.is_err() {
        return false;
    }
    if sock.send(HEALTH_PROBE).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    matches!(
        tokio::time::timeout(Duration::from_millis(500), sock.recv(&mut buf)).await,
        Ok(Ok(_))
    )
}

/// The probe payload backends answer to prove liveness. An echo backend simply
/// echoes it; a dedicated health responder recognises it.
pub const HEALTH_PROBE: &[u8] = b"\x00pillar-udp-health\x00";
