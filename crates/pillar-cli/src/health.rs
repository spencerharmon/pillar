//! A **real** node readiness probe for the containerized `pillar node run`
//! deployment.
//!
//! A Kubernetes `readinessProbe` that merely checks a bound TCP/QUIC port is
//! satisfied the instant the transport binds — long before the node can
//! actually serve correct answers. A node that reports `Ready` while its
//! identity is unloaded, its materialized views are un-rehydrated, or its
//! Web-of-Trust root fails self-verification is a node that silently serves
//! WRONG results and, worse, passes a rolling upgrade's acceptance gate so the
//! rollout continues over broken pods.
//!
//! This module makes readiness mean what the operator's ROI ("Real readiness
//! probe", P1) requires: a node is `Ready` ONLY when ALL THREE substantive
//! conditions hold —
//!
//! 1. **Identity loaded** — the node's long-lived keypair is loaded and its
//!    stable [`libp2p::PeerId`] is known (see
//!    [`crate::run::load_or_create_identity`]).
//! 2. **Views rehydrated** — the durable streaming DB opened and its
//!    materialized view was rehydrated from the persisted op store (a fresh,
//!    empty store counts as rehydrated: zero ops IS the correct materialized
//!    state for a first boot; the condition asserts the rehydrate STEP ran to
//!    completion, not that ops exist).
//! 3. **WoT root self-verifies** — the node's Web-of-Trust authority root
//!    (its trust anchor) verifies against itself: the anchor's own key is not
//!    revoked and it is reachable at full delegation depth. A root that cannot
//!    self-verify can vouch for nobody, so the node can make no authoritative
//!    decision.
//!
//! The HTTP surface is deliberately tiny and dependency-free (a raw
//! `TcpListener` request/response, matching the style of [`crate::web_serve`]),
//! so the readiness endpoint runs unconditionally on every `node run` boot —
//! it does NOT depend on the optional `--web-bind` UI surface. The probe path
//! is `GET /readyz`: `200 OK` with body `ready` when all three conditions
//! hold, `503 Service Unavailable` with a body naming the first FAILED
//! condition otherwise. A liveness path `GET /healthz` always answers `200`
//! (the process is up) so liveness and readiness are separable in the manifest.
//!
//! The readiness DECISION is a pure function over the three conditions
//! ([`NodeReadiness`]/[`ReadinessReport`]), unit-tested below, so the
//! definition of done (`cargo test --all`) exercises the real accept/reject
//! logic — a probe that lied (reporting Ready on a 503-worthy state) would fail
//! these tests.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};

/// The default port the readiness/liveness health server listens on when the
/// deployment does not override it. Chosen distinct from the web UI default
/// ([`crate::run::DEFAULT_WEB_PORT`]) so both can run at once.
pub const DEFAULT_HEALTH_PORT: u16 = 8643;

/// The three substantive conditions a node must satisfy before it may report
/// Kubernetes `Ready`. A bound port is explicitly NOT one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeReadiness {
    /// The node's long-lived identity keypair is loaded and its stable
    /// `PeerId` is known.
    pub identity_loaded: bool,
    /// The durable streaming DB opened and its materialized view was
    /// rehydrated from the persisted op store (an empty store counts —
    /// zero ops is the correct rehydrated state for a first boot).
    pub views_rehydrated: bool,
    /// The Web-of-Trust authority root self-verifies (its anchor key is not
    /// revoked and it is reachable at full delegation depth).
    pub wot_root_verified: bool,
}

/// One substantive readiness condition, so a failing probe can name EXACTLY
/// which precondition is unmet (surfaced in the `503` body and in logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessCondition {
    /// Identity keypair not yet loaded.
    IdentityLoaded,
    /// Materialized views not yet rehydrated from the durable store.
    ViewsRehydrated,
    /// WoT root failed self-verification.
    WotRootVerified,
}

impl ReadinessCondition {
    /// A short, stable machine-readable token for this condition, used in the
    /// probe's `503` body and log lines.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            ReadinessCondition::IdentityLoaded => "identity-loaded",
            ReadinessCondition::ViewsRehydrated => "views-rehydrated",
            ReadinessCondition::WotRootVerified => "wot-root-verified",
        }
    }
}

/// The outcome of evaluating [`NodeReadiness`]: either fully ready, or NOT
/// ready with the FIRST unmet condition named (checked in the ROI's stated
/// order: identity, then views, then WoT root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadinessReport {
    /// All three substantive conditions hold — the node may serve.
    Ready,
    /// At least one condition is unmet; carries the first failing one.
    NotReady(ReadinessCondition),
}

impl NodeReadiness {
    /// Evaluate readiness, returning [`ReadinessReport::Ready`] iff ALL three
    /// conditions hold, else [`ReadinessReport::NotReady`] naming the first
    /// unmet one in ROI order (identity → views → WoT root).
    #[must_use]
    pub fn evaluate(&self) -> ReadinessReport {
        if !self.identity_loaded {
            return ReadinessReport::NotReady(ReadinessCondition::IdentityLoaded);
        }
        if !self.views_rehydrated {
            return ReadinessReport::NotReady(ReadinessCondition::ViewsRehydrated);
        }
        if !self.wot_root_verified {
            return ReadinessReport::NotReady(ReadinessCondition::WotRootVerified);
        }
        ReadinessReport::Ready
    }

    /// Convenience: is this node ready to serve?
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self.evaluate(), ReadinessReport::Ready)
    }
}

impl ReadinessReport {
    /// The HTTP status line this report maps to: `200 OK` when ready, `503
    /// Service Unavailable` when not — so a failing readiness probe keeps the
    /// pod OUT of the Service endpoints and visibly HALTS a rolling upgrade
    /// instead of silently serving broken.
    #[must_use]
    pub fn status_line(&self) -> &'static str {
        match self {
            ReadinessReport::Ready => "HTTP/1.1 200 OK",
            ReadinessReport::NotReady(_) => "HTTP/1.1 503 Service Unavailable",
        }
    }

    /// The response body: `ready` when ready, else `not-ready: <condition>`
    /// naming the first unmet condition.
    #[must_use]
    pub fn body(&self) -> String {
        match self {
            ReadinessReport::Ready => "ready".to_owned(),
            ReadinessReport::NotReady(cond) => format!("not-ready: {}", cond.token()),
        }
    }

    /// Render a full, minimal HTTP/1.1 response (status line + `Content-Type`
    /// + `Content-Length` + body) for this report.
    #[must_use]
    pub fn http_response(&self) -> String {
        http_response(self.status_line(), &self.body())
    }
}

/// Whether a WoT authority root SELF-VERIFIES: its anchor (owner) key vouches
/// for itself — i.e. the owner is reachable from itself at full delegation
/// depth, which is exactly the condition [`pillar_wot_authority::WotAuthority`]
/// fails when the owner's own key has been revoked. A root that cannot
/// self-verify can carry authority for nobody.
#[must_use]
pub fn wot_root_self_verifies(authority: &pillar_wot_authority::WotAuthority) -> bool {
    let owner = authority.owner().clone();
    authority.reachable_depth(&owner) == Some(authority.max_depth())
}

/// Format a minimal HTTP/1.1 response with an explicit `Content-Length` and a
/// `text/plain` type. `Connection: close` so the probe client (kubelet) does
/// not hold the socket.
fn http_response(status_line: &str, body: &str) -> String {
    format!(
        "{status_line}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    )
}

/// The two health routes the server answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealthRoute {
    /// `GET /readyz` — substantive readiness (the readinessProbe target).
    Readyz,
    /// `GET /healthz` — liveness: the process is up (the livenessProbe target).
    Healthz,
    /// Anything else.
    NotFound,
}

/// Parse the request line of a raw HTTP request into a [`HealthRoute`]. Only
/// `GET` is accepted; the path is compared exactly (query strings stripped).
fn route_of(request: &str) -> HealthRoute {
    let mut lines = request.split("\r\n");
    let Some(request_line) = lines.next() else {
        return HealthRoute::NotFound;
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method != "GET" {
        return HealthRoute::NotFound;
    }
    let path = target.split('?').next().unwrap_or(target);
    match path {
        "/readyz" => HealthRoute::Readyz,
        "/healthz" => HealthRoute::Healthz,
        _ => HealthRoute::NotFound,
    }
}

/// Build the full HTTP response string for a raw `request`, given a snapshot
/// of the node's current readiness. This is the pure request→response core of
/// the health server (unit-tested); [`serve`] only does the socket I/O around
/// it.
#[must_use]
pub fn respond(request: &str, readiness: &NodeReadiness) -> String {
    match route_of(request) {
        HealthRoute::Readyz => readiness.evaluate().http_response(),
        HealthRoute::Healthz => http_response("HTTP/1.1 200 OK", "alive"),
        HealthRoute::NotFound => http_response("HTTP/1.1 404 Not Found", "not found"),
    }
}

/// Bind the health server's TCP listener on `addr:port`.
pub fn bind(addr: IpAddr, port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind((addr, port))
}

/// Serve health probes forever on `listener`, computing readiness afresh for
/// each request via `readiness` (a live closure, so the answer tracks the
/// node's real, current state — never a stale snapshot). This is the
/// imperative shell over [`respond`]; the accept/reject logic it serves is the
/// unit-tested pure core.
pub fn serve<F>(listener: TcpListener, readiness: F)
where
    F: Fn() -> NodeReadiness,
{
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle_connection(stream, &readiness()),
            Err(e) => tracing::warn!(error = %e, "pillar health probe accept failed"),
        }
    }
}

/// Read one request off `stream` and write its health response back.
fn handle_connection(mut stream: TcpStream, readiness: &NodeReadiness) {
    let mut buf = [0u8; 1024];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "pillar health probe read failed");
            return;
        }
    };
    let request = String::from_utf8_lossy(&buf[..n]);
    let response = respond(&request, readiness);
    if let Err(e) = stream.write_all(response.as_bytes()) {
        tracing::warn!(error = %e, "pillar health probe write failed");
    }
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_core::NodeId;
    use pillar_wot_authority::WotAuthority;

    const ALL_READY: NodeReadiness = NodeReadiness {
        identity_loaded: true,
        views_rehydrated: true,
        wot_root_verified: true,
    };

    #[test]
    fn all_three_conditions_met_is_ready() {
        assert_eq!(ALL_READY.evaluate(), ReadinessReport::Ready);
        assert!(ALL_READY.is_ready());
        assert_eq!(ALL_READY.evaluate().status_line(), "HTTP/1.1 200 OK");
        assert_eq!(ALL_READY.evaluate().body(), "ready");
    }

    #[test]
    fn a_bound_port_alone_is_not_ready_missing_identity() {
        // The whole point: transport is up (implied) but identity is not
        // loaded → NOT ready, and the failing condition is named.
        let r = NodeReadiness {
            identity_loaded: false,
            ..ALL_READY
        };
        assert_eq!(
            r.evaluate(),
            ReadinessReport::NotReady(ReadinessCondition::IdentityLoaded)
        );
        assert!(!r.is_ready());
        assert_eq!(
            r.evaluate().status_line(),
            "HTTP/1.1 503 Service Unavailable"
        );
        assert_eq!(r.evaluate().body(), "not-ready: identity-loaded");
    }

    #[test]
    fn unrehydrated_views_are_not_ready() {
        let r = NodeReadiness {
            views_rehydrated: false,
            ..ALL_READY
        };
        assert_eq!(
            r.evaluate(),
            ReadinessReport::NotReady(ReadinessCondition::ViewsRehydrated)
        );
        assert_eq!(r.evaluate().body(), "not-ready: views-rehydrated");
    }

    #[test]
    fn unverified_wot_root_is_not_ready() {
        let r = NodeReadiness {
            wot_root_verified: false,
            ..ALL_READY
        };
        assert_eq!(
            r.evaluate(),
            ReadinessReport::NotReady(ReadinessCondition::WotRootVerified)
        );
        assert_eq!(r.evaluate().body(), "not-ready: wot-root-verified");
    }

    #[test]
    fn first_unmet_condition_is_reported_in_roi_order() {
        // Every condition failing → identity is reported first (ROI order).
        let none = NodeReadiness {
            identity_loaded: false,
            views_rehydrated: false,
            wot_root_verified: false,
        };
        assert_eq!(
            none.evaluate(),
            ReadinessReport::NotReady(ReadinessCondition::IdentityLoaded)
        );
        // Identity ok, views + wot fail → views reported before wot.
        let views_and_wot = NodeReadiness {
            identity_loaded: true,
            views_rehydrated: false,
            wot_root_verified: false,
        };
        assert_eq!(
            views_and_wot.evaluate(),
            ReadinessReport::NotReady(ReadinessCondition::ViewsRehydrated)
        );
    }

    #[test]
    fn readyz_route_reflects_readiness() {
        let req = "GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(respond(req, &ALL_READY).starts_with("HTTP/1.1 200 OK"));
        let not_ready = NodeReadiness {
            wot_root_verified: false,
            ..ALL_READY
        };
        let resp = respond(req, &not_ready);
        assert!(resp.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(resp.contains("not-ready: wot-root-verified"));
    }

    #[test]
    fn readyz_with_query_string_still_routes() {
        let req = "GET /readyz?probe=k8s HTTP/1.1\r\n\r\n";
        assert!(respond(req, &ALL_READY).starts_with("HTTP/1.1 200 OK"));
    }

    #[test]
    fn healthz_is_always_alive_even_when_not_ready() {
        // Liveness ≠ readiness: the process is up even while it is still
        // rehydrating, so a rolling upgrade does not kill a warming pod.
        let not_ready = NodeReadiness {
            identity_loaded: false,
            views_rehydrated: false,
            wot_root_verified: false,
        };
        let req = "GET /healthz HTTP/1.1\r\n\r\n";
        let resp = respond(req, &not_ready);
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("alive"));
    }

    #[test]
    fn unknown_route_is_404() {
        let req = "GET /metrics HTTP/1.1\r\n\r\n";
        assert!(respond(req, &ALL_READY).starts_with("HTTP/1.1 404 Not Found"));
    }

    #[test]
    fn non_get_method_is_404() {
        let req = "POST /readyz HTTP/1.1\r\n\r\n";
        assert!(respond(req, &ALL_READY).starts_with("HTTP/1.1 404 Not Found"));
    }

    #[test]
    fn http_response_has_correct_content_length() {
        let resp = ALL_READY.evaluate().http_response();
        assert!(resp.contains("Content-Length: 5")); // "ready"
        assert!(resp.contains("Connection: close"));
        assert!(resp.ends_with("ready"));
    }

    #[test]
    fn fresh_wot_root_self_verifies() {
        // A freshly-anchored authority: the owner is reachable from itself at
        // full depth, so the root self-verifies.
        let auth = WotAuthority::new(NodeId::from("owner"), 16);
        assert!(wot_root_self_verifies(&auth));
    }

    #[test]
    fn wot_root_with_revoked_owner_key_does_not_self_verify() {
        // Revoke the owner's own key: the anchor can vouch for no one,
        // including itself → the readiness precondition must FAIL.
        let mut auth = WotAuthority::new(NodeId::from("owner"), 16);
        auth.revoke_key(NodeId::from("owner"));
        assert!(!wot_root_self_verifies(&auth));
    }

    #[test]
    fn end_to_end_health_server_over_a_real_socket() {
        // Bind a real loopback listener, serve one /readyz probe, and assert
        // the readiness decision reaches the client — proving the socket
        // shell wraps the pure core correctly.
        let listener = bind(IpAddr::from([127, 0, 0, 1]), 0).unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            // Serve exactly one connection then stop.
            if let Some(Ok(stream)) = listener.incoming().next() {
                handle_connection(
                    stream,
                    &NodeReadiness {
                        identity_loaded: true,
                        views_rehydrated: true,
                        wot_root_verified: false,
                    },
                );
            }
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(b"GET /readyz HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(resp.contains("not-ready: wot-root-verified"));
        handle.join().unwrap();
    }
}
