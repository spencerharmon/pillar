//! Serves the web PORTAL from the deployed `pillar node run` process on a
//! configurable, **non-loopback** bind (`--web-bind`/`PILLAR_WEB_BIND`), so a
//! k8s Service can reach it (flux's `pillar-web-ingress-tls` gates on this).
//!
//! `pillar --web` (see `pillar-cli/src/main.rs`) stays localhost-only for the
//! no-identity-yet bootstrap flow; THIS surface is the one that leaves the
//! host, and it never inherits that surface's loopback exemption.
//!
//! ## Node-side custody login (the REVISED model)
//!
//! This portal implements **node-side key custody on a trusted node** (see
//! [`pillar_web::node_custody`], refining `specs/NodeCustodyLogin.tla`). It
//! SUPERSEDES the old client-side model that asked for THREE fields (handle +
//! CID + password). The user now supplies exactly **TWO** inputs — a user
//! identifier and an unlock factor (password/passkey); **no CID field** (a
//! third field would be a bug for a trusted node). The NODE resolves the
//! user's node-sealed key offer from the cell DB (CID → sealed blob), strips
//! the node-seal with its node key, unlocks the operational key SERVER-SIDE
//! (argon2id last line), signs the origin+expiry nonce, runs the shared
//! WoT/RBAC decider, and admits the user into an authenticated portal view
//! greeting them by handle with node management. Nonce/sign/verify stay hidden
//! plumbing.
//!
//! SECURITY MODEL — the password crosses TLS to the trusted node, which holds
//! the key ONLY because the cell sealed an offer to it (per-node, revocable —
//! that per-node seal IS the access control), NOT a blanket leak. Client-side
//! signing / caBLE ([`pillar_web::key_login`]) remains only the
//! untrusted/foreign-node path; passkey/WebAuthn stays an optional stronger
//! unlock factor.
//!
//! ## First-run bootstrap (operator-driven)
//!
//! On a FRESH, unbootstrapped node the `/` page guides the OPERATOR to (a)
//! create the cell, then (b) create the first user in the same guided step,
//! which links cell↔initial-user and CONSUMES the one-shot
//! `cell_key_can_create_user` capability (auto-flips false after the first
//! create — see [`pillar_web::node_custody::CellBootstrap`]). A bootstrapped
//! node shows the two-field login screen directly. The swarm DELIVERS this
//! flow; it never runs it — the operator drives it.
//!
//! ## Transport: HTTP/1.1
//!
//! The surface speaks HTTP/1.1 so a browser, `curl`, or a k8s Ingress can
//! reach it. Endpoints:
//!
//! - `GET /` — the graphical portal UI (HTML, 200): the two-field login (or,
//!   on a fresh node, the create-cell → create-first-user bootstrap flow).
//! - `GET /nonce` — a fresh origin/expiry-bound challenge nonce; body
//!   `NONCE <id> <expiry>`.
//! - `POST /login` — body `<identifier>\n<password>`: node-side custody
//!   login; 200 `OK` (+ `X-Pillar-Session`) with the greeted handle, or 401
//!   `DENIED <reason>`.
//! - `GET /bootstrap/status` — `FRESH` (unbootstrapped) or `BOOTSTRAPPED`.
//! - `POST /bootstrap/create` — body `<cell-id>\n<handle>\n<password>`: the
//!   ONE atomic bootstrap the portal drives — create the cell AND the first
//!   user together, so a reload between steps can never strand a cell with no
//!   first user. 200 `OK BOOTSTRAPPED <handle>` or 409 `DENIED <reason>`.
//! - `POST /bootstrap/create-cell` — body `<cell-id>`: operator step (a), the
//!   lower-level cell-only step (also used by the CLI + request flow).
//! - `POST /bootstrap/create-user` — body `<handle>\n<password>`: operator
//!   step (b), consuming the one-shot capability AND, atomically, applying
//!   the key-distribution label to this node + escrowing the new user's
//!   node-sealed operational-key offer to it, so this node can resolve it at
//!   the very next login.
//! - `POST /ping` — a stand-in signing action gated through
//!   [`pillar_web::authorize_nonloopback_signing_action`]; a non-loopback
//!   peer must present an admitted session (`X-Pillar-Session`).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::time::Instant;

use pillar_core::{Epoch, NodeId};
use pillar_coordination::LeaseRegister;
use pillar_identity::NodeSubkey;
use pillar_streamdb::{OpId, OpLog};
use pillar_web::key_login::{LoginSession, Origin};
use pillar_web::node_custody::{
    BootstrapError, CellBootstrap, CellNameRegistry, Cid, InMemoryCellNameRegistry,
    NodeCustodyError, NodeCustodySession, NodeCustodyVerifier, NodeKey, CELL_NAME_IN_USE_MESSAGE,
};
use pillar_web::{authorize_nonloopback_signing_action, bind_web};
use pillar_bootstrap::custody::parse_custody_kind;
use pillar_bootstrap::{
    BootstrapRequestId, BootstrapRequestKind, BootstrapRequestQueue, CustodyKind, NodeIdentity,
    RequestError,
};
use pillar_wot_authority::{FencedActor, WotAuthority};

/// A read-only snapshot of this node's identity/reachability, as the
/// authenticated portal renders it: [`NodeId`]-derived peer id, the
/// multiaddrs this node listens on, and the peers it currently considers
/// connected. Real values are supplied by the boot-time `pillar-net` swarm
/// (see `crates/pillar-cli/src/run.rs`); the default here is an empty view
/// (a node with no configured listen/dial peers yet) until wired via
/// [`WebAuthContext::with_identity`].
#[derive(Clone, Debug, Default)]
pub struct NodeIdentitySnapshot {
    /// This node's libp2p-style peer id (derived from its identity keypair).
    pub peer_id: String,
    /// The multiaddrs this node listens on.
    pub listen_addrs: Vec<String>,
    /// The peers this node currently considers connected (peer ids).
    pub connected_peers: Vec<String>,
}

/// The server-side state the node-side-custody portal needs: the node-custody
/// verifier (holding this node's node key + its cell-DB view of node-sealed
/// offers), the shared WoT authority/actor login admission resolves through
/// (never a parallel one), the one-shot bootstrap capability state, and the
/// admitted portal sessions keyed by the bearer token handed to the client.
pub struct WebAuthContext {
    verifier: NodeCustodyVerifier,
    authority: WotAuthority,
    actor: FencedActor,
    bootstrap: CellBootstrap,
    /// The best-effort, peer-sourced cell-name registry the create-cell step
    /// queries BEFORE generating the cell key, so the web-UI bootstrap enforces
    /// the SAME network name-uniqueness rule as the CLI (both call the shared
    /// [`CellBootstrap::create_cell_checked`]). A real node resolves the
    /// pillar-scoped cell-name pointer over the swarm; the default here is an
    /// empty [`InMemoryCellNameRegistry`] (every name FREE) until a swarm-backed
    /// resolver is injected via [`WebAuthContext::with_cell_name_registry`].
    name_registry: Box<dyn CellNameRegistry + Send + Sync>,
    /// Admitted node-custody portal sessions, keyed by the `X-Pillar-Session`
    /// bearer. HTTP is connection-per-request, so an admitted session must
    /// outlive the connection it was minted on.
    sessions: HashMap<String, NodeCustodySession>,
    /// The `pillar_web` login-session view (for the shared non-loopback gate).
    login_sessions: HashMap<String, LoginSession>,
    next_session: u64,
    /// The node/user bootstrap-request queue for the cell this node serves.
    /// `None` until the cell is created (a request joins an EXISTING cell).
    requests: Option<BootstrapRequestQueue>,
    /// This node's identity/reachability snapshot (PeerId, listen addrs, the
    /// peers it considers connected) — the authenticated portal's "node
    /// status" tile reads this. Defaults empty; wire the real swarm-derived
    /// values via [`WebAuthContext::with_identity`].
    identity: NodeIdentitySnapshot,
    /// When this context was created — the portal reports uptime as the
    /// elapsed time since.
    started_at: Instant,
    /// The quorum-fenced lease register backing the portal's "lease holder"
    /// tile (see `pillar-coordination`). A fresh node is its own single
    /// voter/candidate, self-granting `lease_epoch` at construction so a
    /// solo node reports itself as holder; a real multi-node cell wires
    /// additional voters over the streaming DB / gossip layer.
    lease: LeaseRegister,
    /// The epoch the portal reads the lease holder at.
    lease_epoch: Epoch,
    /// UI-persisted layouts, stored as signed, content-addressed ops riding
    /// the streaming DB (`pillar-streamdb`) — never a server-side database.
    /// Each stored op's payload is `<signer-handle>\n<layout-content>`; its
    /// content-addressed [`OpId`] is the resource's CID, and
    /// `OpLog::root()` is the resource's streaming tip.
    layouts: OpLog,
}

impl WebAuthContext {
    /// A fresh context for a node identified by `node`, holding node key
    /// `node_secret`, serving `origin`, with `owner` as the WoT authority root
    /// at `max_depth`. The node starts UNBOOTSTRAPPED (its `/` serves the
    /// create-cell → create-first-user flow) with no offers provisioned yet.
    #[must_use]
    pub fn new(
        origin: impl Into<String>,
        node: NodeId,
        node_secret: impl Into<String>,
        owner: NodeId,
        max_depth: u8,
    ) -> Self {
        let origin = origin.into();
        let owner_for_lease = owner.clone();
        let node_for_identity = node.clone();
        let authority = WotAuthority::new(owner, max_depth);
        let mut actor = FencedActor::new();
        actor.refresh(&authority);
        let node_key = NodeKey::new(node, node_secret);
        let mut lease = LeaseRegister::new(1);
        let lease_epoch = Epoch(1);
        // A solo node is its own voter and candidate: self-grant + acquire so
        // a fresh node reports itself as the lease holder out of the box.
        let _ = lease.grant(owner_for_lease.clone(), owner_for_lease.clone(), lease_epoch);
        let _ = lease.try_acquire(&owner_for_lease, lease_epoch);
        WebAuthContext {
            verifier: NodeCustodyVerifier::new(node_key, Origin::from(origin.as_str())),
            authority,
            actor,
            bootstrap: CellBootstrap::new(),
            name_registry: Box::new(InMemoryCellNameRegistry::new()),
            sessions: HashMap::new(),
            login_sessions: HashMap::new(),
            next_session: 0,
            requests: None,
            identity: NodeIdentitySnapshot {
                peer_id: node_for_identity.to_string(),
                listen_addrs: Vec::new(),
                connected_peers: Vec::new(),
            },
            started_at: Instant::now(),
            lease,
            lease_epoch,
            layouts: OpLog::new(),
        }
    }

    /// Inject this node's real identity/reachability snapshot (PeerId, listen
    /// addrs, connected peers) as `run.rs` observes it from the live swarm.
    #[must_use]
    pub fn with_identity(mut self, identity: NodeIdentitySnapshot) -> Self {
        self.identity = identity;
        self
    }

    /// The current identity/reachability snapshot the portal renders.
    #[must_use]
    pub fn identity(&self) -> &NodeIdentitySnapshot {
        &self.identity
    }

    /// Seconds elapsed since this context was created — the portal's uptime.
    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// The current holder of this node's lease epoch, if any.
    #[must_use]
    pub fn lease_holder(&self) -> Option<&NodeId> {
        self.lease.holder(self.lease_epoch)
    }

    /// Persist a UI layout as a signed, content-addressed op riding the
    /// streaming DB — no server-side database. `signer` is the authenticated
    /// handle that produced `content` (the portal only ever calls this for an
    /// admitted session). Returns the resource's content-addressed [`OpId`]
    /// (its CID).
    pub fn store_layout(&mut self, signer: &str, content: &str) -> OpId {
        let payload = format!("{signer}\n{content}");
        self.layouts.append(payload.into_bytes())
    }

    /// Resolve a previously stored layout by its CID, returning
    /// `(signer, content)`.
    #[must_use]
    pub fn get_layout(&self, id: OpId) -> Option<(String, String)> {
        self.layouts.order().into_iter().find(|op| op.id() == id).and_then(|op| {
            let text = String::from_utf8_lossy(op.payload());
            let mut lines = text.splitn(2, '\n');
            let signer = lines.next()?.to_owned();
            let content = lines.next().unwrap_or("").to_owned();
            Some((signer, content))
        })
    }

    /// The streaming tip (Merkle root) of the layout resource log.
    #[must_use]
    pub fn layout_tip(&self) -> u64 {
        self.layouts.root()
    }

    /// Chain `subject` to the authority root at `level`, admitting it as
    /// WoT-authoritative — required before a login for its operational subkey
    /// can admit.
    pub fn admit_subject(&mut self, subject: NodeId, level: u8) {
        let root = self.authority.owner().clone();
        self.authority.issue_edge(root, subject, level);
        self.actor.refresh(&self.authority);
    }

    /// Provision a node-sealed key offer this node custodies (the cell sealed
    /// it to THIS node): the user `identifier` (greeted by `handle`) resolves
    /// to `cid`, whose blob unlocks the operational `subkey` under `password`
    /// (`secret` = the operational-key material). In a real node the label +
    /// offer arrive via `pillar_key_distribution`.
    #[allow(clippy::too_many_arguments)]
    pub fn provision_offer(
        &mut self,
        identifier: impl Into<String>,
        handle: impl Into<String>,
        cid: Cid,
        subkey: pillar_identity::NodeSubkey,
        password: &str,
        secret: &str,
    ) {
        self.verifier
            .provision_offer(identifier, handle, cid, subkey, password, secret);
    }

    /// Mutable access to the one-shot bootstrap capability state — the `/`
    /// bootstrap flow drives this.
    pub fn bootstrap_mut(&mut self) -> &mut CellBootstrap {
        &mut self.bootstrap
    }

    /// Step (b) of the bootstrap flow, DONE ATOMICALLY: create the first user
    /// AND seal their operational key's offer to THIS node — applying the
    /// key-distribution label + escrowing the node-sealed L1 offer (per the
    /// always-node-sealed offer mechanism) — so the very node that created
    /// the user can immediately resolve, strip, and unlock it at first login.
    /// Without this, a fresh bootstrap node correctly reports the untrusted-
    /// node `no-offer-for-user` mode even for the user it just created — the
    /// observed bug. Shared by both the CLI and the web-UI create-first-user
    /// steps (crates/pillar-cli/src/web_serve.rs) so neither drifts.
    ///
    /// `password` is the user's chosen unlock factor (never retained in the
    /// clear beyond this call); the scoped, revocable OPERATIONAL key is what
    /// gets escrowed — the cold root is never touched, and node authority is
    /// unchanged (this node only ever holds what the cell explicitly seals to
    /// it, per-node/opt-in/revocable).
    ///
    /// # Errors
    ///
    /// Propagates [`BootstrapError`] from the underlying [`CellBootstrap`]
    /// step (no cell yet / capability already spent) — the offer is escrowed
    /// only once that step succeeds.
    pub fn bootstrap_create_first_user(
        &mut self,
        handle: impl Into<String>,
        password: &str,
    ) -> Result<(), BootstrapError> {
        let handle = handle.into();
        self.bootstrap.create_first_user(handle.clone())?;

        // (1) Apply the key-distribution label: chain the new user's
        // operational subkey into the WoT authority at the root's own
        // budget, so it is authoritative once admitted.
        let subkey = NodeSubkey::from(format!("op-subkey-{handle}").as_str());
        let level = self.authority.max_depth();
        self.admit_subject(subkey.node_id(), level);

        // (2) Escrow the scoped operational key as a node-sealed L1 offer to
        // THIS bootstrap node's own node key — the per-node seal IS the
        // access control; no other node custodies this offer.
        let cid = Cid::from(format!("cid-{handle}").as_str());
        let secret = format!("operational-key-material-{handle}");
        self.provision_offer(handle.clone(), handle, cid, subkey, password, &secret);

        Ok(())
    }

    /// The bootstrap capability state.
    #[must_use]
    pub fn bootstrap(&self) -> &CellBootstrap {
        &self.bootstrap
    }

    /// Inject the swarm-backed cell-name registry used for the create-cell
    /// network name-uniqueness pre-check. A real node passes a resolver that
    /// queries the pillar-scoped cell-name pointer over the swarm; tests pass a
    /// deterministic [`InMemoryCellNameRegistry`].
    #[must_use]
    pub fn with_cell_name_registry(
        mut self,
        registry: Box<dyn CellNameRegistry + Send + Sync>,
    ) -> Self {
        self.name_registry = registry;
        self
    }

    /// The create-cell step BOTH surfaces route through: run the shared network
    /// name-uniqueness pre-check (`CellBootstrap::create_cell_checked` over this
    /// context's registry) BEFORE the cell key is generated, refusing a name a
    /// peer already serves. This is the single shared implementation the web UI
    /// uses; the CLI bootstrap calls the same `create_cell_checked`.
    ///
    /// # Errors
    ///
    /// The matching [`BootstrapError`] — notably
    /// [`BootstrapError::CellNameInUse`] when the network already claims it.
    pub fn create_cell(&mut self, cell: NodeId) -> Result<(), BootstrapError> {
        self.bootstrap
            .create_cell_checked(cell.clone(), self.name_registry.as_ref())?;
        // The cell now exists: open the bootstrap-request queue for it so fresh
        // nodes/users can request to join.
        self.requests = Some(BootstrapRequestQueue::new(cell, std::iter::empty()));
        Ok(())
    }

    /// The ONE atomic bootstrap step the web portal drives: create the cell AND
    /// the first user in a single call, so the node is only ever FRESH or fully
    /// BOOTSTRAPPED — never stranded with a cell but no first user (the bug the
    /// split create-cell/create-user flow left behind when the operator hit the
    /// back button / reloaded between the two steps). If a cell already exists
    /// from an older half-completed bootstrap, the cell step is skipped and only
    /// the missing first-user step runs, so this endpoint also RECOVERS such a
    /// stranded node.
    ///
    /// # Errors
    ///
    /// Propagates [`BootstrapError`] — a name a peer already serves
    /// ([`BootstrapError::CellNameInUse`]) from the cell step, or a spent
    /// capability from the first-user step.
    pub fn bootstrap_cell_and_first_user(
        &mut self,
        cell: NodeId,
        handle: &str,
        password: &str,
    ) -> Result<(), BootstrapError> {
        if self.bootstrap.cell().is_none() {
            self.create_cell(cell)?;
        }
        self.bootstrap_create_first_user(handle, password)
    }

    fn store_session(&mut self, session: NodeCustodySession) -> String {
        let token = format!("s{}", self.next_session);
        self.next_session += 1;
        // Mirror a `pillar_web` login-session view keyed by the same token so
        // the shared non-loopback signing gate can resolve it.
        self.login_sessions.insert(
            token.clone(),
            LoginSession {
                subject: session.subject.clone(),
                nonce_id: session.nonce_id,
                watermark: session.watermark,
            },
        );
        self.sessions.insert(token.clone(), session);
        token
    }

    fn login_session_for(&self, token: &str) -> Option<&LoginSession> {
        self.login_sessions.get(token)
    }
}

/// Bind the portal listener on `addr:port` — `addr` MAY be non-loopback (see
/// module docs); the caller must still gate every signing action through
/// [`authorize_nonloopback_signing_action`].
///
/// # Errors
///
/// Propagates [`std::io::Error`] if the address/port cannot be bound.
pub fn bind(addr: IpAddr, port: u16) -> std::io::Result<TcpListener> {
    bind_web(addr, port)
}

/// Serve HTTP/1.1 on `listener` until it errors or the process is torn down.
/// Blocking — run on a dedicated thread.
pub fn serve(listener: TcpListener, ctx: &mut WebAuthContext) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        handle_connection(stream, ctx);
    }
}

/// The graphical portal UI served at `GET /` — a real login page (two fields:
/// user identifier + unlock factor, NO CID), whose embedded script drives the
/// `GET /nonce` → `POST /login` handshake as hidden plumbing and, on success,
/// transitions into an authenticated portal view greeting the user by handle
/// with node management. On a FRESH node the same page guides the operator
/// through the create-cell → create-first-user bootstrap flow. The origin is
/// derived from the browser (`location`) at runtime, so no infrastructure
/// identifier is embedded in this public source.
const LANDING_PAGE: &str = include_str!("web_login.html");

/// A parsed HTTP request: method, path, and body.
struct HttpRequest {
    method: String,
    path: String,
    body: String,
}

/// Read and parse one HTTP/1.1 request from `reader`. Returns `None` on a
/// closed connection or an unparseable request line.
fn read_http_request(reader: &mut impl BufRead) -> Option<HttpRequest> {
    let mut request_line = String::new();
    match reader.read_line(&mut request_line) {
        Ok(0) | Err(_) => return None,
        Ok(_) => {}
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();

    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let trimmed = header.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }

    let mut body = String::new();
    if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        if reader.read_exact(&mut buf).is_ok() {
            body = String::from_utf8_lossy(&buf).into_owned();
        }
    }

    Some(HttpRequest { method, path, body })
}

/// An HTTP response to write back.
struct HttpResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    session_token: Option<String>,
    body: String,
}

impl HttpResponse {
    fn write_to(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len(),
        );
        if let Some(token) = &self.session_token {
            head.push_str(&format!("X-Pillar-Session: {token}\r\n"));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes())?;
        stream.write_all(self.body.as_bytes())?;
        stream.flush()
    }
}

fn handle_connection(mut stream: TcpStream, ctx: &mut WebAuthContext) {
    let Ok(peer) = stream.peer_addr() else { return };
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let Some(request) = read_http_request(&mut reader) else {
        return;
    };
    let response = dispatch_http(ctx, &peer, &request);
    let _ = response.write_to(&mut stream);
}

/// Map an HTTP request onto the portal action, preserving the auth gate.
fn dispatch_http(
    ctx: &mut WebAuthContext,
    peer: &SocketAddr,
    request: &HttpRequest,
) -> HttpResponse {
    let path = request.path.split('?').next().unwrap_or(&request.path);
    match (request.method.as_str(), path) {
        ("GET", "/") => HttpResponse {
            status: 200,
            reason: "OK",
            content_type: "text/html; charset=utf-8",
            session_token: None,
            body: LANDING_PAGE.to_owned(),
        },
        ("GET", "/bootstrap/status") => {
            // BOOTSTRAPPED only once the first USER exists — not merely the
            // cell. A cell-created-but-no-user node is still FRESH so the
            // portal keeps showing the (atomic) bootstrap form; reporting
            // BOOTSTRAPPED on a cell alone is exactly what stranded the
            // operator (the login form showed but no user could log in).
            let status = if ctx.bootstrap().initial_user().is_some() {
                "BOOTSTRAPPED"
            } else {
                "FRESH"
            };
            text_response(200, "OK", status.to_owned())
        }
        ("POST", "/bootstrap/create-cell") => {
            let cell = request.body.trim();
            if cell.is_empty() {
                return text_response(400, "Bad Request", "MISSING cell id".to_owned());
            }
            match ctx.create_cell(NodeId::from(cell)) {
                Ok(()) => text_response(200, "OK", "CELL-CREATED".to_owned()),
                Err(BootstrapError::CellNameInUse) => text_response(
                    409,
                    "Conflict",
                    format!("DENIED {CELL_NAME_IN_USE_MESSAGE}"),
                ),
                Err(e) => text_response(409, "Conflict", format!("DENIED {e:?}")),
            }
        }
        ("POST", "/bootstrap/create-user") => {
            // Body: "<handle>\n<password>" — the operator's chosen unlock
            // factor for the new user, escrowed atomically (see
            // `bootstrap_create_first_user`) so login works immediately.
            let mut lines = request.body.lines();
            let handle = lines.next().unwrap_or("").trim();
            let password = lines.next().unwrap_or("").trim();
            if handle.is_empty() || password.is_empty() {
                return text_response(400, "Bad Request", "MISSING handle-or-password".to_owned());
            }
            match ctx.bootstrap_create_first_user(handle, password) {
                Ok(()) => text_response(200, "OK", format!("USER-CREATED {handle}")),
                Err(e) => text_response(409, "Conflict", format!("DENIED {e:?}")),
            }
        }
        ("POST", "/bootstrap/create") => {
            // Body: "<cell>\n<handle>\n<password>" — the ONE atomic bootstrap
            // action the portal uses (cell + first user together, so a reload
            // between steps can never strand a cell with no first user). See
            // `bootstrap_cell_and_first_user`.
            let mut lines = request.body.lines();
            let cell = lines.next().unwrap_or("").trim();
            let handle = lines.next().unwrap_or("").trim();
            let password = lines.next().unwrap_or("").trim();
            if cell.is_empty() || handle.is_empty() || password.is_empty() {
                return text_response(
                    400,
                    "Bad Request",
                    "MISSING cell-handle-or-password".to_owned(),
                );
            }
            match ctx.bootstrap_cell_and_first_user(NodeId::from(cell), handle, password) {
                Ok(()) => text_response(200, "OK", format!("BOOTSTRAPPED {handle}")),
                Err(BootstrapError::CellNameInUse) => text_response(
                    409,
                    "Conflict",
                    format!("DENIED {CELL_NAME_IN_USE_MESSAGE}"),
                ),
                Err(e) => text_response(409, "Conflict", format!("DENIED {e:?}")),
            }
        }
        ("GET", "/nonce") => {
            let nonce = ctx.verifier.issue_nonce(u64::MAX);
            text_response(
                200,
                "OK",
                format!("NONCE {} {}", nonce.id(), nonce.expiry()),
            )
        }
        ("POST", "/login") => dispatch_login(ctx, request),
        ("POST", "/bootstrap/request/node") => dispatch_request_submit(ctx, request, true),
        ("POST", "/bootstrap/request/user") => dispatch_request_submit(ctx, request, false),
        ("GET", "/bootstrap/request/list") => dispatch_request_list(ctx),
        ("POST", "/bootstrap/request/approve") => dispatch_request_decide(ctx, request, true),
        ("POST", "/bootstrap/request/reject") => dispatch_request_decide(ctx, request, false),
        ("POST", "/ping") => {
            // Resolve the admitted session from the bearer token, then run the
            // UNCHANGED shared gate: a non-loopback peer with no admitted
            // session is still always refused.
            let token = request.body.trim();
            let session = ctx.login_session_for(token).cloned();
            match authorize_nonloopback_signing_action(peer, session.as_ref()) {
                Ok(()) => text_response(200, "OK", "PONG".to_owned()),
                Err(e) => text_response(403, "Forbidden", format!("REFUSED {e:?}")),
            }
        }
        ("GET", "/portal/status") => dispatch_portal_status(ctx, request),
        ("POST", "/portal/layout") => dispatch_layout_store(ctx, request),
        ("GET", "/portal/layout") => dispatch_layout_get(ctx, request),
        _ => text_response(404, "Not Found", "not found".to_owned()),
    }
}

/// Extract `key`'s value from `path`'s query string (`GET /x?a=1&b=2`), if
/// present. A bare helper — this portal has no framework, so query params are
/// parsed by hand exactly like the existing header/body parsing above.
fn query_value<'a>(path: &'a str, key: &str) -> Option<&'a str> {
    let query = path.split_once('?')?.1;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

/// The real authenticated portal's identity/reachability + lease-holder tile:
/// `GET /portal/status?token=<session>`. Requires an admitted session — an
/// unauthenticated (or unknown/expired-token) request is refused, exactly
/// like every other signing/read action gated behind login. Renders PeerId,
/// listen addrs, connected peer count + list, uptime, and the current lease
/// holder — all read from this node's live [`WebAuthContext`] state, never a
/// server-side database.
fn dispatch_portal_status(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let identity = ctx.identity();
    let lease_holder = ctx
        .lease_holder()
        .map(|n| n.to_string())
        .unwrap_or_else(|| "none".to_owned());
    let mut body = String::new();
    body.push_str(&format!("PEER-ID {}\n", identity.peer_id));
    body.push_str(&format!("LISTEN {}\n", identity.listen_addrs.join(",")));
    body.push_str(&format!("PEER-COUNT {}\n", identity.connected_peers.len()));
    body.push_str(&format!("PEERS {}\n", identity.connected_peers.join(",")));
    body.push_str(&format!("UPTIME-SECS {}\n", ctx.uptime_secs()));
    body.push_str(&format!("LEASE-HOLDER {lease_holder}\n"));
    text_response(200, "OK", body)
}

/// Persist a UI layout as a signed, content-addressed streaming-DB resource:
/// `POST /portal/layout`, body `<token>\n<content>`. Requires an admitted
/// session (the resource is signed by that session's handle); returns the
/// resource's content address (CID) and the log's new streaming tip.
fn dispatch_layout_store(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let mut lines = request.body.lines();
    let token = lines.next().unwrap_or("").trim();
    let content: String = lines.collect::<Vec<_>>().join("\n");
    let Some(session) = ctx.login_session_for(token).cloned() else {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    };
    let cid = ctx.store_layout(&session.subject.to_string(), &content);
    text_response(
        200,
        "OK",
        format!("LAYOUT-CID {} TIP {}", cid.0, ctx.layout_tip()),
    )
}

/// Retrieve a previously stored UI layout: `GET
/// /portal/layout?token=<session>&cid=<id>`. Requires an admitted session;
/// the resource's own signer + content are returned so a differently
/// authenticated viewer can see who produced the layout.
fn dispatch_layout_get(ctx: &WebAuthContext, request: &HttpRequest) -> HttpResponse {
    let token = query_value(&request.path, "token").unwrap_or("");
    if ctx.login_session_for(token).is_none() {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    }
    let Some(cid_raw) = query_value(&request.path, "cid") else {
        return text_response(400, "Bad Request", "MISSING cid".to_owned());
    };
    let Ok(cid) = cid_raw.parse::<u64>() else {
        return text_response(400, "Bad Request", "BAD cid".to_owned());
    };
    match ctx.get_layout(OpId(cid)) {
        Some((signer, content)) => {
            text_response(200, "OK", format!("SIGNER {signer}\nCONTENT {content}"))
        }
        None => text_response(404, "Not Found", "DENIED unknown-layout".to_owned()),
    }
}

/// Drive one node-side custody login: parse the TWO fields (identifier +
/// password), issue nothing here (the client already fetched a nonce), and let
/// the node resolve+strip+unlock+sign+admit SERVER-SIDE.
fn dispatch_login(ctx: &mut WebAuthContext, request: &HttpRequest) -> HttpResponse {
    // Body: "<identifier>\n<password>\n<nonce_id>". The client fetched the
    // nonce via GET /nonce and echoes its id so the server can bind the login
    // to that exact challenge; the password + identifier are the two human
    // fields. The CID is NEVER in the body — the node resolves it.
    let mut lines = request.body.lines();
    let identifier = lines.next().unwrap_or("").trim();
    let password = lines.next().unwrap_or("").trim();
    let nonce_id: u64 = lines
        .next()
        .unwrap_or("")
        .trim()
        .parse()
        .unwrap_or(u64::MAX);

    if identifier.is_empty() || password.is_empty() {
        return text_response(401, "Unauthorized", "DENIED missing-field".to_owned());
    }

    let authority = ctx.authority.clone();
    let actor = ctx.actor.clone();
    match ctx
        .verifier
        .admit(identifier, password, nonce_id, 0, &authority, &actor)
    {
        Ok(session) => {
            let handle = session.handle.clone();
            let token = ctx.store_session(session);
            HttpResponse {
                status: 200,
                reason: "OK",
                content_type: "text/plain; charset=utf-8",
                session_token: Some(token),
                body: format!("OK {handle}\n"),
            }
        }
        Err(e) => {
            let reason = login_reason(&e);
            text_response(401, "Unauthorized", format!("DENIED {reason}"))
        }
    }
}

fn parse_custody_field(token: &str) -> CustodyKind {
    parse_custody_kind(token).unwrap_or(CustodyKind::Password)
}

/// Submit a node/user bootstrap request. `is_node` selects the kind; the body
/// carries the requester's identifying info as newline-separated fields (see
/// the CLI `pillar bootstrap node`/`user` clients for the exact framing).
/// Requires the cell to exist (a request joins an EXISTING cell).
fn dispatch_request_submit(
    ctx: &mut WebAuthContext,
    request: &HttpRequest,
    is_node: bool,
) -> HttpResponse {
    let Some(queue) = ctx.requests.as_mut() else {
        return text_response(409, "Conflict", "DENIED no-cell-yet".to_owned());
    };
    let mut lines = request.body.lines();
    let subject = lines.next().unwrap_or("").trim();
    if subject.is_empty() {
        return text_response(400, "Bad Request", "MISSING subject".to_owned());
    }
    let subject = NodeId::from(subject);
    let id = if is_node {
        // Fields: <subject>\n<peer_id>\n<version>\n<os>\n<public_key_cid>\n<custody>
        // then any number of `pub=<addr>` / `priv=<addr>` / `label=<l>` lines.
        let peer_id = lines.next().unwrap_or("").trim().to_owned();
        let version = lines.next().unwrap_or("").trim().to_owned();
        let os = lines.next().unwrap_or("").trim().to_owned();
        let public_key_cid = lines.next().unwrap_or("").trim().to_owned();
        let custody = parse_custody_field(lines.next().unwrap_or("").trim());
        let mut identity = NodeIdentity::new(peer_id);
        identity.version = version;
        identity.os = os;
        identity.public_key_cid = public_key_cid;
        let mut labels = Vec::new();
        for line in lines {
            let line = line.trim();
            if let Some(a) = line.strip_prefix("pub=") {
                identity.public_addrs.push(a.to_owned());
            } else if let Some(a) = line.strip_prefix("priv=") {
                identity.private_addrs.push(a.to_owned());
            } else if let Some(l) = line.strip_prefix("label=") {
                labels.push(l.to_owned());
            }
        }
        queue.submit_node(subject, identity, custody, labels)
    } else {
        // Fields: <subject>\n<custody> then any number of `label=<l>` lines.
        let custody = parse_custody_field(lines.next().unwrap_or("").trim());
        let labels: Vec<String> = lines
            .filter_map(|l| l.trim().strip_prefix("label=").map(str::to_owned))
            .collect();
        queue.submit_user(subject, custody, labels)
    };
    text_response(200, "OK", format!("REQUEST {}", id.0))
}

/// List the pending bootstrap requests, one per line: `<id> <kind> <subject>`.
fn dispatch_request_list(ctx: &WebAuthContext) -> HttpResponse {
    let Some(queue) = ctx.requests.as_ref() else {
        return text_response(409, "Conflict", "DENIED no-cell-yet".to_owned());
    };
    let mut body = String::new();
    for req in queue.pending() {
        let kind = match req.kind() {
            BootstrapRequestKind::Node => "node",
            BootstrapRequestKind::User => "user",
        };
        body.push_str(&format!("{} {} {}\n", req.id().0, kind, req.subject().0));
    }
    text_response(200, "OK", body)
}

/// Approve or reject a pending request. The body is `<id>\n<session-token>`.
/// The presented session token must resolve to an admitted login session; its
/// subject is the authorized member that decides the request. A NODE approval
/// seals the cell key and returns its CID; a USER approval escrows the offer.
fn dispatch_request_decide(
    ctx: &mut WebAuthContext,
    request: &HttpRequest,
    approve: bool,
) -> HttpResponse {
    let mut lines = request.body.lines();
    let id_raw = lines.next().unwrap_or("").trim();
    let token = lines.next().unwrap_or("").trim();
    let Ok(id) = id_raw.parse::<u64>() else {
        return text_response(400, "Bad Request", "MISSING request-id".to_owned());
    };
    // Authenticated member = the subject of a valid login session.
    let Some(session) = ctx.login_sessions.get(token) else {
        return text_response(401, "Unauthorized", "DENIED not-authenticated".to_owned());
    };
    let member = session.subject.clone();
    let Some(queue) = ctx.requests.as_mut() else {
        return text_response(409, "Conflict", "DENIED no-cell-yet".to_owned());
    };
    // An authenticated (WoT-authoritative) login IS an authorized member.
    queue.add_member(member.clone());
    let id = BootstrapRequestId(id);
    if approve {
        match queue.approve(id, &member) {
            Ok(Some(sealed)) => text_response(200, "OK", format!("APPROVED {}", sealed.cid)),
            Ok(None) => text_response(200, "OK", format!("ESCROWED {}", id.0)),
            Err(e) => text_response(409, "Conflict", format!("DENIED {}", request_reason(&e))),
        }
    } else {
        match queue.reject(id, &member) {
            Ok(()) => text_response(200, "OK", format!("REJECTED {}", id.0)),
            Err(e) => text_response(409, "Conflict", format!("DENIED {}", request_reason(&e))),
        }
    }
}

fn request_reason(e: &RequestError) -> &'static str {
    match e {
        RequestError::UnknownRequest => "unknown-request",
        RequestError::NotPending => "already-decided",
        RequestError::NotAuthorizedMember => "not-authorized-member",
    }
}

/// Map a [`NodeCustodyError`] onto a stable in-UI reason token — including the
/// NEW node-custody mode "this node lacks the key-distribution label / has no
/// offer for this user".
fn login_reason(e: &NodeCustodyError) -> &'static str {
    match e {
        NodeCustodyError::NoOfferForUser => "no-offer-for-user",
        NodeCustodyError::NoCustody => "no-custody-on-this-node",
        NodeCustodyError::UnlockFailed => "unlock-failed",
        NodeCustodyError::NotAuthorized(_) => "not-authorized",
        NodeCustodyError::BadNonce => "bad-nonce",
    }
}

fn text_response(status: u16, reason: &'static str, mut body: String) -> HttpResponse {
    if !body.ends_with('\n') {
        body.push('\n');
    }
    HttpResponse {
        status,
        reason,
        content_type: "text/plain; charset=utf-8",
        session_token: None,
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_identity::NodeSubkey;
    use std::net::Ipv4Addr;

    const PASSWORD: &str = "correct horse battery staple";
    const SECRET: &str = "operational-key-material";
    const ORIGIN: &str = "https://pillar.example.com";

    fn remote_peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 4242)
    }

    // A node that already custodies an offer for alice, WoT-chained + admitted.
    fn provisioned_ctx() -> (WebAuthContext, NodeSubkey) {
        let subkey = NodeSubkey::from("op-subkey-alice");
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );
        ctx.admit_subject(subkey.node_id(), 4);
        ctx.provision_offer(
            "alice@pillar",
            "Alice",
            Cid::from("cid-alice"),
            subkey.clone(),
            PASSWORD,
            SECRET,
        );
        (ctx, subkey)
    }

    fn get(ctx: &mut WebAuthContext, path: &str) -> HttpResponse {
        dispatch_http(
            ctx,
            &remote_peer(),
            &HttpRequest {
                method: "GET".into(),
                path: path.into(),
                body: String::new(),
            },
        )
    }

    fn post(ctx: &mut WebAuthContext, path: &str, body: &str) -> HttpResponse {
        dispatch_http(
            ctx,
            &remote_peer(),
            &HttpRequest {
                method: "POST".into(),
                path: path.into(),
                body: body.into(),
            },
        )
    }

    #[test]
    fn node_run_web_surface_binds_a_non_loopback_address() {
        let listener = bind(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).expect("bind non-loopback");
        let addr = listener.local_addr().expect("local_addr");
        assert!(
            !addr.ip().is_loopback(),
            "node-run web surface must bind a non-loopback address"
        );
    }

    // The full HTTP node-side custody login: GET /nonce, then POST /login with
    // exactly TWO fields (identifier + password, NO CID) — the node resolves
    // the offer, strips the seal, unlocks the key, signs, and admits. Then a
    // signing action POST /ping with and without the session token.
    #[test]
    fn two_field_node_custody_login_then_ping_dispatch_preserves_the_auth_gate() {
        let (mut ctx, _subkey) = provisioned_ctx();

        // Unauthenticated signing action against a non-loopback peer: 403.
        let refused = post(&mut ctx, "/ping", "");
        assert_eq!(
            refused.status, 403,
            "unauthenticated non-loopback ping must be refused"
        );

        // GET /nonce.
        let nonce_resp = get(&mut ctx, "/nonce");
        assert_eq!(nonce_resp.status, 200);
        let mut parts = nonce_resp.body.split_whitespace();
        assert_eq!(parts.next(), Some("NONCE"));
        let id: u64 = parts.next().expect("id").parse().expect("id");

        // POST /login — TWO fields + the nonce id (hidden plumbing). NO CID.
        let login_body = format!("alice@pillar\n{PASSWORD}\n{id}");
        let login_resp = post(&mut ctx, "/login", &login_body);
        assert_eq!(login_resp.status, 200, "login body: {}", login_resp.body);
        assert!(
            login_resp.body.starts_with("OK Alice"),
            "the node greets the user by handle: {}",
            login_resp.body
        );
        let token = login_resp.session_token.expect("a session token");

        // POST /ping WITH the token → 200 PONG.
        let ping_resp = post(&mut ctx, "/ping", &token);
        assert_eq!(
            ping_resp.status, 200,
            "authenticated ping: {}",
            ping_resp.body
        );
        assert!(ping_resp.body.starts_with("PONG"));
    }

    #[test]
    fn login_form_asks_two_fields_only_no_cid_field() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get(&mut ctx, "/");
        assert_eq!(resp.status, 200);
        assert!(resp.content_type.contains("text/html"));
        let body = &resp.body;

        // A real graphical login FORM with EXACTLY the two human inputs.
        assert!(body.contains("<form"), "must render a login form");
        assert!(
            body.contains("id=\"identifier\"") && body.contains("id=\"password\""),
            "must present the identifier + unlock-factor inputs"
        );
        // NO CID field — a third field would be a bug for node-side custody.
        assert!(
            !body.contains("id=\"cid\"") && !body.contains("id=\"keymat\""),
            "the node-side custody login must NOT ask for a CID / key material"
        );
        // The script drives the handshake as hidden plumbing.
        assert!(body.contains("<script"), "must embed a client-side script");
        assert!(
            body.contains("/nonce") && body.contains("/login"),
            "the script must drive the /nonce and /login endpoints itself"
        );
        // It transitions into an authenticated portal view.
        assert!(
            body.contains("id=\"portal\""),
            "must transition into an authenticated portal view"
        );
    }

    #[test]
    fn root_page_is_the_interactive_portal_not_the_protocol_description() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get(&mut ctx, "/");
        let lower = resp.body.to_lowercase();
        assert!(
            !(lower.contains("get <code>/nonce</code> for a challenge")
                || lower.contains("post the signature to")),
            "the page must NOT be the bare protocol-description text"
        );
    }

    #[test]
    fn get_root_over_http_yields_a_2xx_response_with_a_body() {
        use std::io::Read as _;

        let listener = bind(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).expect("bind non-loopback");
        let addr = listener.local_addr().expect("local_addr");
        assert!(!addr.ip().is_loopback(), "must bind a non-loopback address");

        let handle = std::thread::spawn(move || {
            let (mut ctx, _subkey) = provisioned_ctx();
            let stream = listener
                .incoming()
                .next()
                .expect("one connection")
                .expect("accept");
            super::handle_connection(stream, &mut ctx);
        });

        let connect = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port());
        let mut client = TcpStream::connect(connect).expect("connect");
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: pillar.example.com\r\n\r\n")
            .expect("write request");
        let mut raw = String::new();
        client.read_to_string(&mut raw).expect("read response");
        handle.join().expect("server thread");

        let status_line = raw.lines().next().expect("a status line");
        assert!(
            status_line.starts_with("HTTP/1.1 2"),
            "expected an HTTP/1.1 2xx status line, got: {status_line}"
        );
        let (_, body) = raw.split_once("\r\n\r\n").expect("a header/body separator");
        assert!(!body.is_empty(), "expected a non-empty response body");
    }

    #[test]
    fn a_wrong_password_surfaces_a_clear_unlock_failed_message() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let nonce_resp = get(&mut ctx, "/nonce");
        let id: u64 = nonce_resp
            .body
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let resp = post(&mut ctx, "/login", &format!("alice@pillar\nwrong\n{id}"));
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("unlock-failed"), "got: {}", resp.body);
    }

    #[test]
    fn a_node_without_an_offer_surfaces_the_new_no_offer_mode() {
        // A node that holds NO offer for this user (or lacks the label) must
        // surface the NEW node-custody mode, distinct from a wrong password.
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );
        let nonce_resp = get(&mut ctx, "/nonce");
        let id: u64 = nonce_resp
            .body
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let resp = post(
            &mut ctx,
            "/login",
            &format!("nobody@pillar\n{PASSWORD}\n{id}"),
        );
        assert_eq!(resp.status, 401);
        assert!(
            resp.body.contains("no-offer-for-user"),
            "got: {}",
            resp.body
        );
    }

    // The first-run BOOTSTRAP flow: a fresh node serves the create-cell ->
    // create-first-user flow; the first create consumes the one-shot
    // capability (a second cell-key create-user is refused) and links
    // cell<->initial-user; a bootstrapped node reports BOOTSTRAPPED.
    #[test]
    fn fresh_node_serves_create_cell_then_create_first_user_consuming_the_capability() {
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );

        // Fresh: status FRESH.
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");

        // Cannot create a user before the cell.
        let early = post(&mut ctx, "/bootstrap/create-user", &format!("spencer\n{PASSWORD}"));
        assert_eq!(early.status, 409);
        assert!(early.body.contains("NoCellYet"), "got: {}", early.body);

        // (a) create the cell.
        let cell = post(&mut ctx, "/bootstrap/create-cell", "cell-genesis");
        assert_eq!(cell.status, 200);
        assert!(cell.body.contains("CELL-CREATED"));

        // (b) create the first user — consumes the one-shot capability.
        let user = post(&mut ctx, "/bootstrap/create-user", &format!("spencer\n{PASSWORD}"));
        assert_eq!(user.status, 200);
        assert!(user.body.contains("USER-CREATED spencer"));

        // Now BOOTSTRAPPED, cell<->user linked.
        assert_eq!(
            get(&mut ctx, "/bootstrap/status").body.trim(),
            "BOOTSTRAPPED"
        );
        assert_eq!(ctx.bootstrap().initial_user(), Some("spencer"));

        // A SECOND cell-key create-user is refused (capability spent).
        let second = post(&mut ctx, "/bootstrap/create-user", &format!("second-user\n{PASSWORD}"));
        assert_eq!(second.status, 409);
        assert!(
            second.body.contains("CapabilitySpent"),
            "got: {}",
            second.body
        );
    }

    // Regression: the observed bug — after create-cell -> create-first-user
    // on a fresh bootstrap node, login used to fail "no offer for you" for
    // the very user just created. The bootstrap create-first-user step MUST
    // atomically apply the key-distribution label + escrow the new user's
    // node-sealed offer to this node, so the FIRST login succeeds
    // immediately, with no separate operator provisioning step.
    #[test]
    fn first_login_immediately_after_bootstrap_succeeds_with_no_extra_provisioning() {
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );

        let cell = post(&mut ctx, "/bootstrap/create-cell", "cell-genesis");
        assert_eq!(cell.status, 200);
        let user = post(&mut ctx, "/bootstrap/create-user", &format!("spencer\n{PASSWORD}"));
        assert_eq!(user.status, 200, "got: {}", user.body);

        // Log in as the just-created user with NO further offer provisioning.
        let nonce_resp = get(&mut ctx, "/nonce");
        let id: u64 = nonce_resp.body.split_whitespace().nth(1).unwrap().parse().unwrap();
        let login = post(&mut ctx, "/login", &format!("spencer\n{PASSWORD}\n{id}"));
        assert_eq!(
            login.status, 200,
            "first login right after bootstrap must succeed, got: {}",
            login.body
        );
        assert!(login.body.contains("spencer"), "got: {}", login.body);

        // A wrong password on the same identifier is still a plain
        // unlock-failed, never the no-offer mode — proving the offer really
        // is present and the failure mode is unlock-specific.
        let nonce_resp2 = get(&mut ctx, "/nonce");
        let id2: u64 = nonce_resp2.body.split_whitespace().nth(1).unwrap().parse().unwrap();
        let bad = post(&mut ctx, "/login", &format!("spencer\nwrong\n{id2}"));
        assert_eq!(bad.status, 401);
        assert!(bad.body.contains("unlock-failed"), "got: {}", bad.body);
    }


    #[test]
    fn a_bootstrapped_node_reports_bootstrapped_directly() {
        let (mut ctx, _subkey) = provisioned_ctx();
        // A node is BOOTSTRAPPED only once it has a cell AND its first user;
        // a cell alone is still FRESH (see the status endpoint). Bootstrap it
        // fully through the atomic step.
        let done = post(
            &mut ctx,
            "/bootstrap/create",
            &format!("cell-genesis\nspencer\n{PASSWORD}"),
        );
        assert_eq!(done.status, 200, "got: {}", done.body);
        assert_eq!(
            get(&mut ctx, "/bootstrap/status").body.trim(),
            "BOOTSTRAPPED"
        );
    }

    #[test]
    fn create_cell_refuses_a_name_already_claimed_on_the_network_with_a_clear_message() {
        use pillar_web::node_custody::InMemoryCellNameRegistry;
        // A node whose swarm view already serves a pointer for "cell-genesis".
        let mut registry = InMemoryCellNameRegistry::new();
        registry.claim("cell-genesis");
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        )
        .with_cell_name_registry(Box::new(registry));

        // The web-UI create-cell step must REFUSE with the clear message and
        // must NOT create the colliding cell.
        let resp = post(&mut ctx, "/bootstrap/create-cell", "cell-genesis");
        assert_eq!(resp.status, 409);
        assert!(
            resp.body
                .contains("cell name already in use — choose another"),
            "got: {}",
            resp.body
        );
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");
        assert!(!ctx.bootstrap().is_bootstrapped());

        // A DIFFERENT, free name is accepted (best-effort check does not block
        // an unclaimed name).
        let ok = post(&mut ctx, "/bootstrap/create-cell", "cell-unique");
        assert_eq!(ok.status, 200);
        assert!(ok.body.contains("CELL-CREATED"), "got: {}", ok.body);
        // Cell created but NO first user yet — still FRESH (BOOTSTRAPPED is
        // reserved for a cell WITH its first user), so a reload keeps showing
        // the bootstrap form instead of stranding on the login form.
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");
    }

    // The atomic single-step bootstrap (POST /bootstrap/create): one request
    // creates the cell AND the first user, leaving the node fully
    // BOOTSTRAPPED, and the just-created user can log in immediately.
    #[test]
    fn atomic_bootstrap_creates_cell_and_first_user_in_one_step() {
        let (mut ctx, _subkey) = provisioned_ctx();
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");

        let done = post(
            &mut ctx,
            "/bootstrap/create",
            &format!("spencer-cell\nspencer\n{PASSWORD}"),
        );
        assert_eq!(done.status, 200, "got: {}", done.body);
        assert!(done.body.contains("BOOTSTRAPPED spencer"), "got: {}", done.body);
        assert_eq!(
            get(&mut ctx, "/bootstrap/status").body.trim(),
            "BOOTSTRAPPED"
        );
        assert_eq!(ctx.bootstrap().initial_user(), Some("spencer"));

        // The just-created user logs in immediately (offer escrowed atomically).
        let nonce = get(&mut ctx, "/nonce");
        let id: u64 = nonce.body.split_whitespace().nth(1).unwrap().parse().unwrap();
        let login = post(&mut ctx, "/login", &format!("spencer\n{PASSWORD}\n{id}"));
        assert_eq!(login.status, 200, "got: {}", login.body);
    }

    // Recovery: a node stranded in the OLD bug's half-state (cell created, no
    // first user) is completed by the atomic endpoint rather than erroring —
    // exactly the reload/back-button situation the operator hit.
    #[test]
    fn atomic_bootstrap_recovers_a_half_created_cell_without_a_user() {
        let (mut ctx, _subkey) = provisioned_ctx();
        // Simulate the stranded state: only the cell was created (old step a).
        let cell = post(&mut ctx, "/bootstrap/create-cell", "spencer-cell");
        assert_eq!(cell.status, 200);
        // Status is still FRESH (no first user yet) — so the portal re-shows the
        // bootstrap form on reload, and the atomic create completes it.
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");

        let done = post(
            &mut ctx,
            "/bootstrap/create",
            &format!("spencer-cell\nspencer\n{PASSWORD}"),
        );
        assert_eq!(done.status, 200, "got: {}", done.body);
        assert!(done.body.contains("BOOTSTRAPPED spencer"), "got: {}", done.body);
        assert_eq!(ctx.bootstrap().initial_user(), Some("spencer"));
    }

    // Log alice in through the real HTTP handshake and return her session token.
    fn login_alice(ctx: &mut WebAuthContext) -> String {
        let nonce = get(ctx, "/nonce");
        let nonce_id = nonce.body.split_whitespace().nth(1).unwrap().to_owned();
        let login = post(ctx, "/login", &format!("alice@pillar\n{PASSWORD}\n{nonce_id}"));
        assert_eq!(login.status, 200, "login body: {}", login.body);
        login.session_token.expect("session token")
    }

    #[test]
    fn node_bootstrap_request_can_be_submitted_listed_and_approved_returning_a_cid() {
        let (mut ctx, _subkey) = provisioned_ctx();
        // A request can only join an EXISTING cell.
        assert_eq!(
            post(&mut ctx, "/bootstrap/request/node", "new-node").status,
            409
        );
        assert_eq!(post(&mut ctx, "/bootstrap/create-cell", "spencer-cell").status, 200);

        // Submit a node request carrying identifying info.
        let body = "new-node\n12D3KooWpeer\npillar 0.0.0\nlinux\nbafy-nodekey\ntpm\npub=/ip4/203.0.113.7/tcp/4001\nlabel=edge";
        let submitted = post(&mut ctx, "/bootstrap/request/node", body);
        assert_eq!(submitted.status, 200);
        assert!(submitted.body.starts_with("REQUEST "), "got: {}", submitted.body);
        let id = submitted.body.trim_start_matches("REQUEST ").trim();

        // It shows up in the pending list.
        let list = get(&mut ctx, "/bootstrap/request/list");
        assert!(list.body.contains("node new-node"), "got: {}", list.body);

        // Approving without authentication is refused.
        let unauth = post(&mut ctx, "/bootstrap/request/approve", &format!("{id}\nnot-a-token"));
        assert_eq!(unauth.status, 401);

        // Authenticated approval seals the cell key and returns its CID.
        let token = login_alice(&mut ctx);
        let approved = post(&mut ctx, "/bootstrap/request/approve", &format!("{id}\n{token}"));
        assert_eq!(approved.status, 200, "got: {}", approved.body);
        assert!(approved.body.contains("APPROVED bafy-cellkey-"), "got: {}", approved.body);

        // The request is terminal: a second decision is refused.
        let again = post(&mut ctx, "/bootstrap/request/approve", &format!("{id}\n{token}"));
        assert_eq!(again.status, 409);
    }

    #[test]
    fn user_bootstrap_request_approval_escrows_and_returns_no_cell_key() {
        let (mut ctx, _subkey) = provisioned_ctx();
        assert_eq!(post(&mut ctx, "/bootstrap/create-cell", "spencer-cell").status, 200);
        let submitted = post(&mut ctx, "/bootstrap/request/user", "new-user\npassword\nlabel=ops");
        assert_eq!(submitted.status, 200);
        let id = submitted.body.trim_start_matches("REQUEST ").trim().to_owned();
        let token = login_alice(&mut ctx);
        let approved = post(&mut ctx, "/bootstrap/request/approve", &format!("{id}\n{token}"));
        assert_eq!(approved.status, 200, "got: {}", approved.body);
        assert!(approved.body.contains("ESCROWED"), "got: {}", approved.body);
    }

    // The real authenticated portal: an unauthenticated request for node
    // identity/peer/lease status is refused, exactly like every other
    // signing/read action gated behind login.
    #[test]
    fn portal_status_requires_an_admitted_session() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get(&mut ctx, "/portal/status?token=not-a-token");
        assert_eq!(resp.status, 401);
        assert!(resp.body.contains("not-authenticated"), "got: {}", resp.body);
    }

    // Once admitted, the portal renders node/identity status (PeerId, listen
    // addrs, uptime), peer list + count, and the lease holder — all from this
    // node's live view, never a server-side database.
    #[test]
    fn authenticated_portal_renders_identity_status_peer_list_and_lease_holder() {
        let (mut ctx, _subkey) = provisioned_ctx();
        ctx = ctx.with_identity(NodeIdentitySnapshot {
            peer_id: "12D3KooWThisNode".to_owned(),
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/4001".to_owned()],
            connected_peers: vec!["peer-a".to_owned(), "peer-b".to_owned()],
        });
        let token = login_alice(&mut ctx);

        let resp = get(&mut ctx, &format!("/portal/status?token={token}"));
        assert_eq!(resp.status, 200, "got: {}", resp.body);
        assert!(resp.body.contains("PEER-ID 12D3KooWThisNode"), "got: {}", resp.body);
        assert!(
            resp.body.contains("LISTEN /ip4/0.0.0.0/tcp/4001"),
            "got: {}",
            resp.body
        );
        assert!(resp.body.contains("PEER-COUNT 2"), "got: {}", resp.body);
        assert!(resp.body.contains("PEERS peer-a,peer-b"), "got: {}", resp.body);
        assert!(resp.body.contains("UPTIME-SECS"), "got: {}", resp.body);
        // A solo node self-grants its lease at construction, so it reports
        // itself ("owner") as holder out of the box.
        assert!(resp.body.contains("LEASE-HOLDER owner"), "got: {}", resp.body);
    }

    // A UI-persisted layout is a signed, content-addressed resource riding the
    // streaming DB (`pillar-streamdb`) — never a server-side database. Storing
    // requires an admitted session (the resource is signed by that session's
    // subject); it round-trips by its content-addressed CID and advances the
    // log's streaming tip.
    #[test]
    fn ui_persisted_layout_round_trips_as_a_signed_streaming_db_resource() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let token = login_alice(&mut ctx);

        // Unauthenticated store is refused.
        let refused = post(&mut ctx, "/portal/layout", "bad-token\n{\"widgets\":[]}");
        assert_eq!(refused.status, 401);

        let tip_before = ctx.layout_tip();
        let stored = post(
            &mut ctx,
            "/portal/layout",
            &format!("{token}\n{{\"widgets\":[\"peers\",\"inbox\"]}}"),
        );
        assert_eq!(stored.status, 200, "got: {}", stored.body);
        assert!(stored.body.starts_with("LAYOUT-CID "), "got: {}", stored.body);
        let cid: u64 = stored
            .body
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        // The streaming tip (Merkle root) advanced once the op was appended.
        assert_ne!(ctx.layout_tip(), tip_before);

        // Unauthenticated fetch is refused.
        let refused_get = get(&mut ctx, &format!("/portal/layout?token=nope&cid={cid}"));
        assert_eq!(refused_get.status, 401);

        // Authenticated fetch round-trips the signed content, attributed to
        // the storing session's subject.
        let fetched = get(&mut ctx, &format!("/portal/layout?token={token}&cid={cid}"));
        assert_eq!(fetched.status, 200, "got: {}", fetched.body);
        assert!(fetched.body.contains("SIGNER"), "got: {}", fetched.body);
        assert!(
            fetched.body.contains("CONTENT {\"widgets\":[\"peers\",\"inbox\"]}"),
            "got: {}",
            fetched.body
        );
    }

    // The request-approval inbox UI: the portal HTML renders the pending
    // request's fields and Approve/Reject controls wired to the existing
    // backend endpoints (no bare protocol description — a real UI).
    #[test]
    fn request_inbox_ui_renders_list_and_approve_reject_controls() {
        let (mut ctx, _subkey) = provisioned_ctx();
        let resp = get(&mut ctx, "/");
        let body = &resp.body;
        assert!(body.contains("id=\"inbox-list\""), "must render an inbox list container");
        assert!(
            body.contains("/bootstrap/request/list"),
            "must fetch the pending request list"
        );
        assert!(
            body.contains("/bootstrap/request/approve") && body.contains("/bootstrap/request/reject"),
            "must dispatch Approve/Reject through the existing endpoints"
        );
        assert!(body.contains("Approve") && body.contains("Reject"), "got: {}", body);
        // The identity/peer/lease-holder tile is also rendered.
        assert!(body.contains("id=\"portal-peer-id\""), "must render node identity");
        assert!(body.contains("id=\"portal-lease-holder\""), "must render lease holder");
    }

    // The shipped bootstrap flow + status semantics still pass unchanged —
    // regression guard against this task's additions.
    #[test]
    fn bootstrap_flow_and_status_semantics_are_unregressed_by_the_portal_additions() {
        let mut ctx = WebAuthContext::new(
            ORIGIN,
            NodeId::from("this-node"),
            "this-node-secret",
            NodeId::from("owner"),
            4,
        );
        assert_eq!(get(&mut ctx, "/bootstrap/status").body.trim(), "FRESH");
        let done = post(
            &mut ctx,
            "/bootstrap/create",
            &format!("regress-cell\nspencer\n{PASSWORD}"),
        );
        assert_eq!(done.status, 200, "got: {}", done.body);
        assert_eq!(
            get(&mut ctx, "/bootstrap/status").body.trim(),
            "BOOTSTRAPPED"
        );
    }
}
