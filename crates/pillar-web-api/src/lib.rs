//! Shared DTO crate for the `pillar` web portal — see the crate-level
//! `description` in `Cargo.toml`.
//!
//! Every type here crosses the client/server boundary: today that boundary is
//! the hand-rolled HTTP/1.1 surface `pillar-cli::web_serve` speaks (see its
//! module docs for the wire framing of each endpoint); tomorrow it is the
//! same surface a Rust/WASM Yew client (`pillar-frontend`, wired by the
//! `yew-build-wiring` task) parses. Defining these types ONCE here — instead
//! of once in the server and, when the client is built, a hand-copied second
//! time — is what makes drift between the two a *compile error* rather than a
//! runtime surprise.
//!
//! Two shapes of DTO live here:
//!
//! - **Line-framed types** (`LoginRequest`, `NonceResponse`,
//!   `BootstrapStatus`, `BootstrapCreateRequest`, …) mirror the CURRENT
//!   newline-separated plain-text wire framing `web_serve.rs` already speaks
//!   (documented in its module doc). Each carries `to_wire`/`from_body`
//!   helpers that render/parse EXACTLY that framing, so a server handler
//!   constructs/parses the shared type instead of hand-rolling
//!   `lines().next()` calls inline — the type is the single source of truth
//!   for the framing, and a round-trip test below pins it.
//! - **JSON types** (`SessionSummary`, `NodeIdentitySnapshot`,
//!   `CustodyRecord`, the WebAuthn ceremony payloads, the observability query
//!   result, and the trust/RBAC views) are plain `serde`-derived structs
//!   meant for a JSON body (or, today, for constructing the in-process values
//!   the portal's HTML rendering already reads) — the shape a Yew client
//!   fetches/deserializes directly.
//!
//! Every DTO has a serde round-trip test in this crate (`cargo test -p
//! pillar-web-api`): decode(encode(x)) == x. That is the whole definition of
//! done this task's `Check:` gates on.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------

/// `POST /login` request — the two human-supplied fields (identifier +
/// unlock factor) plus the nonce id the client echoes back from a prior
/// `GET /nonce`, binding the login to that exact challenge. Wire framing:
/// `"<identifier>\n<password>\n<nonce_id>"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    /// The user identifier (never a CID — the node resolves that itself).
    pub identifier: String,
    /// The unlock factor (password / passkey secret).
    pub password: String,
    /// The nonce id this login is bound to (from a prior `GET /nonce`).
    pub nonce_id: u64,
}

impl LoginRequest {
    /// Parse the current newline-framed `/login` body into a
    /// [`LoginRequest`]. A missing trailing field parses as an empty string /
    /// `u64::MAX` (an intentionally-unmatchable nonce id), matching the
    /// permissive `lines().next().unwrap_or("")` behavior the handler relied
    /// on before this DTO existed.
    #[must_use]
    pub fn from_body(body: &str) -> Self {
        let mut lines = body.lines();
        let identifier = lines.next().unwrap_or("").trim().to_owned();
        let password = lines.next().unwrap_or("").trim().to_owned();
        let nonce_id = lines
            .next()
            .unwrap_or("")
            .trim()
            .parse()
            .unwrap_or(u64::MAX);
        LoginRequest {
            identifier,
            password,
            nonce_id,
        }
    }

    /// Render back to the exact newline-framed wire body.
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!("{}\n{}\n{}", self.identifier, self.password, self.nonce_id)
    }
}

/// `POST /login` success response — `200 OK` body `"OK <handle>"` plus the
/// `X-Pillar-Session` bearer token (carried out-of-band as an HTTP header,
/// not part of this body type).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginResponse {
    /// The handle the session was admitted under.
    pub handle: String,
}

impl LoginResponse {
    /// Render the `"OK <handle>\n"` success body.
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!("OK {}\n", self.handle)
    }
}

// ---------------------------------------------------------------------
// Nonce
// ---------------------------------------------------------------------

/// `GET /nonce` response — a fresh origin/expiry-bound challenge. Wire
/// framing: `"NONCE <id> <expiry>"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceResponse {
    /// The nonce id (echoed back by a subsequent `/login`).
    pub id: u64,
    /// The nonce's logical expiry tick.
    pub expiry: u64,
}

impl NonceResponse {
    /// Render the `"NONCE <id> <expiry>"` wire body.
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!("NONCE {} {}", self.id, self.expiry)
    }

    /// Parse a `"NONCE <id> <expiry>"` body back into a [`NonceResponse`].
    #[must_use]
    pub fn from_body(body: &str) -> Option<Self> {
        let mut parts = body.split_whitespace();
        if parts.next()? != "NONCE" {
            return None;
        }
        let id = parts.next()?.parse().ok()?;
        let expiry = parts.next()?.parse().ok()?;
        Some(NonceResponse { id, expiry })
    }
}

// ---------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------

/// `GET /bootstrap/status` response — whether this node has its first user
/// yet. Wire framing: `"FRESH"` / `"BOOTSTRAPPED"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootstrapStatus {
    /// No first user yet — the portal shows the create-cell → create-first-
    /// user flow.
    Fresh,
    /// The first user exists — the portal shows the two-field login screen.
    Bootstrapped,
}

impl BootstrapStatus {
    /// Render the `"FRESH"` / `"BOOTSTRAPPED"` wire body.
    #[must_use]
    pub fn to_wire(self) -> &'static str {
        match self {
            BootstrapStatus::Fresh => "FRESH",
            BootstrapStatus::Bootstrapped => "BOOTSTRAPPED",
        }
    }

    /// Parse a `"FRESH"` / `"BOOTSTRAPPED"` body back into a
    /// [`BootstrapStatus`].
    #[must_use]
    pub fn from_body(body: &str) -> Option<Self> {
        match body.trim() {
            "FRESH" => Some(BootstrapStatus::Fresh),
            "BOOTSTRAPPED" => Some(BootstrapStatus::Bootstrapped),
            _ => None,
        }
    }
}

/// `POST /bootstrap/create` request — the ONE atomic bootstrap (cell + first
/// user together). Wire framing: `"<cell_id>\n<handle>\n<password>"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapCreateRequest {
    /// The new cell's id.
    pub cell_id: String,
    /// The first user's handle.
    pub handle: String,
    /// The first user's unlock factor.
    pub password: String,
}

impl BootstrapCreateRequest {
    /// Parse the `"<cell_id>\n<handle>\n<password>"` body.
    #[must_use]
    pub fn from_body(body: &str) -> Self {
        let mut lines = body.lines();
        BootstrapCreateRequest {
            cell_id: lines.next().unwrap_or("").trim().to_owned(),
            handle: lines.next().unwrap_or("").trim().to_owned(),
            password: lines.next().unwrap_or("").trim().to_owned(),
        }
    }

    /// Render back to the exact wire body.
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!("{}\n{}\n{}", self.cell_id, self.handle, self.password)
    }
}

/// `POST /bootstrap/create-cell` request — operator step (a). Wire framing:
/// the body IS the cell id (no newlines).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapCreateCellRequest {
    /// The new cell's id.
    pub cell_id: String,
}

impl BootstrapCreateCellRequest {
    /// Parse the bare-cell-id body.
    #[must_use]
    pub fn from_body(body: &str) -> Self {
        BootstrapCreateCellRequest {
            cell_id: body.trim().to_owned(),
        }
    }

    /// Render back to the exact wire body.
    #[must_use]
    pub fn to_wire(&self) -> String {
        self.cell_id.clone()
    }
}

/// `POST /bootstrap/create-user` request — operator step (b). Wire framing:
/// `"<handle>\n<password>"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapCreateUserRequest {
    /// The new first user's handle.
    pub handle: String,
    /// The new first user's unlock factor.
    pub password: String,
}

impl BootstrapCreateUserRequest {
    /// Parse the `"<handle>\n<password>"` body.
    #[must_use]
    pub fn from_body(body: &str) -> Self {
        let mut lines = body.lines();
        BootstrapCreateUserRequest {
            handle: lines.next().unwrap_or("").trim().to_owned(),
            password: lines.next().unwrap_or("").trim().to_owned(),
        }
    }

    /// Render back to the exact wire body.
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!("{}\n{}", self.handle, self.password)
    }
}

// ---------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------

/// A portal session-management panel's per-session view: id, node/domain,
/// issued-at, expiry, and whether this IS the caller's own current session.
/// The canonical shared definition of what was, before this task, a
/// server-private struct in `pillar-cli::web_serve` — moved here so a future
/// Yew client deserializes the identical shape the server renders.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    /// The session id (== the portal bearer token it was minted for).
    pub id: String,
    /// The node/domain this session was issued on (this node's own peer id —
    /// a portal session is always local-node scoped).
    pub node: String,
    /// Logical issue time.
    pub issued_at: u64,
    /// Logical expiry time — the panel derives its live countdown from this.
    pub expiry: u64,
    /// Whether this is the session the panel's own caller is viewing under.
    pub is_current: bool,
}

// ---------------------------------------------------------------------
// Identity / reachability
// ---------------------------------------------------------------------

/// A read-only snapshot of a node's identity/reachability, as the
/// authenticated portal renders it: peer id, listen multiaddrs, connected
/// peers. Moved here from `pillar-cli::web_serve` for the same reason as
/// [`SessionSummary`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentitySnapshot {
    /// This node's libp2p-style peer id (derived from its identity keypair).
    pub peer_id: String,
    /// The multiaddrs this node listens on.
    pub listen_addrs: Vec<String>,
    /// The peers this node currently considers connected (peer ids).
    pub connected_peers: Vec<String>,
}

// ---------------------------------------------------------------------
// Custody
// ---------------------------------------------------------------------

/// One handle's custody record, as the key & offer UI renders/drives it.
/// `holder` and `cid` are carried as plain strings (rather than the server's
/// internal `NodeId`/`Cid` newtypes) so this crate stays free of any
/// server-internal domain-type dependency — a client parses this DTO without
/// pulling in `pillar-core`/`pillar-web`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyRecord {
    /// The node currently custodying this handle's operational-key offer.
    pub holder: String,
    /// The offer's content address.
    pub cid: String,
    /// Whether the offer is currently sealed (escrowed) to `holder`.
    pub sealed: bool,
    /// Bumped by every rotate — the current key-material generation.
    pub generation: u64,
}

// ---------------------------------------------------------------------
// WebAuthn ceremony payloads
// ---------------------------------------------------------------------
//
// The current portal speaks only password-based node-custody login
// (`pillar_web::key_login`/`node_custody`); no browser WebAuthn ceremony is
// wired yet (that is Yew-client work this crate exists to unblock without
// drift). These payload shapes are the forward-looking shared contract a
// future `/webauthn/*` surface constructs/parses on both sides, expressed
// generically (base64url-encoded opaque blobs, per the WebAuthn spec's own
// wire convention) so they need no browser/WASM types to compile natively.

/// A WebAuthn registration ("attestation") ceremony ask: the challenge plus
/// the relying-party id and the user handle being enrolled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnRegisterChallenge {
    /// Base64url-encoded random challenge.
    pub challenge: String,
    /// The WebAuthn relying-party id (typically the portal's origin host).
    pub rp_id: String,
    /// The user handle being enrolled.
    pub user_handle: String,
}

/// The browser's WebAuthn registration ceremony result, handed back for the
/// server to verify and register.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnRegisterAttestation {
    /// The new credential's id (base64url).
    pub credential_id: String,
    /// The base64url-encoded CBOR attestation object.
    pub attestation_object: String,
    /// The base64url-encoded `clientDataJSON`.
    pub client_data_json: String,
}

/// A WebAuthn authentication ("assertion") ceremony ask: the challenge a
/// registered credential must sign.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnAuthChallenge {
    /// Base64url-encoded random challenge.
    pub challenge: String,
}

/// The browser's WebAuthn authentication ceremony result, handed back for the
/// server to verify against the registered credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnAuthAssertion {
    /// The asserting credential's id (base64url).
    pub credential_id: String,
    /// The base64url-encoded authenticator data.
    pub authenticator_data: String,
    /// The base64url-encoded `clientDataJSON`.
    pub client_data_json: String,
    /// The base64url-encoded signature over authenticator data +
    /// `clientDataJSON` hash.
    pub signature: String,
}

// ---------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------

/// An observability query the portal's dashboard/panel issues against the
/// node's streaming-DB-backed timeseries store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityQueryRequest {
    /// The signal kind being queried (mirrors `pillar_observability::SignalKind`
    /// by name so this crate need not depend on that crate).
    pub kind: String,
    /// An optional selector narrowing the query (label/name match).
    pub selector: Option<String>,
}

/// One row of an observability query result — an ordered list of
/// `(column, value)` pairs so a heterogeneous result set (different signal
/// kinds project different columns) round-trips without a fixed schema.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityRow {
    /// The row's `(column, value)` pairs, in display order.
    pub fields: Vec<(String, String)>,
}

/// An observability query's result set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityQueryResult {
    /// The matched rows, in query order.
    pub rows: Vec<ObservabilityRow>,
}

// ---------------------------------------------------------------------
// Trust / RBAC views
// ---------------------------------------------------------------------

/// One member's view in the `GET /portal/members` panel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberView {
    /// The member's handle.
    pub handle: String,
    /// The member's role.
    pub role: String,
}

/// The `GET /portal/members` response: this cell's members and their roles.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembersResponse {
    /// The cell's members, in listing order.
    pub members: Vec<MemberView>,
}

/// A resource/workload `describe` view: full detail INCLUDING provenance
/// (the signer, the authorizing capability, and the emitting event's CID) —
/// mirrors what `GET /portal/resource/describe` renders.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceDescribeView {
    /// The resource's kind (e.g. `Workload`, `User`).
    pub kind: String,
    /// The resource's name.
    pub name: String,
    /// The resource's fields, in display order.
    pub fields: Vec<(String, String)>,
    /// The signer that authored the last act against this resource, if any.
    pub signer: Option<String>,
    /// The RBAC capability that authorized the last act, if any.
    pub capability: Option<String>,
    /// The event CID the last act emitted, if any.
    pub event_cid: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(value).expect("serialize");
        let back: T = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&back, value, "round-trip drift for json: {json}");
    }

    #[test]
    fn login_request_json_round_trips() {
        round_trip(&LoginRequest {
            identifier: "alice@pillar".to_owned(),
            password: "hunter2".to_owned(),
            nonce_id: 42,
        });
    }

    #[test]
    fn login_request_wire_round_trips() {
        let req = LoginRequest {
            identifier: "alice@pillar".to_owned(),
            password: "hunter2".to_owned(),
            nonce_id: 42,
        };
        let wire = req.to_wire();
        assert_eq!(LoginRequest::from_body(&wire), req);
    }

    #[test]
    fn login_response_json_round_trips() {
        round_trip(&LoginResponse {
            handle: "alice".to_owned(),
        });
    }

    #[test]
    fn login_response_wire_renders() {
        let resp = LoginResponse {
            handle: "alice".to_owned(),
        };
        assert_eq!(resp.to_wire(), "OK alice\n");
    }

    #[test]
    fn nonce_response_json_round_trips() {
        round_trip(&NonceResponse {
            id: 7,
            expiry: 1_000_000,
        });
    }

    #[test]
    fn nonce_response_wire_round_trips() {
        let resp = NonceResponse {
            id: 7,
            expiry: 1_000_000,
        };
        let wire = resp.to_wire();
        assert_eq!(NonceResponse::from_body(&wire), Some(resp));
    }

    #[test]
    fn bootstrap_status_json_round_trips() {
        round_trip(&BootstrapStatus::Fresh);
        round_trip(&BootstrapStatus::Bootstrapped);
    }

    #[test]
    fn bootstrap_status_wire_round_trips() {
        for status in [BootstrapStatus::Fresh, BootstrapStatus::Bootstrapped] {
            let wire = status.to_wire();
            assert_eq!(BootstrapStatus::from_body(wire), Some(status));
        }
    }

    #[test]
    fn bootstrap_create_request_json_round_trips() {
        round_trip(&BootstrapCreateRequest {
            cell_id: "cell-1".to_owned(),
            handle: "spencer".to_owned(),
            password: "s3cret".to_owned(),
        });
    }

    #[test]
    fn bootstrap_create_request_wire_round_trips() {
        let req = BootstrapCreateRequest {
            cell_id: "cell-1".to_owned(),
            handle: "spencer".to_owned(),
            password: "s3cret".to_owned(),
        };
        let wire = req.to_wire();
        assert_eq!(BootstrapCreateRequest::from_body(&wire), req);
    }

    #[test]
    fn bootstrap_create_cell_request_json_round_trips() {
        round_trip(&BootstrapCreateCellRequest {
            cell_id: "cell-1".to_owned(),
        });
    }

    #[test]
    fn bootstrap_create_cell_request_wire_round_trips() {
        let req = BootstrapCreateCellRequest {
            cell_id: "cell-1".to_owned(),
        };
        let wire = req.to_wire();
        assert_eq!(BootstrapCreateCellRequest::from_body(&wire), req);
    }

    #[test]
    fn bootstrap_create_user_request_json_round_trips() {
        round_trip(&BootstrapCreateUserRequest {
            handle: "spencer".to_owned(),
            password: "s3cret".to_owned(),
        });
    }

    #[test]
    fn bootstrap_create_user_request_wire_round_trips() {
        let req = BootstrapCreateUserRequest {
            handle: "spencer".to_owned(),
            password: "s3cret".to_owned(),
        };
        let wire = req.to_wire();
        assert_eq!(BootstrapCreateUserRequest::from_body(&wire), req);
    }

    #[test]
    fn session_summary_json_round_trips() {
        round_trip(&SessionSummary {
            id: "tok-1".to_owned(),
            node: "peer-1".to_owned(),
            issued_at: 10,
            expiry: 1_000_010,
            is_current: true,
        });
    }

    #[test]
    fn node_identity_snapshot_json_round_trips() {
        round_trip(&NodeIdentitySnapshot {
            peer_id: "peer-1".to_owned(),
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/4001".to_owned()],
            connected_peers: vec!["peer-2".to_owned()],
        });
    }

    #[test]
    fn node_identity_snapshot_default_json_round_trips() {
        round_trip(&NodeIdentitySnapshot::default());
    }

    #[test]
    fn custody_record_json_round_trips() {
        round_trip(&CustodyRecord {
            holder: "peer-1".to_owned(),
            cid: "cid-1".to_owned(),
            sealed: true,
            generation: 3,
        });
    }

    #[test]
    fn webauthn_register_challenge_json_round_trips() {
        round_trip(&WebAuthnRegisterChallenge {
            challenge: "Y2hhbGxlbmdl".to_owned(),
            rp_id: "pillar.example".to_owned(),
            user_handle: "alice".to_owned(),
        });
    }

    #[test]
    fn webauthn_register_attestation_json_round_trips() {
        round_trip(&WebAuthnRegisterAttestation {
            credential_id: "Y3JlZA".to_owned(),
            attestation_object: "YXR0ZXN0".to_owned(),
            client_data_json: "Y2xpZW50ZGF0YQ".to_owned(),
        });
    }

    #[test]
    fn webauthn_auth_challenge_json_round_trips() {
        round_trip(&WebAuthnAuthChallenge {
            challenge: "Y2hhbGxlbmdl".to_owned(),
        });
    }

    #[test]
    fn webauthn_auth_assertion_json_round_trips() {
        round_trip(&WebAuthnAuthAssertion {
            credential_id: "Y3JlZA".to_owned(),
            authenticator_data: "YXV0aGRhdGE".to_owned(),
            client_data_json: "Y2xpZW50ZGF0YQ".to_owned(),
            signature: "c2ln".to_owned(),
        });
    }

    #[test]
    fn observability_query_request_json_round_trips() {
        round_trip(&ObservabilityQueryRequest {
            kind: "cpu".to_owned(),
            selector: Some("node=peer-1".to_owned()),
        });
        round_trip(&ObservabilityQueryRequest {
            kind: "cpu".to_owned(),
            selector: None,
        });
    }

    #[test]
    fn observability_row_json_round_trips() {
        round_trip(&ObservabilityRow {
            fields: vec![("ts".to_owned(), "10".to_owned()), ("value".to_owned(), "0.5".to_owned())],
        });
    }

    #[test]
    fn observability_query_result_json_round_trips() {
        round_trip(&ObservabilityQueryResult {
            rows: vec![ObservabilityRow {
                fields: vec![("ts".to_owned(), "10".to_owned())],
            }],
        });
    }

    #[test]
    fn member_view_json_round_trips() {
        round_trip(&MemberView {
            handle: "alice".to_owned(),
            role: "admin".to_owned(),
        });
    }

    #[test]
    fn members_response_json_round_trips() {
        round_trip(&MembersResponse {
            members: vec![MemberView {
                handle: "alice".to_owned(),
                role: "admin".to_owned(),
            }],
        });
    }

    #[test]
    fn resource_describe_view_json_round_trips() {
        round_trip(&ResourceDescribeView {
            kind: "Workload".to_owned(),
            name: "web".to_owned(),
            fields: vec![("replicas".to_owned(), "3".to_owned())],
            signer: Some("alice".to_owned()),
            capability: Some("resource/act".to_owned()),
            event_cid: Some("cid-1".to_owned()),
        });
    }
}
