//! `pillar apply -f`/`pillar delete` over pillar-message
//! (`cli-apply-over-pillar-message`, 2026-09-11 ROI HEAD): THE CAPSTONE proof
//! that a Pillar mutation is never a privileged REST call to a node. This
//! module constructs a [`pillar_ops::ResourceOp`] from a manifest (or a
//! `kind/name` address for `delete`), seals+signs it with the caller's own
//! ed25519 signing key, and dials a live node over the real pillar-UDP ->
//! QUIC -> HTTPS fallback chain via [`pillar_client::transport`] — the SAME
//! client crate every future Pillar client (a GUI, a CI runner) reuses.
//!
//! Authentication here IS the ed25519 signature over the sealed body: the
//! node authenticates the producer from that signature alone (see
//! `pillar_net::client_ingest`/`crate::resource_op_udp_server`) and then
//! authorizes it under the SAME WoT/RBAC decider a workload/cronjob HTTP
//! mutation already runs through — there is no separate, weaker act for a
//! manifest apply. `pillar apply`/`pillar delete` therefore need no session
//! login of their own; they need only the signing key the operator's node
//! has already admitted (see `POST /bootstrap/admit-resource-signer`, a
//! one-time SETUP step, never part of the mutation path itself).
//!
//! ## Connecting
//!
//! The caller supplies where to dial and which key to sign with via
//! environment variables (mirroring `PILLAR_DATA_DIR` etc. elsewhere in this
//! binary) rather than a `config.yaml` layer, since this is the FIRST
//! pillar-message-native mutation path and the config/discovery slices this
//! crate's sibling `pillar-client::config`/`discovery` modules own are a
//! separate, already-shipped concern this command is free to grow into:
//!
//! - `PILLAR_RESOURCE_OP_ADDR` — `host:port` of the target node's
//!   resource-op pillar-UDP tier (required).
//! - `PILLAR_CELL_ID_HEX` — the target cell id's raw bytes, lowercase hex
//!   (required; a node's own `cell_id` is itself a derived byte string, not
//!   readable UTF-8 text, so it must travel as hex here).
//! - `PILLAR_CELL_SEED_HEX` — the SAME per-cell seed material the node
//!   derived its `cell_group_key` from (`pillar_crypto::cell::
//!   group_key_from_seed`), lowercase hex (required). This crate derives
//!   the group key from it identically, so a caller never needs to compute
//!   or transmit the raw symmetric key itself.
//! - `PILLAR_SIGNER_SECRET_HEX` / `PILLAR_SIGNER_PUBLIC_HEX` — the caller's
//!   ed25519 signing keypair, lowercase hex (required).

use std::net::{SocketAddr, ToSocketAddrs};
use std::process::ExitCode;

use pillar_client::transport::{send_op_with_fallback, TierAddr};
use pillar_client::TransportKind;
use pillar_crypto::cell::group_key_from_seed;
use pillar_crypto::{CellId, SigningPublicKey, SigningSecretKey};
use pillar_wire::{Body, Visibility};

use crate::resource::Address;

/// A fault preparing to dial — a missing/malformed environment variable, or
/// an address string that will not parse.
#[derive(Debug)]
pub enum ConnectError {
    /// A required environment variable is missing (names the variable).
    MissingEnv(&'static str),
    /// An address string that will not parse (names the offending value).
    BadAddr(&'static str),
    /// A hex-encoded value that will not decode (names the offending value).
    BadHex(&'static str),
    /// No `PILLAR_RESOURCE_OP_ADDR` env and no `identity:` block in any loaded
    /// `config.yaml` — nothing tells the CLI where/how to connect. Run the
    /// UI's "Download CLI config" (profile page) and drop the file at
    /// `~/.config/pillar/config.yaml`.
    MissingIdentity,
    /// A `config.yaml` was present but could not be loaded/parsed.
    Config(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::MissingEnv(v) => write!(f, "missing required env var {v}"),
            ConnectError::BadAddr(v) => write!(f, "{v} is not a valid host:port"),
            ConnectError::BadHex(v) => write!(f, "{v} is not valid lowercase hex"),
            ConnectError::MissingIdentity => f.write_str(
                "no PILLAR_RESOURCE_OP_ADDR env and no identity: block in config.yaml — \
                 download a CLI config from the portal profile page",
            ),
            ConnectError::Config(e) => write!(f, "loading config.yaml: {e}"),
        }
    }
}

struct Connect {
    addr: SocketAddr,
    cell: CellId,
    group: pillar_crypto::cell::CellGroupKey,
    signer: SigningPublicKey,
    secret: SigningSecretKey,
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn env(name: &'static str) -> Result<String, ConnectError> {
    std::env::var(name).map_err(|_| ConnectError::MissingEnv(name))
}

/// Resolve a `host:port` (or `ip:port`) endpoint to a concrete [`SocketAddr`],
/// so a `config.yaml` / env value may carry a DNS name (e.g.
/// `pillar.example.com:8644` — the UI-exported endpoint) rather than only a
/// literal IP. Prefers an IPv4 result when a name resolves to both families
/// (the resource-op hostPort is IPv4), else the first address returned.
fn resolve_addr(s: &str, field: &'static str) -> Result<SocketAddr, ConnectError> {
    let addrs: Vec<SocketAddr> = s
        .to_socket_addrs()
        .map_err(|_| ConnectError::BadAddr(field))?
        .collect();
    addrs
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .or_else(|| addrs.first().copied())
        .ok_or(ConnectError::BadAddr(field))
}

fn connect_from_env() -> Result<Connect, ConnectError> {
    let addr_s = env("PILLAR_RESOURCE_OP_ADDR")?;
    let addr = resolve_addr(&addr_s, "PILLAR_RESOURCE_OP_ADDR")?;
    let cell_id_hex = env("PILLAR_CELL_ID_HEX")?;
    let cell = CellId::from_bytes(
        decode_hex(&cell_id_hex).ok_or(ConnectError::BadHex("PILLAR_CELL_ID_HEX"))?,
    );
    let seed_hex = env("PILLAR_CELL_SEED_HEX")?;
    let seed_bytes = decode_hex(&seed_hex).ok_or(ConnectError::BadHex("PILLAR_CELL_SEED_HEX"))?;
    let group = group_key_from_seed(&pillar_crypto::Seed::from_bytes(seed_bytes))
        .map_err(|_| ConnectError::BadHex("PILLAR_CELL_SEED_HEX"))?;
    let signer_hex = env("PILLAR_SIGNER_PUBLIC_HEX")?;
    let signer = SigningPublicKey::from_bytes(
        decode_hex(&signer_hex).ok_or(ConnectError::BadHex("PILLAR_SIGNER_PUBLIC_HEX"))?,
    );
    let secret_hex = env("PILLAR_SIGNER_SECRET_HEX")?;
    let secret = SigningSecretKey::from_bytes(
        decode_hex(&secret_hex).ok_or(ConnectError::BadHex("PILLAR_SIGNER_SECRET_HEX"))?,
    );
    Ok(Connect {
        addr,
        cell,
        group,
        signer,
        secret,
    })
}

/// Build a [`Connect`] from a loaded `config.yaml`'s `identity:` block (the
/// UI-exported turnkey material). The layered search path is the standard
/// [`pillar_client::ConfigDirs::from_env`] (`/etc/pillar` < XDG < `~/.pillar`)
/// plus an explicit `$PILLAR_CONFIG`.
fn connect_from_config() -> Result<Connect, ConnectError> {
    let explicit = std::env::var("PILLAR_CONFIG")
        .ok()
        .map(std::path::PathBuf::from);
    let cfg = pillar_client::load(&pillar_client::ConfigDirs::from_env(), explicit.as_deref())
        .map_err(|e| ConnectError::Config(e.to_string()))?;
    let id = cfg.identity.ok_or(ConnectError::MissingIdentity)?;
    let addr = resolve_addr(&id.addr, "identity.addr")?;
    let cell = CellId::from_bytes(
        decode_hex(&id.cell_id_hex).ok_or(ConnectError::BadHex("identity.cell-id-hex"))?,
    );
    let seed_bytes =
        decode_hex(&id.cell_seed_hex).ok_or(ConnectError::BadHex("identity.cell-seed-hex"))?;
    let group = group_key_from_seed(&pillar_crypto::Seed::from_bytes(seed_bytes))
        .map_err(|_| ConnectError::BadHex("identity.cell-seed-hex"))?;
    let signer = SigningPublicKey::from_bytes(
        decode_hex(&id.signer_public_hex)
            .ok_or(ConnectError::BadHex("identity.signer-public-hex"))?,
    );
    let secret = SigningSecretKey::from_bytes(
        decode_hex(&id.signer_secret_hex)
            .ok_or(ConnectError::BadHex("identity.signer-secret-hex"))?,
    );
    Ok(Connect {
        addr,
        cell,
        group,
        signer,
        secret,
    })
}

/// Resolve connection material, preferring the explicit `PILLAR_*` environment
/// (the advanced / test path) and otherwise reading the `identity:` block of a
/// loaded `config.yaml` (the UI-exported turnkey path). The env override is
/// selected iff `PILLAR_RESOURCE_OP_ADDR` is set, so an all-env invocation is
/// byte-for-byte unchanged.
fn connect() -> Result<Connect, ConnectError> {
    if std::env::var("PILLAR_RESOURCE_OP_ADDR").is_ok() {
        connect_from_env()
    } else {
        connect_from_config()
    }
}

fn tiers(addr: SocketAddr) -> Vec<TierAddr> {
    vec![TierAddr {
        tier: TransportKind::PillarUdp,
        addr,
    }]
}

/// A fault sending a [`pillar_ops::ResourceOp`] over pillar-message —
/// returned by [`send_op`], the pure (non-`ExitCode`) core [`apply`]/
/// [`delete`] wrap, so a test can assert on the real outcome text rather
/// than an opaque process exit code.
#[derive(Debug)]
pub enum SendError {
    /// Failed to establish the connection to the resource-op endpoint.
    Connect(ConnectError),
    /// A transport-level failure while sending/receiving (with a description).
    Transport(String),
    /// The response acknowledgement could not be unsealed.
    UnsealAck,
    /// The acknowledgement body was malformed.
    BadAckBody,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Connect(e) => write!(f, "{e}"),
            SendError::Transport(e) => write!(f, "{e}"),
            SendError::UnsealAck => {
                f.write_str("node ack did not open under this cell's group key")
            }
            SendError::BadAckBody => f.write_str("node ack body was not the expected Control text"),
        }
    }
}

/// Send `op` to the node named by the `PILLAR_*` environment (see the module
/// docs) over the real dial/seal/sign [`pillar_client::transport`] path, and
/// return the node's decoded ack text (`"OK <event-cid>"` / `"ERR <reason>"`)
/// plus which transport tier actually answered. This is the pure core
/// [`apply`]/[`delete`] wrap with argv parsing + `ExitCode` translation; a
/// test calls this directly to assert on the real outcome.
///
/// # Errors
/// [`SendError`] for a missing/malformed environment variable, an
/// unreachable node, or a reply that fails to open/decode.
pub fn send_op(op: &pillar_ops::ResourceOp) -> Result<(String, TransportKind), SendError> {
    let conn = connect().map_err(SendError::Connect)?;
    let outcome = send_op_with_fallback(
        &tiers(conn.addr),
        op,
        &conn.group,
        conn.cell.clone(),
        conn.signer,
        &conn.secret,
        Visibility::Cell,
    )
    .map_err(SendError::Transport)?;
    use pillar_wire::seal::{CellSeal, ContentSeal};
    let aad =
        pillar_wire::PillarMessage::header_aad(outcome.response.visibility, &outcome.response.cell);
    let plaintext = CellSeal
        .open(&conn.group, &outcome.response.body_sealed, &aad)
        .map_err(|_| SendError::UnsealAck)?;
    match Body::from_canonical_cbor(&plaintext) {
        Ok(Body::Control(bytes)) => {
            Ok((String::from_utf8_lossy(&bytes).into_owned(), outcome.tier))
        }
        _ => Err(SendError::BadAckBody),
    }
}

/// One resource's apply outcome within a (possibly multi-document) manifest.
pub struct AppliedAck {
    /// The resource's `kind/name`, for a per-document report line.
    pub label: String,
    /// The node's acknowledgement string (starts with `OK` on success).
    pub ack: String,
    /// The transport tier the op was accepted over.
    pub tier: TransportKind,
}

/// Parse `text` as a (possibly multi-document) manifest and send EACH resource
/// as its own `ResourceOp::Apply` over pillar-message (see [`send_op`]). This is
/// the pure core `pillar apply -f` wraps with argv parsing + `ExitCode`
/// translation — a test calls this directly to assert on the real outcome.
///
/// Parsing is atomic: a malformed document fails the whole batch BEFORE any op
/// is sent. Sending is sequential; the first transport failure aborts and is
/// returned (resources already accepted by the node stay applied — upsert
/// semantics, so a re-run is safe).
///
/// # Errors
/// A parse error string for a malformed manifest; else the first [`SendError`].
pub fn apply_manifest_text(text: &str) -> Result<Vec<AppliedAck>, String> {
    let crds = pillar_manifest::Crd::from_documents(text).map_err(|e| e.to_string())?;
    let mut acks = Vec::with_capacity(crds.len());
    for crd in crds {
        let label = format!("{}/{}", crd.kind, crd.metadata.name);
        let (ack, tier) =
            send_op(&pillar_ops::ResourceOp::Apply { crd }).map_err(|e| e.to_string())?;
        acks.push(AppliedAck { label, ack, tier });
    }
    Ok(acks)
}

/// Parse `addr` as `kind/name` and send it as a `ResourceOp::Delete` over
/// pillar-message (see [`send_op`]). The pure core `pillar delete` wraps.
///
/// # Errors
/// A parse error string for a malformed address; else [`SendError`].
pub fn delete_resource(addr: &str) -> Result<(String, TransportKind), String> {
    let address = Address::parse(addr).map_err(|e| e.to_string())?;
    send_op(&pillar_ops::ResourceOp::Delete {
        kind: address.kind,
        name: address.name,
    })
    .map_err(|e| e.to_string())
}

/// `pillar apply -f <manifest.yaml>`: parse a YAML or JSON manifest bundle
/// (multi-document `---` stream, single document, or a `kind: List`) into one
/// CRD per resource and send each as a `ResourceOp::Apply` over pillar-message.
pub fn apply(args: &[String]) -> ExitCode {
    let mut file = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--file" => {
                file = args.get(i + 1).cloned();
                i += 2;
            }
            _ => i += 1,
        }
    }
    let Some(file) = file else {
        eprintln!("usage: pillar apply -f <manifest.yaml>");
        return ExitCode::from(2);
    };
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("pillar apply: reading {file}: {e}");
            return ExitCode::FAILURE;
        }
    };
    match apply_manifest_text(&text) {
        Ok(acks) => {
            let mut all_ok = true;
            for a in &acks {
                println!("{}: {} (via {:?})", a.label, a.ack, a.tier);
                if !a.ack.starts_with("OK") {
                    all_ok = false;
                }
            }
            if all_ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("pillar apply: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `pillar delete <kind>/<name>`: send a `ResourceOp::Delete` over
/// pillar-message.
pub fn delete(args: &[String]) -> ExitCode {
    let Some(addr) = args.first() else {
        eprintln!("usage: pillar delete <kind>/<name>");
        return ExitCode::from(2);
    };
    match delete_resource(addr) {
        Ok((ack, tier)) => {
            println!("{ack} (via {tier:?})");
            if ack.starts_with("OK") {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("pillar delete: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Send a read-only [`pillar_ops::ResourceOp`] (`Get`/`Describe`) and return
/// the node's materialized-view payload — the text the ack carries after its
/// `OK ` status prefix (see `resource_op_udp_server::ack_message`). A node
/// refusal (`ERR <reason>`) is returned as an `Err(<reason>)`.
///
/// # Errors
/// The stringified [`SendError`] for a transport/connection fault, or the
/// node's refusal reason for a `ERR` ack.
fn read_op(op: &pillar_ops::ResourceOp) -> Result<String, String> {
    let (ack, _tier) = send_op(op).map_err(|e| e.to_string())?;
    if let Some(payload) = ack.strip_prefix("OK ") {
        Ok(payload.to_owned())
    } else if ack == "OK" {
        Ok(String::new())
    } else {
        Err(ack.strip_prefix("ERR ").unwrap_or(&ack).to_owned())
    }
}

/// Read the live cell's materialized view of `kind` over pillar-message. `name`
/// `None` lists every object as a `---`-separated CRD-YAML stream; `Some`
/// renders that one object's CRD YAML. The pure core `pillar get` wraps.
///
/// # Errors
/// A transport error string, or the node's refusal reason (unauthorized signer,
/// not-found).
pub fn get_resource(kind: &str, name: Option<&str>) -> Result<String, String> {
    read_op(&pillar_ops::ResourceOp::Get {
        kind: kind.to_owned(),
        name: name.map(ToOwned::to_owned),
    })
}

/// Describe one resource over pillar-message: full detail INCLUDING provenance
/// (signer, authorizing capability, event CID). The pure core `pillar describe`
/// wraps.
///
/// # Errors
/// A transport error string, or the node's refusal reason.
pub fn describe_resource(kind: &str, name: &str) -> Result<String, String> {
    read_op(&pillar_ops::ResourceOp::Describe {
        kind: kind.to_owned(),
        name: name.to_owned(),
    })
}

/// `pillar get <kind> [name]`: read the live cell's materialized resource view
/// over pillar-message and print each matching resource as CRD YAML.
pub fn get(args: &[String]) -> ExitCode {
    let Some(kind) = args.first() else {
        eprintln!("usage: pillar get <kind> [name]");
        return ExitCode::from(2);
    };
    let name = args.get(1).map(String::as_str);
    match get_resource(kind, name) {
        Ok(text) => {
            if text.trim().is_empty() {
                eprintln!("no {kind} resources");
            } else {
                print!("{text}");
                if !text.ends_with('\n') {
                    println!();
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("pillar get: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `pillar describe <kind>/<name>` (or `<kind> <name>`): print one resource's
/// full detail (incl. provenance) from the live view over pillar-message.
pub fn describe(args: &[String]) -> ExitCode {
    let (kind, name) = match args {
        [one] => match one.split_once('/') {
            Some((k, n)) if !k.is_empty() && !n.is_empty() => (k.to_owned(), n.to_owned()),
            _ => {
                eprintln!("usage: pillar describe <kind>/<name>");
                return ExitCode::from(2);
            }
        },
        [k, n] => (k.clone(), n.clone()),
        _ => {
            eprintln!("usage: pillar describe <kind>/<name>");
            return ExitCode::from(2);
        }
    };
    match describe_resource(&kind, &name) {
        Ok(text) => {
            print!("{text}");
            if !text.ends_with('\n') {
                println!();
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("pillar describe: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// Control ops (`pillar_ops::ControlOp`) over the SAME sealed resource-op tier.
// The first family is `member`; each new family adds a thin client wrap here
// and a signer-gated handler node-side (see `web_serve::WebAuthContext`).
// ---------------------------------------------------------------------------

/// Send a [`pillar_ops::ControlOp`] over pillar-message and return the node's
/// decoded ack text (`"OK <detail>"` / `"ERR <reason>"`) plus the tier that
/// answered. The control-op sibling of [`send_op`] — identical dial/seal/sign/
/// open path, only the op class (and its seal domain) differ.
///
/// # Errors
/// [`SendError`] for a missing/malformed environment, an unreachable node, or a
/// reply that fails to open/decode.
pub fn send_control_op(op: &pillar_ops::ControlOp) -> Result<(String, TransportKind), SendError> {
    let conn = connect().map_err(SendError::Connect)?;
    let outcome = pillar_client::transport::send_control_op_with_fallback(
        &tiers(conn.addr),
        op,
        &conn.group,
        conn.cell.clone(),
        conn.signer,
        &conn.secret,
        Visibility::Cell,
    )
    .map_err(SendError::Transport)?;
    use pillar_wire::seal::{CellSeal, ContentSeal};
    let aad =
        pillar_wire::PillarMessage::header_aad(outcome.response.visibility, &outcome.response.cell);
    let plaintext = CellSeal
        .open(&conn.group, &outcome.response.body_sealed, &aad)
        .map_err(|_| SendError::UnsealAck)?;
    match Body::from_canonical_cbor(&plaintext) {
        Ok(Body::Control(bytes)) => {
            Ok((String::from_utf8_lossy(&bytes).into_owned(), outcome.tier))
        }
        _ => Err(SendError::BadAckBody),
    }
}

/// Send a control op and unwrap its ack to the payload text, mapping an `ERR`
/// ack to `Err`. Mirrors [`read_op`] for the control-op class. `pub` so
/// acceptance tests (e.g. `um-security-events-feed`) can drive an arbitrary
/// [`pillar_ops::ControlOp`] (members/session/identity acts) over the real
/// remote surface, the same way [`user_op`] does for [`pillar_ops::UserOp`].
///
/// # Errors
/// A transport error string, or the node's refusal reason (unauthorized signer,
/// not-found, …) with the `ERR ` prefix stripped.
pub fn control_op(op: &pillar_ops::ControlOp) -> Result<String, String> {
    let (ack, _tier) = send_control_op(op).map_err(|e| e.to_string())?;
    if let Some(payload) = ack.strip_prefix("OK ") {
        Ok(payload.to_owned())
    } else if ack == "OK" {
        Ok(String::new())
    } else {
        Err(ack.strip_prefix("ERR ").unwrap_or(&ack).to_owned())
    }
}

/// List the cell's members over pillar-message. The pure core `pillar member
/// ls` wraps.
///
/// # Errors
/// A transport error string, or the node's refusal reason.
pub fn list_members() -> Result<String, String> {
    control_op(&pillar_ops::ControlOp::Members(pillar_ops::MembersOp::List))
}

/// Add or invite a member with a role over pillar-message. The pure core
/// `pillar member add` wraps.
///
/// # Errors
/// A transport error string, or the node's refusal (unauthorized actor for
/// `portal:members:write`).
pub fn add_member(handle: &str, role: &str) -> Result<String, String> {
    control_op(&pillar_ops::ControlOp::Members(
        pillar_ops::MembersOp::Add {
            handle: handle.to_owned(),
            role: role.to_owned(),
        },
    ))
}

/// Change an existing member's role over pillar-message. The pure core `pillar
/// member role` wraps.
///
/// # Errors
/// A transport error string, or the node's refusal (unauthorized actor, or an
/// unknown member).
pub fn set_member_role(handle: &str, role: &str) -> Result<String, String> {
    control_op(&pillar_ops::ControlOp::Members(
        pillar_ops::MembersOp::SetRole {
            handle: handle.to_owned(),
            role: role.to_owned(),
        },
    ))
}

/// `pillar member {ls | add <handle> [role] | role <handle> <role>}`: manage
/// this cell's membership over the sealed resource-op tier (no HTTP).
pub fn member(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("ls") | Some("list") => match list_members() {
            Ok(text) => {
                if text.trim().is_empty() {
                    eprintln!("no members");
                } else {
                    print!("{text}");
                    if !text.ends_with('\n') {
                        println!();
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("pillar member ls: {e}");
                ExitCode::FAILURE
            }
        },
        Some("add") => {
            let Some(handle) = args.get(1) else {
                eprintln!("usage: pillar member add <handle> [role]");
                return ExitCode::from(2);
            };
            let role = args.get(2).map(String::as_str).unwrap_or("member");
            match add_member(handle, role) {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("pillar member add: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("role") => {
            let (Some(handle), Some(role)) = (args.get(1), args.get(2)) else {
                eprintln!("usage: pillar member role <handle> <role>");
                return ExitCode::from(2);
            };
            match set_member_role(handle, role) {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("pillar member role: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("usage: pillar member {{ls | add <handle> [role] | role <handle> <role>}}");
            ExitCode::from(2)
        }
    }
}

/// List `principal`'s active sessions over pillar-message.
///
/// # Errors
/// A transport error string, or the node's refusal reason.
pub fn session_ls(principal: &str) -> Result<String, String> {
    control_op(&pillar_ops::ControlOp::Session(
        pillar_ops::SessionOp::List {
            principal: principal.to_owned(),
        },
    ))
}

/// Show one of `principal`'s session records over pillar-message.
///
/// # Errors
/// A transport error string, or the node's refusal reason.
pub fn session_show(principal: &str, id: &str) -> Result<String, String> {
    control_op(&pillar_ops::ControlOp::Session(
        pillar_ops::SessionOp::Show {
            principal: principal.to_owned(),
            id: id.to_owned(),
        },
    ))
}

/// Revoke one of `principal`'s sessions over pillar-message.
///
/// # Errors
/// A transport error string, or the node's refusal reason.
pub fn session_revoke(principal: &str, id: &str) -> Result<String, String> {
    control_op(&pillar_ops::ControlOp::Session(
        pillar_ops::SessionOp::Revoke {
            principal: principal.to_owned(),
            id: id.to_owned(),
        },
    ))
}

/// Revoke every one of `principal`'s sessions over pillar-message.
///
/// # Errors
/// A transport error string, or the node's refusal reason.
pub fn session_revoke_all(principal: &str) -> Result<String, String> {
    control_op(&pillar_ops::ControlOp::Session(
        pillar_ops::SessionOp::RevokeAll {
            principal: principal.to_owned(),
        },
    ))
}

/// `pillar session {ls <principal> | show <principal> <id> | revoke <principal>
/// <id> | revoke-all <principal>}`: manage a principal's server-side sessions
/// over the sealed resource-op tier (no HTTP). Views need cell membership; the
/// revoke acts run the same signed-act decider `member` acts use.
pub fn session(args: &[String]) -> ExitCode {
    let render = |r: Result<String, String>, verb: &str| -> ExitCode {
        match r {
            Ok(text) => {
                if text.trim().is_empty() {
                    eprintln!("no sessions");
                } else {
                    print!("{text}");
                    if !text.ends_with('\n') {
                        println!();
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("pillar session {verb}: {e}");
                ExitCode::FAILURE
            }
        }
    };
    match args.first().map(String::as_str) {
        Some("ls") | Some("list") => {
            let Some(principal) = args.get(1) else {
                eprintln!("usage: pillar session ls <principal>");
                return ExitCode::from(2);
            };
            render(session_ls(principal), "ls")
        }
        Some("show") => {
            let (Some(principal), Some(id)) = (args.get(1), args.get(2)) else {
                eprintln!("usage: pillar session show <principal> <id>");
                return ExitCode::from(2);
            };
            render(session_show(principal, id), "show")
        }
        Some("revoke") => {
            let (Some(principal), Some(id)) = (args.get(1), args.get(2)) else {
                eprintln!("usage: pillar session revoke <principal> <id>");
                return ExitCode::from(2);
            };
            render(session_revoke(principal, id), "revoke")
        }
        Some("revoke-all") => {
            let Some(principal) = args.get(1) else {
                eprintln!("usage: pillar session revoke-all <principal>");
                return ExitCode::from(2);
            };
            render(session_revoke_all(principal), "revoke-all")
        }
        _ => {
            eprintln!(
                "usage: pillar session {{ls <principal> | show <principal> <id> | \
                 revoke <principal> <id> | revoke-all <principal>}}"
            );
            ExitCode::from(2)
        }
    }
}

/// Print a view `Result` from a control op, or its error under `label`.
fn print_view(r: Result<String, String>, label: &str) -> ExitCode {
    match r {
        Ok(text) => {
            if text.trim().is_empty() {
                eprintln!("(empty)");
            } else {
                print!("{text}");
                if !text.ends_with('\n') {
                    println!();
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("pillar {label}: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `pillar wot {graph | list-trust | list-signatures | list-attestations}`:
/// web-of-trust views over the live trust store, over pillar-message (no HTTP,
/// no `--token`: the signing key is the credential). Member-gated reads.
pub fn wot(args: &[String]) -> ExitCode {
    let op = match args.first().map(String::as_str) {
        None | Some("graph") => pillar_ops::WotOp::Graph,
        Some("list-trust") => pillar_ops::WotOp::ListTrust,
        Some("list-signatures") => pillar_ops::WotOp::ListSignatures,
        Some("list-attestations") => pillar_ops::WotOp::ListAttestations,
        Some(other) => {
            eprintln!(
                "usage: pillar wot {{graph | list-trust | list-signatures | \
                 list-attestations}}  (got `{other}`)"
            );
            return ExitCode::from(2);
        }
    };
    print_view(control_op(&pillar_ops::ControlOp::Wot(op)), "wot")
}

/// `pillar obs {explore <kind> | query <kind> [filter] | live-explore <kind> |
/// live-kinds | psl <query…> | metric-names | label-keys | label-values <key> |
/// retention}`: observability views over the node's live obs substrate, over
/// pillar-message. Member-gated reads.
pub fn obs(args: &[String]) -> ExitCode {
    let usage = || {
        eprintln!(
            "usage: pillar obs {{explore <kind> | query <kind> [filter] | \
             live-explore <kind> | live-kinds | psl <query…> | metric-names | \
             label-keys | label-values <key> | retention | retention-set <body…> | \
             recording <spec…> | alert <spec…> | dashboard-save <name> <spec…> | \
             dashboard-get <id>}}"
        );
        ExitCode::from(2)
    };
    let op = match args.first().map(String::as_str) {
        Some("explore") => match args.get(1) {
            Some(kind) => pillar_ops::ObsOp::Explore { kind: kind.clone() },
            None => return usage(),
        },
        Some("query") => match args.get(1) {
            Some(kind) => pillar_ops::ObsOp::Query {
                kind: kind.clone(),
                filter: args.get(2).cloned(),
            },
            None => return usage(),
        },
        Some("live-explore") => match args.get(1) {
            Some(kind) => pillar_ops::ObsOp::LiveExplore { kind: kind.clone() },
            None => return usage(),
        },
        Some("live-kinds") => pillar_ops::ObsOp::LiveKinds,
        Some("psl") => {
            if args.len() < 2 {
                return usage();
            }
            pillar_ops::ObsOp::Psl {
                query: args[1..].join(" "),
            }
        }
        Some("metric-names") => pillar_ops::ObsOp::MetricNames,
        Some("label-keys") => pillar_ops::ObsOp::LabelKeys,
        Some("label-values") => match args.get(1) {
            Some(key) => pillar_ops::ObsOp::LabelValues { key: key.clone() },
            None => return usage(),
        },
        Some("retention") => pillar_ops::ObsOp::RetentionGet,
        Some("retention-set") => {
            if args.len() < 2 {
                return usage();
            }
            pillar_ops::ObsOp::RetentionSet {
                body: args[1..].join(" "),
            }
        }
        Some("recording") => {
            if args.len() < 2 {
                return usage();
            }
            pillar_ops::ObsOp::Recording {
                spec: args[1..].join(" "),
            }
        }
        Some("alert") => {
            if args.len() < 2 {
                return usage();
            }
            pillar_ops::ObsOp::Alert {
                spec: args[1..].join(" "),
            }
        }
        Some("dashboard-save") => match args.get(1) {
            Some(name) if args.len() >= 3 => pillar_ops::ObsOp::DashboardSave {
                name: name.clone(),
                spec: args[2..].join(" "),
            },
            _ => {
                eprintln!("usage: pillar obs dashboard-save <name> <spec…>");
                return ExitCode::from(2);
            }
        },
        Some("dashboard-get") => match args.get(1) {
            Some(id) => pillar_ops::ObsOp::DashboardGet { id: id.clone() },
            None => {
                eprintln!("usage: pillar obs dashboard-get <id>");
                return ExitCode::from(2);
            }
        },
        _ => return usage(),
    };
    print_view(control_op(&pillar_ops::ControlOp::Obs(op)), "obs")
}

/// `pillar identity {show | domains | enroll <domain> | rotate <new-primary> |
/// recover}`: global-identity views + signed acts over pillar-message.
pub fn identity(args: &[String]) -> ExitCode {
    let op = match args.first().map(String::as_str) {
        None | Some("show") => pillar_ops::IdentityOp::Show,
        Some("domains") => pillar_ops::IdentityOp::Domains,
        Some("enroll") => match args.get(1) {
            Some(domain) => pillar_ops::IdentityOp::Enroll {
                domain: domain.clone(),
            },
            None => {
                eprintln!("usage: pillar identity enroll <domain>");
                return ExitCode::from(2);
            }
        },
        Some("rotate") => match args.get(1) {
            Some(np) => pillar_ops::IdentityOp::Rotate {
                new_primary: np.clone(),
            },
            None => {
                eprintln!("usage: pillar identity rotate <new-primary>");
                return ExitCode::from(2);
            }
        },
        Some("recover") => pillar_ops::IdentityOp::Recover,
        Some(other) => {
            eprintln!(
                "usage: pillar identity {{show | domains | enroll <domain> | \
                 rotate <new-primary> | recover}}  (got `{other}`)"
            );
            return ExitCode::from(2);
        }
    };
    print_view(control_op(&pillar_ops::ControlOp::Identity(op)), "identity")
}

/// `pillar user {ls | show <handle> | audit <handle> | security-events [kind]
/// | login-observe <handle> <origin> <lat> <lon> [--at <secs>]
/// | invite <handle> <email> [--password <p>]
/// [--no-force-change] [--require-passkey] | disable <handle> | enable <handle>
/// | require-change <handle> | set-password <handle> <password> [--force]}`:
/// IAM user views + lifecycle acts over pillar-message.
pub fn user(args: &[String]) -> ExitCode {
    let has = |f: &str| args.iter().any(|a| a == f);
    let flag = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let op = match args.first().map(String::as_str) {
        None | Some("ls") | Some("list") => pillar_ops::UserOp::List,
        Some("show") => match args.get(1) {
            Some(h) => pillar_ops::UserOp::Show { handle: h.clone() },
            None => return user_usage(),
        },
        Some("audit") | Some("timeline") => match args.get(1) {
            Some(h) => pillar_ops::UserOp::AuditTimeline { handle: h.clone() },
            None => return user_usage(),
        },
        Some("security-events") => pillar_ops::UserOp::SecurityEventsFeed {
            kind: args.get(1).cloned(),
        },
        Some("login-observe") => match (args.get(1), args.get(2), args.get(3), args.get(4)) {
            (Some(handle), Some(origin), Some(lat), Some(lon)) => {
                let at = flag("--at")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or_else(|| {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0)
                    });
                pillar_ops::UserOp::LoginObserve {
                    handle: handle.clone(),
                    origin: origin.clone(),
                    lat: lat.clone(),
                    lon: lon.clone(),
                    at,
                }
            }
            _ => {
                eprintln!(
                    "usage: pillar user login-observe <handle> <origin> <lat> <lon> [--at <secs>]"
                );
                return ExitCode::from(2);
            }
        },
        Some("invite") => match (args.get(1), args.get(2)) {
            (Some(handle), Some(email)) => pillar_ops::UserOp::Invite {
                handle: handle.clone(),
                email: email.clone(),
                force_password_change: !has("--no-force-change"),
                require_passkey: has("--require-passkey"),
                password: flag("--password"),
            },
            _ => {
                eprintln!(
                    "usage: pillar user invite <handle> <email> [--password <p>] \
                     [--no-force-change] [--require-passkey]"
                );
                return ExitCode::from(2);
            }
        },
        Some("disable") => match args.get(1) {
            Some(h) => pillar_ops::UserOp::Disable { handle: h.clone() },
            None => return user_usage(),
        },
        Some("enable") => match args.get(1) {
            Some(h) => pillar_ops::UserOp::Enable { handle: h.clone() },
            None => return user_usage(),
        },
        Some("require-change") => match args.get(1) {
            Some(h) => pillar_ops::UserOp::RequireChange { handle: h.clone() },
            None => return user_usage(),
        },
        Some("set-password") => match (args.get(1), args.get(2)) {
            (Some(h), Some(pw)) => pillar_ops::UserOp::SetPassword {
                handle: h.clone(),
                password: pw.clone(),
                force: has("--force"),
            },
            _ => {
                eprintln!("usage: pillar user set-password <handle> <password> [--force]");
                return ExitCode::from(2);
            }
        },
        Some(_) => return user_usage(),
    };
    print_view(control_op(&pillar_ops::ControlOp::User(op)), "user")
}

// ---------------------------------------------------------------------------
// Data-query ops (`pillar_ops::QueryOp`) over the SAME sealed resource-op tier.
// `pillar kv` / `pillar doc` / `pillar sql`: a real remote read/query surface
// over the node's keyed store (K/V + Document) and its SQL views —
// `data-query-tier-remote-surface`. Writes are signed acts; reads member-gated
// views. Identical dial/seal/sign/open path as `send_op`/`send_control_op`,
// only the op class (and its seal domain) differ.
// ---------------------------------------------------------------------------

/// Send a [`pillar_ops::QueryOp`] over pillar-message and return the node's
/// decoded ack text plus the tier that answered. The query-op sibling of
/// [`send_op`]/[`send_control_op`].
///
/// # Errors
/// [`SendError`] for a missing/malformed environment, an unreachable node, or a
/// reply that fails to open/decode.
pub fn send_query_op(op: &pillar_ops::QueryOp) -> Result<(String, TransportKind), SendError> {
    let conn = connect().map_err(SendError::Connect)?;
    let outcome = pillar_client::transport::send_query_op_with_fallback(
        &tiers(conn.addr),
        op,
        &conn.group,
        conn.cell.clone(),
        conn.signer,
        &conn.secret,
        Visibility::Cell,
    )
    .map_err(SendError::Transport)?;
    use pillar_wire::seal::{CellSeal, ContentSeal};
    let aad =
        pillar_wire::PillarMessage::header_aad(outcome.response.visibility, &outcome.response.cell);
    let plaintext = CellSeal
        .open(&conn.group, &outcome.response.body_sealed, &aad)
        .map_err(|_| SendError::UnsealAck)?;
    match Body::from_canonical_cbor(&plaintext) {
        Ok(Body::Control(bytes)) => {
            Ok((String::from_utf8_lossy(&bytes).into_owned(), outcome.tier))
        }
        _ => Err(SendError::BadAckBody),
    }
}

/// Send a query op and unwrap its ack to the payload text, mapping an `ERR`
/// ack to `Err`. Mirrors [`read_op`]/[`control_op`] for the query-op class.
///
/// # Errors
/// A transport error string, or the node's refusal reason (`ERR ` stripped).
pub fn query_op(op: &pillar_ops::QueryOp) -> Result<String, String> {
    let (ack, _tier) = send_query_op(op).map_err(|e| e.to_string())?;
    if let Some(payload) = ack.strip_prefix("OK ") {
        Ok(payload.to_owned())
    } else if ack == "OK" {
        Ok(String::new())
    } else {
        Err(ack.strip_prefix("ERR ").unwrap_or(&ack).to_owned())
    }
}

/// Send a [`pillar_ops::UserOp`] over the control-op tier (`ControlOp::User`)
/// and unwrap its ack to the payload text — the public sibling of
/// [`query_op`] for IAM user views/acts. Used by `pillar user …` and the
/// `um-per-user-audit-timeline` acceptance harness to exercise the real
/// remote control-op surface end to end.
///
/// # Errors
/// A transport error string, or the node's refusal reason (`ERR ` stripped).
pub fn user_op(op: &pillar_ops::UserOp) -> Result<String, String> {
    control_op(&pillar_ops::ControlOp::User(op.clone()))
}

/// Lowercase-hex-encode a K/V value byte string for the wire.
fn hex_encode_value(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode a lowercase-hex K/V value ack back to raw bytes.
fn hex_decode_value(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// `pillar kv {put <collection> <key> <value> | get <collection> <key> |
/// delete <collection> <key> | keys <collection> | collections}`: the K/V
/// surface over the sealed query tier (no HTTP). `put`/`delete` are signed
/// acts; `get`/`keys`/`collections` are member-gated views. A `get`'s value is
/// printed as raw UTF-8 (falling back to hex) after de-hexing the wire form.
pub fn kv(args: &[String]) -> ExitCode {
    let usage = || {
        eprintln!(
            "usage: pillar kv {{put <collection> <key> <value> | get <collection> <key> | \
             delete <collection> <key> | keys <collection> | collections}}"
        );
        ExitCode::from(2)
    };
    match args.first().map(String::as_str) {
        Some("put") => match (args.get(1), args.get(2), args.get(3)) {
            (Some(c), Some(k), Some(v)) => print_view(
                query_op(&pillar_ops::QueryOp::Kv(pillar_ops::KvOp::Put {
                    collection: c.clone(),
                    key: k.clone(),
                    value_hex: hex_encode_value(v.as_bytes()),
                })),
                "kv put",
            ),
            _ => usage(),
        },
        Some("get") => match (args.get(1), args.get(2)) {
            (Some(c), Some(k)) => match query_op(&pillar_ops::QueryOp::Kv(pillar_ops::KvOp::Get {
                collection: c.clone(),
                key: k.clone(),
            })) {
                Ok(hex) => {
                    let raw = hex_decode_value(hex.trim()).unwrap_or_default();
                    match String::from_utf8(raw.clone()) {
                        Ok(s) => println!("{s}"),
                        Err(_) => println!("{}", hex.trim()),
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("pillar kv get: {e}");
                    ExitCode::FAILURE
                }
            },
            _ => usage(),
        },
        Some("delete") => match (args.get(1), args.get(2)) {
            (Some(c), Some(k)) => print_view(
                query_op(&pillar_ops::QueryOp::Kv(pillar_ops::KvOp::Delete {
                    collection: c.clone(),
                    key: k.clone(),
                })),
                "kv delete",
            ),
            _ => usage(),
        },
        Some("keys") => match args.get(1) {
            Some(c) => print_view(
                query_op(&pillar_ops::QueryOp::Kv(pillar_ops::KvOp::Keys {
                    collection: c.clone(),
                })),
                "kv keys",
            ),
            None => usage(),
        },
        Some("collections") => print_view(
            query_op(&pillar_ops::QueryOp::Kv(pillar_ops::KvOp::Collections)),
            "kv collections",
        ),
        _ => usage(),
    }
}

/// `pillar doc {put <collection> <id> <field> <value> | get <collection> <id>
/// <field> | delete <collection> <id> <field> | fields <collection> <id> |
/// ids <collection>}`: the structured Document surface over the sealed query
/// tier. `put`/`delete` are signed acts; the rest are member-gated views.
pub fn doc(args: &[String]) -> ExitCode {
    let usage = || {
        eprintln!(
            "usage: pillar doc {{put <collection> <id> <field> <value> | \
             get <collection> <id> <field> | delete <collection> <id> <field> | \
             fields <collection> <id> | ids <collection>}}"
        );
        ExitCode::from(2)
    };
    match args.first().map(String::as_str) {
        Some("put") => match (args.get(1), args.get(2), args.get(3), args.get(4)) {
            (Some(c), Some(id), Some(f), Some(v)) => print_view(
                query_op(&pillar_ops::QueryOp::Doc(pillar_ops::DocOp::PutField {
                    collection: c.clone(),
                    id: id.clone(),
                    field: f.clone(),
                    value: v.clone(),
                })),
                "doc put",
            ),
            _ => usage(),
        },
        Some("get") => match (args.get(1), args.get(2), args.get(3)) {
            (Some(c), Some(id), Some(f)) => print_view(
                query_op(&pillar_ops::QueryOp::Doc(pillar_ops::DocOp::GetField {
                    collection: c.clone(),
                    id: id.clone(),
                    field: f.clone(),
                })),
                "doc get",
            ),
            _ => usage(),
        },
        Some("delete") => match (args.get(1), args.get(2), args.get(3)) {
            (Some(c), Some(id), Some(f)) => print_view(
                query_op(&pillar_ops::QueryOp::Doc(pillar_ops::DocOp::DeleteField {
                    collection: c.clone(),
                    id: id.clone(),
                    field: f.clone(),
                })),
                "doc delete",
            ),
            _ => usage(),
        },
        Some("fields") => match (args.get(1), args.get(2)) {
            (Some(c), Some(id)) => print_view(
                query_op(&pillar_ops::QueryOp::Doc(pillar_ops::DocOp::Fields {
                    collection: c.clone(),
                    id: id.clone(),
                })),
                "doc fields",
            ),
            _ => usage(),
        },
        Some("ids") => match args.get(1) {
            Some(c) => print_view(
                query_op(&pillar_ops::QueryOp::Doc(pillar_ops::DocOp::Ids {
                    collection: c.clone(),
                })),
                "doc ids",
            ),
            None => usage(),
        },
        _ => usage(),
    }
}

/// `pillar sql {create-view <name> <source> [--eq <field> <value>]
/// [--project <f1,f2,…>] | drop-view <name> | view <name> | views}`: SQL views
/// over the Document store, folded live over the sealed query tier. DDL
/// (`create-view`/`drop-view`) are signed acts; `view`/`views` are member-gated
/// views.
pub fn sql(args: &[String]) -> ExitCode {
    let usage = || {
        eprintln!(
            "usage: pillar sql {{create-view <name> <source> [--eq <field> <value>] \
             [--project <f1,f2,…>] | drop-view <name> | view <name> | views}}"
        );
        ExitCode::from(2)
    };
    match args.first().map(String::as_str) {
        Some("create-view") => {
            let (Some(name), Some(source)) = (args.get(1), args.get(2)) else {
                return usage();
            };
            let mut filter_field = None;
            let mut filter_value = None;
            let mut project = None;
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--eq" => {
                        let (Some(f), Some(v)) = (args.get(i + 1), args.get(i + 2)) else {
                            return usage();
                        };
                        filter_field = Some(f.clone());
                        filter_value = Some(v.clone());
                        i += 3;
                    }
                    "--project" => {
                        let Some(list) = args.get(i + 1) else {
                            return usage();
                        };
                        project = Some(list.split(',').map(str::to_owned).collect());
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            print_view(
                query_op(&pillar_ops::QueryOp::Sql(pillar_ops::SqlOp::CreateView {
                    name: name.clone(),
                    source: source.clone(),
                    filter_field,
                    filter_value,
                    project,
                })),
                "sql create-view",
            )
        }
        Some("drop-view") => match args.get(1) {
            Some(name) => print_view(
                query_op(&pillar_ops::QueryOp::Sql(pillar_ops::SqlOp::DropView {
                    name: name.clone(),
                })),
                "sql drop-view",
            ),
            None => usage(),
        },
        Some("view") => match args.get(1) {
            Some(name) => print_view(
                query_op(&pillar_ops::QueryOp::Sql(pillar_ops::SqlOp::View {
                    name: name.clone(),
                })),
                "sql view",
            ),
            None => usage(),
        },
        Some("views") => print_view(
            query_op(&pillar_ops::QueryOp::Sql(pillar_ops::SqlOp::Views)),
            "sql views",
        ),
        _ => usage(),
    }
}

/// `pillar object {put <public|sealed> <payload> [--link <cid-hex>]... \
/// [--recipient <sealing-pubkey-hex>]... | stat <cid> | links <cid> | \
/// get <cid> [--secret <sealing-secret-hex>] | cat <cid> [--secret <hex>] | \
/// verify <cid>}`: the content-addressed IPFS object-inspection tier — the
/// bottom layer of `repo/docs/data-inspection.md`'s inspection stack, over
/// the SAME sealed query tier as `kv`/`doc`/`sql`. `put` is a signed act;
/// `stat`/`links`/`get`/`cat`/`verify` are member-gated views. `<payload>` is
/// taken as UTF-8 text and hex-encoded for the wire; `get`/`cat` print the
/// decoded body when it can be opened, else the envelope-only rendering.
pub fn object(args: &[String]) -> ExitCode {
    let usage = || {
        eprintln!(
            "usage: pillar object {{put <public|sealed> <payload> [--link <cid-hex>]... \
             [--recipient <sealing-pubkey-hex>]... | stat <cid> | links <cid> | \
             get <cid> [--secret <sealing-secret-hex>] | cat <cid> [--secret <hex>] | \
             verify <cid>}}"
        );
        ExitCode::from(2)
    };
    match args.first().map(String::as_str) {
        Some("put") => {
            let (Some(vis), Some(payload)) = (args.get(1), args.get(2)) else {
                return usage();
            };
            let visibility = match vis.as_str() {
                "public" => pillar_ops::ObjectVisibility::Public,
                "sealed" => pillar_ops::ObjectVisibility::Sealed,
                _ => return usage(),
            };
            let mut links_hex = Vec::new();
            let mut recipients_hex = Vec::new();
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--link" => {
                        let Some(l) = args.get(i + 1) else {
                            return usage();
                        };
                        links_hex.push(l.clone());
                        i += 2;
                    }
                    "--recipient" => {
                        let Some(r) = args.get(i + 1) else {
                            return usage();
                        };
                        recipients_hex.push(r.clone());
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            print_view(
                query_op(&pillar_ops::QueryOp::Object(pillar_ops::ObjectOp::Put {
                    visibility,
                    payload_hex: hex_encode_value(payload.as_bytes()),
                    links_hex,
                    recipients_hex,
                })),
                "object put",
            )
        }
        Some("stat") => match args.get(1) {
            Some(cid) => print_view(
                query_op(&pillar_ops::QueryOp::Object(pillar_ops::ObjectOp::Stat {
                    cid_hex: cid.clone(),
                })),
                "object stat",
            ),
            None => usage(),
        },
        Some("links") => match args.get(1) {
            Some(cid) => print_view(
                query_op(&pillar_ops::QueryOp::Object(pillar_ops::ObjectOp::Links {
                    cid_hex: cid.clone(),
                })),
                "object links",
            ),
            None => usage(),
        },
        Some("get") => match args.get(1) {
            Some(cid) => {
                let secret = object_secret_flag(args);
                print_view(
                    query_op(&pillar_ops::QueryOp::Object(pillar_ops::ObjectOp::Get {
                        cid_hex: cid.clone(),
                        sealing_secret_hex: secret,
                    })),
                    "object get",
                )
            }
            None => usage(),
        },
        Some("cat") => match args.get(1) {
            Some(cid) => {
                let secret = object_secret_flag(args);
                print_view(
                    query_op(&pillar_ops::QueryOp::Object(pillar_ops::ObjectOp::Cat {
                        cid_hex: cid.clone(),
                        sealing_secret_hex: secret,
                    })),
                    "object cat",
                )
            }
            None => usage(),
        },
        Some("verify") => match args.get(1) {
            Some(cid) => print_view(
                query_op(&pillar_ops::QueryOp::Object(pillar_ops::ObjectOp::Verify {
                    cid_hex: cid.clone(),
                })),
                "object verify",
            ),
            None => usage(),
        },
        _ => usage(),
    }
}

/// Parse a trailing `--secret <hex>` flag for `pillar object get|cat`.
fn object_secret_flag(args: &[String]) -> Option<String> {
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--secret" {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

/// `pillar catalog {databases | collections | views | describe <collection>}`:
/// the catalog-introspection surface, every verb a member-gated VIEW folded
/// live from the `__catalog` collection + the keyed store's live collections +
/// the collection-placement registry over the sealed query tier. Discovery is
/// a query, not hard-coded help.
pub fn catalog(args: &[String]) -> ExitCode {
    let usage = || {
        eprintln!(
            "usage: pillar catalog {{databases | collections | views | describe <collection>}}"
        );
        ExitCode::from(2)
    };
    match args.first().map(String::as_str) {
        Some("databases") => print_view(
            query_op(&pillar_ops::QueryOp::Catalog(
                pillar_ops::CatalogOp::Databases,
            )),
            "catalog databases",
        ),
        Some("collections") => print_view(
            query_op(&pillar_ops::QueryOp::Catalog(
                pillar_ops::CatalogOp::Collections,
            )),
            "catalog collections",
        ),
        Some("views") => print_view(
            query_op(&pillar_ops::QueryOp::Catalog(pillar_ops::CatalogOp::Views)),
            "catalog views",
        ),
        Some("describe") => match args.get(1) {
            Some(collection) => print_view(
                query_op(&pillar_ops::QueryOp::Catalog(
                    pillar_ops::CatalogOp::Describe {
                        collection: collection.clone(),
                    },
                )),
                "catalog describe",
            ),
            None => usage(),
        },
        _ => usage(),
    }
}

/// `pillar log {info <collection> | blocks <collection> | list <collection> |
/// show <collection> <event-id-hex> | dag <collection> | watch <collection> |
/// verify <collection> <event-id-hex>}`: the op-log inspection tier
/// (`pillar-log-inspection-tier`) — the middle layer of
/// `repo/docs/data-inspection.md`'s inspection stack, over a collection's
/// signed, content-addressed op log (the SAME log every `kv`/`doc`/`sql`/
/// `object` write already appends to). Every verb is a member-gated view.
pub fn log(args: &[String]) -> ExitCode {
    let usage = || {
        eprintln!(
            "usage: pillar log {{info <collection> | blocks <collection> | \
             list <collection> | show <collection> <event-id-hex> | \
             dag <collection> | watch <collection> | \
             verify <collection> <event-id-hex>}}"
        );
        ExitCode::from(2)
    };
    match args.first().map(String::as_str) {
        Some("info") => match args.get(1) {
            Some(collection) => print_view(
                query_op(&pillar_ops::QueryOp::Log(pillar_ops::LogOp::Info {
                    collection: collection.clone(),
                })),
                "log info",
            ),
            None => usage(),
        },
        Some("blocks") => match args.get(1) {
            Some(collection) => print_view(
                query_op(&pillar_ops::QueryOp::Log(pillar_ops::LogOp::Blocks {
                    collection: collection.clone(),
                })),
                "log blocks",
            ),
            None => usage(),
        },
        Some("list") => match args.get(1) {
            Some(collection) => print_view(
                query_op(&pillar_ops::QueryOp::Log(pillar_ops::LogOp::List {
                    collection: collection.clone(),
                })),
                "log list",
            ),
            None => usage(),
        },
        Some("show") => match (args.get(1), args.get(2)) {
            (Some(collection), Some(event_id_hex)) => print_view(
                query_op(&pillar_ops::QueryOp::Log(pillar_ops::LogOp::Show {
                    collection: collection.clone(),
                    event_id_hex: event_id_hex.clone(),
                })),
                "log show",
            ),
            _ => usage(),
        },
        Some("dag") => match args.get(1) {
            Some(collection) => print_view(
                query_op(&pillar_ops::QueryOp::Log(pillar_ops::LogOp::Dag {
                    collection: collection.clone(),
                })),
                "log dag",
            ),
            None => usage(),
        },
        Some("watch") => match args.get(1) {
            Some(collection) => print_view(
                query_op(&pillar_ops::QueryOp::Log(pillar_ops::LogOp::Watch {
                    collection: collection.clone(),
                })),
                "log watch",
            ),
            None => usage(),
        },
        Some("verify") => match (args.get(1), args.get(2)) {
            (Some(collection), Some(event_id_hex)) => print_view(
                query_op(&pillar_ops::QueryOp::Log(pillar_ops::LogOp::Verify {
                    collection: collection.clone(),
                    event_id_hex: event_id_hex.clone(),
                })),
                "log verify",
            ),
            _ => usage(),
        },
        _ => usage(),
    }
}

fn user_usage() -> ExitCode {
    eprintln!(
        "usage: pillar user {{ls | show <handle> | audit <handle> | \
         security-events [kind] | login-observe <handle> <origin> <lat> <lon> [--at <secs>] | \
         invite <handle> <email> \
         [--password <p>] [--no-force-change] [--require-passkey] | disable <handle> | \
         enable <handle> | require-change <handle> | set-password <handle> <password> \
         [--force]}}"
    );
    ExitCode::from(2)
}

/// Collect every value of a repeatable `--flag <v>` occurrence.
fn multi_flag(args: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

/// `pillar request {ls | approve <id> | reject <id> | submit-user <subject>
/// [--custody <k>] [--label <l>]… | submit-node <subject> --peer-id <p>
/// --version <v> --os <o> --pubkey <cid> [--custody <k>] [--pub <a>]…
/// [--priv <a>]… [--label <l>]…}`: bootstrap-request queue over pillar-message.
pub fn request(args: &[String]) -> ExitCode {
    let flag = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let op = match args.first().map(String::as_str) {
        None | Some("ls") | Some("list") => pillar_ops::ClusterOp::RequestList,
        Some("approve") => match args.get(1).and_then(|s| s.parse::<u64>().ok()) {
            Some(id) => pillar_ops::ClusterOp::RequestApprove { id },
            None => {
                eprintln!("usage: pillar request approve <id>");
                return ExitCode::from(2);
            }
        },
        Some("reject") => match args.get(1).and_then(|s| s.parse::<u64>().ok()) {
            Some(id) => pillar_ops::ClusterOp::RequestReject { id },
            None => {
                eprintln!("usage: pillar request reject <id>");
                return ExitCode::from(2);
            }
        },
        Some("submit-user") => match args.get(1) {
            Some(subject) => pillar_ops::ClusterOp::RequestSubmitUser {
                subject: subject.clone(),
                custody: flag("--custody"),
                labels: multi_flag(args, "--label"),
            },
            None => {
                eprintln!(
                    "usage: pillar request submit-user <subject> [--custody <k>] [--label <l>]…"
                );
                return ExitCode::from(2);
            }
        },
        Some("submit-node") => {
            let (Some(subject), Some(peer_id), Some(version), Some(os), Some(public_key_cid)) = (
                args.get(1).cloned(),
                flag("--peer-id"),
                flag("--version"),
                flag("--os"),
                flag("--pubkey"),
            ) else {
                eprintln!(
                    "usage: pillar request submit-node <subject> --peer-id <p> --version <v> \
                     --os <o> --pubkey <cid> [--custody <k>] [--pub <a>]… [--priv <a>]… \
                     [--label <l>]…"
                );
                return ExitCode::from(2);
            };
            pillar_ops::ClusterOp::RequestSubmitNode {
                subject,
                peer_id,
                version,
                os,
                public_key_cid,
                custody: flag("--custody"),
                pub_addrs: multi_flag(args, "--pub"),
                priv_addrs: multi_flag(args, "--priv"),
                labels: multi_flag(args, "--label"),
            }
        }
        Some(other) => {
            eprintln!(
                "usage: pillar request {{ls | approve <id> | reject <id> | \
                 submit-user <subject> … | submit-node <subject> …}}  (got `{other}`)"
            );
            return ExitCode::from(2);
        }
    };
    print_view(control_op(&pillar_ops::ControlOp::Cluster(op)), "request")
}

/// `pillar topology {tree <tier> | nodes <tier> <value> | domains | members}`:
/// topology + domain + membership views over pillar-message.
pub fn topology(args: &[String]) -> ExitCode {
    let op = match args.first().map(String::as_str) {
        Some("tree") => match args.get(1) {
            Some(tier) => pillar_ops::ClusterOp::TopologyTree { tier: tier.clone() },
            None => {
                eprintln!("usage: pillar topology tree <tier>");
                return ExitCode::from(2);
            }
        },
        Some("nodes") => match (args.get(1), args.get(2)) {
            (Some(tier), Some(value)) => pillar_ops::ClusterOp::NodesAt {
                tier: tier.clone(),
                value: value.clone(),
            },
            _ => {
                eprintln!("usage: pillar topology nodes <tier> <value>");
                return ExitCode::from(2);
            }
        },
        Some("domains") => pillar_ops::ClusterOp::Domains,
        Some("members") => pillar_ops::ClusterOp::Members,
        _ => {
            eprintln!(
                "usage: pillar topology {{tree <tier> | nodes <tier> <value> | \
                 domains | members}}"
            );
            return ExitCode::from(2);
        }
    };
    print_view(control_op(&pillar_ops::ControlOp::Cluster(op)), "topology")
}

/// `pillar trust {<subject> [--depth N] | path <subject>}`: install a WoT
/// trust edge (act) or read the reachable trust depth (view), over
/// pillar-message. The signing key is the credential (no `--token`).
pub fn trust(args: &[String]) -> ExitCode {
    let flag = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let op = match args.first().map(String::as_str) {
        Some("path") => match args.get(1) {
            Some(subject) => pillar_ops::TrustOp::Path {
                subject: subject.clone(),
            },
            None => {
                eprintln!("usage: pillar trust path <subject>");
                return ExitCode::from(2);
            }
        },
        Some(subject) if !subject.starts_with("--") => {
            let depth = match flag("--depth") {
                Some(d) => match d.parse::<u8>() {
                    Ok(n) => n,
                    Err(_) => {
                        eprintln!("pillar trust: --depth must be a u8");
                        return ExitCode::from(2);
                    }
                },
                None => 1,
            };
            pillar_ops::TrustOp::Edge {
                subject: subject.to_string(),
                depth,
            }
        }
        _ => {
            eprintln!("usage: pillar trust {{<subject> [--depth N] | path <subject>}}");
            return ExitCode::from(2);
        }
    };
    print_view(control_op(&pillar_ops::ControlOp::Trust(op)), "trust")
}

/// `pillar attest {build --as <self|role@scope> --subject <id> --allow <action>
/// <resource> [--authority <cid>] [--quota key=N] --in <scope> [--issuer <id>] |
/// audit <cid>}`: issue a capacity-checked attestation (act) or verify an
/// attest proof chain (view), over pillar-message.
pub fn attest(args: &[String]) -> ExitCode {
    let flag = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let usage = || {
        eprintln!(
            "usage: pillar attest {{build --as <self|role@scope> --subject <id> \
             --allow <action> <resource> [--authority <cid>] [--quota key=N] \
             --in <scope> [--issuer <id>] | audit <cid>}}"
        );
        ExitCode::from(2)
    };
    let op = match args.first().map(String::as_str) {
        Some("audit") => match args.get(1) {
            Some(cid) => pillar_ops::TrustOp::Audit { cid: cid.clone() },
            None => return usage(),
        },
        Some("build") => {
            let capacity = match flag("--as") {
                Some(c) => c,
                None => return usage(),
            };
            let subject = match flag("--subject") {
                Some(s) => s,
                None => return usage(),
            };
            let scope = match flag("--in") {
                Some(s) => s,
                None => return usage(),
            };
            // `--allow <action> <resource>`: the two tokens following --allow.
            let (action, resource) = match args.iter().position(|a| a == "--allow") {
                Some(i) => match (args.get(i + 1), args.get(i + 2)) {
                    (Some(a), Some(r)) => (a.clone(), r.clone()),
                    _ => return usage(),
                },
                None => return usage(),
            };
            let issuer = flag("--issuer").unwrap_or_else(|| subject.clone());
            let authority = flag("--authority").unwrap_or_default();
            let quota = match flag("--quota") {
                Some(spec) => match spec
                    .split_once('=')
                    .and_then(|(_, n)| n.parse::<u64>().ok())
                {
                    Some(n) => Some(n),
                    None => {
                        eprintln!("pillar attest: --quota expects key=N (N a u64)");
                        return ExitCode::from(2);
                    }
                },
                None => None,
            };
            pillar_ops::TrustOp::AttestBuild {
                issuer,
                capacity,
                authority,
                subject,
                action,
                resource,
                quota,
                scope,
            }
        }
        _ => return usage(),
    };
    print_view(control_op(&pillar_ops::ControlOp::Trust(op)), "attest")
}

/// `pillar grant {add <cap> --to <subject> [--allow|--deny] | rm <cap> --to
/// <subject> | check <cap> --as <subject> | who-can <cap>}`: explicit ALLOW/DENY
/// grant acts + decider views over pillar-message.
pub fn grant(args: &[String]) -> ExitCode {
    let has = |f: &str| args.iter().any(|a| a == f);
    let flag = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let usage = || {
        eprintln!(
            "usage: pillar grant {{add <cap> --to <subject> [--allow|--deny] | \
             rm <cap> --to <subject> | check <cap> --as <subject> | who-can <cap>}}"
        );
        ExitCode::from(2)
    };
    let op = match args.first().map(String::as_str) {
        Some("add") => match (args.get(1), flag("--to")) {
            (Some(cap), Some(subject)) => pillar_ops::TrustOp::GrantAdd {
                subject,
                capability: cap.clone(),
                allow: !has("--deny"),
            },
            _ => return usage(),
        },
        Some("rm") => match (args.get(1), flag("--to")) {
            (Some(cap), Some(subject)) => pillar_ops::TrustOp::GrantRm {
                subject,
                capability: cap.clone(),
            },
            _ => return usage(),
        },
        Some("check") => match (args.get(1), flag("--as")) {
            (Some(cap), Some(subject)) => pillar_ops::TrustOp::GrantCheck {
                subject,
                capability: cap.clone(),
            },
            _ => return usage(),
        },
        Some("who-can") => match args.get(1) {
            Some(cap) => pillar_ops::TrustOp::WhoCan {
                capability: cap.clone(),
            },
            None => return usage(),
        },
        _ => return usage(),
    };
    print_view(control_op(&pillar_ops::ControlOp::Trust(op)), "grant")
}

/// `pillar caps <subject> --probe <cap>…`: the effective ALLOW set the decider
/// computes for `subject` across the named capability universe, over
/// pillar-message (a view). The decider has no "list all capabilities"
/// primitive, so the caller names the capabilities to probe.
pub fn caps(args: &[String]) -> ExitCode {
    let subject = match args.first() {
        Some(s) if !s.starts_with("--") => s.clone(),
        _ => {
            eprintln!("usage: pillar caps <subject> --probe <cap>… (at least one --probe)");
            return ExitCode::from(2);
        }
    };
    let candidates = multi_flag(args, "--probe");
    if candidates.is_empty() {
        eprintln!("usage: pillar caps <subject> --probe <cap>… (at least one --probe)");
        return ExitCode::from(2);
    }
    let op = pillar_ops::TrustOp::Caps {
        subject,
        candidates,
    };
    print_view(control_op(&pillar_ops::ControlOp::Trust(op)), "caps")
}

/// `pillar role {add <name> --grant <cap>… | rm <name> | list | show <name>}`:
/// named capability-set management over pillar-message. Acts gated on
/// `iam:roles:write`; list/show are member-gated views.
pub fn role(args: &[String]) -> ExitCode {
    let usage = || {
        eprintln!(
            "usage: pillar role {{add <name> --grant <cap>… | rm <name> | list | show <name>}}"
        );
        ExitCode::from(2)
    };
    let op = match args.first().map(String::as_str) {
        Some("list") | None => pillar_ops::IamOp::RoleList,
        Some("show") => match args.get(1) {
            Some(name) => pillar_ops::IamOp::RoleShow { name: name.clone() },
            None => return usage(),
        },
        Some("add") => match args.get(1) {
            Some(name) => pillar_ops::IamOp::RoleAdd {
                name: name.clone(),
                capabilities: multi_flag(args, "--grant"),
            },
            None => return usage(),
        },
        Some("rm") => match args.get(1) {
            Some(name) => pillar_ops::IamOp::RoleRm { name: name.clone() },
            None => return usage(),
        },
        _ => return usage(),
    };
    print_view(control_op(&pillar_ops::ControlOp::Iam(op)), "role")
}

/// `pillar group {add <name> --role <r>… | add-member <name> <handle> | rm
/// <name> | list | show <name>}`: managed-group membership over pillar-message.
/// Acts gated on `iam:groups:write`; list/show are member-gated views.
pub fn group(args: &[String]) -> ExitCode {
    let usage = || {
        eprintln!(
            "usage: pillar group {{add <name> --role <r>… | add-member <name> <handle> | \
             rm <name> | list | show <name>}}"
        );
        ExitCode::from(2)
    };
    let op = match args.first().map(String::as_str) {
        Some("list") | None => pillar_ops::IamOp::GroupList,
        Some("show") => match args.get(1) {
            Some(name) => pillar_ops::IamOp::GroupShow { name: name.clone() },
            None => return usage(),
        },
        Some("add") => match args.get(1) {
            Some(name) => pillar_ops::IamOp::GroupAdd {
                name: name.clone(),
                roles: multi_flag(args, "--role"),
            },
            None => return usage(),
        },
        Some("add-member") => match (args.get(1), args.get(2)) {
            (Some(name), Some(handle)) => pillar_ops::IamOp::GroupAddMember {
                name: name.clone(),
                handle: handle.clone(),
            },
            _ => return usage(),
        },
        Some("rm") => match args.get(1) {
            Some(name) => pillar_ops::IamOp::GroupRm { name: name.clone() },
            None => return usage(),
        },
        _ => return usage(),
    };
    print_view(control_op(&pillar_ops::ControlOp::Iam(op)), "group")
}

/// `pillar oauth {register <client-id> --type <public|confidential> --redirect
/// <uri>… --scope <s>… --grant <g>… | list | show <client-id>}`: OAuth/OIDC
/// client-registry management over pillar-message. Register gated on
/// `iam:oauth:write`; list/show are member-gated views.
pub fn oauth(args: &[String]) -> ExitCode {
    let flag = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let usage = || {
        eprintln!(
            "usage: pillar oauth {{register <client-id> --type <public|confidential> \
             --redirect <uri>… --scope <s>… --grant <g>… | list | show <client-id>}}"
        );
        ExitCode::from(2)
    };
    let op = match args.first().map(String::as_str) {
        Some("list") | None => pillar_ops::IamOp::OauthList,
        Some("show") => match args.get(1) {
            Some(id) => pillar_ops::IamOp::OauthShow {
                client_id: id.clone(),
            },
            None => return usage(),
        },
        Some("register") => match args.get(1) {
            Some(id) => {
                let client_type = flag("--type").unwrap_or_else(|| "public".to_owned());
                pillar_ops::IamOp::OauthRegister {
                    client_id: id.clone(),
                    client_type,
                    redirect_uris: multi_flag(args, "--redirect"),
                    scopes: multi_flag(args, "--scope"),
                    grants: multi_flag(args, "--grant"),
                }
            }
            None => return usage(),
        },
        _ => return usage(),
    };
    print_view(control_op(&pillar_ops::ControlOp::Iam(op)), "oauth")
}

#[cfg(test)]
mod resolve_tests {
    use super::resolve_addr;

    #[test]
    fn resolve_addr_accepts_a_literal_ip_port() {
        let a = resolve_addr("127.0.0.1:8644", "test").expect("ip:port resolves");
        assert_eq!(a.port(), 8644);
        assert!(a.ip().is_loopback());
    }

    #[test]
    fn resolve_addr_resolves_a_dns_name() {
        // `localhost` is guaranteed resolvable without network access, standing
        // in for the UI-exported `pillar.<domain>:8644` endpoint (a DNS name,
        // not a literal IP) — the case that regressed turnkey apply.
        let a = resolve_addr("localhost:8644", "test").expect("hostname resolves");
        assert_eq!(a.port(), 8644);
        assert!(a.ip().is_loopback());
    }

    #[test]
    fn resolve_addr_rejects_an_unparseable_endpoint() {
        assert!(resolve_addr("not a socket addr", "test").is_err());
    }
}
