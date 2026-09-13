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
    MissingEnv(&'static str),
    BadAddr(&'static str),
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
    Connect(ConnectError),
    Transport(String),
    UnsealAck,
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
