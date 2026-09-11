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

use std::net::SocketAddr;
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
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::MissingEnv(v) => write!(f, "missing required env var {v}"),
            ConnectError::BadAddr(v) => write!(f, "{v} is not a valid host:port"),
            ConnectError::BadHex(v) => write!(f, "{v} is not valid lowercase hex"),
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

fn connect_from_env() -> Result<Connect, ConnectError> {
    let addr_s = env("PILLAR_RESOURCE_OP_ADDR")?;
    let addr: SocketAddr = addr_s
        .parse()
        .map_err(|_| ConnectError::BadAddr("PILLAR_RESOURCE_OP_ADDR"))?;
    let cell_id_hex = env("PILLAR_CELL_ID_HEX")?;
    let cell = CellId::from_bytes(
        decode_hex(&cell_id_hex).ok_or(ConnectError::BadHex("PILLAR_CELL_ID_HEX"))?,
    );
    let seed_hex = env("PILLAR_CELL_SEED_HEX")?;
    let seed_bytes =
        decode_hex(&seed_hex).ok_or(ConnectError::BadHex("PILLAR_CELL_SEED_HEX"))?;
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
    let conn = connect_from_env().map_err(SendError::Connect)?;
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
    let aad = pillar_wire::PillarMessage::header_aad(outcome.response.visibility, &outcome.response.cell);
    let plaintext = CellSeal
        .open(&conn.group, &outcome.response.body_sealed, &aad)
        .map_err(|_| SendError::UnsealAck)?;
    match Body::from_canonical_cbor(&plaintext) {
        Ok(Body::Control(bytes)) => Ok((String::from_utf8_lossy(&bytes).into_owned(), outcome.tier)),
        _ => Err(SendError::BadAckBody),
    }
}

/// Parse `text` as a manifest and send it as a `ResourceOp::Apply` over
/// pillar-message (see [`send_op`]). This is the pure core `pillar apply -f`
/// wraps with argv parsing + `ExitCode` translation — a test calls this
/// directly to assert on the real outcome.
///
/// # Errors
/// A parse error string for a malformed manifest; else [`SendError`].
pub fn apply_manifest_text(text: &str) -> Result<(String, TransportKind), String> {
    let crd = crate::parse_crd(text).map_err(|e| e.to_string())?;
    send_op(&pillar_ops::ResourceOp::Apply { crd }).map_err(|e| e.to_string())
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

/// `pillar apply -f <manifest.txt>`: parse the manifest into a CRD and send
/// it as a `ResourceOp::Apply` over pillar-message.
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
        eprintln!("usage: pillar apply -f <manifest.txt>");
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
        Ok((ack, tier)) => {
            println!("{ack} (via {tier:?})");
            if ack.starts_with("OK") {
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
