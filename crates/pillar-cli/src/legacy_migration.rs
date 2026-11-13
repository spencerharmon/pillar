//! Offline, crash-safe conversion of a LEGACY solo cell to independent cell
//! credentials, so the existing logical cell can admit other nodes through the
//! normal signed enrollment flow.
//!
//! A legacy data directory (written before independent credentials existed)
//! holds a `streamdb/` stream whose cell ID and group-key seed were derived
//! from the device's private identity bytes. Enrollment correctly refuses to
//! distribute such credentials. This module re-seals the SAME journal (every
//! op payload, in order, signed by the SAME device segment signer, so op IDs
//! and the Merkle root are identical) under freshly generated credentials.
//!
//! Contract (see `docs/legacy-cell-enrollment-migration.md`):
//! - The legacy `streamdb/` is never modified or deleted; it is the rollback
//!   source. The converted stream lives in `streamdb-converted/`.
//! - The cryptographic cell ID changes. Client configs exported before the
//!   conversion carry the legacy (device-derived) cell material and are
//!   rejected afterwards; already admitted signer keys stay admitted, so an
//!   administrator re-exports (or replaces only the cell fields).
//! - `legacy-cell-migration.json` is the write-ahead marker: any state other
//!   than `committed` makes `pillar node run` refuse to boot until the operator
//!   resumes (`--apply`) or rolls back (`--rollback`).
//! - Rollback after commit is allowed only before the boundary: no op was
//!   written to the converted stream and no enrollment was approved with the
//!   new credentials. Past it, rollback would strand data or joined nodes.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::enrollment::{self, CellCredentials};

/// Write-ahead marker file name inside the data directory.
pub const MARKER: &str = "legacy-cell-migration.json";
/// Converted stream directory inside the data directory.
pub const CONVERTED: &str = "streamdb-converted";
const LEGACY: &str = "streamdb";
const STAGING: &str = "legacy-cell-migration.staging";
const CREDENTIALS: &str = "cell-credentials.json";
/// Flag that acknowledges the public contract change before an apply.
pub const ACK_FLAG: &str = "--acknowledge-cell-id-change";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u32,
    state: String,
    peer_id: String,
    legacy_ops: u64,
    legacy_root: String,
    /// SHA256 of the legacy cell ID (the raw ID embeds device key bytes).
    legacy_cell_fingerprint: String,
    new_cell_id: String,
}

/// How `node run` must open this data directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootLayout {
    /// Fresh or independently-credentialed issuer (or an enrolled node).
    Current,
    /// Unconverted legacy stream under device-derived credentials.
    Legacy,
    /// Committed conversion: open `streamdb-converted/` with the new credentials.
    Converted,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn exists(path: &Path) -> Result<bool, String> {
    path.try_exists()
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn read_marker(data_dir: &Path) -> Result<Option<Marker>, String> {
    match fs::read(data_dir.join(MARKER)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("corrupt {MARKER}: {e}; refusing to guess the migration state")),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

fn write_marker(data_dir: &Path, marker: &Marker) -> Result<(), String> {
    enrollment::write_private(
        &data_dir.join(MARKER),
        &serde_json::to_vec_pretty(marker).map_err(|e| e.to_string())?,
    )
}

/// Decide the boot layout, refusing an interrupted or inconsistent conversion.
///
/// # Errors
/// An uncommitted/corrupt marker, or a converted layout with missing pieces.
pub fn boot_layout(data_dir: &Path, has_enrollment: bool) -> Result<BootLayout, String> {
    match read_marker(data_dir)? {
        Some(marker) if marker.state == "committed" => {
            if has_enrollment {
                return Err("legacy cell migration marker conflicts with an installed enrollment".into());
            }
            if !exists(&data_dir.join(CONVERTED))? || !exists(&data_dir.join(CREDENTIALS))? {
                return Err(format!(
                    "{MARKER} is committed but {CONVERTED}/ or {CREDENTIALS} is missing; restore them from backup or run `pillar node migrate-legacy-cell --rollback`"
                ));
            }
            let credentials = enrollment::load_credentials(data_dir)?;
            if hex(&credentials.cell_id) != marker.new_cell_id {
                return Err(format!("{CREDENTIALS} does not match the committed legacy cell migration"));
            }
            Ok(BootLayout::Converted)
        }
        Some(marker) => Err(format!(
            "legacy cell migration is incomplete (state {:?}); resume with `pillar node migrate-legacy-cell --apply {ACK_FLAG}` or undo with `--rollback` before starting the node",
            marker.state
        )),
        None => {
            if exists(&data_dir.join(CONVERTED))? || exists(&data_dir.join(STAGING))? {
                return Err(format!(
                    "{CONVERTED}/ or {STAGING}/ exists without {MARKER}; refusing to guess which stream is authoritative"
                ));
            }
            if !has_enrollment
                && exists(&data_dir.join(LEGACY))?
                && !exists(&data_dir.join(CREDENTIALS))?
            {
                Ok(BootLayout::Legacy)
            } else {
                Ok(BootLayout::Current)
            }
        }
    }
}

/// The per-device segment-signer seed (unchanged by conversion; never shared).
///
/// # Errors
/// If the identity cannot be encoded.
pub fn device_signer_seed(keypair: &Keypair) -> Result<pillar_crypto::Seed, String> {
    let id_bytes = keypair.to_protobuf_encoding().map_err(|e| e.to_string())?;
    let mut m = b"pillar-streamdb/segment-signer/v1:".to_vec();
    m.extend_from_slice(&id_bytes);
    Ok(pillar_crypto::Seed::from_bytes(m))
}

/// The legacy device-derived cell ID/seed. Only ever used to READ a legacy
/// stream (or to keep serving one unconverted); never distributed.
#[must_use]
pub fn legacy_cell_material(
    device_seed: &pillar_crypto::Seed,
) -> (pillar_crypto::CellId, pillar_crypto::Seed) {
    let mut m = b"pillar-streamdb/cell-id/v1:".to_vec();
    m.extend_from_slice(device_seed.as_bytes());
    (pillar_crypto::CellId::from_bytes(m), device_seed.clone())
}

fn open_stream(
    root: &Path,
    keypair: &Keypair,
    cell_id: pillar_crypto::CellId,
    seed: &pillar_crypto::Seed,
    must_exist: bool,
) -> Result<pillar_streamdb::IpfsPersistentStream, String> {
    let device = device_signer_seed(keypair)?;
    let (public, secret) =
        pillar_crypto::principal::principal_from_seed(&device).map_err(|e| e.to_string())?;
    let store = pillar_streamdb::ContentStore::open(root)
        .map_err(|e| format!("open {}: {e}", root.display()))?;
    if must_exist && store.resolve_head(&public.signing).is_none() {
        return Err(format!(
            "conflicting identity: {} holds no stream head for this device identity; use the identity.key that wrote it",
            root.display()
        ));
    }
    let group = pillar_crypto::cell::group_key_from_seed(seed).map_err(|e| e.to_string())?;
    pillar_streamdb::IpfsPersistentStream::open_with_store(
        store,
        public.signing,
        secret.signing,
        pillar_streamdb::Visibility::Cell,
        cell_id,
        group,
    )
    .map_err(|e| {
        format!(
            "cannot open {} (corrupt or foreign stream): {e}",
            root.display()
        )
    })
}

fn payloads(stream: &pillar_streamdb::IpfsPersistentStream) -> Vec<Vec<u8>> {
    stream
        .stream()
        .log()
        .order()
        .iter()
        .map(|op| op.payload().to_vec())
        .collect()
}

fn load_identity(path: &Path) -> Result<Keypair, String> {
    let bytes = fs::read(path).map_err(|e| {
        format!(
            "cannot read device identity {}: {e}; no identity is generated by migration",
            path.display()
        )
    })?;
    Keypair::from_protobuf_encoding(&bytes)
        .map_err(|e| format!("invalid identity {}: {e}", path.display()))
}

fn lock(data_dir: &Path) -> Result<fs::File, String> {
    let path = data_dir.join("enrollment.lock");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|e| {
        format!(
            "cannot lock {}: {e}; stop the node before migrating its cell",
            path.display()
        )
    })?;
    Ok(file)
}

/// Fault injection for crash-safety verification: abort the process (no
/// unwinding, no cleanup) at a named step, exactly like a power loss/kill.
fn crash_point(step: &str) {
    if std::env::var("PILLAR_LEGACY_MIGRATION_CRASH_AT").is_ok_and(|v| v == step) {
        std::process::abort();
    }
}

fn sync_dir(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("sync {}: {e}", path.display()))
}

/// Run `pillar node migrate-legacy-cell`.
///
/// # Errors
/// Usage errors and every refused/failed migration step.
pub fn run(args: &[String]) -> Result<String, String> {
    let mut data_dir = None;
    let mut identity = None;
    let mut mode = None;
    let mut ack = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--data-dir" => {
                data_dir = Some(PathBuf::from(
                    it.next().ok_or("--data-dir requires a value")?,
                ))
            }
            "--identity-key" => {
                identity = Some(PathBuf::from(
                    it.next().ok_or("--identity-key requires a value")?,
                ))
            }
            "--plan" | "--apply" | "--rollback" if mode.is_none() => mode = Some(arg.clone()),
            a if a == ACK_FLAG => ack = true,
            other => return Err(format!("{}\nunexpected argument {other:?}", usage())),
        }
    }
    let data_dir = data_dir.ok_or_else(|| usage().to_owned())?;
    let identity = identity.unwrap_or_else(|| data_dir.join("identity.key"));
    let _lock = lock(&data_dir)?;
    let keypair = load_identity(&identity)?;
    match mode.as_deref().unwrap_or("--plan") {
        "--plan" => plan(&data_dir, &keypair),
        "--apply" if !ack => Err(format!(
            "refusing to convert without {ACK_FLAG}: the cryptographic cell ID changes and previously exported client configs stop working (review `--plan` first)"
        )),
        "--apply" => apply(&data_dir, &keypair),
        _ => rollback(&data_dir, &keypair),
    }
}

fn usage() -> &'static str {
    "usage: pillar node migrate-legacy-cell --data-dir DIR [--identity-key PATH] [--plan | --apply --acknowledge-cell-id-change | --rollback]"
}

struct LegacySnapshot {
    payloads: Vec<Vec<u8>>,
    root: String,
    fingerprint: String,
}

fn legacy_snapshot(data_dir: &Path, keypair: &Keypair) -> Result<LegacySnapshot, String> {
    let device = device_signer_seed(keypair)?;
    let (cell_id, seed) = legacy_cell_material(&device);
    let fingerprint = hex(&Sha256::digest(cell_id.as_bytes()));
    let stream = open_stream(&data_dir.join(LEGACY), keypair, cell_id, &seed, true)?;
    Ok(LegacySnapshot {
        payloads: payloads(&stream),
        root: stream.stream().log().root().to_hex(),
        fingerprint,
    })
}

fn plan(data_dir: &Path, keypair: &Keypair) -> Result<String, String> {
    let marker = read_marker(data_dir)?;
    if let Some(m) = &marker {
        return Ok(format!(
            "legacy cell migration state: {}\npeer: {}\nops: {}\nroot: {}\nnew cell id: {}",
            m.state, m.peer_id, m.legacy_ops, m.legacy_root, m.new_cell_id
        ));
    }
    if boot_layout(data_dir, exists(&data_dir.join("enrollment.sealed"))?)? != BootLayout::Legacy {
        return Err("not a legacy cell: nothing to migrate".into());
    }
    let snap = legacy_snapshot(data_dir, keypair)?;
    Ok(format!(
        "LEGACY CELL (device-derived credentials; enrollment refuses to distribute them)\n\
         peer: {}\nops: {}\nroot: {}\nlegacy cell fingerprint: {}\n\
         PLAN: re-seal all ops (same signer, same op IDs and root) into {CONVERTED}/ under new independent credentials; {LEGACY}/ is retained unmodified for rollback.\n\
         CONTRACT: the cryptographic cell ID CHANGES. Client configs exported before conversion stop working; admitted signers, users, custody and membership are preserved — re-export (or replace only the cell fields) after conversion.\n\
         ROLLBACK BOUNDARY: `--rollback` is possible until the first post-conversion write or enrollment approval.\n\
         To proceed: pillar node migrate-legacy-cell --data-dir <DIR> --apply {ACK_FLAG}",
        keypair.public().to_peer_id(),
        snap.payloads.len(),
        snap.root,
        snap.fingerprint
    ))
}

fn apply(data_dir: &Path, keypair: &Keypair) -> Result<String, String> {
    let peer = keypair.public().to_peer_id().to_string();
    let staging = data_dir.join(STAGING);
    let mut marker = match read_marker(data_dir)? {
        Some(m) if m.peer_id != peer => {
            return Err(format!(
                "conflicting identity: migration was started by {} but this identity is {peer}",
                m.peer_id
            ))
        }
        Some(m) if m.state == "committed" => {
            return Ok(format!("ALREADY CONVERTED new cell id {}", m.new_cell_id))
        }
        Some(m) => m,
        None => {
            if exists(&data_dir.join("enrollment.sealed"))? {
                return Err("an enrolled node has no legacy cell to convert".into());
            }
            if exists(&data_dir.join(CREDENTIALS))? {
                return Err(format!(
                    "{CREDENTIALS} already exists: not a legacy cell (or conflicting state)"
                ));
            }
            if boot_layout(data_dir, false)? != BootLayout::Legacy {
                return Err("not a legacy cell: nothing to migrate".into());
            }
            // Validate the legacy stream fully BEFORE writing anything.
            let snap = legacy_snapshot(data_dir, keypair)?;
            let mut seed = vec![0; 32];
            getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
            let credentials = CellCredentials {
                cell_id: Sha256::digest(&seed).to_vec(),
                seed,
            };
            fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
            enrollment::write_private(
                &staging.join(CREDENTIALS),
                &serde_json::to_vec(&credentials).map_err(|e| e.to_string())?,
            )?;
            let marker = Marker {
                version: 1,
                state: "staged".into(),
                peer_id: peer.clone(),
                legacy_ops: snap.payloads.len() as u64,
                legacy_root: snap.root,
                legacy_cell_fingerprint: snap.fingerprint,
                new_cell_id: hex(&credentials.cell_id),
            };
            write_marker(data_dir, &marker)?;
            crash_point("staged");
            marker
        }
    };
    // Resume: everything below is idempotent and re-validated on every run.
    let snap = legacy_snapshot(data_dir, keypair)?;
    if snap.root != marker.legacy_root || snap.payloads.len() as u64 != marker.legacy_ops {
        return Err(
            "legacy stream changed since the migration was staged; roll back and re-plan".into(),
        );
    }
    let staged_credentials = staging.join(CREDENTIALS);
    let credentials: CellCredentials = match fs::read(&staged_credentials) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| format!("corrupt staged credentials: {e}"))?,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // Crash after commit-step credentials install: use the installed copy.
            enrollment::load_credentials_existing(data_dir)?
        }
        Err(e) => return Err(e.to_string()),
    };
    enrollment::validate_credentials(&credentials)?;
    if hex(&credentials.cell_id) != marker.new_cell_id {
        return Err("staged credentials do not match the migration marker".into());
    }
    let cell_id = pillar_crypto::CellId::from_bytes(credentials.cell_id.clone());
    let seed = pillar_crypto::Seed::from_bytes(credentials.seed.clone());
    let converted = data_dir.join(CONVERTED);
    let staged_stream = staging.join("streamdb");
    let target = if exists(&converted)? {
        converted.clone()
    } else {
        staged_stream.clone()
    };
    {
        let mut stream = open_stream(&target, keypair, cell_id.clone(), &seed, false)?;
        let done = payloads(&stream);
        if done.len() > snap.payloads.len() || done[..] != snap.payloads[..done.len()] {
            return Err(
                "staged stream diverged from the legacy journal; run --rollback and re-plan".into(),
            );
        }
        let half = snap.payloads.len() / 2;
        for (index, payload) in snap.payloads.iter().enumerate().skip(done.len()) {
            if index == half && index > done.len() {
                crash_point("partial");
            }
            stream
                .append(payload.clone(), pillar_core::SideEffect::Convergent)
                .map_err(|e| format!("re-seal op: {e}"))?;
        }
    }
    // Verify from disk, not from the in-memory handle.
    let reopened = open_stream(&target, keypair, cell_id, &seed, !snap.payloads.is_empty())?;
    if payloads(&reopened) != snap.payloads
        || reopened.stream().log().root().to_hex() != marker.legacy_root
    {
        return Err("converted stream does not reproduce the legacy journal exactly".into());
    }
    drop(reopened);
    if target == staged_stream {
        fs::rename(&staged_stream, &converted).map_err(|e| e.to_string())?;
        sync_dir(data_dir)?;
        crash_point("renamed");
    }
    if !exists(&data_dir.join(CREDENTIALS))? {
        enrollment::write_private(
            &data_dir.join(CREDENTIALS),
            &serde_json::to_vec(&credentials).map_err(|e| e.to_string())?,
        )?;
    } else if enrollment::load_credentials_existing(data_dir)? != credentials {
        return Err(format!(
            "conflicting {CREDENTIALS}: not the staged credentials"
        ));
    }
    marker.state = "committed".into();
    write_marker(data_dir, &marker)?;
    // The commit point has passed; only migration-owned scratch is removed.
    if exists(&staging)? {
        fs::remove_dir_all(&staging).map_err(|e| e.to_string())?;
        sync_dir(data_dir)?;
    }
    Ok(format!(
        "CONVERTED {} ops (root {}) to new cell id {}\n{LEGACY}/ retained unmodified for rollback. Re-export client configs after restarting the node.",
        marker.legacy_ops, marker.legacy_root, marker.new_cell_id
    ))
}

fn rollback(data_dir: &Path, keypair: &Keypair) -> Result<String, String> {
    let peer = keypair.public().to_peer_id().to_string();
    let Some(marker) = read_marker(data_dir)? else {
        return Err("no legacy cell migration to roll back".into());
    };
    if marker.peer_id != peer {
        return Err(format!(
            "conflicting identity: migration was started by {} but this identity is {peer}",
            marker.peer_id
        ));
    }
    let converted = data_dir.join(CONVERTED);
    let credentials_path = data_dir.join(CREDENTIALS);
    if marker.state == "committed" && exists(&converted)? {
        let credentials = enrollment::load_credentials_existing(data_dir)?;
        let stream = open_stream(
            &converted,
            keypair,
            pillar_crypto::CellId::from_bytes(credentials.cell_id.clone()),
            &pillar_crypto::Seed::from_bytes(credentials.seed),
            marker.legacy_ops > 0,
        )?;
        if stream.stream().log().len() as u64 != marker.legacy_ops
            || stream.stream().log().root().to_hex() != marker.legacy_root
        {
            return Err("rollback boundary passed: the converted cell has post-conversion writes that the legacy stream does not hold".into());
        }
        drop(stream);
        if let Ok(bytes) = fs::read(data_dir.join("enrollment-requests.json")) {
            let requests: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|e| format!("corrupt enrollment inbox: {e}"))?;
            if requests
                .as_object()
                .is_some_and(|m| m.values().any(|r| !r["envelope"].is_null()))
            {
                return Err(
                    "rollback boundary passed: an enrollment was approved with the new credentials"
                        .into(),
                );
            }
        }
    }
    // Never delete: park the converted artifacts for inspection.
    let mut nonce = [0; 8];
    getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
    let parked = data_dir.join(format!("legacy-cell-migration.rolled-back-{}", hex(&nonce)));
    fs::create_dir_all(&parked).map_err(|e| e.to_string())?;
    let staging = data_dir.join(STAGING);
    for (path, name) in [(&converted, CONVERTED), (&staging, STAGING)] {
        if exists(path)? {
            fs::rename(path, parked.join(name)).map_err(|e| e.to_string())?;
        }
    }
    if exists(&credentials_path)? {
        let installed = enrollment::load_credentials_existing(data_dir)?;
        if hex(&installed.cell_id) != marker.new_cell_id {
            return Err(format!(
                "conflicting {CREDENTIALS}: not created by this migration; left in place"
            ));
        }
        fs::rename(&credentials_path, parked.join(CREDENTIALS)).map_err(|e| e.to_string())?;
    }
    fs::rename(data_dir.join(MARKER), parked.join(MARKER)).map_err(|e| e.to_string())?;
    sync_dir(data_dir)?;
    Ok(format!(
        "ROLLED BACK to the legacy cell; converted artifacts parked at {}",
        parked.display()
    ))
}
