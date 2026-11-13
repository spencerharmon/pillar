//! Offline enrollment using the joining daemon's real `identity.key` keypair.
//!
//! Proofs authenticate the joining node, not the issuer. Exchange requests and
//! sealed bundles over authenticated SSH forwarding or another trusted transport;
//! sealing alone does not authenticate whoever supplied a bundle. Callers must
//! serialize enrollment/credential writes for a data directory.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::Path;

use libp2p::identity::{Keypair, PublicKey};
use pillar_crypto::seal::{seal_to_recipients, sealing_keypair_from_seed, unseal};
use pillar_crypto::{SealedEnvelope, SealingPublicKey, SealingSecretKey, Seed};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const REQUEST_DOMAIN: &[u8] = b"pillar/enrollment/submit/v1\0";
const RETRIEVE_DOMAIN: &[u8] = b"pillar/enrollment/retrieve/v1\0";
const SEALING_DOMAIN: &[u8] = b"pillar/enrollment/device-sealing/v1\0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeRequest {
    pub public_key: Vec<u8>,
    pub sealing_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetrieveRequest {
    pub id: u64,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

// Deliberately no Debug: credentials contain the shared cell secret.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CellCredentials {
    pub cell_id: Vec<u8>,
    pub seed: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentBundle {
    pub version: u32,
    pub request_id: u64,
    pub recipient: String,
    pub credentials: CellCredentials,
    pub portal_ops: Vec<Vec<u8>>,
}

fn sealing_keys(keypair: &Keypair) -> Result<(SealingPublicKey, SealingSecretKey), String> {
    let private = keypair.to_protobuf_encoding().map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    hash.update(SEALING_DOMAIN);
    hash.update(private);
    sealing_keypair_from_seed(&Seed::from_bytes(hash.finalize().to_vec()))
        .map_err(|e| e.to_string())
}

/// This node's X25519 sealing keypair, derived from its custody-held identity
/// exactly as its enrollment request advertises it.
pub(crate) fn node_sealing_keys(
    keypair: &Keypair,
) -> Result<(SealingPublicKey, SealingSecretKey), String> {
    sealing_keys(keypair)
}

fn request_bytes(public_key: &[u8], sealing_key: &[u8]) -> Vec<u8> {
    let mut bytes = REQUEST_DOMAIN.to_vec();
    // Length prefixes make the two variable-length fields unambiguous.
    for field in [public_key, sealing_key] {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes
}

fn retrieval_bytes(id: u64) -> Vec<u8> {
    let mut bytes = RETRIEVE_DOMAIN.to_vec();
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes
}

pub(crate) fn request(keypair: &Keypair) -> Result<NodeRequest, String> {
    let public_key = keypair.public().encode_protobuf();
    let sealing_key = sealing_keys(keypair)?.0.into_bytes();
    let signature = keypair
        .sign(&request_bytes(&public_key, &sealing_key))
        .map_err(|e| e.to_string())?;
    Ok(NodeRequest {
        public_key,
        sealing_key,
        signature,
    })
}

pub(crate) fn verify_request(req: &NodeRequest) -> Result<(String, SealingPublicKey), String> {
    let public = PublicKey::try_decode_protobuf(&req.public_key).map_err(|e| e.to_string())?;
    if !public.verify(
        &request_bytes(&req.public_key, &req.sealing_key),
        &req.signature,
    ) {
        return Err("invalid enrollment request signature".into());
    }
    if req.sealing_key.len() != 32 {
        return Err("enrollment sealing key must be 32 bytes".into());
    }
    let sealing = SealingPublicKey::from_bytes(req.sealing_key.clone());
    // Reject low-order X25519 points rather than sealing to a public shared secret.
    let shared = pillar_crypto::seal::x25519_shared_secret(
        &SealingSecretKey::from_bytes(vec![0x42; 32]),
        &sealing,
    )
    .map_err(|e| e.to_string())?;
    if shared == [0; 32] {
        return Err("invalid enrollment sealing key".into());
    }
    Ok((public.to_peer_id().to_string(), sealing))
}

pub(crate) fn retrieval(keypair: &Keypair, id: u64) -> Result<RetrieveRequest, String> {
    Ok(RetrieveRequest {
        id,
        public_key: keypair.public().encode_protobuf(),
        signature: keypair
            .sign(&retrieval_bytes(id))
            .map_err(|e| e.to_string())?,
    })
}

pub(crate) fn verify_retrieval(req: &RetrieveRequest, expected_peer: &str) -> Result<(), String> {
    let public = PublicKey::try_decode_protobuf(&req.public_key).map_err(|e| e.to_string())?;
    if public.to_peer_id().to_string() != expected_peer {
        return Err("retrieval identity does not match the stored request subject".into());
    }
    if !public.verify(&retrieval_bytes(req.id), &req.signature) {
        return Err("invalid enrollment retrieval signature".into());
    }
    Ok(())
}

pub(crate) fn validate_credentials(credentials: &CellCredentials) -> Result<(), String> {
    if credentials.seed.len() != 32
        || credentials.cell_id.as_slice() != Sha256::digest(&credentials.seed).as_slice()
    {
        return Err(
            "invalid cell credentials: expected 32-byte seed and its SHA256 cell ID".into(),
        );
    }
    Ok(())
}

fn validate_bundle(keypair: &Keypair, bundle: &EnrollmentBundle) -> Result<(), String> {
    if bundle.version != 1 {
        return Err("unsupported enrollment bundle version".into());
    }
    if bundle.recipient != keypair.public().to_peer_id().to_string() {
        return Err("enrollment bundle belongs to another identity".into());
    }
    validate_credentials(&bundle.credentials)
}

pub(crate) fn unseal_bundle(
    keypair: &Keypair,
    bytes: &[u8],
    id: u64,
) -> Result<EnrollmentBundle, String> {
    let plaintext = unseal(
        &SealedEnvelope::from_bytes(bytes.to_vec()),
        &sealing_keys(keypair)?.1,
    )
    .map_err(|e| format!("cannot unseal enrollment bundle: {e}"))?;
    let bundle: EnrollmentBundle = serde_json::from_slice(&plaintext).map_err(|e| e.to_string())?;
    validate_bundle(keypair, &bundle)?;
    if bundle.request_id != id {
        return Err("enrollment bundle request ID does not match".into());
    }
    Ok(bundle)
}

pub(crate) fn install(
    data_dir: &Path,
    keypair: &Keypair,
    bundle: &EnrollmentBundle,
) -> Result<(), String> {
    validate_bundle(keypair, bundle)?;
    if let Some(installed) = load_installed(data_dir, keypair)? {
        if installed == *bundle {
            return Ok(());
        }
        return Err("refusing to overwrite an existing enrollment with a different bundle".into());
    }
    if data_dir
        .join("cell-initialized")
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        return Err("refusing to replace an initialized cell".into());
    }
    if data_dir
        .join("streamdb")
        .try_exists()
        .map_err(|e| e.to_string())?
        && !data_dir
            .join("cell-credentials.json")
            .try_exists()
            .map_err(|e| e.to_string())?
    {
        return Err("refusing enrollment over legacy cell storage".into());
    }
    let plaintext = serde_json::to_vec(bundle).map_err(|e| e.to_string())?;
    let envelope =
        seal_to_recipients(&plaintext, &[sealing_keys(keypair)?.0]).map_err(|e| e.to_string())?;
    write_private(&data_dir.join("enrollment.sealed"), envelope.as_bytes())
}

pub(crate) fn load_installed(
    data_dir: &Path,
    keypair: &Keypair,
) -> Result<Option<EnrollmentBundle>, String> {
    let bytes = match fs::read(data_dir.join("enrollment.sealed")) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let plaintext = unseal(
        &SealedEnvelope::from_bytes(bytes),
        &sealing_keys(keypair)?.1,
    )
    .map_err(|e| format!("cannot unseal installed enrollment: {e}"))?;
    let bundle = serde_json::from_slice(&plaintext).map_err(|e| e.to_string())?;
    validate_bundle(keypair, &bundle)?;
    Ok(Some(bundle))
}

/// Issuer initialization only; joining nodes get credentials from their bundle.
pub(crate) fn load_credentials(data_dir: &Path) -> Result<CellCredentials, String> {
    let path = data_dir.join("cell-credentials.json");
    match fs::read(&path) {
        Ok(bytes) => {
            let credentials = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            validate_credentials(&credentials)?;
            Ok(credentials)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let mut seed = vec![0; 32];
            getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
            let credentials = CellCredentials {
                cell_id: Sha256::digest(&seed).to_vec(),
                seed,
            };
            write_private(
                &path,
                &serde_json::to_vec(&credentials).map_err(|e| e.to_string())?,
            )?;
            Ok(credentials)
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Atomically replace a private file, syncing both contents and directory entry.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = (path, bytes);
        Err("private enrollment persistence requires Unix file permissions".into())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).map_err(|e| e.to_string())?;
        let nonce = u128::from_be_bytes(random);
        let temporary = parent.join(format!(".enrollment-{nonce:032x}.tmp"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        let result = (|| -> std::io::Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            File::open(parent)?.sync_all()
        })();
        if let Err(error) = result {
            match fs::remove_file(&temporary) {
                Ok(()) => {}
                Err(cleanup) if cleanup.kind() == ErrorKind::NotFound => {}
                Err(cleanup) => {
                    return Err(format!("{error}; temporary file cleanup failed: {cleanup}"));
                }
            }
            return Err(error.to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(keypair: &Keypair) -> EnrollmentBundle {
        let seed = vec![19; 32];
        EnrollmentBundle {
            version: 1,
            request_id: 42,
            recipient: keypair.public().to_peer_id().to_string(),
            credentials: CellCredentials {
                cell_id: Sha256::digest(&seed).to_vec(),
                seed,
            },
            portal_ops: vec![vec![1, 2, 3]],
        }
    }

    fn seal_bundle(keypair: &Keypair, bundle: &EnrollmentBundle) -> Vec<u8> {
        let (_, public) = verify_request(&request(keypair).unwrap()).unwrap();
        seal_to_recipients(&serde_json::to_vec(bundle).unwrap(), &[public])
            .unwrap()
            .into_bytes()
    }

    #[test]
    fn proofs_bind_identity_key_and_request_id() {
        let key = Keypair::generate_ed25519();
        let other = Keypair::generate_ed25519();
        let req = request(&key).unwrap();
        let (peer, _) = verify_request(&req).unwrap();
        assert_eq!(peer, key.public().to_peer_id().to_string());
        for field in 0..3 {
            let mut bad = req.clone();
            match field {
                0 => bad.public_key = other.public().encode_protobuf(),
                1 => bad.sealing_key[0] ^= 1,
                _ => bad.signature[0] ^= 1,
            }
            assert!(verify_request(&bad).is_err());
        }
        let mut bad = req.clone();
        bad.sealing_key = vec![0; 32];
        bad.signature = key
            .sign(&request_bytes(&bad.public_key, &bad.sealing_key))
            .unwrap();
        assert!(verify_request(&bad).is_err());
        let proof = retrieval(&key, 42).unwrap();
        verify_retrieval(&proof, &peer).unwrap();
        assert!(verify_retrieval(&retrieval(&other, 42).unwrap(), &peer).is_err());
        let mut bad = proof.clone();
        bad.id += 1;
        assert!(verify_retrieval(&bad, &peer).is_err());
        bad = proof;
        bad.signature = req.signature;
        assert!(verify_retrieval(&bad, &peer).is_err());
    }

    #[test]
    fn sealed_roundtrip_rejects_wrong_key_tamper_and_invalid_bindings() {
        let key = Keypair::generate_ed25519();
        let other = Keypair::generate_ed25519();
        let original = bundle(&key);
        let bytes = seal_bundle(&key, &original);
        let restored =
            Keypair::from_protobuf_encoding(&key.to_protobuf_encoding().unwrap()).unwrap();
        assert!(unseal_bundle(&restored, &bytes, 42).unwrap() == original);
        assert!(unseal_bundle(&other, &bytes, 42).is_err());
        assert!(unseal_bundle(&key, &bytes, 43).is_err());
        let mut tampered = bytes;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(unseal_bundle(&key, &tampered, 42).is_err());
        for field in 0..4 {
            let mut invalid = original.clone();
            match field {
                0 => invalid.version = 2,
                1 => invalid.recipient = other.public().to_peer_id().to_string(),
                2 => invalid.credentials.seed.pop().map(|_| ()).unwrap(),
                _ => invalid.credentials.cell_id[0] ^= 1,
            }
            assert!(unseal_bundle(&key, &seal_bundle(&key, &invalid), 42).is_err());
        }
    }

    #[test]
    fn installation_is_private_idempotent_and_refuses_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let key = Keypair::generate_ed25519();
        assert!(load_installed(dir.path(), &key).unwrap().is_none());
        let original = bundle(&key);
        install(dir.path(), &key, &original).unwrap();
        let path = dir.path().join("enrollment.sealed");
        let bytes = fs::read(&path).unwrap();
        assert!(serde_json::from_slice::<EnrollmentBundle>(&bytes).is_err());
        install(dir.path(), &key, &original).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(load_installed(dir.path(), &key).unwrap().unwrap() == original);
        let other = Keypair::generate_ed25519();
        assert!(load_installed(dir.path(), &other).is_err());
        assert!(install(dir.path(), &other, &bundle(&other)).is_err());
        let mut changed = original;
        changed.credentials.seed[0] ^= 1;
        changed.credentials.cell_id = Sha256::digest(&changed.credentials.seed).to_vec();
        assert!(install(dir.path(), &key, &changed).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn installation_refuses_initialized_and_legacy_storage() {
        let key = Keypair::generate_ed25519();
        let dir = tempfile::tempdir().unwrap();
        write_private(&dir.path().join("cell-initialized"), b"1\n").unwrap();
        assert!(install(dir.path(), &key, &bundle(&key)).is_err());
        assert!(!dir.path().join("enrollment.sealed").exists());
        let legacy = tempfile::tempdir().unwrap();
        fs::create_dir(legacy.path().join("streamdb")).unwrap();
        assert!(install(legacy.path(), &key, &bundle(&key)).is_err());
        assert!(!legacy.path().join("enrollment.sealed").exists());
    }

    #[test]
    fn issuer_credentials_are_random_persistent_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let credentials = load_credentials(dir.path()).unwrap();
        assert!(credentials == load_credentials(dir.path()).unwrap());
        assert!(credentials != load_credentials(other.path()).unwrap());
        let path = dir.path().join("cell-credentials.json");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            write_private(&path, b"invalid").unwrap();
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        write_private(&path, b"invalid").unwrap();
        assert!(load_credentials(dir.path()).is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
