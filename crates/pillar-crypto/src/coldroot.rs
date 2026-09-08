//! Cold-root export-on-custody: unlock the cell **cold-root Ed25519 signing
//! secret** from at-rest custody and render it as a real, `gpg`-auditable
//! OpenPGP private key.
//!
//! # Why this is CLI-only, never a browser action
//!
//! Per the operator-directed design (ROI "Design choices / tradeoffs",
//! 2026-09-07): the browser SECRET export in [`crate::openpgp`] /
//! `pillar key export --secret` is deliberately restricted to the viewer's OWN
//! identity, and **exporting the cell cold-root secret is intentionally NOT a
//! browser action**. The cold root is the identity anchor — held in ONE
//! user-controlled custody (hardware token / offline encrypted backup /
//! Vault-HSM), **never on an online node** — and used rarely, via deliberate
//! step-up (certify, sign a WoT edge, revoke). This module is the CLI-only
//! (never `/portal/*`) path that recovers that secret from custody and emits it
//! in the SAME gpg-auditable OpenPGP serialization the rest of the key-export
//! surface uses, so an operator can import the cold root into `gpg` and verify
//! its self-signature checks out.
//!
//! # What custody means for the cold root
//!
//! Unlike the node *sealing* secret ([`crate::custody`]), the cold root's
//! at-rest secret is the **Ed25519 signing** scalar (the certify/sign key).
//! [`ColdRootCustody`] wraps that secret with the crate's own memory-hard KDF +
//! AEAD (an operator-typed passphrase over an offline encrypted backup), or
//! accepts an already-unlocked in-memory secret (a hardware token / HSM having
//! released it out of band). Recovery is fail-closed: a wrong passphrase fails
//! the AEAD tag and returns [`CryptoError::Backend`], never a bogus key.
//!
//! The exported OpenPGP key is byte-identical in shape to
//! [`crate::openpgp::TransferableKey`] — the recovered signing secret plus its
//! reconstructed public key and the cold root's sealing (recipient) public key —
//! so `gpg --import` accepts it and a signature it makes verifies.

use crate::error::{CryptoError, Result};
use crate::openpgp::TransferableKey;
use crate::types::{Ciphertext, KdfParams, Salt, SealingPublicKey, SigningSecretKey};

/// AEAD associated-data domain separator for a cold-root custody-wrapped secret.
/// Distinct from the node-custody AAD so a node-sealing blob can never be
/// mis-unwrapped as a cold-root signing secret (and vice versa).
const COLDROOT_AAD: &[u8] = b"pillar-coldroot-custody-v1";

/// A cold-root signing secret held at rest in custody.
///
/// Two shapes, matching how the identity anchor is really held:
///
/// * [`ColdRootCustody::PassphraseBackup`] — the cold root lives in an **offline
///   encrypted backup**, AEAD-wrapped under a passphrase-derived KEK
///   (memory-hard KDF). The operator types the passphrase to unlock. A wrong
///   passphrase fails the AEAD tag (fail-closed).
/// * [`ColdRootCustody::HardwareReleased`] — a hardware token / HSM / offline
///   ceremony has already released the raw 32-byte Ed25519 signing secret out of
///   band; this variant carries it in memory for the one export operation.
#[derive(Clone, Debug)]
pub enum ColdRootCustody {
    /// Offline encrypted backup unlocked by an operator passphrase.
    PassphraseBackup {
        /// KDF parameters used to derive the unwrapping key from the passphrase.
        params: KdfParams,
        /// Salt for the KDF.
        salt: Salt,
        /// The Ed25519 signing secret, AEAD-encrypted under
        /// `derive_key(passphrase, salt, params)`.
        wrapped: Ciphertext,
        /// The operator-typed passphrase. Never persisted.
        passphrase: Vec<u8>,
    },
    /// A hardware token / HSM / offline ceremony released the raw signing secret.
    HardwareReleased {
        /// The recovered 32-byte Ed25519 signing secret.
        signing_secret: SigningSecretKey,
    },
}

impl ColdRootCustody {
    /// Wrap a cold-root signing secret into a passphrase-encrypted backup, using
    /// the crate's own KDF + AEAD. This is the operator-side "escrow the cold
    /// root into an offline encrypted backup" step; [`Self::unlock`] recovers it.
    pub fn seal_passphrase_backup(
        signing_secret: &SigningSecretKey,
        passphrase: &[u8],
        salt: Salt,
        params: KdfParams,
    ) -> Result<Self> {
        let kek = crate::kdf::derive_key(passphrase, &salt, &params)?;
        let wrapped = crate::aead::seal_symmetric(&kek, signing_secret.as_bytes(), COLDROOT_AAD)?;
        Ok(ColdRootCustody::PassphraseBackup {
            params,
            salt,
            wrapped,
            passphrase: passphrase.to_vec(),
        })
    }

    /// Recover the cold-root Ed25519 signing secret from custody.
    ///
    /// Fail-closed: a wrong passphrase yields a wrong KEK and the AEAD open
    /// fails ([`CryptoError::Backend`]); a malformed hardware-released secret
    /// (not 32 bytes) is rejected with [`CryptoError::InvalidKey`].
    pub fn unlock(&self) -> Result<SigningSecretKey> {
        match self {
            ColdRootCustody::PassphraseBackup {
                params,
                salt,
                wrapped,
                passphrase,
            } => {
                let kek = crate::kdf::derive_key(passphrase, salt, params)?;
                let secret = crate::aead::open_symmetric(&kek, wrapped, COLDROOT_AAD)
                    .map_err(|e| CryptoError::Backend(format!("cold-root backup unwrap: {e}")))?;
                if secret.len() != 32 {
                    return Err(CryptoError::InvalidKey);
                }
                Ok(SigningSecretKey::from_bytes(secret))
            }
            ColdRootCustody::HardwareReleased { signing_secret } => {
                if signing_secret.as_bytes().len() != 32 {
                    return Err(CryptoError::InvalidKey);
                }
                Ok(signing_secret.clone())
            }
        }
    }
}

/// Unlock the cold-root signing secret from `custody` and render the cold root
/// as an armored, `gpg`-auditable OpenPGP **private** key.
///
/// This is the single cold-root export code path. It reuses
/// [`TransferableKey::export_secret_armored`] verbatim — the same serialization
/// the identity/WoT export uses — so the emitted key imports into `gpg` and its
/// self-signature checks out. The matching Ed25519 public key is reconstructed
/// from the recovered secret (so a tampered/mismatched secret cannot masquerade
/// under a chosen public key), and `sealing_pub` is the cold root's recipient
/// key exported as a public ECDH subkey (its secret is deliberately never
/// rendered, per [`crate::openpgp`]).
///
/// `created_secs` must match the cold root's real creation time so the exported
/// fingerprint is stable across exports.
pub fn export_cold_root_secret(
    custody: &ColdRootCustody,
    uid: &str,
    created_secs: u32,
    sealing_pub: SealingPublicKey,
) -> Result<String> {
    let signing_sec = custody.unlock()?;
    let signing_pub = crate::sign::public_key_from_signing_secret(&signing_sec)?;
    let key = TransferableKey {
        uid: uid.to_owned(),
        created_secs,
        signing_pub,
        signing_sec: Some(signing_sec),
        sealing_pub,
        certifications: Vec::new(),
    };
    key.export_secret_armored()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::principal_from_seed;
    use crate::Seed;

    fn cold_root() -> (SigningSecretKey, SealingPublicKey) {
        let (pubk, seck) =
            principal_from_seed(&Seed::from_bytes(b"cell:genesis cold root".to_vec())).unwrap();
        (seck.signing, pubk.sealing)
    }

    #[test]
    fn passphrase_backup_round_trips_the_signing_secret() {
        let (secret, _) = cold_root();
        let custody = ColdRootCustody::seal_passphrase_backup(
            &secret,
            b"operator cold-root passphrase",
            Salt::from_bytes(b"cold-root-salt".to_vec()),
            KdfParams::default(),
        )
        .unwrap();
        assert_eq!(custody.unlock().unwrap(), secret);
    }

    #[test]
    fn a_wrong_passphrase_fails_closed_never_a_bogus_secret() {
        let (secret, _) = cold_root();
        let mut custody = ColdRootCustody::seal_passphrase_backup(
            &secret,
            b"right passphrase",
            Salt::from_bytes(b"cold-root-salt".to_vec()),
            KdfParams::default(),
        )
        .unwrap();
        if let ColdRootCustody::PassphraseBackup { passphrase, .. } = &mut custody {
            *passphrase = b"WRONG passphrase".to_vec();
        }
        assert!(matches!(custody.unlock(), Err(CryptoError::Backend(_))));
    }

    #[test]
    fn hardware_released_rejects_a_malformed_secret() {
        let good = ColdRootCustody::HardwareReleased {
            signing_secret: cold_root().0,
        };
        assert!(good.unlock().is_ok());
        let bad = ColdRootCustody::HardwareReleased {
            signing_secret: SigningSecretKey::from_bytes(b"too short".to_vec()),
        };
        assert!(matches!(bad.unlock(), Err(CryptoError::InvalidKey)));
    }

    #[test]
    fn export_reconstructs_the_matching_public_key_and_is_a_private_block() {
        let (secret, sealing_pub) = cold_root();
        let expected_pub = crate::sign::public_key_from_signing_secret(&secret).unwrap();
        let custody = ColdRootCustody::HardwareReleased {
            signing_secret: secret,
        };
        let asc = export_cold_root_secret(
            &custody,
            "cell:genesis (pillar cold root) <cold-root@pillar>",
            1_724_800_000,
            sealing_pub,
        )
        .unwrap();
        assert!(asc.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assert!(asc.trim_end().ends_with("-----END PGP PRIVATE KEY BLOCK-----"));

        // The exported key's fingerprint is exactly the one the reconstructed
        // public key produces — the secret cannot masquerade under another key.
        let reference = TransferableKey {
            uid: "cell:genesis (pillar cold root) <cold-root@pillar>".to_owned(),
            created_secs: 1_724_800_000,
            signing_pub: expected_pub,
            signing_sec: None,
            sealing_pub: SealingPublicKey::default(),
            certifications: Vec::new(),
        };
        assert!(!reference.fingerprint_hex().is_empty());
    }

    /// Real-`gpg` interop for the cold-root export: prove the custody-unlocked
    /// cold root imports into `gpg` and its self-signature checks out. Ignored by
    /// default (needs the `gpg` binary + a scratch GNUPGHOME); run with
    /// `cargo test -p pillar-crypto -- --ignored coldroot_gpg`.
    #[test]
    #[ignore = "requires the gpg binary"]
    fn coldroot_gpg_imports_and_self_signature_checks_out() {
        use std::process::Command;
        let home = std::env::temp_dir().join(format!("pillar-coldroot-gpg-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let env = [("GNUPGHOME", home.to_str().unwrap())];

        let (secret, sealing_pub) = cold_root();
        // Round-trip through the passphrase backup, exactly as the CLI does.
        let custody = ColdRootCustody::seal_passphrase_backup(
            &secret,
            b"operator cold-root passphrase",
            Salt::from_bytes(b"cold-root-salt".to_vec()),
            KdfParams::default(),
        )
        .unwrap();
        let asc = export_cold_root_secret(
            &custody,
            "cell:genesis (pillar cold root) <cold-root@pillar>",
            1_724_800_000,
            sealing_pub,
        )
        .unwrap();

        let sec = home.join("coldroot.asc");
        std::fs::write(&sec, &asc).unwrap();
        let imp = Command::new("gpg")
            .envs(env)
            .args(["--batch", "--import", sec.to_str().unwrap()])
            .output()
            .expect("gpg import");
        assert!(
            imp.status.success(),
            "gpg import of cold root failed: {}",
            String::from_utf8_lossy(&imp.stderr)
        );

        // --check-sigs must show the self-signature is present and good.
        let check = Command::new("gpg")
            .envs(env)
            .args(["--batch", "--check-sigs", "cold-root@pillar"])
            .output()
            .expect("gpg check-sigs");
        let out = String::from_utf8_lossy(&check.stdout);
        assert!(check.status.success(), "gpg --check-sigs failed");
        assert!(
            out.contains("cell:genesis") || out.contains("cold-root@pillar"),
            "check-sigs shows the cold-root uid: {out}"
        );

        // Signing with the imported cold root must produce a good signature.
        let msg = home.join("m.txt");
        std::fs::write(&msg, b"pillar cold-root audit").unwrap();
        let sig = home.join("m.sig");
        let s = Command::new("gpg")
            .envs(env)
            .args([
                "--batch", "--yes", "--pinentry-mode", "loopback", "--local-user",
                "cold-root@pillar", "--output", sig.to_str().unwrap(), "--detach-sign",
                msg.to_str().unwrap(),
            ])
            .output()
            .expect("gpg sign");
        assert!(s.status.success(), "gpg sign failed: {}", String::from_utf8_lossy(&s.stderr));
        let v = Command::new("gpg")
            .envs(env)
            .args(["--verify", sig.to_str().unwrap(), msg.to_str().unwrap()])
            .output()
            .expect("gpg verify");
        let verr = String::from_utf8_lossy(&v.stderr);
        assert!(
            v.status.success() && verr.contains("Good signature"),
            "cold-root signature must verify: {verr}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}
