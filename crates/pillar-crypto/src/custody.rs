//! Node-key custody backends.
//!
//! A node unseals offers with its **sealing secret key** ([`crate::seal`]). How
//! that secret is protected at rest is a pluggable custody backend. Four are
//! wired here:
//!
//! * [`UnencryptedCustody`] — plaintext on disk (operator-approved for node
//!   keys).
//! * [`PasswordCustody`] — encrypted under a password the operator types at
//!   node restart (KDF + AEAD unwrap).
//! * [`TpmCustody`] — sealed to a TPM, released under a PCR / auth policy.
//! * [`PasskeyCustody`] — unlocked via a passkey / WebAuthn authenticator (e.g.
//!   the PRF/hmac-secret extension).
//!
//! All four are selectable at runtime via the [`Custody`] enum. Every
//! `load_sealing_secret` currently returns [`CryptoError::NotImplemented`]; the
//! contract tests pin each backend. The TPM and passkey backends need a
//! hardware or software provider (swtpm / soft-webauthn) so their contract test
//! can run without physical hardware — the implementer supplies it.

use crate::error::{CryptoError, Result};
use crate::types::{Ciphertext, CustodyKind, KdfParams, Salt, SealingSecretKey};

/// A backend that recovers a node's sealing secret key from at-rest custody.
pub trait NodeCustody {
    /// Which custody kind this backend implements.
    fn kind(&self) -> CustodyKind;

    /// Recover the node's sealing secret key (used to unseal offers sealed to
    /// this node).
    fn load_sealing_secret(&self) -> Result<SealingSecretKey>;
}

/// Plaintext node key on disk (operator-approved).
#[derive(Clone, Debug)]
pub struct UnencryptedCustody {
    secret: SealingSecretKey,
}

impl UnencryptedCustody {
    /// Wrap a plaintext sealing secret read from disk.
    pub fn new(secret: SealingSecretKey) -> Self {
        Self { secret }
    }
}

impl NodeCustody for UnencryptedCustody {
    fn kind(&self) -> CustodyKind {
        CustodyKind::Unencrypted
    }
    fn load_sealing_secret(&self) -> Result<SealingSecretKey> {
        // Even this trivial passthrough is pinned by a test rather than assumed,
        // so "unencrypted" is a deliberate wired choice, not an accident.
        let _ = &self.secret;
        Err(CryptoError::NotImplemented(
            "custody::UnencryptedCustody::load_sealing_secret",
        ))
    }
}

/// Node key encrypted under an operator-typed password (KDF + AEAD).
#[derive(Clone, Debug)]
pub struct PasswordCustody {
    /// KDF parameters used to derive the unwrapping key.
    pub params: KdfParams,
    /// Salt for the KDF.
    pub salt: Salt,
    /// The sealing secret, AEAD-encrypted under `derive_key(password, salt, params)`.
    pub wrapped: Ciphertext,
    /// The password supplied by the operator at node restart. Never persisted.
    pub password: Vec<u8>,
}

impl NodeCustody for PasswordCustody {
    fn kind(&self) -> CustodyKind {
        CustodyKind::Password
    }
    fn load_sealing_secret(&self) -> Result<SealingSecretKey> {
        let _ = (&self.params, &self.salt, &self.wrapped, &self.password);
        Err(CryptoError::NotImplemented(
            "custody::PasswordCustody::load_sealing_secret",
        ))
    }
}

/// Node key sealed to a TPM, released under a policy.
#[derive(Clone, Debug)]
pub struct TpmCustody {
    /// Opaque TPM-sealed blob wrapping the node's sealing secret.
    pub sealed_blob: Vec<u8>,
    /// Opaque policy descriptor (PCR selection / auth) the TPM enforces on release.
    pub policy: Vec<u8>,
}

impl NodeCustody for TpmCustody {
    fn kind(&self) -> CustodyKind {
        CustodyKind::Tpm
    }
    fn load_sealing_secret(&self) -> Result<SealingSecretKey> {
        let _ = (&self.sealed_blob, &self.policy);
        Err(CryptoError::NotImplemented(
            "custody::TpmCustody::load_sealing_secret",
        ))
    }
}

/// Node key unlocked via a passkey / WebAuthn authenticator.
#[derive(Clone, Debug)]
pub struct PasskeyCustody {
    /// WebAuthn credential id to assert against.
    pub credential_id: Vec<u8>,
    /// PRF / hmac-secret salt fed to the authenticator to derive the unwrapping key.
    pub prf_salt: Vec<u8>,
    /// The sealing secret, AEAD-encrypted under the passkey-derived key.
    pub wrapped: Ciphertext,
}

impl NodeCustody for PasskeyCustody {
    fn kind(&self) -> CustodyKind {
        CustodyKind::Passkey
    }
    fn load_sealing_secret(&self) -> Result<SealingSecretKey> {
        let _ = (&self.credential_id, &self.prf_salt, &self.wrapped);
        Err(CryptoError::NotImplemented(
            "custody::PasskeyCustody::load_sealing_secret",
        ))
    }
}

/// Runtime-selectable node custody backend.
#[derive(Clone, Debug)]
pub enum Custody {
    /// See [`UnencryptedCustody`].
    Unencrypted(UnencryptedCustody),
    /// See [`PasswordCustody`].
    Password(PasswordCustody),
    /// See [`TpmCustody`].
    Tpm(TpmCustody),
    /// See [`PasskeyCustody`].
    Passkey(PasskeyCustody),
}

impl NodeCustody for Custody {
    fn kind(&self) -> CustodyKind {
        match self {
            Custody::Unencrypted(b) => b.kind(),
            Custody::Password(b) => b.kind(),
            Custody::Tpm(b) => b.kind(),
            Custody::Passkey(b) => b.kind(),
        }
    }
    fn load_sealing_secret(&self) -> Result<SealingSecretKey> {
        match self {
            Custody::Unencrypted(b) => b.load_sealing_secret(),
            Custody::Password(b) => b.load_sealing_secret(),
            Custody::Tpm(b) => b.load_sealing_secret(),
            Custody::Passkey(b) => b.load_sealing_secret(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::seal_symmetric;
    use crate::kdf::derive_key;

    #[test]
    fn kind_dispatch_reports_the_selected_backend() {
        let secret = SealingSecretKey::from_bytes(b"node-sealing-secret".to_vec());
        let unenc = Custody::Unencrypted(UnencryptedCustody::new(secret));
        assert_eq!(unenc.kind(), CustodyKind::Unencrypted);
        let tpm = Custody::Tpm(TpmCustody {
            sealed_blob: b"blob".to_vec(),
            policy: b"pcr7".to_vec(),
        });
        assert_eq!(tpm.kind(), CustodyKind::Tpm);
    }

    #[test]
    fn unencrypted_custody_returns_the_stored_secret() {
        let secret = SealingSecretKey::from_bytes(b"plaintext node sealing secret".to_vec());
        let backend = UnencryptedCustody::new(secret.clone());
        assert_eq!(backend.kind(), CustodyKind::Unencrypted);
        assert_eq!(
            backend.load_sealing_secret(),
            Ok(secret),
            "unencrypted custody must return exactly the stored secret"
        );
    }

    #[test]
    fn password_custody_recovers_the_wrapped_secret() {
        // Wrap the node secret using the crate's own KDF + AEAD, then prove the
        // backend recovers it. Chains kdf + aead + custody, so it is RED until
        // all three are implemented.
        let params = KdfParams::default();
        let salt = Salt::from_bytes(b"node-custody-salt".to_vec());
        let password = b"node restart passphrase";
        let secret = SealingSecretKey::from_bytes(b"the-node-x25519-sealing-secret!!".to_vec());

        let kek = derive_key(password, &salt, &params).expect("kdf");
        let wrapped =
            seal_symmetric(&kek, secret.as_bytes(), b"pillar-node-custody-v1").expect("wrap");

        let backend = PasswordCustody {
            params,
            salt,
            wrapped,
            password: password.to_vec(),
        };
        assert_eq!(backend.kind(), CustodyKind::Password);
        assert_eq!(
            backend.load_sealing_secret(),
            Ok(secret),
            "password custody must recover exactly the wrapped secret"
        );
    }

    #[test]
    fn tpm_custody_is_wired_and_recovers_a_secret() {
        // Hardware-independent contract: a wired TPM backend recovers the node
        // sealing secret. The implementer provides a swtpm-backed software
        // provider so this runs in CI.
        let backend = TpmCustody {
            sealed_blob: b"tpm-sealed-node-sealing-secret".to_vec(),
            policy: b"pcr7,pcr11".to_vec(),
        };
        assert_eq!(backend.kind(), CustodyKind::Tpm);
        assert!(
            backend.load_sealing_secret().is_ok(),
            "TPM custody must recover the node sealing secret"
        );
    }

    #[test]
    fn passkey_custody_is_wired_and_recovers_a_secret() {
        // Hardware-independent contract: a wired passkey backend recovers the
        // node sealing secret. The implementer provides a soft-webauthn
        // authenticator so this runs in CI.
        let backend = PasskeyCustody {
            credential_id: b"cred-abc".to_vec(),
            prf_salt: b"pillar-node-prf-salt".to_vec(),
            wrapped: Ciphertext::from_bytes(b"passkey-wrapped-node-secret".to_vec()),
        };
        assert_eq!(backend.kind(), CustodyKind::Passkey);
        assert!(
            backend.load_sealing_secret().is_ok(),
            "passkey custody must recover the node sealing secret"
        );
    }
}
