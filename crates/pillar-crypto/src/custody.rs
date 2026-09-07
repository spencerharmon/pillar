//! Node-key custody backends.
//!
//! A node unseals offers with its **sealing secret key** ([`crate::seal`]). How
//! that secret is protected at rest is a pluggable custody backend. The full
//! set of popular hardware security modules is available; the operator selects
//! one at runtime via the [`Custody`] enum:
//!
//! The hardware backends (TPM / passkey / PKCS#11) are behind the crate's
//! `tpm` / `passkey` / `pkcs11` Cargo features (all folded into `hsm`) so the
//! everyday build skips their bindgen crates and native libraries. They are
//! **off by default but on in every shipped node**: the deploy build runs
//! `cargo build -p pillar-cli --features hsm`, so a deployed node carries all
//! of them. When a backend's feature is not compiled in, its
//! [`load_sealing_secret`](NodeCustody::load_sealing_secret) fails closed with
//! [`CryptoError::Backend`] rather than silently returning a bogus secret.
//!
//! * [`UnencryptedCustody`] — plaintext on disk (operator-approved for node
//!   keys).
//! * [`PasswordCustody`] — encrypted under a password the operator types at
//!   node restart (memory-hard KDF + AEAD unwrap).
//! * [`TpmCustody`] — the sealing secret is TPM-sealed under a persistent
//!   parent (SRK) and unsealed on the device via `tss-esapi` / tpm2-tss.
//! * [`PasskeyCustody`] — a FIDO2 authenticator's `hmac-secret` (WebAuthn PRF)
//!   output unwraps the sealing secret, via `ctap-hid-fido2` / CTAP2.
//! * [`Pkcs11Custody`] — a PKCS#11 HSM / smart card decrypts the wrapped
//!   sealing secret with a key that never leaves the device, via `cryptoki`.
//!
//! # What is and is not unit-tested in CI
//!
//! The hardware backends make real device calls; they cannot be exercised in CI
//! without physical hardware (and this crate ships **no** hardware integration
//! test). What CI unit-tests is exactly what is meaningful without a device:
//!
//! * the **pure unwrap** step ([`unwrap_with_kek`]) that turns a
//!   hardware-released key-encryption key into the sealing secret (real AEAD,
//!   round-trip + wrong-key rejection);
//! * **fail-closed** behaviour — a misconfigured hardware backend (empty sealed
//!   blob / module path / credential) returns [`CryptoError::Backend`] BEFORE
//!   any device I/O and never yields a secret.
//!
//! The on-device operations (TPM unseal, HSM decrypt, authenticator assertion)
//! are compiled by CI and validated by the operator against real hardware.

use crate::error::{CryptoError, Result};
#[cfg(any(test, feature = "passkey"))]
use crate::types::SymmetricKey;
use crate::types::{Ciphertext, CustodyKind, KdfParams, Salt, SealingSecretKey};

/// AEAD associated-data domain separator for custody-wrapped node secrets.
const CUSTODY_AAD: &[u8] = b"pillar-node-custody-v1";

/// Domain-separated HKDF-SHA256 to 32 bytes. Used to post-process a raw
/// hardware-released secret (e.g. a FIDO2 `hmac-secret` output) into a
/// key-encryption key bound to a purpose, so the same device secret can never
/// be reused verbatim across domains.
#[cfg(any(test, feature = "passkey"))]
fn hkdf32(domain: &[u8], salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    // `expand` only fails for absurd output lengths; 32 bytes never fails.
    hk.expand(domain, &mut out)
        .expect("hkdf expand of 32 bytes is infallible");
    out
}

/// AEAD-unwrap a sealing secret from `wrapped` using a 32-byte key-encryption
/// key released by a hardware backend. Pure — this is the CI-testable half of
/// the passkey / HSM flows. A wrong KEK fails the AEAD tag and returns an error
/// (fail-closed), never a bogus secret.
#[cfg(any(test, feature = "passkey"))]
fn unwrap_with_kek(kek: [u8; 32], wrapped: &Ciphertext) -> Result<SealingSecretKey> {
    let key = SymmetricKey::from_bytes(kek.to_vec());
    let secret = crate::aead::open_symmetric(&key, wrapped, CUSTODY_AAD)?;
    Ok(SealingSecretKey::from_bytes(secret))
}

/// Map a hardware/library error into a crate error without leaking the concrete
/// dependency type into the public surface.
#[cfg(any(feature = "tpm", feature = "passkey", feature = "pkcs11"))]
fn backend_err(context: &str, e: impl core::fmt::Display) -> CryptoError {
    CryptoError::Backend(format!("{context}: {e}"))
}

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
        Ok(self.secret.clone())
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
        // Derive the key-encryption key from the operator password (memory-hard
        // KDF), then AEAD-unwrap the sealing secret. A wrong password yields a
        // wrong KEK and the AEAD open fails closed.
        let kek = crate::kdf::derive_key(&self.password, &self.salt, &self.params)?;
        let secret = crate::aead::open_symmetric(&kek, &self.wrapped, CUSTODY_AAD)?;
        Ok(SealingSecretKey::from_bytes(secret))
    }
}

/// Node key sealed to a TPM 2.0 and unsealed on the device (`tss-esapi`).
///
/// The sealing secret is a TPM sealed-data object created under a persistent
/// parent (typically the SRK). Recovery loads the object under that parent and
/// asks the TPM to unseal it; the plaintext only ever exists inside the TPM
/// until the unseal result is returned to this process.
#[derive(Clone, Debug)]
pub struct TpmCustody {
    /// TCTI configuration string, e.g. `"device:/dev/tpmrm0"` or
    /// `"swtpm:host=localhost,port=2321"`. Empty ⇒ resolved from the standard
    /// `TPM2TOOLS_TCTI` / `TCTI` environment variable.
    pub tcti: String,
    /// Persistent handle of the parent key the object was sealed under (e.g.
    /// `0x81000001` for a provisioned SRK).
    pub parent_handle: u32,
    /// Marshalled `TPM2B_PUBLIC` of the sealed object.
    pub sealed_public: Vec<u8>,
    /// Marshalled `TPM2B_PRIVATE` of the sealed object.
    pub sealed_private: Vec<u8>,
    /// Optional auth value (password) guarding the sealed object. Empty ⇒ the
    /// object is not password-protected (release is governed by the parent /
    /// platform state alone).
    pub auth: Vec<u8>,
}

impl NodeCustody for TpmCustody {
    fn kind(&self) -> CustodyKind {
        CustodyKind::Tpm
    }
    fn load_sealing_secret(&self) -> Result<SealingSecretKey> {
        // Fail closed on misconfiguration before touching the device.
        if self.sealed_public.is_empty() || self.sealed_private.is_empty() {
            return Err(CryptoError::Backend(
                "tpm: empty sealed object (no public/private)".into(),
            ));
        }

        #[cfg(not(feature = "tpm"))]
        {
            Err(CryptoError::Backend(
                "tpm: TPM custody support was not compiled in (build with the \"tpm\" feature)"
                    .into(),
            ))
        }

        #[cfg(feature = "tpm")]
        {
            use std::str::FromStr;
            use tss_esapi::handles::{PersistentTpmHandle, TpmHandle};
            use tss_esapi::structures::{Auth, Private, Public};
            use tss_esapi::traits::UnMarshall;
            use tss_esapi::{Context, TctiNameConf};

            let tcti = if self.tcti.is_empty() {
                TctiNameConf::from_environment_variable()
                    .map_err(|e| backend_err("tpm: tcti from env", e))?
            } else {
                TctiNameConf::from_str(&self.tcti).map_err(|e| backend_err("tpm: tcti", e))?
            };
            let mut ctx = Context::new(tcti).map_err(|e| backend_err("tpm: context", e))?;

            let persistent = PersistentTpmHandle::new(self.parent_handle)
                .map_err(|e| backend_err("tpm: parent handle", e))?;
            let parent_object = ctx
                .tr_from_tpm_public(TpmHandle::Persistent(persistent))
                .map_err(|e| backend_err("tpm: resolve parent", e))?;

            let public = Public::unmarshall(&self.sealed_public)
                .map_err(|e| backend_err("tpm: unmarshall public", e))?;
            let private = Private::try_from(self.sealed_private.clone())
                .map_err(|e| backend_err("tpm: private", e))?;
            let auth = self.auth.clone();

            let secret: Vec<u8> = ctx
                .execute_with_nullauth_session(|ctx| {
                    let object = ctx.load(parent_object.into(), private.clone(), public.clone())?;
                    if !auth.is_empty() {
                        let auth_value = Auth::try_from(auth.clone())?;
                        ctx.tr_set_auth(object.into(), auth_value)?;
                    }
                    let sensitive = ctx.unseal(object.into())?;
                    Ok::<Vec<u8>, tss_esapi::Error>(sensitive.value().to_vec())
                })
                .map_err(|e| backend_err("tpm: unseal", e))?;

            Ok(SealingSecretKey::from_bytes(secret))
        }
    }
}

/// Node key unlocked by a FIDO2 authenticator's `hmac-secret` (WebAuthn PRF)
/// output (`ctap-hid-fido2`).
///
/// A get-assertion with the `hmac-secret` extension yields a 32-byte output
/// deterministic in the (credential, salt) pair but computable only by the
/// authenticator holding the credential. That output is expanded into a
/// key-encryption key that AEAD-unwraps the stored sealing secret.
#[derive(Clone, Debug)]
pub struct PasskeyCustody {
    /// Relying-party id the credential was registered under.
    pub rp_id: String,
    /// The FIDO2 credential id to assert against.
    pub credential_id: Vec<u8>,
    /// The 32-byte `hmac-secret` salt.
    pub prf_salt: [u8; 32],
    /// The sealing secret, AEAD-encrypted under the passkey-derived KEK.
    pub wrapped: Ciphertext,
}

impl NodeCustody for PasskeyCustody {
    fn kind(&self) -> CustodyKind {
        CustodyKind::Passkey
    }
    fn load_sealing_secret(&self) -> Result<SealingSecretKey> {
        // Fail closed on misconfiguration before touching the authenticator.
        if self.credential_id.is_empty() {
            return Err(CryptoError::Backend("passkey: no credential id".into()));
        }

        #[cfg(not(feature = "passkey"))]
        {
            Err(CryptoError::Backend(
                "passkey: FIDO2 custody support was not compiled in (build with the \"passkey\" \
                 feature)"
                    .into(),
            ))
        }

        #[cfg(feature = "passkey")]
        {
            use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension;
            use ctap_hid_fido2::fidokey::GetAssertionArgsBuilder;
            use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

            let device = FidoKeyHidFactory::create(&Cfg::init())
                .map_err(|e| backend_err("passkey: open authenticator", e))?;

            // The assertion challenge only needs to be present; we consume the
            // hmac-secret output, not the signature, so a domain-bound
            // deterministic challenge avoids pulling in an RNG while staying
            // credential-specific.
            let challenge = hkdf32(
                b"pillar-crypto/custody/passkey/challenge-v1",
                &self.credential_id,
                &self.prf_salt,
            );

            let args = GetAssertionArgsBuilder::new(&self.rp_id, &challenge)
                .credential_id(&self.credential_id)
                .extensions(&[Extension::HmacSecret(Some(self.prf_salt))])
                .build();
            let assertions = device
                .get_assertion_with_args(&args)
                .map_err(|e| backend_err("passkey: get assertion", e))?;

            let output = assertions
                .iter()
                .flat_map(|a| a.extensions.iter())
                .find_map(|e| match e {
                    Extension::HmacSecret(Some(o)) => Some(*o),
                    _ => None,
                })
                .ok_or_else(|| CryptoError::Backend("passkey: no hmac-secret output".into()))?;

            let kek = hkdf32(
                b"pillar-crypto/custody/passkey/kek-v1",
                &self.prf_salt,
                &output,
            );
            unwrap_with_kek(kek, &self.wrapped)
        }
    }
}

/// Which asymmetric mechanism the PKCS#11 token uses to unwrap the sealing
/// secret. The operator wraps the sealing secret to the token's public key with
/// the matching mechanism; the token decrypts with the private key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pkcs11Mechanism {
    /// RSAES-OAEP with SHA-256 (`CKM_RSA_PKCS_OAEP`). Preferred.
    RsaOaepSha256,
    /// RSAES-PKCS1-v1_5 (`CKM_RSA_PKCS`). For tokens without OAEP support.
    RsaPkcs1v15,
}

/// Node key held by a PKCS#11 HSM / smart card (`cryptoki`).
///
/// The sealing secret is wrapped to a key that lives inside the token; the
/// token decrypts it on demand and the private key never leaves the device.
#[derive(Clone, Debug)]
pub struct Pkcs11Custody {
    /// Filesystem path to the PKCS#11 provider module (`.so`).
    pub module_path: String,
    /// User PIN authorising private-key use.
    pub pin: Vec<u8>,
    /// Select the token by label; `None` ⇒ first slot with a present token.
    pub token_label: Option<String>,
    /// `CKA_LABEL` of the decrypting private key object.
    pub key_label: Vec<u8>,
    /// Unwrap mechanism the wrapped secret was produced with.
    pub mechanism: Pkcs11Mechanism,
    /// The sealing secret, encrypted to the token's public key.
    pub wrapped: Vec<u8>,
}

impl NodeCustody for Pkcs11Custody {
    fn kind(&self) -> CustodyKind {
        CustodyKind::Pkcs11
    }
    fn load_sealing_secret(&self) -> Result<SealingSecretKey> {
        // Fail closed on misconfiguration before touching the token.
        if self.module_path.is_empty() {
            return Err(CryptoError::Backend("pkcs11: empty module path".into()));
        }
        if self.wrapped.is_empty() {
            return Err(CryptoError::Backend("pkcs11: empty wrapped secret".into()));
        }

        #[cfg(not(feature = "pkcs11"))]
        {
            Err(CryptoError::Backend(
                "pkcs11: PKCS#11 custody support was not compiled in (build with the \"pkcs11\" \
                 feature)"
                    .into(),
            ))
        }

        #[cfg(feature = "pkcs11")]
        {
            use cryptoki::context::{CInitializeArgs, Pkcs11};
            use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
            use cryptoki::mechanism::{Mechanism, MechanismType};
            use cryptoki::object::Attribute;
            use cryptoki::session::UserType;
            use cryptoki::types::AuthPin;

            let pkcs11 = Pkcs11::new(&self.module_path)
                .map_err(|e| backend_err("pkcs11: load module", e))?;
            pkcs11
                .initialize(CInitializeArgs::OsThreads)
                .map_err(|e| backend_err("pkcs11: initialize", e))?;

            let slots = pkcs11
                .get_slots_with_token()
                .map_err(|e| backend_err("pkcs11: slots", e))?;
            let slot = match &self.token_label {
                None => *slots
                    .first()
                    .ok_or_else(|| CryptoError::Backend("pkcs11: no token present".into()))?,
                Some(label) => {
                    let mut found = None;
                    for s in slots {
                        if let Ok(info) = pkcs11.get_token_info(s) {
                            if info.label().trim_end() == label {
                                found = Some(s);
                                break;
                            }
                        }
                    }
                    found.ok_or_else(|| {
                        CryptoError::Backend(format!("pkcs11: no token labelled {label:?}"))
                    })?
                }
            };

            let session = pkcs11
                .open_ro_session(slot)
                .map_err(|e| backend_err("pkcs11: open session", e))?;
            let pin = AuthPin::new(
                String::from_utf8(self.pin.clone())
                    .map_err(|e| backend_err("pkcs11: pin encoding", e))?,
            );
            session
                .login(UserType::User, Some(&pin))
                .map_err(|e| backend_err("pkcs11: login", e))?;

            let key = session
                .find_objects(&[
                    Attribute::Label(self.key_label.clone()),
                    Attribute::Decrypt(true),
                ])
                .map_err(|e| backend_err("pkcs11: find key", e))?
                .into_iter()
                .next()
                .ok_or_else(|| CryptoError::Backend("pkcs11: decrypting key not found".into()))?;

            let mechanism = match self.mechanism {
                Pkcs11Mechanism::RsaOaepSha256 => Mechanism::RsaPkcsOaep(PkcsOaepParams::new(
                    MechanismType::SHA256,
                    PkcsMgfType::MGF1_SHA256,
                    PkcsOaepSource::empty(),
                )),
                Pkcs11Mechanism::RsaPkcs1v15 => Mechanism::RsaPkcs,
            };

            let secret = session
                .decrypt(&mechanism, key, &self.wrapped)
                .map_err(|e| backend_err("pkcs11: decrypt", e))?;
            Ok(SealingSecretKey::from_bytes(secret))
        }
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
    /// See [`Pkcs11Custody`].
    Pkcs11(Pkcs11Custody),
}

impl NodeCustody for Custody {
    fn kind(&self) -> CustodyKind {
        match self {
            Custody::Unencrypted(b) => b.kind(),
            Custody::Password(b) => b.kind(),
            Custody::Tpm(b) => b.kind(),
            Custody::Passkey(b) => b.kind(),
            Custody::Pkcs11(b) => b.kind(),
        }
    }
    fn load_sealing_secret(&self) -> Result<SealingSecretKey> {
        match self {
            Custody::Unencrypted(b) => b.load_sealing_secret(),
            Custody::Password(b) => b.load_sealing_secret(),
            Custody::Tpm(b) => b.load_sealing_secret(),
            Custody::Passkey(b) => b.load_sealing_secret(),
            Custody::Pkcs11(b) => b.load_sealing_secret(),
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
        assert_eq!(
            Custody::Unencrypted(UnencryptedCustody::new(secret)).kind(),
            CustodyKind::Unencrypted
        );
        assert_eq!(
            Custody::Tpm(TpmCustody {
                tcti: String::new(),
                parent_handle: 0x8100_0001,
                sealed_public: b"pub".to_vec(),
                sealed_private: b"priv".to_vec(),
                auth: Vec::new(),
            })
            .kind(),
            CustodyKind::Tpm
        );
        assert_eq!(
            Custody::Pkcs11(Pkcs11Custody {
                module_path: "/usr/lib/softhsm/libsofthsm2.so".into(),
                pin: b"1234".to_vec(),
                token_label: None,
                key_label: b"pillar-node".to_vec(),
                mechanism: Pkcs11Mechanism::RsaOaepSha256,
                wrapped: b"ct".to_vec(),
            })
            .kind(),
            CustodyKind::Pkcs11
        );
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
        // backend recovers it. Chains kdf + aead + custody.
        let params = KdfParams::default();
        let salt = Salt::from_bytes(b"node-custody-salt".to_vec());
        let password = b"node restart passphrase";
        let secret = SealingSecretKey::from_bytes(b"the-node-x25519-sealing-secret!!".to_vec());

        let kek = derive_key(password, &salt, &params).expect("kdf");
        let wrapped = seal_symmetric(&kek, secret.as_bytes(), CUSTODY_AAD).expect("wrap");

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

    // ---- The CI-testable half of the hardware backends ----

    #[test]
    fn hardware_kek_unwrap_roundtrips_and_rejects_a_wrong_kek() {
        // This is the pure step the passkey / HSM backends run once the device
        // has released a key-encryption key. A real AEAD: the right KEK recovers
        // the secret, a wrong KEK fails the tag (fail-closed, never a bogus key).
        let kek = hkdf32(b"test/kek", b"salt", b"released-hardware-secret");
        let secret = SealingSecretKey::from_bytes(b"the-node-x25519-sealing-secret!!".to_vec());
        let wrapped = seal_symmetric(
            &SymmetricKey::from_bytes(kek.to_vec()),
            secret.as_bytes(),
            CUSTODY_AAD,
        )
        .expect("wrap under kek");

        assert_eq!(
            unwrap_with_kek(kek, &wrapped),
            Ok(secret),
            "the correct hardware-released KEK recovers the sealing secret"
        );

        let wrong = hkdf32(b"test/kek", b"salt", b"a-different-hardware-secret");
        assert!(
            unwrap_with_kek(wrong, &wrapped).is_err(),
            "a wrong KEK must fail the AEAD tag, not yield a bogus secret"
        );
    }

    // ---- Fail-closed: misconfigured hardware backends never yield a secret ----
    // These return before any device I/O, so they are deterministic in CI. The
    // on-device success paths are validated by the operator on real hardware.

    #[test]
    fn tpm_custody_fails_closed_on_empty_sealed_object() {
        let backend = TpmCustody {
            tcti: "device:/dev/tpmrm0".into(),
            parent_handle: 0x8100_0001,
            sealed_public: Vec::new(),
            sealed_private: Vec::new(),
            auth: Vec::new(),
        };
        assert!(
            matches!(backend.load_sealing_secret(), Err(CryptoError::Backend(_))),
            "an unconfigured TPM object must fail closed, never return a secret"
        );
    }

    #[test]
    fn passkey_custody_fails_closed_without_a_credential() {
        let backend = PasskeyCustody {
            rp_id: "pillar.example.com".into(),
            credential_id: Vec::new(),
            prf_salt: [0u8; 32],
            wrapped: Ciphertext::from_bytes(b"ct".to_vec()),
        };
        assert!(
            matches!(backend.load_sealing_secret(), Err(CryptoError::Backend(_))),
            "a passkey backend with no credential must fail closed"
        );
    }

    #[test]
    fn pkcs11_custody_fails_closed_on_empty_module_or_secret() {
        let no_module = Pkcs11Custody {
            module_path: String::new(),
            pin: b"1234".to_vec(),
            token_label: None,
            key_label: b"pillar-node".to_vec(),
            mechanism: Pkcs11Mechanism::RsaOaepSha256,
            wrapped: b"ct".to_vec(),
        };
        assert!(matches!(
            no_module.load_sealing_secret(),
            Err(CryptoError::Backend(_))
        ));

        let no_ct = Pkcs11Custody {
            module_path: "/usr/lib/softhsm/libsofthsm2.so".into(),
            pin: b"1234".to_vec(),
            token_label: None,
            key_label: b"pillar-node".to_vec(),
            mechanism: Pkcs11Mechanism::RsaPkcs1v15,
            wrapped: Vec::new(),
        };
        assert!(matches!(
            no_ct.load_sealing_secret(),
            Err(CryptoError::Backend(_))
        ));
    }
}
