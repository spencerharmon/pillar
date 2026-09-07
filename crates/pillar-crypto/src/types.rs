//! Opaque, algorithm-agnostic types for keys, ciphertext, and parameters.
//!
//! Every key/data type is a thin newtype over `Vec<u8>`: the interface fixes
//! *what* each value means, not *how* it is encoded, so the concrete algorithm
//! can change without touching call sites.

/// Generates an opaque byte-container newtype with a uniform accessor surface.
macro_rules! bytes_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
        pub struct $name(Vec<u8>);

        impl $name {
            /// Wrap raw bytes.
            pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
                Self(bytes.into())
            }
            /// Borrow the raw bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
            /// Consume into the raw bytes.
            pub fn into_bytes(self) -> Vec<u8> {
                self.0
            }
            /// Length in bytes.
            pub fn len(&self) -> usize {
                self.0.len()
            }
            /// True when there are no bytes.
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }
    };
}

bytes_newtype!(
    /// A low-entropy human secret (password / passphrase). Never persisted; fed
    /// through [`crate::kdf::derive_key`] to obtain a symmetric key.
    Password
);
bytes_newtype!(
    /// A KDF salt (per-credential, stored alongside the ciphertext).
    Salt
);
bytes_newtype!(
    /// A symmetric key (AEAD / KDF output).
    SymmetricKey
);
bytes_newtype!(
    /// AEAD ciphertext (nonce + ciphertext + tag, encoding is algorithm-defined).
    Ciphertext
);
bytes_newtype!(
    /// A signature public (verifying) key.
    SigningPublicKey
);
bytes_newtype!(
    /// A signature secret (signing) key.
    SigningSecretKey
);
bytes_newtype!(
    /// A detached signature.
    Signature
);
bytes_newtype!(
    /// A recipient public (sealing) key — identifies a node or a cell that an
    /// artifact may be sealed to.
    SealingPublicKey
);
bytes_newtype!(
    /// A recipient secret (unsealing) key — held by a node (see [`crate::custody`])
    /// or a cell.
    SealingSecretKey
);
bytes_newtype!(
    /// A sealed multi-recipient envelope produced by [`crate::seal::seal_to_recipients`].
    SealedEnvelope
);
bytes_newtype!(
    /// A collision-resistant content address (multihash bytes) produced by
    /// [`crate::content::content_address`].
    ContentId
);
bytes_newtype!(
    /// A cell identifier. Binds a user subkey certificate to the cell it is
    /// valid in (see [`crate::user::certify_subkey`]).
    CellId
);
bytes_newtype!(
    /// Deterministic seed material used to derive a keypair in tests and in
    /// reproducible key generation. Real generation may draw from an OS CSPRNG
    /// instead; this exists so keypairs are reproducible from a fixture.
    Seed
);

/// Advisory work parameters for the password KDF. Values are a starting point,
/// not a locked algorithm choice; the implementation picks the concrete KDF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB (memory-hardness).
    pub mem_kib: u32,
    /// Number of iterations / passes.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
    /// Desired output length in bytes.
    pub output_len: usize,
}

impl Default for KdfParams {
    fn default() -> Self {
        // OWASP-ish argon2id starting point; the implementation may tune these.
        Self {
            mem_kib: 19_456,
            iterations: 2,
            parallelism: 1,
            output_len: 32,
        }
    }
}

/// Which AEAD cipher sealed a [`crate::aead`] envelope.
///
/// This is the "algorithm tag" half of the self-describing sealed-artifact
/// contract: [`crate::aead::seal_symmetric`] stamps the producing algorithm's
/// tag as the first byte of the resulting [`Ciphertext`], and
/// [`crate::aead::open_symmetric`] reads that byte back and dispatches to the
/// matching code path — it never assumes the binary's *current* default.
/// Every variant that has ever sealed a real artifact is retained FOREVER
/// (never deleted/renumbered); only [`AeadAlgorithm::current_default`] may
/// change across releases, so an old artifact keeps decrypting under its
/// original algorithm while a newly-sealed one picks up the new default —
/// both are supported simultaneously. An unrecognized tag is rejected
/// ([`crate::error::CryptoError::UnsupportedAlgorithm`]), never silently
/// treated as the current default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadAlgorithm {
    /// ChaCha20-Poly1305 with a 12-byte random nonce. The original algorithm;
    /// retained forever for artifacts sealed before the default flipped.
    ChaCha20Poly1305V1,
    /// XChaCha20-Poly1305 with a 24-byte random nonce. Current default: the
    /// extended nonce removes the birthday-bound collision concern of
    /// randomly-generated 96-bit nonces under high-volume sealing.
    XChaCha20Poly1305V1,
}

impl AeadAlgorithm {
    /// The algorithm newly-sealed artifacts use unless a caller pins an
    /// explicit older one (e.g. a test proving old-artifact compatibility).
    /// Bumping this NEVER breaks an artifact sealed under a prior default —
    /// that artifact's own inline tag still routes it to its original code
    /// path.
    pub fn current_default() -> Self {
        AeadAlgorithm::XChaCha20Poly1305V1
    }

    /// The stable on-the-wire tag byte for this algorithm. Never renumbered.
    pub fn tag(self) -> u8 {
        match self {
            AeadAlgorithm::ChaCha20Poly1305V1 => 1,
            AeadAlgorithm::XChaCha20Poly1305V1 => 2,
        }
    }

    /// Recover the algorithm from an inline tag byte.
    ///
    /// Contract: fails closed (never falls back to
    /// [`AeadAlgorithm::current_default`]) on any byte that is not a
    /// previously-shipped tag.
    pub fn from_tag(tag: u8) -> core::result::Result<Self, crate::error::CryptoError> {
        match tag {
            1 => Ok(AeadAlgorithm::ChaCha20Poly1305V1),
            2 => Ok(AeadAlgorithm::XChaCha20Poly1305V1),
            other => Err(crate::error::CryptoError::UnsupportedAlgorithm(other)),
        }
    }
}

/// Which at-rest custody backend protects a node's sealing secret key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyKind {
    /// Plaintext on disk (operator-approved for node keys).
    Unencrypted,
    /// Encrypted under a password the operator types at node restart.
    Password,
    /// Sealed to a TPM (released under a PCR / auth policy).
    Tpm,
    /// Unlocked via a passkey / WebAuthn authenticator (e.g. PRF extension).
    Passkey,
    /// Held by a PKCS#11 hardware security module / smart card (YubiHSM,
    /// Nitrokey HSM, SoftHSM, cloud HSM, PIV smart card, …): the HSM decrypts
    /// the wrapped sealing secret with a key that never leaves the device.
    Pkcs11,
}
