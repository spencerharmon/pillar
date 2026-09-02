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
}
