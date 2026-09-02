//! Error type shared by every pillar cryptographic operation.

use crate::types::CustodyKind;
use core::fmt;

/// Result alias for cryptographic operations.
pub type Result<T> = core::result::Result<T, CryptoError>;

/// Failure modes for the factored cryptographic operations.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The operation is defined but not yet implemented. Every function in this
    /// crate starts here; the contract tests fail until a real implementation
    /// replaces it. This is the forcing gate against placeholder cryptography.
    /// The `&'static str` names the operation (e.g. `"sign::verify"`).
    NotImplemented(&'static str),
    /// Supplied key material was malformed or the wrong length for the chosen
    /// algorithm.
    InvalidKey,
    /// An input had an invalid length.
    InvalidLength,
    /// A signature did not verify against the given public key and message.
    VerificationFailed,
    /// AEAD decryption failed: wrong key, wrong associated data, or tampered
    /// ciphertext (indistinguishable on purpose).
    DecryptionFailed,
    /// The supplied secret key is not one of the envelope's recipients.
    NotARecipient,
    /// The requested custody backend is unsupported in this build or on this
    /// platform.
    UnsupportedCustody(CustodyKind),
    /// A custody or hardware backend (TPM, passkey authenticator, …) reported an
    /// error.
    Backend(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::NotImplemented(op) => {
                write!(f, "cryptographic operation not implemented: {op}")
            }
            CryptoError::InvalidKey => write!(f, "invalid key material"),
            CryptoError::InvalidLength => write!(f, "invalid input length"),
            CryptoError::VerificationFailed => write!(f, "signature verification failed"),
            CryptoError::DecryptionFailed => write!(f, "decryption failed"),
            CryptoError::NotARecipient => {
                write!(f, "secret key is not a recipient of this envelope")
            }
            CryptoError::UnsupportedCustody(k) => write!(f, "unsupported custody backend: {k:?}"),
            CryptoError::Backend(msg) => write!(f, "custody/hardware backend error: {msg}"),
        }
    }
}

impl std::error::Error for CryptoError {}
