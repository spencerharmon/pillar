//! # pillar-crypto
//!
//! The factored set of cryptographic operations pillar depends on, in one
//! place, so that no other crate rolls its own primitive or falls back to a
//! non-cryptographic stand-in (a `DefaultHasher` KDF, an FNV content address,
//! an XOR "seal"). The operations, and the pillar model they serve:
//!
//! * [`kdf`] — memory-hard password → key derivation. Turns a user's password
//!   into the symmetric key that encrypts their private key (the "argon2id-
//!   encrypted private key").
//! * [`aead`] — authenticated symmetric encryption. Encrypts the user's
//!   private key under the [`kdf`] output; also the bulk-data cipher.
//! * [`sign`] — asymmetric signatures. The user's private key signs a login
//!   nonce; verification uses only the WoT-registered public key. Also event
//!   authorship and trust attestations.
//! * [`seal`] — public-key recipient sealing. The argon2id-encrypted private
//!   key is sealed to a set of recipient public keys — **nodes and cells** —
//!   and only a holder of a recipient's secret key can unseal it.
//! * [`content`] — collision-resistant content addressing (multihash) for the
//!   streaming DB / CIDs.
//! * [`custody`] — how a **node** holds the secret key it unseals with, at
//!   rest: `unencrypted`, `password`, `tpm`, or `passkey`.
//!
//! ## Algorithms are NOT fixed here
//!
//! The types are opaque byte containers and the parameters are advisory. The
//! concrete algorithms (argon2id vs scrypt, ed25519 vs another curve, X25519
//! sealed-box vs HPKE, sha256 vs blake3) are deliberately left open so we can
//! change them later. What is fixed is the **contract**: the behaviors the
//! module-level unit tests assert.
//!
//! ## Every operation is `NotImplemented` — on purpose
//!
//! Each function returns [`CryptoError::NotImplemented`] today. The unit tests
//! feed contrived fixtures through the real signatures and assert the contract
//! (a signature verifies and rejects tampering; a non-recipient cannot unseal;
//! a wrong password yields a different key; a content address is deterministic,
//! distinct, and wide). They are RED until a real implementation lands, which
//! is the whole point: the tests — not a source grep — force compliance.

mod error;
mod types;

pub mod aead;
pub mod cell;
pub mod content;
pub mod custody;
pub mod kdf;
pub mod node;
pub mod principal;
pub mod seal;
pub mod sign;
pub mod user;

pub use error::{CryptoError, Result};
pub use principal::{PrincipalPublic, PrincipalSecret};
pub use types::{
    Ciphertext, CellId, ContentId, CustodyKind, KdfParams, Password, Salt, SealedEnvelope,
    SealingPublicKey, SealingSecretKey, Seed, Signature, SigningPublicKey, SigningSecretKey,
    SymmetricKey,
};
