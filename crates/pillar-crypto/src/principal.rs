//! The shared principal-key infrastructure every role reuses.
//!
//! A **node**, a **cell**, a **user master**, and a **user's per-cell subkey**
//! all carry exactly the same shape: a signing (identity) keypair and a sealing
//! (recipient) keypair. Generating all of them through [`principal_from_seed`]
//! is what lets the roles share one implementation instead of three parallel
//! ones — the difference between roles is how the keys are *used* (see
//! [`crate::node`], [`crate::cell`], [`crate::user`]), not how they are built.

use crate::error::Result;
use crate::types::{SealingPublicKey, SealingSecretKey, Seed, SigningPublicKey, SigningSecretKey};

/// Public key material shared by every principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalPublic {
    /// Identity / verification key (signs and verifies messages, certs, events).
    pub signing: SigningPublicKey,
    /// Recipient key (artifacts are sealed *to* this).
    pub sealing: SealingPublicKey,
}

/// Secret counterpart to [`PrincipalPublic`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalSecret {
    /// Signing secret (never leaves the holder; for a user it is the
    /// argon2id-encrypted-then-sealed private key).
    pub signing: SigningSecretKey,
    /// Sealing secret (unseals artifacts sealed to this principal; for a node it
    /// is protected at rest by [`crate::custody`]).
    pub sealing: SealingSecretKey,
}

/// Derive a principal keypair from seed material.
///
/// Contract: deterministic in `seed`; distinct seeds yield distinct principals;
/// the signing and sealing halves are independently domain-separated from the
/// one seed. Real generation may draw the seed from an OS CSPRNG. This one
/// function is the shared keygen for nodes, cells, users, and subkeys.
pub fn principal_from_seed(seed: &Seed) -> Result<(PrincipalPublic, PrincipalSecret)> {
    // One seed, one keygen: the signing (ed25519) and sealing (x25519) halves
    // are independently domain-separated from the SAME seed, so a node, a cell,
    // a user master, and a per-cell subkey all build through this one function.
    let (sign_pub, sign_sec) = crate::sign::signing_keypair_from_seed(seed)?;
    let (seal_pub, seal_sec) = crate::seal::sealing_keypair_from_seed(seed)?;
    Ok((
        PrincipalPublic {
            signing: sign_pub,
            sealing: seal_pub,
        },
        PrincipalSecret {
            signing: sign_sec,
            sealing: seal_sec,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(label: &str) -> Seed {
        Seed::from_bytes(format!("pillar-principal-seed::{label}").into_bytes())
    }

    #[test]
    fn principal_generation_is_deterministic_and_distinct() {
        let (pub_a, sec_a) = principal_from_seed(&seed("node-1")).expect("keygen");
        let (pub_a2, sec_a2) = principal_from_seed(&seed("node-1")).expect("keygen");
        assert_eq!(pub_a, pub_a2, "same seed -> same principal (public)");
        assert_eq!(sec_a, sec_a2, "same seed -> same principal (secret)");

        let (pub_b, _) = principal_from_seed(&seed("node-2")).expect("keygen");
        assert_ne!(pub_a, pub_b, "distinct seeds -> distinct principals");
        assert_ne!(
            pub_a.signing.as_bytes(),
            pub_a.sealing.as_bytes(),
            "signing and sealing halves must be distinct key material"
        );
    }
}
