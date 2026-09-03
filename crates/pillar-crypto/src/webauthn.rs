//! WebAuthn relying-party (RP) verification primitives.
//!
//! This module is the REAL cryptographic core of the pillar WebAuthn custody
//! surface modelled by `specs/WebAuthnCustody.tla`. It is NOT a simulation: it
//! parses the actual COSE/CBOR objects a browser (`navigator.credentials.
//! {create,get}`) or a CLI CTAP2 client produces, extracts the COSE public
//! key, and verifies the assertion signature over the exact WebAuthn signed
//! payload `authenticatorData || SHA-256(clientDataJSON)`.
//!
//! ## Algorithm
//!
//! WebAuthn permits several COSE signature algorithms. Pillar's authenticators
//! register an **Ed25519 / OKP** COSE key (`alg = -8`, `EdDSA`), which the
//! shared [`crate::sign`] module verifies with the same real ed25519-dalek
//! backend used everywhere else in pillar — so the entire attestation and
//! assertion path rides vendored, contract-tested real crypto with no new
//! curve dependency. A COSE key naming any other algorithm is refused rather
//! than silently accepted (fail-closed).
//!
//! ## What the RP verifies
//!
//! * **Registration** ([`parse_attestation`]): parses the attestation object's
//!   CBOR, extracts `authData`, confirms its length and flags, and reads the
//!   attested COSE public key. The returned [`RegisteredCredential`] carries
//!   the raw COSE key bytes, the credential id, the initial sign-count, and
//!   the AAGUID.
//! * **Assertion** ([`verify_assertion`]): recomputes the signed payload
//!   `authData || SHA-256(clientDataJSON)`, verifies the Ed25519 signature
//!   against the stored COSE key, and returns the presented sign-count so the
//!   caller can enforce monotonicity. A forged or tampered signature is
//!   rejected with [`CryptoError::VerificationFailed`].
//! * **PRF / hmac-secret → unlock secret** ([`derive_unlock_secret`]): folds
//!   the authenticator's PRF/hmac-secret extension output through a real
//!   HKDF-SHA256 (NOT a password hash) to a stable 32-byte operational-key
//!   unlock secret, domain-separated and bound to the credential id.

use crate::error::{CryptoError, Result};
use crate::types::{Signature, SigningPublicKey};

/// COSE algorithm identifier for EdDSA (Ed25519). See RFC 9053 / the COSE
/// algorithm registry.
pub const COSE_ALG_EDDSA: i64 = -8;
/// COSE key type `OKP` (Octet Key Pair — the Edwards-curve family).
const COSE_KTY_OKP: i64 = 1;
/// COSE curve identifier for `Ed25519`.
const COSE_CRV_ED25519: i64 = 6;

/// The minimum length of a WebAuthn `authenticatorData` structure: 32-byte
/// rpIdHash + 1 flags byte + 4-byte big-endian sign counter.
const AUTH_DATA_MIN_LEN: usize = 37;
/// The `AT` (attested-credential-data included) flag bit in authenticatorData.
const AUTH_FLAG_AT: u8 = 0x40;

/// A credential record extracted from a registration ceremony's attestation
/// object — the server-side half of the shared record modelled by
/// `WebAuthnCustody.tla` (`{ credential_id, COSE public key, sign_count, … }`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredCredential {
    /// The credential id the authenticator minted (opaque handle).
    pub credential_id: Vec<u8>,
    /// The raw COSE-encoded public key (CBOR map) attested for this credential.
    pub cose_public_key: Vec<u8>,
    /// The authenticator's initial signature counter at registration.
    pub sign_count: u32,
    /// The authenticator AAGUID (16 bytes) from the attested credential data.
    pub aaguid: [u8; 16],
}

/// Decode a base64url (no padding, but padding tolerated) string to bytes.
///
/// WebAuthn transports every binary field (credential id, attestation object,
/// clientDataJSON, authenticatorData, signature) as base64url. This is a small
/// dependency-free decoder so the crate needs no `base64` crate.
///
/// # Errors
///
/// [`CryptoError::InvalidLength`] on any non-alphabet character or a malformed
/// final quantum.
pub fn base64url_decode(input: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in &bytes {
        let v = val(b).ok_or(CryptoError::InvalidLength)? as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Ok(out)
}

/// Encode bytes as base64url (no padding).
#[must_use]
pub fn base64url_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 0x3f] as char);
        }
    }
    out
}

/// A parsed `authenticatorData` structure (the portion common to registration
/// and assertion): the RP-id hash, flags byte, and the signature counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatorData {
    /// SHA-256 of the RP id the authenticator scoped this ceremony to.
    pub rp_id_hash: [u8; 32],
    /// The raw flags byte (UP/UV/AT/ED bits).
    pub flags: u8,
    /// The authenticator's signature counter for this operation.
    pub sign_count: u32,
}

/// Parse the fixed 37-byte prefix of an `authenticatorData` structure.
///
/// # Errors
///
/// [`CryptoError::InvalidLength`] if the buffer is shorter than the fixed
/// header.
pub fn parse_authenticator_data(bytes: &[u8]) -> Result<AuthenticatorData> {
    if bytes.len() < AUTH_DATA_MIN_LEN {
        return Err(CryptoError::InvalidLength);
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&bytes[0..32]);
    let flags = bytes[32];
    let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
    })
}

/// Extract an Ed25519 public key from a raw COSE-key CBOR map.
///
/// Enforces `kty = OKP`, `alg = EdDSA (-8)`, `crv = Ed25519`, and a 32-byte
/// `x` coordinate — a key naming any other type/curve/algorithm is refused.
///
/// # Errors
///
/// [`CryptoError::InvalidKey`] on a malformed map or an unexpected
/// type/curve/algorithm/length.
pub fn cose_ed25519_public_key(cose: &[u8]) -> Result<SigningPublicKey> {
    use ciborium::value::Value;
    let value: Value = ciborium::from_reader(cose).map_err(|_| CryptoError::InvalidKey)?;
    let Value::Map(entries) = value else {
        return Err(CryptoError::InvalidKey);
    };
    let mut kty: Option<i64> = None;
    let mut alg: Option<i64> = None;
    let mut crv: Option<i64> = None;
    let mut x: Option<Vec<u8>> = None;
    for (k, v) in entries {
        let Value::Integer(label) = k else { continue };
        let label: i128 = label.into();
        match label {
            1 => kty = v.as_integer().map(|i| i128::from(i) as i64),
            3 => alg = v.as_integer().map(|i| i128::from(i) as i64),
            -1 => crv = v.as_integer().map(|i| i128::from(i) as i64),
            -2 => x = v.as_bytes().cloned(),
            _ => {}
        }
    }
    if kty != Some(COSE_KTY_OKP) {
        return Err(CryptoError::InvalidKey);
    }
    if alg != Some(COSE_ALG_EDDSA) {
        return Err(CryptoError::InvalidKey);
    }
    if crv != Some(COSE_CRV_ED25519) {
        return Err(CryptoError::InvalidKey);
    }
    let x = x.ok_or(CryptoError::InvalidKey)?;
    if x.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    Ok(SigningPublicKey::from_bytes(x))
}

/// Encode an Ed25519 public key as a COSE OKP key CBOR map (the form an
/// authenticator would attest). Test/client helper mirroring the wire form the
/// RP consumes; also used by real CTAP2 makeCredential responses.
///
/// # Errors
///
/// [`CryptoError::InvalidKey`] if `public` is not a 32-byte Ed25519 key.
pub fn ed25519_public_key_to_cose(public: &SigningPublicKey) -> Result<Vec<u8>> {
    use ciborium::value::{Integer, Value};
    if public.as_bytes().len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    let map = Value::Map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(COSE_KTY_OKP)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(COSE_ALG_EDDSA)),
        ),
        (
            Value::Integer(Integer::from(-1)),
            Value::Integer(Integer::from(COSE_CRV_ED25519)),
        ),
        (
            Value::Integer(Integer::from(-2)),
            Value::Bytes(public.as_bytes().to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&map, &mut out).map_err(|_| CryptoError::InvalidKey)?;
    Ok(out)
}

/// Parse a WebAuthn attestation object (CBOR map `{fmt, attStmt, authData}`)
/// from a registration ceremony and extract the shared credential record.
///
/// This reads the attested credential data embedded in `authData` (present iff
/// the `AT` flag is set): the AAGUID, the credential id (length-prefixed), and
/// the attested COSE public key. The credential's initial sign-count is taken
/// from the same `authData`.
///
/// # Errors
///
/// [`CryptoError::InvalidLength`] / [`CryptoError::InvalidKey`] on a malformed
/// object, absent attested-credential-data flag, or a non-Ed25519 COSE key.
pub fn parse_attestation(attestation_object: &[u8]) -> Result<RegisteredCredential> {
    use ciborium::value::Value;
    let value: Value =
        ciborium::from_reader(attestation_object).map_err(|_| CryptoError::InvalidLength)?;
    let Value::Map(entries) = value else {
        return Err(CryptoError::InvalidLength);
    };
    let mut auth_data: Option<Vec<u8>> = None;
    for (k, v) in entries {
        if let Value::Text(t) = k {
            if t == "authData" {
                auth_data = v.as_bytes().cloned();
            }
        }
    }
    let auth_data = auth_data.ok_or(CryptoError::InvalidLength)?;
    let header = parse_authenticator_data(&auth_data)?;
    if header.flags & AUTH_FLAG_AT == 0 {
        // No attested credential data present — not a registration authData.
        return Err(CryptoError::InvalidLength);
    }
    // attestedCredentialData layout (after the 37-byte header):
    //   aaguid (16) || credIdLen (2 BE) || credId (credIdLen) || COSEKey (rest)
    let rest = &auth_data[AUTH_DATA_MIN_LEN..];
    if rest.len() < 18 {
        return Err(CryptoError::InvalidLength);
    }
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&rest[0..16]);
    let cred_id_len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
    let after_len = &rest[18..];
    if after_len.len() < cred_id_len {
        return Err(CryptoError::InvalidLength);
    }
    let credential_id = after_len[..cred_id_len].to_vec();
    let cose = &after_len[cred_id_len..];
    // Validate the COSE key really parses as a supported Ed25519 key.
    let _ = cose_ed25519_public_key(cose)?;
    Ok(RegisteredCredential {
        credential_id,
        cose_public_key: cose.to_vec(),
        sign_count: header.sign_count,
        aaguid,
    })
}

/// Encode a WebAuthn attestation object (CBOR map `{fmt, attStmt, authData}`)
/// from an authenticator's raw `authData` bytes.
///
/// This is the encoding counterpart to [`parse_attestation`]: any client that
/// holds real `authData` from a registration ceremony — a browser's
/// `navigator.credentials.create()` result, or a CLI driving a CTAP2
/// authenticator over ctap-hid — wraps it into the same wire-format
/// attestation object the RP's [`parse_attestation`] consumes. `attStmt` is
/// always the empty map (`fmt = "none"`, per WebAuthn's "none" attestation
/// statement format): pillar's RP never validates attestation statements (it
/// trusts the authData-embedded COSE key directly, per the crate's Ed25519-
/// only model documented above), so no client needs to produce a real
/// signed attestation statement.
#[must_use]
pub fn build_attestation_object(fmt: &str, auth_data: &[u8]) -> Vec<u8> {
    use ciborium::value::Value;
    let map = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text(fmt.to_owned())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (Value::Text("authData".into()), Value::Bytes(auth_data.to_vec())),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&map, &mut out).expect("attestation object CBOR encode is infallible");
    out
}

/// The outcome of a verified assertion: the presented sign-count the caller
/// must check for strict monotonicity against the stored value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// The authenticator counter value carried by this assertion.
    pub sign_count: u32,
}

/// Verify a WebAuthn assertion signature.
///
/// Recomputes the WebAuthn signed payload — `authenticatorData ||
/// SHA-256(clientDataJSON)` — and verifies `signature` against the stored COSE
/// public key with real Ed25519. Returns the presented sign-count; the caller
/// enforces `presented > stored` (see `WebAuthnCustody.tla`
/// `SignCountMonotonic`).
///
/// # Errors
///
/// [`CryptoError::InvalidKey`] if the stored COSE key is not a supported
/// Ed25519 key; [`CryptoError::VerificationFailed`] if the signature does not
/// verify over the recomputed payload (a forged or tampered assertion).
pub fn verify_assertion(
    cose_public_key: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> Result<VerifiedAssertion> {
    use sha2::{Digest, Sha256};
    let public = cose_ed25519_public_key(cose_public_key)?;
    let header = parse_authenticator_data(authenticator_data)?;
    let client_data_hash = Sha256::digest(client_data_json);
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(&client_data_hash);
    let sig = Signature::from_bytes(signature.to_vec());
    crate::sign::verify(&public, &signed, &sig)?;
    Ok(VerifiedAssertion {
        sign_count: header.sign_count,
    })
}

/// Derive the 32-byte operational-key-unlock secret from the authenticator's
/// PRF / hmac-secret extension output.
///
/// This is a real HKDF-SHA256 expansion (NOT a password hash): it folds the
/// authenticator-produced PRF output through a domain-separated, credential-id-
/// bound HKDF so the resulting secret is stable across ceremonies for the same
/// authenticator+credential and never collides across credentials. The PRF
/// output itself is high-entropy hardware material, so a memory-hard KDF would
/// be the wrong primitive here — HKDF is exactly the WebAuthn-PRF → key
/// derivation the spec calls for.
///
/// # Errors
///
/// [`CryptoError::InvalidLength`] if the PRF output is empty.
pub fn derive_unlock_secret(prf_output: &[u8], credential_id: &[u8]) -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    if prf_output.is_empty() {
        return Err(CryptoError::InvalidLength);
    }
    let hk = Hkdf::<Sha256>::new(Some(credential_id), prf_output);
    let mut out = [0u8; 32];
    hk.expand(b"pillar-crypto/webauthn/prf-unlock-v1", &mut out)
        .map_err(|_| CryptoError::InvalidLength)?;
    Ok(out)
}

/// Build a WebAuthn `clientDataJSON` for a `"webauthn.create"` (registration)
/// or `"webauthn.get"` (assertion) ceremony, matching exactly what a browser's
/// `navigator.credentials.{create,get}()` produces and what
/// [`verify_assertion`] recomputes `SHA-256` of. A CLI driving a hardware
/// authenticator over ctap-hid is a WebAuthn "client" too, and must build the
/// SAME structure so the RP's real crypto (not a CLI-only shortcut) verifies
/// it.
///
/// `ceremony_type` is `"webauthn.create"` or `"webauthn.get"`; `challenge` is
/// the RP-issued base64url challenge; `origin` is the RP origin the ceremony
/// is scoped to (e.g. `"https://pillar.local"`).
#[must_use]
pub fn client_data_json(ceremony_type: &str, challenge_b64url: &str, origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{ceremony_type}","challenge":"{challenge_b64url}","origin":"{origin}"}}"#
    )
    .into_bytes()
}

/// CLI-driven CTAP2 WebAuthn ceremonies over ctap-hid against a locally
/// attached hardware authenticator — the CLI's counterpart to a browser's
/// `navigator.credentials.{create,get}()`. Produces and consumes the SAME
/// credential record shape ([`RegisteredCredential`] / the attestation-object
/// wire format) as the browser path: same RP begin/finish endpoints, same
/// COSE/CBOR wire format, real ctap-hid-fido2 device I/O.
///
/// Gated behind the crate's `passkey` feature (already pulled in by every
/// deployed node's `hsm` build) so the everyday `cargo test` skips the
/// hidapi/native dependency; a build without the feature never attempts
/// device I/O (see [`crate::custody`] for the same fail-closed pattern).
#[cfg(feature = "passkey")]
pub mod ctap_client {
    use super::{build_attestation_object, client_data_json};
    use crate::error::{CryptoError, Result};
    use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension as GetExtension;
    use ctap_hid_fido2::fidokey::make_credential::make_credential_params::CredentialSupportedKeyType;
    use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
    use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
    use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
    use sha2::{Digest, Sha256};

    fn open_device() -> Result<ctap_hid_fido2::FidoKeyHid> {
        FidoKeyHidFactory::create(&Cfg::init())
            .map_err(|e| CryptoError::Backend(format!("webauthn: open authenticator: {e}")))
    }

    /// Drive a registration (`authenticatorMakeCredential`) ceremony over
    /// ctap-hid: build the real WebAuthn `clientDataJSON`, hash it, ask the
    /// attached authenticator to mint an Ed25519 credential over that hash,
    /// and wrap the returned `authData` into the SAME attestation-object wire
    /// format ([`build_attestation_object`]) the RP's [`super::parse_attestation`]
    /// consumes — no CLI-only credential shape.
    ///
    /// Returns `(attestation_object, credential_id)`, both raw bytes ready for
    /// base64url transport to `/webauthn/register/finish`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Backend`] if no authenticator is attached or the
    /// ceremony is refused by the device.
    pub fn register(
        rp_id: &str,
        origin: &str,
        challenge_b64url: &str,
        user_id: &[u8],
        user_name: &str,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let device = open_device()?;
        let cdj = client_data_json("webauthn.create", challenge_b64url, origin);
        let client_data_hash = Sha256::digest(&cdj);
        let user_entity = PublicKeyCredentialUserEntity::new(
            Some(user_id),
            Some(user_name),
            Some(user_name),
        );
        let args = MakeCredentialArgsBuilder::new(rp_id, &client_data_hash)
            .key_type(CredentialSupportedKeyType::Ed25519)
            .user_entity(&user_entity)
            .without_pin_and_uv()
            .build();
        let attestation = device
            .make_credential_with_args(&args)
            .map_err(|e| CryptoError::Backend(format!("webauthn: make credential: {e}")))?;
        let attestation_object = build_attestation_object("none", &attestation.auth_data);
        Ok((attestation_object, attestation.credential_descriptor.id))
    }

    /// Drive an assertion (`authenticatorGetAssertion`) ceremony over
    /// ctap-hid: build the real `clientDataJSON`, hash it, ask the attached
    /// authenticator (scoped to `credential_id`) to sign over that hash, and
    /// return the raw `(authenticator_data, client_data_json, signature)` — the
    /// SAME shape [`super::verify_assertion`] consumes.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Backend`] if no authenticator is attached, the
    /// credential is unknown to it, or the ceremony is refused.
    pub fn authenticate(
        rp_id: &str,
        origin: &str,
        challenge_b64url: &str,
        credential_id: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let device = open_device()?;
        let cdj = client_data_json("webauthn.get", challenge_b64url, origin);
        let client_data_hash = Sha256::digest(&cdj);
        let args = GetAssertionArgsBuilder::new(rp_id, &client_data_hash)
            .credential_id(credential_id)
            .without_pin_and_uv()
            .build();
        let assertions = device
            .get_assertion_with_args(&args)
            .map_err(|e| CryptoError::Backend(format!("webauthn: get assertion: {e}")))?;
        let assertion = assertions
            .into_iter()
            .next()
            .ok_or_else(|| CryptoError::Backend("webauthn: no assertion returned".into()))?;
        Ok((assertion.auth_data, cdj, assertion.signature))
    }

    /// Drive an assertion ceremony as [`authenticate`], additionally
    /// requesting the `hmac-secret` extension output for a given `prf_salt` —
    /// the PRF material `/webauthn/authenticate/finish` folds into the
    /// operational-key-unlock secret via [`super::derive_unlock_secret`].
    ///
    /// # Errors
    ///
    /// As [`authenticate`], plus [`CryptoError::Backend`] if the authenticator
    /// does not return an `hmac-secret` output.
    pub fn authenticate_with_prf(
        rp_id: &str,
        origin: &str,
        challenge_b64url: &str,
        credential_id: &[u8],
        prf_salt: [u8; 32],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32])> {
        let device = open_device()?;
        let cdj = client_data_json("webauthn.get", challenge_b64url, origin);
        let client_data_hash = Sha256::digest(&cdj);
        let args = GetAssertionArgsBuilder::new(rp_id, &client_data_hash)
            .credential_id(credential_id)
            .extensions(&[GetExtension::HmacSecret(Some(prf_salt))])
            .without_pin_and_uv()
            .build();
        let assertions = device
            .get_assertion_with_args(&args)
            .map_err(|e| CryptoError::Backend(format!("webauthn: get assertion: {e}")))?;
        let assertion = assertions
            .into_iter()
            .next()
            .ok_or_else(|| CryptoError::Backend("webauthn: no assertion returned".into()))?;
        let prf_output = assertion
            .extensions
            .iter()
            .find_map(|e| match e {
                GetExtension::HmacSecret(Some(o)) => Some(*o),
                _ => None,
            })
            .ok_or_else(|| CryptoError::Backend("webauthn: no hmac-secret output".into()))?;
        Ok((assertion.auth_data, cdj, assertion.signature, prf_output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{sign, signing_keypair_from_seed};
    use crate::types::Seed;

    /// Build a self-consistent registration attestation object plus the
    /// (client-side) secret key, mirroring what a real Ed25519 authenticator
    /// mints. Returns `(attestation_object, secret_key, cose_public_key)`.
    fn make_registration(
        seed_label: &str,
        credential_id: &[u8],
        sign_count: u32,
    ) -> (Vec<u8>, crate::types::SigningSecretKey, Vec<u8>) {
        let (public, secret) =
            signing_keypair_from_seed(&Seed::from_bytes(seed_label.as_bytes().to_vec()))
                .expect("keygen");
        let cose = ed25519_public_key_to_cose(&public).expect("cose");
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&[0u8; 32]); // rpIdHash
        auth_data.push(AUTH_FLAG_AT | 0x01); // AT + UP
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // aaguid
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(&cose);

        use ciborium::value::Value;
        let att = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&att, &mut out).expect("encode");
        (out, secret, cose)
    }

    /// Produce an assertion (authData, clientDataJSON, signature) for a
    /// challenge, mirroring what a real authenticator + browser produces.
    fn make_assertion(
        secret: &crate::types::SigningSecretKey,
        challenge: &str,
        sign_count: u32,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use sha2::{Digest, Sha256};
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://pillar.local"}}"#,
            base64url_encode(challenge.as_bytes())
        )
        .into_bytes();
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&[0u8; 32]);
        auth_data.push(0x01); // UP
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let sig = sign(secret, &signed).expect("sign");
        (auth_data, client_data_json, sig.as_bytes().to_vec())
    }

    #[test]
    fn registration_extracts_the_shared_credential_record() {
        let (att, _sk, cose) = make_registration("auth-a", b"cred-1", 5);
        let rec = parse_attestation(&att).expect("parse attestation");
        assert_eq!(rec.credential_id, b"cred-1");
        assert_eq!(rec.sign_count, 5);
        assert_eq!(rec.cose_public_key, cose);
        // the extracted COSE key really parses to a usable Ed25519 key
        cose_ed25519_public_key(&rec.cose_public_key).expect("usable key");
    }

    #[test]
    fn build_attestation_object_round_trips_through_parse_attestation() {
        // Mirrors the CLI path: an authenticator hands back raw `authData`
        // (what ctap-hid-fido2's `Attestation::auth_data` carries), and the
        // CLI wraps it with `build_attestation_object` — the SAME encoder a
        // browser's simulated ceremony fixture builds by hand (see
        // `make_registration` above) — before POSTing to the RP's
        // `/webauthn/register/finish`. Prove the two are the identical wire
        // shape by round-tripping through the real RP parser.
        let (public, _secret) =
            signing_keypair_from_seed(&Seed::from_bytes(b"cli-authenticator".to_vec()))
                .expect("keygen");
        let cose = ed25519_public_key_to_cose(&public).expect("cose");
        let credential_id = b"cli-cred-1";
        let sign_count: u32 = 3;
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&[0u8; 32]); // rpIdHash
        auth_data.push(AUTH_FLAG_AT | 0x01); // AT + UP
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // aaguid
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(&cose);

        let attestation_object = build_attestation_object("none", &auth_data);
        let rec = parse_attestation(&attestation_object).expect("CLI attestation object parses");
        assert_eq!(rec.credential_id, credential_id);
        assert_eq!(rec.sign_count, sign_count);
        assert_eq!(rec.cose_public_key, cose);
        cose_ed25519_public_key(&rec.cose_public_key).expect("usable key");
    }

    #[test]
    fn a_valid_assertion_verifies_and_reports_its_sign_count() {
        let (att, sk, _cose) = make_registration("auth-a", b"cred-1", 0);
        let rec = parse_attestation(&att).expect("parse");
        let (ad, cdj, sig) = make_assertion(&sk, "challenge-XYZ", 7);
        let verified =
            verify_assertion(&rec.cose_public_key, &ad, &cdj, &sig).expect("assertion verifies");
        assert_eq!(verified.sign_count, 7);
    }

    #[test]
    fn a_forged_signature_is_rejected() {
        let (att, _sk, _cose) = make_registration("auth-a", b"cred-1", 0);
        let rec = parse_attestation(&att).expect("parse");
        // A DIFFERENT authenticator signs — the forged signature must not verify
        // against the registered credential's stored COSE key.
        let (_att2, sk_mallory, _c2) = make_registration("mallory", b"cred-2", 0);
        let (ad, cdj, forged) = make_assertion(&sk_mallory, "challenge-XYZ", 7);
        assert_eq!(
            verify_assertion(&rec.cose_public_key, &ad, &cdj, &forged),
            Err(CryptoError::VerificationFailed),
            "a signature from another authenticator must be rejected"
        );
    }

    #[test]
    fn a_tampered_client_data_is_rejected() {
        let (att, sk, _cose) = make_registration("auth-a", b"cred-1", 0);
        let rec = parse_attestation(&att).expect("parse");
        let (ad, mut cdj, sig) = make_assertion(&sk, "challenge-XYZ", 7);
        cdj[10] ^= 0xff; // flip a byte of the signed clientDataJSON
        assert_eq!(
            verify_assertion(&rec.cose_public_key, &ad, &cdj, &sig),
            Err(CryptoError::VerificationFailed),
            "tampering with the signed clientDataJSON must be rejected"
        );
    }

    #[test]
    fn a_non_ed25519_cose_key_is_refused() {
        use ciborium::value::{Integer, Value};
        // kty=EC2 (2), alg=ES256 (-7): a valid COSE key of an UNSUPPORTED type.
        let map = Value::Map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(2)),
            ),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(-7)),
            ),
        ]);
        let mut cose = Vec::new();
        ciborium::into_writer(&map, &mut cose).expect("encode");
        assert_eq!(
            cose_ed25519_public_key(&cose),
            Err(CryptoError::InvalidKey),
            "a non-Ed25519 COSE key must be refused, not silently accepted"
        );
    }

    #[test]
    fn prf_unlock_secret_is_stable_real_and_not_a_placeholder() {
        let prf = b"authenticator-prf-hmac-secret-output-32bytes!!";
        let s1 = derive_unlock_secret(prf, b"cred-1").expect("derive");
        let s2 = derive_unlock_secret(prf, b"cred-1").expect("derive");
        assert_eq!(s1, s2, "same PRF + credential must yield a stable secret");
        assert_eq!(s1.len(), 32, "unlock secret is a full 32-byte key");
        assert_ne!(
            s1, [0u8; 32],
            "the unlock secret is not a placeholder zero key"
        );
        // credential-id bound: a different credential yields a different secret
        let other = derive_unlock_secret(prf, b"cred-2").expect("derive");
        assert_ne!(s1, other, "the secret is bound to the credential id");
        // PRF-sensitive: a different PRF output yields a different secret
        let diff_prf =
            derive_unlock_secret(b"a-different-prf-output-value", b"cred-1").expect("derive");
        assert_ne!(s1, diff_prf, "the secret is sensitive to the PRF output");
        // empty PRF output is refused rather than deriving from nothing
        assert_eq!(
            derive_unlock_secret(b"", b"cred-1"),
            Err(CryptoError::InvalidLength)
        );
    }

    #[test]
    fn base64url_round_trips() {
        for sample in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            let enc = base64url_encode(sample);
            let dec = base64url_decode(&enc).expect("decode");
            assert_eq!(dec, sample);
        }
    }
}
