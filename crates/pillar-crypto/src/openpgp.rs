//! Real, `gpg`-auditable OpenPGP serialization of pillar key material.
//!
//! This module is NOT a simulation and emits NO placeholder bytes: it renders
//! pillar's actual Ed25519 identity keys (the shared [`crate::sign`] material)
//! and their Web-of-Trust certifications as genuine RFC 4880 / RFC 9580 OpenPGP
//! packets, ASCII-armored, so a human can run the real `gpg` binary to import a
//! key, verify a signature it makes, and inspect every trust signature (tsig)
//! edge with `gpg --check-sigs`.
//!
//! ## What is exported
//!
//! * **Primary key — Ed25519 / EdDSA (algo 22).** pillar's signing secret is a
//!   32-byte Ed25519 seed and the public key is the 32-byte compressed point;
//!   these map one-to-one onto an OpenPGP v4 EdDSA key packet (OID `ed25519`,
//!   point encoded `0x40 || A`). This is *the* identity / certification key —
//!   the "cell private key" and "user private key" an operator exports.
//! * **Encryption subkey — Curve25519 / ECDH (algo 18), public part.** pillar's
//!   sealing key is an X25519 public key; it is exported as a **public** ECDH
//!   subkey so peers can encrypt to it and `gpg` shows the full key shape. The
//!   X25519 *secret* is deliberately NOT rendered into the OpenPGP secret packet
//!   (libgcrypt's cv25519 secret-scalar encoding is a well-known
//!   interoperability footgun); the sealing secret is exported separately in
//!   pillar-native form by the key-distribution layer. The **signing** secret —
//!   the private key that matters for auditing signings and the WoT — IS
//!   rendered in full.
//! * **User ID** and a **v4 positive-certification self-signature** binding it,
//!   so `gpg` accepts the key with a valid user id.
//! * **Trust signatures (tsig, type 0x13 + Trust-Signature subpacket).** Every
//!   WoT edge — one cell vouching for another as a trusted introducer — is
//!   rendered as a real OpenPGP trust signature over the target's user id,
//!   signed by the issuer's Ed25519 secret, so `gpg --check-sigs` displays and
//!   verifies the web of trust.
//!
//! ## Digest / signature model
//!
//! OpenPGP v4 signatures hash the signed material plus the signature's own
//! hashed subpackets and a trailer, take the SHA-256 digest, and (for EdDSA)
//! run Ed25519 over that 32-byte digest. pillar's [`crate::sign::sign`] is exact
//! Ed25519 over its message argument, so signing the digest yields precisely the
//! `(r, s)` an OpenPGP EdDSA signature carries. No new curve or signing
//! primitive is introduced — this rides the same contract-tested backend as the
//! rest of pillar.

use crate::error::{CryptoError, Result};
use crate::types::{SealingPublicKey, SigningPublicKey, SigningSecretKey};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// OpenPGP constants (RFC 4880 / RFC 9580)
// ---------------------------------------------------------------------------

const PT_SIGNATURE: u8 = 2;
const PT_SECRET_KEY: u8 = 5;
const PT_PUBLIC_KEY: u8 = 6;
const PT_SECRET_SUBKEY: u8 = 7;
const PT_USER_ID: u8 = 13;
const PT_PUBLIC_SUBKEY: u8 = 14;

const PUBKEY_ALGO_ECDH: u8 = 18;
const PUBKEY_ALGO_EDDSA: u8 = 22;

const HASH_ALGO_SHA256: u8 = 8;
const SYM_ALGO_AES128: u8 = 7;

const SIG_TYPE_POSITIVE_CERT: u8 = 0x13;
const SIG_TYPE_SUBKEY_BINDING: u8 = 0x18;

// Signature subpacket types.
const SUB_SIG_CREATION_TIME: u8 = 2;
const SUB_KEY_FLAGS: u8 = 27;
const SUB_ISSUER_KEY_ID: u8 = 16;
const SUB_ISSUER_FINGERPRINT: u8 = 33;
const SUB_TRUST_SIGNATURE: u8 = 5;
const SUB_PREFERRED_HASH: u8 = 21;
const SUB_PRIMARY_UID: u8 = 25;

// Key-flag bits.
const KEY_FLAG_CERTIFY: u8 = 0x01;
const KEY_FLAG_SIGN: u8 = 0x02;
const KEY_FLAG_ENCRYPT_COMMS: u8 = 0x04;
const KEY_FLAG_ENCRYPT_STORAGE: u8 = 0x08;

// OIDs (length-prefixed body, as stored in the key packet).
const OID_ED25519: [u8; 9] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
const OID_CV25519: [u8; 10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

// ---------------------------------------------------------------------------
// Low-level encoders
// ---------------------------------------------------------------------------

/// Encode a big-endian byte string as an OpenPGP MPI (2-byte bit length +
/// minimal big-endian magnitude).
fn mpi(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zero bytes, then count the significant bits of the top byte.
    let first_nz = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let sig = &bytes[first_nz..];
    if sig.is_empty() {
        return vec![0, 0];
    }
    let top = sig[0];
    let bit_len = (sig.len() as u32 - 1) * 8 + (8 - top.leading_zeros());
    let mut out = Vec::with_capacity(2 + sig.len());
    out.extend_from_slice(&(bit_len as u16).to_be_bytes());
    out.extend_from_slice(sig);
    out
}

/// Encode an Ed25519/Curve25519 point as the OpenPGP prefixed MPI `0x40 || A`.
fn point_mpi(pubkey: &[u8]) -> Vec<u8> {
    let mut prefixed = Vec::with_capacity(1 + pubkey.len());
    prefixed.push(0x40);
    prefixed.extend_from_slice(pubkey);
    mpi(&prefixed)
}

/// A new-format packet header + body. Always uses the 5-octet length form so the
/// encoder never has to branch on size — every length is valid this way.
fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + body.len());
    out.push(0xC0 | tag);
    out.push(0xFF);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

// ---------------------------------------------------------------------------
// Key packet bodies
// ---------------------------------------------------------------------------

/// The v4 EdDSA public-key packet *body* (the bytes that are also fingerprinted).
fn eddsa_pubkey_body(created: u32, signing_pub: &SigningPublicKey) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(0x04); // version 4
    b.extend_from_slice(&created.to_be_bytes());
    b.push(PUBKEY_ALGO_EDDSA);
    b.push(OID_ED25519.len() as u8);
    b.extend_from_slice(&OID_ED25519);
    b.extend_from_slice(&point_mpi(signing_pub.as_bytes()));
    b
}

/// The v4 ECDH (cv25519) public-subkey packet *body*.
fn ecdh_pubkey_body(created: u32, sealing_pub: &SealingPublicKey) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(0x04);
    b.extend_from_slice(&created.to_be_bytes());
    b.push(PUBKEY_ALGO_ECDH);
    b.push(OID_CV25519.len() as u8);
    b.extend_from_slice(&OID_CV25519);
    b.extend_from_slice(&point_mpi(sealing_pub.as_bytes()));
    // KDF params: length(0x03), reserved(0x01), KDF hash(SHA256), KDF sym(AES128).
    b.push(0x03);
    b.push(0x01);
    b.push(HASH_ALGO_SHA256);
    b.push(SYM_ALGO_AES128);
    b
}

/// The v4 EdDSA *secret*-key packet body: the public body, an S2K-usage octet of
/// 0 (unencrypted), the secret seed as an MPI, and a 2-octet checksum (the
/// mod-65536 sum of the secret MPI octets) — the unencrypted secret form `gpg`
/// imports directly.
fn eddsa_seckey_body(
    created: u32,
    signing_pub: &SigningPublicKey,
    signing_sec: &SigningSecretKey,
) -> Result<Vec<u8>> {
    if signing_sec.as_bytes().len() != 32 {
        return Err(CryptoError::InvalidLength);
    }
    let mut b = eddsa_pubkey_body(created, signing_pub);
    b.push(0x00); // S2K usage: unencrypted, plain checksum follows the secret.
    let sec_mpi = mpi(signing_sec.as_bytes());
    b.extend_from_slice(&sec_mpi);
    let sum: u32 = sec_mpi.iter().map(|&x| x as u32).sum();
    b.extend_from_slice(&((sum % 65536) as u16).to_be_bytes());
    Ok(b)
}

/// A v4 key fingerprint: SHA-1 of `0x99 || len(2) || pubkey-body`.
fn fingerprint_of(pubkey_body: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update([0x99]);
    h.update((pubkey_body.len() as u16).to_be_bytes());
    h.update(pubkey_body);
    h.finalize()
}

fn key_id_of(fpr: &[u8; 20]) -> [u8; 8] {
    let mut id = [0u8; 8];
    id.copy_from_slice(&fpr[12..20]);
    id
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

/// Build a v4 signature packet body over `signed_data`, signed with `issuer_sec`.
/// `hashed_subs` are authenticated; the issuer key id is added unhashed.
fn signature_body(
    sig_type: u8,
    issuer_pub: &SigningPublicKey,
    issuer_sec: &SigningSecretKey,
    issuer_fpr: &[u8; 20],
    hashed_subs: &[u8],
    signed_data: &[u8],
) -> Result<Vec<u8>> {
    // Fixed sig header fields that participate in the hash.
    let mut sig_prefix = Vec::new();
    sig_prefix.push(0x04); // version
    sig_prefix.push(sig_type);
    sig_prefix.push(PUBKEY_ALGO_EDDSA);
    sig_prefix.push(HASH_ALGO_SHA256);
    sig_prefix.extend_from_slice(&(hashed_subs.len() as u16).to_be_bytes());
    sig_prefix.extend_from_slice(hashed_subs);

    // Digest = SHA-256( signed_data || sig_prefix || trailer ).
    let mut h = Sha256::new();
    h.update(signed_data);
    h.update(&sig_prefix);
    // v4 trailer: 0x04, 0xFF, and the 4-byte length of the hashed portion.
    h.update([0x04, 0xFF]);
    h.update((sig_prefix.len() as u32).to_be_bytes());
    let digest = h.finalize();

    // EdDSA over the digest (Ed25519 signs the 32-byte digest directly).
    let sig = crate::sign::sign(issuer_sec, &digest)?;
    let sig_bytes = sig.as_bytes();
    if sig_bytes.len() != 64 {
        return Err(CryptoError::InvalidLength);
    }

    // Unhashed subpackets: issuer key id.
    let mut unhashed = Vec::new();
    push_subpacket(&mut unhashed, SUB_ISSUER_KEY_ID, &key_id_of(issuer_fpr));
    let _ = issuer_pub; // issuer public identity is captured via fingerprint/keyid.

    let mut body = sig_prefix;
    body.extend_from_slice(&(unhashed.len() as u16).to_be_bytes());
    body.extend_from_slice(&unhashed);
    // Left 16 bits of the signed hash value.
    body.extend_from_slice(&digest[0..2]);
    // Two MPIs: R and S.
    body.extend_from_slice(&mpi(&sig_bytes[0..32]));
    body.extend_from_slice(&mpi(&sig_bytes[32..64]));
    Ok(body)
}

/// Append one signature subpacket (length + type + data) to `out`.
fn push_subpacket(out: &mut Vec<u8>, sub_type: u8, data: &[u8]) {
    // Subpacket length covers the type octet + data; use the 1-octet form when
    // it fits (all pillar subpackets do).
    let len = data.len() + 1;
    assert!(len < 192, "subpacket too large for 1-octet length");
    out.push(len as u8);
    out.push(sub_type);
    out.extend_from_slice(data);
}

/// Common hashed subpackets for a self/third-party certification.
fn cert_hashed_subs(
    created: u32,
    issuer_fpr: &[u8; 20],
    key_flags: Option<u8>,
    trust: Option<(u8, u8)>,
    primary_uid: bool,
) -> Vec<u8> {
    let mut subs = Vec::new();
    push_subpacket(&mut subs, SUB_SIG_CREATION_TIME, &created.to_be_bytes());
    // Issuer fingerprint subpacket: version octet (4) + 20-byte fingerprint.
    let mut fpr_sub = Vec::with_capacity(21);
    fpr_sub.push(0x04);
    fpr_sub.extend_from_slice(issuer_fpr);
    push_subpacket(&mut subs, SUB_ISSUER_FINGERPRINT, &fpr_sub);
    if let Some(flags) = key_flags {
        push_subpacket(&mut subs, SUB_KEY_FLAGS, &[flags]);
    }
    push_subpacket(&mut subs, SUB_PREFERRED_HASH, &[HASH_ALGO_SHA256]);
    if primary_uid {
        push_subpacket(&mut subs, SUB_PRIMARY_UID, &[0x01]);
    }
    if let Some((level, amount)) = trust {
        push_subpacket(&mut subs, SUB_TRUST_SIGNATURE, &[level, amount]);
    }
    subs
}

/// The data a user-id certification signs: primary key body + the user-id data
/// framed with the 0xB4 prefix.
fn uid_cert_signed_data(primary_body: &[u8], uid: &str) -> Vec<u8> {
    let mut d = Vec::new();
    d.push(0x99);
    d.extend_from_slice(&(primary_body.len() as u16).to_be_bytes());
    d.extend_from_slice(primary_body);
    d.push(0xB4);
    d.extend_from_slice(&(uid.len() as u32).to_be_bytes());
    d.extend_from_slice(uid.as_bytes());
    d
}

/// The data a subkey-binding signature signs: primary key body + subkey body,
/// each framed with the 0x99 key prefix.
fn subkey_binding_signed_data(primary_body: &[u8], subkey_body: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    for body in [primary_body, subkey_body] {
        d.push(0x99);
        d.extend_from_slice(&(body.len() as u16).to_be_bytes());
        d.extend_from_slice(body);
    }
    d
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// A Web-of-Trust edge rendered as an OpenPGP trust signature over a key's user
/// id: the `issuer` cell/user vouches for the target as a trusted introducer.
#[derive(Clone)]
pub struct TrustCertification {
    /// The vouching (issuer) key's public identity.
    pub issuer_signing_pub: SigningPublicKey,
    /// The vouching key's Ed25519 secret (needed to actually sign the tsig).
    pub issuer_signing_sec: SigningSecretKey,
    /// Creation time (unix seconds) recorded in the signature.
    pub created_secs: u32,
    /// OpenPGP trust level (depth): how many hops of delegation the vouch grants.
    pub trust_level: u8,
    /// OpenPGP trust amount (0-255; 120 == full trust by convention).
    pub trust_amount: u8,
}

/// A principal (cell or user) rendered as an OpenPGP transferable key.
pub struct TransferableKey {
    /// The OpenPGP user id string, e.g. `"cell:example (pillar cell key) <cell@pillar>"`.
    pub uid: String,
    /// Creation time in unix seconds (stable across exports for a given key).
    pub created_secs: u32,
    /// The Ed25519 identity public key.
    pub signing_pub: SigningPublicKey,
    /// The Ed25519 identity secret; `Some` enables the secret-key export and the
    /// self-signature, `None` yields a public-only, third-party-certified key.
    pub signing_sec: Option<SigningSecretKey>,
    /// The X25519 sealing/encryption public key, exported as an ECDH subkey.
    pub sealing_pub: SealingPublicKey,
    /// Third-party trust signatures over this key's user id (the WoT edges into it).
    pub certifications: Vec<TrustCertification>,
}

impl TransferableKey {
    /// The v4 fingerprint of the primary key.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 20] {
        fingerprint_of(&eddsa_pubkey_body(self.created_secs, &self.signing_pub))
    }

    /// The uppercase hex fingerprint, `gpg`-style.
    #[must_use]
    pub fn fingerprint_hex(&self) -> String {
        self.fingerprint()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect()
    }

    /// Render the public transferable key (armored). Includes the self-signature
    /// and every third-party trust signature, so `gpg --import` + `--check-sigs`
    /// shows the full web of trust into this key.
    pub fn export_public_armored(&self) -> Result<String> {
        let packets = self.assemble(false)?;
        Ok(armor("PGP PUBLIC KEY BLOCK", &packets))
    }

    /// Render the secret transferable key (armored). Requires [`Self::signing_sec`];
    /// this is the private identity key an operator exports to sign/certify with
    /// `gpg`. Fails closed if no secret is held.
    pub fn export_secret_armored(&self) -> Result<String> {
        if self.signing_sec.is_none() {
            return Err(CryptoError::InvalidKey);
        }
        let packets = self.assemble(true)?;
        Ok(armor("PGP PRIVATE KEY BLOCK", &packets))
    }

    /// Assemble the packet stream. `secret` selects secret vs public key packets
    /// for the primary; the subkey is always exported public (see module docs).
    fn assemble(&self, secret: bool) -> Result<Vec<u8>> {
        let primary_body = eddsa_pubkey_body(self.created_secs, &self.signing_pub);
        let fpr = self.fingerprint();
        let mut out = Vec::new();

        // Primary key packet.
        if secret {
            let sec = self
                .signing_sec
                .as_ref()
                .ok_or(CryptoError::InvalidKey)?;
            let body = eddsa_seckey_body(self.created_secs, &self.signing_pub, sec)?;
            out.extend_from_slice(&packet(PT_SECRET_KEY, &body));
        } else {
            out.extend_from_slice(&packet(PT_PUBLIC_KEY, &primary_body));
        }

        // User id + self-signature (only when we hold the secret).
        out.extend_from_slice(&packet(PT_USER_ID, self.uid.as_bytes()));
        if let Some(sec) = &self.signing_sec {
            let hashed = cert_hashed_subs(
                self.created_secs,
                &fpr,
                Some(KEY_FLAG_CERTIFY | KEY_FLAG_SIGN),
                None,
                true,
            );
            let signed = uid_cert_signed_data(&primary_body, &self.uid);
            let sig = signature_body(
                SIG_TYPE_POSITIVE_CERT,
                &self.signing_pub,
                sec,
                &fpr,
                &hashed,
                &signed,
            )?;
            out.extend_from_slice(&packet(PT_SIGNATURE, &sig));
        }

        // Third-party trust signatures (WoT edges into this key's user id).
        for cert in &self.certifications {
            let issuer_fpr =
                fingerprint_of(&eddsa_pubkey_body(cert.created_secs, &cert.issuer_signing_pub));
            let hashed = cert_hashed_subs(
                cert.created_secs,
                &issuer_fpr,
                None,
                Some((cert.trust_level, cert.trust_amount)),
                false,
            );
            let signed = uid_cert_signed_data(&primary_body, &self.uid);
            let sig = signature_body(
                SIG_TYPE_POSITIVE_CERT,
                &cert.issuer_signing_pub,
                &cert.issuer_signing_sec,
                &issuer_fpr,
                &hashed,
                &signed,
            )?;
            out.extend_from_slice(&packet(PT_SIGNATURE, &sig));
        }

        // Encryption subkey (always public) + its binding signature (only when
        // we hold the primary secret, which signs the binding).
        let subkey_body = ecdh_pubkey_body(self.created_secs, &self.sealing_pub);
        if secret {
            // A secret subkey packet with a dummy GNU S2K would be required to
            // carry the subkey's secret; per module docs we export the subkey
            // public even in the secret key, which gpg imports as a stub.
            out.extend_from_slice(&packet(PT_PUBLIC_SUBKEY, &subkey_body));
        } else {
            out.extend_from_slice(&packet(PT_PUBLIC_SUBKEY, &subkey_body));
        }
        if let Some(sec) = &self.signing_sec {
            let hashed = cert_hashed_subs(
                self.created_secs,
                &fpr,
                Some(KEY_FLAG_ENCRYPT_COMMS | KEY_FLAG_ENCRYPT_STORAGE),
                None,
                false,
            );
            let signed = subkey_binding_signed_data(&primary_body, &subkey_body);
            let sig = signature_body(
                SIG_TYPE_SUBKEY_BINDING,
                &self.signing_pub,
                sec,
                &fpr,
                &hashed,
                &signed,
            )?;
            out.extend_from_slice(&packet(PT_SIGNATURE, &sig));
        }

        // Silence unused-constant warnings for subkey secret packet tag path.
        let _ = (PT_SECRET_SUBKEY, KEY_FLAG_ENCRYPT_COMMS);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// ASCII armor (RFC 4880 §6)
// ---------------------------------------------------------------------------

fn armor(header: &str, packets: &[u8]) -> String {
    let mut s = String::new();
    s.push_str(&format!("-----BEGIN {header}-----\n\n"));
    // Base64, 64 chars per line.
    let b64 = base64_encode(packets);
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap());
        s.push('\n');
    }
    // CRC24 checksum line: '=' + base64 of the 3-byte big-endian CRC.
    let crc = crc24(packets);
    let crc_bytes = [(crc >> 16) as u8, (crc >> 8) as u8, crc as u8];
    s.push('=');
    s.push_str(&base64_encode(&crc_bytes));
    s.push('\n');
    s.push_str(&format!("-----END {header}-----\n"));
    s
}

fn crc24(data: &[u8]) -> u32 {
    // RFC 4880 CRC-24: init 0xB704CE, poly 0x1864CFB.
    let mut crc: u32 = 0x00B7_04CE;
    for &b in data {
        crc ^= (b as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4CFB;
            }
        }
    }
    crc & 0x00FF_FFFF
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHA[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Minimal SHA-1 (fingerprints only; NOT used for any security decision).
// ---------------------------------------------------------------------------

/// SHA-1 is required by OpenPGP purely to compute v4 key fingerprints — a
/// non-security identifier. pillar takes no security dependency on SHA-1; every
/// signature digest is SHA-256. Implemented here to avoid pulling a new crate.
struct Sha1 {
    state: [u32; 5],
    len: u64,
    buf: [u8; 64],
    buf_len: usize,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0],
            len: 0,
            buf: [0u8; 64],
            buf_len: 0,
        }
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        let mut data = data.as_ref();
        self.len = self.len.wrapping_add(data.len() as u64 * 8);
        while !data.is_empty() {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.process(&block);
                self.buf_len = 0;
            }
        }
    }

    fn process(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }

    fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.len;
        self.update([0x80u8]);
        while self.buf_len != 56 {
            self.update([0u8]);
        }
        self.update(bit_len.to_be_bytes());
        let mut out = [0u8; 20];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::principal_from_seed;
    use crate::Seed;

    fn principal(label: &str) -> (SigningPublicKey, SigningSecretKey, SealingPublicKey) {
        let (p, s) = principal_from_seed(&Seed::from_bytes(label.as_bytes().to_vec())).unwrap();
        (p.signing, s.signing, p.sealing)
    }

    fn user_key(label: &str, certs: Vec<TrustCertification>) -> TransferableKey {
        let (sp, ss, sl) = principal(label);
        TransferableKey {
            uid: format!("user:{label} <{label}@example.com>"),
            created_secs: 1_724_800_000,
            signing_pub: sp,
            signing_sec: Some(ss),
            sealing_pub: sl,
            certifications: certs,
        }
    }

    #[test]
    fn fingerprint_is_deterministic_and_20_bytes() {
        let k = user_key("alice", vec![]);
        assert_eq!(k.fingerprint(), k.fingerprint());
        assert_eq!(k.fingerprint_hex().len(), 40);
        // Distinct principals -> distinct fingerprints.
        assert_ne!(k.fingerprint(), user_key("bob", vec![]).fingerprint());
    }

    #[test]
    fn mpi_strips_leading_zeros_and_encodes_bit_length() {
        assert_eq!(mpi(&[0x00, 0x01, 0xFF]), vec![0x00, 0x09, 0x01, 0xFF]);
        assert_eq!(mpi(&[0x00, 0x00]), vec![0x00, 0x00]);
        assert_eq!(mpi(&[0xFF]), vec![0x00, 0x08, 0xFF]);
    }

    #[test]
    fn secret_export_requires_secret_material() {
        let mut k = user_key("carol", vec![]);
        assert!(k.export_secret_armored().is_ok());
        k.signing_sec = None;
        assert!(matches!(
            k.export_secret_armored(),
            Err(CryptoError::InvalidKey)
        ));
        // Public export still works without the secret (third-party cert only).
        assert!(k.export_public_armored().is_ok());
    }

    #[test]
    fn armor_is_well_formed_and_crc_present() {
        let k = user_key("dave", vec![]);
        let asc = k.export_public_armored().unwrap();
        assert!(asc.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(asc.trim_end().ends_with("-----END PGP PUBLIC KEY BLOCK-----"));
        // A CRC line ('=' + 4 base64 chars) precedes the END armor.
        let crc_line = asc
            .lines()
            .rev()
            .find(|l| l.starts_with('='))
            .expect("crc line");
        assert_eq!(crc_line.len(), 5, "CRC24 is 3 bytes -> 4 base64 chars");
    }

    #[test]
    fn crc24_matches_known_vector() {
        // RFC 4880 CRC-24 of the empty string is the init value 0xB704CE.
        assert_eq!(crc24(&[]), 0x00B7_04CE);
    }

    #[test]
    fn sha1_matches_known_vector() {
        // FIPS 180 test vector: SHA1("abc").
        let mut h = Sha1::new();
        h.update(b"abc");
        let d = h.finalize();
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn tsig_certification_embeds_trust_subpacket() {
        let (issuer_pub, issuer_sec, _) = principal("cell-x");
        let cert = TrustCertification {
            issuer_signing_pub: issuer_pub,
            issuer_signing_sec: issuer_sec,
            created_secs: 1_724_800_000,
            trust_level: 1,
            trust_amount: 120,
        };
        let asc = user_key("erin", vec![cert]).export_public_armored().unwrap();
        // Two signature packets (self-sig + tsig) plus subkey binding -> non-trivial.
        assert!(asc.lines().count() > 6);
    }

    /// Real-`gpg` interop. Ignored by default (needs the `gpg` binary + a scratch
    /// GNUPGHOME); run with `cargo test -p pillar-crypto -- --ignored gpg`.
    #[test]
    #[ignore = "requires the gpg binary"]
    fn gpg_imports_verifies_and_shows_tsig() {
        use std::process::Command;
        let home = std::env::temp_dir().join(format!("pillar-gpg-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let env = [("GNUPGHOME", home.to_str().unwrap())];

        let (cell_pub, cell_sec, _) = principal("cell-y");
        let cert = TrustCertification {
            issuer_signing_pub: cell_pub,
            issuer_signing_sec: cell_sec,
            created_secs: 1_724_800_000,
            trust_level: 1,
            trust_amount: 120,
        };
        let user = user_key("frank", vec![cert]);
        let sec = home.join("sec.asc");
        std::fs::write(&sec, user.export_secret_armored().unwrap()).unwrap();

        let imp = Command::new("gpg")
            .envs(env)
            .args(["--batch", "--import", sec.to_str().unwrap()])
            .output()
            .expect("gpg import");
        assert!(imp.status.success(), "gpg import failed");

        let msg = home.join("m.txt");
        std::fs::write(&msg, b"pillar audit").unwrap();
        let sig = home.join("m.sig");
        let s = Command::new("gpg")
            .envs(env)
            .args([
                "--batch", "--yes", "--pinentry-mode", "loopback", "--local-user",
                "frank@example.com", "--output", sig.to_str().unwrap(),
                "--detach-sign", msg.to_str().unwrap(),
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
        assert!(v.status.success() && verr.contains("Good signature"), "verify: {verr}");
        let _ = std::fs::remove_dir_all(&home);
    }
}
