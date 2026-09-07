//! Real IPFS **CIDv1** (`raw` codec) addressing over a pillar
//! [`ContentId`].
//!
//! A pillar `ContentId` is a self-describing SHA2-256 multihash
//! `<0x12><0x20><32-byte digest>` (see [`pillar_crypto::content_address`]). A
//! real IPFS **CIDv1** is `<version=0x01><codec><multihash>`, multibase-encoded.
//! Storing content as `raw`(`0x55`) blocks means CIDv1(`raw`, mh) is simply the
//! on-the-wire spelling of the SAME identity a reference IPFS node computes — so
//! these functions are pure re-encodings, not a second hash.

use pillar_crypto::ContentId;

/// multicodec `raw`.
const CODEC_RAW: u8 = 0x55;
/// CID version 1.
const CID_V1: u8 = 0x01;
/// SHA2-256 multihash code.
const MH_SHA2_256: u8 = 0x12;
/// SHA2-256 digest length.
const MH_SHA2_256_LEN: u8 = 0x20;
/// RFC4648 base32 lower alphabet (no padding) — multibase `b`.
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The content id (SHA2-256 multihash) of `bytes` — the address a block is
/// stored under. Infallible for an in-memory slice (a hashing failure would
/// mean the SHA2-256 primitive itself is broken, which is not a representable
/// state — the same contract [`pillar_streamdb`](../pillar_streamdb) documents
/// for its op ids).
#[must_use]
pub fn content_id(bytes: &[u8]) -> ContentId {
    pillar_crypto::content::content_address(bytes)
        .expect("SHA2-256 content addressing is infallible for an in-memory payload")
}

/// The CIDv1(`raw`) multibase-`base32` string for a [`ContentId`] (e.g.
/// `bafkrei…`) — the canonical real-IPFS spelling of this identity, used as the
/// on-disk block filename and the value a reference IPFS node agrees on.
#[must_use]
pub fn to_cidv1_raw(id: &ContentId) -> String {
    let mh = id.as_bytes();
    let mut bytes = Vec::with_capacity(2 + mh.len());
    bytes.push(CID_V1);
    bytes.push(CODEC_RAW);
    bytes.extend_from_slice(mh);
    let mut s = String::with_capacity(1 + bytes.len() * 8 / 5 + 1);
    s.push('b'); // multibase: base32 lower, no padding
    base32_lower_encode(&bytes, &mut s);
    s
}

/// Parse a CIDv1(`raw`) multibase-`base32` string back to a [`ContentId`].
/// Returns `None` unless it is a v1 `raw` CID whose multihash is a SHA2-256
/// multihash (the only shape this node emits).
#[must_use]
pub fn from_cidv1_raw(s: &str) -> Option<ContentId> {
    let s = s.trim();
    if s.chars().next()? != 'b' {
        return None; // we only emit/accept base32-lower ('b')
    }
    let bytes = base32_lower_decode(&s[1..])?;
    if bytes.len() < 2 || bytes[0] != CID_V1 || bytes[1] != CODEC_RAW {
        return None;
    }
    let mh = &bytes[2..];
    if mh.len() != 34 || mh[0] != MH_SHA2_256 || mh[1] != MH_SHA2_256_LEN {
        return None;
    }
    Some(ContentId::from_bytes(mh.to_vec()))
}

fn base32_lower_encode(data: &[u8], out: &mut String) {
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
}

fn base32_lower_decode(s: &str) -> Option<Vec<u8>> {
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for c in s.bytes() {
        let val = BASE32_ALPHABET.iter().position(|&a| a == c)? as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidv1_raw_round_trips_a_content_id() {
        let id = content_id(b"a pillar segment's wire bytes");
        let s = to_cidv1_raw(&id);
        assert!(
            s.starts_with("bafkrei"),
            "raw+sha2-256 CIDv1 is `bafkrei...`, got {s}"
        );
        assert_eq!(from_cidv1_raw(&s), Some(id), "CIDv1 string must round-trip");
    }

    #[test]
    fn cidv1_rejects_non_raw_or_garbage() {
        assert_eq!(from_cidv1_raw("not-a-cid"), None);
        assert_eq!(from_cidv1_raw("Qmfoo"), None); // v0, not our shape
    }

    #[test]
    fn base32_matches_known_vectors() {
        // RFC4648 base32 (lowercase, no pad) of "foobar" is "mzxw6ytboi".
        let mut out = String::new();
        base32_lower_encode(b"foobar", &mut out);
        assert_eq!(out, "mzxw6ytboi");
        assert_eq!(
            base32_lower_decode("mzxw6ytboi").as_deref(),
            Some(&b"foobar"[..])
        );
    }
}
