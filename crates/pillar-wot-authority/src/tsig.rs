//! OpenPGP Trust Signature subpacket parsing (RFC 9580 §5.2.3.13, née RFC
//! 4880 §5.2.3.13).
//!
//! A trust signature (tsig) is an OpenPGP certification carrying a *Trust
//! Signature* subpacket in its hashed area: two octets, `level` then
//! `amount`. `level` is the delegation depth the signer grants the
//! subject — `0` means "trusted to certify others' identities but not to
//! further delegate trust", each level above that permits one additional
//! hop of delegation. `amount` is a fraction of 255 expressing how *much*
//! the signer trusts the subject; per RFC 9580 the reference value `120`
//! denotes complete/full trust, so this module treats `amount` as
//! effectively binary — only `amount >= FULL_TRUST_AMOUNT` yields a usable
//! edge, mirroring GnuPG's own `TRUST_FULLY` cutoff. Anything below that is
//! partial trust and confers no delegated authority here.
//!
//! # GnuPG owner-trust is deliberately never consulted
//!
//! GnuPG additionally maintains a local, unsigned "owner-trust" database
//! (`trustdb.gpg`) that a user can hand-set on any key, entirely outside any
//! certification the key's owner ever signed. That value is not part of the
//! OpenPGP certificate — it is neither transmitted, verifiable, nor
//! attributable to anyone. This module parses *only* the hashed subpacket
//! area of a genuine, verified signature packet; it has no code path that
//! reads or accepts an owner-trust value from anywhere, so a GnuPG
//! owner-trust setting can never manufacture an edge here.

#![forbid(unsafe_code)]

/// A parsed OpenPGP Trust Signature subpacket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustSignature {
    /// Delegation depth granted to the subject (RFC 9580 `level`).
    pub level: u8,
    /// Trust amount, a fraction of 255 (RFC 9580 `amount`).
    pub amount: u8,
}

/// The reference "fully trusted" amount (RFC 9580 §5.2.3.13 / GnuPG
/// `TRUST_FULLY`). An `amount` below this is partial trust and is rejected.
pub const FULL_TRUST_AMOUNT: u8 = 120;

/// Subpacket type id for a Trust Signature (RFC 9580 §5.2.3.13).
const TRUST_SIGNATURE_TYPE: u8 = 5;

/// Why a tsig subpacket area failed to yield a usable trust signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TsigError {
    /// The subpacket length header was truncated or malformed.
    MalformedLength,
    /// A subpacket's declared length ran past the end of the buffer.
    TruncatedSubpacket,
    /// No Trust Signature subpacket (type 5) was present in the hashed area.
    NoTrustSignature,
    /// A Trust Signature subpacket was present but its body was not exactly
    /// the two octets (`level`, `amount`) RFC 9580 mandates.
    MalformedTrustSignature,
    /// The subpacket's `amount` fell below [`FULL_TRUST_AMOUNT`] — partial
    /// trust, which this model never treats as a usable edge.
    PartialTrust {
        /// The amount actually presented.
        amount: u8,
    },
}

/// One decoded (type, body) subpacket from a hashed subpacket area.
struct RawSubpacket<'a> {
    kind: u8,
    body: &'a [u8],
}

/// Decode the RFC 9580 §5.2.3.1 scalar subpacket-length header at the start
/// of `data`, returning `(length_of_body_plus_type, header_len)`.
fn read_subpacket_length(data: &[u8]) -> Result<(usize, usize), TsigError> {
    let first = *data.first().ok_or(TsigError::MalformedLength)?;
    match first {
        0..=191 => Ok((first as usize, 1)),
        192..=223 => {
            let second = *data.get(1).ok_or(TsigError::MalformedLength)?;
            let len = ((first as usize - 192) << 8) + second as usize + 192;
            Ok((len, 2))
        }
        255 => {
            let bytes: [u8; 4] = data
                .get(1..5)
                .ok_or(TsigError::MalformedLength)?
                .try_into()
                .map_err(|_| TsigError::MalformedLength)?;
            Ok((u32::from_be_bytes(bytes) as usize, 5))
        }
        // 224..=254: partial-body lengths are a signature-packet-body
        // concept, not valid inside a subpacket length header.
        _ => Err(TsigError::MalformedLength),
    }
}

/// Walk every subpacket in a hashed subpacket area.
fn subpackets(mut data: &[u8]) -> Result<Vec<RawSubpacket<'_>>, TsigError> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let (body_len, header_len) = read_subpacket_length(data)?;
        if body_len == 0 {
            return Err(TsigError::MalformedLength);
        }
        let rest = &data[header_len..];
        let chunk = rest.get(..body_len).ok_or(TsigError::TruncatedSubpacket)?;
        // The critical-bit (high bit of the type octet) is not meaningful
        // here: we neither honor nor reject unknown-critical subpackets,
        // since we only ever look for the one type we understand.
        let kind = chunk[0] & 0x7f;
        let body = &chunk[1..];
        out.push(RawSubpacket { kind, body });
        data = &rest[body_len..];
    }
    Ok(out)
}

/// Parse a genuine, already-signature-verified hashed subpacket area and
/// extract its Trust Signature, if any, enforcing full trust.
///
/// `data` must be the hashed subpacket area of an OpenPGP certification that
/// has ALREADY been cryptographically verified to have been produced by the
/// claimed signer — this function only decodes the tsig depth/amount fields,
/// it performs no signature verification of its own.
///
/// # Errors
///
/// See [`TsigError`] for every rejection reason, including a present but
/// merely-partial trust amount.
pub fn parse_trust_signature(data: &[u8]) -> Result<TrustSignature, TsigError> {
    let subs = subpackets(data)?;
    let tsig = subs
        .into_iter()
        .find(|s| s.kind == TRUST_SIGNATURE_TYPE)
        .ok_or(TsigError::NoTrustSignature)?;
    let [level, amount] = *tsig.body else {
        return Err(TsigError::MalformedTrustSignature);
    };
    if amount < FULL_TRUST_AMOUNT {
        return Err(TsigError::PartialTrust { amount });
    }
    Ok(TrustSignature { level, amount })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a single Trust Signature subpacket (short-form length header).
    fn tsig_subpacket(level: u8, amount: u8) -> Vec<u8> {
        // body = type octet + level + amount = 3 bytes.
        vec![3, TRUST_SIGNATURE_TYPE, level, amount]
    }

    #[test]
    fn full_trust_tsig_parses_level_and_amount() {
        let area = tsig_subpacket(2, 120);
        let tsig = parse_trust_signature(&area).unwrap();
        assert_eq!(
            tsig,
            TrustSignature {
                level: 2,
                amount: 120
            }
        );
    }

    #[test]
    fn partial_trust_amount_is_rejected() {
        // amount below the full-trust cutoff must never yield a usable edge,
        // mirroring GnuPG's own TRUST_FULLY threshold.
        let area = tsig_subpacket(2, 60);
        assert_eq!(
            parse_trust_signature(&area),
            Err(TsigError::PartialTrust { amount: 60 })
        );
    }

    #[test]
    fn missing_trust_signature_subpacket_is_rejected() {
        // Some unrelated subpacket (e.g. Issuer, type 16, 8-byte body) with
        // no Trust Signature present at all.
        let area = vec![9, 16, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            parse_trust_signature(&area),
            Err(TsigError::NoTrustSignature)
        );
    }

    #[test]
    fn malformed_trust_signature_body_is_rejected() {
        // Type 5 present but body is only 1 octet instead of the mandated 2.
        let area = vec![2, TRUST_SIGNATURE_TYPE, 3];
        assert_eq!(
            parse_trust_signature(&area),
            Err(TsigError::MalformedTrustSignature)
        );
    }

    #[test]
    fn truncated_subpacket_area_is_rejected() {
        // Header claims a 3-byte body but only 1 byte follows.
        let area = vec![3, TRUST_SIGNATURE_TYPE, 5];
        assert_eq!(
            parse_trust_signature(&area),
            Err(TsigError::TruncatedSubpacket)
        );
    }

    #[test]
    fn two_byte_length_header_decodes_correctly() {
        // 192..=223 first-octet form: length = ((first-192)<<8)+second+192.
        // Encode a 3-byte body (type+level+amount) using the 2-byte header
        // form: first=192, second=(3-192) is negative in the short form, so
        // instead pick a first octet that actually yields 3: solve
        // 3 = ((first-192)<<8)+second+192 => second = 3-192-((first-192)<<8).
        // Simplest valid case is first=192, second=... but 3-192 is negative,
        // so the 2-byte form cannot express 3 without overshooting; instead
        // pad with a trailing unknown subpacket type 100 body to hit a
        // reachable 2-byte-header length window (>=192).
        let mut area = Vec::new();
        // First subpacket: Trust Signature, short-form length 3.
        area.extend_from_slice(&tsig_subpacket(1, 120));
        // Second subpacket: a filler of exactly 195 body bytes, requiring
        // the 2-byte length header (192..=223 window): len=195 =>
        // first-192 = 0 (since (0<<8)+second+192=195 => second=3), first=192.
        area.push(192);
        area.push(3);
        area.push(200); // filler subpacket type (non-tsig, high bit unset)
        area.extend_from_slice(&[0u8; 194]);
        let tsig = parse_trust_signature(&area).unwrap();
        assert_eq!(
            tsig,
            TrustSignature {
                level: 1,
                amount: 120
            }
        );
    }
}
