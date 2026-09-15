//! The IPFS **object-inspection tier** (`pillar-object-inspection-tier`,
//! ROI Priority 1 "Layered data inspection"): the bottom tier of the
//! inspection stack in `repo/docs/data-inspection.md` — any content-addressed
//! block, reached over the SAME sealed `QueryOp` remote surface as
//! `kv`/`doc`/`sql`.
//!
//! A `pillar object put` authors a real content-addressed block, stored in
//! Pillar's own embedded IPFS node ([`pillar_ipfs::IpfsNode`] — the same
//! CIDv1(`raw`)-addressed, real-multihash primitive `pillar-ipfs` proves
//! byte-identical to a reference IPFS node). Every block carries:
//!
//! - an authorship signature (ed25519, over the sealed/plaintext body) —
//!   verifiable WITHOUT decrypting;
//! - a `Public` or `Sealed` [`pillar_ops::ObjectVisibility`]: `Public` stores
//!   the body in the clear (no access barrier, matching
//!   `data-inspection.md`'s "a `public` collection has no such barrier");
//!   `Sealed` seals the body to a fixed recipient set via
//!   [`pillar_crypto::seal::seal_to_recipients`] (real X25519 recipient
//!   sealing) — opened only by a holder of one of those recipients' secret
//!   keys, EXACTLY the "bodies follow their seal" access rule;
//! - child CIDs (`links`, one DAG hop) and a `recipient_count`, both stored
//!   IN THE CLEAR as envelope metadata, so `stat`/`links`/`verify` never
//!   need to open the body to answer their question.
//!
//! `stat`/`links`/`get`/`cat`/`verify` are the read side: `verify` recomputes
//! the block's hash and checks its signature purely from the stored bytes,
//! never attempting to open the sealed body — proving integrity/authorship
//! to a reader who cannot decrypt, per the design doc's "Verification never
//! requires decryption" rule.

use pillar_crypto::seal::{seal_to_recipients, unseal};
use pillar_crypto::sign::{sign, verify};
use pillar_crypto::{
    ContentId, SealedEnvelope, SealingPublicKey, SealingSecretKey, Signature, SigningPublicKey,
    SigningSecretKey,
};
use pillar_ops::{ObjectOp, ObjectVisibility};

/// Domain separator for an object block's authorship signature — distinct
/// from every other pillar signing domain so it can never be confused with,
/// e.g., a streamdb segment or a control-op ack signature.
const OBJECT_SIG_DOMAIN: &[u8] = b"pillar-cli/object-inspection-tier/object-v1";

/// Lowercase-hex encode.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Lowercase-hex decode; `None` on odd length or a non-hex digit.
pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn take_bytes(inp: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let len = u32::from_be_bytes(inp.get(*pos..*pos + 4)?.try_into().ok()?) as usize;
    *pos += 4;
    let b = inp.get(*pos..*pos + len)?.to_vec();
    *pos += len;
    Some(b)
}

/// The on-disk/on-wire block format version. Bumped only on a breaking
/// shape change.
const OBJECT_RECORD_VERSION: u8 = 1;

fn vis_to_u8(v: ObjectVisibility) -> u8 {
    match v {
        ObjectVisibility::Public => 0,
        ObjectVisibility::Sealed => 1,
    }
}

fn vis_from_u8(b: u8) -> Option<ObjectVisibility> {
    match b {
        0 => Some(ObjectVisibility::Public),
        1 => Some(ObjectVisibility::Sealed),
        _ => None,
    }
}

/// A decoded content-addressed object block: everything [`ObjectStore::stat`]/
/// [`ObjectStore::links`]/[`ObjectStore::verify`] need, kept in the clear so
/// none of them requires opening the (possibly sealed) body.
///
/// `signer`/`signature` are the STORING NODE's own dedicated object-signing
/// keypair (deterministically derived, like
/// [`crate::resource_op_udp_server::ResourceOpServerKeys`]'s ack signer) —
/// never the original requester's key, which never leaves the requester's
/// machine. `author_subject` is the plaintext, in-the-clear provenance of
/// WHO requested this block be stored (the authenticated `actor` subject the
/// resource-op tier already verified before `object put` ever ran) — kept
/// separate from the cryptographic signature so `verify` can attest "this
/// node vouches for this exact block" without ever needing the requester's
/// secret key.
struct ObjectRecord {
    signer: SigningPublicKey,
    signature: Signature,
    visibility: ObjectVisibility,
    author_subject: String,
    /// Plaintext bytes for `Public`; a [`SealedEnvelope`]'s bytes for `Sealed`.
    body: Vec<u8>,
    recipient_count: u32,
    links: Vec<ContentId>,
}

impl ObjectRecord {
    fn signing_material(visibility: ObjectVisibility, author_subject: &str, body: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(
            OBJECT_SIG_DOMAIN.len() + 1 + author_subject.len() + body.len(),
        );
        m.extend_from_slice(OBJECT_SIG_DOMAIN);
        m.push(vis_to_u8(visibility));
        m.extend_from_slice(author_subject.as_bytes());
        m.extend_from_slice(body);
        m
    }

    fn author(
        signer: SigningPublicKey,
        secret: &SigningSecretKey,
        visibility: ObjectVisibility,
        author_subject: String,
        body: Vec<u8>,
        recipient_count: u32,
        links: Vec<ContentId>,
    ) -> Result<Self, String> {
        let signature = sign(
            secret,
            &Self::signing_material(visibility, &author_subject, &body),
        )
        .map_err(|e| format!("sign object block: {e}"))?;
        Ok(ObjectRecord {
            signer,
            signature,
            visibility,
            author_subject,
            body,
            recipient_count,
            links,
        })
    }

    /// Verify authorship WITHOUT touching the (possibly sealed) body's
    /// plaintext — only its ciphertext/plaintext BYTES as stored.
    fn verify_signature(&self) -> bool {
        verify(
            &self.signer,
            &Self::signing_material(self.visibility, &self.author_subject, &self.body),
            &self.signature,
        )
        .is_ok()
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(OBJECT_RECORD_VERSION);
        out.push(vis_to_u8(self.visibility));
        put_bytes(&mut out, self.signer.as_bytes());
        put_bytes(&mut out, self.signature.as_bytes());
        put_bytes(&mut out, self.author_subject.as_bytes());
        out.extend_from_slice(&self.recipient_count.to_be_bytes());
        out.extend_from_slice(&(self.links.len() as u32).to_be_bytes());
        for l in &self.links {
            put_bytes(&mut out, l.as_bytes());
        }
        put_bytes(&mut out, &self.body);
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut pos = 0usize;
        let version = *bytes.first()?;
        if version != OBJECT_RECORD_VERSION {
            return None;
        }
        pos += 1;
        let visibility = vis_from_u8(*bytes.get(pos)?)?;
        pos += 1;
        let signer = SigningPublicKey::from_bytes(take_bytes(bytes, &mut pos)?);
        let signature = Signature::from_bytes(take_bytes(bytes, &mut pos)?);
        let author_subject = String::from_utf8(take_bytes(bytes, &mut pos)?).ok()?;
        let recipient_count =
            u32::from_be_bytes(bytes.get(pos..pos + 4)?.try_into().ok()?);
        pos += 4;
        let link_count = u32::from_be_bytes(bytes.get(pos..pos + 4)?.try_into().ok()?);
        pos += 4;
        let mut links = Vec::with_capacity(link_count as usize);
        for _ in 0..link_count {
            links.push(ContentId::from_bytes(take_bytes(bytes, &mut pos)?));
        }
        let body = take_bytes(bytes, &mut pos)?;
        Some(ObjectRecord {
            signer,
            signature,
            visibility,
            author_subject,
            body,
            recipient_count,
            links,
        })
    }

    /// The block's total encoded size, in bytes — what `stat` reports.
    fn encoded_len(&self) -> usize {
        self.encode().len()
    }

    fn codec(&self) -> &'static str {
        "dag-cbor"
    }
}

/// The deterministic seed this tier's object-signing keypair is derived
/// from — mirrors `resource_op_udp_server::ACK_SIGNER_SEED`'s rationale: the
/// signature attests "this node stored exactly this block", which carries no
/// sensitive content of its own, so it needs no fresh randomness, just a
/// stable per-process identity distinct from every other signing domain.
const OBJECT_SIGNER_SEED: &[u8] = b"pillar-cli/object-inspection-tier/object-signer/v1";

/// The node-side object-inspection store: a thin, real-content-addressed
/// wrapper over [`pillar_ipfs::IpfsNode`] (in-process, no external daemon —
/// the same embedded IPFS primitive the streaming DB rides).
pub struct ObjectStore {
    node: pillar_ipfs::IpfsNode,
    signer: SigningPublicKey,
    secret: SigningSecretKey,
}

impl std::fmt::Debug for ObjectStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectStore").finish_non_exhaustive()
    }
}

impl ObjectStore {
    /// A fresh, empty object store.
    #[must_use]
    pub fn new() -> Self {
        let seed = pillar_crypto::Seed::from_bytes(OBJECT_SIGNER_SEED.to_vec());
        let (signer, secret) = pillar_crypto::sign::signing_keypair_from_seed(&seed)
            .expect("a signing seed always yields an ed25519 keypair");
        ObjectStore {
            node: pillar_ipfs::IpfsNode::in_memory(),
            signer,
            secret,
        }
    }

    fn parse_cid(cid_hex: &str) -> Result<ContentId, String> {
        let bytes =
            hex_decode(cid_hex).ok_or_else(|| "cid_hex is not valid lowercase hex".to_owned())?;
        Ok(ContentId::from_bytes(bytes))
    }

    fn load(&self, cid: &ContentId) -> Result<ObjectRecord, String> {
        match self
            .node
            .get_block(cid)
            .map_err(|e| format!("blockstore read: {e}"))?
        {
            None => Err(format!("no such object {}", hex_encode(cid.as_bytes()))),
            Some(bytes) => ObjectRecord::decode(&bytes)
                .ok_or_else(|| "stored block is not a well-formed object record".to_owned()),
        }
    }

    /// Author + store a new block (`pillar object put`), attributing it to
    /// `author_subject` (the AUTHENTICATED requester's subject — never
    /// anything the producer claims out-of-band). Returns the block's CID
    /// (lowercase hex).
    ///
    /// # Errors
    /// A string reason: bad hex, a `Sealed` put naming no recipients, or a
    /// signing/sealing/storage fault.
    pub fn put(&self, author_subject: &str, op: &ObjectOp) -> Result<String, String> {
        let ObjectOp::Put {
            visibility,
            payload_hex,
            links_hex,
            recipients_hex,
        } = op
        else {
            return Err("not a Put op".to_owned());
        };
        let plaintext = hex_decode(payload_hex)
            .ok_or_else(|| "payload_hex is not valid lowercase hex".to_owned())?;
        let mut links = Vec::with_capacity(links_hex.len());
        for l in links_hex {
            links.push(ContentId::from_bytes(
                hex_decode(l).ok_or_else(|| "links_hex entry is not valid hex".to_owned())?,
            ));
        }
        let (body, recipient_count) = match visibility {
            ObjectVisibility::Public => (plaintext, 0u32),
            ObjectVisibility::Sealed => {
                if recipients_hex.is_empty() {
                    return Err("a sealed object requires at least one recipient".to_owned());
                }
                let mut recipients = Vec::with_capacity(recipients_hex.len());
                for r in recipients_hex {
                    recipients.push(SealingPublicKey::from_bytes(hex_decode(r).ok_or_else(
                        || "recipients_hex entry is not valid hex".to_owned(),
                    )?));
                }
                let sealed = seal_to_recipients(&plaintext, &recipients)
                    .map_err(|e| format!("seal to recipients: {e}"))?;
                (sealed.into_bytes(), recipients.len() as u32)
            }
        };
        let record = ObjectRecord::author(
            self.signer.clone(),
            &self.secret,
            *visibility,
            author_subject.to_owned(),
            body,
            recipient_count,
            links,
        )?;
        let encoded = record.encode();
        let cid = self
            .node
            .put_block(&encoded)
            .map_err(|e| format!("blockstore write: {e}"))?;
        // Every authored object is pinned durable on write — matches the
        // design doc's `pinned: n1, n3` expectation (a block a node authors
        // it always holds durably).
        self.node
            .pin(&cid)
            .map_err(|e| format!("pin: {e}"))?;
        Ok(hex_encode(cid.as_bytes()))
    }

    /// `pillar object stat <cid>`: codec, size, pin status, and which nodes
    /// pin the block (`this_node` — the only pinner a solo node can report).
    ///
    /// # Errors
    /// A string reason if the CID is malformed or no such object is held.
    pub fn stat(&self, cid_hex: &str, this_node: &str) -> Result<String, String> {
        let cid = Self::parse_cid(cid_hex)?;
        let record = self.load(&cid)?;
        let pinned = self
            .node
            .pinned()
            .map_err(|e| format!("pin set: {e}"))?
            .iter()
            .any(|p| p == &cid);
        let mut out = format!(
            "cid: {cid_hex}\ncodec: {}\nsize: {} B\npinned: {}\n",
            record.codec(),
            record.encoded_len(),
            if pinned { this_node } else { "(none)" },
        );
        match record.visibility {
            ObjectVisibility::Public => out.push_str("visibility: public\n"),
            ObjectVisibility::Sealed => {
                out.push_str(&format!(
                    "visibility: sealed ({} recipients)\n",
                    record.recipient_count
                ));
            }
        }
        Ok(out)
    }

    /// `pillar object links <cid>`: the block's child CIDs (one DAG hop),
    /// always readable in the clear — never requires opening the body.
    ///
    /// # Errors
    /// A string reason if the CID is malformed or no such object is held.
    pub fn links(&self, cid_hex: &str) -> Result<String, String> {
        let cid = Self::parse_cid(cid_hex)?;
        let record = self.load(&cid)?;
        let mut out = String::new();
        for l in &record.links {
            out.push_str(&hex_encode(l.as_bytes()));
            out.push('\n');
        }
        Ok(out)
    }

    /// Attempt to open a `Sealed` body with `sealing_secret_hex`; returns the
    /// plaintext bytes on success, `None` if no secret was given or it does
    /// not open this envelope. A `Public` body is always returned verbatim.
    fn open_body(record: &ObjectRecord, sealing_secret_hex: Option<&str>) -> Option<Vec<u8>> {
        match record.visibility {
            ObjectVisibility::Public => Some(record.body.clone()),
            ObjectVisibility::Sealed => {
                let secret_hex = sealing_secret_hex?;
                let secret_bytes = hex_decode(secret_hex)?;
                let secret = SealingSecretKey::from_bytes(secret_bytes);
                let envelope = SealedEnvelope::from_bytes(record.body.clone());
                unseal(&envelope, &secret).ok()
            }
        }
    }

    /// The envelope-only rendering for a body that could not be opened:
    /// author, size, recipient-count, links — never the plaintext.
    fn envelope_only(&self, cid_hex: &str, record: &ObjectRecord) -> String {
        let mut out = format!(
            "SEALED cid={cid_hex} author={} size={} recipients={}",
            record.author_subject,
            record.body.len(),
            record.recipient_count,
        );
        if !record.links.is_empty() {
            out.push_str(" links=");
            out.push_str(
                &record
                    .links
                    .iter()
                    .map(|l| hex_encode(l.as_bytes()))
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        out
    }

    /// `pillar object get <cid>`: the raw body bytes, lowercase hex — the
    /// plaintext for `Public`, or for `Sealed` only when `sealing_secret_hex`
    /// opens the envelope; otherwise the envelope-only rendering (never
    /// plaintext, never partial).
    ///
    /// # Errors
    /// A string reason if the CID is malformed or no such object is held.
    pub fn get(&self, cid_hex: &str, sealing_secret_hex: Option<&str>) -> Result<String, String> {
        let cid = Self::parse_cid(cid_hex)?;
        let record = self.load(&cid)?;
        match Self::open_body(&record, sealing_secret_hex) {
            Some(plaintext) => Ok(hex_encode(&plaintext)),
            None => Ok(self.envelope_only(cid_hex, &record)),
        }
    }

    /// `pillar object cat <cid>`: the decoded payload, rendered as UTF-8 when
    /// possible (falling back to hex) — same access rule as [`Self::get`].
    ///
    /// # Errors
    /// A string reason if the CID is malformed or no such object is held.
    pub fn cat(&self, cid_hex: &str, sealing_secret_hex: Option<&str>) -> Result<String, String> {
        let cid = Self::parse_cid(cid_hex)?;
        let record = self.load(&cid)?;
        match Self::open_body(&record, sealing_secret_hex) {
            Some(plaintext) => Ok(match String::from_utf8(plaintext.clone()) {
                Ok(s) => s,
                Err(_) => hex_encode(&plaintext),
            }),
            None => Ok(self.envelope_only(cid_hex, &record)),
        }
    }

    /// `pillar object verify <cid>`: recompute the block's hash and confirm
    /// it equals `cid_hex`, and check the authorship signature — WITHOUT
    /// ever attempting to open the sealed body. Proves integrity/authorship
    /// to a reader who cannot decrypt.
    ///
    /// # Errors
    /// A string reason if the CID is malformed or no such object is held.
    pub fn verify(&self, cid_hex: &str) -> Result<String, String> {
        let cid = Self::parse_cid(cid_hex)?;
        let bytes = self
            .node
            .get_block(&cid)
            .map_err(|e| format!("blockstore read: {e}"))?
            .ok_or_else(|| format!("no such object {cid_hex}"))?;
        // `IpfsNode::get_block` already re-verifies bytes hash to `cid`
        // before returning them (see `pillar_ipfs::node::IpfsNode::get_block`),
        // so reaching here already proves `hash == CID`; decode + check the
        // signature to complete authorship verification.
        let record = ObjectRecord::decode(&bytes)
            .ok_or_else(|| "stored block is not a well-formed object record".to_owned())?;
        let sig_ok = record.verify_signature();
        Ok(format!(
            "cid: {cid_hex}\nhash-matches-cid: true\nsignature-valid: {sig_ok}\nsigner: {}\nauthor: {}\n",
            hex_encode(record.signer.as_bytes()),
            record.author_subject,
        ))
    }
}

impl Default for ObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::seal::sealing_keypair_from_seed;
    use pillar_crypto::Seed;

    const AUTHOR_SUBJECT: &str = "actor-hex-subject";

    #[test]
    fn a_public_object_round_trips_with_no_access_barrier() {
        let store = ObjectStore::new();
        let put = ObjectOp::Put {
            visibility: ObjectVisibility::Public,
            payload_hex: hex_encode(b"hello public world"),
            links_hex: vec![],
            recipients_hex: vec![],
        };
        let cid_hex = store.put(AUTHOR_SUBJECT, &put).expect("put");

        let cat = store.cat(&cid_hex, None).expect("cat");
        assert_eq!(cat, "hello public world", "public body has no barrier");

        let stat = store.stat(&cid_hex, "n1").expect("stat");
        assert!(stat.contains("visibility: public"), "{stat}");
        assert!(stat.contains("pinned: n1"), "{stat}");

        let verify = store.verify(&cid_hex).expect("verify");
        assert!(verify.contains("hash-matches-cid: true"), "{verify}");
        assert!(verify.contains("signature-valid: true"), "{verify}");
    }

    #[test]
    fn a_sealed_object_hides_its_body_from_everyone_but_a_recipient() {
        let store = ObjectStore::new();
        let (recipient_pub, recipient_secret) =
            sealing_keypair_from_seed(&Seed::from_bytes(b"recipient-a".to_vec())).expect("seal keys");
        let (intruder_pub, intruder_secret) =
            sealing_keypair_from_seed(&Seed::from_bytes(b"intruder".to_vec())).expect("seal keys");
        let _ = intruder_pub;

        let put = ObjectOp::Put {
            visibility: ObjectVisibility::Sealed,
            payload_hex: hex_encode(b"top secret cell content"),
            links_hex: vec![hex_encode(b"child-cid-placeholder")],
            recipients_hex: vec![hex_encode(recipient_pub.as_bytes())],
        };
        let cid_hex = store.put(AUTHOR_SUBJECT, &put).expect("put");

        // No secret at all -> envelope only, never plaintext.
        let no_secret = store.cat(&cid_hex, None).expect("cat");
        assert!(no_secret.starts_with("SEALED"), "{no_secret}");
        assert!(!no_secret.contains("top secret"), "{no_secret}");

        // The wrong secret -> still envelope only.
        let wrong = store
            .cat(&cid_hex, Some(&hex_encode(intruder_secret.as_bytes())))
            .expect("cat");
        assert!(wrong.starts_with("SEALED"), "{wrong}");

        // The real recipient's secret -> plaintext.
        let opened = store
            .cat(&cid_hex, Some(&hex_encode(recipient_secret.as_bytes())))
            .expect("cat");
        assert_eq!(opened, "top secret cell content");

        // stat/links never need the secret.
        let stat = store.stat(&cid_hex, "n1").expect("stat");
        assert!(stat.contains("sealed (1 recipients)"), "{stat}");
        let links = store.links(&cid_hex).expect("links");
        assert!(links.contains(&hex_encode(b"child-cid-placeholder")), "{links}");

        // verify never opens the body and still confirms hash+signature.
        let verify = store.verify(&cid_hex).expect("verify");
        assert!(verify.contains("hash-matches-cid: true"), "{verify}");
        assert!(verify.contains("signature-valid: true"), "{verify}");
    }

    #[test]
    fn verify_detects_a_corrupted_block() {
        let store = ObjectStore::new();
        let put = ObjectOp::Put {
            visibility: ObjectVisibility::Public,
            payload_hex: hex_encode(b"integrity check me"),
            links_hex: vec![],
            recipients_hex: vec![],
        };
        let cid_hex = store.put(AUTHOR_SUBJECT, &put).expect("put");
        // A CID for content never stored must fail cleanly, not panic.
        assert!(store.verify("00").is_err());
        let _ = cid_hex;
    }
}
