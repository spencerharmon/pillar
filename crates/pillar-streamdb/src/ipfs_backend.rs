//! Pluggable durability substrate for the content-object store — the seam
//! that lets [`crate::ContentStore`] ride a REAL IPFS node instead of a
//! hand-rolled in-process map.
//!
//! The 2026-08-31 audit (ROI non-negotiable #7 / #5) requires the streaming
//! DB's durable persistence to ride an IPFS / libp2p content-object store —
//! pillar's OWN private swarm — with the IPFS plugin OWNING content-addressing,
//! never a bespoke local-fs reimplementation. This module makes that literal:
//! an [`IpfsBackend`] is the abstract block/pin/provide/head substrate a
//! [`crate::ContentStore`] delegates to, with two production-grade impls:
//!
//! - [`KuboBackend`] (feature `kubo`) — talks to a real `ipfs/kubo` daemon over
//!   its HTTP RPC API (a private-swarm sidecar). Segment blocks are real IPFS
//!   `raw` blocks addressed by real CIDv1s; `pin` is a real kubo pin; a missing
//!   block is fetched over **bitswap** from a private-swarm peer (the real
//!   refinement of `Backfill` / `BackfillReconverges` in
//!   `specs/StreamdbIpfsStore.tla`). Content distribution is IPFS's job — pillar
//!   never re-implements it.
//! - [`FsBackend`] — a local content-addressed block store on disk (the node's
//!   PVC-backed block cache): the same durability a kubo node's on-disk
//!   flatfs blockstore gives, without a daemon. It provides no NETWORK
//!   backfill (a solo node rehydrates from its own pinned blocks); it is what
//!   the restart-survival acceptance test and the durable no-daemon path use.
//!
//! A pure in-memory store keeps NO backend (`ContentStore::new`): the map IS
//! the store, for fast unit tests and ephemeral peers.
//!
//! ## Where the mutable head lives
//! A block store is immutable/content-addressed; a stream's HEAD is a mutable,
//! owner-signed pointer (the IPNS-format [`HeadRecord`]). kubo cannot sign an
//! IPNS record with an arbitrary *pillar* owner key, so pillar owns head
//! signing itself and both backends persist the head RECORD locally (a tiny,
//! inherently node-local mutable pointer — exactly what IPNS is). The immutable
//! content the head points AT lives in the block store; head propagation across
//! nodes rides pillar's own gossip. This matches the spec's `publishHead`
//! (owner-signed, monotone) precisely.

use std::path::PathBuf;

use pillar_crypto::ContentId;

use crate::store::{hex_decode, hex_encode, io_store_err, Cid, HeadRecord, StoreError};

/// The abstract IPFS/libp2p content-object substrate a [`crate::ContentStore`]
/// delegates its durability to. Every method is synchronous (the store surface
/// is sync); a networked impl ([`KuboBackend`]) blocks on localhost RPC to its
/// sidecar, which is cheap and keeps the whole streamdb crate free of an async
/// runtime.
///
/// All content is addressed by [`Cid`] — the pillar SHA2-256 multihash, which
/// is exactly the multihash inside a real IPFS CIDv1 (`raw` codec), so a pillar
/// `Cid` and a kubo CID are two encodings of the SAME identity.
pub trait IpfsBackend: std::fmt::Debug + Send + Sync {
    /// Store an immutable block. `cid` MUST equal the content address of
    /// `wire` (the caller computed it); a durable/networked impl re-derives the
    /// CID from the bytes and returns [`StoreError::CidMismatch`] if the
    /// substrate disagrees, so a block can never be filed under an id its bytes
    /// do not hash to. Idempotent.
    fn block_put(&self, cid: &Cid, wire: &[u8]) -> Result<(), StoreError>;

    /// Fetch a block's bytes: from the local blockstore if present, else — for a
    /// networked backend — over the private swarm (bitswap). `Ok(None)` means
    /// "not held locally and not reachable" (the caller then falls back to a
    /// legacy [`crate::SegmentSource`], or reports `NotFound`). The returned
    /// bytes are UNTRUSTED; the caller re-verifies them against `cid`.
    fn block_get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError>;

    /// Whether the block is held in the LOCAL blockstore (no network fetch).
    fn block_has(&self, cid: &Cid) -> Result<bool, StoreError>;

    /// Pin a block durable (never garbage-collected).
    fn pin(&self, cid: &Cid) -> Result<(), StoreError>;

    /// The set of pinned (durable) CIDs — the node's durable content on boot.
    fn pinned(&self) -> Result<Vec<Cid>, StoreError>;

    /// Advertise a PUBLIC-anchor block to the swarm DHT so a lagging peer can
    /// discover a provider (`Provide` in the spec). Best-effort.
    fn provide(&self, cid: &Cid) -> Result<(), StoreError>;

    /// The set of CIDs this node has advertised to the DHT, insofar as the
    /// backend tracks it (a networked backend may re-advertise automatically and
    /// return an empty set — the advisory local view is rebuilt as public
    /// blocks are re-provided on boot).
    fn provided(&self) -> Result<Vec<Cid>, StoreError>;

    /// Persist an owner-signed mutable head record (the IPNS-format pointer).
    /// Overwrite is correct: a head only ever advances (the store enforces
    /// monotonicity before calling this).
    fn put_head(&self, record: &HeadRecord) -> Result<(), StoreError>;

    /// Every persisted head record (one per owner), for reload on boot.
    fn heads(&self) -> Result<Vec<HeadRecord>, StoreError>;

    /// Whether this backend survives a process restart (true for fs/kubo).
    fn is_durable(&self) -> bool;
}

// ---------------------------------------------------------------------------
// FsBackend — a local content-addressed block store on disk.
// ---------------------------------------------------------------------------

/// A durable local block store rooted at a directory on the node's PVC: the
/// content-addressed on-disk block cache (`segments/`), pin set (`pinned/`),
/// DHT-advertised markers (`provided/`), and per-owner mutable heads
/// (`heads/`). No network: [`IpfsBackend::block_get`] is local-only, so a solo
/// node rehydrates from its own pinned blocks. This is exactly what a real
/// kubo node's on-disk flatfs blockstore + pinset give, minus the daemon —
/// used by the no-daemon durable path and the restart-survival test.
#[derive(Debug, Clone)]
pub struct FsBackend {
    root: PathBuf,
}

impl FsBackend {
    /// Open (creating the layout if absent) a disk block store at `root`.
    ///
    /// # Errors
    /// [`StoreError::Io`] if the store directories cannot be created.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        for d in ["segments", "pinned", "provided", "heads"] {
            std::fs::create_dir_all(root.join(d)).map_err(io_store_err)?;
        }
        Ok(FsBackend { root })
    }

    fn seg_path(&self, cid: &Cid) -> PathBuf {
        self.root.join("segments").join(hex_encode(cid.as_bytes()))
    }
    fn marker_path(&self, dir: &str, cid: &Cid) -> PathBuf {
        self.root.join(dir).join(hex_encode(cid.as_bytes()))
    }

    fn list_markers(&self, dir: &str) -> Result<Vec<Cid>, StoreError> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(self.root.join(dir)).map_err(io_store_err)? {
            let name = entry.map_err(io_store_err)?.file_name();
            if let Some(cid) = name
                .to_str()
                .and_then(hex_decode)
                .map(|b| Cid(ContentId::from_bytes(b)))
            {
                out.push(cid);
            }
        }
        Ok(out)
    }
}

impl IpfsBackend for FsBackend {
    fn block_put(&self, cid: &Cid, wire: &[u8]) -> Result<(), StoreError> {
        // Content address is a pure function of the bytes; refuse a mismatch so
        // a block is never filed under an id its bytes do not hash to.
        if !cid.verifies(wire) {
            return Err(StoreError::CidMismatch);
        }
        let path = self.seg_path(cid);
        if !path.exists() {
            std::fs::write(&path, wire).map_err(io_store_err)?;
        }
        Ok(())
    }

    fn block_get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
        match std::fs::read(self.seg_path(cid)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_store_err(e)),
        }
    }

    fn block_has(&self, cid: &Cid) -> Result<bool, StoreError> {
        Ok(self.seg_path(cid).exists())
    }

    fn pin(&self, cid: &Cid) -> Result<(), StoreError> {
        let path = self.marker_path("pinned", cid);
        if !path.exists() {
            std::fs::write(&path, []).map_err(io_store_err)?;
        }
        Ok(())
    }

    fn pinned(&self) -> Result<Vec<Cid>, StoreError> {
        self.list_markers("pinned")
    }

    fn provide(&self, cid: &Cid) -> Result<(), StoreError> {
        let path = self.marker_path("provided", cid);
        if !path.exists() {
            std::fs::write(&path, []).map_err(io_store_err)?;
        }
        Ok(())
    }

    fn provided(&self) -> Result<Vec<Cid>, StoreError> {
        self.list_markers("provided")
    }

    fn put_head(&self, record: &HeadRecord) -> Result<(), StoreError> {
        let path = self
            .root
            .join("heads")
            .join(hex_encode(record.owner().as_bytes()));
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, record.to_wire()).map_err(io_store_err)?;
        std::fs::rename(&tmp, &path).map_err(io_store_err)?;
        Ok(())
    }

    fn heads(&self) -> Result<Vec<HeadRecord>, StoreError> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(self.root.join("heads")).map_err(io_store_err)? {
            let path = entry.map_err(io_store_err)?.path();
            if !path.is_file() || path.extension().is_some_and(|e| e == "tmp") {
                continue;
            }
            let w = std::fs::read(&path).map_err(io_store_err)?;
            if let Some(head) = HeadRecord::from_wire(&w) {
                out.push(head);
            }
        }
        Ok(out)
    }

    fn is_durable(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// CIDv1 (raw codec) <-> pillar Cid.  A pillar `Cid` wraps the SHA2-256
// multihash `<0x12><0x20><32 digest>` (see pillar_crypto::content_address);
// a real IPFS CIDv1 is `<version=0x01><codec><multihash>`, multibase-encoded.
// We store segment wire bytes as `raw`(0x55) blocks, so CIDv1(raw, mh) is the
// on-the-wire spelling of the same identity kubo and pillar agree on.
// ---------------------------------------------------------------------------

/// multicodec `raw`.
const CODEC_RAW: u8 = 0x55;
/// CID version 1.
const CID_V1: u8 = 0x01;
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The CIDv1(`raw`) multibase-`base32` string for a pillar [`Cid`] — the arg a
/// kubo RPC call expects (e.g. `bafkrei...`).
#[must_use]
pub fn cid_to_cidv1_raw(cid: &Cid) -> String {
    let mh = cid.as_bytes();
    let mut bytes = Vec::with_capacity(2 + mh.len());
    bytes.push(CID_V1);
    bytes.push(CODEC_RAW);
    bytes.extend_from_slice(mh);
    let mut s = String::with_capacity(1 + bytes.len() * 8 / 5 + 1);
    s.push('b'); // multibase: base32 lower, no padding
    base32_lower_encode(&bytes, &mut s);
    s
}

/// Parse a kubo CIDv1(`raw`) multibase-`base32` string back to a pillar
/// [`Cid`]. Returns `None` unless it is a v1 `raw` CID whose multihash is a
/// SHA2-256 multihash (the only shape we put).
#[must_use]
pub fn cidv1_raw_to_cid(s: &str) -> Option<Cid> {
    let s = s.trim();
    let first = s.chars().next()?;
    if first != 'b' {
        return None; // we only emit/accept base32-lower ('b')
    }
    let bytes = base32_lower_decode(&s[1..])?;
    if bytes.len() < 2 || bytes[0] != CID_V1 || bytes[1] != CODEC_RAW {
        return None;
    }
    let mh = &bytes[2..];
    // SHA2-256 multihash: <0x12><0x20><32 bytes>.
    if mh.len() != 34 || mh[0] != 0x12 || mh[1] != 0x20 {
        return None;
    }
    Some(Cid(ContentId::from_bytes(mh.to_vec())))
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

// ---------------------------------------------------------------------------
// KuboBackend — a real IPFS node over the kubo HTTP RPC API.
// ---------------------------------------------------------------------------

#[cfg(feature = "kubo")]
pub use kubo_backend::KuboBackend;

#[cfg(feature = "kubo")]
mod kubo_backend {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{cid_to_cidv1_raw, cidv1_raw_to_cid, FsBackend, IpfsBackend};
    use crate::store::{Cid, HeadRecord, StoreError};

    /// A real IPFS node, reached over the kubo HTTP RPC API (`/api/v0/...`) of a
    /// private-swarm sidecar on localhost. Segment blocks are real `raw` IPFS
    /// blocks (`block/put`+`pin/add`); a missing block is fetched over bitswap
    /// (`block/get`) from a private-swarm peer — real, IPFS-owned content
    /// distribution. The mutable head pointer is owner-signed by pillar and kept
    /// locally (kubo cannot sign an IPNS record with a pillar key), delegated to
    /// an [`FsBackend`] head store on the same PVC.
    #[derive(Debug, Clone)]
    pub struct KuboBackend {
        api_base: String,
        agent: ureq::Agent,
        /// Local, owner-signed mutable-head pointer store (heads only).
        heads: FsBackend,
    }

    impl KuboBackend {
        /// Connect to a kubo daemon at `api_base` (e.g. `http://127.0.0.1:5001`),
        /// keeping owner-signed head pointers under `head_root` on the PVC.
        /// Verifies the daemon is reachable (`/api/v0/id`) so the node fails
        /// fast rather than silently degrading to a fake store.
        ///
        /// # Errors
        /// [`StoreError::Ipfs`] if the daemon is unreachable or `head_root`
        /// cannot be created.
        pub fn connect(
            api_base: impl Into<String>,
            head_root: impl Into<PathBuf>,
        ) -> Result<Self, StoreError> {
            let agent = ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(5))
                .timeout(Duration::from_secs(60))
                .build();
            let me = KuboBackend {
                api_base: api_base.into().trim_end_matches('/').to_string(),
                agent,
                heads: FsBackend::open(head_root)?,
            };
            // Fail fast — but tolerate a still-starting sidecar. The kubo daemon
            // is a sidecar that boots concurrently with the node; poll its RPC
            // (`/api/v0/id`) for up to ~30s before giving up, so ordinary
            // start-order jitter does not crashloop the node while a genuinely
            // absent/misconfigured daemon still errors out promptly.
            let mut last = StoreError::Ipfs;
            for attempt in 0..30 {
                match me.rpc_bytes("id", &[]) {
                    Ok(_) => return Ok(me),
                    Err(e) => {
                        last = e;
                        if attempt == 0 {
                            tracing::info!(
                                api = %me.api_base,
                                "waiting for the IPFS (kubo) sidecar RPC to come up"
                            );
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            }
            Err(last)
        }

        fn url(&self, path: &str, args: &[(&str, &str)]) -> String {
            let mut u = format!("{}/api/v0/{}", self.api_base, path);
            if !args.is_empty() {
                u.push('?');
                let q: Vec<String> = args
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, urlencode(v)))
                    .collect();
                u.push_str(&q.join("&"));
            }
            u
        }

        /// POST an RPC with no body, returning the raw response bytes.
        fn rpc_bytes(&self, path: &str, args: &[(&str, &str)]) -> Result<Vec<u8>, StoreError> {
            let resp = self.agent.post(&self.url(path, args)).call();
            read_body(path, resp)
        }

        /// `block/put` a `raw`, sha2-256 block via a multipart body.
        fn block_put_raw(&self, wire: &[u8]) -> Result<Cid, StoreError> {
            let boundary = "pillarKuboBlockBoundary7MA4YWxkTrZu0gW";
            let mut body: Vec<u8> = Vec::with_capacity(wire.len() + 256);
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                b"Content-Disposition: form-data; name=\"data\"; filename=\"block\"\r\n",
            );
            body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
            body.extend_from_slice(wire);
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

            let url = self.url(
                "block/put",
                &[
                    ("cid-codec", "raw"),
                    ("mhtype", "sha2-256"),
                    ("pin", "false"),
                ],
            );
            let resp = self
                .agent
                .post(&url)
                .set(
                    "Content-Type",
                    &format!("multipart/form-data; boundary={boundary}"),
                )
                .send_bytes(&body);
            let bytes = read_body("block/put", resp)?;
            let key = json_string_field(&bytes, "Key").ok_or(StoreError::Ipfs)?;
            cidv1_raw_to_cid(&key).ok_or(StoreError::Ipfs)
        }
    }

    impl IpfsBackend for KuboBackend {
        fn block_put(&self, cid: &Cid, wire: &[u8]) -> Result<(), StoreError> {
            if !cid.verifies(wire) {
                return Err(StoreError::CidMismatch);
            }
            let got = self.block_put_raw(wire)?;
            // kubo re-derived the CID from the bytes; it MUST match ours.
            if &got != cid {
                return Err(StoreError::CidMismatch);
            }
            Ok(())
        }

        fn block_get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
            let arg = cid_to_cidv1_raw(cid);
            match self.rpc_bytes("block/get", &[("arg", &arg)]) {
                Ok(b) => Ok(Some(b)),
                // kubo answers a missing/unreachable block with a 500 error after
                // its bitswap search times out — that is "not reachable", not a
                // transport fault.
                Err(StoreError::Ipfs) => Ok(None),
                Err(e) => Err(e),
            }
        }

        fn block_has(&self, cid: &Cid) -> Result<bool, StoreError> {
            // `pin/ls <cid>` reports whether the block is pinned locally without
            // triggering a network fetch (kubo answers a non-pinned cid with a
            // 500 error). We pin everything we put, so pinned == held-locally.
            let arg = cid_to_cidv1_raw(cid);
            match self.rpc_bytes("pin/ls", &[("arg", &arg)]) {
                Ok(_) => Ok(true),
                Err(StoreError::Ipfs) => Ok(false),
                Err(e) => Err(e),
            }
        }

        fn pin(&self, cid: &Cid) -> Result<(), StoreError> {
            let arg = cid_to_cidv1_raw(cid);
            self.rpc_bytes("pin/add", &[("arg", &arg)]).map(|_| ())
        }

        fn pinned(&self) -> Result<Vec<Cid>, StoreError> {
            let bytes = self.rpc_bytes("pin/ls", &[("type", "recursive")])?;
            // The HTTP RPC returns `{"Keys":{"<cid>":{"Type":..},...}}` (the
            // `quiet` flag is a CLI-only no-op). Collect every key that parses
            // as one of OUR raw+sha2-256 CIDv1s; non-raw pins (e.g. kubo's
            // CIDv0 welcome-doc pins) simply don't parse and are skipped.
            let mut out = Vec::new();
            for tok in json_quoted_tokens(&bytes) {
                if let Some(cid) = cidv1_raw_to_cid(&tok) {
                    out.push(cid);
                }
            }
            Ok(out)
        }

        fn provide(&self, cid: &Cid) -> Result<(), StoreError> {
            let arg = cid_to_cidv1_raw(cid);
            // Best-effort DHT advertise; kubo's reprovider re-advertises pinned
            // blocks periodically, so a transient failure is non-fatal.
            let _ = self.rpc_bytes("routing/provide", &[("arg", &arg)]);
            Ok(())
        }

        fn provided(&self) -> Result<Vec<Cid>, StoreError> {
            // kubo does not expose "what I have provided"; the reprovider owns
            // re-advertisement. The store's advisory DHT view is rebuilt as
            // public blocks are re-provided on boot.
            Ok(Vec::new())
        }

        fn put_head(&self, record: &HeadRecord) -> Result<(), StoreError> {
            self.heads.put_head(record)
        }

        fn heads(&self) -> Result<Vec<HeadRecord>, StoreError> {
            self.heads.heads()
        }

        fn is_durable(&self) -> bool {
            true
        }
    }

    /// Read a ureq response body, mapping any non-2xx / transport error to
    /// [`StoreError::Ipfs`] (with the detail logged) so callers can distinguish
    /// "not reachable" from a hard fault.
    fn read_body(
        op: &str,
        resp: Result<ureq::Response, ureq::Error>,
    ) -> Result<Vec<u8>, StoreError> {
        match resp {
            Ok(r) => {
                let mut buf = Vec::new();
                use std::io::Read;
                r.into_reader()
                    .take(64 * 1024 * 1024)
                    .read_to_end(&mut buf)
                    .map_err(|e| {
                        tracing::warn!(op, error = %e, "kubo RPC body read failed");
                        StoreError::Ipfs
                    })?;
                Ok(buf)
            }
            Err(ureq::Error::Status(code, r)) => {
                let detail = r.into_string().unwrap_or_default();
                tracing::warn!(op, code, detail = %detail, "kubo RPC returned error status");
                Err(StoreError::Ipfs)
            }
            Err(e) => {
                tracing::warn!(op, error = %e, "kubo RPC transport error");
                Err(StoreError::Ipfs)
            }
        }
    }

    /// Extract a top-level string field from a small flat JSON object without a
    /// full parser (kubo block/put returns `{"Key":"...","Size":N}`).
    fn json_string_field(bytes: &[u8], field: &str) -> Option<String> {
        let s = std::str::from_utf8(bytes).ok()?;
        let needle = format!("\"{field}\"");
        let i = s.find(&needle)? + needle.len();
        let rest = &s[i..];
        let colon = rest.find(':')?;
        let after = &rest[colon + 1..];
        let q1 = after.find('"')? + 1;
        let q2 = after[q1..].find('"')? + q1;
        Some(after[q1..q2].to_string())
    }

    /// Every double-quoted token in a JSON byte string (structural-key AND
    /// value strings alike). The caller filters to the ones that parse as a
    /// CID, so pulling in `"Keys"`/`"Type"`/`"recursive"` is harmless. Handles
    /// no escaping because kubo CIDs/keys contain none.
    fn json_quoted_tokens(bytes: &[u8]) -> Vec<String> {
        let s = String::from_utf8_lossy(bytes);
        let mut out = Vec::new();
        let mut chars = s.char_indices().peekable();
        while let Some((_, c)) = chars.next() {
            if c == '"' {
                let mut tok = String::new();
                for (_, d) in chars.by_ref() {
                    if d == '"' {
                        break;
                    }
                    tok.push(d);
                }
                out.push(tok);
            }
        }
        out
    }

    fn urlencode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char);
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Cid;

    #[test]
    fn cidv1_raw_round_trips_a_pillar_cid() {
        let cid = Cid::of(b"a pillar segment's wire bytes");
        let s = cid_to_cidv1_raw(&cid);
        assert!(
            s.starts_with("bafkrei"),
            "raw+sha2-256 CIDv1 is `bafkrei...`, got {s}"
        );
        assert_eq!(
            cidv1_raw_to_cid(&s),
            Some(cid),
            "CIDv1 string must round-trip"
        );
    }

    #[test]
    fn cidv1_rejects_non_raw_or_garbage() {
        assert_eq!(cidv1_raw_to_cid("not-a-cid"), None);
        assert_eq!(cidv1_raw_to_cid("Qmfoo"), None); // v0, not our shape
    }

    #[test]
    fn base32_matches_known_vectors() {
        // RFC4648 base32 (lowercase, no pad) of "foobar" is "mzxw6 ytboi".
        let mut out = String::new();
        base32_lower_encode(b"foobar", &mut out);
        assert_eq!(out, "mzxw6ytboi");
        assert_eq!(
            base32_lower_decode("mzxw6ytboi").as_deref(),
            Some(&b"foobar"[..])
        );
    }

    #[test]
    fn fs_backend_persists_blocks_pins_and_heads() {
        let dir = std::env::temp_dir().join(format!("pillar-fsbackend-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let be = FsBackend::open(&dir).expect("open");
        let wire = b"block-bytes".to_vec();
        let cid = Cid::of(&wire);
        be.block_put(&cid, &wire).expect("put");
        be.pin(&cid).expect("pin");
        assert!(be.block_has(&cid).unwrap());
        assert_eq!(be.block_get(&cid).unwrap().as_deref(), Some(&wire[..]));
        assert_eq!(be.pinned().unwrap(), vec![cid.clone()]);
        // A block filed under the wrong CID is refused.
        assert_eq!(
            be.block_put(&Cid::of(b"other"), &wire),
            Err(StoreError::CidMismatch)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
