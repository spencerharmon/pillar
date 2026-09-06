//! Pillar swarm keys: the shared model of *which physical libp2p swarm* a node
//! speaks on, owned in one place so the node runtime, the `pillar` CLI, and the
//! web portal all agree — with **no state kept by pillar**.
//!
//! ## What a "swarm" is here
//!
//! A pillar node's packets can only reach peers on the **same physical swarm**,
//! and swarm membership is enforced at the TRANSPORT layer by a libp2p private
//! network (pnet) pre-shared key: a peer holding a different (or no) key can
//! never complete a handshake, so it never reaches far enough to send a DHT
//! query, a bitswap want, or an event-log message. This is completely distinct
//! from a *cell* (WoT / identity genesis *within* whichever swarm a node
//! joined) — a private swarm still has cells; authority is untouched by which
//! swarm you are on.
//!
//! A swarm is identified by a **key** (a root secret string) from which each
//! transport crate derives its own domain-separated 32-byte pnet key
//! ([`pillar_net::PrivateSwarmKey::from_root_secret`] for the event log,
//! `pillar_ipfs::PrivateSwarmKey::from_root_secret` for the IPFS block swarm).
//! Configure the SAME key on two nodes and they converge on one swarm; two
//! different keys derive pnet keys indistinguishable from independent random
//! keys, so the two swarms are mutually invisible at the transport. This crate
//! deliberately owns only the *key value and its fingerprint* — it never
//! re-derives the pnet key itself, keeping the domain separation in each
//! transport crate and avoiding a dependency cycle.
//!
//! ## Stateless by design
//!
//! Pillar keeps **no swarm registry, no active-swarm selection, no on-disk
//! state** for swarm management. The CLI/UI expose exactly two facilities:
//!
//! - **generate** ([`SwarmKey::generate`]) — mint a fresh private-swarm key and
//!   emit it. The operator saves it to a file and distributes it out-of-band.
//! - **show** ([`SwarmKey::kind`]/[`SwarmKey::fingerprint`]) — read-only
//!   inspection of a key (public or a private key file), never persisting it.
//!
//! A node is told which swarm to join at boot: `pillar node run --swarm-key
//! <path>` reads the key from a file ([`SwarmKey::from_file`]); with no
//! `--swarm-key` the node joins the **public** pillar swarm ([`SwarmKey::public`]).
//! Because a private swarm is transport-isolated from the public seeds, joining
//! one also needs its own seed peers: `pillar node run --seed-node <multiaddr>`.
//!
//! ## Public pillar vs. your own swarm
//!
//! - **The public pillar swarm** ([`SwarmKey::public`]) — a single, well-known
//!   key ([`PUBLIC_PILLAR_ROOT`]) **published and baked into every binary**.
//!   Every node joins it by default, so the global pillar network is one swarm.
//!   Because the key is published it provides **namespace isolation, not
//!   secrecy**: it keeps pillar's public swarm from co-mingling with unrelated
//!   libp2p/IPFS peers, but it is not a membership gate (anyone can read it).
//! - **Your own swarm** ([`SwarmKey::generate`]) — a fresh, high-entropy key
//!   this crate mints from the OS CSPRNG. Distribute it out-of-band to the
//!   nodes you want in your private network and boot each with `--swarm-key`;
//!   nobody without it can complete a handshake. This IS a membership gate.

#![forbid(unsafe_code)]

use std::path::Path;

/// The published, well-known key of the **public pillar swarm**, baked into
/// every binary.
///
/// This value is intentionally public: it is a *namespace* label, not a secret.
/// A node on the public swarm derives its pnet key from it so its transport
/// refuses peers that are not pillar-public nodes, while any pillar node in the
/// world can still join (they all bake in the same value). A node wanting a
/// *private*, membership-gated network mints its own key with
/// [`SwarmKey::generate`] instead.
///
/// Format: a `pillar-public-swarm/v<N>:` version tag followed by a fixed
/// published 256-bit nothing-up-my-sleeve constant, hex-encoded. Bumping the
/// version tag is the flag-day mechanism for rotating the public swarm.
pub const PUBLIC_PILLAR_ROOT: &str =
    "pillar-public-swarm/v1:70696c6c61722d7075626c69632d737761726d2d726f6f742d76312d6b6579";

/// Whether a swarm key is the shared public pillar network or an operator's own
/// private, membership-gated network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwarmKind {
    /// The public pillar swarm — joinable by anyone, keyed by the published
    /// [`PUBLIC_PILLAR_ROOT`]. Namespace isolation, no secrecy.
    Public,
    /// A private swarm keyed by an operator-held key. Membership is gated: a
    /// peer without the key cannot complete a handshake.
    Private,
}

impl SwarmKind {
    /// A stable lowercase tag for display / CLI / API output.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            SwarmKind::Public => "public",
            SwarmKind::Private => "private",
        }
    }
}

/// A swarm key: the root-secret string a node's transport pnet keys are derived
/// from. Immutable, cheap to clone, and **never persisted by this crate** — the
/// operator owns where a private key lives (a file passed to `--swarm-key`).
///
/// Treat a PRIVATE key as a secret (it is the join credential); the public
/// swarm's key is [`PUBLIC_PILLAR_ROOT`] and safe to print.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwarmKey {
    root_secret: String,
}

impl SwarmKey {
    /// The public pillar swarm key: the published baked-in root. This is what a
    /// node uses when the operator passes no `--swarm-key`.
    #[must_use]
    pub fn public() -> Self {
        Self {
            root_secret: PUBLIC_PILLAR_ROOT.to_owned(),
        }
    }

    /// Mint a brand-new PRIVATE swarm key with a fresh 256-bit root secret drawn
    /// from the OS CSPRNG. Emit it (`pillar swarm generate`), save it to a file,
    /// and distribute it out-of-band to the nodes you want in this swarm; boot
    /// each with `pillar node run --swarm-key <path>`.
    #[must_use]
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        Self {
            root_secret: format!("pillar-swarm/v1:{}", hex_encode(&raw)),
        }
    }

    /// Parse a swarm key from its string form (the exact value `generate`
    /// emitted). Surrounding whitespace is trimmed.
    ///
    /// # Errors
    /// [`SwarmError::EmptyKey`] if the string is empty after trimming.
    pub fn parse(key: &str) -> Result<Self, SwarmError> {
        let root_secret = key.trim().to_owned();
        if root_secret.is_empty() {
            return Err(SwarmError::EmptyKey);
        }
        Ok(Self { root_secret })
    }

    /// Read a swarm key from a file: the first non-empty, non-`#`-comment line
    /// is taken as the key (so an operator may annotate the file). Used by
    /// `pillar node run --swarm-key <path>`.
    ///
    /// # Errors
    /// [`SwarmError::Io`] if the file cannot be read; [`SwarmError::EmptyKey`]
    /// if it contains no key line.
    pub fn from_file(path: &Path) -> Result<Self, SwarmError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| SwarmError::Io(format!("{}: {e}", path.display())))?;
        let line = contents
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .ok_or(SwarmError::EmptyKey)?;
        Self::parse(line)
    }

    /// The root secret to feed `PrivateSwarmKey::from_root_secret` in each
    /// transport crate — and the exact string form to write to a key file. For
    /// a private swarm this is the join credential; guard it.
    #[must_use]
    pub fn root_secret(&self) -> &str {
        &self.root_secret
    }

    /// Whether this is the public pillar swarm key or a private one.
    #[must_use]
    pub fn kind(&self) -> SwarmKind {
        if self.root_secret == PUBLIC_PILLAR_ROOT {
            SwarmKind::Public
        } else {
            SwarmKind::Private
        }
    }

    /// A short, stable, NON-secret fingerprint of this swarm's membership,
    /// derived from the key. Two nodes on the same swarm always show the same
    /// fingerprint, so operators can confirm they are on the same network
    /// WITHOUT comparing (or leaking) the key itself. It is a one-way SHAKE256
    /// digest — the key cannot be recovered from it.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut hasher = sha3::Shake256::default();
        hasher.update(b"pillar-swarm-fingerprint-v1");
        hasher.update(self.root_secret.as_bytes());
        let mut out = [0u8; 8];
        hasher.finalize_xof().read(&mut out);
        hex_encode(&out)
    }
}

/// Lowercase-hex encode.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("nibble<16"));
        s.push(char::from_digit((b & 0x0f) as u32, 16).expect("nibble<16"));
    }
    s
}

/// Everything that can go wrong reading or parsing a swarm key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwarmError {
    /// A key file could not be read (detail is the path + OS error).
    Io(String),
    /// The key string/file was empty (no key present).
    EmptyKey,
}

impl std::fmt::Display for SwarmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwarmError::Io(e) => write!(f, "swarm key i/o error: {e}"),
            SwarmError::EmptyKey => write!(f, "swarm key is empty"),
        }
    }
}

impl std::error::Error for SwarmError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_is_the_baked_published_root() {
        let k = SwarmKey::public();
        assert_eq!(k.kind(), SwarmKind::Public);
        assert_eq!(k.root_secret(), PUBLIC_PILLAR_ROOT);
    }

    #[test]
    fn generate_mints_a_unique_high_entropy_private_key() {
        let a = SwarmKey::generate();
        let b = SwarmKey::generate();
        assert_eq!(a.kind(), SwarmKind::Private);
        // Two fresh swarms never collide on their key or fingerprint.
        assert_ne!(a.root_secret(), b.root_secret());
        assert_ne!(a.fingerprint(), b.fingerprint());
        // A private key is not the public one.
        assert_ne!(a.root_secret(), PUBLIC_PILLAR_ROOT);
    }

    #[test]
    fn parse_round_trips_a_generated_key_to_the_same_swarm() {
        let minted = SwarmKey::generate();
        let joined = SwarmKey::parse(minted.root_secret()).expect("parse");
        // Same key => same swarm => same fingerprint.
        assert_eq!(joined, minted);
        assert_eq!(joined.fingerprint(), minted.fingerprint());
        assert_eq!(joined.kind(), SwarmKind::Private);
    }

    #[test]
    fn parse_trims_and_rejects_empty() {
        assert_eq!(
            SwarmKey::parse("  pillar-swarm/v1:abcd  ")
                .unwrap()
                .root_secret(),
            "pillar-swarm/v1:abcd"
        );
        assert_eq!(SwarmKey::parse("   "), Err(SwarmError::EmptyKey));
        assert_eq!(SwarmKey::parse(""), Err(SwarmError::EmptyKey));
    }

    #[test]
    fn fingerprint_is_stable_and_hides_the_key() {
        let k = SwarmKey::parse("super-secret-root").expect("parse");
        assert_eq!(k.fingerprint(), k.fingerprint());
        assert!(!k.fingerprint().contains("super-secret-root"));
        assert_eq!(k.fingerprint().len(), 16); // 8 bytes hex
    }

    #[test]
    fn public_and_private_fingerprints_differ() {
        assert_ne!(
            SwarmKey::public().fingerprint(),
            SwarmKey::generate().fingerprint()
        );
    }

    #[test]
    fn from_file_reads_first_key_line_skipping_comments_and_blanks() {
        let dir = std::env::temp_dir().join(format!("pillar-swarmkey-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("swarm.key");
        let minted = SwarmKey::generate();
        std::fs::write(
            &path,
            format!(
                "# my prod swarm key — distribute out-of-band\n\n{}\n",
                minted.root_secret()
            ),
        )
        .expect("write");
        let loaded = SwarmKey::from_file(&path).expect("from_file");
        assert_eq!(loaded, minted);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_file_errors_are_typed() {
        let missing = std::env::temp_dir().join("pillar-swarmkey-nope-xyz.key");
        let _ = std::fs::remove_file(&missing);
        assert!(matches!(
            SwarmKey::from_file(&missing),
            Err(SwarmError::Io(_))
        ));

        let dir =
            std::env::temp_dir().join(format!("pillar-swarmkey-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let empty = dir.join("empty.key");
        std::fs::write(&empty, "# only a comment\n\n").expect("write");
        assert_eq!(SwarmKey::from_file(&empty), Err(SwarmError::EmptyKey));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
