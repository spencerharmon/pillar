//! Pillar swarm membership: the shared model of *which physical libp2p swarm*
//! a node speaks on, owned in one place so the node runtime, the `pillar` CLI,
//! and the web portal all agree.
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
//! A swarm is identified by a **root secret**: a single operator-chosen string
//! from which each transport crate derives its own domain-separated 32-byte
//! pnet key ([`pillar_net::PrivateSwarmKey::from_root_secret`] for the event
//! log, `pillar_ipfs::PrivateSwarmKey::from_root_secret` for the IPFS block
//! swarm). Configure the SAME root on two nodes and they converge on one
//! swarm; two different roots derive keys indistinguishable from independent
//! random keys, so the two swarms are mutually invisible at the transport. This
//! crate deliberately owns only the *root secret and the profile bookkeeping* —
//! it never re-derives the pnet key itself, keeping the domain separation in
//! each transport crate and avoiding a dependency cycle.
//!
//! ## Public pillar vs. your own swarm
//!
//! There are two ways to be on a swarm:
//!
//! - **The public pillar swarm** ([`SwarmProfile::public`]) — a single,
//!   well-known root ([`PUBLIC_PILLAR_ROOT`]) **published and baked into every
//!   binary**. Every node joins it by default, so the global pillar network is
//!   one swarm. Because the key is published it provides **namespace
//!   isolation, not secrecy**: it keeps pillar's public swarm from co-mingling
//!   with unrelated libp2p/IPFS peers on the open transport, but it is not a
//!   membership gate (anyone can read it here). That is the correct model for a
//!   public network: joinable by all, still isolated from the rest of the
//!   libp2p world.
//! - **Your own swarm** ([`SwarmProfile::generate`]) — a fresh, high-entropy
//!   root this crate mints from the OS CSPRNG. Distribute it out-of-band to the
//!   nodes you want in your private network ([`SwarmProfile::import`] on each);
//!   nobody without it can complete a handshake. This IS a membership gate.
//!
//! [`SwarmRegistry`] persists the set of swarms a node knows plus which one is
//! active, at `<data-dir>/swarm/registry.json`. It always contains the public
//! swarm and always has a valid active selection.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The published, well-known root secret of the **public pillar swarm**, baked
/// into every binary.
///
/// This value is intentionally public: it is a *namespace* label, not a
/// secret. A node on the public swarm derives its pnet key from this root so
/// its transport refuses peers that are not pillar-public nodes, while any
/// pillar node in the world can still join (they all bake in the same value).
/// A node wanting a *private*, membership-gated network mints its own root with
/// [`SwarmProfile::generate`] instead.
///
/// Format: a `pillar-public-swarm/v<N>:` version tag followed by a fixed
/// published 256-bit nothing-up-my-sleeve constant, hex-encoded. Bumping the
/// version tag is the flag-day mechanism for rotating the public swarm.
pub const PUBLIC_PILLAR_ROOT: &str =
    "pillar-public-swarm/v1:70696c6c61722d7075626c69632d737761726d2d726f6f742d76312d6b6579";

/// The reserved name of the public swarm profile in a [`SwarmRegistry`].
pub const PUBLIC_SWARM_NAME: &str = "public";

/// Whether a swarm is the shared public pillar network or an operator's own
/// private, membership-gated network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SwarmKind {
    /// The public pillar swarm — joinable by anyone, keyed by the published
    /// [`PUBLIC_PILLAR_ROOT`]. Namespace isolation, no secrecy.
    Public,
    /// A private swarm keyed by an operator-held root secret. Membership is
    /// gated: a peer without the secret cannot complete a handshake.
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

/// One swarm a node knows about: a name, whether it is the public or a private
/// swarm, and the root secret its transport keys are derived from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmProfile {
    /// The local, unique name for this swarm (the selector `pillar swarm use`
    /// and the registry key). `public` is reserved for the public swarm.
    name: String,
    /// Whether this is the public pillar swarm or a private one.
    kind: SwarmKind,
    /// The root secret every transport pnet key is derived from. For the public
    /// swarm this is [`PUBLIC_PILLAR_ROOT`]; for a private swarm it is the
    /// operator's generated/imported secret. Local node config, same trust
    /// level as `identity.key`.
    root_secret: String,
}

impl SwarmProfile {
    /// The public pillar swarm profile: name `public`, the published baked-in
    /// root. This is what a node uses when the operator has configured nothing.
    #[must_use]
    pub fn public() -> Self {
        Self {
            name: PUBLIC_SWARM_NAME.to_owned(),
            kind: SwarmKind::Public,
            root_secret: PUBLIC_PILLAR_ROOT.to_owned(),
        }
    }

    /// Mint a brand-new PRIVATE swarm named `name` with a fresh 256-bit root
    /// secret drawn from the OS CSPRNG. Share the returned profile's
    /// [`root_secret`](Self::root_secret) out-of-band with the other nodes you
    /// want in this swarm ([`import`](Self::import) it on each).
    ///
    /// # Errors
    /// [`SwarmError::InvalidName`] if `name` is empty; [`SwarmError::Reserved`]
    /// if `name` is the reserved public name.
    pub fn generate(name: impl Into<String>) -> Result<Self, SwarmError> {
        let name = name.into();
        validate_name(&name)?;
        use rand_core::{OsRng, RngCore};
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        Ok(Self {
            kind: SwarmKind::Private,
            root_secret: format!("pillar-swarm/v1:{}", hex_encode(&raw)),
            name,
        })
    }

    /// Adopt an EXISTING private swarm: build a profile named `name` from a
    /// root secret another node generated and handed you.
    ///
    /// # Errors
    /// [`SwarmError::InvalidName`] if `name` is empty; [`SwarmError::Reserved`]
    /// if `name` is the reserved public name; [`SwarmError::EmptySecret`] if
    /// `secret` is empty.
    pub fn import(name: impl Into<String>, secret: impl Into<String>) -> Result<Self, SwarmError> {
        let name = name.into();
        validate_name(&name)?;
        let root_secret = secret.into();
        if root_secret.is_empty() {
            return Err(SwarmError::EmptySecret);
        }
        Ok(Self {
            name,
            kind: SwarmKind::Private,
            root_secret,
        })
    }

    /// This swarm's local name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether this is the public or a private swarm.
    #[must_use]
    pub fn kind(&self) -> SwarmKind {
        self.kind
    }

    /// The root secret to feed `PrivateSwarmKey::from_root_secret` in each
    /// transport crate. Handle as a secret for PRIVATE swarms (this is the join
    /// credential); the public swarm's root is [`PUBLIC_PILLAR_ROOT`] and safe
    /// to print.
    #[must_use]
    pub fn root_secret(&self) -> &str {
        &self.root_secret
    }

    /// A short, stable, NON-secret fingerprint of this swarm's membership,
    /// derived from the root secret. Two nodes on the same swarm always show
    /// the same fingerprint, so operators can confirm they are on the same
    /// network WITHOUT comparing (or leaking) the root secret itself. It is a
    /// one-way SHAKE256 digest — the secret cannot be recovered from it.
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

/// The set of swarms a node knows plus which one is active. Persisted at
/// `<data-dir>/swarm/registry.json`. Invariants held at all times: the public
/// swarm is always present, and `active` always names a present profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmRegistry {
    /// The name of the currently-selected swarm — what a node boots onto and
    /// what the CLI/UI report as "current".
    active: String,
    /// Every known swarm, keyed by name.
    profiles: BTreeMap<String, SwarmProfile>,
}

impl Default for SwarmRegistry {
    fn default() -> Self {
        let mut profiles = BTreeMap::new();
        let public = SwarmProfile::public();
        profiles.insert(public.name.clone(), public);
        Self {
            active: PUBLIC_SWARM_NAME.to_owned(),
            profiles,
        }
    }
}

impl SwarmRegistry {
    /// The on-disk path of the registry under `data_dir`.
    #[must_use]
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("swarm").join("registry.json")
    }

    /// Load the registry under `data_dir`, or the [`Default`] (public-only)
    /// registry if none exists yet. A loaded registry is REPAIRED to its
    /// invariants: the public profile is re-inserted if missing, and `active`
    /// falls back to `public` if it names an absent profile.
    ///
    /// # Errors
    /// [`SwarmError::Io`] if the file exists but cannot be read;
    /// [`SwarmError::Parse`] if it exists but is not valid registry JSON.
    pub fn load_or_default(data_dir: &Path) -> Result<Self, SwarmError> {
        let path = Self::path(data_dir);
        let mut reg = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<SwarmRegistry>(&bytes)
                .map_err(|e| SwarmError::Parse(e.to_string()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => SwarmRegistry::default(),
            Err(e) => return Err(SwarmError::Io(e.to_string())),
        };
        reg.repair();
        Ok(reg)
    }

    /// Re-establish the invariants (public present, active valid). Idempotent.
    fn repair(&mut self) {
        self.profiles
            .entry(PUBLIC_SWARM_NAME.to_owned())
            .or_insert_with(SwarmProfile::public);
        if !self.profiles.contains_key(&self.active) {
            self.active = PUBLIC_SWARM_NAME.to_owned();
        }
    }

    /// Persist the registry under `data_dir`, creating `<data_dir>/swarm/` as
    /// needed. On Unix the file is written `0600` because it holds private
    /// swarm root secrets (join credentials).
    ///
    /// # Errors
    /// [`SwarmError::Io`] if the directory or file cannot be written;
    /// [`SwarmError::Parse`] if serialization fails (never expected).
    pub fn save(&self, data_dir: &Path) -> Result<(), SwarmError> {
        let path = Self::path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SwarmError::Io(e.to_string()))?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(|e| SwarmError::Parse(e.to_string()))?;
        std::fs::write(&path, &json).map_err(|e| SwarmError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| SwarmError::Io(e.to_string()))?;
        }
        Ok(())
    }

    /// The active swarm's profile. Never fails — the invariants guarantee it.
    #[must_use]
    pub fn active_profile(&self) -> &SwarmProfile {
        self.profiles
            .get(&self.active)
            .expect("registry invariant: active always names a present profile")
    }

    /// The active swarm's name.
    #[must_use]
    pub fn active_name(&self) -> &str {
        &self.active
    }

    /// Every known profile, sorted by name.
    pub fn list(&self) -> impl Iterator<Item = &SwarmProfile> {
        self.profiles.values()
    }

    /// Look up a profile by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&SwarmProfile> {
        self.profiles.get(name)
    }

    /// Add a profile. Does NOT change the active selection.
    ///
    /// # Errors
    /// [`SwarmError::Duplicate`] if a profile with that name already exists.
    pub fn add(&mut self, profile: SwarmProfile) -> Result<(), SwarmError> {
        if self.profiles.contains_key(&profile.name) {
            return Err(SwarmError::Duplicate(profile.name));
        }
        self.profiles.insert(profile.name.clone(), profile);
        Ok(())
    }

    /// Mint a new private swarm named `name`, store it, and return it (a clone,
    /// so the caller can surface the root secret to distribute). Does NOT
    /// switch to it — call [`use_swarm`](Self::use_swarm) to activate.
    ///
    /// # Errors
    /// [`SwarmError::InvalidName`]/[`SwarmError::Reserved`] for a bad name;
    /// [`SwarmError::Duplicate`] if the name is taken.
    pub fn create(&mut self, name: impl Into<String>) -> Result<SwarmProfile, SwarmError> {
        let profile = SwarmProfile::generate(name)?;
        self.add(profile.clone())?;
        Ok(profile)
    }

    /// Adopt an existing private swarm from a shared root secret, store it, and
    /// return it. Does NOT switch to it.
    ///
    /// # Errors
    /// Name/secret validation errors, or [`SwarmError::Duplicate`].
    pub fn import(
        &mut self,
        name: impl Into<String>,
        secret: impl Into<String>,
    ) -> Result<SwarmProfile, SwarmError> {
        let profile = SwarmProfile::import(name, secret)?;
        self.add(profile.clone())?;
        Ok(profile)
    }

    /// Make `name` the active swarm.
    ///
    /// # Errors
    /// [`SwarmError::NotFound`] if no such profile is known.
    pub fn use_swarm(&mut self, name: &str) -> Result<(), SwarmError> {
        if !self.profiles.contains_key(name) {
            return Err(SwarmError::NotFound(name.to_owned()));
        }
        self.active = name.to_owned();
        Ok(())
    }

    /// Forget a known swarm.
    ///
    /// # Errors
    /// [`SwarmError::NotFound`] if unknown; [`SwarmError::Reserved`] for the
    /// public swarm; [`SwarmError::ForgetActive`] for the active swarm (switch
    /// away first).
    pub fn forget(&mut self, name: &str) -> Result<(), SwarmError> {
        if name == PUBLIC_SWARM_NAME {
            return Err(SwarmError::Reserved(name.to_owned()));
        }
        if name == self.active {
            return Err(SwarmError::ForgetActive(name.to_owned()));
        }
        if self.profiles.remove(name).is_none() {
            return Err(SwarmError::NotFound(name.to_owned()));
        }
        Ok(())
    }
}

/// Reject an empty name or the reserved public name for a NEW private swarm.
fn validate_name(name: &str) -> Result<(), SwarmError> {
    if name.trim().is_empty() {
        return Err(SwarmError::InvalidName(name.to_owned()));
    }
    if name == PUBLIC_SWARM_NAME {
        return Err(SwarmError::Reserved(name.to_owned()));
    }
    Ok(())
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

/// Everything that can go wrong managing swarms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwarmError {
    /// A filesystem read/write of the registry failed (detail is the OS error).
    Io(String),
    /// The registry file was not valid JSON (detail is the parse error).
    Parse(String),
    /// No swarm with that name is known.
    NotFound(String),
    /// The name is reserved for the public swarm and cannot be reused/removed.
    Reserved(String),
    /// A swarm with that name already exists.
    Duplicate(String),
    /// The name is empty or otherwise invalid.
    InvalidName(String),
    /// An imported secret was empty.
    EmptySecret,
    /// The active swarm cannot be forgotten; switch away first.
    ForgetActive(String),
}

impl std::fmt::Display for SwarmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwarmError::Io(e) => write!(f, "swarm registry i/o error: {e}"),
            SwarmError::Parse(e) => write!(f, "swarm registry parse error: {e}"),
            SwarmError::NotFound(n) => write!(f, "no known swarm named `{n}`"),
            SwarmError::Reserved(n) => write!(f, "`{n}` is the reserved public swarm name"),
            SwarmError::Duplicate(n) => write!(f, "a swarm named `{n}` already exists"),
            SwarmError::InvalidName(n) => write!(f, "invalid swarm name `{n}`"),
            SwarmError::EmptySecret => write!(f, "imported swarm root secret is empty"),
            SwarmError::ForgetActive(n) => {
                write!(
                    f,
                    "cannot forget the active swarm `{n}` — switch away first"
                )
            }
        }
    }
}

impl std::error::Error for SwarmError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_profile_is_the_baked_published_root() {
        let p = SwarmProfile::public();
        assert_eq!(p.name(), PUBLIC_SWARM_NAME);
        assert_eq!(p.kind(), SwarmKind::Public);
        assert_eq!(p.root_secret(), PUBLIC_PILLAR_ROOT);
    }

    #[test]
    fn generate_mints_a_unique_high_entropy_private_root() {
        let a = SwarmProfile::generate("team-a").expect("gen");
        let b = SwarmProfile::generate("team-b").expect("gen");
        assert_eq!(a.kind(), SwarmKind::Private);
        // Two fresh swarms never collide on their root or fingerprint.
        assert_ne!(a.root_secret(), b.root_secret());
        assert_ne!(a.fingerprint(), b.fingerprint());
        // A private root is not the public one.
        assert_ne!(a.root_secret(), PUBLIC_PILLAR_ROOT);
    }

    #[test]
    fn import_reconstructs_the_same_swarm_from_a_shared_secret() {
        let minted = SwarmProfile::generate("lab").expect("gen");
        let joined = SwarmProfile::import("lab-node-2", minted.root_secret()).expect("import");
        // Same secret => same swarm => same fingerprint, regardless of local name.
        assert_eq!(joined.fingerprint(), minted.fingerprint());
        assert_eq!(joined.root_secret(), minted.root_secret());
    }

    #[test]
    fn fingerprint_is_stable_and_hides_the_secret() {
        let p = SwarmProfile::import("x", "super-secret-root").expect("import");
        assert_eq!(p.fingerprint(), p.fingerprint());
        assert!(!p.fingerprint().contains("super-secret-root"));
        assert_eq!(p.fingerprint().len(), 16); // 8 bytes hex
    }

    #[test]
    fn reserved_and_empty_names_are_rejected() {
        assert_eq!(
            SwarmProfile::generate("public"),
            Err(SwarmError::Reserved("public".to_owned()))
        );
        assert_eq!(
            SwarmProfile::generate("  "),
            Err(SwarmError::InvalidName("  ".to_owned()))
        );
        assert_eq!(SwarmProfile::import("y", ""), Err(SwarmError::EmptySecret));
    }

    #[test]
    fn default_registry_is_public_only_and_active() {
        let reg = SwarmRegistry::default();
        assert_eq!(reg.active_name(), PUBLIC_SWARM_NAME);
        assert_eq!(reg.active_profile().root_secret(), PUBLIC_PILLAR_ROOT);
        assert_eq!(reg.list().count(), 1);
    }

    #[test]
    fn create_use_forget_lifecycle() {
        let mut reg = SwarmRegistry::default();
        let minted = reg.create("prod").expect("create");
        assert_eq!(reg.list().count(), 2);
        // Creating does not switch.
        assert_eq!(reg.active_name(), PUBLIC_SWARM_NAME);
        // Duplicate name refused.
        assert!(matches!(reg.create("prod"), Err(SwarmError::Duplicate(_))));
        // Switch to it.
        reg.use_swarm("prod").expect("use");
        assert_eq!(reg.active_name(), "prod");
        assert_eq!(reg.active_profile().root_secret(), minted.root_secret());
        // Cannot forget the active swarm, nor the public swarm.
        assert!(matches!(
            reg.forget("prod"),
            Err(SwarmError::ForgetActive(_))
        ));
        assert!(matches!(reg.forget("public"), Err(SwarmError::Reserved(_))));
        // Switch away then forget.
        reg.use_swarm("public").expect("use public");
        reg.forget("prod").expect("forget");
        assert_eq!(reg.list().count(), 1);
        assert!(matches!(
            reg.use_swarm("prod"),
            Err(SwarmError::NotFound(_))
        ));
    }

    #[test]
    fn round_trips_through_disk_and_is_private() {
        let dir = std::env::temp_dir().join(format!("pillar-swarm-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut reg = SwarmRegistry::load_or_default(&dir).expect("load empty -> default");
        let minted = reg.create("edge").expect("create");
        reg.use_swarm("edge").expect("use");
        reg.save(&dir).expect("save");

        let reloaded = SwarmRegistry::load_or_default(&dir).expect("reload");
        assert_eq!(reloaded.active_name(), "edge");
        assert_eq!(
            reloaded.active_profile().root_secret(),
            minted.root_secret()
        );
        // Public is still there after a round trip.
        assert!(reloaded.get("public").is_some());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(SwarmRegistry::path(&dir))
                .expect("stat")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "registry holds private secrets, must be 0600");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn repair_reinserts_public_and_fixes_dangling_active() {
        // A registry whose active names a since-removed profile, missing public.
        let json = r#"{"active":"ghost","profiles":{}}"#;
        let mut reg: SwarmRegistry = serde_json::from_str(json).expect("parse");
        reg.repair();
        assert!(reg.get("public").is_some());
        assert_eq!(reg.active_name(), "public");
    }
}
