//! Client configuration: resolving *where* to connect and *who* as.
//!
//! A pillar client only ever needs three things from the user — a **cell
//! name**, a **username**, and a **credential** to unlock that user's key in
//! the cell. Everything else is either discovered (the full pillar-IPNS path)
//! or cached in a `config.yaml` for a faster direct reconnect. This module
//! owns that resolution: the on-disk schema, its standard search locations,
//! how layers and CLI/env overrides merge, and validation into a
//! ready-to-connect [`ConnectParams`].
//!
//! ## Search locations (lowest → highest precedence)
//!
//! 1. `/etc/pillar/config.yaml` — system-wide defaults.
//! 2. `$XDG_CONFIG_HOME/pillar/config.yaml` (or `~/.config/pillar/config.yaml`
//!    when `XDG_CONFIG_HOME` is unset) — the per-user config.
//! 3. `~/.pillar/config.yaml` — a user's explicit home-dir config.
//! 4. An explicit `--config <path>` / `$PILLAR_CONFIG` — always wins.
//!
//! Each existing file is parsed and merged onto the accumulator in that order,
//! so a more-specific layer overrides a less-specific one **field by field**
//! (an unset field in a higher layer leaves the lower layer's value intact).
//! CLI flags and environment variables are applied as one more highest-
//! precedence layer by the caller (they build a [`ClientConfig`] from their
//! flags and [`ClientConfig::merge`] it on top).
//!
//! ## On-disk schema (`config.yaml`)
//!
//! ```yaml
//! cell: my-cell                 # the cell to act on
//! user: alice                   # the username within that cell
//! token: <cached-wot-token>     # optional: a cached WoT-verified session
//!                               #   token (fast path; re-auth on expiry)
//! credential:                   # how to unlock alice's cell key
//!   kind: passkey               #   password | passkey | keyring | tpm
//!   key-id: alice@my-cell       #   optional backend key identifier
//! nodes:                        # optional: cached reachable ingest nodes
//!   - /ip4/192.0.2.10/udp/4001/p-pillar/p2p/<peer-id>
//! transport: [pillar-udp, quic, https]   # optional preference order
//! swarm:                        # private-swarm callers only
//!   key: /home/alice/.pillar/swarm.key
//!   seeds:
//!     - /ip4/192.0.2.1/udp/4001/p-pillar/p2p/<seed-peer-id>
//! ```
//!
//! Every field is optional on disk; the same values may instead be supplied
//! via CLI options. Unknown fields are ignored (forward compatibility).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Which standard pillar transport a client dials over. A client tries these
/// in preference order, falling to the next when a transport is unavailable
/// for a given node/link. **Sealed [`pillar_wire::PillarMessage`]s ride every
/// one of them** — the transport carries confidentiality of the *link*, the
/// per-message seal carries confidentiality of the *content*.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportKind {
    /// The pillar-UDP libp2p transport — the preferred default (reliable,
    /// ordered, handshakeless; confidentiality by per-datagram seal).
    PillarUdp,
    /// libp2p QUIC — the fallback for a healthy link where pillar-UDP is
    /// unavailable.
    Quic,
    /// HTTPS — the last-resort fallback for a network that only passes
    /// ordinary web traffic. Still carries a sealed `PillarMessage` body.
    Https,
}

/// The default transport preference order a client uses when `config.yaml`
/// does not pin one: pillar-UDP first, then QUIC, then HTTPS.
pub const DEFAULT_TRANSPORT_ORDER: [TransportKind; 3] = [
    TransportKind::PillarUdp,
    TransportKind::Quic,
    TransportKind::Https,
];

/// How the user's cell key is unlocked to authenticate an act. Mirrors the
/// custody backends [`pillar_identity`] supports (see `login.rs`); the client
/// prompts for / consults the matching authenticator when it needs to sign a
/// challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialKind {
    /// A password-derived key (supported but not recommended).
    Password,
    /// A passkey / WebAuthn authenticator.
    Passkey,
    /// An OS keyring-held key.
    Keyring,
    /// A TPM-held key.
    Tpm,
}

/// How to unlock the user's cell key: which authenticator kind, and an
/// optional backend-specific key identifier (a keyring slot, a passkey
/// credential id, …). The secret itself is NEVER stored here — only the
/// reference the authenticator needs to locate it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialConfig {
    /// The authenticator kind used to unlock the key.
    pub kind: CredentialKind,
    /// An optional backend-specific identifier for the key material (keyring
    /// slot, passkey credential id, TPM handle, …).
    #[serde(rename = "key-id", skip_serializing_if = "Option::is_none", default)]
    pub key_id: Option<String>,
}

/// Baked-in seal+sign material for a NON-interactive client (the UI-exported
/// `config.yaml`, see the node's `POST /portal/profile/cli-config`). Unlike
/// [`CredentialConfig`] — which only *references* a custody-held key the client
/// unlocks interactively — this block carries the actual material a `pillar`
/// CLI needs to seal/open this cell's content and sign resource ops with a
/// scoped, node-admitted subkey, so `pillar apply -f` works with no prompt.
///
/// **Security:** this is sensitive, kubeconfig-equivalent material (the cell
/// seed lets its holder open cell content; the signer secret acts as an
/// admitted writer). The exporting UI warns on download and the CLI persists
/// the file `0600`. The signer here is a scoped CLI subkey, so revoking it
/// (retiring its node admission) never revokes the user's own cell key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityMaterial {
    /// `host:port` of the target node's resource-op pillar-UDP tier.
    pub addr: String,
    /// The target cell id's raw bytes, lowercase hex (a cell id is derived
    /// bytes, not readable UTF-8, so it travels as hex).
    #[serde(rename = "cell-id-hex")]
    pub cell_id_hex: String,
    /// The per-cell seed the node derived its cell group key from, lowercase
    /// hex. The client derives the same group key from it identically.
    #[serde(rename = "cell-seed-hex")]
    pub cell_seed_hex: String,
    /// The scoped CLI signing subkey's ed25519 public key, lowercase hex.
    #[serde(rename = "signer-public-hex")]
    pub signer_public_hex: String,
    /// The scoped CLI signing subkey's ed25519 secret key, lowercase hex.
    #[serde(rename = "signer-secret-hex")]
    pub signer_secret_hex: String,
}

/// The private-swarm parameters a non-public-swarm client must additionally
/// supply: the swarm pnet key file and the seed nodes to bootstrap from. Public
/// -swarm clients omit this block entirely.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SwarmConfig {
    /// Path to the private-swarm pnet key file (as emitted by `pillar swarm
    /// generate`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key: Option<PathBuf>,
    /// The seed-node multiaddrs to bootstrap the private swarm from.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub seeds: Option<Vec<String>>,
}

impl SwarmConfig {
    /// Merge `higher` onto `self`, field by field (a `Some` in `higher` wins).
    #[must_use]
    fn merge(self, higher: SwarmConfig) -> SwarmConfig {
        SwarmConfig {
            key: higher.key.or(self.key),
            seeds: higher.seeds.or(self.seeds),
        }
    }

    /// True when neither a key nor seeds were supplied (an empty block, which
    /// resolves to the public swarm).
    fn is_empty(&self) -> bool {
        self.key.is_none() && self.seeds.is_none()
    }
}

/// The raw, on-disk `config.yaml` shape: every field optional so layers can be
/// merged and a value can be supplied by any of file / env / CLI. Deserialize
/// to READ a config; serialize to WRITE one (the cache a client generates for
/// a faster reconnect). Unknown fields are ignored for forward compatibility.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ClientConfig {
    /// The cell to act on.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cell: Option<String>,
    /// The username within the cell.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user: Option<String>,
    /// A cached WoT-verified session token (fast path; the client re-
    /// authenticates with the credential when it is absent or expired).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub token: Option<String>,
    /// How to unlock the user's cell key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub credential: Option<CredentialConfig>,
    /// Cached reachable ingest-node multiaddrs. When absent/empty the client
    /// discovers them from the cell name via pillar-IPNS.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nodes: Option<Vec<String>>,
    /// The transport preference order (defaults to [`DEFAULT_TRANSPORT_ORDER`]).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub transport: Option<Vec<TransportKind>>,
    /// Private-swarm parameters (public-swarm clients omit this).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub swarm: Option<SwarmConfig>,
    /// Baked-in seal+sign material for a non-interactive client (the
    /// UI-exported turnkey config). When present, `pillar apply`/`delete`
    /// dial and sign directly from it with no prompt.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identity: Option<IdentityMaterial>,
}

impl ClientConfig {
    /// Merge `higher` onto `self`: for every field a `Some`/present value in
    /// `higher` wins, otherwise `self`'s is retained. `swarm` merges
    /// recursively so a higher layer can override just the key or just the
    /// seeds. This is the one operation both file layering and CLI/env
    /// overrides use.
    #[must_use]
    pub fn merge(self, higher: ClientConfig) -> ClientConfig {
        ClientConfig {
            cell: higher.cell.or(self.cell),
            user: higher.user.or(self.user),
            token: higher.token.or(self.token),
            credential: higher.credential.or(self.credential),
            nodes: higher.nodes.or(self.nodes),
            transport: higher.transport.or(self.transport),
            swarm: match (self.swarm, higher.swarm) {
                (Some(lo), Some(hi)) => Some(lo.merge(hi)),
                (lo, hi) => hi.or(lo),
            },
            identity: higher.identity.or(self.identity),
        }
    }

    /// Cache a freshly-minted session `token` into this config (builder-style),
    /// so the next process starts on the auth fast path. This is the write half
    /// of the auth cache contract: [`crate::auth::authenticate`] yields a token
    /// and the caller stores it here, then [`Self::save`]s the config.
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> ClientConfig {
        self.token = Some(token.into());
        self
    }

    /// Serialize this config to a `config.yaml` document, ready to write to
    /// disk. The inverse of [`Self::parse`]; only the SET (`Some`) fields are
    /// emitted, so writing back a cached token never clobbers unrelated
    /// commented-out or defaulted fields with explicit nulls.
    ///
    /// # Errors
    /// [`ConfigError::Parse`] if serialization fails (should not happen for a
    /// well-formed in-memory config).
    pub fn to_yaml(&self) -> Result<String, ConfigError> {
        serde_yaml::to_string(self).map_err(|e| ConfigError::Parse {
            path: PathBuf::from("<in-memory>"),
            message: e.to_string(),
        })
    }

    /// Write this config to `path` as a `config.yaml` (the cached-token
    /// write-back path). Creates parent directories as needed.
    ///
    /// # Errors
    /// [`ConfigError::Io`] on a create-dir/write fault; [`ConfigError::Parse`]
    /// on a serialization fault.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| ConfigError::Io {
                    path: parent.to_path_buf(),
                    message: e.to_string(),
                })?;
            }
        }
        let text = self.to_yaml()?;
        std::fs::write(path, text).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
    }

    /// Parse a `config.yaml` document. An empty or comments-only document is a
    /// valid *empty* config (not an error), so a placeholder file never breaks
    /// loading.
    ///
    /// # Errors
    /// [`ConfigError::Parse`] when `text` is a non-empty document that is not
    /// well-formed for this schema.
    pub fn parse(text: &str, path: &Path) -> Result<ClientConfig, ConfigError> {
        // `Option<ClientConfig>` so a null document (empty file / comments
        // only) deserializes to `None` rather than erroring on "expected a
        // map, found null".
        let parsed: Option<ClientConfig> =
            serde_yaml::from_str(text).map_err(|e| ConfigError::Parse {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;
        Ok(parsed.unwrap_or_default())
    }

    /// Validate and resolve this merged config into a ready-to-connect
    /// [`ConnectParams`]. Trims string fields; an all-whitespace required
    /// field counts as absent.
    ///
    /// # Errors
    /// [`ResolveError`] naming the first unmet requirement (missing cell /
    /// user / credential, an incomplete private-swarm block, or an explicitly
    /// empty transport order).
    pub fn resolve(self) -> Result<ConnectParams, ResolveError> {
        let cell = non_empty(self.cell).ok_or(ResolveError::MissingCell)?;
        let user = non_empty(self.user).ok_or(ResolveError::MissingUser)?;
        let token = non_empty(self.token);

        // The user must be able to authenticate: either a cached token (fast
        // path) or a credential to unlock the cell key (to obtain one).
        if token.is_none() && self.credential.is_none() {
            return Err(ResolveError::MissingCredential);
        }

        let transport = match self.transport {
            Some(order) if order.is_empty() => return Err(ResolveError::EmptyTransportOrder),
            Some(order) => order,
            None => DEFAULT_TRANSPORT_ORDER.to_vec(),
        };

        let nodes: Vec<String> = self
            .nodes
            .unwrap_or_default()
            .into_iter()
            .filter_map(|n| non_empty(Some(n)))
            .collect();

        let swarm = match self.swarm {
            None => SwarmMode::Public,
            Some(s) if s.is_empty() => SwarmMode::Public,
            Some(s) => {
                let key = s.key.ok_or(ResolveError::PrivateSwarmIncomplete)?;
                let seeds: Vec<String> = s
                    .seeds
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|n| non_empty(Some(n)))
                    .collect();
                if seeds.is_empty() {
                    return Err(ResolveError::PrivateSwarmIncomplete);
                }
                SwarmMode::Private { key, seeds }
            }
        };

        Ok(ConnectParams {
            cell,
            user,
            credential: self.credential,
            token,
            nodes,
            transport,
            swarm,
        })
    }
}

/// The injectable set of base directories the config search paths are built
/// from — real env in production, explicit temp dirs in tests (so a test never
/// touches a developer's real `~/.config`).
#[derive(Clone, Debug, Default)]
pub struct ConfigDirs {
    /// The system config root (`/etc` in production; its `pillar/config.yaml`
    /// is the lowest layer).
    pub etc: Option<PathBuf>,
    /// `$XDG_CONFIG_HOME` when set; its `pillar/config.yaml` is the per-user
    /// layer. When `None`, `home`'s `.config` is used instead.
    pub xdg_config: Option<PathBuf>,
    /// The user's home directory (`$HOME`); source of both the
    /// `~/.config/pillar` fallback and `~/.pillar/config.yaml`.
    pub home: Option<PathBuf>,
}

impl ConfigDirs {
    /// Build from the process environment: `etc = /etc`, `xdg_config =
    /// $XDG_CONFIG_HOME`, `home = $HOME`.
    #[must_use]
    pub fn from_env() -> Self {
        ConfigDirs {
            etc: Some(PathBuf::from("/etc")),
            xdg_config: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            home: std::env::var_os("HOME").map(PathBuf::from),
        }
    }

    /// The config file search paths in **lowest → highest** precedence order,
    /// skipping any whose base directory is unknown.
    #[must_use]
    pub fn search_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(etc) = &self.etc {
            paths.push(etc.join("pillar").join("config.yaml"));
        }
        // Per-user: XDG_CONFIG_HOME wins; else ~/.config.
        if let Some(xdg) = &self.xdg_config {
            paths.push(xdg.join("pillar").join("config.yaml"));
        } else if let Some(home) = &self.home {
            paths.push(home.join(".config").join("pillar").join("config.yaml"));
        }
        if let Some(home) = &self.home {
            paths.push(home.join(".pillar").join("config.yaml"));
        }
        paths
    }
}

/// Load and merge the layered `config.yaml` files: each existing file in
/// [`ConfigDirs::search_paths`] order, lowest → highest, then an `explicit`
/// path (from `--config` / `$PILLAR_CONFIG`) on top. A missing layered file is
/// simply skipped; a missing *explicit* file is an error (the user named a
/// path that is not there). CLI/env field overrides are applied by the caller
/// via [`ClientConfig::merge`] on the returned value.
///
/// # Errors
/// [`ConfigError::MissingExplicit`] when `explicit` names a nonexistent path;
/// [`ConfigError::Io`] / [`ConfigError::Parse`] on a read/parse fault of any
/// layer.
pub fn load(dirs: &ConfigDirs, explicit: Option<&Path>) -> Result<ClientConfig, ConfigError> {
    let mut acc = ClientConfig::default();
    for path in dirs.search_paths() {
        if path.is_file() {
            acc = acc.merge(read_layer(&path)?);
        }
    }
    if let Some(explicit) = explicit {
        if !explicit.is_file() {
            return Err(ConfigError::MissingExplicit(explicit.to_path_buf()));
        }
        acc = acc.merge(read_layer(explicit)?);
    }
    Ok(acc)
}

/// Read and parse a single config layer.
fn read_layer(path: &Path) -> Result<ClientConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    ClientConfig::parse(&text, path)
}

/// Trim a candidate string; `None` (or all-whitespace) becomes `None`.
fn non_empty(value: Option<String>) -> Option<String> {
    value.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

/// The public vs. private swarm the client connects over.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwarmMode {
    /// The public pillar swarm (the baked-in pnet root); no extra parameters.
    Public,
    /// A private swarm: its pnet key file and the seed nodes to bootstrap from.
    Private {
        /// Path to the private-swarm pnet key file.
        key: PathBuf,
        /// The seed-node multiaddrs to bootstrap from (non-empty).
        seeds: Vec<String>,
    },
}

/// A fully-resolved, validated set of connection parameters: everything a
/// client needs to reach a cell and authenticate as a user. Produced by
/// [`ClientConfig::resolve`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectParams {
    /// The cell to act on.
    pub cell: String,
    /// The username within the cell.
    pub user: String,
    /// How to unlock the user's cell key (may be `None` when a valid cached
    /// `token` makes re-authentication unnecessary).
    pub credential: Option<CredentialConfig>,
    /// A cached WoT-verified session token, if any.
    pub token: Option<String>,
    /// Cached reachable ingest-node multiaddrs; empty means the client must
    /// discover them from the cell name (see [`Self::needs_discovery`]).
    pub nodes: Vec<String>,
    /// The transport preference order to dial over.
    pub transport: Vec<TransportKind>,
    /// Public vs. private swarm.
    pub swarm: SwarmMode,
}

impl ConnectParams {
    /// True when no ingest nodes are cached, so the client must resolve them
    /// from the cell name via pillar-IPNS before it can connect.
    #[must_use]
    pub fn needs_discovery(&self) -> bool {
        self.nodes.is_empty()
    }

    /// True when connecting over a private swarm.
    #[must_use]
    pub fn is_private_swarm(&self) -> bool {
        matches!(self.swarm, SwarmMode::Private { .. })
    }
}

/// A fault loading or parsing a config file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// A config file could not be read.
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying OS error text.
        message: String,
    },
    /// A config file's contents are not well-formed for this schema.
    Parse {
        /// The path that failed.
        path: PathBuf,
        /// The parser's error text.
        message: String,
    },
    /// An explicit `--config` / `$PILLAR_CONFIG` path does not exist.
    MissingExplicit(PathBuf),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io { path, message } => {
                write!(f, "reading config {}: {message}", path.display())
            }
            ConfigError::Parse { path, message } => {
                write!(f, "parsing config {}: {message}", path.display())
            }
            ConfigError::MissingExplicit(path) => {
                write!(f, "config file not found: {}", path.display())
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// A fault resolving a merged [`ClientConfig`] into [`ConnectParams`]: a
/// required value is missing or a supplied one is internally inconsistent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// No cell name was supplied by any layer/flag.
    MissingCell,
    /// No username was supplied by any layer/flag.
    MissingUser,
    /// Neither a cached token nor a credential was supplied, so the user
    /// cannot authenticate.
    MissingCredential,
    /// A private-swarm block was supplied but is incomplete (needs both a key
    /// and at least one seed node).
    PrivateSwarmIncomplete,
    /// A `transport` list was supplied but empty (no transport to dial over).
    EmptyTransportOrder,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::MissingCell => {
                f.write_str("no cell specified (set `cell:` in config.yaml or pass --cell)")
            }
            ResolveError::MissingUser => {
                f.write_str("no user specified (set `user:` in config.yaml or pass --user)")
            }
            ResolveError::MissingCredential => f.write_str(
                "no credential or cached token (set `credential:`/`token:` in \
                 config.yaml or pass a credential option)",
            ),
            ResolveError::PrivateSwarmIncomplete => {
                f.write_str("private swarm needs both a key and at least one seed node")
            }
            ResolveError::EmptyTransportOrder => f.write_str("transport preference list is empty"),
        }
    }
}

impl std::error::Error for ResolveError {}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
cell: my-cell
user: alice
token: cached-tok
credential:
  kind: passkey
  key-id: alice@my-cell
nodes:
  - /ip4/192.0.2.10/udp/4001/p-pillar/p2p/peerA
  - /ip4/192.0.2.11/udp/4001/p-pillar/p2p/peerB
transport: [pillar-udp, quic, https]
swarm:
  key: /home/alice/.pillar/swarm.key
  seeds:
    - /ip4/192.0.2.1/udp/4001/p-pillar/p2p/seed1
"#;

    #[test]
    fn parses_a_full_config_document() {
        let cfg = ClientConfig::parse(FULL, Path::new("test.yaml")).expect("parse");
        assert_eq!(cfg.cell.as_deref(), Some("my-cell"));
        assert_eq!(cfg.user.as_deref(), Some("alice"));
        assert_eq!(cfg.token.as_deref(), Some("cached-tok"));
        let cred = cfg.credential.as_ref().expect("credential");
        assert_eq!(cred.kind, CredentialKind::Passkey);
        assert_eq!(cred.key_id.as_deref(), Some("alice@my-cell"));
        assert_eq!(cfg.nodes.as_ref().expect("nodes").len(), 2);
        assert_eq!(
            cfg.transport.as_deref(),
            Some(
                &[
                    TransportKind::PillarUdp,
                    TransportKind::Quic,
                    TransportKind::Https
                ][..]
            )
        );
        let sw = cfg.swarm.as_ref().expect("swarm");
        assert_eq!(
            sw.key.as_deref(),
            Some(Path::new("/home/alice/.pillar/swarm.key"))
        );
        assert_eq!(sw.seeds.as_ref().expect("seeds").len(), 1);
    }

    #[test]
    fn config_round_trips_through_yaml() {
        let cfg = ClientConfig::parse(FULL, Path::new("t.yaml")).expect("parse");
        let text = serde_yaml::to_string(&cfg).expect("serialize");
        let again = ClientConfig::parse(&text, Path::new("t.yaml")).expect("reparse");
        assert_eq!(cfg, again, "serialize -> parse is faithful");
    }

    #[test]
    fn identity_material_block_round_trips_with_kebab_case_keys() {
        let cfg = ClientConfig {
            cell: Some("pillar".to_owned()),
            user: Some("spencer".to_owned()),
            identity: Some(IdentityMaterial {
                addr: "node.example.com:8643".to_owned(),
                cell_id_hex: "deadbeef".to_owned(),
                cell_seed_hex: "c0ffee".to_owned(),
                signer_public_hex: "aa11".to_owned(),
                signer_secret_hex: "bb22".to_owned(),
            }),
            ..ClientConfig::default()
        };
        let text = cfg.to_yaml().expect("serialize");
        // On-disk keys are kebab-case (matches the exporter + docs).
        assert!(text.contains("cell-id-hex:"), "kebab-case keys: {text}");
        assert!(
            text.contains("signer-secret-hex:"),
            "kebab-case keys: {text}"
        );
        let again = ClientConfig::parse(&text, Path::new("id.yaml")).expect("reparse");
        assert_eq!(cfg, again, "identity block survives serialize -> parse");
        // A merged higher layer's identity block wins wholesale.
        let base = ClientConfig::parse("cell: pillar\n", Path::new("lo")).expect("lo");
        assert_eq!(base.merge(cfg.clone()).identity, cfg.identity);
    }

    #[test]
    fn empty_and_comment_only_documents_are_empty_configs_not_errors() {
        assert_eq!(
            ClientConfig::parse("", Path::new("e.yaml")).expect("empty"),
            ClientConfig::default()
        );
        assert_eq!(
            ClientConfig::parse("   \n\n", Path::new("ws.yaml")).expect("whitespace"),
            ClientConfig::default()
        );
        assert_eq!(
            ClientConfig::parse("# just a comment\n", Path::new("c.yaml")).expect("comment"),
            ClientConfig::default()
        );
    }

    #[test]
    fn unknown_fields_are_ignored_for_forward_compat() {
        let cfg = ClientConfig::parse("cell: c\nuser: u\nfuture_field: 42\n", Path::new("f.yaml"))
            .expect("parse with unknown field");
        assert_eq!(cfg.cell.as_deref(), Some("c"));
        assert_eq!(cfg.user.as_deref(), Some("u"));
    }

    #[test]
    fn malformed_document_is_a_parse_error() {
        let err = ClientConfig::parse("cell: [unterminated", Path::new("bad.yaml"))
            .expect_err("malformed");
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn merge_lets_a_higher_layer_override_field_by_field() {
        let lo = ClientConfig::parse(
            "cell: base-cell\nuser: base-user\ntoken: base-tok\n",
            Path::new("lo"),
        )
        .expect("lo");
        let hi = ClientConfig::parse("user: override-user\n", Path::new("hi")).expect("hi");
        let merged = lo.merge(hi);
        // Higher wins where present; lower is retained where higher is unset.
        assert_eq!(merged.cell.as_deref(), Some("base-cell"));
        assert_eq!(merged.user.as_deref(), Some("override-user"));
        assert_eq!(merged.token.as_deref(), Some("base-tok"));
    }

    #[test]
    fn merge_recurses_into_the_swarm_block() {
        let lo = ClientConfig::parse("swarm:\n  key: /base/key\n  seeds: [s1]\n", Path::new("lo"))
            .expect("lo");
        // Higher layer overrides only the seeds; key is retained from lower.
        let hi = ClientConfig::parse("swarm:\n  seeds: [s2, s3]\n", Path::new("hi")).expect("hi");
        let sw = lo.merge(hi).swarm.expect("swarm");
        assert_eq!(sw.key.as_deref(), Some(Path::new("/base/key")));
        assert_eq!(
            sw.seeds.as_deref(),
            Some(&["s2".to_owned(), "s3".to_owned()][..])
        );
    }

    #[test]
    fn search_paths_are_lowest_to_highest_with_xdg_preferred() {
        let dirs = ConfigDirs {
            etc: Some(PathBuf::from("/etc")),
            xdg_config: Some(PathBuf::from("/xdg")),
            home: Some(PathBuf::from("/home/alice")),
        };
        assert_eq!(
            dirs.search_paths(),
            vec![
                PathBuf::from("/etc/pillar/config.yaml"),
                PathBuf::from("/xdg/pillar/config.yaml"),
                PathBuf::from("/home/alice/.pillar/config.yaml"),
            ]
        );
    }

    #[test]
    fn search_paths_fall_back_to_home_config_without_xdg() {
        let dirs = ConfigDirs {
            etc: Some(PathBuf::from("/etc")),
            xdg_config: None,
            home: Some(PathBuf::from("/home/alice")),
        };
        assert_eq!(
            dirs.search_paths(),
            vec![
                PathBuf::from("/etc/pillar/config.yaml"),
                PathBuf::from("/home/alice/.config/pillar/config.yaml"),
                PathBuf::from("/home/alice/.pillar/config.yaml"),
            ]
        );
    }

    #[test]
    fn search_paths_skip_unknown_base_dirs() {
        let dirs = ConfigDirs {
            etc: None,
            xdg_config: None,
            home: None,
        };
        assert!(dirs.search_paths().is_empty());
    }

    /// A layered load: a system `/etc` file provides a base, a `~/.pillar`
    /// file overrides one field; the merge reflects both.
    #[test]
    fn load_merges_layered_files_lowest_to_highest() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let etc = tmp.path().join("etc");
        let home = tmp.path().join("home");
        std::fs::create_dir_all(etc.join("pillar")).expect("mk etc");
        std::fs::create_dir_all(home.join(".pillar")).expect("mk home");
        std::fs::write(
            etc.join("pillar").join("config.yaml"),
            "cell: sys-cell\nuser: sys-user\ntransport: [https]\n",
        )
        .expect("write etc");
        std::fs::write(
            home.join(".pillar").join("config.yaml"),
            "user: my-user\ncredential:\n  kind: password\n",
        )
        .expect("write home");

        let dirs = ConfigDirs {
            etc: Some(etc),
            xdg_config: None,
            home: Some(home),
        };
        let cfg = load(&dirs, None).expect("load");
        // System base retained where user file is silent…
        assert_eq!(cfg.cell.as_deref(), Some("sys-cell"));
        assert_eq!(cfg.transport.as_deref(), Some(&[TransportKind::Https][..]));
        // …user file overrides the user and adds a credential.
        assert_eq!(cfg.user.as_deref(), Some("my-user"));
        assert_eq!(cfg.credential.expect("cred").kind, CredentialKind::Password);
    }

    #[test]
    fn load_skips_missing_layers_and_returns_empty_when_none_exist() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dirs = ConfigDirs {
            etc: Some(tmp.path().join("no-etc")),
            xdg_config: None,
            home: Some(tmp.path().join("no-home")),
        };
        assert_eq!(load(&dirs, None).expect("load"), ClientConfig::default());
    }

    #[test]
    fn explicit_path_wins_and_missing_explicit_is_an_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let etc = tmp.path().join("etc");
        std::fs::create_dir_all(etc.join("pillar")).expect("mk etc");
        std::fs::write(
            etc.join("pillar").join("config.yaml"),
            "cell: base\nuser: base\n",
        )
        .expect("write etc");
        let explicit = tmp.path().join("explicit.yaml");
        std::fs::write(&explicit, "cell: explicit-cell\n").expect("write explicit");

        let dirs = ConfigDirs {
            etc: Some(etc),
            xdg_config: None,
            home: None,
        };
        let cfg = load(&dirs, Some(&explicit)).expect("load");
        assert_eq!(
            cfg.cell.as_deref(),
            Some("explicit-cell"),
            "explicit overrides base"
        );
        assert_eq!(
            cfg.user.as_deref(),
            Some("base"),
            "base retained where explicit silent"
        );

        let err = load(&dirs, Some(&tmp.path().join("nope.yaml"))).expect_err("missing explicit");
        assert!(matches!(err, ConfigError::MissingExplicit(_)));
    }

    #[test]
    fn resolve_full_config_yields_connect_params() {
        let params = ClientConfig::parse(FULL, Path::new("t"))
            .expect("parse")
            .resolve()
            .expect("resolve");
        assert_eq!(params.cell, "my-cell");
        assert_eq!(params.user, "alice");
        assert_eq!(params.token.as_deref(), Some("cached-tok"));
        assert_eq!(
            params.credential.as_ref().expect("cred").kind,
            CredentialKind::Passkey
        );
        assert_eq!(params.nodes.len(), 2);
        assert!(!params.needs_discovery());
        assert!(params.is_private_swarm());
    }

    #[test]
    fn resolve_requires_cell_and_user() {
        assert_eq!(
            ClientConfig::parse("user: u\ntoken: t\n", Path::new("t"))
                .unwrap()
                .resolve()
                .unwrap_err(),
            ResolveError::MissingCell
        );
        assert_eq!(
            ClientConfig::parse("cell: c\ntoken: t\n", Path::new("t"))
                .unwrap()
                .resolve()
                .unwrap_err(),
            ResolveError::MissingUser
        );
    }

    #[test]
    fn resolve_treats_all_whitespace_required_fields_as_missing() {
        assert_eq!(
            ClientConfig::parse("cell: \"   \"\nuser: u\ntoken: t\n", Path::new("t"))
                .unwrap()
                .resolve()
                .unwrap_err(),
            ResolveError::MissingCell
        );
    }

    #[test]
    fn resolve_accepts_token_only_or_credential_only_but_not_neither() {
        // token only (fast path, no credential needed)
        let p = ClientConfig::parse("cell: c\nuser: u\ntoken: t\n", Path::new("t"))
            .unwrap()
            .resolve()
            .expect("token only");
        assert!(p.credential.is_none());
        assert!(p.token.is_some());

        // credential only (will authenticate to obtain a token)
        let p = ClientConfig::parse(
            "cell: c\nuser: u\ncredential:\n  kind: password\n",
            Path::new("t"),
        )
        .unwrap()
        .resolve()
        .expect("credential only");
        assert!(p.token.is_none());
        assert!(p.credential.is_some());

        // neither -> cannot authenticate
        assert_eq!(
            ClientConfig::parse("cell: c\nuser: u\n", Path::new("t"))
                .unwrap()
                .resolve()
                .unwrap_err(),
            ResolveError::MissingCredential
        );
    }

    #[test]
    fn resolve_defaults_transport_order_when_unset_and_rejects_empty() {
        let p = ClientConfig::parse("cell: c\nuser: u\ntoken: t\n", Path::new("t"))
            .unwrap()
            .resolve()
            .expect("resolve");
        assert_eq!(p.transport, DEFAULT_TRANSPORT_ORDER.to_vec());

        assert_eq!(
            ClientConfig::parse(
                "cell: c\nuser: u\ntoken: t\ntransport: []\n",
                Path::new("t")
            )
            .unwrap()
            .resolve()
            .unwrap_err(),
            ResolveError::EmptyTransportOrder
        );
    }

    #[test]
    fn resolve_empty_swarm_block_is_public_and_incomplete_is_rejected() {
        // empty block -> public
        let p = ClientConfig::parse("cell: c\nuser: u\ntoken: t\nswarm: {}\n", Path::new("t"))
            .unwrap()
            .resolve()
            .expect("empty swarm");
        assert_eq!(p.swarm, SwarmMode::Public);
        assert!(!p.is_private_swarm());

        // key without seeds -> incomplete
        assert_eq!(
            ClientConfig::parse(
                "cell: c\nuser: u\ntoken: t\nswarm:\n  key: /k\n",
                Path::new("t")
            )
            .unwrap()
            .resolve()
            .unwrap_err(),
            ResolveError::PrivateSwarmIncomplete
        );

        // seeds without key -> incomplete
        assert_eq!(
            ClientConfig::parse(
                "cell: c\nuser: u\ntoken: t\nswarm:\n  seeds: [s1]\n",
                Path::new("t")
            )
            .unwrap()
            .resolve()
            .unwrap_err(),
            ResolveError::PrivateSwarmIncomplete
        );
    }

    #[test]
    fn resolve_complete_private_swarm_yields_private_mode() {
        let p = ClientConfig::parse(
            "cell: c\nuser: u\ntoken: t\nswarm:\n  key: /k\n  seeds: [s1, s2]\n",
            Path::new("t"),
        )
        .unwrap()
        .resolve()
        .expect("private");
        match p.swarm {
            SwarmMode::Private { key, seeds } => {
                assert_eq!(key, PathBuf::from("/k"));
                assert_eq!(seeds, vec!["s1".to_owned(), "s2".to_owned()]);
            }
            SwarmMode::Public => panic!("expected private swarm"),
        }
    }

    #[test]
    fn resolve_drops_blank_node_entries_and_flags_discovery() {
        let p = ClientConfig::parse(
            "cell: c\nuser: u\ntoken: t\nnodes: [\"\", \"  \"]\n",
            Path::new("t"),
        )
        .unwrap()
        .resolve()
        .expect("resolve");
        assert!(p.nodes.is_empty());
        assert!(p.needs_discovery(), "no usable nodes -> discovery required");
    }
}
