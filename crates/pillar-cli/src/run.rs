//! `pillar node run`: the full-peer boot entrypoint.
//!
//! This is the process the containerized deployment (flux ROI Priority 3)
//! runs to bring a real Pillar peer online. It is a thin, deterministic
//! sequence with no hidden state:
//!
//! 1. **Identity** — load the node's long-lived ed25519 keypair from
//!    `--identity-key <path>` (protobuf-encoded, the libp2p canonical form),
//!    generating and persisting a fresh key at that path on first boot so a
//!    peer keeps a stable [`libp2p::PeerId`] across restarts.
//! 2. **Streaming DB** — open the node's append-only op store rooted at
//!    `--data-dir <path>` (created if absent), the durable home of the event
//!    log the controller reconciles against.
//! 3. **Transport** — bring up the libp2p [`pillar_net`] event swarm on the
//!    configured listen multiaddrs and subscribe it to the Pillar event-log
//!    gossipsub topic.
//! 4. **Controller loop** — drive the swarm event loop, folding inbound events
//!    into the stream, and block until a shutdown signal (SIGINT/SIGTERM).
//!
//! Every knob is configurable by flag OR environment variable so the same
//! binary works from a shell and from a container spec:
//!
//! | flag | env | default |
//! |------|-----|---------|
//! | `--identity-key` | `PILLAR_IDENTITY_KEY` | `<data-dir>/identity.key` |
//! | `--data-dir` | `PILLAR_DATA_DIR` | `./pillar-data` |
//! | `--listen` (repeatable) | `PILLAR_LISTEN` (comma/space list) | `/ip4/0.0.0.0/tcp/0` |
//! | `--dial` (repeatable) | `PILLAR_DIAL` (comma/space list) | none |
//! | `--seed` (repeatable) | `PILLAR_SEED_MULTIADDR` (comma/space list) | none (this node is itself a seed) |
//! | `--network-root` | `PILLAR_NETWORK_ROOT` | none (the well-known public root) |
//!
//! `--dial` names peer multiaddrs to connect out to at boot — the rootless,
//! multi-process integration rig's only mesh-formation mechanism, since this
//! process runs no separate bootstrap/rendezvous service. Every dial target
//! is attempted; a single bad dial does not abort boot (peers may come and
//! go), but is logged loudly.
//!
//! `PILLAR_TEST_PUBLISH`, if set, is an integration-rig-only hook: once the
//! swarm has been listening for [`TEST_PUBLISH_DELAY`], the node publishes
//! its value once to the event-log gossipsub topic, and every message this
//! node (or any peer) receives on that topic is logged at `info` with its
//! exact payload — so an external script can grep peer stdout for the value
//! to assert real cross-process gossipsub convergence. It has no effect on
//! a production boot that never sets the variable.
//!
//! The config parsing, identity load/persist, and data-dir preparation are
//! pure and filesystem-scoped, so they are exercised directly by the unit
//! tests below; [`run`] itself only wires those results into the async swarm
//! loop and blocks.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use libp2p::identity::Keypair;
use libp2p::Multiaddr;

/// The default listen address when none is configured: an ephemeral TCP port
/// on all interfaces (the container/orchestrator maps it).
pub const DEFAULT_LISTEN: &str = "/ip4/0.0.0.0/tcp/0";

/// The default data directory, relative to the process CWD.
pub const DEFAULT_DATA_DIR: &str = "pillar-data";

/// Environment variable names, kept in one place so flags and env stay in sync.
const ENV_IDENTITY_KEY: &str = "PILLAR_IDENTITY_KEY";
const ENV_DATA_DIR: &str = "PILLAR_DATA_DIR";
const ENV_LISTEN: &str = "PILLAR_LISTEN";
const ENV_DIAL: &str = "PILLAR_DIAL";
/// `--seed` / `PILLAR_SEED_MULTIADDR`: one or more federation seed multiaddrs
/// (each terminating in `/p2p/<peer-id>`) used to JOIN Pillar's own Kademlia
/// DHT. Unlike `--dial` (a raw libp2p dial), a seed is added to the Kademlia
/// routing table and a DHT bootstrap is issued from it, so the node actually
/// enters the federation swarm. Unset means this node is itself a seed/first
/// node. Seeds are discovery helpers, never a control plane — authority stays
/// with the WoT.
const ENV_SEED: &str = "PILLAR_SEED_MULTIADDR";
/// `--network-root` / `PILLAR_NETWORK_ROOT`: the secret that defines this
/// node's NETWORK — the physical libp2p swarm its packets can reach, not the
/// WoT/cell identity within whichever network it joins. Unset (the default)
/// means the well-known public root: [`pillar_net::PrivateSwarmKey::disabled`],
/// the same open federation `build_event_swarm` has always built. Set to a
/// secret value, the node derives a libp2p pnet pre-shared key from it
/// ([`pillar_net::PrivateSwarmKey::from_root_secret`]) and only ever completes
/// a transport handshake with a peer configured with the SAME root — a
/// mismatched or absent root on the other side refuses the handshake below
/// every higher protocol, so it can never dial into or be dialed by the
/// public federation. Standing up a private/app-specific network needs no new
/// mechanism: set the SAME `--network-root` on each owned node and point them
/// at each other via the existing `--seed`/`PILLAR_SEED_MULTIADDR` — every
/// pillar node is inherently a seed node.
const ENV_NETWORK_ROOT: &str = "PILLAR_NETWORK_ROOT";
/// `--web-bind` / `PILLAR_WEB_BIND`: the address the web UI listens on.
/// Unset (the default) disables the web surface entirely — `node run` never
/// opens a web listener unless explicitly configured.
const ENV_WEB_BIND: &str = "PILLAR_WEB_BIND";
/// `--web-port` / `PILLAR_WEB_PORT`: the port the web UI listens on, only
/// consulted when a bind address is configured.
const ENV_WEB_PORT: &str = "PILLAR_WEB_PORT";

/// The default web UI port when `--web-bind`/`PILLAR_WEB_BIND` is set but no
/// port is given.
pub const DEFAULT_WEB_PORT: u16 = 8642;

/// `--health-bind` / `PILLAR_HEALTH_BIND`: the address the readiness/liveness
/// health server listens on. Unlike the web UI, this defaults to ENABLED on
/// all interfaces (`0.0.0.0`) so a k8s `readinessProbe` can always reach it —
/// the whole point of the probe is that the orchestrator gates traffic on the
/// node's REAL readiness. Set it to a specific IP to narrow the bind.
const ENV_HEALTH_BIND: &str = "PILLAR_HEALTH_BIND";
/// `--health-port` / `PILLAR_HEALTH_PORT`: the port the health server listens
/// on. Defaults to [`crate::health::DEFAULT_HEALTH_PORT`].
const ENV_HEALTH_PORT: &str = "PILLAR_HEALTH_PORT";

/// The default address the health server binds when unconfigured: all
/// interfaces, so the readinessProbe (from the kubelet, off-loopback) reaches
/// it. Overridable via `--health-bind`/`PILLAR_HEALTH_BIND`.
pub const DEFAULT_HEALTH_BIND: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

/// Integration-rig-only: the value to publish once to the event-log
/// gossipsub topic after boot settles. Unset in every production boot.
const ENV_TEST_PUBLISH: &str = "PILLAR_TEST_PUBLISH";

/// How long after listen-address bind-up the [`ENV_TEST_PUBLISH`] hook waits
/// before publishing, giving `--dial` connections + gossipsub mesh
/// (re)grafting a real chance to settle first.
const TEST_PUBLISH_DELAY: std::time::Duration = std::time::Duration::from_secs(8);

/// A fully-resolved configuration for a `pillar node run` boot, produced by
/// [`NodeConfig::from_args_env`] from CLI flags layered over environment
/// variables layered over defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    /// Path to the node's ed25519 identity keypair (protobuf-encoded).
    pub identity_key: PathBuf,
    /// Directory the streaming DB / event log is rooted at.
    pub data_dir: PathBuf,
    /// libp2p multiaddrs the peer listens on. Never empty.
    pub listen: Vec<Multiaddr>,
    /// libp2p multiaddrs (of already-running peers) to dial at boot — the
    /// rig's mesh-formation mechanism. May be empty (a first/seed node).
    pub dial: Vec<Multiaddr>,
    /// Federation seed multiaddrs used to JOIN Pillar's own Kademlia DHT: each
    /// (terminating in `/p2p/<peer-id>`) is added to the routing table and a
    /// DHT bootstrap is issued from it, so the node enters the federation swarm
    /// rather than merely opening a point-to-point connection. May be empty
    /// (this node is itself a seed / first node). Distinct from `dial`.
    pub seed: Vec<Multiaddr>,
    /// The configured network root secret (`--network-root` /
    /// `PILLAR_NETWORK_ROOT`), if any. `None` is the public default — the
    /// well-known OPEN federation, no pnet pre-shared key. `Some(secret)`
    /// derives a private-swarm key via
    /// [`pillar_net::PrivateSwarmKey::from_root_secret`] so this node's
    /// transport only ever completes a handshake with a peer configured with
    /// the identical root.
    pub network_root: Option<String>,
    /// The address the web UI listens on, if configured. `None` (the
    /// default) means `node run` serves no web surface at all. When set to
    /// a **non-loopback** address (e.g. `0.0.0.0`, so a k8s Service can
    /// reach it), every signing action over that surface is gated through
    /// [`pillar_web::authorize_nonloopback_signing_action`] — the loopback-
    /// only bootstrap exemption never applies here.
    pub web_bind: Option<IpAddr>,
    /// The port the web UI listens on; only consulted when `web_bind` is
    /// `Some`.
    pub web_port: u16,
    /// The address the readiness/liveness health server binds. `None` here
    /// means "use [`DEFAULT_HEALTH_BIND`]" — the health server is ENABLED by
    /// default (unlike the web UI) because the k8s readinessProbe must always
    /// be able to reach it. Present so a deployment can narrow the bind.
    pub health_bind: Option<IpAddr>,
    /// The port the health server listens on. `None` means
    /// [`crate::health::DEFAULT_HEALTH_PORT`].
    pub health_port: Option<u16>,
}

/// A failure resolving a [`NodeConfig`] from flags/env.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// A flag that requires a value was given none.
    MissingValue(&'static str),
    /// A `--listen` / `PILLAR_LISTEN` entry did not parse as a multiaddr.
    BadListen {
        /// The offending value.
        value: String,
        /// The parser's reason.
        reason: String,
    },
    /// An argument was not recognized.
    Unknown(String),
    /// A `--web-bind` / `PILLAR_WEB_BIND` value did not parse as an IP
    /// address.
    BadWebBind {
        /// The offending value.
        value: String,
        /// The parser's reason.
        reason: String,
    },
    /// A `--web-port` / `PILLAR_WEB_PORT` value did not parse as a port
    /// number.
    BadWebPort {
        /// The offending value.
        value: String,
        /// The parser's reason.
        reason: String,
    },
    /// A `--health-bind` / `PILLAR_HEALTH_BIND` value did not parse as an IP
    /// address.
    BadHealthBind {
        /// The offending value.
        value: String,
        /// The parser's reason.
        reason: String,
    },
    /// A `--health-port` / `PILLAR_HEALTH_PORT` value did not parse as a port
    /// number.
    BadHealthPort {
        /// The offending value.
        value: String,
        /// The parser's reason.
        reason: String,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingValue(flag) => write!(f, "{flag} requires a value"),
            ConfigError::BadListen { value, reason } => {
                write!(f, "invalid listen multiaddr `{value}`: {reason}")
            }
            ConfigError::Unknown(arg) => write!(f, "unknown `node run` argument `{arg}`"),
            ConfigError::BadWebBind { value, reason } => {
                write!(f, "invalid --web-bind value `{value}`: {reason}")
            }
            ConfigError::BadWebPort { value, reason } => {
                write!(f, "invalid --web-port value `{value}`: {reason}")
            }
            ConfigError::BadHealthBind { value, reason } => {
                write!(f, "invalid --health-bind value `{value}`: {reason}")
            }
            ConfigError::BadHealthPort { value, reason } => {
                write!(f, "invalid --health-port value `{value}`: {reason}")
            }
        }
    }
}
impl std::error::Error for ConfigError {}

impl NodeConfig {
    /// Resolves a config from `args` (the argv slice AFTER `node run`) layered
    /// over an environment lookup `env` layered over the built-in defaults.
    ///
    /// Precedence, highest first: an explicit flag, then the matching env var,
    /// then the default. `--listen` may be repeated; when unset, a single
    /// `PILLAR_LISTEN` may carry a comma-or-whitespace-separated list. The
    /// identity-key default is derived from the resolved data dir so a lone
    /// `--data-dir` keeps the key beside the data.
    ///
    /// `env` is injected (rather than reading `std::env` directly) so the pure
    /// resolution is unit-testable without mutating process globals.
    pub fn from_args_env<F>(args: &[String], env: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut identity_key: Option<PathBuf> = None;
        let mut data_dir: Option<PathBuf> = None;
        let mut listen: Vec<Multiaddr> = Vec::new();
        let mut dial: Vec<Multiaddr> = Vec::new();
        let mut seed: Vec<Multiaddr> = Vec::new();
        let mut network_root: Option<String> = None;
        let mut web_bind: Option<IpAddr> = None;
        let mut web_port: Option<u16> = None;
        let mut health_bind: Option<IpAddr> = None;
        let mut health_port: Option<u16> = None;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--identity-key" => {
                    let v = args
                        .get(i + 1)
                        .ok_or(ConfigError::MissingValue("--identity-key"))?;
                    identity_key = Some(PathBuf::from(v));
                    i += 2;
                }
                "--data-dir" => {
                    let v = args
                        .get(i + 1)
                        .ok_or(ConfigError::MissingValue("--data-dir"))?;
                    data_dir = Some(PathBuf::from(v));
                    i += 2;
                }
                "--listen" => {
                    let v = args
                        .get(i + 1)
                        .ok_or(ConfigError::MissingValue("--listen"))?;
                    listen.push(parse_listen(v)?);
                    i += 2;
                }
                "--dial" => {
                    let v = args.get(i + 1).ok_or(ConfigError::MissingValue("--dial"))?;
                    dial.push(parse_listen(v)?);
                    i += 2;
                }
                "--seed" => {
                    let v = args.get(i + 1).ok_or(ConfigError::MissingValue("--seed"))?;
                    seed.push(parse_listen(v)?);
                    i += 2;
                }
                "--network-root" => {
                    let v = args
                        .get(i + 1)
                        .ok_or(ConfigError::MissingValue("--network-root"))?;
                    network_root = Some(v.clone());
                    i += 2;
                }
                "--web-bind" => {
                    let v = args
                        .get(i + 1)
                        .ok_or(ConfigError::MissingValue("--web-bind"))?;
                    web_bind = Some(parse_web_bind(v)?);
                    i += 2;
                }
                "--web-port" => {
                    let v = args
                        .get(i + 1)
                        .ok_or(ConfigError::MissingValue("--web-port"))?;
                    web_port = Some(parse_web_port(v)?);
                    i += 2;
                }
                "--health-bind" => {
                    let v = args
                        .get(i + 1)
                        .ok_or(ConfigError::MissingValue("--health-bind"))?;
                    health_bind = Some(parse_health_bind(v)?);
                    i += 2;
                }
                "--health-port" => {
                    let v = args
                        .get(i + 1)
                        .ok_or(ConfigError::MissingValue("--health-port"))?;
                    health_port = Some(parse_health_port(v)?);
                    i += 2;
                }
                other => return Err(ConfigError::Unknown(other.to_owned())),
            }
        }

        // Env fallbacks for the scalar knobs.
        if data_dir.is_none() {
            if let Some(v) = env(ENV_DATA_DIR) {
                data_dir = Some(PathBuf::from(v));
            }
        }
        let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));

        if identity_key.is_none() {
            if let Some(v) = env(ENV_IDENTITY_KEY) {
                identity_key = Some(PathBuf::from(v));
            }
        }
        let identity_key = identity_key.unwrap_or_else(|| data_dir.join("identity.key"));

        // Listen: explicit flags win; else a single env list; else the default.
        if listen.is_empty() {
            if let Some(v) = env(ENV_LISTEN) {
                for entry in v.split([',', ' ', '\t']).filter(|s| !s.is_empty()) {
                    listen.push(parse_listen(entry)?);
                }
            }
        }
        if listen.is_empty() {
            listen.push(parse_listen(DEFAULT_LISTEN)?);
        }

        // Dial: explicit flags win; else a single env list; no default (a
        // seed/first node dials nothing).
        if dial.is_empty() {
            if let Some(v) = env(ENV_DIAL) {
                for entry in v.split([',', ' ', '\t']).filter(|s| !s.is_empty()) {
                    dial.push(parse_listen(entry)?);
                }
            }
        }

        // Seed: explicit flags win; else a single env list; no default (a
        // seed/first node has no seed to join through).
        if seed.is_empty() {
            if let Some(v) = env(ENV_SEED) {
                for entry in v.split([',', ' ', '\t']).filter(|s| !s.is_empty()) {
                    seed.push(parse_listen(entry)?);
                }
            }
        }

        // Network root: explicit flag wins; else env; else the public
        // default (`None` — no pnet key, the well-known open federation).
        if network_root.is_none() {
            network_root = env(ENV_NETWORK_ROOT);
        }

        // web_bind: explicit flag wins; else env; else disabled (no web
        // surface). `node run` never opens a web listener unless configured.
        if web_bind.is_none() {
            if let Some(v) = env(ENV_WEB_BIND) {
                web_bind = Some(parse_web_bind(&v)?);
            }
        }
        if web_port.is_none() {
            if let Some(v) = env(ENV_WEB_PORT) {
                web_port = Some(parse_web_port(&v)?);
            }
        }

        // health_bind/health_port: explicit flag wins; else env; else the
        // built-in default (enabled on all interfaces). Left as `None` here
        // and resolved to the default at serve time so the struct records
        // only an explicit override.
        if health_bind.is_none() {
            if let Some(v) = env(ENV_HEALTH_BIND) {
                health_bind = Some(parse_health_bind(&v)?);
            }
        }
        if health_port.is_none() {
            if let Some(v) = env(ENV_HEALTH_PORT) {
                health_port = Some(parse_health_port(&v)?);
            }
        }

        Ok(NodeConfig {
            identity_key,
            data_dir,
            listen,
            dial,
            seed,
            network_root,
            web_bind,
            web_port: web_port.unwrap_or(DEFAULT_WEB_PORT),
            health_bind,
            health_port,
        })
    }

    /// Resolves a config from a real argv slice and the process environment.
    pub fn from_process_args(args: &[String]) -> Result<Self, ConfigError> {
        Self::from_args_env(args, |k| std::env::var(k).ok())
    }
}

fn parse_listen(value: &str) -> Result<Multiaddr, ConfigError> {
    value
        .parse::<Multiaddr>()
        .map_err(|e| ConfigError::BadListen {
            value: value.to_owned(),
            reason: e.to_string(),
        })
}

fn parse_web_bind(value: &str) -> Result<IpAddr, ConfigError> {
    value
        .parse::<IpAddr>()
        .map_err(|e| ConfigError::BadWebBind {
            value: value.to_owned(),
            reason: e.to_string(),
        })
}

fn parse_web_port(value: &str) -> Result<u16, ConfigError> {
    value.parse::<u16>().map_err(|e| ConfigError::BadWebPort {
        value: value.to_owned(),
        reason: e.to_string(),
    })
}

fn parse_health_bind(value: &str) -> Result<IpAddr, ConfigError> {
    value
        .parse::<IpAddr>()
        .map_err(|e| ConfigError::BadHealthBind {
            value: value.to_owned(),
            reason: e.to_string(),
        })
}

fn parse_health_port(value: &str) -> Result<u16, ConfigError> {
    value
        .parse::<u16>()
        .map_err(|e| ConfigError::BadHealthPort {
            value: value.to_owned(),
            reason: e.to_string(),
        })
}

/// A failure booting the peer.
#[derive(Debug)]
pub enum BootError {
    /// The data directory could not be created/prepared.
    DataDir {
        /// The directory being prepared.
        path: PathBuf,
        /// The underlying I/O failure.
        source: std::io::Error,
    },
    /// The identity key could not be read, decoded, generated, or persisted.
    Identity {
        /// The key file path.
        path: PathBuf,
        /// A human-readable reason.
        reason: String,
    },
    /// The libp2p swarm could not be built or bound.
    Transport(String),
    /// The durable streaming DB could not be opened under the data dir.
    StreamDb {
        /// The streaming DB root directory.
        path: PathBuf,
        /// A human-readable reason.
        reason: String,
    },
    /// This build's own compatibility self-check failed (ROI P1
    /// "Compatibility contract: check, negotiate, N-1+"): it would drop
    /// support for a surface version still legitimately inside the N-1+
    /// backward-compat window, orphaning any peer still running it. Boot is
    /// refused rather than shipping a release that strands an in-window
    /// peer — see [`run_startup_self_checks`].
    CompatSelfCheck(pillar_crypto::StartupSelfCheckFailed),
}

impl std::fmt::Display for BootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootError::DataDir { path, source } => {
                write!(f, "preparing data dir {}: {source}", path.display())
            }
            BootError::Identity { path, reason } => {
                write!(f, "identity key {}: {reason}", path.display())
            }
            BootError::Transport(e) => write!(f, "transport bring-up: {e}"),
            BootError::StreamDb { path, reason } => {
                write!(f, "streaming DB {}: {reason}", path.display())
            }
            BootError::CompatSelfCheck(e) => write!(f, "compatibility self-check: {e}"),
        }
    }
}

impl std::error::Error for BootError {}

/// Runs this build's compatibility startup self-checks (ROI P1
/// "Compatibility contract: check, negotiate, N-1+") over every wire surface
/// this binary negotiates on, failing closed the instant ANY of them would
/// drop support for a version still inside its N-1+ compat window — refusing
/// to boot a release that would silently orphan an already-in-window peer.
///
/// Each check names: the surface, the current running/released version this
/// build assumes for it, the OLDEST version this build still supports (its
/// `min`), and the compat window in force. A future release that widens a
/// surface's version without widening (or explicitly retiring, by lowering
/// the window) its own `min` accordingly fails here BEFORE any transport
/// comes up.
///
/// # Errors
/// Returns the FIRST [`pillar_crypto::StartupSelfCheckFailed`] encountered.
pub fn run_startup_self_checks() -> Result<(), pillar_crypto::StartupSelfCheckFailed> {
    pillar_crypto::startup_self_check(
        pillar_net::pillar_udp::PROTOCOL_SURFACE,
        pillar_net::pillar_udp::PROTOCOL_VERSION,
        pillar_net::pillar_udp::MIN_PROTOCOL_VERSION,
        pillar_net::pillar_udp::PROTOCOL_COMPAT_WINDOW,
    )?;
    pillar_crypto::startup_self_check(
        pillar_net::MESSAGE_SURFACE,
        pillar_net::MESSAGE_VERSION,
        pillar_net::MIN_MESSAGE_VERSION,
        pillar_net::MESSAGE_COMPAT_WINDOW,
    )?;
    pillar_crypto::startup_self_check(
        "http-ingest-api",
        crate::web_serve::API_VERSION,
        crate::web_serve::MIN_API_VERSION,
        pillar_crypto::CompatWindow(
            crate::web_serve::API_VERSION.0 - crate::web_serve::MIN_API_VERSION.0,
        ),
    )?;
    Ok(())
}

/// Ensures `data_dir` exists (creating it and any parents), returning it back
/// for chaining.
pub fn prepare_data_dir(data_dir: &Path) -> Result<(), BootError> {
    std::fs::create_dir_all(data_dir).map_err(|source| BootError::DataDir {
        path: data_dir.to_path_buf(),
        source,
    })
}

/// Loads the node's ed25519 keypair from `path`, generating and persisting a
/// fresh one if the file does not yet exist.
///
/// The on-disk form is the libp2p canonical protobuf encoding
/// ([`Keypair::to_protobuf_encoding`] / [`Keypair::from_protobuf_encoding`]),
/// so a persisted key round-trips to the identical [`libp2p::PeerId`] across
/// restarts. The parent directory must already exist (see
/// [`prepare_data_dir`]).
pub fn load_or_create_identity(path: &Path) -> Result<Keypair, BootError> {
    if path.exists() {
        let bytes = std::fs::read(path).map_err(|e| BootError::Identity {
            path: path.to_path_buf(),
            reason: format!("read: {e}"),
        })?;
        Keypair::from_protobuf_encoding(&bytes).map_err(|e| BootError::Identity {
            path: path.to_path_buf(),
            reason: format!("decode: {e}"),
        })
    } else {
        let keypair = Keypair::generate_ed25519();
        let bytes = keypair
            .to_protobuf_encoding()
            .map_err(|e| BootError::Identity {
                path: path.to_path_buf(),
                reason: format!("encode: {e}"),
            })?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| BootError::Identity {
                    path: path.to_path_buf(),
                    reason: format!("create parent dir: {e}"),
                })?;
            }
        }
        std::fs::write(path, &bytes).map_err(|e| BootError::Identity {
            path: path.to_path_buf(),
            reason: format!("write: {e}"),
        })?;
        Ok(keypair)
    }
}

/// Boots a full peer from `config` and blocks until a shutdown signal.
///
/// The steps are exactly those the module doc lists: prepare the data dir,
/// load/create the identity, open the streaming DB, bring up the libp2p event
/// swarm on the configured listen addrs, subscribe to the event-log topic, and
/// run the swarm/controller event loop until SIGINT/SIGTERM. Returns `Ok(())`
/// on a clean shutdown.
///
/// This is the imperative shell over the pure, unit-tested helpers above; it
/// performs real network and filesystem side effects and so is driven by the
/// integration/deploy path rather than unit tests.
pub async fn run(config: NodeConfig) -> Result<(), BootError> {
    use futures::StreamExt;
    use libp2p::swarm::SwarmEvent;

    // Compatibility self-check FIRST, before any state is touched or
    // transport brought up: a build that would drop support for a still
    // in-window surface version refuses to boot at all.
    run_startup_self_checks().map_err(BootError::CompatSelfCheck)?;

    prepare_data_dir(&config.data_dir)?;
    let keypair = load_or_create_identity(&config.identity_key)?;
    let peer_id = pillar_net::peer_id_of(&keypair);
    tracing::info!(%peer_id, data_dir = %config.data_dir.display(), "pillar peer identity loaded");

    // Streaming DB: the durable, content-addressed op store the controller
    // reconciles against, rooted under the data dir so ops survive a restart.
    let streamdb_root = config.data_dir.join("streamdb");
    let mut stream = pillar_streamdb::PersistentStream::open(&streamdb_root).map_err(|e| {
        BootError::StreamDb {
            path: streamdb_root.clone(),
            reason: e.to_string(),
        }
    })?;
    tracing::info!(
        streamdb_root = %streamdb_root.display(),
        ops = stream.stream().log().len(),
        "pillar streaming DB opened (durable, content-addressed)"
    );

    // Readiness: at this point the identity keypair is loaded and the durable
    // streaming DB has been opened and its materialized view rehydrated from
    // the persisted op store (zero ops on a first boot IS the correct
    // rehydrated state). The WoT root self-verifies iff this node's trust
    // anchor vouches for itself — a fresh anchor rooted at this peer does.
    // These three facts are exactly what the readinessProbe gates on; a bound
    // port alone is NOT sufficient. We publish a live readiness snapshot and
    // serve `GET /readyz` (200 ready / 503 with the failing condition) so a
    // node that is not truly ready keeps its pod out of the Service and halts
    // a rolling upgrade visibly instead of silently serving broken.
    let wot_anchor = pillar_wot_authority::WotAuthority::new(
        pillar_core::NodeId::from(format!("{peer_id}").as_str()),
        16,
    );
    let readiness = crate::health::NodeReadiness {
        identity_loaded: true,
        views_rehydrated: true,
        wot_root_verified: crate::health::wot_root_self_verifies(&wot_anchor),
    };
    let health_bind = config.health_bind.unwrap_or(DEFAULT_HEALTH_BIND);
    let health_port = config
        .health_port
        .unwrap_or(crate::health::DEFAULT_HEALTH_PORT);
    match crate::health::bind(health_bind, health_port) {
        Ok(listener) => {
            let bound = listener
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| format!("{health_bind}:{health_port}"));
            tracing::info!(bound = %bound, ready = readiness.is_ready(), "pillar readiness/liveness probe listening");
            std::thread::spawn(move || {
                crate::health::serve(listener, move || readiness);
            });
        }
        Err(e) => {
            tracing::error!(error = %e, %health_bind, port = health_port, "pillar health probe failed to bind — readiness cannot be reported");
        }
    }

    // Transport: bring up the libp2p event swarm and subscribe to the log
    // topic. The configured network root (`None` == the public default)
    // selects whether the transport is pnet-walled to a private swarm.
    let root = match &config.network_root {
        Some(secret) => {
            tracing::info!(
                "pillar peer configured with a PRIVATE network root (pnet-walled transport)"
            );
            pillar_net::PrivateSwarmKey::from_root_secret(secret)
        }
        None => pillar_net::PrivateSwarmKey::disabled(),
    };
    let mut swarm = pillar_net::build_event_swarm_with_root(keypair, root)
        .map_err(|e| BootError::Transport(e.to_string()))?;
    let topic = pillar_net::event_log_topic();
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topic)
        .map_err(|e| BootError::Transport(format!("subscribe: {e}")))?;
    for addr in &config.listen {
        swarm
            .listen_on(addr.clone())
            .map_err(|e| BootError::Transport(format!("listen_on {addr}: {e}")))?;
    }
    for addr in &config.dial {
        match swarm.dial(addr.clone()) {
            Ok(()) => tracing::info!(%addr, "pillar peer dialing configured peer"),
            Err(e) => {
                tracing::warn!(%addr, error = %e, "pillar peer failed to dial configured peer")
            }
        }
    }

    // Federation join: parse each configured seed multiaddr and seed the
    // Kademlia routing table, then kick a DHT bootstrap so this node enters
    // Pillar's own swarm (NOT the public IPFS DHT). A malformed seed (no
    // `/p2p/<peer-id>`) is logged and skipped — one bad seed never aborts boot.
    // Seeds are discovery helpers only; authority stays with the WoT.
    let mut seeds = Vec::with_capacity(config.seed.len());
    for addr in &config.seed {
        match pillar_net::parse_seed_multiaddr(addr.clone()) {
            Ok(seed) => {
                tracing::info!(%addr, peer_id = %seed.peer_id, "pillar peer configured federation seed");
                seeds.push(seed);
            }
            Err(e) => tracing::warn!(%addr, error = %e, "ignoring malformed federation seed"),
        }
    }
    let added = pillar_net::seed_event_dht(&mut swarm, &seeds);
    if added > 0 {
        tracing::info!(
            seeds = added,
            "pillar peer bootstrapping DHT from federation seed(s)"
        );
    } else {
        tracing::info!("pillar peer has no federation seed; acting as a seed/first node");
    }

    tracing::info!("pillar peer running; press Ctrl-C to stop");

    // Serve the web UI on a configurable, possibly non-loopback bind (see
    // `crate::web_serve` for the auth-gate contract) — only when
    // `--web-bind`/`PILLAR_WEB_BIND` was actually configured; unset, `node
    // run` opens no web listener at all.
    if let Some(web_bind) = config.web_bind {
        match crate::web_serve::bind(web_bind, config.web_port) {
            Ok(listener) => {
                let bound = listener
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| format!("{web_bind}:{}", config.web_port));
                tracing::info!(bound = %bound, "pillar web UI listening");
                // Real deployments register offers / admit subjects out of
                // band (the manifest-driven onboarding + key-distribution
                // flow); this boot sequence opens the gated listener with an
                // empty node-side-custody `WebAuthContext` (a fresh,
                // unbootstrapped node whose `/` serves the create-cell ->
                // create-first-user flow) — every non-loopback signing action
                // is refused until a login admits, matching the
                // "exposed ⇒ authenticated" invariant exactly.
                let mut ctx = crate::web_serve::WebAuthContext::new(
                    format!("https://{peer_id}"),
                    pillar_core::NodeId::from("pillar-node"),
                    format!("pillar-node-key-{peer_id}"),
                    pillar_core::NodeId::from("pillar-node"),
                    16,
                );
                std::thread::spawn(move || crate::web_serve::serve(listener, &mut ctx));
            }
            Err(e) => {
                tracing::warn!(error = %e, %web_bind, port = config.web_port, "pillar web UI failed to bind; continuing without it");
            }
        }
    }

    // Integration-rig-only: once the listening addr(s) are confirmed and a
    // grace period elapses (letting `--dial` connections/gossipsub mesh
    // settle), publish PILLAR_TEST_PUBLISH's value once to the event-log
    // topic. Absent the env var this future never resolves and costs
    // nothing beyond the idle `tokio::select!` arm.
    let test_publish = std::env::var(ENV_TEST_PUBLISH).ok();
    let mut publish_at = test_publish
        .is_some()
        .then(|| Box::pin(tokio::time::sleep(TEST_PUBLISH_DELAY)));
    let mut published = false;

    // Controller loop: fold inbound event-log messages into the stream and
    // block until a shutdown signal.
    let mut shutdown = Box::pin(shutdown_signal());
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received; stopping peer");
                return Ok(());
            }
            () = async {
                if let Some(sleep) = publish_at.as_mut() {
                    sleep.await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if !published && publish_at.is_some() => {
                if let Some(payload) = &test_publish {
                    match swarm.behaviour_mut().gossipsub.publish(topic.clone(), payload.clone().into_bytes()) {
                        Ok(_) => tracing::info!(%payload, "pillar peer published test payload"),
                        Err(e) => tracing::warn!(%payload, error = %e, "pillar peer failed to publish test payload"),
                    }
                }
                published = true;
                publish_at = None;
            }
            event = swarm.select_next_some() => {
                match &event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        tracing::info!(%address, "pillar peer listening");
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        tracing::info!(%peer_id, "pillar peer connection established");
                    }
                    _ => {}
                }
                if let SwarmEvent::Behaviour(pillar_net::EventBehaviourEvent::Gossipsub(
                    libp2p::gossipsub::Event::Message { message, .. },
                )) = event
                {
                    let payload_text = String::from_utf8_lossy(&message.data).into_owned();
                    tracing::info!(payload = %payload_text, "pillar peer received gossip event");
                    // Every gossiped event-log message is an append-only op the
                    // controller folds into the local stream view AND durably
                    // persists under the content-addressed data-dir store.
                    if let Err(e) = stream.append(
                        message.data,
                        pillar_core::SideEffect::Convergent,
                    ) {
                        tracing::warn!(error = %e, "pillar streaming DB append failed");
                    }
                }
            }
        }
    }
}

/// A future that resolves on the first SIGINT or (on Unix) SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn s(v: &str) -> String {
        v.to_owned()
    }

    // --- startup compat self-check (ROI P1 "Compatibility contract: check,
    // negotiate, N-1+") ---

    #[test]
    fn startup_self_checks_pass_for_the_current_build() {
        // The currently-shipped [min, max] windows for every negotiated
        // surface must never fail their own self-check — this is the
        // regression a future release-time regression would trip.
        run_startup_self_checks().expect("current build's own compat windows are self-consistent");
    }

    #[test]
    fn defaults_when_no_flags_and_no_env() {
        let cfg = NodeConfig::from_args_env(&[], no_env).unwrap();
        assert_eq!(cfg.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
        // Identity key defaults beside the data dir.
        assert_eq!(
            cfg.identity_key,
            PathBuf::from(DEFAULT_DATA_DIR).join("identity.key")
        );
        assert_eq!(
            cfg.listen,
            vec![DEFAULT_LISTEN.parse::<Multiaddr>().unwrap()]
        );
        // No web surface unless explicitly configured.
        assert_eq!(cfg.web_bind, None);
        assert_eq!(cfg.web_port, DEFAULT_WEB_PORT);
    }

    #[test]
    fn web_bind_flag_configures_a_non_loopback_surface() {
        let args = vec![s("--web-bind"), s("0.0.0.0"), s("--web-port"), s("9999")];
        let cfg = NodeConfig::from_args_env(&args, no_env).unwrap();
        assert_eq!(
            cfg.web_bind,
            Some(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(cfg.web_port, 9999);
    }

    #[test]
    fn web_bind_env_configures_a_non_loopback_surface() {
        let env = |k: &str| match k {
            "PILLAR_WEB_BIND" => Some("0.0.0.0".to_owned()),
            "PILLAR_WEB_PORT" => Some("7777".to_owned()),
            _ => None,
        };
        let cfg = NodeConfig::from_args_env(&[], env).unwrap();
        assert_eq!(
            cfg.web_bind,
            Some(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(cfg.web_port, 7777);
    }

    #[test]
    fn bad_web_bind_value_errors() {
        let args = vec![s("--web-bind"), s("not-an-ip")];
        let err = NodeConfig::from_args_env(&args, no_env).unwrap_err();
        assert!(matches!(err, ConfigError::BadWebBind { .. }));
    }

    #[test]
    fn flags_override_everything() {
        let args = vec![
            s("--identity-key"),
            s("/keys/node.key"),
            s("--data-dir"),
            s("/var/lib/pillar"),
            s("--listen"),
            s("/ip4/127.0.0.1/tcp/4001"),
            s("--listen"),
            s("/ip4/0.0.0.0/udp/4001/quic-v1"),
        ];
        let cfg = NodeConfig::from_args_env(&args, no_env).unwrap();
        assert_eq!(cfg.identity_key, PathBuf::from("/keys/node.key"));
        assert_eq!(cfg.data_dir, PathBuf::from("/var/lib/pillar"));
        assert_eq!(
            cfg.listen,
            vec![
                "/ip4/127.0.0.1/tcp/4001".parse::<Multiaddr>().unwrap(),
                "/ip4/0.0.0.0/udp/4001/quic-v1"
                    .parse::<Multiaddr>()
                    .unwrap(),
            ]
        );
    }

    #[test]
    fn env_fills_when_flags_absent() {
        let env = |k: &str| match k {
            ENV_IDENTITY_KEY => Some(s("/env/id.key")),
            ENV_DATA_DIR => Some(s("/env/data")),
            ENV_LISTEN => Some(s("/ip4/10.0.0.1/tcp/5001, /ip4/10.0.0.1/tcp/5002")),
            _ => None,
        };
        let cfg = NodeConfig::from_args_env(&[], env).unwrap();
        assert_eq!(cfg.identity_key, PathBuf::from("/env/id.key"));
        assert_eq!(cfg.data_dir, PathBuf::from("/env/data"));
        assert_eq!(
            cfg.listen,
            vec![
                "/ip4/10.0.0.1/tcp/5001".parse::<Multiaddr>().unwrap(),
                "/ip4/10.0.0.1/tcp/5002".parse::<Multiaddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn flags_take_precedence_over_env() {
        let env = |k: &str| match k {
            ENV_DATA_DIR => Some(s("/env/data")),
            _ => None,
        };
        let args = vec![s("--data-dir"), s("/flag/data")];
        let cfg = NodeConfig::from_args_env(&args, env).unwrap();
        assert_eq!(cfg.data_dir, PathBuf::from("/flag/data"));
    }

    #[test]
    fn identity_key_default_follows_env_data_dir() {
        let env = |k: &str| match k {
            ENV_DATA_DIR => Some(s("/env/data")),
            _ => None,
        };
        let cfg = NodeConfig::from_args_env(&[], env).unwrap();
        assert_eq!(
            cfg.identity_key,
            PathBuf::from("/env/data").join("identity.key")
        );
    }

    #[test]
    fn explicit_listen_flag_wins_over_env_list() {
        let env = |k: &str| match k {
            ENV_LISTEN => Some(s("/ip4/10.0.0.1/tcp/5001")),
            _ => None,
        };
        let args = vec![s("--listen"), s("/ip4/127.0.0.1/tcp/1")];
        let cfg = NodeConfig::from_args_env(&args, env).unwrap();
        assert_eq!(
            cfg.listen,
            vec!["/ip4/127.0.0.1/tcp/1".parse::<Multiaddr>().unwrap()]
        );
    }

    #[test]
    fn missing_flag_value_errors() {
        let err = NodeConfig::from_args_env(&[s("--data-dir")], no_env).unwrap_err();
        assert_eq!(err, ConfigError::MissingValue("--data-dir"));
    }

    #[test]
    fn bad_listen_multiaddr_errors() {
        let args = vec![s("--listen"), s("not-a-multiaddr")];
        let err = NodeConfig::from_args_env(&args, no_env).unwrap_err();
        match err {
            ConfigError::BadListen { value, .. } => assert_eq!(value, "not-a-multiaddr"),
            other => panic!("expected BadListen, got {other:?}"),
        }
    }

    #[test]
    fn unknown_arg_errors() {
        let err = NodeConfig::from_args_env(&[s("--frobnicate")], no_env).unwrap_err();
        assert_eq!(err, ConfigError::Unknown(s("--frobnicate")));
    }

    #[test]
    fn identity_is_generated_persisted_and_stable_across_loads() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("nested").join("identity.key");

        // First load generates and persists.
        assert!(!key_path.exists());
        let first = load_or_create_identity(&key_path).unwrap();
        assert!(key_path.exists(), "key file persisted on first boot");
        let first_peer = pillar_net::peer_id_of(&first);

        // Second load reads the same key back to the same PeerId.
        let second = load_or_create_identity(&key_path).unwrap();
        let second_peer = pillar_net::peer_id_of(&second);
        assert_eq!(first_peer, second_peer, "peer id stable across restarts");
    }

    #[test]
    fn prepare_data_dir_creates_nested_path() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        assert!(!nested.exists());
        prepare_data_dir(&nested).unwrap();
        assert!(nested.is_dir());
    }

    #[test]
    fn seed_defaults_empty_and_is_distinct_from_dial() {
        let cfg = NodeConfig::from_args_env(&[], no_env).unwrap();
        assert!(
            cfg.seed.is_empty(),
            "no seed by default (a seed/first node)"
        );
        assert!(cfg.dial.is_empty(), "no dial by default");
    }

    #[test]
    fn seed_flags_are_collected_and_repeatable() {
        let args = vec![
            s("--seed"),
            s("/ip4/10.0.0.1/tcp/4001/p2p/12D3KooWA6qcyKq9Ph8jNKa2P4kHwxwyF3vD4t5xNfBqkQ8mQmVn"),
            s("--seed"),
            s("/ip4/10.0.0.2/tcp/4001/p2p/12D3KooWA6qcyKq9Ph8jNKa2P4kHwxwyF3vD4t5xNfBqkQ8mQmVn"),
        ];
        let cfg = NodeConfig::from_args_env(&args, no_env).unwrap();
        assert_eq!(cfg.seed.len(), 2);
        // --dial and --seed are independent knobs.
        assert!(cfg.dial.is_empty());
    }

    #[test]
    fn seed_env_list_fills_when_flag_absent() {
        let env = |k: &str| match k {
            ENV_SEED => Some(s(
                "/ip4/10.0.0.1/tcp/4001/p2p/12D3KooWA6qcyKq9Ph8jNKa2P4kHwxwyF3vD4t5xNfBqkQ8mQmVn, \
                 /ip4/10.0.0.2/tcp/4001/p2p/12D3KooWA6qcyKq9Ph8jNKa2P4kHwxwyF3vD4t5xNfBqkQ8mQmVn",
            )),
            _ => None,
        };
        let cfg = NodeConfig::from_args_env(&[], env).unwrap();
        assert_eq!(cfg.seed.len(), 2);
    }

    #[test]
    fn seed_flag_wins_over_env_list() {
        let env = |k: &str| match k {
            ENV_SEED => Some(s(
                "/ip4/10.0.0.9/tcp/4001/p2p/12D3KooWA6qcyKq9Ph8jNKa2P4kHwxwyF3vD4t5xNfBqkQ8mQmVn",
            )),
            _ => None,
        };
        let args = vec![
            s("--seed"),
            s("/ip4/127.0.0.1/tcp/1/p2p/12D3KooWA6qcyKq9Ph8jNKa2P4kHwxwyF3vD4t5xNfBqkQ8mQmVn"),
        ];
        let cfg = NodeConfig::from_args_env(&args, env).unwrap();
        assert_eq!(cfg.seed.len(), 1);
        assert_eq!(
            cfg.seed[0],
            "/ip4/127.0.0.1/tcp/1/p2p/12D3KooWA6qcyKq9Ph8jNKa2P4kHwxwyF3vD4t5xNfBqkQ8mQmVn"
                .parse::<Multiaddr>()
                .unwrap()
        );
    }

    #[test]
    fn missing_seed_value_errors() {
        let err = NodeConfig::from_args_env(&[s("--seed")], no_env).unwrap_err();
        assert_eq!(err, ConfigError::MissingValue("--seed"));
    }

    #[test]
    fn network_root_defaults_unset_the_public_default() {
        let cfg = NodeConfig::from_args_env(&[], no_env).unwrap();
        assert_eq!(
            cfg.network_root, None,
            "no configured root means the well-known public federation"
        );
    }

    #[test]
    fn network_root_flag_configures_a_private_root() {
        let args = vec![s("--network-root"), s("my-app-secret-root")];
        let cfg = NodeConfig::from_args_env(&args, no_env).unwrap();
        assert_eq!(cfg.network_root, Some(s("my-app-secret-root")));
    }

    #[test]
    fn network_root_env_fills_when_flag_absent() {
        let env = |k: &str| match k {
            ENV_NETWORK_ROOT => Some(s("env-root-secret")),
            _ => None,
        };
        let cfg = NodeConfig::from_args_env(&[], env).unwrap();
        assert_eq!(cfg.network_root, Some(s("env-root-secret")));
    }

    #[test]
    fn network_root_flag_wins_over_env() {
        let env = |k: &str| match k {
            ENV_NETWORK_ROOT => Some(s("env-root-secret")),
            _ => None,
        };
        let args = vec![s("--network-root"), s("flag-root-secret")];
        let cfg = NodeConfig::from_args_env(&args, env).unwrap();
        assert_eq!(cfg.network_root, Some(s("flag-root-secret")));
    }

    #[test]
    fn missing_network_root_value_errors() {
        let err = NodeConfig::from_args_env(&[s("--network-root")], no_env).unwrap_err();
        assert_eq!(err, ConfigError::MissingValue("--network-root"));
    }

    #[test]
    fn health_bind_defaults_unset_meaning_the_all_interfaces_default() {
        let cfg = NodeConfig::from_args_env(&[], no_env).unwrap();
        // Unset in the struct → resolved to DEFAULT_HEALTH_BIND at serve
        // time (enabled by default so the readinessProbe can reach it).
        assert_eq!(cfg.health_bind, None);
        assert_eq!(cfg.health_port, None);
    }

    #[test]
    fn health_bind_and_port_flags_configure_the_probe() {
        let args = vec![
            s("--health-bind"),
            s("127.0.0.1"),
            s("--health-port"),
            s("9100"),
        ];
        let cfg = NodeConfig::from_args_env(&args, no_env).unwrap();
        assert_eq!(
            cfg.health_bind,
            Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        );
        assert_eq!(cfg.health_port, Some(9100));
    }

    #[test]
    fn health_env_fills_when_flags_absent() {
        let env = |k: &str| match k {
            "PILLAR_HEALTH_BIND" => Some(s("0.0.0.0")),
            "PILLAR_HEALTH_PORT" => Some(s("9200")),
            _ => None,
        };
        let cfg = NodeConfig::from_args_env(&[], env).unwrap();
        assert_eq!(
            cfg.health_bind,
            Some(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(cfg.health_port, Some(9200));
    }

    #[test]
    fn bad_health_bind_value_errors() {
        let args = vec![s("--health-bind"), s("nope")];
        let err = NodeConfig::from_args_env(&args, no_env).unwrap_err();
        assert!(matches!(err, ConfigError::BadHealthBind { .. }));
    }

    #[test]
    fn bad_health_port_value_errors() {
        let args = vec![s("--health-port"), s("99999")];
        let err = NodeConfig::from_args_env(&args, no_env).unwrap_err();
        assert!(matches!(err, ConfigError::BadHealthPort { .. }));
    }
}
