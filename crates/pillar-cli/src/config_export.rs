//! `pillar config export`: the CLI half of `cli-config-subkey-credential`.
//!
//! Every `ResourceOp` is individually cell-sealed AND signer-signed, and the
//! node re-verifies both (see `crate::apply_over_pillar_message` /
//! `crate::resource_op_udp_server`) — so the CLI's baked-in credential must
//! be REAL seal+sign key material, never a bearer session token. This
//! command drives that mint end to end over the caller's own AUTHENTICATED
//! `pillar login` session:
//!
//! 1. Reads the session bearer `pillar login` minted (`$PILLAR_TOKEN` /
//!    `--token`) and the node authority (`$PILLAR_DOMAIN` / `--domain`).
//! 2. `POST /portal/profile/cli-config` with that bearer. The node mints a
//!    FRESH, scoped ed25519 signing subkey for this user (never the user's
//!    own cell key), durably WoT-admits it as a resource-op signer under the
//!    authenticated session (never the unauthenticated
//!    `/bootstrap/admit-resource-signer` SETUP-only endpoint), and returns a
//!    ready `config.yaml` carrying that subkey plus the cell group key the
//!    user already holds.
//! 3. Persists the parsed config to `~/.config/pillar/config.yaml` (or
//!    `--out <path>`) and — on a Unix host — chmods it `0600` immediately
//!    after writing, so the sensitive key material is never briefly
//!    world/group-readable on disk.
//!
//! Revoking this CLI credential (retiring the subkey's admission, server
//! side) never revokes the user's own key — the two are deliberately
//! distinct principals from the node's point of view.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pillar_bootstrap::token::{PILLAR_DOMAIN_ENV, PILLAR_TOKEN_ENV};
use pillar_client::ClientConfig;

use crate::bootstrap::{authority_of, http};

/// A fault exporting/persisting a CLI config — a human-readable message.
#[derive(Debug, PartialEq, Eq)]
pub struct ExportError(pub String);

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ExportError {}

/// Strip a leading `#`-comment banner (the human-facing warning the node
/// prepends) before handing the body to the YAML parser — comments are
/// already valid YAML and `serde_yaml` ignores them, but stripping keeps the
/// parse path independent of that incidental fact.
fn strip_comment_banner(body: &str) -> String {
    body.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Call `POST /portal/profile/cli-config` at `authority` with session
/// `token`, mint+enroll a fresh CLI signing subkey, and parse the returned
/// `config.yaml` into a [`ClientConfig`]. This is the pure, testable core
/// [`run`] wraps.
///
/// # Errors
/// [`ExportError`] on an unreachable node, a non-2xx reply (most commonly an
/// expired/invalid session — re-run `pillar login`), or a malformed
/// `config.yaml` body.
pub fn fetch_config(authority: &str, token: &str) -> Result<ClientConfig, ExportError> {
    let reply = http(authority, "POST", "/portal/profile/cli-config", token)
        .map_err(ExportError)?;
    if reply.status != 200 {
        return Err(ExportError(format!(
            "cli-config export refused: {} {} — run `pillar login` again if your session expired",
            reply.status, reply.body
        )));
    }
    let yaml = strip_comment_banner(&reply.body);
    ClientConfig::parse(&yaml, Path::new("<cli-config-export>"))
        .map_err(|e| ExportError(format!("parsing exported config.yaml: {e}")))
}

/// The default per-user config path (`~/.config/pillar/config.yaml`, or
/// `$XDG_CONFIG_HOME/pillar/config.yaml` when set) — the SAME per-user layer
/// [`pillar_client::ConfigDirs::search_paths`] resolves, so a config saved
/// here is picked up with no further flag on the next `pillar apply`/`pillar
/// delete`.
#[must_use]
pub fn default_export_path() -> Option<PathBuf> {
    let dirs = pillar_client::ConfigDirs::from_env();
    if let Some(xdg) = dirs.xdg_config {
        return Some(xdg.join("pillar").join("config.yaml"));
    }
    dirs.home.map(|home| home.join(".config").join("pillar").join("config.yaml"))
}

/// Save `cfg` to `path`, creating parent directories as needed, and — on a
/// Unix host — restrict its mode to `0600` immediately after writing so the
/// baked-in signer secret and cell seed are never left group/world-readable.
/// Non-interactive: never prompts, never reads a passphrase (the subkey
/// itself unlocks with no custody ceremony — that IS the point of a scoped,
/// revocable CLI credential).
///
/// # Errors
/// [`ExportError`] on a create-dir/write/chmod fault.
pub fn save_0600(cfg: &ClientConfig, path: &Path) -> Result<(), ExportError> {
    cfg.save(path)
        .map_err(|e| ExportError(format!("writing {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| ExportError(format!("chmod 0600 {}: {e}", path.display())))?;
    }
    Ok(())
}

/// A key=value/positional argv scanner mirroring `crate::bootstrap`'s.
struct Args<'a> {
    flags: Vec<(&'a str, String)>,
}

impl<'a> Args<'a> {
    fn parse(args: &'a [String]) -> Result<Self, ExportError> {
        let mut flags = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            if let Some(name) = a.strip_prefix("--") {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| ExportError(format!("flag --{name} requires a value")))?;
                flags.push((name, value.clone()));
                i += 2;
            } else {
                i += 1;
            }
        }
        Ok(Args { flags })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// `pillar config export [--domain D] [--token T] [--out PATH]`: mint+enroll
/// a scoped CLI signing subkey over the caller's authenticated `pillar
/// login` session and persist it as a `config.yaml`, 0600, ready for `pillar
/// apply`/`pillar delete` with no further setup.
///
/// # Errors
/// A human-readable message on any usage / auth / transport / io failure.
pub fn export(args: &[String]) -> Result<PathBuf, ExportError> {
    let parsed = Args::parse(args)?;
    let domain = parsed
        .get("domain")
        .map(str::to_owned)
        .or_else(|| std::env::var(PILLAR_DOMAIN_ENV).ok())
        .ok_or_else(|| {
            ExportError(format!(
                "no --domain and {PILLAR_DOMAIN_ENV} is unset — run `pillar login` first"
            ))
        })?;
    let (authority, _host) = authority_of(&domain);
    let token = parsed
        .get("token")
        .map(str::to_owned)
        .or_else(|| std::env::var(PILLAR_TOKEN_ENV).ok())
        .ok_or_else(|| {
            ExportError(format!(
                "no --token and {PILLAR_TOKEN_ENV} is unset — run `pillar login` first to authenticate"
            ))
        })?;
    let out = parsed
        .get("out")
        .map(PathBuf::from)
        .or_else(default_export_path)
        .ok_or_else(|| {
            ExportError("no --out and no $HOME/$XDG_CONFIG_HOME to derive a default path".to_owned())
        })?;

    let cfg = fetch_config(&authority, &token)?;
    save_0600(&cfg, &out)?;
    Ok(out)
}

/// `pillar config …` verb dispatch.
pub fn run(args: &[String]) -> ExitCode {
    let Some((sub, rest)) = args.split_first() else {
        eprintln!("usage: pillar config export [--domain D] [--token T] [--out PATH]");
        return ExitCode::from(2);
    };
    match sub.as_str() {
        "export" => match export(rest) {
            Ok(path) => {
                println!("CLI config written to {} (0600)", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("pillar config export: {e}");
                ExitCode::FAILURE
            }
        },
        other => {
            eprintln!("pillar config: unknown subcommand {other:?} (expected `export`)");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_comment_banner_drops_hash_lines_only() {
        let body = "# banner line one\n# banner line two\ncell: c\nuser: u\n";
        assert_eq!(strip_comment_banner(body), "cell: c\nuser: u");
    }

    #[test]
    fn export_requires_domain() {
        std::env::remove_var(PILLAR_DOMAIN_ENV);
        std::env::remove_var(PILLAR_TOKEN_ENV);
        let err = export(&["--token".to_owned(), "t".to_owned()]).unwrap_err();
        assert!(err.0.contains("--domain"), "{}", err.0);
    }

    #[test]
    fn export_requires_token() {
        std::env::remove_var(PILLAR_TOKEN_ENV);
        let err = export(&[
            "--domain".to_owned(),
            "example.invalid:8642".to_owned(),
        ])
        .unwrap_err();
        assert!(err.0.contains("--token"), "{}", err.0);
    }

    #[test]
    fn default_export_path_prefers_xdg_config_home() {
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/cli-config-subkey-credential-xdg");
        std::env::set_var("HOME", "/tmp/cli-config-subkey-credential-home");
        let path = default_export_path().expect("path");
        assert_eq!(
            path,
            PathBuf::from("/tmp/cli-config-subkey-credential-xdg/pillar/config.yaml")
        );
        std::env::remove_var("XDG_CONFIG_HOME");
    }
}
