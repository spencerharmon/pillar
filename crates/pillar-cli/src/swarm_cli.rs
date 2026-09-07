//! `pillar swarm …` — read-only inspection + keygen for the physical libp2p
//! swarm this node speaks on. **Pillar keeps no swarm state**: this verb neither
//! reads nor writes any registry. It offers exactly two facilities:
//!
//! - `pillar swarm generate` — mint a fresh PRIVATE swarm key and print it to
//!   stdout (nothing else on stdout, so `pillar swarm generate > prod.key`
//!   yields a clean key file). Save it, distribute it out-of-band, and boot
//!   each node with `pillar node run --swarm-key prod.key --seed-node <addr>`.
//! - `pillar swarm show [--swarm-key <path>] [--secret]` — read-only: print a
//!   key's kind (public/private) and non-secret fingerprint. With no
//!   `--swarm-key` it shows the **public** pillar swarm; with one it inspects
//!   that key file. Nothing is persisted.
//!
//! See `pillar_swarm` for the model: a **public** pillar swarm (the published,
//! baked-in key everyone shares) versus your **own** private swarm (a
//! high-entropy key you mint and distribute out-of-band).

use std::path::PathBuf;
use std::process::ExitCode;

use pillar_swarm::{SwarmKey, SwarmKind};

/// The `swarm` verb entrypoint, dispatched from [`crate::cli_surface`]. `args`
/// is argv AFTER the `swarm` token.
#[must_use]
pub fn run(args: &[String]) -> ExitCode {
    match dispatch(args) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("{msg}");
            eprintln!("{}", usage());
            ExitCode::from(2)
        }
    }
}

/// Pure command dispatch — the unit-tested core. Returns the stdout text or an
/// error message. Stateless: no filesystem reads except an explicit
/// `--swarm-key <path>` the operator named.
fn dispatch(args: &[String]) -> Result<String, String> {
    let reveal = args.iter().any(|a| a == "--secret" || a == "--reveal");
    let key_path = flag_value(args, "--swarm-key");
    let positional: Vec<&str> = strip_flags(args);
    match positional.split_first() {
        Some((&"generate", _)) | Some((&"gen", _)) => {
            // ONLY the key on stdout, so it can be redirected straight to a
            // file; guidance goes to stderr.
            let key = SwarmKey::generate();
            eprintln!(
                "minted a new private swarm key (fingerprint {}). Save it, distribute it \
                 out-of-band, and boot each node with `pillar node run --swarm-key <file> \
                 --seed-node <multiaddr>`.",
                key.fingerprint()
            );
            Ok(format!("{}\n", key.root_secret()))
        }
        None | Some((&"show", _)) => {
            let key = load_key(key_path.as_deref())?;
            Ok(render_show(&key, reveal))
        }
        Some((other, _)) => Err(format!("unknown `pillar swarm` subcommand `{other}`")),
    }
}

/// Load the key to inspect: the file named by `--swarm-key`, or the public
/// pillar key when none is given.
fn load_key(key_path: Option<&str>) -> Result<SwarmKey, String> {
    match key_path {
        Some(path) => SwarmKey::from_file(&PathBuf::from(path)).map_err(|e| format!("swarm: {e}")),
        None => Ok(SwarmKey::public()),
    }
}

/// The value following `flag` in `args`, if present.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Drop known flags (and their values) leaving the positional subcommand.
fn strip_flags(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--swarm-key" => i += 2,
            "--secret" | "--reveal" => i += 1,
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    out
}

fn render_show(key: &SwarmKey, reveal: bool) -> String {
    let mut out = format!(
        "kind:        {}\nfingerprint: {}\n",
        key.kind().tag(),
        key.fingerprint(),
    );
    match key.kind() {
        SwarmKind::Public => {
            out.push_str("key:         <published public pillar key — baked into every binary>\n");
        }
        SwarmKind::Private => {
            if reveal {
                out.push_str(&format!("key:         {}\n", key.root_secret()));
            } else {
                out.push_str(
                    "key:         <hidden — this is the join credential; pass --secret to reveal>\n",
                );
            }
        }
    }
    out
}

/// The `pillar swarm` help text.
#[must_use]
pub fn usage() -> &'static str {
    "usage: pillar swarm <subcommand>\n\
     \x20 generate                        mint a new PRIVATE swarm key, print it to stdout\n\
     \x20                                 (e.g. `pillar swarm generate > prod.key`)\n\
     \x20 show [--swarm-key <path>]       show a key's kind + fingerprint (public if no --swarm-key)\n\
     \x20      [--secret]                 also reveal a private key's value\n\
     \n\
     Pillar keeps NO swarm state. A node joins a swarm at boot:\n\
     \x20 pillar node run                                 join the public pillar swarm\n\
     \x20 pillar node run --swarm-key <path> --seed-node <multiaddr>   join a private swarm\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_owned()
    }

    #[test]
    fn generate_emits_only_a_parseable_private_key_on_stdout() {
        let out = dispatch(&[s("generate")]).expect("generate");
        let key = out.trim();
        // Exactly one line: the key, nothing else.
        assert_eq!(out.lines().count(), 1);
        let parsed = SwarmKey::parse(key).expect("stdout is a valid key");
        assert_eq!(parsed.kind(), SwarmKind::Private);
        // Two invocations never collide.
        let out2 = dispatch(&[s("gen")]).expect("gen");
        assert_ne!(out, out2);
    }

    #[test]
    fn show_with_no_key_reports_the_public_swarm() {
        let out = dispatch(&[]).expect("bare show");
        assert!(out.contains("kind:        public"), "got: {out}");
        assert!(out.contains("baked into every binary"), "got: {out}");
        // `show` explicitly behaves the same as bare.
        assert_eq!(out, dispatch(&[s("show")]).expect("show"));
    }

    #[test]
    fn show_inspects_a_private_key_file_hiding_the_secret_by_default() {
        let dir = std::env::temp_dir().join(format!("pillar-swarmcli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("prod.key");
        // Generate a key, write it, then show it back.
        let key = SwarmKey::generate();
        std::fs::write(&path, format!("{}\n", key.root_secret())).expect("write");
        let p = path.to_string_lossy().to_string();

        let hidden = dispatch(&[s("show"), s("--swarm-key"), s(&p)]).expect("show file");
        assert!(hidden.contains("kind:        private"), "got: {hidden}");
        assert!(hidden.contains(&key.fingerprint()), "got: {hidden}");
        assert!(
            !hidden.contains(key.root_secret()),
            "secret hidden by default: {hidden}"
        );

        let shown = dispatch(&[s("show"), s("--swarm-key"), s(&p), s("--secret")]).expect("reveal");
        assert!(shown.contains(key.root_secret()), "got: {shown}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_key_file_is_a_typed_error() {
        let missing = std::env::temp_dir().join("pillar-swarmcli-nope-xyz.key");
        let _ = std::fs::remove_file(&missing);
        let err = dispatch(&[s("show"), s("--swarm-key"), s(&missing.to_string_lossy())])
            .expect_err("missing file errors");
        assert!(err.contains("swarm key i/o error"), "got: {err}");
    }

    #[test]
    fn unknown_subcommand_is_rejected() {
        assert!(dispatch(&[s("frobnicate")]).is_err());
    }
}
