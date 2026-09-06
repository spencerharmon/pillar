//! `pillar swarm …` — manage which physical libp2p swarm this node speaks on.
//!
//! Unlike most cluster verbs (which act over a live platform and print
//! library-API guidance), swarm membership is LOCAL node configuration — a file
//! at `<data-dir>/swarm/registry.json`, the same registry
//! [`crate::run`] boots the transport from — so this verb does real work in the
//! shell, exactly like the local-context (`pillar use`/`ctx`) verbs.
//!
//! The data dir is resolved the same way the node resolves it: `--data-dir` /
//! `PILLAR_DATA_DIR` / the [`crate::run::DEFAULT_DATA_DIR`] default, so
//! `pillar swarm new prod` and `pillar node run` see the SAME registry.
//!
//! See `pillar_swarm` for the model: a **public** pillar swarm (the published,
//! baked-in root everyone shares) versus your **own** private swarm (a
//! high-entropy root you mint and distribute out-of-band).

use std::path::PathBuf;
use std::process::ExitCode;

use pillar_swarm::{SwarmError, SwarmKind, SwarmRegistry};

use crate::run::DEFAULT_DATA_DIR;

/// The `swarm` verb entrypoint, dispatched from
/// [`crate::cli_surface`]. `args` is argv AFTER the `swarm` token.
#[must_use]
pub fn run(args: &[String]) -> ExitCode {
    let data_dir = resolve_data_dir(args, |k| std::env::var(k).ok());
    let mut registry = match SwarmRegistry::load_or_default(&data_dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("swarm: {e}");
            return ExitCode::from(2);
        }
    };
    match dispatch(&mut registry, args) {
        Ok(Outcome { text, dirty }) => {
            if dirty {
                if let Err(e) = registry.save(&data_dir) {
                    eprintln!("swarm: could not persist registry: {e}");
                    return ExitCode::from(2);
                }
            }
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

/// The `--data-dir`/`PILLAR_DATA_DIR`/default resolution the node also uses, so
/// the CLI and the node agree on one registry.
fn resolve_data_dir<F>(args: &[String], env: F) -> PathBuf
where
    F: Fn(&str) -> Option<String>,
{
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--data-dir" {
            if let Some(v) = it.next() {
                return PathBuf::from(v);
            }
        }
    }
    env("PILLAR_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR))
}

/// The text + whether the registry changed and must be persisted.
#[derive(Debug)]
struct Outcome {
    text: String,
    dirty: bool,
}

impl Outcome {
    fn view(text: String) -> Self {
        Self { text, dirty: false }
    }
    fn changed(text: String) -> Self {
        Self { text, dirty: true }
    }
}

/// Pure command dispatch over an already-loaded registry — the unit-tested
/// core. Returns the text to print (+ dirty flag) or an error message. Ignores
/// `--data-dir <v>` tokens (consumed by [`resolve_data_dir`]).
fn dispatch(registry: &mut SwarmRegistry, args: &[String]) -> Result<Outcome, String> {
    let positional: Vec<&str> = strip_data_dir(args);
    let reveal = args.iter().any(|a| a == "--secret" || a == "--reveal");
    match positional.split_first() {
        None | Some((&"ls", _)) | Some((&"list", _)) => Ok(Outcome::view(render_list(registry))),
        Some((&"current", _)) => Ok(Outcome::view(render_show(
            registry,
            registry.active_name().to_owned().as_str(),
            reveal,
        )?)),
        Some((&"show", rest)) => {
            let name = rest
                .first()
                .copied()
                .unwrap_or_else(|| registry.active_name());
            Ok(Outcome::view(render_show(registry, name, reveal)?))
        }
        Some((&"new", rest)) => {
            let name = rest
                .first()
                .ok_or_else(|| "usage: pillar swarm new <name>".to_owned())?;
            let profile = registry.create(*name).map_err(fmt_err)?;
            Ok(Outcome::changed(format!(
                "created private swarm `{}` (fingerprint {})\n\
                 \n\
                 Share this root secret out-of-band with every node you want in this swarm,\n\
                 then run `pillar swarm import <local-name> <secret>` (and `pillar swarm use`) on each:\n\
                 \n  {}\n\
                 \nActivate it here with: pillar swarm use {}\n",
                profile.name(),
                profile.fingerprint(),
                profile.root_secret(),
                profile.name(),
            )))
        }
        Some((&"import", rest)) => {
            let name = rest
                .first()
                .ok_or_else(|| "usage: pillar swarm import <name> <root-secret>".to_owned())?;
            let secret = rest
                .get(1)
                .ok_or_else(|| "usage: pillar swarm import <name> <root-secret>".to_owned())?;
            let profile = registry.import(*name, *secret).map_err(fmt_err)?;
            Ok(Outcome::changed(format!(
                "imported swarm `{}` (fingerprint {}) — confirm this fingerprint matches the \
                 minting node.\nActivate it with: pillar swarm use {}\n",
                profile.name(),
                profile.fingerprint(),
                profile.name(),
            )))
        }
        Some((&"use", rest)) => {
            let name = rest
                .first()
                .ok_or_else(|| "usage: pillar swarm use <name>".to_owned())?;
            registry.use_swarm(name).map_err(fmt_err)?;
            let p = registry.active_profile();
            Ok(Outcome::changed(format!(
                "active swarm is now `{}` ({}, fingerprint {})\n",
                p.name(),
                p.kind().tag(),
                p.fingerprint()
            )))
        }
        Some((&"export", rest)) => {
            let name = rest
                .first()
                .copied()
                .unwrap_or_else(|| registry.active_name());
            let p = registry
                .get(name)
                .ok_or_else(|| fmt_err(SwarmError::NotFound(name.to_owned())))?;
            // Export is the explicit "give me the shareable join credential"
            // verb — it prints the secret by design (that is its whole point).
            Ok(Outcome::view(format!("{}\n", p.root_secret())))
        }
        Some((&"forget", rest)) => {
            let name = rest
                .first()
                .ok_or_else(|| "usage: pillar swarm forget <name>".to_owned())?;
            registry.forget(name).map_err(fmt_err)?;
            Ok(Outcome::changed(format!("forgot swarm `{name}`\n")))
        }
        Some((other, _)) => Err(format!("unknown `pillar swarm` subcommand `{other}`")),
    }
}

/// Drop the `--data-dir <value>` pair and any `--secret`/`--reveal` flags,
/// leaving the positional subcommand + args.
fn strip_data_dir(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => i += 2,
            "--secret" | "--reveal" => i += 1,
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    out
}

fn render_list(registry: &SwarmRegistry) -> String {
    let active = registry.active_name();
    let mut out = String::from("ACTIVE  NAME                 KIND     FINGERPRINT\n");
    for p in registry.list() {
        let marker = if p.name() == active { "*" } else { " " };
        out.push_str(&format!(
            "{marker}       {:<20} {:<8} {}\n",
            p.name(),
            p.kind().tag(),
            p.fingerprint()
        ));
    }
    out
}

fn render_show(registry: &SwarmRegistry, name: &str, reveal: bool) -> Result<String, String> {
    let p = registry
        .get(name)
        .ok_or_else(|| fmt_err(SwarmError::NotFound(name.to_owned())))?;
    let active = if registry.active_name() == name {
        " (active)"
    } else {
        ""
    };
    let mut out = format!(
        "name:        {}{active}\nkind:        {}\nfingerprint: {}\n",
        p.name(),
        p.kind().tag(),
        p.fingerprint(),
    );
    match p.kind() {
        SwarmKind::Public => {
            out.push_str("root:        <published public pillar root — baked into every binary>\n");
        }
        SwarmKind::Private => {
            if reveal {
                out.push_str(&format!("root-secret: {}\n", p.root_secret()));
            } else {
                out.push_str(
                    "root-secret: <hidden — this is the join credential; pass --secret to reveal, \
                     or `pillar swarm export` to print it>\n",
                );
            }
        }
    }
    Ok(out)
}

fn fmt_err(e: SwarmError) -> String {
    format!("swarm: {e}")
}

/// The `pillar swarm` help text.
#[must_use]
pub fn usage() -> &'static str {
    "usage: pillar swarm <subcommand> [--data-dir <path>]\n\
     \x20 ls | list                     list known swarms (marks the active one)\n\
     \x20 current                       show the active swarm\n\
     \x20 show [<name>] [--secret]      show a swarm's details (--secret reveals a private root)\n\
     \x20 new <name>                    mint a new PRIVATE swarm + print its root secret to distribute\n\
     \x20 use <name>                    switch the active swarm this node boots onto\n\
     \x20 import <name> <root-secret>   adopt an existing private swarm from a shared root secret\n\
     \x20 export [<name>]               print a swarm's root secret (the shareable join credential)\n\
     \x20 forget <name>                 remove a known swarm (not the public or active one)\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_owned()
    }

    #[test]
    fn empty_and_ls_list_the_public_swarm_marked_active() {
        let mut reg = SwarmRegistry::default();
        let out = dispatch(&mut reg, &[]).expect("ls").text;
        assert!(out.contains("public"));
        assert!(out.contains('*'), "active swarm is marked");
        assert!(!dispatch(&mut reg, &[s("ls")]).expect("ls").dirty);
    }

    #[test]
    fn new_then_use_then_forget_flow() {
        let mut reg = SwarmRegistry::default();

        let created = dispatch(&mut reg, &[s("new"), s("prod")]).expect("new");
        assert!(created.dirty);
        assert!(created.text.contains("created private swarm `prod`"));
        // The root secret to distribute is printed.
        assert!(created.text.contains("pillar-swarm/v1:"));

        // Creating does not switch the active swarm.
        assert_eq!(reg.active_name(), "public");

        let used = dispatch(&mut reg, &[s("use"), s("prod")]).expect("use");
        assert!(used.dirty);
        assert_eq!(reg.active_name(), "prod");

        // `current` shows prod, hiding the secret by default.
        let cur = dispatch(&mut reg, &[s("current")]).expect("current").text;
        assert!(cur.contains("name:        prod"));
        assert!(cur.contains("<hidden"));

        // --secret reveals it.
        let revealed = dispatch(&mut reg, &[s("show"), s("prod"), s("--secret")])
            .expect("show --secret")
            .text;
        assert!(revealed.contains("root-secret: pillar-swarm/v1:"));

        // Cannot forget the active swarm.
        let err = dispatch(&mut reg, &[s("forget"), s("prod")]).unwrap_err();
        assert!(err.contains("switch away first"));

        // Switch back to public, then forget prod.
        dispatch(&mut reg, &[s("use"), s("public")]).expect("use public");
        let forgot = dispatch(&mut reg, &[s("forget"), s("prod")]).expect("forget");
        assert!(forgot.dirty);
        assert!(reg.get("prod").is_none());
    }

    #[test]
    fn import_reconstructs_same_swarm_export_prints_secret() {
        let mut a = SwarmRegistry::default();
        let created = dispatch(&mut a, &[s("new"), s("lab")]).expect("new");
        // Pull the secret the way an operator would: `export`.
        dispatch(&mut a, &[s("use"), s("lab")]).expect("use");
        let secret = dispatch(&mut a, &[s("export")]).expect("export").text;
        let secret = secret.trim().to_owned();
        assert!(created.text.contains(&secret));

        // A second node imports it under a different local name.
        let mut b = SwarmRegistry::default();
        let imported = dispatch(&mut b, &[s("import"), s("lab2"), secret.clone()]).expect("import");
        assert!(imported.dirty);
        // Same secret => same fingerprint on both nodes.
        assert_eq!(
            a.active_profile().fingerprint(),
            b.get("lab2").unwrap().fingerprint()
        );
    }

    #[test]
    fn public_root_is_never_hidden_and_reserved_name_refused() {
        let mut reg = SwarmRegistry::default();
        let show = dispatch(&mut reg, &[s("show"), s("public")])
            .expect("show")
            .text;
        assert!(show.contains("published public pillar root"));

        let err = dispatch(&mut reg, &[s("new"), s("public")]).unwrap_err();
        assert!(err.contains("reserved public swarm name"));
    }

    #[test]
    fn data_dir_flag_is_resolved_and_ignored_by_dispatch() {
        let dir = resolve_data_dir(&[s("--data-dir"), s("/tmp/x"), s("ls")], |_| None);
        assert_eq!(dir, PathBuf::from("/tmp/x"));
        // env fallback
        let dir2 = resolve_data_dir(&[s("ls")], |k| {
            (k == "PILLAR_DATA_DIR").then(|| "/env/dir".to_owned())
        });
        assert_eq!(dir2, PathBuf::from("/env/dir"));
        // dispatch ignores the --data-dir pair
        let mut reg = SwarmRegistry::default();
        let out = dispatch(&mut reg, &[s("--data-dir"), s("/tmp/x"), s("ls")]).expect("ls");
        assert!(out.text.contains("public"));
    }
}
