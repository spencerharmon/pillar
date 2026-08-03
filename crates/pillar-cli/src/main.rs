//! The `pillar` binary: a thin argv shell over [`pillar_cli`].
//!
//! The verbs mirror kubectl — `apply`, `get`, `describe` — plus the `render`
//! helpers (`kustomize`, `helm`) that emit the shared manifest text a `pillar
//! apply` consumes. The engine (validation, WoT/RBAC authorization, envelope
//! signing, the event log, and the materialized view) lives in the library so
//! it is exercised by ordinary unit tests; this shell only parses argv, reads
//! files, and prints.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::ExitCode;

use pillar_cli::{parse_crd, HelmChart};
use pillar_identity::{NodeSubkey, UserPrimary};
use pillar_web::{AuthMode, Bootstrap};

fn usage() -> &'static str {
    "pillar — signed-manifest CLI (status is a view, never written back)\n\
     \n\
     USAGE:\n\
     \x20 pillar apply    <manifest.txt>            validate, authorize, sign, emit a signed event\n\
     \x20 pillar get      <api> <kind> <name>       render a resource from the materialized view\n\
     \x20 pillar describe <api> <kind> <name>       render a resource + its envelope provenance\n\
     \x20 pillar render helm <template> [k=v ...]   fill a helm template, print manifest text\n\
     \x20 pillar render kustomize <base.txt>        (see library API for overlay construction)\n\
     \x20 pillar --web [--port N]                  serve the localhost-only bootstrap/web UI\n\
     \n\
     apply/get/describe act over a live platform (schema registry + WoT/RBAC\n\
     authority + event log). This shell renders and validates manifests; the\n\
     authoritative engine is the `pillar_cli` library.\n"
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("-h") | Some("--help") | Some("help") => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        Some("--web") => web(&args[1..]),
        Some("render") => render(&args[1..]),
        Some("apply") | Some("get") | Some("describe") => {
            // These verbs act over a live, persistent platform, which this
            // demonstration shell does not host. The library `Platform` API is
            // the authoritative entry point; print guidance rather than fake
            // success.
            eprintln!(
                "`pillar {}` operates over a live platform via the pillar_cli library API.",
                args[0]
            );
            eprintln!("Use `pillar render …` to produce manifest text, and the library to apply it.");
            ExitCode::from(2)
        }
        Some(other) => {
            eprintln!("unknown verb `{other}`\n");
            print!("{}", usage());
            ExitCode::from(2)
        }
    }
}

/// `pillar --web [--port N]`: serve the localhost-only bootstrap surface —
/// same binary, no separate daemon. Accepts one line-oriented command per
/// connection (`keygen`, `admit <primary> <subkey>`, or `quit` to stop
/// serving) over a plaintext TCP protocol; every accepted connection is
/// authorized via [`AuthMode::LocalhostBootstrap`] before dispatch, refusing
/// anything not from loopback regardless of what the OS routes to the bound
/// port. Real request parsing/rendering (HTML, WebAuthn, predicted-effect
/// forms) is intentionally left to grow behind this same auth gate and
/// `pillar_web` API — this shell only wires the socket loop.
fn web(args: &[String]) -> ExitCode {
    let mut port: u16 = 8642;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                let Some(value) = args.get(i + 1) else {
                    eprintln!("--port requires a value");
                    return ExitCode::from(2);
                };
                match value.parse() {
                    Ok(p) => port = p,
                    Err(e) => {
                        eprintln!("invalid --port value `{value}`: {e}");
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
            other => {
                eprintln!("unknown --web argument `{other}`");
                return ExitCode::from(2);
            }
        }
    }

    let listener = match pillar_web::bind_localhost(port) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind localhost:{port}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let bound = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| format!("127.0.0.1:{port}"));
    eprintln!("pillar web interface listening on {bound} (bootstrap mode, localhost-only)");

    let auth = AuthMode::LocalhostBootstrap;
    let mut bootstrap = Bootstrap::new();

    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let Ok(peer) = stream.peer_addr() else { continue };
        if let Err(e) = auth.authorize(&peer, None) {
            let _ = writeln!(stream, "refused: {e:?}");
            continue;
        }

        let mut line = String::new();
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
        if reader.read_line(&mut line).is_err() {
            continue;
        }
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("keygen") => {
                let primary = bootstrap.keygen_user();
                let _ = writeln!(stream, "ok {}", primary.0);
            }
            Some("admit") => {
                let (Some(primary), Some(subkey)) = (parts.next(), parts.next()) else {
                    let _ = writeln!(stream, "usage: admit <primary> <subkey>");
                    continue;
                };
                match bootstrap.sign_node(UserPrimary::from(primary), NodeSubkey::from(subkey)) {
                    Ok(node) => {
                        let _ = writeln!(stream, "ok {node}");
                    }
                    Err(e) => {
                        let _ = writeln!(stream, "denied {e:?}");
                    }
                }
            }
            Some("quit") => {
                let _ = writeln!(stream, "bye");
                break;
            }
            _ => {
                let _ = writeln!(stream, "unknown command; use `keygen`, `admit <primary> <subkey>`, or `quit`");
            }
        }
    }
    ExitCode::SUCCESS
}

fn render(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("helm") => render_helm(&args[1..]),
        _ => {
            eprintln!("usage: pillar render helm <template-file> [key=value ...]");
            ExitCode::from(2)
        }
    }
}

fn render_helm(args: &[String]) -> ExitCode {
    let Some(template_path) = args.first() else {
        eprintln!("usage: pillar render helm <template-file> [key=value ...]");
        return ExitCode::from(2);
    };
    let template = match std::fs::read_to_string(template_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {template_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut values = BTreeMap::new();
    for kv in &args[1..] {
        let Some((k, v)) = kv.split_once('=') else {
            eprintln!("value must be key=value, got `{kv}`");
            return ExitCode::from(2);
        };
        values.insert(k.to_owned(), v.to_owned());
    }
    let chart = HelmChart::new(template);
    match chart.render(&values) {
        Ok(text) => {
            // Validate that it parses before emitting, so a bad render fails loud.
            if let Err(e) = parse_crd(&text) {
                eprintln!("rendered manifest is invalid: {e}");
                return ExitCode::FAILURE;
            }
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("render failed: {e}");
            ExitCode::FAILURE
        }
    }
}
