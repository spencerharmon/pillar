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
     \x20 pillar node run [--identity-key P] [--data-dir D] [--listen A ...] [--dial A ...] [--web-bind ADDR] [--web-port N]  boot a full peer and block\n\
     \x20 pillar bootstrap cell <name> --user <handle> [opts]  combined single-step cell+user bootstrap\n\
     \x20 pillar bootstrap node|user --domain <D> [opts]       submit a node/user join request\n\
     \x20 pillar bootstrap request list|approve <id> [--domain D]  review/decide join requests\n\
     \x20 pillar login --domain <D> --user <id> [--password P]    print export PILLAR_DOMAIN/PILLAR_TOKEN\n\
     \x20 pillar session ls|show <id>|revoke <id>|revoke-all       server-side sessions (ls/show view; revoke acts)\n\
     \x20 pillar logout | whoami | status           session lifecycle (see pillar_cli::resource::Session)\n\
     \x20 pillar use|ctx <ls|show|add|rm|rename|current>  local context (see pillar_cli::resource::ContextStore)\n\
     \x20 pillar <get|describe|apply|create|delete|patch|label|scale|diff|explain> <kind>/<name> [-l sel] [-L cols]  kubectl-parity resource plane (see pillar_cli::resource::ResourcePlane)\n\
     \x20 pillar describe <api> <kind> <name>       render a resource + its envelope provenance\n\
     \x20 pillar onboard                            run the keygen->signing->trust->policy sequence, asserting invariants\n\
     \x20 pillar render helm <template> [k=v ...]   fill a helm template, print manifest text\n\
     \x20 pillar render kustomize <base.txt>        (see library API for overlay construction)\n\
     \x20 pillar --web [--port N]                  serve the localhost-only bootstrap/web UI\n\
     \x20 pillar obs <family> <verb> [args]         per-signal observability views (see below)\n\
     \n\
     apply/get/describe act over a live platform (schema registry + WoT/RBAC\n\
     authority + event log). This shell renders and validates manifests; the\n\
     authoritative engine is the `pillar_cli` library.\n\
     \n\
     `pillar obs` families (every verb below is a VIEW — reads state, signs\n\
     nothing — except `obs dashboard {create|update|delete}`, which is an ACT\n\
     emitting one signed IPFS+streaming-tip resource; see `pillar_cli::\n\
     observability_ui::ObservabilityBuilders`, the authoritative engine this\n\
     shell operates over a per-invocation substrate of):\n\
     \x20 pillar obs metric   {query|series|tail|top|retention}\n\
     \x20 pillar obs log      {query|tail|fields}\n\
     \x20 pillar obs trace    {get|search|graph}\n\
     \x20 pillar obs profile  {get|flame|top}\n\
     \x20 pillar obs metadata {query|current|history|series}\n\
     \x20 pillar obs explore  <metric|log|trace|profile|metadata>\n\
     \x20 pillar obs query    -f <q.pql>\n\
     \x20 pillar obs dashboard {create|update|delete|get} ...\n"
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("-h") | Some("--help") | Some("help") => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        Some("--web") => web(&args[1..]),
        Some("node") => node(&args[1..]),
        Some("bootstrap") => bootstrap(&args[1..]),
        Some("session") => session(&args[1..]),
        Some("login") => login(&args[1..]),
        Some("render") => render(&args[1..]),
        Some("onboard") => onboard(),
        Some("obs") => {
            // Every `obs` verb reads (or, for `dashboard create/update/delete`,
            // signs) a live node's materialized observability substrate — the
            // same "no live platform in this shell" boundary `apply`/`get`/
            // `describe` already document below. The authoritative, fully
            // unit-tested engine for every verb this help text lists is
            // `pillar_cli::observability_ui::ObservabilityBuilders`.
            eprintln!(
                "`pillar obs …` reads/acts over a live node's observability substrate via the \
                 pillar_cli::observability_ui::ObservabilityBuilders library API."
            );
            eprintln!("Run `pillar --help` for the full `obs` verb list.");
            ExitCode::from(2)
        }
        Some("apply") | Some("get") | Some("describe") => {
            // These verbs act over a live, persistent platform, which this
            // demonstration shell does not host. The library `Platform` API is
            // the authoritative entry point; print guidance rather than fake
            // success.
            eprintln!(
                "`pillar {}` operates over a live platform via the pillar_cli library API.",
                args[0]
            );
            eprintln!(
                "Use `pillar render …` to produce manifest text, and the library to apply it."
            );
            ExitCode::from(2)
        }
        Some(other) => {
            eprintln!("unknown verb `{other}`\n");
            print!("{}", usage());
            ExitCode::from(2)
        }
    }
}

/// `pillar onboard`: drive the keygen -> node-key signing -> cross-user
/// trust -> depth/policy-config sequence in one process, asserting every
/// safety invariant `pillar_cli::onboard` checks. Prints one `ok: <step>`
/// line per passing step; exits non-zero with a `FAIL: <step>: <why>` line
/// naming the first violated invariant.
fn onboard() -> ExitCode {
    match pillar_cli::onboard::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// `pillar bootstrap …`: the combined cell+user bootstrap, node/user join
/// requests, and request approval, over the shared `pillar_cli::bootstrap`
/// library and the node's HTTP endpoints.
fn bootstrap(args: &[String]) -> ExitCode {
    match pillar_cli::bootstrap::run(args) {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}

/// `pillar login …`: obtain a temporary token and print `export` lines for
/// `PILLAR_DOMAIN` / `PILLAR_TOKEN`. Intended to be `eval`'d:
/// `eval "$(pillar login --domain D --user U)"`.
fn login(args: &[String]) -> ExitCode {
    match pillar_cli::bootstrap::login(args) {
        Ok(exports) => {
            print!("{exports}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// `pillar session {ls|show <id>|revoke <id>|revoke-all}`: the SERVER-SIDE
/// session family. `ls`/`show` are VIEWS (sign nothing); `revoke`/`revoke-all`
/// are ACTS (emit one signed, decider-authorized revocation event). Distinct
/// from the local `ctx`/context family. The authoritative, fully unit-tested
/// engine is [`pillar_cli::session_cli::SessionCli`], which this shell operates
/// over a live node's materialized session substrate — the same "no live
/// platform in this demonstration shell" boundary `apply`/`get`/`obs` document.
fn session(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("ls") | Some("show") | Some("revoke") | Some("revoke-all") => {
            eprintln!(
                "`pillar session …` reads/acts over a live node's server-side session substrate \
                 via the pillar_cli::session_cli::SessionCli library API."
            );
            eprintln!(
                "ls/show are views (sign nothing); revoke/revoke-all emit one signed, \
                 decider-authorized revocation event."
            );
            ExitCode::from(2)
        }
        _ => {
            eprintln!(
                "usage: pillar session {{ls | show <id> | revoke <id> | revoke-all}} [--principal <p>]"
            );
            ExitCode::from(2)
        }
    }
}

/// `pillar node run [flags]`: boot a full peer and block until shutdown.
///
/// Delegates entirely to the unit-tested [`pillar_cli::run`] module: it
/// resolves a [`pillar_cli::run::NodeConfig`] from flags layered over env,
/// then drives the async boot sequence (identity load, streamdb open, libp2p
/// transport bring-up, controller loop) on a Tokio runtime until SIGINT/
/// SIGTERM. `node run` is the only `node` subcommand today.
fn node(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("run") => node_run(&args[1..]),
        _ => {
            eprintln!(
                "usage: pillar node run [--identity-key <path>] [--data-dir <path>] [--listen <multiaddr> ...]"
            );
            ExitCode::from(2)
        }
    }
}

fn node_run(args: &[String]) -> ExitCode {
    // Emit `tracing` output (peer id, listen addrs, connections, gossip
    // messages) to stderr so both an operator and the integration rig script
    // can observe real boot/convergence events; defaults to `info` unless
    // `RUST_LOG` overrides it. Safe to call even if a subscriber is already
    // installed elsewhere (ignored on error).
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let config = match pillar_cli::run::NodeConfig::from_process_args(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("pillar node run: {e}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(pillar_cli::run::run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pillar node run: {e}");
            ExitCode::FAILURE
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
        let Ok(peer) = stream.peer_addr() else {
            continue;
        };
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
                let _ = writeln!(
                    stream,
                    "unknown command; use `keygen`, `admit <primary> <subkey>`, or `quit`"
                );
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
