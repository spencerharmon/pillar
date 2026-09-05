//! The `pillar` binary's real, dispatched top-level verb tree — a single
//! DATA-driven table ([`VERBS`]) that [`dispatch`] (called by `main.rs`)
//! walks to route argv, and that a surface-inventory emitter walks to list
//! "every CLI verb the binary actually serves". There is exactly ONE table:
//! a verb registered here is both dispatchable AND inventoried; a verb never
//! registered here is neither. This is the deliberate alternative to a
//! hand-maintained catalog that can drift from what `main()` really does.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::ExitCode;

use crate::{parse_crd, HelmChart};
use pillar_identity::{NodeSubkey, UserPrimary};
use pillar_web::{AuthMode, Bootstrap};

/// One entry in the real, served CLI verb tree.
type VerbHandler = fn(&str, &[String]) -> ExitCode;

/// A single top-level verb this binary dispatches — the exact data
/// [`dispatch`] routes argv through.
#[derive(Clone, Copy)]
pub struct VerbSpec {
    /// The literal first argv token this verb answers to (e.g. `"node"`).
    pub name: &'static str,
    handler: VerbHandler,
}

/// Every top-level verb the `pillar` binary actually dispatches — the SINGLE
/// source of truth [`dispatch`] routes argv through. A surface-inventory
/// emitter reads this table (not a hand-maintained catalog), so a verb added
/// or removed here is added or removed from what the binary serves AND from
/// what the inventory reports, by construction.
pub static VERBS: &[VerbSpec] = &[
    VerbSpec {
        name: "surface-inventory",
        handler: |_v, args| surface_inventory(args),
    },
    VerbSpec {
        name: "--web",
        handler: |_v, args| web(args),
    },
    VerbSpec {
        name: "node",
        handler: |_v, args| node(args),
    },
    VerbSpec {
        name: "bootstrap",
        handler: |_v, args| bootstrap(args),
    },
    VerbSpec {
        name: "webauthn",
        handler: |_v, args| webauthn(args),
    },
    VerbSpec {
        name: "session",
        handler: |_v, args| session(args),
    },
    VerbSpec {
        name: "identity",
        handler: identity_trust,
    },
    VerbSpec {
        name: "user",
        handler: identity_trust,
    },
    VerbSpec {
        name: "key",
        handler: identity_trust,
    },
    VerbSpec {
        name: "offer",
        handler: identity_trust,
    },
    VerbSpec {
        name: "trust",
        handler: identity_trust,
    },
    VerbSpec {
        name: "attest",
        handler: identity_trust,
    },
    VerbSpec {
        name: "grant",
        handler: identity_trust,
    },
    VerbSpec {
        name: "caps",
        handler: identity_trust,
    },
    VerbSpec {
        name: "revoke",
        handler: identity_trust,
    },
    VerbSpec {
        name: "audit",
        handler: identity_trust,
    },
    VerbSpec {
        name: "login",
        handler: |_v, args| login(args),
    },
    VerbSpec {
        name: "domain",
        handler: cluster_stream,
    },
    VerbSpec {
        name: "cell",
        handler: cluster_stream,
    },
    VerbSpec {
        name: "space",
        handler: cluster_stream,
    },
    VerbSpec {
        name: "peer",
        handler: cluster_stream,
    },
    VerbSpec {
        name: "lease",
        handler: cluster_stream,
    },
    VerbSpec {
        name: "request",
        handler: cluster_stream,
    },
    VerbSpec {
        name: "stream",
        handler: cluster_stream,
    },
    VerbSpec {
        name: "render",
        handler: |_v, args| render(args),
    },
    VerbSpec {
        name: "onboard",
        handler: |_v, _args| onboard(),
    },
    VerbSpec {
        name: "secrets-audit-rotation-mfa",
        handler: |_v, _args| secrets_audit_rotation_mfa(),
    },
    VerbSpec {
        name: "apply-authz",
        handler: |_v, _args| apply_authz(),
    },
    VerbSpec {
        name: "versioning-rollout",
        handler: |_v, _args| versioning_rollout(),
    },
    VerbSpec {
        name: "obs",
        handler: |_v, _args| obs(),
    },
    VerbSpec {
        name: "apply",
        handler: live_platform_guidance,
    },
    VerbSpec {
        name: "get",
        handler: live_platform_guidance,
    },
    VerbSpec {
        name: "describe",
        handler: live_platform_guidance,
    },
    VerbSpec {
        name: "explain",
        handler: |_v, args| explain(args),
    },
    VerbSpec {
        name: "completion",
        handler: |_v, args| completion(args),
    },
];

/// The real, currently-dispatched CLI verb table — the exact data `main()`
/// routes argv through via [`dispatch`].
#[must_use]
pub fn verb_table() -> &'static [VerbSpec] {
    VERBS
}

/// Route `args` (argv minus the binary name) through the real verb table.
/// Returns `None` for the help/no-args case (the caller prints usage) so
/// `main.rs` keeps ownership of the usage text.
pub fn dispatch(args: &[String]) -> Option<ExitCode> {
    let verb = args.first()?.as_str();
    let spec = VERBS.iter().find(|s| s.name == verb)?;
    Some((spec.handler)(verb, &args[1..]))
}

fn obs() -> ExitCode {
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

fn live_platform_guidance(verb: &str, _args: &[String]) -> ExitCode {
    // These verbs act over a live, persistent platform, which this
    // demonstration shell does not host. The library `Platform` API is
    // the authoritative entry point; print guidance rather than fake
    // success.
    eprintln!("`pillar {verb}` operates over a live platform via the pillar_cli library API.");
    eprintln!("Use `pillar render …` to produce manifest text, and the library to apply it.");
    ExitCode::from(2)
}

/// `pillar explain <PSL query>`: parse the query with the real PSL parser and
/// print both the parsed AST and the query engine's real execution plan.
fn explain(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("usage: pillar explain <PSL query>");
        eprintln!("  prints the parsed AST and the real execution plan for a PSL query");
        return ExitCode::from(2);
    }
    // Join the argv tail so an unquoted query still parses.
    let query = args.join(" ");
    match crate::polish::explain_psl(&query) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("pillar explain: {e}");
            ExitCode::from(2)
        }
    }
}

/// `pillar completion <bash>`: emit a shell completion script generated from
/// the real served verb table.
fn completion(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("bash") => {
            print!("{}", crate::polish::bash_completion());
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: pillar completion bash");
            ExitCode::from(2)
        }
    }
}

/// `pillar surface-inventory`: emit the `pillar-integration/v1` machine-
/// readable inventory of every external surface THIS binary serves (CLI
/// verbs, HTTP routes, manifest kinds, wire ops), read from the live
/// registries — the black-box source of truth the `pillar-integration`
/// portal-cli-parity scenario drives its parity assertion against. Prints
/// JSON to stdout; exits 0.
fn surface_inventory(_args: &[String]) -> ExitCode {
    println!("{}", crate::surface_inventory::emit_json());
    ExitCode::SUCCESS
}

/// `pillar onboard`: drive the keygen -> node-key signing -> cross-user
/// trust -> depth/policy-config sequence in one process, asserting every
/// safety invariant `pillar_cli::onboard` checks.
fn onboard() -> ExitCode {
    match crate::onboard::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// `pillar secrets-audit-rotation-mfa`: the sealed-secret-store/audit-log/
/// key-rotation/step-up-MFA onboarding-style rig (see
/// [`crate::secrets_audit_rotation_mfa`]).
fn secrets_audit_rotation_mfa() -> ExitCode {
    match crate::secrets_audit_rotation_mfa::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
/// `pillar versioning-rollout`: the compat-negotiation/rolling-migration/
/// readiness-gating/rollback rig (see [`crate::versioning_rollout`]).
fn versioning_rollout() -> ExitCode {
    match crate::versioning_rollout::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// `pillar apply-authz`: drive the real certify->trust->attest->revoke
/// pipeline and the real RBAC decider, proving an unauthorized manifest
/// `apply` is rejected with a real fail-closed 403 (never a mock).
fn apply_authz() -> ExitCode {
    crate::trust_rbac_authz::run()
}

/// `pillar bootstrap …`.
fn bootstrap(args: &[String]) -> ExitCode {
    match crate::bootstrap::run(args) {
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

/// `pillar login …`.
fn login(args: &[String]) -> ExitCode {
    match crate::bootstrap::login(args) {
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

/// `pillar webauthn register|login`.
fn webauthn(args: &[String]) -> ExitCode {
    match crate::webauthn_cli::run(args) {
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

/// `pillar {identity|user|key|offer|trust|attest|grant|caps|revoke|audit} …`.
fn identity_trust(verb: &str, _args: &[String]) -> ExitCode {
    eprintln!(
        "`pillar {verb} …` reads/acts over a live node's identity/trust substrate via the \
         pillar_cli::identity_trust_cli library API."
    );
    eprintln!("Run `pillar --help` for the full verb list of this family.");
    ExitCode::from(2)
}

/// `pillar session {ls|show <id>|revoke <id>|revoke-all}`.
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

/// `pillar node {run|list|describe|cordon|uncordon|drain|taint}`.
fn node(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("run") => node_run(&args[1..]),
        Some(_) => cluster_stream("node", args),
        None => {
            eprintln!(
                "usage: pillar node run [--identity-key <path>] [--data-dir <path>] [--listen <multiaddr> ...]"
            );
            ExitCode::from(2)
        }
    }
}

/// `pillar {domain|cell|space|node|peer|lease|request|stream} …`.
fn cluster_stream(verb: &str, _args: &[String]) -> ExitCode {
    let module = match verb {
        "stream" => "pillar_cli::stream_cli::StreamCli",
        "domain" => "pillar_cli::cluster::DomainCli",
        "cell" => "pillar_cli::cluster::CellCli",
        "space" => "pillar_cli::cluster::SpaceCli",
        "node" => "pillar_cli::cluster::NodeCli",
        "peer" => "pillar_cli::cluster::PeerCli",
        "lease" => "pillar_cli::cluster::LeaseCli",
        "request" => "pillar_cli::cluster::RequestCli",
        _ => "pillar_cli::cluster",
    };
    eprintln!("`pillar {verb} …` reads/acts over a live node's materialized substrate via the {module} library API.");
    eprintln!("Run `pillar --help` for the full verb list of this family.");
    ExitCode::from(2)
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

    let config = match crate::run::NodeConfig::from_process_args(args) {
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
    match runtime.block_on(crate::run::run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pillar node run: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `pillar --web [--port N]`: serve the localhost-only bootstrap surface —
/// same binary, no separate daemon.
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
