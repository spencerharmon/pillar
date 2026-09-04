//! The `pillar` binary: a thin argv shell over [`pillar_cli`].
//!
//! The verbs mirror kubectl — `apply`, `get`, `describe` — plus the `render`
//! helpers (`kustomize`, `helm`) that emit the shared manifest text a `pillar
//! apply` consumes. The engine (validation, WoT/RBAC authorization, envelope
//! signing, the event log, and the materialized view) lives in the library so
//! it is exercised by ordinary unit tests; this shell only parses argv, reads
//! files, and prints. Routing itself is data-driven — see
//! [`pillar_cli::cli_surface`]: `main()` here calls
//! [`pillar_cli::cli_surface::dispatch`], which walks the SAME verb table a
//! surface-inventory emitter reads, so there is no separate hand-maintained
//! verb catalog to drift out of sync with what this binary actually serves.

#![forbid(unsafe_code)]

use std::process::ExitCode;

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
     \x20 pillar webauthn register --user <handle> [--domain D] [--token T]  register a hardware credential (ctap-hid)\n\
     \x20 pillar webauthn login [--domain D] [--token T] --credential-id <id>  authenticate with a hardware credential (ctap-hid)\n\
     \x20 pillar session ls|show <id>|revoke <id>|revoke-all       server-side sessions (ls/show view; revoke acts)\n\
     \x20 pillar logout | whoami | status           session lifecycle (see pillar_cli::resource::Session)\n\
     \x20 pillar use|ctx <ls|show|add|rm|rename|current>  local context (see pillar_cli::resource::ContextStore)\n\
     \x20 pillar <get|describe|apply|create|delete|patch|label|scale|diff|explain> <kind>/<name> [-l sel] [-L cols]  kubectl-parity resource plane (see pillar_cli::resource::ResourcePlane)\n\
     \x20 pillar identity new|show|enroll|rotate-primary|link|unlink|backup|recover   global identity (identity_trust_cli::IdentityCli)\n\
     \x20 pillar user add|invite|rm|rename|suspend|resume|passwd|roles|attestations   cell members (identity_trust_cli::UserCli)\n\
     \x20 pillar key gen|fingerprint|label|custody|rotate|revoke|verify|export|import|escrow|recover   subkeys (identity_trust_cli::KeyCli)\n\
     \x20 pillar offer seal|escrow|resolve|revoke|status         operational-key offers (identity_trust_cli::OfferCli)\n\
     \x20 pillar trust <id> [--depth N]|path|graph               WoT trust edges (identity_trust_cli::TrustCli)\n\
     \x20 pillar attest --as <role>@<scope> --subject --allow --quota --in cell   authorization claims (identity_trust_cli::AttestCli)\n\
     \x20 pillar grant add|rm|check(can-i)|who-can                explicit grants (identity_trust_cli::GrantCli)\n\
     \x20 pillar caps [<user>]                                    effective capability set (identity_trust_cli::CapsCli)\n\
     \x20 pillar revoke trust|grant|key|attest <ref>               authority-reducing acts (identity_trust_cli::RevokeCli)\n\
     \x20 pillar audit <cid>                                      proof chain + sentence (identity_trust_cli::AuditCli)\n\
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
     \x20 pillar obs dashboard {create|update|delete|get} ...\n\
     \n\
     `pillar {domain|cell|space|node|peer|lease|request|stream} …` (the naming,\n\
     topology, and data-plane families of docs/cli-surface.md §§ 3.4-3.6) act\n\
     over a live node's materialized substrate via the pillar_cli library API\n\
     — same boundary as apply/get/describe/session/obs above:\n\
     \x20 pillar domain  list|show|new|add-cell|rm-cell        (pillar_cli::cluster::DomainCli — naming-only, signs nothing)\n\
     \x20 pillar cell    status|members|health|rotate-key      (pillar_cli::cluster::CellCli)\n\
     \x20 pillar space   get|describe|create|label|delete      (pillar_cli::cluster::SpaceCli)\n\
     \x20 pillar node    list|describe|cordon|uncordon|drain|taint  (pillar_cli::cluster::NodeCli)\n\
     \x20 pillar peer    ls|dial|ping|addrs                    (pillar_cli::cluster::PeerCli)\n\
     \x20 pillar lease   list|show|acquire|release|status      (pillar_cli::cluster::LeaseCli over pillar-coordination)\n\
     \x20 pillar request ls|approve|reject                     (pillar_cli::cluster::RequestCli; node-approve returns the sealed-cell-key CID)\n\
     \x20 pillar stream  ls|tip|log|get|verify|snapshot|sync|sub|unsub|head  (pillar_cli::stream_cli::StreamCli over pillar-streamdb)\n"
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("-h") | Some("--help") | Some("help") => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        Some(other) => match pillar_cli::cli_surface::dispatch(&args) {
            Some(code) => code,
            None => {
                eprintln!("unknown verb `{other}`\n");
                print!("{}", usage());
                ExitCode::from(2)
            }
        },
    }
}
