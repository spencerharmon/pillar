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
use std::process::ExitCode;

use pillar_cli::{parse_crd, HelmChart};

fn usage() -> &'static str {
    "pillar — signed-manifest CLI (status is a view, never written back)\n\
     \n\
     USAGE:\n\
     \x20 pillar apply    <manifest.txt>            validate, authorize, sign, emit a signed event\n\
     \x20 pillar get      <api> <kind> <name>       render a resource from the materialized view\n\
     \x20 pillar describe <api> <kind> <name>       render a resource + its envelope provenance\n\
     \x20 pillar render helm <template> [k=v ...]   fill a helm template, print manifest text\n\
     \x20 pillar render kustomize <base.txt>        (see library API for overlay construction)\n\
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
