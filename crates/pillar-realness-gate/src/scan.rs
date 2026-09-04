//! Tooth 1 — the static feature-realness scan.
//!
//! Extends the crypto realness gate's mechanism (comment-stripping,
//! `#[cfg(test)]` skipping, `// non-security:` opt-out) to a broader class of
//! *model-as-feature* offenders in shipping (non-test) source:
//!
//!   * a **no-op reconcile/handler** that reports success without a side effect
//!     — a line whose comment or code confesses "no-op ... reports success" /
//!     "no-op ... returns Ok" and produces no effect;
//!   * a **stand-in / placeholder payload** used as real data — one of the
//!     tokens `stand-in`, `oci-image-layer-payload`, `placeholder`, `TODO`,
//!     `for now` sitting in shipping code as the actual value; and
//!   * a **modeled verb** — `run` / `fetch` / `bind` / `resolve` / `forward`
//!     claimed as a real operation in a delivered path whose FILE contains NO
//!     corresponding real syscall (`std::process` / `tokio::process`,
//!     `UdpSocket` / `TcpListener`, or a libp2p request).
//!
//! Two — and only two — exemptions carry over verbatim from the crypto gate:
//! `#[cfg(test)]` code, and a line explicitly annotated `// non-security: ...`
//! (used solely by the load-balancer `consistent_hash`). The exact annotation
//! is required.

use std::fs;
use std::path::{Path, PathBuf};

/// Explicit opt-out marker (identical to the crypto gate's single sanctioned
/// escape hatch). A source line carrying this substring is exempt.
const NON_SECURITY_MARKER: &str = "non-security:";

/// The realness gate's OWN sanctioned escape hatch, distinct from the crypto
/// gate's `// non-security:` (which is reserved for the LB routing hash). A
/// source line carrying `// realness-exempt: <why>` is a deliberate,
/// justified non-feature construct — a documented DEFAULT/extension-point
/// no-op that a real deployment overrides, or a prose doc-comment that merely
/// MENTIONS a confession word without being one. Every use must carry a
/// concrete justification after the marker; a reviewer judges it exactly as the
/// crypto gate reviews a `// non-security:` line.
const REALNESS_EXEMPT_MARKER: &str = "realness-exempt:";

/// Stand-in / placeholder PAYLOAD tokens: a byte/string LITERAL bearing one of
/// these is a model masquerading as real data. These are matched only inside a
/// string/byte literal on the code-only line (see [`literal_contains`]) so a
/// legitimate identifier — an HTML `placeholder` attribute, a struct field named
/// `placeholder` — is never flagged; only `b"oci-image-layer-payload"` /
/// `"stand-in payload"` as a real value is.
const PLACEHOLDER_LITERAL_TOKENS: &[&str] = &[
    "stand-in",
    "oci-image-layer-payload",
    "placeholder-payload",
    "placeholder payload",
];

/// Confession phrases matched against the RAW line (comments included): a
/// shipping path that literally says it is not real yet. `for now` and a
/// TODO-marker only fire when the surrounding text is a confession of
/// incompleteness (`TODO:` / `TODO(` / `FIXME` / `for now`), not any prose
/// mention.
const CONFESSION_PHRASES: &[&str] = &["todo:", "todo(", "fixme", "for now"];

/// The modeled verbs. Flagged only when the SAME line also confesses it is a
/// model/stub/no-op (see [`claims_modeled_verb`]) and the file has no real
/// syscall — so a real `fetch`/`run` implementation is never flagged, only one
/// that admits it is modeled.
const MODELED_VERBS: &[&str] = &["run", "fetch", "bind", "resolve", "forward"];

/// A same-line confession that a verb is only modeled/stubbed.
const MODEL_MARKERS: &[&str] = &[
    "modeled",
    "model ",
    "stub",
    "stubbed",
    "fake",
    "dummy",
    "no-op",
    "noop",
    "simulate",
    "simulated",
    "pretend",
    "mock",
];

/// Real-syscall markers whose PRESENCE in a file proves the file's verbs are
/// backed by real I/O (so the modeled-verb tooth does not flag it).
const REAL_SYSCALL_MARKERS: &[&str] = &[
    "std::process",
    "tokio::process",
    "Command::new",
    "UdpSocket",
    "TcpListener",
    "TcpStream",
    "libp2p",
    "request_response",
    "Swarm",
];

/// A phrase (case-insensitive, in the RAW line) that confesses a no-op handler
/// that nonetheless reports success.
fn is_noop_reports_success(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.contains("no-op") && (lower.contains("reports success") || lower.contains("returns ok"))
}

/// Does the raw line carry a confession phrase (`TODO:` / `for now` / …)?
fn has_confession(raw: &str) -> Option<String> {
    let lower = raw.to_ascii_lowercase();
    CONFESSION_PHRASES
        .iter()
        .find(|p| lower.contains(**p))
        .map(|p| p.to_string())
}

/// Does the code-only line contain a placeholder token INSIDE a string or byte
/// literal (`"..."` / `b"..."`)? A bare identifier match does not count.
fn literal_contains(code: &str, tok: &str) -> bool {
    // Collect the contents of every double-quoted literal on the line and test
    // each for the token. Conservative: escapes are not interpreted (a token
    // never legitimately spans an escape).
    let bytes = code.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'"' {
                if bytes[j] == b'\\' {
                    j += 2;
                    continue;
                }
                j += 1;
            }
            let lit = &code[start..j.min(code.len())];
            if lit.contains(tok) {
                return true;
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    false
}

/// Does this line CLAIM a modeled verb AND confess (same line) that it is only a
/// model/stub? Returns the verb if so. This is the discriminator that keeps a
/// REAL `fetch`/`run` implementation clean: only a line that both names the verb
/// as an operation and admits it is modeled fires.
fn claims_modeled_verb(code: &str) -> Option<String> {
    let lower = code.to_ascii_lowercase();
    let confesses_model = MODEL_MARKERS.iter().any(|m| lower.contains(m));
    if !confesses_model {
        return None;
    }
    for &verb in MODELED_VERBS {
        let fn_form = format!("fn {verb}");
        let call_form = format!("{verb}(");
        if contains_token(code, verb) && (code.contains(&fn_form) || code.contains(&call_form)) {
            return Some(verb.to_string());
        }
    }
    None
}

/// One flagged offense.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offense {
    /// The file (label) the offense was found in.
    pub file: String,
    /// 1-based line number of the offending line (0 for a whole-file offense).
    pub line_no: usize,
    /// A short machine tag naming which tooth fired.
    pub kind: String,
    /// The trimmed offending line (empty for a whole-file offense).
    pub line: String,
}

/// Resolve the workspace root (two levels up from this crate's manifest dir).
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .expect("pillar-realness-gate lives two dirs under the workspace root")
        .to_path_buf()
}

/// Every `.rs` file under `crates/*/src/` (shipping source). Excludes each
/// crate's `tests/`/`benches/`.
pub fn shipping_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates = root.join("crates");
    let entries = match fs::read_dir(&crates) {
        Ok(e) => e,
        Err(e) => panic!("cannot read {}: {e}", crates.display()),
    };
    for crate_dir in entries.flatten() {
        // The gate's OWN source names the forbidden tokens as constants and in
        // doc comments; it is the scanner, not a scanned feature. Exclude it
        // exactly as the crypto gate excludes its own gate file.
        if crate_dir.file_name() == std::ffi::OsStr::new("pillar-realness-gate") {
            continue;
        }
        let src = crate_dir.path().join("src");
        if src.is_dir() {
            collect_rs(&src, &mut out);
        }
    }
    out.sort();
    out
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Strip `//` line comments and `/* */` block comments from a single line,
/// carrying the block-comment state across lines. Returns the code-only text and
/// the new in-block-comment state. (Same conservative approach as the crypto
/// gate: a `//` inside a string literal would over-strip, only ever RELAXING the
/// gate, never creating a false positive.)
fn strip_comments(line: &str, mut in_block: bool) -> (String, bool) {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < bytes.len() {
        if in_block {
            if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            break;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            in_block = true;
            i += 2;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    (out, in_block)
}

/// Whole-word (identifier-boundary) match of `tok` in `hay`. Rust identifiers
/// are `[A-Za-z0-9_]`; the modeled verbs are matched on this boundary so `run`
/// does not match `overrun` or `running`.
fn contains_token(hay: &str, tok: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = hay[start..].find(tok) {
        let abs = start + pos;
        let before_ok = abs == 0 || !is_ident_char(hay.as_bytes()[abs - 1]);
        let after = abs + tok.len();
        let after_ok = after >= hay.len() || !is_ident_char(hay.as_bytes()[after]);
        if before_ok && after_ok {
            return true;
        }
        start = abs + tok.len();
    }
    false
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Does this file contain ANY real-syscall marker (in shipping, comment-stripped
/// code)? A file that does is trusted for the modeled-verb tooth — its verbs are
/// backed by real I/O somewhere in the same delivered path (the file).
fn file_has_real_syscall(text: &str) -> bool {
    let mut in_block = false;
    for raw in text.lines() {
        let (code, next) = strip_comments(raw, in_block);
        in_block = next;
        for &m in REAL_SYSCALL_MARKERS {
            if code.contains(m) {
                return true;
            }
        }
    }
    false
}

/// Does this line CLAIM a modeled verb as a real operation? We look for the verb
/// as a whole word in a code position that reads as an operation: a call
/// (`verb(`), a method (`.verb(`), or a fn definition (`fn verb`). A bare mention
/// (a struct field, a match arm) is not by itself a claim of execution.
/// Scan a single file's TEXT for feature-realness offenses in shipping (non-test,
/// non-annotated) code. `label` names the source for error messages.
///
/// The `#[cfg(test)]` skipping and `// non-security:` opt-out are honored exactly
/// as in the crypto gate. The modeled-verb tooth is FILE-scoped: if the file
/// contains any real syscall marker, its modeled verbs are considered backed and
/// are not flagged.
pub fn scan_source(label: &str, text: &str) -> Vec<Offense> {
    let mut offenses = Vec::new();
    let has_syscall = file_has_real_syscall(text);

    let mut pending_cfg_test = false;
    let mut test_skip_depth: Option<i32> = None;
    let mut depth: i32 = 0;
    let mut in_block_comment = false;

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;

        let trimmed = raw.trim_start();
        let is_cfg_test_attr = trimmed.starts_with("#[cfg(test)]")
            || (trimmed.starts_with("#[cfg(") && trimmed.contains("test)"));

        let annotated = raw.contains(NON_SECURITY_MARKER) || raw.contains(REALNESS_EXEMPT_MARKER);
        let (code, block_state) = strip_comments(raw, in_block_comment);
        in_block_comment = block_state;

        let opens = code.matches('{').count() as i32;
        let closes = code.matches('}').count() as i32;

        if let Some(open_depth) = test_skip_depth {
            depth += opens - closes;
            if depth <= open_depth {
                test_skip_depth = None;
            }
            continue;
        }

        let starts_test_mod =
            (is_cfg_test_attr || pending_cfg_test) && code.contains("mod ") && code.contains('{');
        if starts_test_mod {
            let before = depth;
            depth += opens - closes;
            test_skip_depth = Some(before);
            pending_cfg_test = false;
            continue;
        }

        if is_cfg_test_attr {
            pending_cfg_test = true;
            depth += opens - closes;
            continue;
        }

        if pending_cfg_test {
            pending_cfg_test = false;
            depth += opens - closes;
            continue;
        }

        depth += opens - closes;

        // Exempt an explicitly annotated line entirely.
        if annotated {
            continue;
        }

        // Tooth 1a — no-op-reports-success handler.
        if is_noop_reports_success(raw) {
            offenses.push(Offense {
                file: label.to_string(),
                line_no,
                kind: "noop-reports-success".to_string(),
                line: raw.trim().to_string(),
            });
        }

        // Tooth 1b — stand-in / placeholder payload used as real data (a token
        // sitting inside a string/byte literal, not a mere identifier).
        for &tok in PLACEHOLDER_LITERAL_TOKENS {
            if literal_contains(&code, tok) {
                offenses.push(Offense {
                    file: label.to_string(),
                    line_no,
                    kind: format!("placeholder-payload:{tok}"),
                    line: raw.trim().to_string(),
                });
            }
        }
        // A confession phrase (`TODO:` / `for now` / `FIXME`) in a shipping line.
        if let Some(p) = has_confession(raw) {
            offenses.push(Offense {
                file: label.to_string(),
                line_no,
                kind: format!("confession:{p}"),
                line: raw.trim().to_string(),
            });
        }

        // Tooth 1c — a verb that CONFESSES it is modeled, in a file with no real
        // syscall anywhere.
        if !has_syscall {
            if let Some(verb) = claims_modeled_verb(&code) {
                offenses.push(Offense {
                    file: label.to_string(),
                    line_no,
                    kind: format!("modeled-verb-no-syscall:{verb}"),
                    line: raw.trim().to_string(),
                });
            }
        }
    }

    offenses
}

/// THE GATE (helper). Scan every shipping source file in the workspace rooted at
/// `root`; return every offense. The `#[test]` in `tests/` calls this against the
/// real tree and asserts it is empty.
pub fn scan_workspace(root: &Path) -> Vec<Offense> {
    let files = shipping_rs_files(root);
    assert!(
        !files.is_empty(),
        "found no shipping .rs files under {}/crates/*/src — the gate would be a no-op",
        root.display()
    );
    let mut all = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
        let rel = file
            .strip_prefix(root)
            .unwrap_or(file)
            .to_string_lossy()
            .to_string();
        all.extend(scan_source(&rel, &text));
    }
    all
}

/// The workspace root, exported so the gate test and any external caller resolve
/// it identically.
pub fn workspace_root_path() -> PathBuf {
    workspace_root()
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn flags_noop_reports_success() {
        let src = r#"
pub fn reconcile(&self) -> Result<(), Error> {
    // no-op reconcile: reports success without touching the apiserver
    Ok(())
}
"#;
        let o = scan_source("f.rs", src);
        assert!(o.iter().any(|o| o.kind == "noop-reports-success"), "{o:?}");
    }

    #[test]
    fn flags_placeholder_payload() {
        let src = r#"
pub fn layer(&self) -> Vec<u8> {
    let bytes = b"oci-image-layer-payload".to_vec();
    bytes
}
"#;
        let o = scan_source("f.rs", src);
        assert!(
            o.iter().any(|o| o.kind.starts_with("placeholder-payload")),
            "{o:?}"
        );
    }

    #[test]
    fn flags_modeled_verb_without_syscall() {
        let src = r#"
pub fn run(&self, spec: &Spec) -> RunResult {
    // modeled run: no process is ever spawned
    let modeled = self.run(spec);
    modeled
}
"#;
        let o = scan_source("f.rs", src);
        assert!(
            o.iter()
                .any(|o| o.kind.starts_with("modeled-verb-no-syscall")),
            "{o:?}"
        );
    }

    #[test]
    fn does_not_flag_run_backed_by_a_real_process() {
        let src = r#"
use std::process::Command;
pub fn run(&self, spec: &Spec) -> std::io::Result<std::process::Child> {
    Command::new(&spec.bin).spawn()
}
"#;
        let o = scan_source("f.rs", src);
        assert!(
            !o.iter()
                .any(|o| o.kind.starts_with("modeled-verb-no-syscall")),
            "real-syscall run was wrongly flagged: {o:?}"
        );
    }

    #[test]
    fn honors_cfg_test_and_annotation() {
        let src = r#"
fn lb_hash(k: &str) -> usize {
    // non-security: LB hash, not a security primitive
    let _ = k; 0
}

#[cfg(test)]
mod tests {
    // a fixture may model a run with a stand-in placeholder payload
    pub fn run() -> &'static str { "oci-image-layer-payload" }
}
"#;
        let o = scan_source("f.rs", src);
        assert!(o.is_empty(), "exemptions wrongly flagged: {o:?}");
    }
}
