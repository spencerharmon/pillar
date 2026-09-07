//! Workspace-wide no-stub gate (companion to `realness_gate.rs`).
//!
//! The crypto realness gate keeps a placeholder *primitive* out of shipping
//! code. This gate closes the other half of "close every remaining stub": it
//! FAILS CI if any shipping (non-test) source file uses an unfinished-code
//! macro — `todo!()`, `unimplemented!()`, or `panic!("not implemented"...)` —
//! so no future stub can pass review as DONE undetected across the WHOLE tree,
//! not just the crypto crate.
//!
//! Two — and only two — call sites are exempt, mirroring the realness gate:
//!
//!   * `#[cfg(test)]` code (a fixture may legitimately `todo!()`/`unimplemented!()`
//!     in an unfinished test path), and
//!   * a line explicitly annotated `// allow-stub: <why>` — a sanctioned,
//!     documented escape hatch, kept as a single constant.
//!
//! The gate is RED against an inline pre-cleanup fixture (a shipping function
//! whose body is `todo!()`) and GREEN against the real post-cleanup tree — the
//! `pre_cleanup_fixture_is_red` test pins that direction so the gate can never
//! silently become a no-op.

use std::fs;
use std::path::{Path, PathBuf};

/// Explicit opt-out marker. A source line carrying this substring is exempt.
/// Kept as a single constant so there is exactly one sanctioned escape hatch.
const ALLOW_STUB_MARKER: &str = "allow-stub:";

/// A forbidden unfinished-code macro, matched as a whole-word token in stripped
/// (comment-free) source. Each marks code that is not actually implemented.
const FORBIDDEN_TOKENS: &[&str] = &[
    "todo!",
    "unimplemented!",
];

/// The `panic!("not implemented"...)` shape is matched separately: `panic!` on
/// its own is a legitimate assertion, so it is only forbidden when its message
/// begins with "not implemented".
const PANIC_NOT_IMPLEMENTED_PREFIXES: &[&str] = &[
    "panic!(\"not implemented",
    "panic!(\"not yet implemented",
];

/// Resolve the workspace root (two levels up from this crate's manifest dir:
/// `crates/pillar-crypto` -> workspace root).
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("pillar-crypto lives two dirs under the workspace root")
        .to_path_buf()
}

/// Every `.rs` file under `crates/*/src/` (shipping source). Excludes each
/// crate's `tests/` and `benches/` — integration tests and benches are not
/// shipping code.
fn shipping_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates = root.join("crates");
    let entries = fs::read_dir(&crates)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", crates.display()));
    for crate_dir in entries.flatten() {
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

/// One flagged offense.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Offense {
    file: String,
    line_no: usize,
    token: String,
    line: String,
}

/// Scan a single file's TEXT (not path) for stub macros in shipping (non-test,
/// non-comment, non-annotated) code. `label` names the source for error
/// messages. Returns every offense found.
///
/// The scan strips comments, skips `#[cfg(test)]` modules and lines, and honors
/// the `// allow-stub:` opt-out.
fn scan_source(label: &str, text: &str) -> Vec<Offense> {
    let mut offenses = Vec::new();
    let mut pending_cfg_test = false;
    let mut test_skip_depth: Option<i32> = None;
    let mut depth: i32 = 0;
    let mut in_block_comment = false;

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;

        let trimmed = raw.trim_start();
        let is_cfg_test_attr = trimmed.starts_with("#[cfg(test)]")
            || (trimmed.starts_with("#[cfg(") && trimmed.contains("test)"));

        let annotated = raw.contains(ALLOW_STUB_MARKER);
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

        let starts_test_mod = (is_cfg_test_attr || pending_cfg_test)
            && code.contains("mod ")
            && code.contains('{');
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

        if annotated {
            continue;
        }

        // Whole-word macro tokens (`todo!`, `unimplemented!`).
        for &tok in FORBIDDEN_TOKENS {
            if contains_macro_token(&code, tok) {
                offenses.push(Offense {
                    file: label.to_string(),
                    line_no,
                    token: tok.to_string(),
                    line: raw.trim().to_string(),
                });
            }
        }

        // `panic!("not implemented"...)` — a substring shape, whitespace-normalized
        // so `panic!(  "not implemented"` still matches.
        let normalized: String = code.split_whitespace().collect::<Vec<_>>().join(" ");
        let compact = normalized.replace("panic! (", "panic!(");
        for prefix in PANIC_NOT_IMPLEMENTED_PREFIXES {
            if compact.contains(prefix) {
                offenses.push(Offense {
                    file: label.to_string(),
                    line_no,
                    token: "panic!(\"not implemented\"...)".to_string(),
                    line: raw.trim().to_string(),
                });
                break;
            }
        }
    }
    offenses
}

/// Strip `//` line comments and `/* */` block comments from a single line,
/// carrying the block-comment state across lines. Returns the code-only text and
/// the new in-block-comment state.
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
            break; // line comment: rest of line is a comment
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

/// Match a macro token like `todo!` at an identifier boundary on its LEFT (so
/// `mytodo!` does not match) — the trailing `!` is itself the right boundary.
fn contains_macro_token(hay: &str, tok: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = hay[start..].find(tok) {
        let abs = start + pos;
        let before_ok = abs == 0 || !is_ident_char(hay.as_bytes()[abs - 1]);
        if before_ok {
            return true;
        }
        start = abs + tok.len();
    }
    false
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// THE GATE. Scan every shipping source file in the workspace; fail with a
/// precise report if any unfinished-code stub macro survives in shipping code.
#[test]
fn no_stub_macros_in_shipping_code() {
    let root = workspace_root();
    let files = shipping_rs_files(&root);
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
            .strip_prefix(&root)
            .unwrap_or(file)
            .to_string_lossy()
            .to_string();
        all.extend(scan_source(&rel, &text));
    }

    if !all.is_empty() {
        let mut msg = String::from(
            "no-stub gate: an unfinished-code stub macro survives in shipping code.\n\
             `todo!()`, `unimplemented!()`, and `panic!(\"not implemented\"...)` mark \
             code that is not actually implemented and must never ship as DONE. Finish \
             the implementation. If a call site is genuinely a permanent, justified \
             unreachable/placeholder, annotate that exact line `// allow-stub: <why>`; \
             test-only code under `#[cfg(test)]` is exempt.\n\n",
        );
        for o in &all {
            msg.push_str(&format!(
                "  {}:{}  uses `{}`\n      {}\n",
                o.file, o.line_no, o.token, o.line
            ));
        }
        panic!("{msg}");
    }
}

/// Direction pin: the gate must be RED against a PRE-CLEANUP shipping-code
/// snapshot (a stub macro in shipping code) and GREEN once it is removed. This
/// proves the scanner actually detects a stub rather than being a vacuous pass,
/// without depending on git history.
#[test]
fn pre_cleanup_fixture_is_red() {
    let pre_cleanup = r#"
/// An unfinished function shipping a stub body.
pub fn compute(x: u32) -> u32 {
    todo!("wire up the real computation")
}

pub fn other() -> u8 {
    unimplemented!()
}

pub fn third() -> u8 {
    panic!("not implemented yet")
}
"#;
    let offenses = scan_source("fixture/pre_cleanup.rs", pre_cleanup);
    assert!(
        offenses.iter().any(|o| o.token == "todo!"),
        "scanner FAILED to flag a shipping `todo!()` — the gate would miss stubs; got {offenses:?}"
    );
    assert!(
        offenses.iter().any(|o| o.token == "unimplemented!"),
        "scanner FAILED to flag a shipping `unimplemented!()`; got {offenses:?}"
    );
    assert!(
        offenses
            .iter()
            .any(|o| o.token == "panic!(\"not implemented\"...)"),
        "scanner FAILED to flag a shipping `panic!(\"not implemented\"...)`; got {offenses:?}"
    );
}

/// The scanner must NOT flag the sanctioned exemptions: a `#[cfg(test)]` module
/// using a stub macro, a line explicitly annotated `// allow-stub:`, a plain
/// `panic!("real assertion")`, an identifier that merely CONTAINS a token, and
/// doc-comment prose.
#[test]
fn exemptions_are_honored() {
    let exempt = r#"
/// A doc comment mentioning todo! and unimplemented! in prose is not code.
pub fn real() -> u8 { 0 }

pub fn asserts() {
    panic!("this is a real, legitimate assertion");
}

pub fn permanently_unreachable() -> u8 {
    unimplemented!() // allow-stub: this variant is structurally impossible, kept for exhaustiveness
}

fn my_todo_list() -> u8 { 1 }

#[cfg(test)]
mod tests {
    #[test]
    fn a_stub_in_a_fixture_is_fine() {
        fn helper() -> u8 { todo!() }
        let _ = helper;
    }
}
"#;
    let offenses = scan_source("fixture/exempt.rs", exempt);
    assert!(
        offenses.is_empty(),
        "scanner wrongly flagged a sanctioned exemption (annotated line, cfg(test) \
         module, real panic!, boundaried identifier, or doc-comment prose): {offenses:?}"
    );
}
