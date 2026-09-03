//! Workspace-wide crypto realness gate.
//!
//! The narrow `pillar-crypto` contract tests prove that THIS crate's primitives
//! are real (a >=256-bit collision-resistant content address, a real Ed25519
//! signature, a real AEAD seal). They do NOT stop a CONSUMING crate from quietly
//! reintroducing a placeholder primitive — a `DefaultHasher`/`SipHash`/FNV
//! "digest", a `u64`-typed "signature", or a bare `==` standing in for a
//! signature verification. The six real-crypto migration tasks
//! (node-custody-real-crypto, passkey-credential-real-crypto,
//! bootstrap-request-seal-real-crypto, bootstrap-token-real-crypto,
//! identity-login-real-crypto, eventlog-signature-real-crypto) each removed one
//! such offender; nothing kept them out.
//!
//! This gate scans EVERY workspace crate's shipping (non-test) source and FAILS
//! CI if a forbidden non-cryptographic primitive is used as a security
//! primitive anywhere in the tree. Two — and only two — call sites are exempt:
//!
//!   * `#[cfg(test)]` code (fixtures may legitimately use a cheap hash), and
//!   * a line explicitly annotated `// non-security: ...` — used solely by the
//!     load-balancer `consistent_hash` in `pillar-manifest/src/ingress.rs`,
//!     which is a routing hash, not a security primitive.
//!
//! The gate is RED against the pre-migration tree (each offender used a
//! forbidden primitive in shipping code) and GREEN once all six land — the
//! `pre_migration_fixture_is_red` test pins that direction against an inline
//! fixture snapshot so the gate can never silently become a no-op.

use std::collections::hash_map::DefaultHasher; // non-security: this file is a test; scanner skips tests/
use std::fs;
use std::path::{Path, PathBuf};

/// Explicit opt-out marker. A source line carrying this substring is exempt
/// (the load-balancer routing hash in ingress.rs). Kept as a single constant so
/// there is exactly one sanctioned escape hatch.
const NON_SECURITY_MARKER: &str = "non-security:";

/// A forbidden non-cryptographic primitive, matched as a whole-word token in
/// stripped (comment-free) source. Each of these, used as a security digest or
/// signature, is a placeholder the six migration tasks removed.
const FORBIDDEN_TOKENS: &[&str] = &[
    "DefaultHasher", // std SipHash — a 64-bit checksum, not a crypto digest
    "SipHasher",     // the underlying SipHash type
    "SipHasher13",
    "FnvHasher", // the fnv crate's hasher
    "FnvHashMap",
    "FnvHashSet",
    "FnvBuildHasher",
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
/// shipping code — and this gate file itself.
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

/// Scan a single file's TEXT (not path) for forbidden primitives in shipping
/// (non-test, non-comment, non-annotated) code. `label` names the source for
/// error messages. Returns every offense found.
///
/// The scan strips comments, skips `#[cfg(test)]` modules and lines, and honors
/// the `// non-security:` opt-out — so it flags only a forbidden token in real,
/// shipping, security-relevant code.
fn scan_source(label: &str, text: &str) -> Vec<Offense> {
    let mut offenses = Vec::new();
    // Depth-tracked skip of `#[cfg(test)]` modules: once we see the attribute
    // immediately before a `mod ... {`, skip until its matching brace closes.
    let mut pending_cfg_test = false;
    let mut test_skip_depth: Option<i32> = None; // brace depth at which the test mod opened
    let mut depth: i32 = 0;
    let mut in_block_comment = false;

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;

        // Track a `#[cfg(test)]` attribute so the following `mod` block is skipped.
        let trimmed = raw.trim_start();
        let is_cfg_test_attr = trimmed.starts_with("#[cfg(test)]")
            || (trimmed.starts_with("#[cfg(") && trimmed.contains("test)"));

        // Strip comments to get the code-only view of the line, while remembering
        // whether the ORIGINAL line carried the non-security opt-out.
        let annotated = raw.contains(NON_SECURITY_MARKER);
        let (code, block_state) = strip_comments(raw, in_block_comment);
        in_block_comment = block_state;

        // Maintain brace depth on the code-only text.
        let opens = code.matches('{').count() as i32;
        let closes = code.matches('}').count() as i32;

        // If we are inside a skipped test module, just track depth until it closes.
        if let Some(open_depth) = test_skip_depth {
            depth += opens - closes;
            if depth <= open_depth {
                test_skip_depth = None;
            }
            continue;
        }

        // A `#[cfg(test)] mod foo {` (attribute + mod on one line) opens a
        // skipped module. Record the depth BEFORE this line's braces.
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

        // A bare `#[cfg(test)]` attribute line (no `mod {` on it) arms the NEXT
        // line: it gates either a `mod tests {` block (skip the whole block) or a
        // single test-only item (skip that line). Always arm, and skip this
        // attribute line itself.
        if is_cfg_test_attr {
            pending_cfg_test = true;
            depth += opens - closes;
            continue;
        }

        // Armed by a prior `#[cfg(test)]` and this line is not a mod open: it is
        // a per-item `#[cfg(test)] fn ...` whose item body is test-only. Skip this
        // line's token scan and disarm.
        if pending_cfg_test {
            pending_cfg_test = false;
            depth += opens - closes;
            continue;
        }

        depth += opens - closes;

        // Exempt lines that are themselves test-gated or explicitly annotated.
        if is_cfg_test_attr || annotated {
            continue;
        }

        for &tok in FORBIDDEN_TOKENS {
            if contains_token(&code, tok) {
                offenses.push(Offense {
                    file: label.to_string(),
                    line_no,
                    token: tok.to_string(),
                    line: raw.trim().to_string(),
                });
            }
        }
    }
    offenses
}

/// Strip `//` line comments and `/* */` block comments from a single line,
/// carrying the block-comment state across lines. Returns the code-only text and
/// the new in-block-comment state. String/char literals are treated
/// conservatively: a `//` inside a string would over-strip, but the forbidden
/// tokens never legitimately appear inside a string literal in shipping code, so
/// this only ever RELAXES the gate on a pathological line, never tightens it into
/// a false positive.
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

/// Whole-word (identifier-boundary) match of `tok` in `hay`, so `DefaultHasher`
/// does not match a longer identifier like `MyDefaultHasherWrapper` unless the
/// token stands on its own boundary. Rust identifiers are `[A-Za-z0-9_]`.
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

/// THE GATE. Scan every shipping source file in the workspace; fail with a
/// precise report if any forbidden primitive is used in security-relevant code.
#[test]
fn no_placeholder_crypto_in_shipping_code() {
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
            "crypto realness gate: forbidden non-cryptographic primitive used as a \
             security primitive in shipping code.\n\
             A `DefaultHasher`/`SipHash`/FNV hash is a 64-bit checksum, not a crypto \
             digest or signature. Use a real primitive from pillar-crypto (a >=256-bit \
             content address, an Ed25519 signature, an AEAD seal). If a use is genuinely \
             NON-security (a load-balancer routing hash), annotate that exact line \
             `// non-security: <why>`; test-only code under `#[cfg(test)]` is exempt.\n\n",
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

/// Direction pin: the gate must be RED against a PRE-MIGRATION shipping-code
/// snapshot (a forbidden primitive used outside test/annotation) and GREEN once
/// it is removed. This proves the scanner actually detects an offender rather
/// than being a vacuous pass, without depending on git history.
#[test]
fn pre_migration_fixture_is_red() {
    // A representative pre-migration offender: a consuming crate deriving a
    // "content address" from `DefaultHasher` in SHIPPING code (no annotation,
    // not under cfg(test)). This is exactly the shape the six tasks removed.
    let pre_migration = r#"
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Placeholder content address — a 64-bit checksum masquerading as a digest.
pub fn content_address(bytes: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}
"#;
    let offenses = scan_source("fixture/pre_migration.rs", pre_migration);
    assert!(
        !offenses.is_empty(),
        "scanner FAILED to flag a pre-migration DefaultHasher content address — \
         the gate would not have caught the six offenders"
    );
    assert!(
        offenses.iter().any(|o| o.token == "DefaultHasher"),
        "expected a DefaultHasher offense in the pre-migration fixture, got {offenses:?}"
    );
}

/// The scanner must NOT flag the two sanctioned exemptions: a `#[cfg(test)]`
/// module using a cheap hash, and a line explicitly annotated `// non-security:`.
#[test]
fn exemptions_are_honored() {
    let exempt = r#"
/// A doc comment mentioning DefaultHasher and SipHash in prose is not code.
pub fn real() -> u8 { 0 }

fn lb_hash(k: &str, n: usize) -> usize {
    use std::collections::hash_map::DefaultHasher; // non-security: LB hash, not a security primitive
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new(); // non-security: LB hash, not a security primitive
    k.hash(&mut h);
    (h.finish() as usize) % n
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    #[test]
    fn cheap_hash_in_a_fixture_is_fine() {
        let mut h = DefaultHasher::new();
        42u8.hash(&mut h);
        assert!(h.finish() != 0 || h.finish() == 0);
    }
}
"#;
    let offenses = scan_source("fixture/exempt.rs", exempt);
    assert!(
        offenses.is_empty(),
        "scanner wrongly flagged a sanctioned exemption (annotated line, cfg(test) \
         module, or doc-comment prose): {offenses:?}"
    );
}

/// Silence the unused-import lint for the top-of-file `DefaultHasher` (kept so
/// this test file itself demonstrates the token is fine in test code).
#[test]
fn this_test_file_is_itself_test_code() {
    let mut h = DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    42u8.hash(&mut h);
    let _ = h.finish();
}
