//! Doc-comment freshness lint (comment-hygiene-sweep).
//!
//! The operator was actively misled during the crypto audit by comment ROT:
//! `pillar-crypto` carried module/doc comments asserting "Every operation is
//! `NotImplemented`" and "RED until a real implementation lands" long after the
//! primitives were really shipped (see `docs/tasks/stale-crypto-doc-cleanup.md`
//! and the repo-wide `comment-hygiene-sweep`). Unmaintained comments are worse
//! than none; this test catches THAT class of rot mechanically so a future
//! regression is a failing test, not another manual audit.
//!
//! The heuristic, deliberately narrow and grep-free of intent: a source file
//! may only claim its operations are "not (yet) implemented" / "returns
//! `NotImplemented` today" / "RED until a real implementation lands" if that
//! same file's CODE actually still leaves work unimplemented — i.e. it returns
//! `CryptoError::NotImplemented` / `Err(...NotImplemented...)`, or contains a
//! `todo!()` / `unimplemented!()` / `panic!("not implemented")`. A file that
//! asserts un-implementedness in prose while its code implements the operation
//! is stale-by-construction and fails here.

use std::fs;
use std::path::{Path, PathBuf};

/// Prose fragments (lowercased) that CLAIM the code is not implemented yet.
/// Matched only inside comment lines.
const STALE_CLAIM_FRAGMENTS: &[&str] = &[
    "not yet implemented",
    "returns notimplemented today",
    "return notimplemented today",
    "returns `notimplemented` today",
    "red until a real implementation lands",
    "every operation is `notimplemented`",
    "every operation is notimplemented",
    "each function returns [`cryptoerror::notimplemented`]",
    "each function returns `notimplemented`",
];

/// Code tokens that make an "un-implemented" claim TRUE for a given file.
const UNIMPL_CODE_TOKENS: &[&str] = &[
    "todo!(",
    "unimplemented!(",
    "notimplemented(", // e.g. Err(CryptoError::NotImplemented("sign::verify"))
    "\"not implemented",
];

/// Is `line` a Rust comment line (`//`, `///`, `//!`, or a `*`-prefixed block
/// body line)? Coarse but sufficient — we only need to avoid matching the
/// literal `NotImplemented` variant name in real code, and comment prose is
/// where the stale CLAIMS live.
fn is_comment_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with('*') || t.starts_with("/*")
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = .../crates/pillar-core
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("workspace root above crates/pillar-core")
        .to_path_buf()
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            // Skip build output and version-control dirs.
            if name == "target" || name == ".git" {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

#[test]
fn no_stale_unimplemented_claims() {
    let root = workspace_root();
    let crates_dir = root.join("crates");
    let mut files = Vec::new();
    collect_rs_files(&crates_dir, &mut files);
    assert!(
        !files.is_empty(),
        "found no .rs files under {} — lint would be a no-op",
        crates_dir.display()
    );

    let mut offenders: Vec<String> = Vec::new();

    for file in &files {
        // This lint file itself names the fragments as data; exempt it.
        if file.ends_with("tests/doc_freshness.rs") {
            continue;
        }
        let Ok(content) = fs::read_to_string(file) else {
            continue;
        };
        let lower = content.to_lowercase();

        // Does the file's CODE genuinely still leave something unimplemented?
        // (Search non-comment lines for the unimpl tokens.)
        let code_is_unimpl = lower.lines().any(|line| {
            if is_comment_line(line) {
                return false;
            }
            UNIMPL_CODE_TOKENS.iter().any(|tok| line.contains(tok))
        });
        if code_is_unimpl {
            continue; // claim is (still) true for this file
        }

        // Otherwise, no comment line may CLAIM un-implementedness.
        for (idx, line) in lower.lines().enumerate() {
            if !is_comment_line(line) {
                continue;
            }
            for frag in STALE_CLAIM_FRAGMENTS {
                if line.contains(frag) {
                    offenders.push(format!(
                        "{}:{}: stale claim {:?} but the file implements the \
                         operation (no todo!/unimplemented!/NotImplemented in \
                         its code)",
                        file.strip_prefix(&root).unwrap_or(file).display(),
                        idx + 1,
                        frag,
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "doc-comment freshness lint found stale \"not implemented\" claims \
         whose code contradicts them (fix or DELETE the comment):\n{}",
        offenders.join("\n"),
    );
}
