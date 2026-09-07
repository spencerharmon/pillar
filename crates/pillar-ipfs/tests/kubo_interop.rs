//! Proof that this node's blocks ARE real IPFS blocks — validated against the
//! reference implementation (`ipfs`/kubo) used purely as an EXTERNAL ORACLE.
//!
//! kubo is not a dependency of `pillar-ipfs` (or of pillar): this test shells
//! out to the `ipfs` CLI, runs it fully **offline** against a throwaway repo,
//! and checks two directions of agreement:
//!   1. kubo, given the exact bytes this node stores, computes the IDENTICAL
//!      CIDv1(`raw`, sha2-256) string this node computes.
//!   2. kubo can address (`block get`) that block by the CID this node computed,
//!      returning byte-identical content.
//!
//! Gated `#[ignore]` + requires `PILLAR_TEST_KUBO=1` and an `ipfs` binary on
//! PATH, so ordinary `cargo test` never needs kubo. Run it with:
//!   PILLAR_TEST_KUBO=1 cargo test -p pillar-ipfs --test kubo_interop -- --ignored

use std::io::Write;
use std::process::{Command, Stdio};

/// Run `ipfs <args>` (with `--offline`) against `repo`, feeding `stdin_bytes`,
/// returning stdout bytes. Panics with the CLI's stderr on failure.
fn ipfs(repo: &std::path::Path, args: &[&str], stdin_bytes: Option<&[u8]>) -> Vec<u8> {
    let mut cmd = Command::new("ipfs");
    cmd.env("IPFS_PATH", repo)
        .arg("--offline")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn ipfs (is the kubo CLI on PATH?)");
    if let Some(bytes) = stdin_bytes {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(bytes)
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait ipfs");
    assert!(
        out.status.success(),
        "ipfs {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

#[test]
#[ignore = "requires PILLAR_TEST_KUBO=1 and the ipfs/kubo CLI on PATH"]
fn our_blocks_are_real_ipfs_blocks_agreeing_with_kubo() {
    if std::env::var("PILLAR_TEST_KUBO").ok().as_deref() != Some("1") {
        eprintln!("skipping: set PILLAR_TEST_KUBO=1 to run the kubo interop oracle");
        return;
    }

    let repo = std::env::temp_dir().join(format!("pillar-ipfs-kubo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&repo);
    // A throwaway, offline kubo repo — the oracle, no daemon, no network.
    ipfs(&repo, &["init", "--profile", "test"], None);

    let block = b"a pillar signed segment stored as a real IPFS raw block".to_vec();

    // (1) The CID this node computes.
    let ours = pillar_ipfs::to_cidv1_raw(&pillar_ipfs::content_id(&block));

    // kubo's CID for the SAME bytes, stored as a raw+sha2-256 block.
    let kubo_cid = String::from_utf8(ipfs(
        &repo,
        &["block", "put", "--cid-codec=raw", "--mhtype=sha2-256"],
        Some(&block),
    ))
    .expect("utf8 cid")
    .trim()
    .to_string();

    assert_eq!(
        ours, kubo_cid,
        "pillar-ipfs and kubo must compute the identical CIDv1(raw) for the same bytes"
    );

    // (2) kubo can address the block by the CID this node computed.
    let fetched = ipfs(&repo, &["block", "get", &ours], None);
    assert_eq!(
        fetched, block,
        "kubo must return byte-identical content for the CID pillar-ipfs computed"
    );

    // And the round-trip parses back to the same content id.
    assert_eq!(
        pillar_ipfs::from_cidv1_raw(&kubo_cid),
        Some(pillar_ipfs::content_id(&block)),
        "kubo's CID string must parse back to the pillar content id"
    );

    let _ = std::fs::remove_dir_all(&repo);
}
