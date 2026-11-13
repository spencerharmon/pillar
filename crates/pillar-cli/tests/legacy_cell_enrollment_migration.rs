//! Real-process legacy-cell conversion + enrollment:
//! `cargo test -p pillar-cli --test legacy_cell_enrollment_migration`.
//!
//! The fixture is a LEGACY cell: a real `pillar node run` whose data directory
//! already holds `streamdb/` without `cell-credentials.json` boots under the
//! pre-independent-credentials derivation (cell ID and group-key seed derived
//! from the device's private identity bytes — asserted below against
//! `identity.key`), and a real bootstrap/login/apply writes signed, cell-
//! encrypted ops to it. No state is reconstructed by the test.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::config_export;
use pillar_client::ClientConfig;
use pillar_manifest::Crd;
use sha2::{Digest, Sha256};

const PASSWORD: &str = "legacy migration integration unlock factor";
const HANDLE: &str = "alice";
const ACK: &str = "--acknowledge-cell-id-change";

fn cli(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pillar"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("RUST_LOG", "error")
        .current_dir(home)
        .stdin(Stdio::null());
    command
}

fn success(command: &mut Command) -> String {
    let output = command.output().expect("execute pillar");
    assert!(
        output.status.success(),
        "pillar failed ({}):\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 CLI output")
}

fn failure(command: &mut Command, reason: &str) -> String {
    let Output {
        status,
        stdout,
        stderr,
    } = command.output().expect("execute pillar");
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(!status.success(), "unexpected success: {text}");
    assert!(text.contains(reason), "expected {reason:?}: {text}");
    text
}

fn http(port: u16, method: &str, path: &str, body: &str) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(2),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut text = String::new();
    stream.read_to_string(&mut text)?;
    let (headers, body) = text.split_once("\r\n\r\n").expect("HTTP response");
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    Ok((status, body.to_owned()))
}

fn free_tcp() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Node {
    dir: tempfile::TempDir,
    child: Option<Child>,
    http_port: u16,
    resource_port: u16,
}

impl Node {
    fn new(dir: tempfile::TempDir) -> Self {
        Self {
            dir,
            child: None,
            http_port: free_tcp(),
            resource_port: free_udp(),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn run_command(&self) -> Command {
        let mut command = cli(self.path());
        command
            .args(["node", "run"])
            .env("PILLAR_DATA_DIR", self.path())
            .env("PILLAR_LISTEN", "/ip4/127.0.0.1/tcp/0")
            .env("PILLAR_WEB_BIND", "127.0.0.1")
            .env("PILLAR_WEB_PORT", self.http_port.to_string())
            .env("PILLAR_HEALTH_BIND", "127.0.0.1")
            .env("PILLAR_HEALTH_PORT", "0")
            .env("PILLAR_RESOURCE_OP_UDP_BIND", self.resource_addr())
            .env("PILLAR_PUBLIC_RESOURCE_OP_ADDR", self.resource_addr());
        command
    }

    fn start(&mut self) {
        assert!(self.child.is_none());
        self.child = Some(
            self.run_command()
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn pillar node run"),
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "node exited before readiness"
            );
            if matches!(
                http(self.http_port, "GET", "/bootstrap/status", ""),
                Ok((200, _))
            ) {
                return;
            }
            assert!(Instant::now() < deadline, "node readiness timed out");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }

    fn authority(&self) -> String {
        format!("127.0.0.1:{}", self.http_port)
    }

    fn resource_addr(&self) -> String {
        format!("127.0.0.1:{}", self.resource_port)
    }

    fn login(&self) -> String {
        let output = success(cli(self.path()).args([
            "login",
            "--domain",
            &self.authority(),
            "--user",
            HANDLE,
            "--password",
            PASSWORD,
        ]));
        output
            .lines()
            .find_map(|l| l.strip_prefix("export PILLAR_TOKEN="))
            .filter(|t| !t.is_empty())
            .expect("login exports token")
            .to_owned()
    }

    fn migrate(&self, args: &[&str]) -> Command {
        let mut command = cli(self.path());
        command
            .args(["node", "migrate-legacy-cell", "--data-dir"])
            .arg(self.path())
            .args(args);
        command
    }

    fn submit_to(&self, issuer: &Node) -> String {
        let output = success(
            cli(self.path())
                .args([
                    "bootstrap",
                    "node",
                    "--domain",
                    &issuer.authority(),
                    "--data-dir",
                ])
                .arg(self.path()),
        );
        output
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("REQUEST "))
            .expect("REQUEST <id>")
            .to_owned()
    }

    fn complete_from(&self, issuer: &Node, id: &str) -> Command {
        let mut command = cli(self.path());
        command
            .args([
                "bootstrap",
                "node",
                "complete",
                id,
                "--domain",
                &issuer.authority(),
                "--data-dir",
            ])
            .arg(self.path());
        command
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

fn approve(home: &Path, issuer: &Node, token: &str, id: &str) -> Command {
    let mut command = cli(home);
    command.env("PILLAR_TOKEN", token).args([
        "bootstrap",
        "request",
        "approve",
        id,
        "--domain",
        &issuer.authority(),
    ]);
    command
}

fn manifest(name: &str, window: u64) -> String {
    format!(
        "apiVersion: pillar.dev/v1\nkind: RetentionPolicy\nmetadata:\n  name: {name}\nspec:\n  signalKind: Metric\n  window: {window}\n"
    )
}

fn apply(home: &Path, config: &Path, name: &str, window: u64) -> String {
    let file = home.join(format!("{name}.yaml"));
    std::fs::write(&file, manifest(name, window)).unwrap();
    let mut command = cli(home);
    command
        .env("PILLAR_CONFIG", config)
        .args(["apply", "-f"])
        .arg(&file);
    let out = success(&mut command);
    assert!(out.contains("OK"), "{out}");
    out
}

fn apply_fails(home: &Path, config: &Path, name: &str) -> String {
    let file = home.join(format!("{name}.yaml"));
    std::fs::write(&file, manifest(name, 60)).unwrap();
    let output = cli(home)
        .env("PILLAR_CONFIG", config)
        .args(["apply", "-f"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(!output.status.success(), "stale config must be refused");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_resource(home: &Path, config: &Path, name: &str, window: u64) {
    let output =
        success(
            cli(home)
                .env("PILLAR_CONFIG", config)
                .args(["get", "RetentionPolicy", name]),
        );
    assert_eq!(
        Crd::from_documents(&output).unwrap(),
        Crd::from_documents(&manifest(name, window)).unwrap()
    );
}

fn save(config: &ClientConfig, path: &Path, addr: &str) {
    let mut config = config.clone();
    config.identity.as_mut().unwrap().addr = addr.to_owned();
    config_export::save_0600(&config, path).unwrap();
}

/// Content hash of every file under `root` (relative path -> sha256).
fn tree(root: &Path) -> BTreeMap<PathBuf, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    hex(&Sha256::digest(std::fs::read(&path).unwrap())),
                );
            }
        }
    }
    out
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        let target = to.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_tree(&path, &target);
        } else {
            std::fs::copy(&path, &target).unwrap();
        }
    }
}

fn clone_node(from: &Node) -> Node {
    let dir = tempfile::tempdir().unwrap();
    copy_tree(from.path(), dir.path());
    Node::new(dir)
}

fn line<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines()
        .find_map(|l| l.strip_prefix(key))
        .unwrap_or_else(|| panic!("{key} missing: {text}"))
        .trim()
}

/// A real legacy cell: bootstrapped, one admin, one admitted CLI signer, one
/// applied resource — all written under the device-derived credentials.
struct Legacy {
    node: Node,
    client: tempfile::TempDir,
    config: ClientConfig,
}

fn legacy_fixture() -> Legacy {
    let dir = tempfile::tempdir().unwrap();
    // Pre-existing stream directory without independent credentials selects
    // the legacy derivation exactly as an upgraded legacy deployment does.
    std::fs::create_dir(dir.path().join("streamdb")).unwrap();
    let mut node = Node::new(dir);
    node.start();
    success(cli(node.path()).args([
        "bootstrap",
        "cell",
        "neutral-cell",
        "--user",
        HANDLE,
        "--password",
        PASSWORD,
        "--domain",
        &node.authority(),
    ]));
    let token = node.login();
    let config = config_export::fetch_config(&node.authority(), &token).unwrap();
    let identity = config.identity.as_ref().unwrap();
    // Prove the old derivation: the exported cell seed IS the device key.
    let mut legacy_seed = b"pillar-streamdb/segment-signer/v1:".to_vec();
    legacy_seed.extend(std::fs::read(node.path().join("identity.key")).unwrap());
    assert_eq!(identity.cell_seed_hex, hex(&legacy_seed));
    let mut legacy_id = b"pillar-streamdb/cell-id/v1:".to_vec();
    legacy_id.extend(&legacy_seed);
    assert_eq!(identity.cell_id_hex, hex(&legacy_id));
    assert!(!node.path().join("cell-credentials.json").exists());

    let client = tempfile::tempdir().unwrap();
    let path = client.path().join("legacy.yaml");
    save(&config, &path, &node.resource_addr());
    apply(client.path(), &path, "legacy-retained", 2592000);
    assert_resource(client.path(), &path, "legacy-retained", 2592000);
    node.stop();
    Legacy {
        node,
        client,
        config,
    }
}

#[test]
fn legacy_cell_converts_and_admits_an_independent_node_preserving_state() {
    let Legacy {
        mut node,
        client,
        config: legacy_config,
    } = legacy_fixture();
    let home = client.path();

    // Before conversion the legacy cell refuses to distribute its credentials,
    // and the refusal records no admission.
    node.start();
    let token = node.login();
    let mut early = Node::new(tempfile::tempdir().unwrap());
    early.start();
    let early_id = early.submit_to(&node);
    failure(
        &mut approve(home, &node, &token, &early_id),
        "legacy-cell-credentials",
    );
    early.stop();
    node.stop();

    // A running node holds the lock: no hot conversion.
    node.start();
    failure(&mut node.migrate(&["--apply", ACK]), "stop the node");
    node.stop();

    let legacy_tree = tree(&node.path().join("streamdb"));
    let plan = success(&mut node.migrate(&["--plan"]));
    assert!(
        plan.contains("LEGACY CELL") && plan.contains("CONTRACT"),
        "{plan}"
    );
    let ops: u64 = line(&plan, "ops:").parse().unwrap();
    let root = line(&plan, "root:").to_owned();
    assert!(ops > 2, "{plan}");
    failure(&mut node.migrate(&["--apply"]), ACK);
    assert!(!node.path().join("legacy-cell-migration.json").exists());

    // Interrupted mid-reseal (process aborted), then a refused boot, then resume.
    let crashed = node
        .migrate(&["--apply", ACK])
        .env("PILLAR_LEGACY_MIGRATION_CRASH_AT", "partial")
        .output()
        .unwrap();
    assert!(!crashed.status.success());
    failure(
        &mut node.run_command(),
        "legacy cell migration is incomplete",
    );
    let staged = success(&mut node.migrate(&["--plan"]));
    assert!(staged.contains("state: staged"), "{staged}");
    let crashed = node
        .migrate(&["--apply", ACK])
        .env("PILLAR_LEGACY_MIGRATION_CRASH_AT", "renamed")
        .output()
        .unwrap();
    assert!(!crashed.status.success());
    failure(
        &mut node.run_command(),
        "legacy cell migration is incomplete",
    );
    let converted = success(&mut node.migrate(&["--apply", ACK]));
    assert!(
        converted.contains(&format!("CONVERTED {ops} ops (root {root})")),
        "{converted}"
    );
    assert!(success(&mut node.migrate(&["--apply", ACK])).contains("ALREADY CONVERTED"));
    assert_eq!(
        tree(&node.path().join("streamdb")),
        legacy_tree,
        "legacy stream untouched"
    );

    // Rollback boundary, before any post-conversion write: allowed (on a copy).
    let mut rolled = clone_node(&node);
    let back = success(&mut rolled.migrate(&["--rollback"]));
    assert!(back.contains("ROLLED BACK"), "{back}");
    rolled.start();
    let rolled_path = home.join("rolled.yaml");
    save(&legacy_config, &rolled_path, &rolled.resource_addr());
    assert_resource(home, &rolled_path, "legacy-retained", 2592000);
    rolled.stop();

    // Converted node: same logical cell, same admin, same retained resource.
    node.start();
    let token = node.login();
    let fresh = config_export::fetch_config(&node.authority(), &token).unwrap();
    let new_identity = fresh.identity.as_ref().unwrap();
    assert_ne!(
        new_identity.cell_id_hex,
        legacy_config.identity.as_ref().unwrap().cell_id_hex
    );
    let seed: Vec<u8> = (0..new_identity.cell_seed_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&new_identity.cell_seed_hex[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(
        seed.len(),
        32,
        "independent 32-byte seed, not device material"
    );
    assert_eq!(new_identity.cell_id_hex, hex(&Sha256::digest(&seed)));

    // Documented contract: the stale export is refused; the previously
    // admitted signer keeps its admission once the cell fields are updated.
    let stale = home.join("stale.yaml");
    save(&legacy_config, &stale, &node.resource_addr());
    apply_fails(home, &stale, "stale-export-write");
    let mut retargeted = legacy_config.clone();
    {
        let id = retargeted.identity.as_mut().unwrap();
        id.cell_id_hex = new_identity.cell_id_hex.clone();
        id.cell_seed_hex = new_identity.cell_seed_hex.clone();
    }
    let admin = home.join("admin.yaml");
    save(&retargeted, &admin, &node.resource_addr());
    assert_resource(home, &admin, "legacy-retained", 2592000);
    apply(home, &admin, "post-conversion", 604800);
    node.stop();

    // Past the boundary: rollback refused, nothing moved.
    failure(
        &mut node.migrate(&["--rollback"]),
        "rollback boundary passed",
    );
    node.start();
    assert_resource(home, &admin, "post-conversion", 604800);

    // Independent join: forged approval denied, pending cannot install.
    let mut joining = Node::new(tempfile::tempdir().unwrap());
    joining.start();
    let id = joining.submit_to(&node);
    failure(&mut approve(home, &node, "forged-session", &id), "401");
    joining.stop();
    failure(&mut joining.complete_from(&node, &id), "DENIED pending");
    assert!(!joining.path().join("enrollment.sealed").exists());
    let token = node.login();
    let approved = success(&mut approve(home, &node, &token, &id));
    assert_eq!(approved.trim(), format!("APPROVED {id}"));
    success(&mut joining.complete_from(&node, &id));
    // The issuer's device identity never reaches the joiner.
    let issuer_key = std::fs::read(node.path().join("identity.key")).unwrap();
    assert_ne!(
        std::fs::read(joining.path().join("identity.key")).unwrap(),
        issuer_key
    );
    joining.start();
    node.stop();

    let joined = home.join("joined.yaml");
    save(&retargeted, &joined, &joining.resource_addr());
    assert_resource(home, &joined, "legacy-retained", 2592000);
    assert_resource(home, &joined, "post-conversion", 604800);
    apply(home, &joined, "post-join", 86400);
    joining.stop();
    joining.start();
    assert_resource(home, &joined, "legacy-retained", 2592000);
    assert_resource(home, &joined, "post-join", 86400);
    joining.stop();

    // Issuer restart: admin login and retained state survive.
    node.start();
    node.login();
    assert_resource(home, &admin, "legacy-retained", 2592000);
    assert_eq!(tree(&node.path().join("streamdb")), legacy_tree);
}

#[test]
fn corrupt_conflicting_and_staged_rollback_are_refused_or_recovered_safely() {
    let Legacy {
        node,
        client,
        config,
    } = legacy_fixture();
    let home = client.path();

    // Conflicting identity: another device key cannot convert this cell.
    let other = tempfile::tempdir().unwrap();
    let mut probe = Node::new(tempfile::tempdir().unwrap());
    probe.start();
    probe.stop();
    let foreign = other.path().join("identity.key");
    std::fs::copy(probe.path().join("identity.key"), &foreign).unwrap();
    let mut cmd = node.migrate(&["--apply", ACK, "--identity-key"]);
    cmd.arg(&foreign);
    failure(&mut cmd, "conflicting identity");
    assert!(!node.path().join("legacy-cell-migration.json").exists());

    // Corrupt legacy storage: refused before anything is written.
    let corrupt = clone_node(&node);
    let blocks = tree(&corrupt.path().join("streamdb"));
    for rel in blocks.keys() {
        let path = corrupt.path().join("streamdb").join(rel);
        let mut bytes = std::fs::read(&path).unwrap();
        for b in bytes.iter_mut() {
            *b ^= 0x5a;
        }
        std::fs::write(&path, bytes).unwrap();
    }
    let before = tree(corrupt.path());
    corrupt
        .migrate(&["--apply", ACK])
        .output()
        .unwrap()
        .status
        .success()
        .then(|| panic!("corrupt legacy store converted"));
    assert_eq!(tree(corrupt.path()), before, "refusal wrote nothing");

    // Corrupt marker: refused at boot and by migration.
    let marker = clone_node(&node);
    std::fs::write(
        marker.path().join("legacy-cell-migration.json"),
        b"{not json",
    )
    .unwrap();
    failure(
        &mut marker.migrate(&["--apply", ACK]),
        "corrupt legacy-cell-migration.json",
    );
    failure(
        &mut marker.run_command(),
        "corrupt legacy-cell-migration.json",
    );

    // Interrupted right after staging, then rolled back: legacy cell intact.
    let mut staged = clone_node(&node);
    let crashed = staged
        .migrate(&["--apply", ACK])
        .env("PILLAR_LEGACY_MIGRATION_CRASH_AT", "staged")
        .output()
        .unwrap();
    assert!(!crashed.status.success());
    let mut cmd = staged.migrate(&["--rollback", "--identity-key"]);
    cmd.arg(&foreign);
    failure(&mut cmd, "conflicting identity");
    assert!(success(&mut staged.migrate(&["--rollback"])).contains("ROLLED BACK"));
    assert!(!staged.path().join("cell-credentials.json").exists());
    staged.start();
    let path = home.join("legacy.yaml");
    save(&config, &path, &staged.resource_addr());
    assert_resource(home, &path, "legacy-retained", 2592000);
    staged.stop();
    // And a fresh conversion after rollback still succeeds.
    assert!(success(&mut staged.migrate(&["--apply", ACK])).contains("CONVERTED"));
}
