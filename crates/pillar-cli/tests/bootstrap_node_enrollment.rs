//! Real-process enrollment, deliberately ungated: run with
//! `cargo test -p pillar-cli --test bootstrap_node_enrollment`.
//! No test-side identity reconstruction, credential installation, or admissions.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use pillar_cli::config_export;
use pillar_manifest::Crd;

const PASSWORD: &str = "enrollment integration test unlock factor";
const HANDLE: &str = "alice";

// Every invocation is isolated from the operator's PILLAR_* overrides and config.
// In particular, apply/get must load the exported file, not env signing keys.
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

fn failure(command: &mut Command, reason: &str) {
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
}

fn http(port: u16, method: &str, path: &str, body: &str) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_secs(2),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut text = String::new();
    stream.read_to_string(&mut text)?;
    let (headers, body) = text.split_once("\r\n\r\n").expect("HTTP response");
    let status = headers
        .split_whitespace()
        .nth(1)
        .expect("HTTP status")
        .parse()
        .expect("numeric HTTP status");
    Ok((status, body.to_owned()))
}

// Same real `node run` harness as cli_config_subkey_credential, with stable
// addresses across restarts and a separate data directory for each daemon.
struct Node {
    dir: tempfile::TempDir,
    child: Option<Child>,
    http_port: u16,
    resource_port: u16,
}

impl Node {
    fn boot() -> Self {
        let http_port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let resource_port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut node = Self {
            dir: tempfile::tempdir().expect("node data directory"),
            child: None,
            http_port,
            resource_port,
        };
        node.start();
        node
    }

    fn start(&mut self) {
        assert!(self.child.is_none());
        self.child = Some(
            cli(self.dir.path())
                .args(["node", "run"])
                .env("PILLAR_DATA_DIR", self.dir.path())
                .env("PILLAR_LISTEN", "/ip4/127.0.0.1/tcp/0")
                .env("PILLAR_WEB_BIND", "127.0.0.1")
                .env("PILLAR_WEB_PORT", self.http_port.to_string())
                .env("PILLAR_HEALTH_BIND", "127.0.0.1")
                .env("PILLAR_HEALTH_PORT", "0")
                .env("PILLAR_RESOURCE_OP_UDP_BIND", self.resource_addr())
                .env("PILLAR_PUBLIC_RESOURCE_OP_ADDR", self.resource_addr())
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
            child.kill().expect("stop test daemon");
            child.wait().expect("reap test daemon");
        }
    }

    fn authority(&self) -> String {
        format!("127.0.0.1:{}", self.http_port)
    }

    fn resource_addr(&self) -> String {
        format!("127.0.0.1:{}", self.resource_port)
    }

    fn bootstrap(&self) {
        success(cli(self.dir.path()).args([
            "bootstrap",
            "cell",
            "enrollment-cell",
            "--user",
            HANDLE,
            "--password",
            PASSWORD,
            "--domain",
            &self.authority(),
        ]));
    }

    fn login(&self) -> String {
        let output = success(cli(self.dir.path()).args([
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
            .find_map(|line| line.strip_prefix("export PILLAR_TOKEN="))
            .filter(|token| !token.is_empty())
            .expect("login exports session token")
            .to_owned()
    }

    fn submit_to(&self, issuer: &Node) -> String {
        let output = success(
            cli(self.dir.path())
                .args([
                    "bootstrap",
                    "node",
                    "--domain",
                    &issuer.authority(),
                    "--data-dir",
                ])
                .arg(self.dir.path()),
        );
        let id = output
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("REQUEST "))
            .expect("submission prints REQUEST <id>");
        id.parse::<u64>().expect("numeric request ID");
        id.to_owned()
    }

    fn complete_from(&self, issuer: &Node, id: &str) -> Command {
        let mut command = cli(self.dir.path());
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
            .arg(self.dir.path());
        command
    }

    fn denied_json(&self, path: &str, body: &str) {
        let (status, response) = http(self.http_port, "POST", path, body).expect("POST JSON");
        assert_eq!(status, 401, "{path}: {response}");
        assert!(response.starts_with("DENIED"), "{response}");
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn manifest(name: &str, window: u64) -> String {
    format!(
        "apiVersion: pillar.dev/v1\nkind: RetentionPolicy\nmetadata:\n  name: {name}\nspec:\n  signalKind: Metric\n  window: {window}\n"
    )
}

fn assert_resource(home: &Path, config: &Path, name: &str, expected: &str) {
    let output =
        success(
            cli(home)
                .env("PILLAR_CONFIG", config)
                .args(["get", "RetentionPolicy", name]),
        );
    assert_eq!(
        Crd::from_documents(&output).expect("get returns CRD YAML"),
        Crd::from_documents(expected).expect("expected CRD"),
        "get must return exactly the applied resource, not just its name"
    );
}

#[test]
fn enrollment_transfers_real_cell_and_signer_admissions_and_survives_both_restarts() {
    let mut issuer = Node::boot();
    let mut joining = Node::boot();
    assert_ne!(issuer.dir.path(), joining.dir.path());
    assert_ne!(issuer.http_port, joining.http_port);
    assert_ne!(issuer.resource_port, joining.resource_port);
    issuer.bootstrap();
    let token = issuer.login();
    // Export BEFORE approval: the sealed portal snapshot must carry this admission.
    let original = config_export::fetch_config(&issuer.authority(), &token).expect("export config");
    assert_eq!(
        original.identity.as_ref().unwrap().addr,
        issuer.resource_addr()
    );
    let client = tempfile::tempdir().unwrap();
    let config = client.path().join("config.yaml");
    config_export::save_0600(&original, &config).unwrap();

    let id = joining.submit_to(&issuer);
    failure(
        cli(client.path())
            .env("PILLAR_TOKEN", "invalid-session")
            .args([
                "bootstrap",
                "request",
                "approve",
                &id,
                "--domain",
                &issuer.authority(),
            ]),
        "401",
    );
    failure(
        &mut joining.complete_from(&issuer, &id),
        "stop the joining daemon",
    );
    assert!(!joining.dir.path().join("enrollment.sealed").exists());
    joining.stop();
    failure(&mut joining.complete_from(&issuer, &id), "DENIED pending");
    assert!(!joining.dir.path().join("enrollment.sealed").exists());

    let approval = success(cli(client.path()).env("PILLAR_TOKEN", &token).args([
        "bootstrap",
        "request",
        "approve",
        &id,
        "--domain",
        &issuer.authority(),
    ]));
    assert_eq!(approval.trim(), format!("APPROVED {id}"));
    issuer.stop();
    issuer.start();
    issuer.denied_json(
        "/bootstrap/request/retrieve",
        &serde_json::json!({"id": id.parse::<u64>().unwrap(), "public_key": [], "signature": []})
            .to_string(),
    );
    success(&mut joining.complete_from(&issuer, &id));
    let installed = joining.dir.path().join("enrollment.sealed");
    assert!(installed.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    joining.start();

    let mut retargeted = original.clone();
    retargeted.identity.as_mut().unwrap().addr = joining.resource_addr();
    config_export::save_0600(&retargeted, &config).unwrap();
    let mut reloaded =
        pillar_client::ClientConfig::parse(&std::fs::read_to_string(&config).unwrap(), &config)
            .unwrap();
    reloaded.identity.as_mut().unwrap().addr = issuer.resource_addr();
    assert!(reloaded == original, "only the endpoint may change");
    let config_bytes = std::fs::read(&config).unwrap();
    // Prevent any accidental issuer fallback from satisfying the resource checks.
    issuer.stop();

    let first = manifest("enrolled-before-restart", 2592000);
    let first_path = client.path().join("first.yaml");
    std::fs::write(&first_path, &first).unwrap();
    let applied = success(
        cli(client.path())
            .env("PILLAR_CONFIG", &config)
            .args(["apply", "-f"])
            .arg(&first_path),
    );
    assert!(
        applied.contains("OK") && applied.contains("PillarUdp"),
        "{applied}"
    );
    assert_resource(client.path(), &config, "enrolled-before-restart", &first);

    // A valid but never-admitted signer with the correct cell seed is still denied.
    let (public, secret) = pillar_crypto::sign::random_signing_keypair().unwrap();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut unknown = retargeted.clone();
    let identity = unknown.identity.as_mut().unwrap();
    identity.signer_public_hex = hex(public.as_bytes());
    identity.signer_secret_hex = hex(secret.as_bytes());
    let unknown_path = client.path().join("unknown.yaml");
    config_export::save_0600(&unknown, &unknown_path).unwrap();
    let forbidden = client.path().join("forbidden.yaml");
    std::fs::write(&forbidden, manifest("unknown-signer", 60)).unwrap();
    failure(
        cli(client.path())
            .env("PILLAR_CONFIG", &unknown_path)
            .args(["apply", "-f"])
            .arg(&forbidden),
        "not authorized",
    );
    // An authorized list proves the rejected write left no resource behind.
    let listed = success(
        cli(client.path())
            .env("PILLAR_CONFIG", &config)
            .args(["get", "RetentionPolicy"]),
    );
    assert!(Crd::from_documents(&listed)
        .unwrap()
        .iter()
        .all(|resource| resource.metadata.name != "unknown-signer"));

    joining.stop();
    joining.start();
    assert_resource(client.path(), &config, "enrolled-before-restart", &first);
    let second = manifest("enrolled-after-restart", 604800);
    let second_path = client.path().join("second.yaml");
    std::fs::write(&second_path, &second).unwrap();
    success(
        cli(client.path())
            .env("PILLAR_CONFIG", &config)
            .args(["apply", "-f"])
            .arg(&second_path),
    );
    assert_resource(client.path(), &config, "enrolled-after-restart", &second);
    assert_eq!(std::fs::read(&config).unwrap(), config_bytes);
}

#[test]
fn arbitrary_forged_json_cannot_submit_a_node_request() {
    let issuer = Node::boot();
    issuer.bootstrap();
    let (status, response) = http(
        issuer.http_port,
        "POST",
        "/bootstrap/request/node",
        r#"{"subject":"invented-peer","approved":true}"#,
    )
    .unwrap();
    assert_eq!(status, 400, "{response}");
    assert!(response.contains("signed-node-request-required"));
    for body in [
        r#"{"public_key":[],"sealing_key":[],"signature":[]}"#,
        r#"{"public_key":[1,2,3],"sealing_key":[4,5,6],"signature":[7,8,9]}"#,
    ] {
        issuer.denied_json("/bootstrap/request/node", body);
    }
    let (status, pending) = http(issuer.http_port, "GET", "/bootstrap/request/list", "").unwrap();
    assert_eq!(status, 200);
    assert!(
        pending.trim().is_empty(),
        "forged requests entered the queue: {pending}"
    );
}

#[test]
fn pending_request_requires_subject_proof_and_cannot_be_installed_before_approval() {
    let issuer = Node::boot();
    let mut joining = Node::boot();
    issuer.bootstrap();
    let id = joining.submit_to(&issuer);
    let numeric_id = id.parse::<u64>().unwrap();
    for body in [
        serde_json::json!({"id": numeric_id}),
        serde_json::json!({"id": numeric_id, "public_key": [], "signature": []}),
        serde_json::json!({"id": numeric_id, "public_key": [1, 2, 3], "signature": [4, 5, 6]}),
    ] {
        issuer.denied_json("/bootstrap/request/retrieve", &body.to_string());
    }
    joining.stop();
    // The CLI's real subject proof reaches the pending gate, unlike forged JSON.
    failure(
        &mut joining.complete_from(&issuer, &id),
        "409 DENIED pending",
    );
    assert!(!joining.dir.path().join("enrollment.sealed").exists());
}
