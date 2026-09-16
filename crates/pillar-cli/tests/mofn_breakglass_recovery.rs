//! Acceptance test — `um-mofn-breakglass-recovery-impl` (ROI P1 "User
//! management & lifecycle" roadmap A4, impl half).
//!
//! Proves the M-of-N quorum-authorized break-glass recovery of a locked-out
//! user's operational key, model-checked by `specs/BreakGlassRecovery.tla`:
//! no single admin can unilaterally recover a subject — a recovery is OPENED
//! by `ControlOp::Recovery(Start)` (declaring the quorum threshold M) and only
//! FIRES on the Mth DISTINCT currently-authoritative admin's
//! `ControlOp::Recovery(Approve)`, at which point the node rotates + revokes
//! the subject's operational key and mints a CONTAINED one-time recovery
//! credential (the subject holds NO usable authority until it completes
//! onboarding by changing the temp password).
//!
//! Black-box: execs the real compiled `pillar` binary and drives its real
//! HTTP portal surface (`/portal/recovery/start`, `/portal/recovery/approve`),
//! exactly the way the sibling `delegated_signed_user_admin` acceptance test
//! drives `/portal/users/*`. Every recovery act rides the SAME delegated-signed
//! `ControlOp` tier: each approver re-proves its OWN password per co-signature,
//! so a session token alone is never a quorum vote.
//!
//! The REGRESSIONS this proves, each of which would FAIL before this task:
//!   * A SUB-QUORUM approval set never recovers the subject
//!     (`SubThresholdNeverRecovers`): after M-1 distinct approvals the subject
//!     still cannot log in with any temp password.
//!   * The Mth DISTINCT approval fires exactly once, rotating the key and
//!     issuing a fresh contained temp password (`RecoveryRotatesAndRevokes` /
//!     `RecoveryHonorsContainment`): the subject's OLD password no longer
//!     works, and the new temp credential is forced-change (contained).
//!   * A repeated approval by an ALREADY-COUNTED admin does not advance the
//!     quorum (distinct-approver counting): two approvals by the same admin do
//!     not reach M=2.
//!
//! `#[cfg(feature = "acceptance")]`-gated; run via `cargo test -p pillar-cli
//! --test mofn_breakglass_recovery --features acceptance`.

#![cfg(feature = "acceptance")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ADMIN1_HANDLE: &str = "alice@pillar";
const ADMIN1_PASSWORD: &str = "correct horse battery staple 2026 mofn-recovery admin-1";
const ADMIN2_HANDLE: &str = "carol@pillar";
const ADMIN2_PASSWORD: &str = "correct horse battery staple 2026 mofn-recovery admin-2";
const SUBJECT_HANDLE: &str = "bob@pillar";
const SUBJECT_PASSWORD: &str = "bob-original-operational-password-2026";

struct HttpResponse {
    status: u16,
    body: String,
    session_token: Option<String>,
}

fn http(port: u16, method: &str, path: &str, body: &str) -> Option<HttpResponse> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).ok()?;
    stream.flush().ok()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();

    let mut reader = BufReader::new(text.as_bytes());
    let mut status_line = String::new();
    reader.read_line(&mut status_line).ok()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut session_token = None;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        if header == "\r\n" || header.is_empty() {
            break;
        }
        if let Some(value) = header.trim_end().strip_prefix("X-Pillar-Session: ") {
            session_token = Some(value.to_owned());
        }
    }
    let mut resp_body = String::new();
    reader.read_to_string(&mut resp_body).ok();

    Some(HttpResponse {
        status,
        body: resp_body,
        session_token,
    })
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("claim free tcp port")
}

struct Node {
    child: Child,
    http_port: u16,
}

impl Node {
    fn boot(data_dir: &std::path::Path) -> Node {
        let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pillar"));
        let http_port = free_tcp_port();
        let child = Command::new(bin)
            .arg("node")
            .arg("run")
            .env("PILLAR_DATA_DIR", data_dir)
            .env("PILLAR_LISTEN", "/ip4/127.0.0.1/tcp/0")
            .env("PILLAR_WEB_BIND", "127.0.0.1")
            .env("PILLAR_WEB_PORT", http_port.to_string())
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pillar node run");
        let node = Node { child, http_port };
        node.await_ready(Duration::from_secs(20));
        node
    }

    fn await_ready(&self, within: Duration) {
        let deadline = Instant::now() + within;
        loop {
            if let Some(resp) = http(self.http_port, "GET", "/bootstrap/status", "") {
                if resp.status == 200 {
                    return;
                }
            }
            if Instant::now() >= deadline {
                panic!(
                    "pillar node run did not serve /bootstrap/status within {within:?} on port {}",
                    self.http_port
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn post(&self, path: &str, body: &str) -> HttpResponse {
        http(self.http_port, "POST", path, body).expect("POST succeeds")
    }

    fn get(&self, path: &str) -> HttpResponse {
        http(self.http_port, "GET", path, "").expect("GET succeeds")
    }

    fn login(&self, identifier: &str, password: &str) -> Option<String> {
        let nonce_resp = self.get("/nonce");
        if nonce_resp.status != 200 {
            return None;
        }
        let id: u64 = nonce_resp.body.split_whitespace().nth(1)?.parse().ok()?;
        let login_resp = self.post("/login", &format!("{identifier}\n{password}\n{id}"));
        if login_resp.status != 200 {
            return None;
        }
        login_resp.session_token
    }

    fn login_ok(&self, identifier: &str, password: &str) -> String {
        self.login(identifier, password)
            .unwrap_or_else(|| panic!("login must succeed for {identifier}"))
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Invite a fresh user through the delegated-signed admin invite path, with an
/// explicit initial password and force-password-change OFF so the invitee can
/// log in immediately (mirrors the `delegated_signed_user_admin` harness).
fn invite_user(node: &Node, admin_token: &str, admin_password: &str, handle: &str, password: &str) {
    let invite = node.post(
        "/portal/users/invite",
        &format!(
            "{admin_password}\n{admin_token}\n{handle}\n{handle}@example.com\n{password}\nfalse\nfalse"
        ),
    );
    assert_eq!(invite.status, 200, "invite {handle}: {}", invite.body);
}

#[test]
fn a_locked_out_user_is_recovered_only_by_an_m_of_n_admin_quorum_never_a_single_admin() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let node = Node::boot(data_dir.path());

    // Bootstrap the cell + the first admin (alice).
    let create_cell = node.post("/bootstrap/create-cell", "cell-genesis");
    assert_eq!(create_cell.status, 200, "create-cell: {}", create_cell.body);
    let create_user = node.post(
        "/bootstrap/create-user",
        &format!("{ADMIN1_HANDLE}\n{ADMIN1_PASSWORD}"),
    );
    assert_eq!(create_user.status, 200, "create-user: {}", create_user.body);

    let admin1 = node.login_ok(ADMIN1_HANDLE, ADMIN1_PASSWORD);

    // alice invites a second admin (carol) and the subject (bob). Both are
    // WoT-admitted the moment they log in, so both hold `iam:users:write`
    // authority — carol as a distinct quorum member, bob as the locked-out
    // subject whose ORIGINAL operational password we then exercise.
    invite_user(
        &node,
        &admin1,
        ADMIN1_PASSWORD,
        ADMIN2_HANDLE,
        ADMIN2_PASSWORD,
    );
    invite_user(
        &node,
        &admin1,
        ADMIN1_PASSWORD,
        SUBJECT_HANDLE,
        SUBJECT_PASSWORD,
    );

    // The second admin logs in (proves its own password works, and admits it
    // as an authoritative signer for its own delegated approvals). Each admin
    // uses its OWN session token, so the delegated signature (and thus the
    // COUNTED approver) is that admin's own key.
    let admin2 = node.login_ok(ADMIN2_HANDLE, ADMIN2_PASSWORD);
    // The subject can log in with its ORIGINAL password (pre-recovery).
    assert!(
        node.login(SUBJECT_HANDLE, SUBJECT_PASSWORD).is_some(),
        "subject logs in with its original password before recovery"
    );

    // === Open an M=2 recovery for the locked-out subject. ===
    let start = node.post(
        "/portal/recovery/start",
        &format!("{ADMIN1_PASSWORD}\n{admin1}\n{SUBJECT_HANDLE}\n2"),
    );
    assert_eq!(start.status, 200, "recovery start: {}", start.body);
    assert!(
        start.body.contains("RECOVERY-OPEN") && start.body.contains("m=2"),
        "recovery opened with m=2: {}",
        start.body
    );

    // Opening a recovery requires the admin's REAL password: a wrong one is
    // refused by the delegated-signature gate (not merely a session token).
    let bad_start = node.post(
        "/portal/recovery/start",
        &format!("wrong-admin-password\n{admin1}\n{SUBJECT_HANDLE}\n2"),
    );
    assert_eq!(
        bad_start.status, 403,
        "a wrong admin password must be refused: {}",
        bad_start.body
    );
    assert!(
        bad_start.body.contains("delegated-sign"),
        "the refusal names the delegated-signature gate: {}",
        bad_start.body
    );

    // === First approval (alice). Sub-quorum: 1 of 2. ===
    let approve1 = node.post(
        "/portal/recovery/approve",
        &format!("{ADMIN1_PASSWORD}\n{admin1}\n{SUBJECT_HANDLE}"),
    );
    assert_eq!(approve1.status, 200, "approve #1: {}", approve1.body);
    assert!(
        approve1.body.contains("quorum=pending") && approve1.body.contains("approvals=1"),
        "one approval is sub-quorum, not a recovery: {}",
        approve1.body
    );
    assert!(
        !approve1.body.contains("TEMP-PASSWORD"),
        "a sub-quorum approval must NOT mint a recovery credential: {}",
        approve1.body
    );

    // A repeated approval by the SAME admin does not advance the distinct
    // quorum (`Cardinality(approvers)` counts distinct admins, not signatures).
    let approve_dup = node.post(
        "/portal/recovery/approve",
        &format!("{ADMIN1_PASSWORD}\n{admin1}\n{SUBJECT_HANDLE}"),
    );
    assert_eq!(approve_dup.status, 200, "dup approve: {}", approve_dup.body);
    assert!(
        approve_dup.body.contains("approvals=1") && approve_dup.body.contains("quorum=pending"),
        "a repeated approval by an already-counted admin does not reach M=2: {}",
        approve_dup.body
    );

    // SUB-QUORUM never recovers: the subject's ORIGINAL password still works
    // and no recovery has fired.
    assert!(
        node.login(SUBJECT_HANDLE, SUBJECT_PASSWORD).is_some(),
        "sub-quorum must not have rotated the subject's key: original login still valid"
    );

    // === Second DISTINCT approval (carol). Quorum reached: fires recovery. ===
    let approve2 = node.post(
        "/portal/recovery/approve",
        &format!("{ADMIN2_PASSWORD}\n{admin2}\n{SUBJECT_HANDLE}"),
    );
    // carol uses her OWN token + password: the delegated signature is carol's,
    // so carol is the counted approver — a SECOND distinct admin. This is
    // exactly "each approver re-proves its own password".
    assert_eq!(approve2.status, 200, "approve #2: {}", approve2.body);
    assert!(
        approve2.body.contains("RECOVERY-COMPLETE") && approve2.body.contains("approvals=2"),
        "the 2nd distinct approval fires the recovery: {}",
        approve2.body
    );
    let temp = approve2
        .body
        .split_whitespace()
        .skip_while(|t| *t != "TEMP-PASSWORD")
        .nth(1)
        .expect("recovery mints a one-time temp password")
        .to_owned();
    assert!(!temp.is_empty() && temp != SUBJECT_PASSWORD);

    // === The recovery ROTATED + REVOKED the old key. ===
    // The subject's ORIGINAL operational password is DEAD forever.
    assert!(
        node.login(SUBJECT_HANDLE, SUBJECT_PASSWORD).is_none(),
        "recovery must retire the subject's prior operational key: old login refused"
    );

    // The freshly-recovered credential is CONTAINED: the subject is listed as
    // force_password_change=true (no usable operational authority until it
    // completes onboarding), mirroring `RecoveryHonorsContainment`.
    let list = node.get(&format!("/portal/users?token={admin1}"));
    assert_eq!(list.status, 200, "user list: {}", list.body);
    assert!(
        list.body
            .lines()
            .any(|l| l.starts_with(&format!("{SUBJECT_HANDLE} "))
                && l.contains("force_password_change=true")),
        "the recovered credential is contained (forced-change): {}",
        list.body
    );

    // A stray approval AFTER the one-time recovery already fired is refused —
    // the open recovery was consumed exactly once.
    let stray = node.post(
        "/portal/recovery/approve",
        &format!("{ADMIN1_PASSWORD}\n{admin1}\n{SUBJECT_HANDLE}"),
    );
    assert_eq!(
        stray.status, 409,
        "no open recovery remains after it fired: {}",
        stray.body
    );
}
