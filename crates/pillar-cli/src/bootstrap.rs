//! `pillar bootstrap …` and `pillar login`: the CLI surface over the shared
//! [`pillar_bootstrap`] library and the node's HTTP bootstrap/login endpoints.
//!
//! Subcommands:
//!
//! - `pillar bootstrap cell <name> --user <handle> [custody/label opts]` —
//!   run the combined single-step cell+user bootstrap (locally by default, or
//!   drive a running node's `--domain` endpoints). Refuses a cell name already
//!   claimed on the network.
//! - `pillar bootstrap node --domain <d> --data-dir <dir> [--identity-key <path>]`
//!   submits a join request signed by the joining node's existing identity.
//! - `pillar bootstrap node complete <id> --domain <d> --data-dir <dir>`
//!   retrieves and installs the approved enrollment while the joining daemon is
//!   stopped; accepts the same optional identity-key path as submission.
//! - `pillar bootstrap user --domain <d> [opts]` — a new user submits a join
//!   request.
//! - `pillar bootstrap request list [--domain <d>]` — list pending requests.
//! - `pillar bootstrap request approve|reject <id> [--domain <d>]` — decide a
//!   request (authenticated via `PILLAR_TOKEN`); a node approval returns the
//!   sealed cell-key CID.
//! - `pillar login --domain <d> --user <id> [--password P]` — obtain a
//!   temporary token and print `export PILLAR_DOMAIN=… PILLAR_TOKEN=…`.
//!
//! The credential/token model these drive is the one proven in
//! `specs/BootstrapRequest.tla` and `specs/LoginToken.tla`. The HTTP transport
//! here is plaintext HTTP/1.1 (std-only, no TLS): point it at the node's
//! HTTP listener directly (in-cluster Service or a port-forward). A public
//! HTTPS ingress terminates TLS in front of that listener.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use pillar_bootstrap::custody::{parse_custody_kind, CUSTODY_KINDS_HELP};
use pillar_bootstrap::name::InMemoryCellNameRegistry;
use pillar_bootstrap::token::{PILLAR_DOMAIN_ENV, PILLAR_TOKEN_ENV};
use pillar_bootstrap::{bootstrap_cell_and_user, CustodyChoice, CustodyKind, TokenStore};
use pillar_core::NodeId;

/// The trust depth a freshly-bootstrapped cell anchors its first user at.
const BOOTSTRAP_TRUST_DEPTH: u8 = 4;

/// A parsed HTTP reply from the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpReply {
    /// The HTTP status code.
    pub status: u16,
    /// The `X-Pillar-Session` bearer, if the reply set one.
    pub session: Option<String>,
    /// The response body (trimmed of a trailing newline for convenience).
    pub body: String,
}

/// Normalize a `--domain` value into a `host:port` authority for a plaintext
/// HTTP connection, stripping any `http://`/`https://` scheme and defaulting
/// the port to the node's web port (8642). Returns the authority and the
/// original host (for `PILLAR_DOMAIN`).
pub(crate) fn authority_of(domain: &str) -> (String, String) {
    let stripped = domain
        .strip_prefix("https://")
        .or_else(|| domain.strip_prefix("http://"))
        .unwrap_or(domain);
    let stripped = stripped.trim_end_matches('/');
    let host = stripped.to_owned();
    if stripped.contains(':') {
        (stripped.to_owned(), host)
    } else {
        (format!("{stripped}:8642"), host)
    }
}

/// Perform one plaintext HTTP/1.1 request against `authority` (`host:port`).
///
/// # Errors
///
/// Any connection / I/O / parse failure, as a human-readable string.
pub(crate) fn http(
    authority: &str,
    method: &str,
    path: &str,
    body: &str,
) -> Result<HttpReply, String> {
    let mut stream =
        TcpStream::connect(authority).map_err(|e| format!("cannot reach {authority}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let host = authority.split(':').next().unwrap_or(authority);
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write failed: {e}"))?;
    stream.flush().ok();

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| format!("read failed: {e}"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("malformed status line: {status_line:?}"))?;

    let mut session = None;
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader
            .read_line(&mut header)
            .map_err(|e| format!("read failed: {e}"))?
            == 0
        {
            break;
        }
        let trimmed = header.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("x-pillar-session") {
                session = Some(value.to_owned());
            } else if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            }
        }
    }
    let mut body_buf = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body_buf)
            .map_err(|e| format!("read body failed: {e}"))?;
    }
    let body = String::from_utf8_lossy(&body_buf)
        .trim_end_matches('\n')
        .to_owned();
    Ok(HttpReply {
        status,
        session,
        body,
    })
}

/// A key=value flag scanner over a plain argv slice, supporting repeated flags
/// (labels) and positional args.
struct Args<'a> {
    positional: Vec<&'a str>,
    flags: Vec<(&'a str, String)>,
}

impl<'a> Args<'a> {
    fn parse(args: &'a [String]) -> Result<Self, String> {
        let mut positional = Vec::new();
        let mut flags = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            if let Some(name) = a.strip_prefix("--") {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| format!("flag --{name} requires a value"))?;
                flags.push((name, value.clone()));
                i += 2;
            } else {
                positional.push(a);
                i += 1;
            }
        }
        Ok(Args { positional, flags })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.flags
            .iter()
            .filter(|(k, _)| *k == name)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

// `strip_prefix` yields a `&str` borrowed from the arg slice; the flag key is
// stored by that borrow, so no allocation is needed for keys.

fn custody_or_default(token: Option<&str>, default: CustodyKind) -> Result<CustodyKind, String> {
    match token {
        None => Ok(default),
        Some(t) => parse_custody_kind(t)
            .ok_or_else(|| format!("unknown custody `{t}` (expected {CUSTODY_KINDS_HELP})")),
    }
}

/// Dispatch `pillar bootstrap <sub> …`.
///
/// # Errors
///
/// A human-readable message for any usage or transport error.
pub fn run(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("cell") => bootstrap_cell(&args[1..]),
        Some("node") => bootstrap_node(&args[1..]),
        Some("user") => bootstrap_user(&args[1..]),
        Some("request") => bootstrap_request(&args[1..]),
        _ => Err(usage().to_owned()),
    }
}

fn usage() -> &'static str {
    "usage:\n\
     \x20 pillar bootstrap cell <name> --user <handle> [--domain D] [--cell-custody K] [--user-custody K] [--cell-label L]... [--user-label L]...\n\
     \x20 pillar bootstrap node --domain <D> --data-dir DIR [--identity-key PATH]\n\
     \x20 pillar bootstrap node complete <id> --domain <D> --data-dir DIR [--identity-key PATH]\n\
     \x20 pillar bootstrap user --domain <D> --user <id> [--user-custody K] [--label L]...\n\
     \x20 pillar bootstrap request list [--domain D]\n\
     \x20 pillar bootstrap request approve <id> [--domain D]\n\
     \x20 pillar bootstrap request reject <id> [--domain D]\n\
     custody K one of: password | passkey | tpm | keyring"
}

/// `pillar bootstrap cell <name> --user <handle>`: the combined single-step
/// cell+user bootstrap. Without `--domain`, runs the sequence locally and
/// prints a summary. With `--domain`, drives the running node's create-cell +
/// create-user endpoints as one operator step.
fn bootstrap_cell(args: &[String]) -> Result<String, String> {
    let parsed = Args::parse(args)?;
    let name = *parsed
        .positional
        .first()
        .ok_or("bootstrap cell requires a <name>")?;
    let user = parsed
        .get("user")
        .ok_or("bootstrap cell requires --user <handle>")?;
    let cell_custody = custody_or_default(parsed.get("cell-custody"), CustodyKind::FileKeyring)?;
    let user_custody = custody_or_default(parsed.get("user-custody"), CustodyKind::Password)?;
    let cell_choice = CustodyChoice::new(cell_custody).with_labels(parsed.all("cell-label"));
    let user_choice = CustodyChoice::new(user_custody).with_labels(parsed.all("user-label"));

    if let Some(domain) = parsed.get("domain") {
        // Drive the running node's two endpoints as one operator step.
        let (authority, _host) = authority_of(domain);
        let created = http(&authority, "POST", "/bootstrap/create-cell", name)?;
        if created.status != 200 {
            return Err(format!(
                "create-cell refused: {} {}",
                created.status, created.body
            ));
        }
        // The node's create-user body is "<handle>\n<password>"; the unlock
        // factor for a non-password custody is still submitted as the factor
        // secret the node escrows. Require --password for the user's factor.
        let password = parsed
            .get("password")
            .ok_or("--domain create-user requires --password <unlock-factor>")?;
        let user_body = format!("{user}\n{password}");
        let made = http(&authority, "POST", "/bootstrap/create-user", &user_body)?;
        if made.status != 200 {
            return Err(format!(
                "create-user refused: {} {}",
                made.status, made.body
            ));
        }
        return Ok(format!(
            "bootstrapped cell `{name}` with first user `{user}` on {domain}\n{}",
            made.body
        ));
    }

    // Local combined genesis. A real node injects a swarm-backed name registry;
    // locally every name is FREE unless a collision is known.
    let registry = InMemoryCellNameRegistry::new();
    let outcome = bootstrap_cell_and_user(
        NodeId::from(name),
        user,
        &cell_choice,
        &user_choice,
        &registry,
        BOOTSTRAP_TRUST_DEPTH,
    )
    .map_err(|e| e.to_string())?;

    Ok(format!(
        "bootstrapped cell `{}` (cell custody: {:?})\n\
         first user `{}` created and signed by the cell key (user custody: {:?})\n\
         granted `{}` to the user; revoked it from the cell key\n\
         one-shot cell_key_can_create_user capability: consumed",
        outcome.cell.0,
        cell_choice.kind(),
        outcome.user_handle,
        user_choice.kind(),
        pillar_bootstrap::ADD_USERS_CAPABILITY,
    ))
}

/// Validate that `--domain` references a reachable pillar node (its
/// `/bootstrap/status` answers), returning its `host:port` authority.
fn require_valid_domain(parsed: &Args<'_>) -> Result<(String, String), String> {
    let domain = parsed
        .get("domain")
        .ok_or("this command requires --domain <D>")?;
    let (authority, host) = authority_of(domain);
    let status = http(&authority, "GET", "/bootstrap/status", "")
        .map_err(|e| format!("domain `{domain}` is not a valid pillar domain: {e}"))?;
    if status.status != 200 {
        return Err(format!(
            "domain `{domain}` is not a valid pillar domain (status {})",
            status.status
        ));
    }
    Ok((authority, host))
}

/// Submit or complete enrollment using the joining daemon's existing identity.
fn bootstrap_node(args: &[String]) -> Result<String, String> {
    use crate::enrollment;
    use std::fs::{self, OpenOptions};
    use std::path::PathBuf;

    let parsed = Args::parse(args)?;
    for (index, (name, value)) in parsed.flags.iter().enumerate() {
        if !matches!(*name, "domain" | "data-dir" | "identity-key") {
            return Err(format!("bootstrap node does not accept --{name}"));
        }
        if value.is_empty() || value.starts_with("--") {
            return Err(format!("flag --{name} requires a nonempty value"));
        }
        if parsed.flags[..index].iter().any(|(key, _)| key == name) {
            return Err(format!("flag --{name} must be specified only once"));
        }
    }
    let request_id = match parsed.positional.as_slice() {
        [] => None,
        ["complete", id] => Some(
            id.parse::<u64>()
                .map_err(|_| "bootstrap node complete requires a numeric request <id>")?,
        ),
        _ => return Err(usage().to_owned()),
    };
    let domain = parsed
        .get("domain")
        .ok_or("bootstrap node requires --domain <D>")?;
    let data_dir = PathBuf::from(
        parsed
            .get("data-dir")
            .ok_or("bootstrap node requires --data-dir DIR")?,
    );
    if domain
        .get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
    {
        return Err("bootstrap node does not support HTTPS: its HTTP helper is plaintext; use an authenticated SSH forward or another trusted transport to the issuer's HTTP listener".into());
    }
    let endpoint = domain.strip_prefix("http://").unwrap_or(domain);
    if endpoint.trim_end_matches('/').is_empty()
        || endpoint.trim_end_matches('/').contains('/')
        || endpoint.chars().any(char::is_whitespace)
    {
        return Err("bootstrap node --domain must be an HTTP host[:port], without a path".into());
    }
    let (authority, _) = authority_of(domain);
    let identity_path = parsed
        .get("identity-key")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join("identity.key"));

    // Keep the same lock as the daemon until installation finishes. Never unlink
    // it: replacing its inode would allow a concurrent daemon to bypass the lock.
    let _enrollment_lock = if request_id.is_some() {
        let path = data_dir.join("enrollment.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| format!("cannot open enrollment lock {}: {e}", path.display()))?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|e| {
            format!(
                "cannot lock {}: {e}; stop the joining daemon before running bootstrap node complete (enrollment cannot hot-replace a running cell)",
                path.display()
            )
        })?;
        Some(file)
    } else {
        None
    };
    let bytes = fs::read(&identity_path).map_err(|e| {
        format!(
            "cannot read existing joining identity {}: {e}; no identity was generated",
            identity_path.display()
        )
    })?;
    let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&bytes)
        .map_err(|e| format!("invalid joining identity {}: {e}", identity_path.display()))?;
    let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
    let local_options = format!(
        "--data-dir {} --identity-key {}",
        quote(&data_dir.to_string_lossy()),
        quote(&identity_path.to_string_lossy())
    );

    if let Some(id) = request_id {
        let body = serde_json::to_string(&enrollment::retrieval(&keypair, id)?)
            .map_err(|e| format!("cannot encode enrollment retrieval: {e}"))?;
        let reply = http(&authority, "POST", "/bootstrap/request/retrieve", &body)?;
        if reply.status != 200 {
            return Err(format!(
                "node enrollment retrieval refused: {} {}",
                reply.status, reply.body
            ));
        }
        let envelope: Vec<u8> = serde_json::from_str(&reply.body)
            .map_err(|e| format!("invalid enrollment envelope response: {e}"))?;
        let bundle = enrollment::unseal_bundle(&keypair, &envelope, id)?;
        enrollment::install(&data_dir, &keypair, &bundle)?;
        Ok(format!(
            "installed node enrollment for request {id}\n\
             Restart the joining daemon with:\n\
             pillar node run {local_options}\n\
             Preserve its previous listener, dial, and other runtime options. The enrollment takes effect only on restart."
        ))
    } else {
        let body = serde_json::to_string(&enrollment::request(&keypair)?)
            .map_err(|e| format!("cannot encode node enrollment request: {e}"))?;
        let reply = http(&authority, "POST", "/bootstrap/request/node", &body)?;
        if reply.status != 200 {
            return Err(format!(
                "node request refused: {} {}",
                reply.status, reply.body
            ));
        }
        let id = reply
            .body
            .strip_prefix("REQUEST ")
            .and_then(|id| id.parse::<u64>().ok())
            .ok_or("malformed node request response: expected REQUEST <id>")?;
        Ok(format!(
            "REQUEST {id}\n\
             An existing member must approve this request. Then stop the joining daemon and run:\n\
             pillar bootstrap node complete {id} --domain {} {local_options}\n\
             Use an authenticated SSH forward or another trusted transport; plaintext HTTP does not authenticate the issuer.",
            quote(domain)
        ))
    }
}

/// `pillar bootstrap user --domain <D> --user <id>`: submit a user join request.
fn bootstrap_user(args: &[String]) -> Result<String, String> {
    let parsed = Args::parse(args)?;
    let (authority, _host) = require_valid_domain(&parsed)?;
    let user = parsed
        .get("user")
        .ok_or("bootstrap user requires --user <id>")?;
    let custody = custody_or_default(parsed.get("user-custody"), CustodyKind::Password)?;

    let mut body = format!("{user}\n{}", custody_token(custody));
    for label in parsed.all("label") {
        body.push_str(&format!("\nlabel={label}"));
    }
    let reply = http(&authority, "POST", "/bootstrap/request/user", &body)?;
    if reply.status != 200 {
        return Err(format!(
            "user request refused: {} {}",
            reply.status, reply.body
        ));
    }
    Ok(format!(
        "submitted user bootstrap request ({}) to {} — an existing member must approve it",
        reply.body,
        parsed.get("domain").unwrap_or("")
    ))
}

/// `pillar bootstrap request list|approve|reject`.
fn bootstrap_request(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("list") => request_list(&args[1..]),
        Some("approve") => request_decide(&args[1..], "approve"),
        Some("reject") => request_decide(&args[1..], "reject"),
        _ => Err(
            "usage: pillar bootstrap request list|approve <id>|reject <id> [--domain D]".to_owned(),
        ),
    }
}

fn domain_from(parsed: &Args<'_>) -> Result<(String, String), String> {
    if let Some(d) = parsed.get("domain") {
        return Ok(authority_of(d));
    }
    let d = std::env::var(PILLAR_DOMAIN_ENV).map_err(|_| {
        format!(
            "no --domain and {PILLAR_DOMAIN_ENV} is unset — run `pillar login` or pass --domain"
        )
    })?;
    Ok(authority_of(&d))
}

fn request_list(args: &[String]) -> Result<String, String> {
    let parsed = Args::parse(args)?;
    let (authority, _host) = domain_from(&parsed)?;
    let reply = http(&authority, "GET", "/bootstrap/request/list", "")?;
    if reply.status != 200 {
        return Err(format!(
            "request list refused: {} {}",
            reply.status, reply.body
        ));
    }
    if reply.body.is_empty() {
        Ok("no pending bootstrap requests".to_owned())
    } else {
        Ok(format!(
            "pending bootstrap requests (id kind subject):\n{}",
            reply.body
        ))
    }
}

fn request_decide(args: &[String], verb: &str) -> Result<String, String> {
    let parsed = Args::parse(args)?;
    let id = *parsed
        .positional
        .first()
        .ok_or_else(|| format!("bootstrap request {verb} requires an <id>"))?;
    let (authority, _host) = domain_from(&parsed)?;
    let token = std::env::var(PILLAR_TOKEN_ENV).map_err(|_| {
        format!("{PILLAR_TOKEN_ENV} is unset — run `pillar login` first to authenticate")
    })?;
    let body = format!("{id}\n{token}");
    let path = format!("/bootstrap/request/{verb}");
    let reply = http(&authority, "POST", &path, &body)?;
    if reply.status != 200 {
        return Err(format!(
            "request {verb} refused: {} {}",
            reply.status, reply.body
        ));
    }
    Ok(reply.body)
}

/// `pillar login --domain <D> --user <id> [--password P]`: obtain a temporary
/// token and print shell `export` lines for `PILLAR_DOMAIN` / `PILLAR_TOKEN`.
///
/// # Errors
///
/// A human-readable message on any usage / auth / transport failure.
pub fn login(args: &[String]) -> Result<String, String> {
    let parsed = Args::parse(args)?;
    let domain = parsed
        .get("domain")
        .map(str::to_owned)
        .or_else(|| std::env::var(PILLAR_DOMAIN_ENV).ok())
        .ok_or("pillar login requires --domain <D>")?;
    let (authority, host) = authority_of(&domain);
    let identifier = parsed
        .get("user")
        .map(str::to_owned)
        .or_else(|| parsed.positional.first().map(|s| (*s).to_owned()))
        .ok_or("pillar login requires --user <identifier>")?;
    let password = read_password(&parsed)?;

    // 1. Fetch a challenge nonce.
    let nonce_reply = http(&authority, "GET", "/nonce", "")?;
    if nonce_reply.status != 200 {
        return Err(format!("could not get a login nonce: {}", nonce_reply.body));
    }
    // Body: "NONCE <id> <expiry>".
    let nonce_id = nonce_reply
        .body
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("malformed nonce reply: {:?}", nonce_reply.body))?;

    // 2. Submit the two fields + nonce id; the node resolves + unlocks
    //    server-side and returns a session bearer in X-Pillar-Session.
    let login_body = format!("{identifier}\n{password}\n{nonce_id}");
    let reply = http(&authority, "POST", "/login", &login_body)?;
    if reply.status != 200 {
        return Err(format!("login failed: {}", reply.body));
    }
    let token = reply
        .session
        .ok_or("login succeeded but the node returned no session token")?;

    let store = TokenStore::new(host, token);
    Ok(store.export_lines())
}

fn read_password(parsed: &Args<'_>) -> Result<String, String> {
    if let Some(p) = parsed.get("password") {
        return Ok(p.to_owned());
    }
    if let Ok(p) = std::env::var("PILLAR_PASSWORD") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    Err("no --password and PILLAR_PASSWORD is unset".to_owned())
}

fn custody_token(kind: CustodyKind) -> &'static str {
    match kind {
        CustodyKind::Password => "password",
        CustodyKind::Passkey => "passkey",
        CustodyKind::Tpm => "tpm",
        CustodyKind::FileKeyring => "keyring",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_defaults_the_port_and_strips_scheme() {
        assert_eq!(
            authority_of("https://pillar.example.com"),
            (
                "pillar.example.com:8642".to_owned(),
                "pillar.example.com".to_owned()
            )
        );
        assert_eq!(
            authority_of("node.local:9000"),
            ("node.local:9000".to_owned(), "node.local:9000".to_owned())
        );
        assert_eq!(
            authority_of("http://10.0.0.4/"),
            ("10.0.0.4:8642".to_owned(), "10.0.0.4".to_owned())
        );
    }

    #[test]
    fn args_parse_positional_flags_and_repeats() {
        let raw: Vec<String> = [
            "spencer-cell",
            "--user",
            "spencer",
            "--label",
            "a",
            "--label",
            "b",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let parsed = Args::parse(&raw).unwrap();
        assert_eq!(parsed.positional, vec!["spencer-cell"]);
        assert_eq!(parsed.get("user"), Some("spencer"));
        assert_eq!(parsed.all("label"), vec!["a".to_owned(), "b".to_owned()]);
    }

    #[test]
    fn a_flag_without_a_value_is_an_error() {
        let raw: Vec<String> = ["--user"].iter().map(|s| s.to_string()).collect();
        assert!(Args::parse(&raw).is_err());
    }

    #[test]
    fn local_bootstrap_cell_runs_the_combined_step_and_reports_each_stage() {
        let raw: Vec<String> = ["spencer-cell", "--user", "spencer", "--cell-custody", "tpm"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = bootstrap_cell(&raw).expect("bootstrap");
        assert!(out.contains("bootstrapped cell `spencer-cell`"));
        assert!(out.contains("first user `spencer`"));
        assert!(out.contains("revoked it from the cell key"));
        assert!(out.contains("consumed"));
    }

    #[test]
    fn bootstrap_cell_requires_a_name_and_user() {
        assert!(bootstrap_cell(&[]).is_err());
        let raw: Vec<String> = ["only-name"].iter().map(|s| s.to_string()).collect();
        assert!(bootstrap_cell(&raw).is_err());
    }

    #[test]
    fn custody_token_round_trips_every_kind() {
        for k in [
            CustodyKind::Password,
            CustodyKind::Passkey,
            CustodyKind::Tpm,
            CustodyKind::FileKeyring,
        ] {
            assert_eq!(parse_custody_kind(custody_token(k)), Some(k));
        }
    }

    #[test]
    fn custody_or_default_rejects_garbage_and_honors_default() {
        assert_eq!(
            custody_or_default(None, CustodyKind::Tpm),
            Ok(CustodyKind::Tpm)
        );
        assert_eq!(
            custody_or_default(Some("passkey"), CustodyKind::Tpm),
            Ok(CustodyKind::Passkey)
        );
        assert!(custody_or_default(Some("nope"), CustodyKind::Tpm).is_err());
    }
}
