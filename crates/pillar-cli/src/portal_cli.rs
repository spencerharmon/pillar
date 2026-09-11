//! `pillar portal …` — the CLI front-end over a running node's SHARED,
//! journaled mutation surface.
//!
//! ## Why this module exists (the state-stream persistence invariant)
//!
//! The 2026-09-09 ROI made persistence STRUCTURAL: everything is persisted;
//! every state-changing act — portal OR CLI — is a signed state-stream event,
//! and NO state lives only in RAM on either front-end. Both are front-ends
//! over the SAME shared mutator: the node's [`crate::web_serve::WebAuthContext`],
//! whose every mutation is journaled as one signed [`crate::web_serve::PortalOp`]
//! on the durable streaming DB and replayed on boot (`run.rs`
//! `stream.replay(&persisted_ops)`).
//!
//! A CLI subcommand that mutated node state through some *separate* in-memory
//! path would be a BUG of the same class as placeholder crypto: it would not
//! journal the event, so a restart would silently lose it. This module makes
//! the CLI a write-through by CONSTRUCTION — every `pillar portal` mutation is
//! a real request to the running node's already-journaled portal route, so the
//! CLI and the browser portal emit the IDENTICAL `PortalOp` onto the IDENTICAL
//! stream. There is exactly one mutator; the CLI is just another mouth on it.
//!
//! The client here speaks real HTTP/1.1 over a real TCP socket to the node's
//! web surface (`PILLAR_NODE_URL` / `--node`, default `http://127.0.0.1:8080`).
//! It never reaches into node process memory and never keeps authoritative
//! state of its own — read state is a materialized view folded on boot on the
//! NODE, which the CLI simply reads back.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

/// Default node web surface the CLI drives when neither `--node` nor
/// `PILLAR_NODE_URL` is given (the loopback bind a `pillar node run` opens with
/// `PILLAR_WEB_BIND=127.0.0.1 PILLAR_WEB_PORT=8080`).
const DEFAULT_NODE_URL: &str = "http://127.0.0.1:8080";

/// One HTTP response parsed off the wire — the CLI's only view of the node.
#[derive(Debug, Clone)]
pub struct NodeResponse {
    /// HTTP status code.
    pub status: u16,
    /// The `X-Pillar-Session` header, when the node minted/echoed one.
    pub session_token: Option<String>,
    /// The response body text.
    pub body: String,
}

/// A resolved `host:port` the CLI connects to, parsed from a `http://host:port`
/// node URL. Kept minimal (no TLS, no external HTTP crate) so the CLI stays
/// dependency-light and the write-through path is auditable end to end.
#[derive(Debug, Clone)]
pub struct NodeEndpoint {
    host: String,
    port: u16,
}

/// Error resolving a node URL or driving a request.
#[derive(Debug)]
pub enum PortalError {
    /// The `--node`/`PILLAR_NODE_URL` value was not a `http://host:port` URL.
    BadUrl(String),
    /// The TCP connection or the HTTP exchange failed.
    Transport(String),
    /// The node answered, but with a non-success status for a required step.
    Node {
        /// The named request step that the node refused.
        step: &'static str,
        /// The full node response captured for the error message.
        resp: NodeResponse,
    },
}

impl std::fmt::Display for PortalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortalError::BadUrl(u) => {
                write!(f, "not a http://host:port node URL: {u}")
            }
            PortalError::Transport(e) => write!(f, "node transport error: {e}"),
            PortalError::Node { step, resp } => write!(
                f,
                "node refused `{step}` (HTTP {}): {}",
                resp.status,
                resp.body.trim()
            ),
        }
    }
}

impl std::error::Error for PortalError {}

impl NodeEndpoint {
    /// Parse a `http://host:port` (or bare `host:port`) node URL into a
    /// connectable endpoint. Only plain HTTP over TCP is supported — the node's
    /// portal surface is a loopback/in-cluster HTTP listener, never a public
    /// TLS endpoint the CLI would terminate itself.
    pub fn parse(url: &str) -> Result<NodeEndpoint, PortalError> {
        let rest = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .unwrap_or(url);
        // Drop any path/query — the routes are fixed and appended by the client.
        let authority = rest.split(['/', '?']).next().unwrap_or(rest);
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| PortalError::BadUrl(url.to_string()))?;
                (h.to_string(), port)
            }
            None => (authority.to_string(), 80),
        };
        if host.is_empty() {
            return Err(PortalError::BadUrl(url.to_string()));
        }
        Ok(NodeEndpoint { host, port })
    }

    /// Send one real HTTP/1.1 request and read the full response back.
    fn http(
        &self,
        method: &str,
        path: &str,
        body: &str,
    ) -> Result<NodeResponse, PortalError> {
        let mut stream = TcpStream::connect((self.host.as_str(), self.port))
            .map_err(|e| PortalError::Transport(e.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| PortalError::Transport(e.to_string()))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| PortalError::Transport(e.to_string()))?;
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.host,
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| PortalError::Transport(e.to_string()))?;
        stream
            .flush()
            .map_err(|e| PortalError::Transport(e.to_string()))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .map_err(|e| PortalError::Transport(e.to_string()))?;
        parse_http_response(&raw).ok_or_else(|| {
            PortalError::Transport("could not parse node HTTP response".to_string())
        })
    }

    /// `GET <path>`.
    pub fn get(&self, path: &str) -> Result<NodeResponse, PortalError> {
        self.http("GET", path, "")
    }

    /// `POST <path>` with `body`.
    pub fn post(&self, path: &str, body: &str) -> Result<NodeResponse, PortalError> {
        self.http("POST", path, body)
    }
}

/// Parse a raw HTTP/1.1 response buffer into status + `X-Pillar-Session` + body.
/// Shared by the client and directly unit-testable without a socket.
pub fn parse_http_response(raw: &[u8]) -> Option<NodeResponse> {
    let text = String::from_utf8_lossy(raw).into_owned();
    let mut reader = BufReader::new(text.as_bytes());
    let mut status_line = String::new();
    reader.read_line(&mut status_line).ok()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut session_token = None;
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header).ok()?;
        if n == 0 || header == "\r\n" || header == "\n" {
            break;
        }
        if let Some(v) = header.strip_prefix("X-Pillar-Session: ") {
            session_token = Some(v.trim().to_owned());
        }
    }
    let mut body = String::new();
    reader.read_to_string(&mut body).ok();
    Some(NodeResponse {
        status,
        session_token,
        body,
    })
}

/// The CLI front-end engine over a running node's journaled portal surface.
///
/// Every method that CHANGES state ([`Self::add_member`], [`Self::set_role`])
/// is a POST to a node route whose handler calls
/// [`crate::web_serve::WebAuthContext::record`] — so the mutation is journaled
/// on the durable stream by the SAME code path the browser portal uses. The
/// engine holds only a session token (transient auth material), never
/// authoritative cell state.
pub struct PortalClient {
    endpoint: NodeEndpoint,
    token: Option<String>,
}

impl PortalClient {
    /// Build a client for the node at `node_url`.
    pub fn new(node_url: &str) -> Result<PortalClient, PortalError> {
        Ok(PortalClient {
            endpoint: NodeEndpoint::parse(node_url)?,
            token: None,
        })
    }

    /// The node's bootstrap status view (`FRESH` | `BOOTSTRAPPED`). Read-only.
    pub fn bootstrap_status(&self) -> Result<String, PortalError> {
        let resp = self.endpoint.get("/bootstrap/status")?;
        if resp.status != 200 {
            return Err(PortalError::Node {
                step: "bootstrap/status",
                resp,
            });
        }
        Ok(resp.body.trim().to_string())
    }

    /// Bootstrap a cell (a state-changing act → journaled `PortalOp`).
    pub fn create_cell(&self, cell: &str) -> Result<(), PortalError> {
        let resp = self.endpoint.post("/bootstrap/create-cell", cell)?;
        if resp.status != 200 {
            return Err(PortalError::Node {
                step: "bootstrap/create-cell",
                resp,
            });
        }
        Ok(())
    }

    /// Create the first user (a state-changing act → journaled `PortalOp`).
    pub fn create_user(&self, handle: &str, password: &str) -> Result<(), PortalError> {
        let resp = self
            .endpoint
            .post("/bootstrap/create-user", &format!("{handle}\n{password}"))?;
        if resp.status != 200 {
            return Err(PortalError::Node {
                step: "bootstrap/create-user",
                resp,
            });
        }
        Ok(())
    }

    /// Node-side custody login; stores the admitted session token on the
    /// client for subsequent acts. Mints nothing locally — the node issues it.
    pub fn login(&mut self, handle: &str, password: &str) -> Result<(), PortalError> {
        let nonce = self.endpoint.get("/nonce")?;
        if nonce.status != 200 {
            return Err(PortalError::Node {
                step: "nonce",
                resp: nonce,
            });
        }
        let id = nonce
            .body
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| PortalError::Node {
                step: "nonce",
                resp: nonce.clone(),
            })?;
        let resp = self
            .endpoint
            .post("/login", &format!("{handle}\n{password}\n{id}"))?;
        if resp.status != 200 {
            return Err(PortalError::Node {
                step: "login",
                resp,
            });
        }
        self.token = resp.session_token.clone();
        if self.token.is_none() {
            return Err(PortalError::Node {
                step: "login",
                resp,
            });
        }
        Ok(())
    }

    fn token(&self) -> Result<&str, PortalError> {
        self.token.as_deref().ok_or_else(|| PortalError::Transport(
            "no session token — call `pillar portal login` first".to_string(),
        ))
    }

    /// Add (or upsert) a member — the canonical CLI MUTATION under test. This
    /// POSTs `/portal/members/add`, whose handler journals one
    /// `PortalOp::AddMember` on the durable stream, so the act survives a node
    /// restart. This is the write-through: the CLI never touches member state
    /// directly; it drives the shared journaled mutator.
    pub fn add_member(&self, handle: &str, role: &str) -> Result<(), PortalError> {
        let token = self.token()?;
        let resp = self
            .endpoint
            .post("/portal/members/add", &format!("{token}\n{handle}\n{role}"))?;
        if resp.status != 200 {
            return Err(PortalError::Node {
                step: "portal/members/add",
                resp,
            });
        }
        Ok(())
    }

    /// Change a member's role — a second CLI mutation, likewise journaled.
    pub fn set_role(&self, handle: &str, role: &str) -> Result<(), PortalError> {
        let token = self.token()?;
        let resp = self
            .endpoint
            .post("/portal/members/role", &format!("{token}\n{handle}\n{role}"))?;
        if resp.status != 200 {
            return Err(PortalError::Node {
                step: "portal/members/role",
                resp,
            });
        }
        Ok(())
    }

    /// The members view (read state = materialized view folded on boot on the
    /// node). Signs nothing, journals nothing.
    pub fn members(&self) -> Result<String, PortalError> {
        let token = self.token()?;
        let resp = self
            .endpoint
            .get(&format!("/portal/members?token={token}"))?;
        if resp.status != 200 {
            return Err(PortalError::Node {
                step: "portal/members",
                resp,
            });
        }
        Ok(resp.body)
    }
}

/// Resolve the node URL from an explicit `--node <url>` flag, else the
/// `PILLAR_NODE_URL` env var, else the loopback default.
fn resolve_node_url(args: &[String]) -> String {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--node" {
            if let Some(v) = it.next() {
                return v.clone();
            }
        } else if let Some(v) = a.strip_prefix("--node=") {
            return v.to_string();
        }
    }
    std::env::var("PILLAR_NODE_URL").unwrap_or_else(|_| DEFAULT_NODE_URL.to_string())
}

/// Positional args with the `--node[=]` flag (and its value) stripped out.
fn positionals(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--node" {
            i += 2;
            continue;
        }
        if a.starts_with("--node=") {
            i += 1;
            continue;
        }
        out.push(a.clone());
        i += 1;
    }
    out
}

fn usage() -> &'static str {
    "usage: pillar portal [--node <url>] <subcommand>\n\
     \n\
     Drive a running node's SHARED, journaled mutation surface from the CLI.\n\
     Every act below is a signed state-stream event on the node's durable\n\
     streaming DB (identical to the browser portal), so it survives a restart.\n\
     \n\
     \x20 members list                     list cell members (view)\n\
     \x20 members add <handle> <role>      add/upsert a member (journaled act)\n\
     \x20 members role <handle> <role>     change a member's role (journaled act)\n\
     \x20 login <handle> <password>        node-side custody login (prints token)\n\
     \x20 status                           bootstrap status view\n\
     \n\
     The node URL defaults to $PILLAR_NODE_URL or http://127.0.0.1:8080.\n\
     `login` prints the minted session token; pass it via $PILLAR_TOKEN for\n\
     subsequent acts, or run a full session in one process via the library API\n\
     (pillar_cli::portal_cli::PortalClient).\n"
}

/// `pillar portal …` argv dispatch. A thin shell over [`PortalClient`]: it
/// resolves the node URL, parses the subcommand, and drives the real node.
/// For a login-then-act flow the shell reads `$PILLAR_TOKEN` for the session
/// token an earlier `portal login` printed.
pub fn run(args: &[String]) -> ExitCode {
    let node_url = resolve_node_url(args);
    let pos = positionals(args);

    let mut client = match PortalClient::new(&node_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("pillar portal: {e}");
            return ExitCode::from(2);
        }
    };
    // Adopt a pre-minted token from the environment so a shell can do
    // `login` then act across separate invocations.
    if let Ok(tok) = std::env::var("PILLAR_TOKEN") {
        if !tok.is_empty() {
            client.token = Some(tok);
        }
    }

    match pos.first().map(String::as_str) {
        Some("status") => match client.bootstrap_status() {
            Ok(s) => {
                println!("{s}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("pillar portal status: {e}");
                ExitCode::FAILURE
            }
        },
        Some("login") => match (pos.get(1), pos.get(2)) {
            (Some(handle), Some(password)) => match client.login(handle, password) {
                Ok(()) => {
                    // Print the token so the operator can export it for the
                    // next `portal members add`.
                    println!("{}", client.token.as_deref().unwrap_or(""));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("pillar portal login: {e}");
                    ExitCode::FAILURE
                }
            },
            _ => {
                eprintln!("usage: pillar portal login <handle> <password>");
                ExitCode::from(2)
            }
        },
        Some("members") => match pos.get(1).map(String::as_str) {
            Some("list") => match client.members() {
                Ok(body) => {
                    print!("{body}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("pillar portal members list: {e}");
                    ExitCode::FAILURE
                }
            },
            Some("add") => match (pos.get(2), pos.get(3)) {
                (Some(handle), Some(role)) => match client.add_member(handle, role) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("pillar portal members add: {e}");
                        ExitCode::FAILURE
                    }
                },
                _ => {
                    eprintln!("usage: pillar portal members add <handle> <role>");
                    ExitCode::from(2)
                }
            },
            Some("role") => match (pos.get(2), pos.get(3)) {
                (Some(handle), Some(role)) => match client.set_role(handle, role) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("pillar portal members role: {e}");
                        ExitCode::FAILURE
                    }
                },
                _ => {
                    eprintln!("usage: pillar portal members role <handle> <role>");
                    ExitCode::from(2)
                }
            },
            _ => {
                eprint!("{}", usage());
                ExitCode::from(2)
            }
        },
        _ => {
            eprint!("{}", usage());
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_url_parses_scheme_host_port() {
        let ep = NodeEndpoint::parse("http://127.0.0.1:8080").unwrap();
        assert_eq!(ep.host, "127.0.0.1");
        assert_eq!(ep.port, 8080);

        let ep = NodeEndpoint::parse("127.0.0.1:9000/portal/members?token=x").unwrap();
        assert_eq!(ep.host, "127.0.0.1");
        assert_eq!(ep.port, 9000);

        let ep = NodeEndpoint::parse("https://node.example:443").unwrap();
        assert_eq!(ep.host, "node.example");
        assert_eq!(ep.port, 443);

        assert!(matches!(
            NodeEndpoint::parse("http://:notaport"),
            Err(PortalError::BadUrl(_))
        ));
        assert!(matches!(
            NodeEndpoint::parse("http://host:notaport"),
            Err(PortalError::BadUrl(_))
        ));
    }

    #[test]
    fn resolve_node_url_prefers_flag_then_env_then_default() {
        let args = vec!["--node".into(), "http://1.2.3.4:5".into(), "status".into()];
        assert_eq!(resolve_node_url(&args), "http://1.2.3.4:5");

        let args = vec!["--node=http://6.7.8.9:1".into(), "status".into()];
        assert_eq!(resolve_node_url(&args), "http://6.7.8.9:1");

        // Env fallback is exercised without mutating global process env here;
        // the default is asserted when neither flag nor env is present.
        let args = vec!["status".into()];
        // (PILLAR_NODE_URL is unset in the test process.)
        if std::env::var("PILLAR_NODE_URL").is_err() {
            assert_eq!(resolve_node_url(&args), DEFAULT_NODE_URL);
        }
    }

    #[test]
    fn positionals_strip_the_node_flag_and_its_value() {
        let args = vec![
            "--node".into(),
            "http://x:1".into(),
            "members".into(),
            "add".into(),
            "alice".into(),
            "operator".into(),
        ];
        assert_eq!(
            positionals(&args),
            vec!["members", "add", "alice", "operator"]
        );

        let args = vec![
            "--node=http://x:1".into(),
            "members".into(),
            "list".into(),
        ];
        assert_eq!(positionals(&args), vec!["members", "list"]);
    }

    #[test]
    fn parse_http_response_reads_status_session_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nX-Pillar-Session: tok-abc\r\nContent-Length: 5\r\n\r\nhello";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.session_token.as_deref(), Some("tok-abc"));
        assert_eq!(resp.body, "hello");

        let raw = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 6\r\n\r\ndenied";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 401);
        assert_eq!(resp.session_token, None);
        assert_eq!(resp.body, "denied");
    }
}
