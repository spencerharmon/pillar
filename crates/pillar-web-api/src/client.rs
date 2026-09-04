//! A generated, dependency-light HTTP client SDK for the `pillar` HTTP
//! ingest API — the programmatic-access half of the `stable-http-api-sdk`
//! task (the DTOs in [`crate`] are the wire types; this module is the client
//! that speaks them over the wire).
//!
//! [`SdkClient`] talks the EXACT wire framing the shared DTOs already define
//! (`LoginRequest::to_wire`, `NonceResponse::from_body`, …) — the same
//! framing `pillar-cli::web_serve` implements server-side — over a plain
//! `std::net::TcpStream` (no external HTTP-client dependency; the server
//! itself is hand-rolled the same way, so the SDK stays symmetric with it).
//! It advertises its OWN declared [`crate::API_VERSION`] on every request via
//! [`crate::API_VERSION_HEADER`] and checks every response's advertised
//! version against its own with `pillar_crypto::compat::negotiate_surface` —
//! reusing the EXACT compat-negotiation primitive every other pillar wire
//! surface uses, never a parallel/bespoke version check. A response whose
//! advertised version falls outside the client's compat window is refused
//! cleanly as [`ClientError::IncompatibleVersion`] — never silently
//! mis-parsed or mis-coded.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use pillar_crypto::compat::{negotiate_surface, NegotiationRefused};
use pillar_crypto::version::SurfaceVersion;

use crate::{LoginRequest, LoginResponse, NonceResponse, API_COMPAT_WINDOW, API_VERSION,
    API_VERSION_HEADER, HTTP_API_SURFACE};

/// Every way an [`SdkClient`] call can fail.
#[derive(Debug)]
pub enum ClientError {
    /// The underlying TCP connection/read/write failed.
    Io(std::io::Error),
    /// The response was not well-formed HTTP, or its body did not parse as
    /// the expected DTO — a decode error, distinct from a version refusal.
    Malformed(String),
    /// The server's advertised [`SurfaceVersion`] and this client's declared
    /// version fall outside the negotiated compat window — cleanly REFUSED
    /// per the shared `pillar_crypto::compat` gate, never silently miscoded
    /// into a best-effort parse of a framing the client cannot actually
    /// understand.
    IncompatibleVersion(NegotiationRefused),
    /// The server answered with a non-success HTTP status.
    Http {
        /// The HTTP status code.
        status: u16,
        /// The raw response body.
        body: String,
    },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "i/o error: {e}"),
            ClientError::Malformed(msg) => write!(f, "malformed response: {msg}"),
            ClientError::IncompatibleVersion(e) => write!(f, "{e}"),
            ClientError::Http { status, body } => {
                write!(f, "http error {status}: {body}")
            }
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// A raw, parsed HTTP/1.1 response: status code, lower-cased header map, and
/// body — the minimal shape [`SdkClient`]'s DTO-level calls decode further.
struct RawResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}

/// A generated client for the `pillar` HTTP ingest API surface. Speaks the
/// exact wire framing [`crate`]'s DTOs define over a plain TCP connection,
/// and negotiates the [`crate::HTTP_API_SURFACE`] version on every call.
pub struct SdkClient {
    addr: SocketAddr,
    declared_version: SurfaceVersion,
    timeout: Duration,
}

impl SdkClient {
    /// Build a client targeting `addr`, declaring this crate's current
    /// [`API_VERSION`].
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        SdkClient {
            addr,
            declared_version: API_VERSION,
            timeout: Duration::from_secs(5),
        }
    }

    /// Build a client that declares an EXPLICIT version rather than this
    /// crate's current [`API_VERSION`] — used to exercise (and by a real
    /// caller pinned to an older/newer SDK release, to run) the version
    /// negotiation gate against a server advertising a different version.
    #[must_use]
    pub fn with_declared_version(addr: SocketAddr, declared_version: SurfaceVersion) -> Self {
        SdkClient {
            addr,
            declared_version,
            timeout: Duration::from_secs(5),
        }
    }

    /// The version this client declares on every request.
    #[must_use]
    pub fn declared_version(&self) -> SurfaceVersion {
        self.declared_version
    }

    /// `GET /nonce` — fetch a fresh login challenge.
    ///
    /// # Errors
    /// Returns [`ClientError::IncompatibleVersion`] if the server's
    /// advertised version falls outside this client's compat window,
    /// [`ClientError::Malformed`] if the body does not parse as a
    /// [`NonceResponse`], or [`ClientError::Io`] / [`ClientError::Http`] on a
    /// transport/HTTP failure.
    pub fn get_nonce(&self) -> Result<NonceResponse, ClientError> {
        let resp = self.send("GET", "/nonce", "")?;
        if resp.status != 200 {
            return Err(ClientError::Http {
                status: resp.status,
                body: resp.body,
            });
        }
        self.check_server_version(&resp.headers)?;
        NonceResponse::from_body(&resp.body)
            .ok_or_else(|| ClientError::Malformed(format!("bad /nonce body: {:?}", resp.body)))
    }

    /// `POST /login` — exchange the two human-supplied fields (plus the
    /// nonce id from a prior [`Self::get_nonce`]) for a session.
    ///
    /// # Errors
    /// Same failure modes as [`Self::get_nonce`], plus a non-200 status is
    /// surfaced as [`ClientError::Http`] carrying the server's error body.
    pub fn login(&self, request: &LoginRequest) -> Result<LoginResponse, ClientError> {
        let resp = self.send("POST", "/login", &request.to_wire())?;
        if resp.status != 200 {
            return Err(ClientError::Http {
                status: resp.status,
                body: resp.body,
            });
        }
        self.check_server_version(&resp.headers)?;
        let handle = resp
            .body
            .trim()
            .strip_prefix("OK ")
            .ok_or_else(|| ClientError::Malformed(format!("bad /login body: {:?}", resp.body)))?
            .to_owned();
        Ok(LoginResponse { handle })
    }

    /// Negotiate the server's advertised [`crate::HTTP_API_SURFACE`] version
    /// (from [`API_VERSION_HEADER`]) against this client's
    /// [`Self::declared_version`] under [`API_COMPAT_WINDOW`] — the SAME
    /// shared primitive every other pillar wire surface negotiates through.
    /// A response with no version header is treated as the pre-versioning
    /// default (`v1`), matching the server's own backward-compatible
    /// no-header handling.
    fn check_server_version(&self, headers: &BTreeMap<String, String>) -> Result<(), ClientError> {
        let server_version = match headers.get(&API_VERSION_HEADER.to_lowercase()) {
            Some(raw) => parse_surface_version(raw)
                .ok_or_else(|| ClientError::Malformed(format!("bad {API_VERSION_HEADER}: {raw:?}")))?,
            None => SurfaceVersion(1),
        };
        negotiate_surface(
            HTTP_API_SURFACE,
            self.declared_version,
            server_version,
            API_COMPAT_WINDOW,
        )
        .map_err(ClientError::IncompatibleVersion)
    }

    /// Open a fresh connection, write a minimal HTTP/1.1 request carrying
    /// [`API_VERSION_HEADER`], and parse the response.
    fn send(&self, method: &str, path: &str, body: &str) -> Result<RawResponse, ClientError> {
        let mut stream = TcpStream::connect(self.addr)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        let request = format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: pillar-sdk\r\n\
             {API_VERSION_HEADER}: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            self.declared_version,
            body.len(),
        );
        stream.write_all(request.as_bytes())?;

        let mut raw = String::new();
        stream.read_to_string(&mut raw)?;
        parse_response(&raw)
            .ok_or_else(|| ClientError::Malformed("unparseable HTTP response".to_owned()))
    }
}

/// Parse a `"v<n>"` (or bare `"<n>"`) header value into a [`SurfaceVersion`].
fn parse_surface_version(raw: &str) -> Option<SurfaceVersion> {
    let raw = raw.trim();
    let digits = raw.strip_prefix('v').unwrap_or(raw);
    digits.parse::<u16>().ok().map(SurfaceVersion)
}

/// Parse a raw HTTP/1.1 response into status + headers + body. Minimal by
/// design — this SDK only ever talks to the pillar HTTP ingest API, whose
/// hand-rolled server (`pillar-cli::web_serve`) never sends chunked
/// transfer-encoding, so a `Content-Length`-driven (or connection-close)
/// body read is sufficient.
fn parse_response(raw: &str) -> Option<RawResponse> {
    let (head, body) = raw.split_once("\r\n\r\n")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next()?;
    let status = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_lowercase(), value.trim().to_owned());
        }
    }

    let body = if let Some(len) = headers.get("content-length").and_then(|v| v.parse::<usize>().ok())
    {
        body.get(..len).unwrap_or(body).to_owned()
    } else {
        body.to_owned()
    };

    Some(RawResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;

    /// A minimal, single-connection HTTP/1.1 fixture server that speaks JUST
    /// enough of the real `pillar-cli::web_serve` wire framing (`GET
    /// /nonce`, `POST /login`, the `X-Pillar-Api-Version` response header,
    /// and its request-side compat check) for [`SdkClient`] to be exercised
    /// against a LIVE socket end-to-end — the "generated SDK round-trips a
    /// real request/response against a live pillar-web-api fixture" test.
    /// `pillar-web-api` cannot depend on `pillar-cli` (the dependency runs
    /// the other way), so this fixture is the crate's own minimal stand-in
    /// for that server, built entirely from the DTOs/constants this crate
    /// already publishes.
    fn spawn_fixture(advertised_version: SurfaceVersion) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fixture");
        let addr = listener.local_addr().expect("local_addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let mut raw = Vec::new();
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            raw.extend_from_slice(&buf[..n]);
                            if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                                let text = String::from_utf8_lossy(&raw);
                                let (head, rest) = text.split_once("\r\n\r\n").unwrap();
                                let content_len = head
                                    .lines()
                                    .find_map(|l| {
                                        l.to_lowercase()
                                            .strip_prefix("content-length:")
                                            .and_then(|v| v.trim().parse::<usize>().ok())
                                    })
                                    .unwrap_or(0);
                                if rest.len() >= content_len {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                let text = String::from_utf8_lossy(&raw).into_owned();
                let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
                let mut lines = head.lines();
                let request_line = lines.next().unwrap_or("");
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");

                // Reject a request whose declared version falls outside our
                // own compat window — mirrors the server's real request-side
                // version gate.
                let asserted = lines
                    .clone()
                    .find_map(|l| {
                        l.strip_prefix("X-Pillar-Api-Version: ").or_else(|| {
                            l.to_lowercase()
                                .starts_with("x-pillar-api-version:")
                                .then(|| l.split_once(':').map(|x| x.1.trim()))
                                .flatten()
                        })
                    })
                    .and_then(parse_surface_version);

                let response = if let Some(asserted) = asserted {
                    if negotiate_surface(
                        HTTP_API_SURFACE,
                        asserted,
                        advertised_version,
                        API_COMPAT_WINDOW,
                    )
                    .is_err()
                    {
                        format!(
                            "HTTP/1.1 505 HTTP Version Not Supported\r\n{API_VERSION_HEADER}: {advertised_version}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    } else {
                        route(method, path, body, advertised_version)
                    }
                } else {
                    route(method, path, body, advertised_version)
                };

                let _ = stream.write_all(response.as_bytes());
            }
        });
        addr
    }

    fn route(method: &str, path: &str, body: &str, advertised_version: SurfaceVersion) -> String {
        match (method, path) {
            ("GET", "/nonce") => {
                let nonce = NonceResponse { id: 7, expiry: 1_000_000 };
                let wire = nonce.to_wire();
                format!(
                    "HTTP/1.1 200 OK\r\n{API_VERSION_HEADER}: {advertised_version}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{wire}",
                    wire.len(),
                )
            }
            ("POST", "/login") => {
                let req = LoginRequest::from_body(body);
                let resp = LoginResponse { handle: req.identifier };
                let wire = resp.to_wire();
                format!(
                    "HTTP/1.1 200 OK\r\n{API_VERSION_HEADER}: {advertised_version}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{wire}",
                    wire.len(),
                )
            }
            _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
        }
    }

    #[test]
    fn sdk_round_trips_a_nonce_request_against_a_live_fixture() {
        let addr = spawn_fixture(API_VERSION);
        let client = SdkClient::new(addr);
        let nonce = client.get_nonce().expect("get_nonce");
        assert_eq!(nonce, NonceResponse { id: 7, expiry: 1_000_000 });
    }

    #[test]
    fn sdk_round_trips_a_login_request_against_a_live_fixture() {
        let addr = spawn_fixture(API_VERSION);
        let client = SdkClient::new(addr);
        let req = LoginRequest {
            identifier: "alice".to_owned(),
            password: "hunter2".to_owned(),
            nonce_id: 7,
        };
        let resp = client.login(&req).expect("login");
        assert_eq!(resp, LoginResponse { handle: "alice".to_owned() });
    }

    #[test]
    fn a_version_incompatible_sdk_client_is_refused_not_miscoded() {
        // The fixture advertises a version far outside this client's
        // zero-width compat window. Because the fixture ALSO runs the
        // server-side request gate symmetric to check_server_version (it
        // sees the client's declared version, negotiates it against its
        // own, and refuses first), the outcome here is the server's clean
        // 505 -- never a 200 whose body gets mis-parsed as if the versions
        // had matched. a_version_outside_the_compat_window_is_refused_not_miscoded
        // (in the crate root) pins the client-side half of this same gate
        // directly against the shared pillar_crypto::compat primitive.
        let incompatible_server_version = SurfaceVersion(API_VERSION.0 + 5);
        let addr = spawn_fixture(incompatible_server_version);
        let client = SdkClient::new(addr);
        let err = client.get_nonce().unwrap_err();
        match err {
            ClientError::Http { status, .. } => assert_eq!(status, 505),
            other => panic!("expected Http(505), got {other:?}"),
        }
    }

    #[test]
    fn a_client_declaring_an_incompatible_version_is_refused_by_the_fixture_server() {
        // Symmetric case: the CLIENT asserts a version the server's own
        // request-side gate refuses (mirrors pillar-cli::web_serve's
        // check_request_api_version) — the client surfaces it as a clean
        // Http/IncompatibleVersion outcome, never silently miscoded.
        let addr = spawn_fixture(API_VERSION);
        let bad_version = SurfaceVersion(API_VERSION.0 + 9);
        let client = SdkClient::with_declared_version(addr, bad_version);
        let err = client.get_nonce().unwrap_err();
        match err {
            ClientError::Http { status, .. } => assert_eq!(status, 505),
            other => panic!("expected Http(505), got {other:?}"),
        }
    }

    #[test]
    fn parse_surface_version_accepts_v_prefixed_and_bare_numbers() {
        assert_eq!(parse_surface_version("v1"), Some(SurfaceVersion(1)));
        assert_eq!(parse_surface_version(" v42 "), Some(SurfaceVersion(42)));
        assert_eq!(parse_surface_version("7"), Some(SurfaceVersion(7)));
        assert_eq!(parse_surface_version("not-a-version"), None);
    }
}
