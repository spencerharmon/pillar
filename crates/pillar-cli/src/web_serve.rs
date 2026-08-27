//! Serves the web UI from the deployed `pillar node run` process on a
//! configurable, **non-loopback** bind (`--web-bind`/`PILLAR_WEB_BIND`), so a
//! k8s Service can reach it (flux's `pillar-web-ingress-tls` gates on this).
//!
//! `pillar --web` (see `pillar-cli/src/main.rs`) stays localhost-only for the
//! no-identity-yet bootstrap flow; THIS surface is the one that leaves the
//! host, and it never inherits that surface's loopback exemption
//! ([`pillar_web::authorize_nonloopback_signing_action`]): reaching a
//! signing action from off-host REQUIRES an already-admitted WoT-key login
//! session ([`pillar_web::key_login`]) — the ROI's default gate for the
//! exposed surface. Passkey/WebAuthn remains available only as an optional
//! signer feeding the very same decider, never a parallel gate.
//!
//! The line protocol, one command per line, over a single TCP connection:
//!
//! - `NONCE` — issue a fresh challenge nonce bound to this server's origin;
//!   replies `NONCE <id> <expiry>`.
//! - `LOGIN <id> <expiry> <subkey> <sig>` — admit a WoT-key login: the client
//!   locally unlocked its auth subkey and signed the nonce
//!   ([`pillar_web::key_login::AuthSubkey::sign_nonce`]); replies `OK` and
//!   the connection is authenticated for its remaining lifetime, or `DENIED
//!   <reason>`.
//! - `PING` — a stand-in signing action, gated through
//!   [`pillar_web::authorize_nonloopback_signing_action`]; replies `PONG` if
//!   authorized (loopback peer, or a non-loopback peer with an admitted
//!   session), else `REFUSED <reason>`.
//! - `QUIT` — closes the connection.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};

use pillar_core::NodeId;
use pillar_identity::NodeSubkey;
use pillar_web::key_login::{KeyLoginVerifier, LoginSession, Nonce, NonceIssuer, RegisteredAuthKey, Signature};
use pillar_web::{authorize_nonloopback_signing_action, bind_web};
use pillar_wot_authority::{FencedActor, WotAuthority};

/// The server-side state a web-serving process needs to run the WoT-key
/// login handshake: the nonce issuer, the verifier holding registered auth
/// keys, and the shared authority/actor login admission resolves through —
/// the SAME [`pillar_wot_authority`] authority the rest of the platform
/// trusts, never a parallel one.
pub struct WebAuthContext {
    issuer: NonceIssuer,
    verifier: KeyLoginVerifier,
    issued: HashMap<u64, Nonce>,
    authority: WotAuthority,
    actor: FencedActor,
}

impl WebAuthContext {
    /// A fresh context: no auth keys registered, `owner` as the WoT
    /// authority root at `max_depth`.
    #[must_use]
    pub fn new(origin: impl Into<String>, owner: NodeId, max_depth: u8) -> Self {
        let authority = WotAuthority::new(owner, max_depth);
        let mut actor = FencedActor::new();
        actor.refresh(&authority);
        WebAuthContext {
            issuer: NonceIssuer::new(origin.into().as_str()),
            verifier: KeyLoginVerifier::new(),
            issued: HashMap::new(),
            authority,
            actor,
        }
    }

    /// Register the public half of an auth key so a login signed by it can
    /// be admitted.
    pub fn register_auth_key(&mut self, key: RegisteredAuthKey) {
        self.verifier.register_auth_key(key);
    }

    /// Chain `subject` to the authority root at `level`, admitting it as
    /// WoT-authoritative — required before a login for its subkey can admit.
    pub fn admit_subject(&mut self, subject: NodeId, level: u8) {
        let root = self.authority.owner().clone();
        self.authority.issue_edge(root, subject, level);
        self.actor.refresh(&self.authority);
    }

    /// Issue a fresh challenge nonce, tracking it as issued so a later
    /// login can be checked against it.
    pub fn issue_nonce(&mut self, expiry: u64) -> Nonce {
        let nonce = self.issuer.issue(expiry);
        self.issued.insert(nonce.id(), nonce.clone());
        self.verifier.track_issued(nonce.clone());
        nonce
    }

    /// This server's own origin.
    #[must_use]
    pub fn origin(&self) -> &pillar_web::key_login::Origin {
        self.issuer.origin()
    }

    /// Admit a login given the wire-transmitted `(id, expiry, subkey, sig)`.
    ///
    /// # Errors
    ///
    /// The matching [`pillar_web::key_login::LoginError`] for the first
    /// failing precondition — an unknown/expired/replayed/wrong-origin
    /// nonce, an unregistered auth key, a bad signature, or a subkey that
    /// fails the fail-closed WoT authority guard.
    pub fn admit_login(
        &mut self,
        id: u64,
        expiry: u64,
        subkey: &NodeSubkey,
        sig: &Signature,
        clock: u64,
    ) -> Result<LoginSession, pillar_web::key_login::LoginError> {
        let Some(nonce) = self.issued.get(&id).cloned() else {
            return Err(pillar_web::key_login::LoginError::UnknownNonce);
        };
        if nonce.expiry() != expiry {
            return Err(pillar_web::key_login::LoginError::UnknownNonce);
        }
        let origin = self.issuer.origin().clone();
        self.verifier
            .admit(&nonce, sig, subkey, &origin, clock, &self.authority, &self.actor)
    }
}

/// Bind the web UI listener on `addr:port` — `addr` MAY be non-loopback (see
/// module docs); the caller must still gate every signing action through
/// [`WebAuthContext`] / [`authorize_nonloopback_signing_action`].
///
/// # Errors
///
/// Propagates [`std::io::Error`] if the address/port cannot be bound.
pub fn bind(addr: IpAddr, port: u16) -> std::io::Result<TcpListener> {
    bind_web(addr, port)
}

/// Serve the line protocol on `listener` until it errors or the process is
/// torn down. Blocking — run on a dedicated thread.
pub fn serve(listener: TcpListener, ctx: &mut WebAuthContext) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        handle_connection(stream, ctx);
    }
}

fn handle_connection(mut stream: TcpStream, ctx: &mut WebAuthContext) {
    let Ok(peer) = stream.peer_addr() else { return };
    let mut session: Option<LoginSession> = None;
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let reply = handle_line(ctx, &mut session, &peer, &line);
        let done = reply.done;
        let _ = writeln!(stream, "{}", reply.text);
        if done {
            return;
        }
    }
}

/// One line-protocol reply: the text to write back, and whether the
/// connection should close after it (`QUIT`).
struct Reply {
    text: String,
    done: bool,
}

fn reply(text: impl Into<String>) -> Reply {
    Reply {
        text: text.into(),
        done: false,
    }
}

/// The pure per-line protocol handler, independent of any real socket, so
/// the auth-gate decision (in particular: a non-loopback `peer` with no
/// admitted session is ALWAYS refused, real network plumbing notwithstanding)
/// is exercised directly by unit tests rather than relying on a real TCP
/// connection's observed peer address (which is loopback whenever the test
/// client and server share a host, regardless of the bind address).
fn handle_line(ctx: &mut WebAuthContext, session: &mut Option<LoginSession>, peer: &SocketAddr, line: &str) -> Reply {
    let mut parts = line.split_whitespace();
    match parts.next() {
        Some("NONCE") => {
            let nonce = ctx.issue_nonce(u64::MAX);
            reply(format!("NONCE {} {}", nonce.id(), nonce.expiry()))
        }
        Some("LOGIN") => {
            let (Some(id), Some(expiry), Some(subkey), Some(sig)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return reply("usage: LOGIN <id> <expiry> <subkey> <sig>");
            };
            let (Ok(id), Ok(expiry), Ok(sig)) = (id.parse::<u64>(), expiry.parse::<u64>(), sig.parse::<u64>()) else {
                return reply("DENIED bad-arguments");
            };
            let subkey = NodeSubkey::from(subkey);
            let signature = Signature::from_wire(sig);
            match ctx.admit_login(id, expiry, &subkey, &signature, 0) {
                Ok(s) => {
                    *session = Some(s);
                    reply("OK")
                }
                Err(e) => reply(format!("DENIED {e:?}")),
            }
        }
        Some("PING") => match authorize_nonloopback_signing_action(peer, session.as_ref()) {
            Ok(()) => reply("PONG"),
            Err(e) => reply(format!("REFUSED {e:?}")),
        },
        Some("QUIT") => Reply {
            text: "BYE".to_owned(),
            done: true,
        },
        _ => reply("unknown command; use NONCE, LOGIN, PING, or QUIT"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const PASSWORD: &str = "correct horse battery staple";
    const SECRET: &str = "plaintext-auth-subkey-secret";

    fn remote_peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 4242)
    }

    fn fresh_ctx_with_subkey() -> (WebAuthContext, NodeSubkey) {
        let subkey = NodeSubkey::from("auth-subkey-node-run");
        let mut ctx = WebAuthContext::new("https://pillar.example.com", NodeId::from("owner"), 4);
        ctx.admit_subject(subkey.node_id(), 4);

        let encrypted = pillar_web::key_login::EncryptedAuthSubkey::seal(subkey.clone(), PASSWORD, SECRET);
        ctx.register_auth_key(pillar_web::key_login::RegisteredAuthKey::register(
            &encrypted, PASSWORD, SECRET,
        ));
        (ctx, subkey)
    }

    #[test]
    fn node_run_web_surface_binds_a_non_loopback_address() {
        let listener = bind(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0).expect("bind non-loopback");
        let addr = listener.local_addr().expect("local_addr");
        assert!(
            !addr.ip().is_loopback(),
            "node-run web surface must bind a non-loopback address"
        );
    }

    // Exercises the auth-gate decision directly against a synthetic
    // non-loopback peer address — a real TCP loopback connection between a
    // test client and server on the same host always reports 127.0.0.1 as
    // the peer regardless of the bind address, so it cannot exercise the
    // "reachable off-host" branch of the gate at all; this is the only way
    // to actually prove the non-loopback refusal.
    #[test]
    fn unauthenticated_signing_action_against_a_nonloopback_peer_is_refused() {
        let (mut ctx, _subkey) = fresh_ctx_with_subkey();
        let mut session: Option<LoginSession> = None;
        let reply = handle_line(&mut ctx, &mut session, &remote_peer(), "PING");
        assert!(
            reply.text.starts_with("REFUSED"),
            "expected an unauthenticated non-loopback PING to be refused, got: {}",
            reply.text
        );
    }

    #[test]
    fn wot_key_login_then_signing_action_from_a_nonloopback_peer_is_admitted() {
        let (mut ctx, subkey) = fresh_ctx_with_subkey();
        let mut session: Option<LoginSession> = None;
        let peer = remote_peer();

        let nonce_reply = handle_line(&mut ctx, &mut session, &peer, "NONCE");
        let mut parts = nonce_reply.text.split_whitespace();
        assert_eq!(parts.next(), Some("NONCE"));
        let id: u64 = parts.next().expect("id").parse().expect("id parses");
        let expiry: u64 = parts.next().expect("expiry").parse().expect("expiry parses");

        // Client side: unlock the auth subkey and sign the nonce locally —
        // the password/plaintext key never cross the wire.
        let encrypted = pillar_web::key_login::EncryptedAuthSubkey::seal(subkey.clone(), PASSWORD, SECRET);
        let unlocked = pillar_web::key_login::unlock_auth_subkey(&encrypted, PASSWORD, SECRET).expect("unlock");
        let signing_nonce = test_nonce(id, "https://pillar.example.com", expiry);
        let sig = unlocked.sign_nonce(&signing_nonce);

        let login_line = format!("LOGIN {id} {expiry} {} {}", subkey.0, sig.to_wire());
        let login_reply = handle_line(&mut ctx, &mut session, &peer, &login_line);
        assert_eq!(login_reply.text, "OK", "login reply: {}", login_reply.text);
        assert!(session.is_some(), "an admitted login must populate the connection session");

        let ping_reply = handle_line(&mut ctx, &mut session, &peer, "PING");
        assert_eq!(
            ping_reply.text, "PONG",
            "expected an authenticated non-loopback PING to be admitted, got: {}",
            ping_reply.text
        );
    }

    // Test-only: reconstruct a `Nonce` with a chosen id for signing, mirroring
    // exactly what `NonceIssuer::issue` produces server-side (verified by
    // `pillar_web::key_login`'s own tests) — used here only because
    // `Nonce`'s fields are crate-private by design.
    fn test_nonce(id: u64, origin: &str, expiry: u64) -> pillar_web::key_login::Nonce {
        // Drive a fresh issuer to the target serial by discarding earlier ids.
        let mut issuer = pillar_web::key_login::NonceIssuer::new(origin);
        let mut nonce = issuer.issue(expiry);
        while nonce.id() != id {
            nonce = issuer.issue(expiry);
        }
        nonce
    }
}
