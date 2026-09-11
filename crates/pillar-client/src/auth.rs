//! Authenticating a client to a cell: a challenge/response against the
//! resolved ingest node that unlocks the user's cell key via the compiled
//! custody backends and yields a **WoT-verified session token**, cached to
//! `config.yaml` for a faster reconnect.
//!
//! This is the fourth and final concern of [`crate`] (config → discovery →
//! transport → **auth**). It rides the already-proven WoT/custody authority
//! — it adds NO new authorization model and NO new TLA+ gate:
//!
//! * the **credential → signature** step reuses `pillar_identity`'s custody
//!   backends verbatim ([`pillar_identity::login::SignerBackend`] /
//!   [`pillar_identity::login::sign_with_backend`]) — the client never sees a
//!   private key, it only asks the labeled backend to sign the node's
//!   challenge, exactly as the node-side login handshake does;
//! * the **is this signer authoritative?** step reuses
//!   [`pillar_wot_authority::WotAuthority`] — the node admits the signer only
//!   when it is reachable (and not revoked) from the cell's trust anchor, the
//!   identical predicate a node uses to admit any acting key.
//!
//! ## The handshake
//!
//! ```text
//!   client                                   ingest node
//!     | -- ChallengeRequest{cell,user} ------>  |  mint a fresh random nonce
//!     |                                          |  bound to (cell,user)
//!     | <-- Challenge{nonce} -------------------  |
//!     |  unlock the user's cell key via its      |
//!     |  labeled custody backend and SIGN nonce  |
//!     | -- ChallengeResponse{signer_pub,token} ->|  verify the signature over
//!     |                                          |  the nonce AND that signer
//!     |                                          |  is WoT-authoritative for
//!     |                                          |  the cell; fail-closed
//!     |                                          |  otherwise
//!     | <-- SessionToken{cell,user,expiry,...} --  |
//! ```
//!
//! ## Cached-token fast path, and re-auth on revoke/expiry
//!
//! [`authenticate`] first consults the token cached in `config.yaml`
//! ([`crate::config::ConnectParams::token`]). It is reused ONLY when it still
//! validates against the node's live authority AND has not expired. A revoked
//! or expired cached token triggers a fresh challenge/response — never blind
//! reuse and never an endless retry loop (a single fresh attempt is made; if
//! *that* fails, the error is returned). A freshly-minted token is written
//! back to `config.yaml` via [`crate::config::ClientConfig`] so the next
//! process starts on the fast path.

use std::time::{SystemTime, UNIX_EPOCH};

use pillar_core::NodeId;
use pillar_identity::login::{
    sign_with_backend, verify_backend_signature, CustodyRegistry, SignerBackend,
};
use pillar_wot_authority::WotAuthority;

/// A WoT-verified session token: the artifact a successful authentication
/// yields and that the client caches to `config.yaml`. It binds the token to
/// exactly one `(cell, user, signer)` triple, records the WoT authority
/// revocation watermark it was minted against, and carries an absolute
/// `expiry` (unix seconds). It is opaque to transport — it travels as the
/// `token:` string and re-parses with [`SessionToken::parse`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionToken {
    /// The cell this token authenticates to.
    pub cell: String,
    /// The user within the cell.
    pub user: String,
    /// The signer public key (as its stable id string) whose custody backend
    /// signed the challenge — the WoT-authoritative principal.
    pub signer: String,
    /// Absolute expiry, unix seconds. A token at or past this instant is
    /// expired and must not be reused.
    pub expiry: u64,
}

/// The wire prefix of a serialized [`SessionToken`], so a random string is
/// never mistaken for one.
const TOKEN_PREFIX: &str = "pillar-wot-token-v1";

impl SessionToken {
    /// Serialize to the opaque `token:` string cached in `config.yaml`:
    /// `pillar-wot-token-v1:<cell>:<user>:<signer>:<expiry>`. The fields are
    /// percent-free identifiers (cell/user/signer ids), so a `:`-join
    /// round-trips faithfully via [`Self::parse`].
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!(
            "{TOKEN_PREFIX}:{}:{}:{}:{}",
            self.cell, self.user, self.signer, self.expiry
        )
    }

    /// Parse a token produced by [`Self::to_wire`]. Returns `None` for any
    /// string that is not a well-formed token of this version (a foreign or
    /// truncated/garbage `token:` value is simply "no usable cached token",
    /// never a panic).
    #[must_use]
    pub fn parse(s: &str) -> Option<SessionToken> {
        let mut parts = s.splitn(5, ':');
        if parts.next()? != TOKEN_PREFIX {
            return None;
        }
        let cell = parts.next()?.to_owned();
        let user = parts.next()?.to_owned();
        let signer = parts.next()?.to_owned();
        let expiry: u64 = parts.next()?.parse().ok()?;
        if cell.is_empty() || user.is_empty() || signer.is_empty() {
            return None;
        }
        Some(SessionToken {
            cell,
            user,
            signer,
            expiry,
        })
    }

    /// True when this token is at or past `now` (unix seconds) — expired.
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expiry
    }
}

/// The current wall-clock as unix seconds (saturating at 0 before the epoch).
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Why an authentication attempt failed. Every variant is TERMINAL for the
/// single attempt it describes — [`authenticate`] never loops on any of them
/// (a revoked/expired cached token is retried EXACTLY ONCE as a fresh
/// challenge/response, whose own failure surfaces here unretried).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The labeled custody backend declined or refused to sign the challenge
    /// (locked keyring, absent passkey, or a key/backend-label mismatch).
    CustodyUnavailable(String),
    /// The node rejected the response: the signature did not verify over the
    /// nonce, OR the signer is not WoT-authoritative for the cell (revoked /
    /// unreachable). Fail-closed.
    Rejected(String),
    /// The user/cell in the response did not match what was requested — a
    /// token can only ever authenticate the triple it was minted for.
    Mismatch,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::CustodyUnavailable(m) => write!(f, "custody backend unavailable: {m}"),
            AuthError::Rejected(m) => write!(f, "node rejected authentication: {m}"),
            AuthError::Mismatch => f.write_str("response did not match the requested cell/user"),
        }
    }
}

impl std::error::Error for AuthError {}

/// The node-side authority a challenge/response is verified against: the
/// cell's live [`WotAuthority`] plus a way to recover a signer's real
/// verifying key from the id it presents. This is the exact predicate a node
/// already applies to admit any acting key — the client library models it so
/// the acceptance test can drive the SAME check a real ingest node runs,
/// without re-implementing an authorization model.
pub trait NodeAuthority {
    /// The cell name this authority anchors (the token is bound to it).
    fn cell(&self) -> &str;

    /// The live WoT authority: who is reachable (and not revoked) from the
    /// cell's trust anchor right now.
    fn wot(&self) -> &WotAuthority;

    /// Recover the real ed25519 verifying key for `signer` (the id a client
    /// presents in its response), or `None` if this authority knows no such
    /// signer. Used to check the challenge signature genuinely came from that
    /// key before consulting the WoT.
    fn verifying_key_for(&self, signer: &str) -> Option<pillar_crypto::SigningPublicKey>;

    /// How long a freshly-minted token is valid, in seconds from now.
    fn token_ttl_secs(&self) -> u64;
}

/// Issue a token for a verified `(cell, user, signer)` — the node-side half of
/// the handshake, exposed so the acceptance test's in-process node runs the
/// REAL admission predicate. Verifies, fail-closed, that:
///
/// 1. the `signature_token` genuinely signs `nonce` under the signer's real
///    verifying key ([`verify_backend_signature`]); and
/// 2. the signer is WoT-authoritative for the cell right now
///    ([`WotAuthority::is_authoritative`]) — i.e. reachable and NOT revoked.
///
/// Only then does it mint a [`SessionToken`] expiring `token_ttl_secs` from
/// `now`.
///
/// # Errors
/// [`AuthError::Rejected`] if the signer is unknown, its signature does not
/// verify over the nonce, or it is not (or no longer) WoT-authoritative.
pub fn issue_token(
    authority: &dyn NodeAuthority,
    user: &str,
    signer: &str,
    nonce: &str,
    signature_token: &str,
    now: u64,
) -> Result<SessionToken, AuthError> {
    let public = authority
        .verifying_key_for(signer)
        .ok_or_else(|| AuthError::Rejected(format!("unknown signer {signer}")))?;
    if !verify_backend_signature(&public, nonce, signature_token) {
        return Err(AuthError::Rejected(
            "challenge signature did not verify".to_owned(),
        ));
    }
    if !authority.wot().is_authoritative(&NodeId(signer.to_owned())) {
        return Err(AuthError::Rejected(format!(
            "signer {signer} is not WoT-authoritative for cell {}",
            authority.cell()
        )));
    }
    Ok(SessionToken {
        cell: authority.cell().to_owned(),
        user: user.to_owned(),
        signer: signer.to_owned(),
        expiry: now.saturating_add(authority.token_ttl_secs()),
    })
}

/// Re-validate a cached token against the node's LIVE authority: it is usable
/// only when it (a) is bound to the requested `(cell, user)`, (b) has not
/// expired at `now`, and (c) names a signer that is STILL WoT-authoritative
/// (a revoked signer invalidates every token it minted, even an unexpired
/// one). Any failure means "re-authenticate", never "reuse anyway".
#[must_use]
pub fn cached_token_is_valid(
    authority: &dyn NodeAuthority,
    token: &SessionToken,
    cell: &str,
    user: &str,
    now: u64,
) -> bool {
    token.cell == cell
        && token.cell == authority.cell()
        && token.user == user
        && !token.is_expired(now)
        && authority
            .wot()
            .is_authoritative(&NodeId(token.signer.clone()))
}

/// A resolved credential: the custody registry that labels the user's cell
/// key and the concrete backend that holds it. Together they unlock the key
/// to sign a challenge WITHOUT ever exposing private material (the backend
/// only answers "sign this").
pub struct Credential<'a> {
    /// The per-key custody labels (which backend each key id must use).
    pub registry: &'a CustodyRegistry,
    /// The key id (the user's cell key) being unlocked.
    pub key_id: &'a str,
    /// The concrete labeled backend that signs on the key's behalf.
    pub backend: &'a dyn SignerBackend,
}

impl Credential<'_> {
    /// The signer id this credential presents to the node — the backend's
    /// real verifying key, rendered as its stable id string. This is the id a
    /// node looks up in its WoT authority.
    #[must_use]
    pub fn signer_id(&self) -> String {
        signer_id_of(&self.backend.public_key())
    }

    /// Sign `nonce` by asking the labeled backend to unlock and sign — the
    /// custody-enforced credential→signature step. Never exposes the key.
    ///
    /// # Errors
    /// [`AuthError::CustodyUnavailable`] if the key has no label, the backend
    /// does not match the label, or the backend declines to sign.
    pub fn sign(&self, nonce: &str) -> Result<String, AuthError> {
        sign_with_backend(self.registry, self.key_id, self.backend, nonce)
            .map_err(|e| AuthError::CustodyUnavailable(format!("{e:?}")))
    }
}

/// Render a verifying key as the stable id string used as its `NodeId` in the
/// WoT authority and its `signer` field in a [`SessionToken`]: lowercase hex
/// of the public key bytes. Deterministic and collision-resistant enough to
/// name a key uniquely.
#[must_use]
pub fn signer_id_of(public: &pillar_crypto::SigningPublicKey) -> String {
    let mut s = String::new();
    for b in public.as_bytes() {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Authenticate `user` to `authority`'s cell using `credential`, preferring a
/// still-valid `cached` token and otherwise running a fresh challenge/response
/// via `nonce_source`.
///
/// Flow (the module's cache/re-auth contract):
///
/// 1. If `cached` is `Some` and still valid against the LIVE authority
///    ([`cached_token_is_valid`]) — reuse it, no network signing.
/// 2. Otherwise (absent / expired / revoked cached token) run EXACTLY ONE
///    fresh challenge/response: obtain a nonce, unlock+sign it via the
///    custody backend, and have the node issue a fresh token
///    ([`issue_token`]). No retry loop — a fresh attempt that fails returns
///    its error.
///
/// The returned token is the caller's to cache back to `config.yaml`
/// ([`crate::config::ClientConfig::token`]); [`authenticate`] itself is
/// transport- and storage-agnostic so it stays unit-testable.
///
/// `nonce_source` models the node minting a fresh challenge nonce bound to the
/// request; in production it is the node's `GET /nonce`, in the acceptance
/// test it is the real in-process node.
///
/// # Errors
/// [`AuthError`] when the custody backend cannot sign or the node rejects the
/// fresh response (never on a merely-expired cached token — that transparently
/// re-authenticates).
pub fn authenticate(
    authority: &dyn NodeAuthority,
    user: &str,
    credential: &Credential<'_>,
    cached: Option<&SessionToken>,
    nonce_source: &mut dyn FnMut() -> String,
    now: u64,
) -> Result<SessionToken, AuthError> {
    let cell = authority.cell();

    // Fast path: a cached token that still validates live.
    if let Some(tok) = cached {
        if cached_token_is_valid(authority, tok, cell, user, now) {
            return Ok(tok.clone());
        }
    }

    // Fresh challenge/response — exactly once, no loop.
    let nonce = nonce_source();
    let signature_token = credential.sign(&nonce)?;
    let signer = credential.signer_id();
    let token = issue_token(authority, user, &signer, &nonce, &signature_token, now)?;
    if token.cell != cell || token.user != user {
        return Err(AuthError::Mismatch);
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::SigningPublicKey;
    use pillar_identity::login::{CustodyKind, FileKeyringBackend};
    use std::collections::HashMap;

    /// A minimal in-process node authority for unit tests: a cell name, a WoT
    /// authority, a signer→key table, and a TTL.
    struct TestNode {
        cell: String,
        wot: WotAuthority,
        keys: HashMap<String, SigningPublicKey>,
        ttl: u64,
    }

    impl NodeAuthority for TestNode {
        fn cell(&self) -> &str {
            &self.cell
        }
        fn wot(&self) -> &WotAuthority {
            &self.wot
        }
        fn verifying_key_for(&self, signer: &str) -> Option<SigningPublicKey> {
            self.keys.get(signer).cloned()
        }
        fn token_ttl_secs(&self) -> u64 {
            self.ttl
        }
    }

    /// Build a node whose WoT authority is anchored at `alice`'s signer id and
    /// where `alice`'s file-keyring backend is registered/enrolled.
    fn node_with_alice() -> (TestNode, CustodyRegistry, FileKeyringBackend, String) {
        let backend = FileKeyringBackend::new("alice@my-cell").unlocked();
        let signer = signer_id_of(&backend.public_key());
        let mut registry = CustodyRegistry::new();
        registry.assign("alice@my-cell", CustodyKind::FileKeyring);

        // The cell's trust anchor is alice's own key (a bootstrapped user
        // whose op key is the cold root — the simplest authoritative case).
        let wot = WotAuthority::new(NodeId(signer.clone()), 4);

        let mut keys = HashMap::new();
        keys.insert(signer.clone(), backend.public_key());
        let node = TestNode {
            cell: "my-cell".to_owned(),
            wot,
            keys,
            ttl: 3600,
        };
        (node, registry, backend, signer)
    }

    fn credential<'a>(
        registry: &'a CustodyRegistry,
        backend: &'a FileKeyringBackend,
    ) -> Credential<'a> {
        Credential {
            registry,
            key_id: "alice@my-cell",
            backend,
        }
    }

    #[test]
    fn token_wire_round_trips() {
        let tok = SessionToken {
            cell: "my-cell".to_owned(),
            user: "alice".to_owned(),
            signer: "deadbeef".to_owned(),
            expiry: 1_700_000_000,
        };
        assert_eq!(SessionToken::parse(&tok.to_wire()), Some(tok));
    }

    #[test]
    fn parse_rejects_foreign_or_truncated_tokens() {
        assert_eq!(SessionToken::parse("not-a-token"), None);
        assert_eq!(SessionToken::parse("pillar-wot-token-v1:c:u:s"), None); // no expiry
        assert_eq!(
            SessionToken::parse("pillar-wot-token-v1:c:u:s:not-a-number"),
            None
        );
        assert_eq!(SessionToken::parse("pillar-wot-token-v1::u:s:1"), None); // empty cell
    }

    #[test]
    fn fresh_challenge_response_yields_a_wot_verified_token() {
        let (node, registry, backend, signer) = node_with_alice();
        let cred = credential(&registry, &backend);
        let mut nonce = || "nonce-abc".to_owned();

        let tok = authenticate(&node, "alice", &cred, None, &mut nonce, 1000).expect("auth");
        assert_eq!(tok.cell, "my-cell");
        assert_eq!(tok.user, "alice");
        assert_eq!(tok.signer, signer);
        assert_eq!(tok.expiry, 1000 + 3600);
    }

    #[test]
    fn valid_cached_token_is_reused_without_signing() {
        let (node, registry, backend, signer) = node_with_alice();
        let cred = credential(&registry, &backend);
        let cached = SessionToken {
            cell: "my-cell".to_owned(),
            user: "alice".to_owned(),
            signer,
            expiry: 5000,
        };
        // A nonce source that PANICS proves the fast path never signed.
        let mut nonce = || panic!("must not run a fresh challenge for a valid cached token");
        let tok = authenticate(&node, "alice", &cred, Some(&cached), &mut nonce, 1000)
            .expect("cached reuse");
        assert_eq!(tok, cached);
    }

    #[test]
    fn expired_cached_token_triggers_fresh_reauth_not_reuse() {
        let (node, registry, backend, _signer) = node_with_alice();
        let cred = credential(&registry, &backend);
        let expired = SessionToken {
            cell: "my-cell".to_owned(),
            user: "alice".to_owned(),
            signer: cred.signer_id(),
            expiry: 500,
        };
        let mut called = 0;
        let mut nonce = || {
            called += 1;
            "fresh-nonce".to_owned()
        };
        // now=1000 > expiry=500 -> must re-auth (call the nonce source once).
        let tok =
            authenticate(&node, "alice", &cred, Some(&expired), &mut nonce, 1000).expect("reauth");
        assert_eq!(called, 1, "exactly one fresh challenge, no loop");
        assert_eq!(tok.expiry, 1000 + 3600, "a genuinely fresh token");
        assert!(tok.expiry > expired.expiry);
    }

    #[test]
    fn revoked_signer_invalidates_cached_token_and_reauth_fails_closed() {
        let (mut node, registry, backend, signer) = node_with_alice();
        let cred = credential(&registry, &backend);
        // Revoke alice's key: every token she minted is now invalid, even an
        // unexpired one, and a fresh attempt must fail closed (no endless
        // retry — a single Rejected error).
        node.wot.revoke_key(NodeId(signer.clone()));

        let cached = SessionToken {
            cell: "my-cell".to_owned(),
            user: "alice".to_owned(),
            signer,
            expiry: 9999,
        };
        assert!(
            !cached_token_is_valid(&node, &cached, "my-cell", "alice", 1000),
            "revoked signer's token is not reusable even unexpired"
        );
        let err = authenticate(
            &node,
            "alice",
            &cred,
            Some(&cached),
            &mut || "n".to_owned(),
            1000,
        )
        .expect_err("revoked signer cannot re-auth");
        assert!(matches!(err, AuthError::Rejected(_)));
    }

    #[test]
    fn forged_signature_is_rejected_fail_closed() {
        let (node, _registry, backend, signer) = node_with_alice();
        // A signature token for a DIFFERENT nonce than the node challenged
        // must not verify.
        let good = backend.sign_challenge("some-other-nonce").expect("sign");
        let err = issue_token(&node, "alice", &signer, "the-real-nonce", &good, 1000)
            .expect_err("mismatched nonce rejected");
        assert!(matches!(err, AuthError::Rejected(_)));
    }

    #[test]
    fn locked_custody_backend_cannot_authenticate() {
        // A LOCKED file-keyring declines to sign -> CustodyUnavailable.
        let backend = FileKeyringBackend::new("alice@my-cell"); // not .unlocked()
        let mut registry = CustodyRegistry::new();
        registry.assign("alice@my-cell", CustodyKind::FileKeyring);
        let wot = WotAuthority::new(NodeId(signer_id_of(&backend.public_key())), 4);
        let mut keys = HashMap::new();
        keys.insert(signer_id_of(&backend.public_key()), backend.public_key());
        let node = TestNode {
            cell: "my-cell".to_owned(),
            wot,
            keys,
            ttl: 3600,
        };
        let cred = Credential {
            registry: &registry,
            key_id: "alice@my-cell",
            backend: &backend,
        };
        let err = authenticate(&node, "alice", &cred, None, &mut || "n".to_owned(), 1000)
            .expect_err("locked backend");
        assert!(matches!(err, AuthError::CustodyUnavailable(_)));
    }
}
