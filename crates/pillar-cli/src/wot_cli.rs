//! The Web-of-Trust view + gpg-auditable key-export library, shared verbatim by
//! the `pillar` CLI (`pillar wot …`, `pillar key export …`) and the portal
//! handlers in [`crate::web_serve`] (`/portal/trust-graph`, `/portal/key-export`)
//! so the two surfaces can never diverge on what the graph shows or who may
//! export a key.
//!
//! * **Graph / list views** ([`list_trust`], [`list_signatures`],
//!   [`list_attestations`], [`graph_text`]) are PURE renderings over a
//!   [`TrustStore`]: every live trust edge, the issuer signing public key behind
//!   each edge's signature, and the full attested predicate. They sign and
//!   mutate nothing.
//! * **Export** ([`export_openpgp`]) renders a principal's key as the real,
//!   gpg-importable OpenPGP form from [`pillar_crypto::openpgp`], but ONLY after
//!   the caller has obtained an [`Decision::Allow`] from
//!   [`pillar_rbac::authorize_key_export`] — the single, shared key-export
//!   authorization both surfaces route through. A non-`Allow` decision fails
//!   closed with [`ExportError::NotAuthorized`]; a secret export with no secret
//!   held fails with [`ExportError::NoSecret`]. There is no unauthorized path.

use pillar_crypto::openpgp::{TransferableKey, TrustCertification};
use pillar_crypto::{SealingPublicKey, SigningPublicKey, SigningSecretKey};
use pillar_rbac::Decision;
use pillar_core::NodeId;
use pillar_trust_artifacts::{identity_principal, public_key_for, TrustStore};

/// Lowercase hex of a byte slice (public-key/fingerprint rendering).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The v4 OpenPGP fingerprint of a node's signing identity key, for display on a
/// trust-graph node (`gpg`-style uppercase hex). Uses the shared identity-key
/// derivation ([`public_key_for`]) so a node's rendered key matches the key that
/// actually signs its artifacts.
#[must_use]
pub fn node_key_fingerprint(node: &NodeId) -> String {
    // A stable created-time of 0 for the display fingerprint; the exported key
    // carries the real creation time. Both derive from the same public key.
    TransferableKey {
        uid: node.0.clone(),
        created_secs: 0,
        signing_pub: public_key_for(node),
        signing_sec: None,
        sealing_pub: SealingPublicKey::default(),
        certifications: vec![],
    }
    .fingerprint_hex()
}

/// Render every currently-live trust edge: `TRUST <from> -> <to> LABEL <l> CID <cid>`.
#[must_use]
pub fn list_trust(store: &TrustStore) -> String {
    let mut out = String::new();
    for e in store.graph_edges() {
        out.push_str(&format!(
            "TRUST {} -> {} LABEL {} CID {}\n",
            e.from.0, e.to.0, e.label, e.cid.0
        ));
    }
    if out.is_empty() {
        out.push_str("(no live trust edges)\n");
    }
    out
}

/// Render the signing public key behind each live attest's signature:
/// `SIG CID <cid> ISSUER <id> KEY <hex>`. This is the per-edge signature a
/// viewer cross-references, and the exact issuer key `gpg --check-sigs` shows.
#[must_use]
pub fn list_signatures(store: &TrustStore) -> String {
    let mut out = String::new();
    for cid in store.live_attestation_cids() {
        if let Some(a) = store.attestation(&cid) {
            out.push_str(&format!(
                "SIG CID {} ISSUER {} KEY {}\n",
                cid.0,
                a.issuer.0,
                hex(a.sig.issuer_public().as_bytes())
            ));
        }
    }
    if out.is_empty() {
        out.push_str("(no signatures)\n");
    }
    out
}

/// Render every live attestation as its full signed sentence (via
/// [`TrustStore::describe`]): `ATTEST CID <cid> <sentence>`.
#[must_use]
pub fn list_attestations(store: &TrustStore) -> String {
    let mut out = String::new();
    for cid in store.live_attestation_cids() {
        if let Some(desc) = store.describe(&cid) {
            out.push_str(&format!("ATTEST CID {} {}\n", cid.0, desc));
        }
    }
    if out.is_empty() {
        out.push_str("(no attestations)\n");
    }
    out
}

/// Render the node-link trust graph the portal visualizes and the CLI prints:
/// one `NODE <id> KEY <fpr>` line per distinct participant (carrying its signing
/// public-key fingerprint) followed by one `EDGE <from> -> <to> LABEL <l> SIG
/// <cid>` line per live trust edge. This is a superset of the legacy
/// `EDGE …`-only body — a viewer now sees every public key and the signature on
/// every edge, exactly as the WoT-transparency requirement asks.
#[must_use]
pub fn graph_text(store: &TrustStore) -> String {
    let edges = store.graph_edges();
    // Distinct nodes in first-seen order for stable rendering.
    let mut seen: Vec<NodeId> = Vec::new();
    for e in &edges {
        for n in [&e.from, &e.to] {
            if !seen.iter().any(|s| s == n) {
                seen.push(n.clone());
            }
        }
    }
    let mut out = String::new();
    for n in &seen {
        out.push_str(&format!("NODE {} KEY {}\n", n.0, node_key_fingerprint(n)));
    }
    for e in &edges {
        out.push_str(&format!(
            "EDGE {} -> {} LABEL {} SIG {}\n",
            e.from.0, e.to.0, e.label, e.cid.0
        ));
    }
    out
}

/// A request to render a principal's key as OpenPGP. Built by the caller from
/// resolved key material (custody-unlocked secret for a secret export) plus any
/// trust certifications it can actually sign.
pub struct ExportRequest {
    /// The OpenPGP user id, e.g. `"cell:example <cell@pillar>"`.
    pub uid: String,
    /// Key creation time (unix seconds); stable for a given identity.
    pub created_secs: u32,
    /// The principal's Ed25519 identity public key.
    pub signing_pub: SigningPublicKey,
    /// The principal's Ed25519 identity secret; required for a secret export.
    pub signing_sec: Option<SigningSecretKey>,
    /// The principal's X25519 sealing/encryption public key.
    pub sealing_pub: SealingPublicKey,
    /// Inbound trust certifications to embed (WoT edges the exporter can sign).
    pub certifications: Vec<TrustCertification>,
    /// Whether to render the secret key (`true`) or the public key (`false`).
    pub include_secret: bool,
}

/// Why an export was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// The RBAC key-export decision was not `Allow` (missing capability, no
    /// fresh step-up, or an explicit deny). Fail-closed.
    NotAuthorized,
    /// A secret export was requested but no secret key material was supplied.
    NoSecret,
    /// The OpenPGP serializer rejected the key material.
    Crypto(String),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::NotAuthorized => write!(
                f,
                "key export refused: caller lacks the cell:key-export capability or a fresh step-up"
            ),
            ExportError::NoSecret => write!(f, "secret export requested but no secret key held"),
            ExportError::Crypto(e) => write!(f, "OpenPGP serialization failed: {e}"),
        }
    }
}

impl std::error::Error for ExportError {}

/// Render `req` as armored OpenPGP — but only if `decision` is
/// [`Decision::Allow`]. The caller MUST obtain `decision` from
/// [`pillar_rbac::authorize_key_export`] (the shared gate); passing anything
/// other than `Allow` yields [`ExportError::NotAuthorized`]. This one function
/// is the single export code path for both the CLI and the portal.
pub fn export_openpgp(decision: Decision, req: ExportRequest) -> Result<String, ExportError> {
    if decision != Decision::Allow {
        return Err(ExportError::NotAuthorized);
    }
    if req.include_secret && req.signing_sec.is_none() {
        return Err(ExportError::NoSecret);
    }
    let tk = TransferableKey {
        uid: req.uid,
        created_secs: req.created_secs,
        signing_pub: req.signing_pub,
        signing_sec: req.signing_sec,
        sealing_pub: req.sealing_pub,
        certifications: req.certifications,
    };
    let armored = if req.include_secret {
        tk.export_secret_armored()
    } else {
        tk.export_public_armored()
    };
    armored.map_err(|e| ExportError::Crypto(format!("{e:?}")))
}

/// Export the named principal (a cell or user identity in the WoT) as armored
/// OpenPGP, embedding every inbound trust edge as a real tsig certification so
/// `gpg --check-sigs` shows who has vouched for it. Builds the canonical
/// identity keypair ([`identity_principal`]) — the same key the trust graph
/// displays — and, for `include_secret`, its real Ed25519 secret. Gated by the
/// shared `decision` exactly like [`export_openpgp`].
pub fn export_named_principal(
    decision: Decision,
    store: &TrustStore,
    name: &NodeId,
    uid: &str,
    created_secs: u32,
    include_secret: bool,
) -> Result<String, ExportError> {
    let (pubk, seck) = identity_principal(name);
    // Every currently-live inbound trust edge becomes a tsig certification,
    // signed by the issuer's canonical identity secret.
    let mut certifications = Vec::new();
    for e in store.graph_edges() {
        if &e.to == name {
            let (issuer_pub, issuer_sec) = identity_principal(&e.from);
            certifications.push(TrustCertification {
                issuer_signing_pub: issuer_pub.signing,
                issuer_signing_sec: issuer_sec.signing,
                created_secs,
                trust_level: 1,
                trust_amount: 120,
            });
        }
    }
    let req = ExportRequest {
        uid: uid.to_owned(),
        created_secs,
        signing_pub: pubk.signing,
        signing_sec: if include_secret {
            Some(seck.signing)
        } else {
            None
        },
        sealing_pub: pubk.sealing,
        certifications,
        include_secret,
    };
    export_openpgp(decision, req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::principal::principal_from_seed;
    use pillar_crypto::Seed;
    use pillar_trust_artifacts::{Attest, Capacity, Predicate, Sig as TrustSig, TrustStore};
    fn store_with_edge() -> TrustStore {
        let genesis = NodeId::from("cell:genesis");
        let mut store = TrustStore::new(genesis.clone());
        let attest = Attest {
            issuer: genesis.clone(),
            capacity: Capacity::Role {
                role: "operator".to_owned(),
                scope: "cell".to_owned(),
            },
            authority: None,
            subject: NodeId::from("user:alice"),
            predicate: Predicate::new("login", "portal"),
            scope: "cell".to_owned(),
            epoch: store.epoch(),
            sig: TrustSig::sign_as(genesis.clone(), b""),
        }
        .signed_by_issuer();
        store.issue_attest(attest).expect("attest");
        store
    }

    #[test]
    fn views_render_nodes_keys_signatures_and_attestations() {
        let store = store_with_edge();
        let g = graph_text(&store);
        assert!(g.contains("NODE cell:genesis KEY "), "node + key line: {g}");
        assert!(g.contains("NODE user:alice KEY "));
        assert!(g.contains("EDGE cell:genesis -> user:alice"));
        assert!(g.contains("SIG "), "edge carries its signature cid: {g}");

        assert!(list_trust(&store).contains("TRUST cell:genesis -> user:alice"));
        assert!(list_signatures(&store).contains("ISSUER cell:genesis KEY "));
        assert!(list_attestations(&store).starts_with("ATTEST CID "));
    }

    #[test]
    fn node_fingerprint_is_stable_40_hex() {
        let f = node_key_fingerprint(&NodeId::from("user:alice"));
        assert_eq!(f.len(), 40);
        assert_eq!(f, node_key_fingerprint(&NodeId::from("user:alice")));
    }

    #[test]
    fn export_is_refused_without_allow() {
        let (p, s) = principal_from_seed(&Seed::from_bytes(b"u".to_vec())).unwrap();
        let req = || ExportRequest {
            uid: "user:alice <a@example.com>".to_owned(),
            created_secs: 1_724_800_000,
            signing_pub: p.signing.clone(),
            signing_sec: Some(s.signing.clone()),
            sealing_pub: p.sealing.clone(),
            certifications: vec![],
            include_secret: true,
        };
        assert_eq!(
            export_openpgp(Decision::Deny, req()),
            Err(ExportError::NotAuthorized)
        );
        let out = export_openpgp(Decision::Allow, req()).expect("allowed export");
        assert!(out.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
    }

    #[test]
    fn secret_export_without_secret_fails_closed() {
        let (p, _) = principal_from_seed(&Seed::from_bytes(b"u".to_vec())).unwrap();
        let req = ExportRequest {
            uid: "user:alice".to_owned(),
            created_secs: 1_724_800_000,
            signing_pub: p.signing,
            signing_sec: None,
            sealing_pub: p.sealing,
            certifications: vec![],
            include_secret: true,
        };
        assert_eq!(export_openpgp(Decision::Allow, req), Err(ExportError::NoSecret));
    }

    #[test]
    fn named_principal_export_embeds_inbound_tsig_and_gates_secret() {
        let store = store_with_edge();
        let asc = export_named_principal(
            Decision::Allow,
            &store,
            &NodeId::from("user:alice"),
            "user:alice <a@example.com>",
            1_724_800_000,
            false,
        )
        .expect("export");
        assert!(asc.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert_eq!(
            export_named_principal(
                Decision::Deny,
                &store,
                &NodeId::from("user:alice"),
                "user:alice",
                1_724_800_000,
                true,
            ),
            Err(ExportError::NotAuthorized)
        );
    }
}

// ---------------------------------------------------------------------------
// CLI runners (`pillar wot …`, `pillar key export …`) — talk to a live node's
// portal over the SAME endpoints the browser uses. Thin argv → HTTP shells; the
// real rendering/authorization runs node-side through the functions above.
// ---------------------------------------------------------------------------

/// Minimal `--flag value` / `--flag` argv reader shared by the runners.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().map(String::as_str);
        }
    }
    None
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn domain_token(args: &[String]) -> Result<(String, String), String> {
    let domain = flag(args, "--domain")
        .map(str::to_owned)
        .or_else(|| std::env::var("PILLAR_DOMAIN").ok())
        .ok_or("missing --domain <host[:port]> (or PILLAR_DOMAIN)")?;
    let token = flag(args, "--token")
        .map(str::to_owned)
        .or_else(|| std::env::var("PILLAR_TOKEN").ok())
        .ok_or("missing --token <session> (from `pillar login`)")?;
    let (authority, _host) = crate::bootstrap::authority_of(&domain);
    Ok((authority, token))
}

/// `pillar wot {graph|list-trust|list-signatures|list-attestations}
/// --domain <d> --token <t>`: fetch and print the live web-of-trust view.
pub fn run_wot(args: &[String]) -> Result<String, String> {
    let sub = args.first().map(String::as_str).unwrap_or("graph");
    let view = match sub {
        "graph" => "graph",
        "list-trust" => "trust",
        "list-signatures" => "signatures",
        "list-attestations" => "attestations",
        other => {
            return Err(format!(
                "usage: pillar wot {{graph|list-trust|list-signatures|list-attestations}} \
                 --domain <d> --token <t>  (got `{other}`)"
            ))
        }
    };
    let (authority, token) = domain_token(&args[1..])?;
    let path = format!("/portal/trust-graph?token={token}&view={view}");
    let reply = crate::bootstrap::http(&authority, "GET", &path, "")?;
    if reply.status != 200 {
        return Err(format!("trust-graph view refused: {} {}", reply.status, reply.body));
    }
    Ok(reply.body)
}

/// `pillar key export --principal <id> --domain <d> --token <t> [--secret]`:
/// fetch the principal's gpg-auditable OpenPGP key from the node. `--secret`
/// requests the private key, which the node authorizes through the shared
/// `cell:key-export` capability + a fresh step-up (refused otherwise).
pub fn run_key_export(args: &[String]) -> Result<String, String> {
    let principal = flag(args, "--principal")
        .ok_or("pillar key export requires --principal <cell-or-user-id>")?;
    let secret = has_flag(args, "--secret");
    let (authority, token) = domain_token(args)?;
    let path = format!(
        "/portal/key-export?token={token}&principal={principal}&secret={}",
        if secret { "true" } else { "false" }
    );
    let reply = crate::bootstrap::http(&authority, "GET", &path, "")?;
    if reply.status != 200 {
        return Err(format!("key export refused: {} {}", reply.status, reply.body));
    }
    Ok(reply.body)
}
