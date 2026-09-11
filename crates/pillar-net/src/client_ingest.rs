//! Ingest of a single signed [`ResourceOp`] from an authenticated **non-node
//! client peer** into the node's op-sync / anti-entropy merge path.
//!
//! A Pillar client (an application that is not itself a cell node — see
//! `pillar-client`) contributes a mutation to a cell by emitting exactly one
//! signed, cell-sealed [`pillar_wire::PillarMessage`] carrying a
//! [`Body::StreamOp`] whose bytes are a [`pillar_ops::ResourceOp`] payload. It
//! is a peer contributing ONE op to the SAME durable op-sync path nodes already
//! use with each other ([`crate::opsync`]) — it adds no new authority model.
//!
//! The processing node's job is the security boundary: it authenticates the
//! producer (the ed25519 signature over the sealed body proves who signed the
//! op), then authorizes the op under the FULL WoT/RBAC decider
//! ([`pillar_rbac::RbacDecider`]) BEFORE applying it. The resource-plane write
//! capability is ONE ordinary capability decision inside that decider — never a
//! parallel, bypass gate: a validly-signed cell member still cannot exceed its
//! capability, and an authenticated stranger with no reachable trust is refused
//! fail-closed exactly like any other unauthorized subject.
//!
//! Policy is enforced HERE, by the processing node, and is NEVER trusted from
//! the producer: the op payload carries no authority claim the node honours;
//! the only thing the producer proves is authorship (via the signature), and
//! authorship alone confers nothing — the decider is what turns an authenticated
//! signer into an authorized (or refused) writer. This mirrors
//! [`crate::antientropy::apply_sync`], which likewise re-verifies each ingested
//! object rather than trusting the sender's framing.

use pillar_core::NodeId;
use pillar_ops::ResourceOp;
use pillar_rbac::{Capability, Decision, ExplicitGrant, PolicyEvent, RbacDecider, ResourceClass};
use pillar_wire::{Body, PillarMessage};

/// Why a client op was refused before it could reach the durable op set. Every
/// variant is a fail-closed refusal the node returns instead of applying the op
/// — never a panic, always scoped to this one op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientOpReject {
    /// The envelope's authorship signature did not verify — the op was not
    /// (provably) signed by the key it names as `signer`. Authentication fails
    /// FIRST, before any authorization or decode work, so an unauthenticated op
    /// never even reaches the decider.
    BadSignature,
    /// The sealed body did not decode to a [`Body::StreamOp`] — a client op MUST
    /// ride a `StreamOp` body; a `Signal`/`Control` body is not a resource op.
    NotAStreamOp,
    /// The `StreamOp` payload bytes did not decode to a well-formed
    /// [`ResourceOp`] (bad codec version / malformed body).
    MalformedOp(pillar_ops::OpCodecError),
    /// The producer IS authenticated and the op IS well-formed, but the FULL
    /// WoT/RBAC decider refused the signer the write capability for this op's
    /// resource kind. This is the load-bearing policy refusal: a valid signature
    /// is not authority.
    Unauthorized,
}

impl std::fmt::Display for ClientOpReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientOpReject::BadSignature => f.write_str("client op signature did not verify"),
            ClientOpReject::NotAStreamOp => {
                f.write_str("client op body is not a StreamOp (resource-op) body")
            }
            ClientOpReject::MalformedOp(e) => write!(f, "malformed client resource op: {e}"),
            ClientOpReject::Unauthorized => {
                f.write_str("client op signer is not authorized to write this resource kind")
            }
        }
    }
}

impl std::error::Error for ClientOpReject {}

/// The prefix under which a client op's resource-plane write capability is
/// named for the RBAC decider: `resource.write:<kind>`. The processing node
/// derives the requested [`Capability`] purely from the op's OWN
/// [`ResourceOp::kind`] — never from anything the producer asserts — so the
/// decider is asked exactly "may this signer write a `<kind>`?".
pub const RESOURCE_WRITE_CAPABILITY_PREFIX: &str = "resource.write";

/// The RBAC [`Capability`] a client op requires: the write capability for the
/// op's target resource kind. A pure function of the op itself.
#[must_use]
pub fn resource_write_capability(op: &ResourceOp) -> Capability {
    Capability(format!("{RESOURCE_WRITE_CAPABILITY_PREFIX}:{}", op.kind()))
}

/// Derive the RBAC/WoT subject [`NodeId`] for a message's producer: the
/// lowercase-hex encoding of its `signer` public key bytes. This is the SAME
/// signer identity the signature was verified against, so the decider judges the
/// authenticated author — the producer cannot present one identity to the
/// signature check and a different one to the policy check.
#[must_use]
pub fn signer_subject(msg: &PillarMessage) -> NodeId {
    let mut hex = String::with_capacity(msg.signer.as_bytes().len() * 2);
    for b in msg.signer.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    NodeId(hex)
}

/// Authorize a single signed client [`PillarMessage`] carrying a resource op,
/// returning the authenticated, authorized [`ResourceOp`] and its raw streamdb
/// payload bytes on success. This is the pure policy core, factored out so it is
/// unit-testable without a live swarm; [`ingest_client_op`] wraps it with the
/// actual apply into the durable store.
///
/// The decision proceeds in the only safe order:
/// 1. **Authenticate** — [`PillarMessage::verify_signature`]; a bad signature is
///    rejected here, before any decode or authorization work.
/// 2. **Open the body** — the caller has already opened the seal into the
///    plaintext `Body` (only a cell node holds the key); we require a
///    [`Body::StreamOp`] and decode the [`ResourceOp`].
/// 3. **Authorize** — build a [`pillar_rbac::Request`] for the op's
///    `resource.write:<kind>` capability with the signer as subject and run the
///    FULL [`RbacDecider`]. Only a [`Decision::Allow`] yields the op.
///
/// `now_secs` stamps the request for any step-up freshness the decider enforces;
/// pass the node's current wall-clock. `resource_class` lets the caller route
/// the write against a specific [`ResourceClass`] (use [`ResourceClass::All`]
/// when the op is not class-specific).
///
/// # Errors
/// A [`ClientOpReject`] for every refusal — bad signature, wrong body kind,
/// malformed op, or an unauthorized signer. The op is NEVER applied on any
/// error.
pub fn authorize_client_op(
    msg: &PillarMessage,
    body: &Body,
    authority: &pillar_wot_authority::WotAuthority,
    policies: &[PolicyEvent],
    grants: &[ExplicitGrant],
    resource_class: ResourceClass,
    now_secs: u64,
) -> Result<(ResourceOp, Vec<u8>), ClientOpReject> {
    // 1. Authenticate the producer FIRST — authorship is a precondition of even
    //    considering the op. A forged/tampered envelope never reaches policy.
    msg.verify_signature()
        .map_err(|_| ClientOpReject::BadSignature)?;

    // 2. A client resource op MUST ride a StreamOp body.
    let payload = match body {
        Body::StreamOp(bytes) => bytes.clone(),
        _ => return Err(ClientOpReject::NotAStreamOp),
    };
    let op = ResourceOp::decode(&payload).map_err(ClientOpReject::MalformedOp)?;

    // 3. Authorize under the FULL WoT/RBAC decider — the resource-plane write
    //    capability is one ordinary capability decision, never a bypass. The
    //    subject is the AUTHENTICATED signer (same identity the signature was
    //    checked against), and the capability is derived from the op's OWN kind
    //    — nothing the producer asserts is trusted here.
    let request = pillar_rbac::Request::new(signer_subject(msg), resource_write_capability(&op))
        .with_resource_class(resource_class)
        .at_time(now_secs);
    let decider = RbacDecider::new(authority, policies, grants);
    match decider.decide(&request) {
        Decision::Allow => Ok((op, payload)),
        Decision::Deny => Err(ClientOpReject::Unauthorized),
    }
}

/// Ingest one signed client [`PillarMessage`] into the durable `stream`:
/// authenticate + authorize it via [`authorize_client_op`], and ONLY on an
/// `Allow` append its op payload into the node's own op set (idempotent —
/// content-addressed, so re-ingesting an already-held op admits nothing). On any
/// refusal the durable set is left UNCHANGED and the [`ClientOpReject`] is
/// returned — the exact fail-closed behaviour the op-sync merge already
/// documents for a policy-refused op.
///
/// Returns `Ok(true)` if the op was newly admitted, `Ok(false)` if it was
/// authorized but already held (dedup no-op).
///
/// # Errors
/// The [`ClientOpReject`] from [`authorize_client_op`] on any authentication /
/// decode / authorization failure; the store is never mutated on error.
pub fn ingest_client_op<S: pillar_streamdb::OpSyncTarget>(
    stream: &mut S,
    msg: &PillarMessage,
    body: &Body,
    authority: &pillar_wot_authority::WotAuthority,
    policies: &[PolicyEvent],
    grants: &[ExplicitGrant],
    resource_class: ResourceClass,
    now_secs: u64,
) -> Result<bool, ClientOpReject> {
    let (_op, payload) = authorize_client_op(
        msg,
        body,
        authority,
        policies,
        grants,
        resource_class,
        now_secs,
    )?;
    let id = pillar_streamdb::OpId(pillar_streamdb::content_address(&payload));
    if stream.log().contains(&id) {
        return Ok(false);
    }
    stream.append_convergent(payload);
    Ok(true)
}
