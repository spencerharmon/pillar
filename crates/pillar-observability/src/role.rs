//! Signed node-role config: subscribe/serve declarations, verified against
//! the SAME owner-anchored WoT/RBAC decider that gates reads — never a
//! parallel authority path.
//!
//! A node declares which observability signals it will *serve* (materialize
//! and answer queries for) and which it *subscribes* to. Because a rogue node
//! must not be able to assert an authoritative serving role for signals it has
//! no capability over, each role declaration is *signed* by the declaring node
//! and only accepted ([`NodeRoleConfig::accept`]) when that node is currently,
//! freshly authoritative under `pillar_wot_authority` — the exact
//! revoke-before-act fencing every other authoritative action uses.

use std::collections::BTreeMap;

use pillar_core::NodeId;
use pillar_wot_authority::{ActError, FencedActor, WotAuthority};

/// The role a node declares for observability signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeRole {
    /// The node subscribes to (consumes) signals.
    Subscribe,
    /// The node serves (materializes + answers queries for) signals.
    Serve,
    /// The node both subscribes and serves.
    SubscribeAndServe,
}

/// A node's *signed* role declaration.
///
/// The "signature" here is modeled as the declaring node's identity plus a
/// content tag over `(node, role)`; the crate's job is not to re-implement PGP
/// (that is the op-log's wire concern) but to prove the *authority binding*:
/// a declaration is only ever accepted for a node the decider says is
/// authoritative, so the signature's meaning ("this node asserts this role")
/// cannot be forged into an accepted config by a non-authoritative node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedNodeRole {
    node: NodeId,
    role: NodeRole,
    /// A content tag binding `(node, role)` — the stand-in for the detached
    /// signature the node produces over its declaration.
    sig_tag: pillar_streamdb::OpId,
}

impl SignedNodeRole {
    /// Produce a node's signed role declaration.
    #[must_use]
    pub fn sign(node: NodeId, role: NodeRole) -> Self {
        let sig_tag = role_sig_tag(&node, role);
        SignedNodeRole {
            node,
            role,
            sig_tag,
        }
    }

    /// The declaring node.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// The declared role.
    #[must_use]
    pub fn role(&self) -> NodeRole {
        self.role
    }

    /// Whether the declaration's signature tag matches its `(node, role)` —
    /// a tampered role or node is detected here before any authority check.
    #[must_use]
    pub fn signature_is_intact(&self) -> bool {
        self.sig_tag == role_sig_tag(&self.node, self.role)
    }
}

fn role_sig_tag(node: &NodeId, role: NodeRole) -> pillar_streamdb::OpId {
    // A deterministic binding of (node, role) via the SAME real cryptographic
    // content-addressing (SHA2-256 multihash) the streaming store uses, so a
    // mismatched/tampered declaration is rejected structurally before the
    // authority check.
    let mut bytes = node.0.clone().into_bytes();
    bytes.push(b'|');
    bytes.push(match role {
        NodeRole::Subscribe => 1,
        NodeRole::Serve => 2,
        NodeRole::SubscribeAndServe => 3,
    });
    pillar_streamdb::OpId(pillar_streamdb::content_address(&bytes))
}

/// Why a signed role declaration was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoleError {
    /// The declaration's signature does not bind its `(node, role)` — tampered
    /// or forged.
    BadSignature,
    /// The declaring node is not currently authoritative under the decider, or
    /// the accepting view is stale (fail-closed) — the underlying
    /// [`ActError`].
    Authority(ActError),
}

impl From<ActError> for RoleError {
    fn from(e: ActError) -> Self {
        RoleError::Authority(e)
    }
}

/// The accepted node-role configuration: the set of role declarations that
/// passed both the signature check and the authority fence.
#[derive(Clone, Debug, Default)]
pub struct NodeRoleConfig {
    roles: BTreeMap<NodeId, NodeRole>,
}

impl NodeRoleConfig {
    /// A fresh, empty config (no node has declared a role yet).
    #[must_use]
    pub fn new() -> Self {
        NodeRoleConfig::default()
    }

    /// The accepted role for `node`, if it has one.
    #[must_use]
    pub fn role_of(&self, node: &NodeId) -> Option<NodeRole> {
        self.roles.get(node).copied()
    }

    /// Whether `node` is an accepted server of signals.
    #[must_use]
    pub fn serves(&self, node: &NodeId) -> bool {
        matches!(
            self.roles.get(node),
            Some(NodeRole::Serve | NodeRole::SubscribeAndServe)
        )
    }

    /// Whether `node` is an accepted subscriber of signals.
    #[must_use]
    pub fn subscribes(&self, node: &NodeId) -> bool {
        matches!(
            self.roles.get(node),
            Some(NodeRole::Subscribe | NodeRole::SubscribeAndServe)
        )
    }

    /// Accept a signed role declaration, gated by the SAME
    /// `pillar_wot_authority` fence as every read: the declaration is recorded
    /// only when its signature is intact AND the declaring node is currently,
    /// freshly authoritative (via `actor`, whose watermark must be caught up).
    ///
    /// # Errors
    ///
    /// [`RoleError::BadSignature`] if the signature does not bind the
    /// declaration; [`RoleError::Authority`] wrapping [`ActError::StaleView`]
    /// (fail-closed) or [`ActError::NotAuthoritative`].
    pub fn accept(
        &mut self,
        authority: &WotAuthority,
        actor: &FencedActor,
        declaration: &SignedNodeRole,
    ) -> Result<(), RoleError> {
        if !declaration.signature_is_intact() {
            return Err(RoleError::BadSignature);
        }
        // The node may only assert its own authoritative serving role if the
        // decider currently grants it — same revoke-before-act fence as a read.
        actor.act(authority, declaration.node())?;
        self.roles
            .insert(declaration.node().clone(), declaration.role());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> NodeId {
        NodeId(s.to_string())
    }

    /// A signed declaration from a fresh, authoritative node is accepted, and
    /// its role is queryable.
    #[test]
    fn authoritative_node_role_is_accepted() {
        let authority = WotAuthority::new(n("owner"), 3);
        let mut actor = FencedActor::new();
        actor.refresh(&authority);

        let mut config = NodeRoleConfig::new();
        let decl = SignedNodeRole::sign(n("owner"), NodeRole::SubscribeAndServe);
        config.accept(&authority, &actor, &decl).unwrap();

        assert_eq!(
            config.role_of(&n("owner")),
            Some(NodeRole::SubscribeAndServe)
        );
        assert!(config.serves(&n("owner")));
        assert!(config.subscribes(&n("owner")));
    }

    /// A non-authoritative node cannot install a serving role, even with a
    /// well-formed signature — the role config rides the single decider.
    #[test]
    fn non_authoritative_node_role_is_refused() {
        let authority = WotAuthority::new(n("owner"), 3);
        let mut actor = FencedActor::new();
        actor.refresh(&authority);

        let mut config = NodeRoleConfig::new();
        let decl = SignedNodeRole::sign(n("outsider"), NodeRole::Serve);
        let err = config.accept(&authority, &actor, &decl).unwrap_err();
        assert!(matches!(
            err,
            RoleError::Authority(ActError::NotAuthoritative)
        ));
        assert!(!config.serves(&n("outsider")));
    }

    /// A tampered declaration (signature no longer binds its role) is rejected
    /// structurally, before any authority check.
    #[test]
    fn tampered_declaration_is_rejected() {
        let authority = WotAuthority::new(n("owner"), 3);
        let mut actor = FencedActor::new();
        actor.refresh(&authority);

        let mut decl = SignedNodeRole::sign(n("owner"), NodeRole::Subscribe);
        // Forge a stronger role while keeping the old signature tag.
        decl.role = NodeRole::Serve;
        assert!(!decl.signature_is_intact());

        let mut config = NodeRoleConfig::new();
        let err = config.accept(&authority, &actor, &decl).unwrap_err();
        assert_eq!(err, RoleError::BadSignature);
    }

    /// A stale accepting view fails closed: even an authoritative node's role
    /// is refused if the fence's watermark lags the current one.
    #[test]
    fn stale_view_fails_closed_when_accepting_a_role() {
        let mut authority = WotAuthority::new(n("owner"), 3);
        let mut actor = FencedActor::new();
        actor.refresh(&authority);
        authority.revoke_grant(n("stranger")); // bumps watermark; actor not refreshed

        let mut config = NodeRoleConfig::new();
        let decl = SignedNodeRole::sign(n("owner"), NodeRole::Serve);
        let err = config.accept(&authority, &actor, &decl).unwrap_err();
        assert!(matches!(
            err,
            RoleError::Authority(ActError::StaleView { .. })
        ));
    }
}
