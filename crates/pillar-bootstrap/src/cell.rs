//! The one-shot `cell_key_can_create_user` bootstrap capability and the
//! **combined single-step** cell+user bootstrap.
//!
//! The bug this module fixes: the web UI used to create the cell in one screen
//! and the first user in another. An operator who created the cell, then hit
//! **back**, could land in a state where the first user could no longer be
//! created. [`bootstrap_cell_and_user`] makes the whole sequence one atomic
//! operation — cell key genesis → sign the user key → grant the user the
//! add-users right → revoke the cell's add-users right — so there is no
//! intermediate screen to abandon. The CLI (`pillar bootstrap cell`) and the
//! web portal call the exact same function.

use pillar_core::NodeId;
use pillar_identity::UserPrimary;
use pillar_rbac::{Capability, ExplicitGrant, GrantEffect};
use pillar_wot_authority::WotAuthority;

use crate::custody::{CustodyChoice, CustodyKind, CustodyRegistry};
use crate::name::{check_cell_name_available, CellNameRegistry};
use crate::BootstrapError;

/// The capability name that authorizes creating/adding users. The combined
/// bootstrap step GRANTS this to the first user and DENIES it to the cell key,
/// making "the cell can no longer add users; the admin user now can" concrete
/// in the RBAC layer (in addition to the one-shot [`CellBootstrap`] flag).
pub const ADD_USERS_CAPABILITY: &str = "identity/add-users";

/// The one-shot `cell_key_can_create_user` bootstrap capability
/// (`identity-node-custody-spec`): on a fresh cell the cell key MAY create the
/// first user; that authority is a self-disabling flag that defaults `true`
/// and auto-flips `false` once the first user is created, atomically linking
/// cell↔initial-user. Afterward, user administration must route through the
/// admin user key, never the coarser cell key — and a second cell-key
/// create-user is refused. Re-enable is ONLY a deliberate cold-root/cell-policy
/// action, never automatic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellBootstrap {
    cell: Option<NodeId>,
    can_create_user: bool,
    initial_user: Option<String>,
}

impl Default for CellBootstrap {
    fn default() -> Self {
        CellBootstrap::new()
    }
}

impl CellBootstrap {
    /// A fresh, unbootstrapped node: no cell, capability primed `true`.
    #[must_use]
    pub fn new() -> Self {
        CellBootstrap {
            cell: None,
            can_create_user: true,
            initial_user: None,
        }
    }

    /// Whether this node has been bootstrapped (its cell exists).
    #[must_use]
    pub fn is_bootstrapped(&self) -> bool {
        self.cell.is_some()
    }

    /// Whether the one-shot cell-key create-user capability is still primed.
    #[must_use]
    pub fn can_create_user(&self) -> bool {
        self.can_create_user
    }

    /// The initial user linked to this cell, once created.
    #[must_use]
    pub fn initial_user(&self) -> Option<&str> {
        self.initial_user.as_deref()
    }

    /// The cell, once created.
    #[must_use]
    pub fn cell(&self) -> Option<&NodeId> {
        self.cell.as_ref()
    }

    /// Step (a): create the cell (cell key genesis + custody choice). The
    /// capability stays primed until the first user is created.
    ///
    /// # Errors
    ///
    /// [`BootstrapError::CellAlreadyExists`] if the cell already exists.
    pub fn create_cell(&mut self, cell: NodeId) -> Result<(), BootstrapError> {
        if self.cell.is_some() {
            return Err(BootstrapError::CellAlreadyExists);
        }
        self.cell = Some(cell);
        Ok(())
    }

    /// Step (a) with the network NAME-UNIQUENESS pre-check: query the network
    /// for the proposed cell name FIRST (via [`check_cell_name_available`]),
    /// and REFUSE — before the cell key is generated — if a peer already
    /// serves a cell-name pointer for it.
    ///
    /// # Errors
    ///
    /// [`BootstrapError::CellNameInUse`] if the network already claims the
    /// name; [`BootstrapError::CellAlreadyExists`] if the cell already exists.
    pub fn create_cell_checked(
        &mut self,
        cell: NodeId,
        registry: &(impl CellNameRegistry + ?Sized),
    ) -> Result<(), BootstrapError> {
        check_cell_name_available(registry, &cell)?;
        self.create_cell(cell)
    }

    /// Step (b): create the first user in the same guided step, CONSUMING the
    /// one-shot capability — it atomically links cell↔initial-user and
    /// auto-flips the flag `false`. A second cell-key create-user is then
    /// refused ([`BootstrapError::CapabilitySpent`]).
    ///
    /// # Errors
    ///
    /// [`BootstrapError::NoCellYet`] if the cell has not been created;
    /// [`BootstrapError::CapabilitySpent`] if the first user already exists.
    pub fn create_first_user(&mut self, handle: impl Into<String>) -> Result<(), BootstrapError> {
        if self.cell.is_none() {
            return Err(BootstrapError::NoCellYet);
        }
        if !self.can_create_user || self.initial_user.is_some() {
            return Err(BootstrapError::CapabilitySpent);
        }
        self.initial_user = Some(handle.into());
        self.can_create_user = false; // one-shot: self-disables.
        Ok(())
    }

    /// The ONLY way the capability returns to `true`: a deliberate
    /// cold-root/cell-policy action (never automatic).
    pub fn deliberate_re_enable(&mut self) {
        self.can_create_user = true;
    }
}

/// The result of a successful [`bootstrap_cell_and_user`]: the material and
/// authority state the sequence produced, ready for a caller to persist /
/// render / seal into offers.
#[derive(Clone, Debug)]
pub struct CellBootstrapOutcome {
    /// The cell key identity (its genesis name).
    pub cell: NodeId,
    /// The generated first-user primary key.
    pub user_primary: UserPrimary,
    /// The first user's human handle.
    pub user_handle: String,
    /// The first user's identity as a WoT node (its primary key, reachable
    /// from the cell anchor).
    pub user_node: NodeId,
    /// The WoT authority anchored at the cell, with the cell→user trust edge
    /// installed ("the cell key signed the user key").
    pub authority: WotAuthority,
    /// The explicit RBAC grants the sequence installed: the user is ALLOWed
    /// `identity/add-users` and the cell is DENYied it (revoked). Both are
    /// returned so the caller can seed the platform's grant set.
    pub grants: Vec<ExplicitGrant>,
    /// The one-shot capability tracker, with the first user consumed.
    pub capability: CellBootstrap,
    /// The per-key custody registry: which real [`SignerBackend`](crate::custody::SignerBackend)
    /// the cell key and the user key are each LABELED to — populated by the
    /// SAME custody choices the caller passed in, so a key's custody label
    /// is a hard requirement enforced at sign time, never cosmetic.
    pub custody: CustodyRegistry,
    /// The cell key's custody backend kind, as actually assigned.
    pub cell_custody: CustodyKind,
    /// The user key's custody backend kind, as actually assigned.
    pub user_custody: CustodyKind,
    /// The genesis proof-of-possession signature the cell key's REAL
    /// custody backend produced (cold-root certifying the user key) — proof
    /// this bootstrap actually invoked the labeled backend, not merely
    /// carried its name.
    pub cell_genesis_signature: String,
    /// The genesis proof-of-possession signature the user key's REAL custody
    /// backend produced.
    pub user_genesis_signature: String,
}

impl CellBootstrapOutcome {
    /// The user's ALLOW grant for `identity/add-users` (the admin right the
    /// cell handed off).
    #[must_use]
    pub fn user_add_users_grant(&self) -> &ExplicitGrant {
        &self.grants[0]
    }

    /// The cell's DENY grant for `identity/add-users` (its right, revoked).
    #[must_use]
    pub fn cell_add_users_deny(&self) -> &ExplicitGrant {
        &self.grants[1]
    }
}

/// The combined **single-step** cell+user bootstrap. Runs the whole sequence
/// the operator described as one atomic operation:
///
/// 1. **Name uniqueness** — refuse if a peer already serves the cell name
///    ([`BootstrapError::CellNameInUse`]), BEFORE any key is generated.
/// 2. **Cell key genesis** — create the cell ([`CellBootstrap::create_cell`]).
/// 3. **Keygen + sign the user key** — anchor a [`WotAuthority`] at the cell
///    and install a cell→user trust edge (the cell key signs the user key),
///    so the first user is trust-reachable from the cell.
/// 4. **Grant the user the add-users right** — an ALLOW
///    [`ExplicitGrant`] of [`ADD_USERS_CAPABILITY`] for the user.
/// 5. **Revoke the cell's add-users right** — consume the one-shot capability
///    ([`CellBootstrap::create_first_user`]) AND install a DENY
///    [`ExplicitGrant`] of [`ADD_USERS_CAPABILITY`] for the cell.
///
/// Because it is one call, there is no intermediate state an operator can
/// abandon (the "created the cell, hit back, could not create the user" bug).
///
/// # Errors
///
/// [`BootstrapError::CellNameInUse`] if the network already claims `cell`.
/// (Later steps are infallible on the fresh [`CellBootstrap`] this constructs,
/// but their `Result`s are still honored — a future invariant change surfaces
/// here rather than being unwrapped away.)
pub fn bootstrap_cell_and_user(
    cell: NodeId,
    user_handle: &str,
    cell_custody: &CustodyChoice,
    user_custody: &CustodyChoice,
    registry: &(impl CellNameRegistry + ?Sized),
    trust_depth: u8,
) -> Result<CellBootstrapOutcome, BootstrapError> {
    // 1 + 2: name check, then cell key genesis — atomic on a fresh tracker.
    let mut capability = CellBootstrap::new();
    capability.create_cell_checked(cell.clone(), registry)?;

    // 3: keygen the user primary and sign it under the cell (a cell→user WoT
    // edge at full trust depth: the cell is the anchor/root).
    let mut keygen = crate::keygen::Bootstrap::new();
    let user_primary = keygen.keygen_user();
    let user_node = NodeId::from(user_primary.0.as_str());
    let mut authority = WotAuthority::new(cell.clone(), trust_depth);
    authority.issue_edge(cell.clone(), user_node.clone(), trust_depth);

    // Per-key custody: label each key to its OWN chosen backend and prove
    // possession with a real genesis signature through it — the cell key and
    // the user key may (and here typically do) use DIFFERENT backends, never
    // funneled through one.
    let mut custody = CustodyRegistry::new();
    let cell_key_id = cell.0.clone();
    let user_key_id = user_node.0.clone();
    let cell_genesis_signature = cell_custody
        .label_and_sign(&mut custody, &cell_key_id, "genesis-certify-user")
        .map_err(|_| BootstrapError::CustodyBackendDeclined)?;
    let user_genesis_signature = user_custody
        .label_and_sign(&mut custody, &user_key_id, "genesis-accept-certification")
        .map_err(|_| BootstrapError::CustodyBackendDeclined)?;

    // 4: grant the user the add-users right.
    let cap = Capability::from(ADD_USERS_CAPABILITY);
    let user_grant = ExplicitGrant {
        subject: user_node.clone(),
        capability: cap.clone(),
        effect: GrantEffect::Allow,
    };

    // 5: revoke the cell's add-users right — one-shot consumed AND an explicit
    // DENY for the cell key, so the coarse cell key can never add users again.
    capability.create_first_user(user_handle)?;
    let cell_deny = ExplicitGrant {
        subject: cell.clone(),
        capability: cap,
        effect: GrantEffect::Deny,
    };

    Ok(CellBootstrapOutcome {
        cell,
        user_primary,
        user_handle: user_handle.to_owned(),
        user_node,
        authority,
        grants: vec![user_grant, cell_deny],
        capability,
        custody,
        cell_custody: cell_custody.kind(),
        user_custody: user_custody.kind(),
        cell_genesis_signature,
        user_genesis_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::{CustodyChoice, CustodyKind};
    use crate::name::InMemoryCellNameRegistry;
    use pillar_rbac::{Decision, RbacDecider, Request};

    fn custody() -> CustodyChoice {
        CustodyChoice::password_default()
    }

    // ---- one-shot capability (moved from pillar-web, unchanged behavior) ----

    #[test]
    fn fresh_node_is_unbootstrapped_and_can_create_the_first_user() {
        let boot = CellBootstrap::new();
        assert!(!boot.is_bootstrapped());
        assert!(boot.can_create_user());
        assert!(boot.initial_user().is_none());
    }

    #[test]
    fn create_cell_then_first_user_consumes_the_one_shot_capability_and_links_them() {
        let mut boot = CellBootstrap::new();
        boot.create_cell(NodeId::from("cell-genesis"))
            .expect("cell");
        assert!(boot.is_bootstrapped());
        assert!(boot.can_create_user(), "capability primed until first user");

        boot.create_first_user("spencer").expect("first user");
        assert!(!boot.can_create_user());
        assert_eq!(boot.initial_user(), Some("spencer"));
        assert_eq!(boot.cell(), Some(&NodeId::from("cell-genesis")));
    }

    #[test]
    fn a_second_cell_key_create_user_is_refused() {
        let mut boot = CellBootstrap::new();
        boot.create_cell(NodeId::from("cell-genesis")).unwrap();
        boot.create_first_user("spencer").unwrap();
        assert_eq!(
            boot.create_first_user("second-user"),
            Err(BootstrapError::CapabilitySpent)
        );
        assert_eq!(boot.initial_user(), Some("spencer"));
    }

    #[test]
    fn first_user_cannot_be_created_before_the_cell() {
        let mut boot = CellBootstrap::new();
        assert_eq!(
            boot.create_first_user("spencer"),
            Err(BootstrapError::NoCellYet)
        );
    }

    #[test]
    fn creating_the_cell_twice_is_refused() {
        let mut boot = CellBootstrap::new();
        boot.create_cell(NodeId::from("cell-genesis")).unwrap();
        assert_eq!(
            boot.create_cell(NodeId::from("cell-again")),
            Err(BootstrapError::CellAlreadyExists)
        );
    }

    #[test]
    fn a_name_already_claimed_is_refused_before_the_cell_is_created() {
        let mut registry = InMemoryCellNameRegistry::new();
        registry.claim("cell-genesis");
        let mut boot = CellBootstrap::new();
        assert_eq!(
            boot.create_cell_checked(NodeId::from("cell-genesis"), &registry),
            Err(BootstrapError::CellNameInUse)
        );
        assert!(!boot.is_bootstrapped());
    }

    // ---- combined single-step ----

    #[test]
    fn combined_step_runs_the_whole_sequence_atomically() {
        let registry = InMemoryCellNameRegistry::new();
        let outcome = bootstrap_cell_and_user(
            NodeId::from("spencer-cell"),
            "spencer",
            &custody(),
            &custody(),
            &registry,
            4,
        )
        .expect("bootstrap");

        // cell created, first user linked, one-shot consumed.
        assert_eq!(outcome.cell, NodeId::from("spencer-cell"));
        assert_eq!(outcome.user_handle, "spencer");
        assert!(!outcome.capability.can_create_user());
        assert_eq!(outcome.capability.initial_user(), Some("spencer"));

        // the cell key signed the user key: the user is trust-reachable from
        // the cell anchor.
        assert!(outcome
            .authority
            .reachable_depth(&outcome.user_node)
            .is_some());
    }

    #[test]
    fn combined_step_grants_the_user_add_users_and_revokes_the_cells_right() {
        let registry = InMemoryCellNameRegistry::new();
        let outcome = bootstrap_cell_and_user(
            NodeId::from("cell-x"),
            "admin",
            &custody(),
            &custody(),
            &registry,
            4,
        )
        .expect("bootstrap");

        let cap = Capability::from(ADD_USERS_CAPABILITY);
        let decider = RbacDecider::new(&outcome.authority, &[], &outcome.grants);

        // The user CAN add users.
        let user_req = Request::new(outcome.user_node.clone(), cap.clone());
        assert_eq!(decider.decide(&user_req), Decision::Allow);

        // The cell key CANNOT add users any more (explicit DENY wins).
        let cell_req = Request::new(outcome.cell.clone(), cap);
        assert_eq!(decider.decide(&cell_req), Decision::Deny);
    }

    #[test]
    fn combined_step_refuses_a_claimed_name_and_generates_nothing() {
        let mut registry = InMemoryCellNameRegistry::new();
        registry.claim("taken-cell");
        let err = bootstrap_cell_and_user(
            NodeId::from("taken-cell"),
            "spencer",
            &custody(),
            &custody(),
            &registry,
            4,
        )
        .unwrap_err();
        assert_eq!(err, BootstrapError::CellNameInUse);
    }

    #[test]
    fn custody_choice_flows_through_for_each_key() {
        // The custody choices are accepted per-key (cell vs user) AND are now
        // REAL backends: each key is labeled to and actually signed by its
        // OWN chosen backend, never funneled through one.
        let registry = InMemoryCellNameRegistry::new();
        let cell_custody = CustodyChoice::new(CustodyKind::Tpm).with_label("cold");
        let user_custody = CustodyChoice::new(CustodyKind::Passkey);
        let outcome = bootstrap_cell_and_user(
            NodeId::from("cell-c"),
            "spencer",
            &cell_custody,
            &user_custody,
            &registry,
            4,
        )
        .expect("bootstrap");
        assert_eq!(outcome.user_handle, "spencer");

        assert_eq!(outcome.cell_custody, CustodyKind::Tpm);
        assert_eq!(outcome.user_custody, CustodyKind::Passkey);
        assert!(outcome.cell_genesis_signature.starts_with("tpm:"));
        assert!(outcome.user_genesis_signature.starts_with("passkey:"));
        assert_ne!(
            outcome.cell_genesis_signature,
            outcome.user_genesis_signature
        );

        // The registry actually labeled each key: a mismatched backend for
        // either is refused.
        assert_eq!(
            outcome.custody.kind_of(&outcome.cell.0),
            Some(CustodyKind::Tpm)
        );
        assert_eq!(
            outcome.custody.kind_of(&outcome.user_node.0),
            Some(CustodyKind::Passkey)
        );
        let wrong = crate::custody::PasswordBackend::new(outcome.cell.0.clone());
        assert_eq!(
            crate::custody::sign_with_backend(
                &outcome.custody,
                &outcome.cell.0,
                &wrong,
                "genesis-certify-user"
            ),
            Err(crate::custody::CustodySignError::KindMismatch {
                expected: CustodyKind::Tpm,
                presented: CustodyKind::Password,
            })
        );
    }

    /// Two keys on the same bootstrap (cell + user) may use DIFFERENT
    /// backends and both actually sign through the trait — not all funneled
    /// to one backend.
    #[test]
    fn cell_and_user_keys_use_different_backends_and_both_sign() {
        let registry = InMemoryCellNameRegistry::new();
        let cell_custody = CustodyChoice::new(CustodyKind::FileKeyring);
        let user_custody = CustodyChoice::new(CustodyKind::Password);
        let outcome = bootstrap_cell_and_user(
            NodeId::from("cell-two-backends"),
            "spencer",
            &cell_custody,
            &user_custody,
            &registry,
            4,
        )
        .expect("bootstrap");
        assert!(outcome.cell_genesis_signature.starts_with("file-keyring:"));
        assert!(outcome.user_genesis_signature.starts_with("password:"));
    }
}
