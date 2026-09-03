//! Cells & confidentiality — the Rust refinement of `specs/Cells.tla`
//! (ROI P1 "Cells & confidentiality").
//!
//! A [`Cell`] is the unit of confidentiality. It conceptually EXTENDS
//! `KeyDistribution.tla` (the offer/seal system, re-used here as
//! [`pillar_key_distribution::KeyDistributionLedger`]) exactly the way the
//! spec's header describes: it CONSUMES the already-proven ground truth —
//! membership is admitted only through the offer system, a group key is
//! sealed only to current members — by SPECIALISING it rather than
//! re-deriving it.
//!
//! # Model
//!
//! * **Group key** — an epoch counter [`Cell::key_epoch`] plus, per epoch,
//!   the member set that epoch was sealed to ([`Cell::epoch_members`]).
//! * **Members** — [`Cell::members`], nodes admitted via the offer system.
//! * **Visibility classes** ([`VisClass`]) — every placed object carries one
//!   class fixing WHO can decrypt it. Decryptability is DERIVED from
//!   class + the current world by the single decider
//!   [`Cell::node_can_decrypt`], never stored as a separate mutable fact, so
//!   it cannot drift.
//! * **Cross-cell user grants** ([`Grant`]) — `ReadOnly`|`ReadWrite` ×
//!   `All`|`Tags`, enforced by the single decider
//!   [`Cell::user_can_read`] / [`Cell::user_can_write`].
//! * **IPNS-format naming pointer** ([`Cell::name_ptr`]) — a mutable pointer
//!   that only ever names a root the cell has published.
//!
//! # Group-key rotation
//!
//! On member-[`Cell::leave`] the key ROTATES (`key_epoch++`, sealed to the
//! reduced set) in the same call the member is dropped, so a departed member
//! holding only the OLD epoch can never decrypt an object authored under the
//! NEW epoch — forward secrecy ([`Cell::leave`]). A write and a rotation are
//! mutually exclusive under a `rotating` fence, so no write straddles a
//! rotation (the [`Cell::begin_rotate`] / [`Cell::end_rotate`] fence and the
//! `~rotating` guard on [`Cell::place_object`]).
//!
//! # Proven properties (re-asserted by this crate's tests)
//!
//! * `VisibilitySound` — a node's ability to decrypt an object is exactly
//!   what its class entitles.
//! * `ForwardSecrecyOnLeave` — a departed member cannot decrypt a
//!   `CellEncrypted` object authored under the current epoch.
//! * `AtomicRotation` — every placed object's recorded epoch never exceeds
//!   the current epoch (no write straddled a rotation).
//! * `GrantScopeRespected` — write implies read; write needs a `ReadWrite`
//!   grant; read needs an in-scope grant.
//! * `NamePtrResolves` — the name pointer, when set, always names a published
//!   root.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use pillar_core::NodeId;
use pillar_key_distribution::{CellId, UserId};

pub mod migration;
pub use migration::{MigrationCoordinator, MigrationError, ViewChoice};

/// The recipient granularity of a [`VisClass::RecipientSealed`] object —
/// mirrors `specs/Cells.tla`'s `Scopes` (`PerNode`/`PerCell`/`PerUser`).
///
/// The explicit recipient set travels *inside* the [`VisClass`] variant so
/// the seal target and its granularity can never disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealScope {
    /// Sealed to individual node keys (the `KeyDistribution` L0 default).
    PerNode(BTreeSet<NodeId>),
    /// Sealed to a whole peer cell (cell-to-cell). A cell member cannot
    /// decrypt a peer-cell seal here (it targets other cells, not our nodes).
    PerCell(BTreeSet<CellId>),
    /// Sealed to a user identity spanning its nodes. Not a node-level
    /// entitlement, so a node cannot decrypt it via this class.
    PerUser(BTreeSet<UserId>),
}

/// A placed object's visibility class — mirrors `specs/Cells.tla`'s
/// `VisClasses`. The class alone fixes who can decrypt the object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VisClass {
    /// Plaintext — decryptable by anyone.
    Public,
    /// Sealed under the group key — decryptable by exactly the members
    /// holding the object's key epoch.
    CellEncrypted,
    /// Sealed to an explicit recipient set at one of three granularities.
    RecipientSealed(SealScope),
}

/// A cross-cell user access grant mode — mirrors `specs/Cells.tla`'s `Modes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    /// Read only.
    ReadOnly,
    /// Read and write.
    ReadWrite,
}

/// A grant scope — mirrors `specs/Cells.tla`'s `GrantScopes` (`All` or
/// `Tags(T)`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GrantScope {
    /// Every object in the cell.
    All,
    /// Only objects tagged within this tag set (a grant covers an object iff
    /// the object's tags intersect this set).
    Tags(BTreeSet<String>),
}

impl GrantScope {
    /// Whether this scope covers an object carrying `obj_tags`
    /// (`ScopeCovers`).
    #[must_use]
    pub fn covers(&self, obj_tags: &BTreeSet<String>) -> bool {
        match self {
            GrantScope::All => true,
            GrantScope::Tags(t) => obj_tags.intersection(t).next().is_some(),
        }
    }
}

/// A cross-cell user access grant — `<<user, mode, scope>>`, mirroring
/// `specs/Cells.tla`'s `Grants`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Grant {
    /// The granted user.
    pub user: UserId,
    /// Read-only or read-write.
    pub mode: Mode,
    /// The object scope the grant covers.
    pub scope: GrantScope,
}

/// An object identity placed into a cell.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(pub String);

impl From<&str> for ObjectId {
    fn from(s: &str) -> Self {
        ObjectId(s.to_owned())
    }
}

/// A published-root value the [`Cell::name_ptr`] may resolve to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Root(pub String);

impl From<&str> for Root {
    fn from(s: &str) -> Self {
        Root(s.to_owned())
    }
}

/// Errors returned by [`Cell`] operations — each mirrors a spec action's
/// enabling guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellError {
    /// An `Admit`/`Leave`/`PlaceObject`/`BeginRotate` was attempted while a
    /// rotation fence was open (`~rotating`), or `EndRotate` while none was.
    RotationFence,
    /// `Admit` of a node already a member, or `Leave` of a non-member.
    MembershipPrecondition,
    /// `PlaceObject` of an object already placed.
    AlreadyPlaced(ObjectId),
    /// `AddGrant` of a grant that already exists, or `RevokeGrant` of one
    /// that does not.
    GrantPrecondition,
    /// `SetNamePtr`/`PublishRoot` precondition: the root is not published
    /// (or is already published for `PublishRoot`).
    RootPrecondition(Root),
    /// [`Cell::admit_versioned`] refused a joining node whose declared
    /// per-surface version(s) fall outside the compat negotiation window
    /// with this cell's own running versions (ROI P1 "Compatibility
    /// contract: check, negotiate, N-1+") — a clean refusal, never a silent
    /// admission of an incompatible member.
    CompatRefused(pillar_crypto::NegotiationError),
}

impl From<pillar_crypto::NegotiationError> for CellError {
    fn from(e: pillar_crypto::NegotiationError) -> Self {
        CellError::CompatRefused(e)
    }
}

/// A single cell: the unit of confidentiality, refining `specs/Cells.tla`.
///
/// The group key is an epoch counter plus per-epoch sealed member sets;
/// membership grows via [`Cell::admit`] and shrinks (with rotation) via
/// [`Cell::leave`]; objects are placed with a [`VisClass`]; cross-cell access
/// is governed by [`Grant`]s; and an IPNS-format pointer names the current
/// published root.
#[derive(Debug, Default)]
pub struct Cell {
    members: BTreeSet<NodeId>,
    key_epoch: u64,
    epoch_members: BTreeMap<u64, BTreeSet<NodeId>>,
    rotating: bool,
    obj_class: BTreeMap<ObjectId, VisClass>,
    obj_epoch: BTreeMap<ObjectId, u64>,
    obj_tags: BTreeMap<ObjectId, BTreeSet<String>>,
    placed: BTreeSet<ObjectId>,
    grants: BTreeSet<Grant>,
    published: BTreeSet<Root>,
    name_ptr: Option<Root>,
}

impl Cell {
    /// A fresh, empty cell: no members, epoch 0 sealed to no members, no
    /// objects/grants/published roots, no name pointer (`Init`).
    #[must_use]
    pub fn new() -> Self {
        let mut epoch_members = BTreeMap::new();
        epoch_members.insert(0, BTreeSet::new());
        Cell {
            members: BTreeSet::new(),
            key_epoch: 0,
            epoch_members,
            rotating: false,
            obj_class: BTreeMap::new(),
            obj_epoch: BTreeMap::new(),
            obj_tags: BTreeMap::new(),
            placed: BTreeSet::new(),
            grants: BTreeSet::new(),
            published: BTreeSet::new(),
            name_ptr: None,
        }
    }

    // ---- membership (via the offer system, consumed as ground truth) ----

    /// Admit a node as a member (`Admit`). Re-seals the CURRENT epoch to
    /// include it (a join widens the epoch's sealed set). Fenced by
    /// `~rotating`.
    pub fn admit(&mut self, node: NodeId) -> Result<(), CellError> {
        if self.rotating {
            return Err(CellError::RotationFence);
        }
        if self.members.contains(&node) {
            return Err(CellError::MembershipPrecondition);
        }
        self.members.insert(node);
        self.epoch_members
            .insert(self.key_epoch, self.members.clone());
        Ok(())
    }

    /// Admit a node as a member EXACTLY like [`Cell::admit`], but ONLY after
    /// negotiating compatibility (ROI P1 "Compatibility contract: check,
    /// negotiate, N-1+") between this cell's own declared per-surface running
    /// versions (`local`) and the joining node's declared versions (`remote`)
    /// over every surface in `required` — the "cell members exchange +
    /// check versions" clause of the ROI, applied to cell admission. A
    /// required surface neither side declared, or one where the two parties'
    /// declared versions fall outside `window`, is [`CellError::CompatRefused`]
    /// — the join never happens on an incompatible or under-declared node,
    /// mirroring [`Cell::admit`]'s existing preconditions rather than
    /// replacing them (a compat refusal is checked FIRST, before any
    /// membership-precondition / rotation-fence check runs, so an
    /// incompatible node is refused before its other preconditions are even
    /// considered).
    ///
    /// # Errors
    /// Returns [`CellError::CompatRefused`] on a negotiation failure, or
    /// whatever [`Cell::admit`] itself would return once negotiation passes.
    pub fn admit_versioned(
        &mut self,
        node: NodeId,
        local: &pillar_crypto::DeclaredVersions,
        remote: &pillar_crypto::DeclaredVersions,
        required: &[&'static str],
        window: pillar_crypto::CompatWindow,
    ) -> Result<(), CellError> {
        pillar_crypto::negotiate_all(local, remote, required, window)?;
        self.admit(node)
    }

    /// A member LEAVES (`Leave`). The group key ROTATES in the SAME call:
    /// `key_epoch` increments and the new epoch is sealed to the reduced
    /// member set. The departed member holds only the old epoch, so it can
    /// never decrypt anything authored under the new one — forward secrecy.
    /// Fenced by `~rotating`.
    pub fn leave(&mut self, node: &NodeId) -> Result<(), CellError> {
        if self.rotating {
            return Err(CellError::RotationFence);
        }
        if !self.members.contains(node) {
            return Err(CellError::MembershipPrecondition);
        }
        self.members.remove(node);
        self.key_epoch += 1;
        self.epoch_members
            .insert(self.key_epoch, self.members.clone());
        Ok(())
    }

    /// Open the rotation fence (`BeginRotate`), a distinct in-progress state
    /// that bars a concurrent write. Disables admit/leave/place while open.
    pub fn begin_rotate(&mut self) -> Result<(), CellError> {
        if self.rotating {
            return Err(CellError::RotationFence);
        }
        self.rotating = true;
        Ok(())
    }

    /// Close the rotation fence (`EndRotate`), committing the new epoch
    /// sealed to the (unchanged) member set. No write could have landed while
    /// rotating.
    pub fn end_rotate(&mut self) -> Result<(), CellError> {
        if !self.rotating {
            return Err(CellError::RotationFence);
        }
        self.key_epoch += 1;
        self.epoch_members
            .insert(self.key_epoch, self.members.clone());
        self.rotating = false;
        Ok(())
    }

    /// Whether `node` is a current member.
    #[must_use]
    pub fn is_member(&self, node: &NodeId) -> bool {
        self.members.contains(node)
    }

    /// The current group-key epoch.
    #[must_use]
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    /// Whether a rotation fence is currently open.
    #[must_use]
    pub fn is_rotating(&self) -> bool {
        self.rotating
    }

    // ---- placing objects ----

    /// Place an object with a visibility class and tags (`PlaceObject`). A
    /// `CellEncrypted` object records the CURRENT epoch as the epoch it was
    /// sealed under. Fenced by `~rotating` — a write can never straddle a
    /// rotation.
    pub fn place_object(
        &mut self,
        object: ObjectId,
        class: VisClass,
        tags: BTreeSet<String>,
    ) -> Result<(), CellError> {
        if self.rotating {
            return Err(CellError::RotationFence);
        }
        if self.placed.contains(&object) {
            return Err(CellError::AlreadyPlaced(object));
        }
        self.obj_class.insert(object.clone(), class);
        self.obj_epoch.insert(object.clone(), self.key_epoch);
        self.obj_tags.insert(object.clone(), tags);
        self.placed.insert(object);
        Ok(())
    }

    /// The single DECIDER: whether `node` can decrypt object `object` under
    /// its visibility class (`NodeCanDecrypt`). Decryptability is derived
    /// here, never stored, so it cannot drift.
    ///
    /// A non-placed object is decryptable by no one.
    #[must_use]
    pub fn node_can_decrypt(&self, node: &NodeId, object: &ObjectId) -> bool {
        if !self.placed.contains(object) {
            return false;
        }
        match self.obj_class.get(object) {
            Some(VisClass::Public) => true,
            Some(VisClass::CellEncrypted) => {
                let epoch = self.obj_epoch.get(object).copied().unwrap_or(0);
                self.epoch_members
                    .get(&epoch)
                    .is_some_and(|m| m.contains(node))
            }
            Some(VisClass::RecipientSealed(SealScope::PerNode(rcpt))) => rcpt.contains(node),
            // PerCell / PerUser are not node-level entitlements.
            Some(VisClass::RecipientSealed(_)) => false,
            None => false,
        }
    }

    // ---- cross-cell user grants ----

    /// Add a cross-cell user grant (`AddGrant`).
    pub fn add_grant(&mut self, grant: Grant) -> Result<(), CellError> {
        if self.grants.contains(&grant) {
            return Err(CellError::GrantPrecondition);
        }
        self.grants.insert(grant);
        Ok(())
    }

    /// Revoke a cross-cell user grant (`RevokeGrant`).
    pub fn revoke_grant(&mut self, grant: &Grant) -> Result<(), CellError> {
        if !self.grants.remove(grant) {
            return Err(CellError::GrantPrecondition);
        }
        Ok(())
    }

    /// The single read DECIDER (`UserCanRead`): a user may read object
    /// `object` iff it holds a grant whose scope covers the object's tags.
    #[must_use]
    pub fn user_can_read(&self, user: &UserId, object: &ObjectId) -> bool {
        let tags = self.obj_tags.get(object).cloned().unwrap_or_default();
        self.grants
            .iter()
            .any(|g| &g.user == user && g.scope.covers(&tags))
    }

    /// The single write DECIDER (`UserCanWrite`): a user may write object
    /// `object` only under a `ReadWrite` grant whose scope covers it.
    #[must_use]
    pub fn user_can_write(&self, user: &UserId, object: &ObjectId) -> bool {
        let tags = self.obj_tags.get(object).cloned().unwrap_or_default();
        self.grants
            .iter()
            .any(|g| &g.user == user && g.mode == Mode::ReadWrite && g.scope.covers(&tags))
    }

    // ---- IPNS-format naming pointer ----

    /// Publish a root (`PublishRoot`). The pointer may later be advanced only
    /// to a published root.
    pub fn publish_root(&mut self, root: Root) -> Result<(), CellError> {
        if self.published.contains(&root) {
            return Err(CellError::RootPrecondition(root));
        }
        self.published.insert(root);
        Ok(())
    }

    /// Advance the IPNS-format pointer to a published root (`SetNamePtr`).
    /// The pointer only ever names a published root.
    pub fn set_name_ptr(&mut self, root: Root) -> Result<(), CellError> {
        if !self.published.contains(&root) {
            return Err(CellError::RootPrecondition(root));
        }
        self.name_ptr = Some(root);
        Ok(())
    }

    /// The current value of the IPNS-format pointer (`namePtr`), or `None`
    /// if never set. When `Some`, it is always a published root
    /// (`NamePtrResolves`).
    #[must_use]
    pub fn name_ptr(&self) -> Option<&Root> {
        self.name_ptr.as_ref()
    }

    /// Whether `root` has been published.
    #[must_use]
    pub fn is_published(&self, root: &Root) -> bool {
        self.published.contains(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    fn node_set(names: &[&str]) -> BTreeSet<NodeId> {
        names.iter().map(|n| NodeId::from(*n)).collect()
    }

    // VisibilitySound: a Public object is decryptable by anyone; a
    // CellEncrypted object exactly by members of its epoch; a PerNode-sealed
    // object exactly by its explicit recipients; PerCell/PerUser by no node.
    #[test]
    fn visibility_is_exactly_class_determined() {
        let mut cell = Cell::new();
        cell.admit(NodeId::from("n1")).unwrap();
        cell.admit(NodeId::from("n2")).unwrap();

        cell.place_object(ObjectId::from("pub"), VisClass::Public, tags(&[]))
            .unwrap();
        cell.place_object(ObjectId::from("cell"), VisClass::CellEncrypted, tags(&[]))
            .unwrap();
        cell.place_object(
            ObjectId::from("pn"),
            VisClass::RecipientSealed(SealScope::PerNode(node_set(&["n1"]))),
            tags(&[]),
        )
        .unwrap();
        cell.place_object(
            ObjectId::from("pc"),
            VisClass::RecipientSealed(SealScope::PerCell(
                [CellId::from("peer")].into_iter().collect(),
            )),
            tags(&[]),
        )
        .unwrap();

        let outsider = NodeId::from("outsider");
        // Public: anyone.
        assert!(cell.node_can_decrypt(&NodeId::from("n1"), &ObjectId::from("pub")));
        assert!(cell.node_can_decrypt(&outsider, &ObjectId::from("pub")));
        // CellEncrypted: exactly current-epoch members.
        assert!(cell.node_can_decrypt(&NodeId::from("n1"), &ObjectId::from("cell")));
        assert!(cell.node_can_decrypt(&NodeId::from("n2"), &ObjectId::from("cell")));
        assert!(!cell.node_can_decrypt(&outsider, &ObjectId::from("cell")));
        // PerNode: exactly its recipients.
        assert!(cell.node_can_decrypt(&NodeId::from("n1"), &ObjectId::from("pn")));
        assert!(!cell.node_can_decrypt(&NodeId::from("n2"), &ObjectId::from("pn")));
        // PerCell: no node.
        assert!(!cell.node_can_decrypt(&NodeId::from("n1"), &ObjectId::from("pc")));
    }

    // A non-placed object is decryptable by no one.
    #[test]
    fn unplaced_object_decryptable_by_none() {
        let cell = Cell::new();
        assert!(!cell.node_can_decrypt(&NodeId::from("n1"), &ObjectId::from("ghost")));
    }

    // ForwardSecrecyOnLeave: a member that LEAVES cannot decrypt a
    // CellEncrypted object authored under the (post-leave) current epoch,
    // because Leave rotates the key in the same call.
    #[test]
    fn departed_member_cannot_decrypt_post_leave_object() {
        let mut cell = Cell::new();
        cell.admit(NodeId::from("n1")).unwrap();
        cell.admit(NodeId::from("n2")).unwrap();

        // Object authored while both are members — n1 can read it (its epoch).
        cell.place_object(ObjectId::from("old"), VisClass::CellEncrypted, tags(&[]))
            .unwrap();
        assert!(cell.node_can_decrypt(&NodeId::from("n1"), &ObjectId::from("old")));

        // n1 leaves — key rotates.
        cell.leave(&NodeId::from("n1")).unwrap();
        assert_eq!(cell.key_epoch(), 1);

        // A new object under the new epoch — n1 (departed) cannot decrypt.
        cell.place_object(ObjectId::from("new"), VisClass::CellEncrypted, tags(&[]))
            .unwrap();
        assert!(!cell.node_can_decrypt(&NodeId::from("n1"), &ObjectId::from("new")));
        assert!(cell.node_can_decrypt(&NodeId::from("n2"), &ObjectId::from("new")));
    }

    // AtomicRotation: a write is fenced out while rotating, so no object's
    // recorded epoch ever exceeds the current epoch.
    #[test]
    fn write_is_fenced_during_rotation() {
        let mut cell = Cell::new();
        cell.admit(NodeId::from("n1")).unwrap();
        cell.begin_rotate().unwrap();
        assert!(cell.is_rotating());
        // Placing, admitting, leaving are all barred while rotating.
        assert_eq!(
            cell.place_object(ObjectId::from("o"), VisClass::CellEncrypted, tags(&[])),
            Err(CellError::RotationFence)
        );
        assert_eq!(
            cell.admit(NodeId::from("n2")),
            Err(CellError::RotationFence)
        );
        assert_eq!(
            cell.leave(&NodeId::from("n1")),
            Err(CellError::RotationFence)
        );
        cell.end_rotate().unwrap();
        assert_eq!(cell.key_epoch(), 1);

        // After the fence closes the write lands under the committed epoch.
        cell.place_object(ObjectId::from("o"), VisClass::CellEncrypted, tags(&[]))
            .unwrap();
        // AtomicRotation invariant: recorded epoch never exceeds current.
        assert!(cell.obj_epoch[&ObjectId::from("o")] <= cell.key_epoch());
    }

    // GrantScopeRespected: write implies read; write needs a ReadWrite grant;
    // an out-of-scope object is never accessible.
    #[test]
    fn grant_scope_is_respected() {
        let mut cell = Cell::new();
        cell.place_object(ObjectId::from("t1"), VisClass::Public, tags(&["red"]))
            .unwrap();
        cell.place_object(ObjectId::from("t2"), VisClass::Public, tags(&["blue"]))
            .unwrap();

        // ReadOnly All grant to alice.
        cell.add_grant(Grant {
            user: UserId::from("alice"),
            mode: Mode::ReadOnly,
            scope: GrantScope::All,
        })
        .unwrap();
        // ReadWrite Tags{red} grant to bob.
        cell.add_grant(Grant {
            user: UserId::from("bob"),
            mode: Mode::ReadWrite,
            scope: GrantScope::Tags(tags(&["red"])),
        })
        .unwrap();

        let alice = UserId::from("alice");
        let bob = UserId::from("bob");

        // alice reads everything (All) but never writes (ReadOnly).
        assert!(cell.user_can_read(&alice, &ObjectId::from("t1")));
        assert!(cell.user_can_read(&alice, &ObjectId::from("t2")));
        assert!(!cell.user_can_write(&alice, &ObjectId::from("t1")));

        // bob reads+writes red (t1), neither on blue (t2, out of scope).
        assert!(cell.user_can_read(&bob, &ObjectId::from("t1")));
        assert!(cell.user_can_write(&bob, &ObjectId::from("t1")));
        assert!(!cell.user_can_read(&bob, &ObjectId::from("t2")));
        assert!(!cell.user_can_write(&bob, &ObjectId::from("t2")));

        // write implies read, structurally, for every user/object.
        for u in [&alice, &bob] {
            for o in [ObjectId::from("t1"), ObjectId::from("t2")] {
                if cell.user_can_write(u, &o) {
                    assert!(cell.user_can_read(u, &o), "write must imply read");
                }
            }
        }
    }

    // Revoking a grant removes the access it conferred.
    #[test]
    fn revoking_a_grant_removes_access() {
        let mut cell = Cell::new();
        cell.place_object(ObjectId::from("o"), VisClass::Public, tags(&[]))
            .unwrap();
        let g = Grant {
            user: UserId::from("alice"),
            mode: Mode::ReadWrite,
            scope: GrantScope::All,
        };
        cell.add_grant(g.clone()).unwrap();
        assert!(cell.user_can_write(&UserId::from("alice"), &ObjectId::from("o")));
        cell.revoke_grant(&g).unwrap();
        assert!(!cell.user_can_read(&UserId::from("alice"), &ObjectId::from("o")));
    }

    // NamePtrResolves: the pointer, when set, always names a published root,
    // and advancing to an unpublished root is refused.
    #[test]
    fn name_pointer_only_ever_names_a_published_root() {
        let mut cell = Cell::new();
        assert!(cell.name_ptr().is_none());
        // Cannot point at an unpublished root.
        assert!(matches!(
            cell.set_name_ptr(Root::from("r1")),
            Err(CellError::RootPrecondition(_))
        ));
        cell.publish_root(Root::from("r1")).unwrap();
        cell.set_name_ptr(Root::from("r1")).unwrap();
        assert_eq!(cell.name_ptr(), Some(&Root::from("r1")));
        assert!(cell.is_published(cell.name_ptr().unwrap()));
    }

    // A join widens the current epoch's sealed set (Admit re-seals).
    #[test]
    fn join_widens_current_epoch_seal() {
        let mut cell = Cell::new();
        cell.admit(NodeId::from("n1")).unwrap();
        cell.place_object(ObjectId::from("o"), VisClass::CellEncrypted, tags(&[]))
            .unwrap();
        assert!(!cell.node_can_decrypt(&NodeId::from("n2"), &ObjectId::from("o")));
        // n2 joins the SAME epoch -> now can decrypt the object of that epoch.
        cell.admit(NodeId::from("n2")).unwrap();
        assert!(cell.node_can_decrypt(&NodeId::from("n2"), &ObjectId::from("o")));
    }

    // Membership + grant + place preconditions are enforced.
    #[test]
    fn preconditions_are_enforced() {
        let mut cell = Cell::new();
        cell.admit(NodeId::from("n1")).unwrap();
        assert_eq!(
            cell.admit(NodeId::from("n1")),
            Err(CellError::MembershipPrecondition)
        );
        assert_eq!(
            cell.leave(&NodeId::from("ghost")),
            Err(CellError::MembershipPrecondition)
        );
        cell.place_object(ObjectId::from("o"), VisClass::Public, tags(&[]))
            .unwrap();
        assert_eq!(
            cell.place_object(ObjectId::from("o"), VisClass::Public, tags(&[])),
            Err(CellError::AlreadyPlaced(ObjectId::from("o")))
        );
        let g = Grant {
            user: UserId::from("alice"),
            mode: Mode::ReadOnly,
            scope: GrantScope::All,
        };
        cell.add_grant(g.clone()).unwrap();
        assert_eq!(cell.add_grant(g.clone()), Err(CellError::GrantPrecondition));
        cell.revoke_grant(&g).unwrap();
        assert_eq!(cell.revoke_grant(&g), Err(CellError::GrantPrecondition));
    }

    // The stand-alone rotation fence (BeginRotate/EndRotate) advances the
    // epoch to a set sealed to the unchanged member set.
    #[test]
    fn standalone_rotation_seals_unchanged_members() {
        let mut cell = Cell::new();
        cell.admit(NodeId::from("n1")).unwrap();
        cell.begin_rotate().unwrap();
        // A second begin while open is refused.
        assert_eq!(cell.begin_rotate(), Err(CellError::RotationFence));
        cell.end_rotate().unwrap();
        // An end while none open is refused.
        assert_eq!(cell.end_rotate(), Err(CellError::RotationFence));
        // n1 still decrypts an object of the new epoch (still a member).
        cell.place_object(ObjectId::from("o"), VisClass::CellEncrypted, tags(&[]))
            .unwrap();
        assert!(cell.node_can_decrypt(&NodeId::from("n1"), &ObjectId::from("o")));
    }

    // --- admit_versioned: cell-member compat negotiation (ROI P1
    // "Compatibility contract: check, negotiate, N-1+") ---

    fn declare(surface: &'static str, v: u16) -> pillar_crypto::DeclaredVersions {
        let mut d = pillar_crypto::DeclaredVersions::new();
        d.declare(surface, pillar_crypto::SurfaceVersion(v));
        d
    }

    #[test]
    fn admit_versioned_admits_a_compatible_joining_node() {
        let mut cell = Cell::new();
        let local = declare("cell-membership", 5);
        let remote = declare("cell-membership", 4);
        assert!(cell
            .admit_versioned(
                NodeId::from("n1"),
                &local,
                &remote,
                &["cell-membership"],
                pillar_crypto::CompatWindow(1),
            )
            .is_ok());
        assert!(cell.members.contains(&NodeId::from("n1")));
    }

    #[test]
    fn admit_versioned_refuses_an_incompatible_joining_node_without_admitting_it() {
        let mut cell = Cell::new();
        let local = declare("cell-membership", 10);
        let remote = declare("cell-membership", 0);
        let err = cell
            .admit_versioned(
                NodeId::from("n1"),
                &local,
                &remote,
                &["cell-membership"],
                pillar_crypto::CompatWindow(1),
            )
            .unwrap_err();
        assert!(matches!(err, CellError::CompatRefused(_)));
        assert!(
            !cell.members.contains(&NodeId::from("n1")),
            "an incompatible node must never be admitted"
        );
    }

    #[test]
    fn admit_versioned_refuses_a_node_missing_a_required_surface_declaration() {
        let mut cell = Cell::new();
        let local = declare("cell-membership", 1);
        let remote = pillar_crypto::DeclaredVersions::new(); // never declared
        let err = cell
            .admit_versioned(
                NodeId::from("n1"),
                &local,
                &remote,
                &["cell-membership"],
                pillar_crypto::CompatWindow(2),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            CellError::CompatRefused(pillar_crypto::NegotiationError::NotDeclared(_))
        ));
        assert!(!cell.members.contains(&NodeId::from("n1")));
    }

    #[test]
    fn admit_versioned_still_honors_the_existing_membership_precondition() {
        // A compatible re-admit of an already-present member is refused by
        // the underlying `admit` precondition, exactly as a bare `admit`
        // call would be — negotiation success does not bypass it.
        let mut cell = Cell::new();
        cell.admit(NodeId::from("n1")).unwrap();
        let local = declare("cell-membership", 1);
        let remote = declare("cell-membership", 1);
        let err = cell
            .admit_versioned(
                NodeId::from("n1"),
                &local,
                &remote,
                &["cell-membership"],
                pillar_crypto::CompatWindow(0),
            )
            .unwrap_err();
        assert_eq!(err, CellError::MembershipPrecondition);
    }
}
