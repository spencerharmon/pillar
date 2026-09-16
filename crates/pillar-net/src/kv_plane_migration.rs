//! `sessions-kv-plane-migration` — proof that `session-registry-impl`'s
//! session records (`pillar_identity::session_registry::SessionRegistry`)
//! and `key-distribution-offer-impl`'s pending offer records
//! (`pillar_key_distribution::KeyDistributionLedger`'s `offered` set) ride
//! `keyed-store-impl`'s (`pillar_keyedstore`) shared K/V surface instead of
//! their own bespoke hand-rolled folds, and expose it to a generic browse
//! view (the `pillar kv` / portal K/V browse surface).
//!
//! # Why here
//!
//! `pillar-key-distribution` already depends on `pillar-net` (for
//! [`crate::BlobDigest`]), so `pillar-net` cannot depend back on it without a
//! cycle — its migration is proven in its OWN crate
//! (`pillar_key_distribution::tests::offer_and_revoke_are_reflected_in_the_kv_browse_surface`).
//! `pillar-identity` has no edge to `pillar-net` in either direction, so this
//! substrate composes it directly and is the natural place to prove the
//! session side of the migration end to end, plus the generic K/V browse
//! primitive both storage consumers now share
//! ([`pillar_keyedstore::KeyedStore::kv_keys`] /
//! [`pillar_keyedstore::KeyedStore::collections`]).
//!
//! # What did NOT change
//!
//! Session/offer semantics and revocation behavior are untouched — this is a
//! storage-consumer swap only. `SessionRegistry`'s public API
//! (`mint`/`revoke_one`/`revoke_all`/`show`/`ls`/`rev_epoch`) and
//! `KeyDistributionLedger`'s offer/accept/admit/revoke state machine kept
//! every one of their own pre-existing unit tests passing unmodified through
//! the swap (see `pillar-identity`'s and `pillar-key-distribution`'s own
//! test suites).

use pillar_identity::session_registry::SessionRegistry;

/// A minimal, generic "browse a K/V-backed collection" view — the shape a
/// `pillar kv` CLI verb / portal K/V browse panel renders. Any storage
/// consumer that exposes its collection name + live key set (as
/// [`SessionRegistry::kv_collection`]/[`SessionRegistry::kv_keys`] now do)
/// can be rendered through this one generic projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvBrowseView {
    /// The collection name (e.g. `"sessions"`, `"key-offers"`).
    pub collection: String,
    /// Every live key currently in that collection, in the order the
    /// underlying store returns them (sorted, per
    /// [`pillar_keyedstore::KeyedStore::kv_keys`]).
    pub keys: Vec<String>,
}

/// Render a generic K/V browse view over a [`SessionRegistry`]'s backing K/V
/// surface — the session side of the `pillar kv` / portal K/V browse
/// surface this task ships.
#[must_use]
pub fn browse_sessions(registry: &SessionRegistry) -> KvBrowseView {
    KvBrowseView {
        collection: registry.kv_collection().to_string(),
        keys: registry.kv_keys(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `session-registry-impl`'s session records are real K/V surface
    /// entries, not an opaque in-memory `HashMap` fold: minting writes a
    /// live key, `show`/`ls`/`admit` still observe exactly the same
    /// semantics as before the storage swap, and the generic browse view
    /// enumerates every minted session.
    #[test]
    fn session_registry_sessions_are_stored_on_the_shared_kv_surface() {
        let mut reg = SessionRegistry::new();
        reg.mint("alice", "s1", 0, 1000);
        reg.mint("alice", "s2", 0, 1000);
        reg.mint("bob", "s1", 0, 1000);

        let view = browse_sessions(&reg);
        assert_eq!(view.collection, "sessions");
        assert_eq!(view.keys.len(), 3, "one live K/V key per minted session");

        // Untouched semantics: ls/show/rev_epoch behave exactly as the
        // pre-migration hand-rolled fold did.
        assert_eq!(reg.ls("alice", 10).len(), 2);
        assert!(reg.show("alice", "s1").is_some());
        assert_eq!(reg.rev_epoch(), 0);
    }

    /// A revocation does not remove the session from the K/V browse surface
    /// (the record itself, not its key, is what changes) — the browse
    /// surface always reflects the live record set, letting an operator
    /// browse a revoked-but-still-recorded session same as any other.
    #[test]
    fn revocation_leaves_the_kv_browse_surface_key_live() {
        let mut reg = SessionRegistry::new();
        reg.mint("alice", "s1", 0, 1000);
        reg.revoke_one("alice", "s1").unwrap();

        let view = browse_sessions(&reg);
        assert_eq!(
            view.keys.len(),
            1,
            "revoked session's record is still a live K/V entry"
        );
        assert!(reg.show("alice", "s1").unwrap().is_revoked());
        // The revocation is real: ls (which filters on `is_active`) excludes it.
        assert!(reg.ls("alice", 10).is_empty());
    }

    /// Two distinct registries never collide on the shared K/V surface —
    /// each owns its own independent [`pillar_keyedstore::KeyedStore`], so
    /// the storage-consumer swap introduces no cross-registry coupling.
    #[test]
    fn independent_registries_do_not_share_kv_state() {
        let mut a = SessionRegistry::new();
        let mut b = SessionRegistry::new();
        a.mint("alice", "s1", 0, 1000);
        assert_eq!(browse_sessions(&a).keys.len(), 1);
        assert_eq!(browse_sessions(&b).keys.len(), 0, "registry b is untouched");
        b.mint("alice", "s1", 0, 1000);
        assert_eq!(browse_sessions(&b).keys.len(), 1);
    }
}
