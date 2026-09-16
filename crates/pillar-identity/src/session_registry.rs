//! Server-side, per-principal session registry — the Rust refinement of
//! `specs/SessionRegistry.tla` (ROI P1 "CLI surface: `pillar session`").
//!
//! # Model
//!
//! Distinct from the local `ctx`/context `cli-session-resource-impl` owns on
//! the client, this is a first-class SERVER-SIDE session object: a
//! per-principal registry of [`Session`]s, each with its own id (a reusable
//! slot), its own expiry, individually revocable ([`SessionRegistry::revoke_one`],
//! CLI `revoke <id>`), and atomically all-revocable
//! ([`SessionRegistry::revoke_all`], CLI `revoke-all`, sign-out-everywhere).
//! Enumeration ([`SessionRegistry::ls`] / [`SessionRegistry::show`]) is pure
//! derived state over the registry, no separate bookkeeping needed.
//!
//! Sessions are minted on a successful node-side custody login (see
//! [`crate::login`]) — this module extends that issuance, it does not fork
//! it; the caller supplies the already-verified principal (e.g. a
//! [`crate::login::LoginOutcome`]'s device or op key, stringified) to
//! [`SessionRegistry::mint`].
//!
//! Every session mint is stamped with a GENERATION (`mint_epoch`, the global
//! revocation epoch at mint time). A generation once revoked never re-admits;
//! a fresh mint into the same reused slot always carries a strictly-later
//! generation and clears any prior revocation stamp, so it is a genuinely new
//! session, never a survivor of an earlier `revoke-all` sweep.
//! [`SessionRegistry::revoke_one`] and [`SessionRegistry::revoke_all`] both
//! bump the single global `rev_epoch` and stamp the affected slot(s)'
//! `revoked_epoch` atomically in the same call.
//!
//! Bearer-action admission ([`SessionView::admit`]) is evaluated against the
//! revocation epoch at action time (revoke-before-act), reusing
//! `pillar_wot_authority::FencedActor`'s fail-closed freshness rule verbatim
//! over this registry's single scalar epoch: a caller whose own watermark
//! lags the registry's current one is REFUSED regardless of whether the
//! session would otherwise admit — freshness unconfirmable ⇒ fail-closed.
//! Expired or revoked sessions admit nothing.

use std::collections::{HashMap, HashSet};

use pillar_keyedstore::{Hlc, SharedStore};
use serde::{Deserialize, Serialize};

/// The K/V collection every session record is stored under — the
/// sessions-kv-plane-migration data-layer consumer swap onto
/// `pillar_keyedstore`'s shared K/V surface (see `specs/KeyedStore.tla`),
/// replacing the registry's former bespoke `HashMap` fold.
const SESSIONS_COLLECTION: &str = "sessions";

/// A minted server-side session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// The session's id — a reusable slot within its principal's sessions.
    pub id: String,
    /// The principal (e.g. a device/op-key identity) this session was minted
    /// for.
    pub principal: String,
    /// The device/origin this session was minted from (e.g. a user agent,
    /// device label, or client IP) — the "device inventory" column of
    /// `session ls`. `"unknown"` for a session minted via the legacy
    /// [`SessionRegistry::mint`] (no origin supplied).
    pub origin: String,
    /// Logical mint timestamp.
    pub issued_at: u64,
    /// Logical timestamp of this session's most recent observed activity
    /// (mint time until [`SessionRegistry::touch`] is called). Distinct from
    /// `issued_at`: `issued_at` never changes after mint, `last_seen`
    /// advances on every touch — the "last-seen" column of `session ls`.
    pub last_seen: u64,
    /// Logical expiry timestamp; the session admits nothing at or after this.
    pub expiry: u64,
    /// The global revocation epoch in effect at mint time (this session's
    /// generation).
    pub mint_epoch: u64,
    /// The revocation epoch at which this exact generation was revoked, if
    /// any. `None` means this generation has never been revoked.
    revoked_epoch: Option<u64>,
}

impl Session {
    /// Whether this session's own generation has been revoked (individually
    /// or swept by a `revoke-all`) — independent of expiry.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked_epoch.is_some()
    }

    /// The epoch at which this generation was revoked, if any.
    #[must_use]
    pub fn revoked_epoch(&self) -> Option<u64> {
        self.revoked_epoch
    }

    /// Whether this session has expired as of logical time `now` (expiry is
    /// exclusive: a session does not admit at or after its `expiry`).
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expiry
    }

    /// Whether this session currently admits: neither revoked nor expired at
    /// `now`.
    #[must_use]
    pub fn is_active(&self, now: u64) -> bool {
        !self.is_revoked() && !self.is_expired(now)
    }
}

/// Why revoking a specific session failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevokeError {
    /// No session with that id exists for that principal.
    NoSuchSession,
}

/// The server-side session registry: refines the `sessions` / `revEpoch`
/// state of `specs/SessionRegistry.tla`. No server-side database — a real
/// deployment persists mint/revoke as epoch-stamped signed events on the
/// streaming DB; this type models the resulting decision state.
///
/// Session records are the storage-consumer swap's payload: each session is
/// stored as one opaque JSON-encoded K/V value in `pillar_keyedstore`'s
/// shared K/V surface (collection [`SESSIONS_COLLECTION`], keyed by
/// `principal\0id`), replacing the registry's former hand-rolled
/// `HashMap<(String, String), Session>` fold. `rev_epoch` and the
/// `by_principal` index remain in-memory bookkeeping — a scalar counter and a
/// key-enumeration index are not themselves stored VALUES the K/V surface is
/// meant to hold, only a means of addressing it (the same role
/// `KeyedStore::kv_keys` plays generically for the browse surface, kept local
/// here so `ls`/`revoke_all` need not scan the whole log).
#[derive(Clone, Debug, Default)]
pub struct SessionRegistry {
    /// The single global revocation epoch (`revEpoch`), bumped by every
    /// revocation (individual or sweep).
    rev_epoch: u64,
    /// The K/V-backed store of session records — a CLONE of the ONE cell-wide
    /// [`SharedStore`] substrate (the data-layer-single-substrate-dogfood
    /// consolidation). The registry NO LONGER owns a private store: sessions
    /// minted here land in the SAME keyed op-log the portal's kv/doc browse
    /// reads, so a real login is immediately visible on the live cell. A
    /// registry built via [`SessionRegistry::new`] wraps a fresh private
    /// substrate (unit-test use); the running portal builds it via
    /// [`SessionRegistry::with_shared_store`] onto its shared substrate.
    store: SharedStore,
    /// A monotonically increasing logical clock feeding each store write's
    /// HLC — this registry is the sole author of its own sessions
    /// collection, so a simple increasing counter (author id fixed to
    /// `"session-registry"`) is a valid, deterministic HLC source.
    clock: u64,
    /// principal -> set of session ids ever minted for it. An addressing
    /// index only (never a copy of session state), letting `ls`/`revoke_all`
    /// enumerate a principal's slots without scanning the whole K/V log.
    by_principal: HashMap<String, HashSet<String>>,
}

impl SessionRegistry {
    /// A fresh registry: no sessions minted, epoch zero.
    #[must_use]
    pub fn new() -> Self {
        SessionRegistry::default()
    }

    /// A registry whose session records land in the supplied CELL-WIDE
    /// [`SharedStore`] substrate instead of a private one — the
    /// data-layer-single-substrate-dogfood wiring. Every session minted here
    /// is written to the SAME keyed op-log the portal's kv/doc browse reads,
    /// so a login on a live cell surfaces in the portal with no second store.
    #[must_use]
    pub fn with_shared_store(store: SharedStore) -> Self {
        SessionRegistry {
            store,
            ..SessionRegistry::default()
        }
    }

    /// The registry's current true global revocation epoch.
    #[must_use]
    pub fn rev_epoch(&self) -> u64 {
        self.rev_epoch
    }

    fn kv_key(principal: &str, id: &str) -> String {
        format!("{principal}\u{0}{id}")
    }

    fn next_hlc(&mut self) -> Hlc {
        self.clock += 1;
        Hlc::new(self.clock, 0, "session-registry")
    }

    fn get(&self, principal: &str, id: &str) -> Option<Session> {
        let bytes = self
            .store
            .with(|s| s.kv_get(SESSIONS_COLLECTION, &Self::kv_key(principal, id)))?;
        serde_json::from_slice(&bytes).ok()
    }

    fn put(&mut self, session: &Session) {
        let key = Self::kv_key(&session.principal, &session.id);
        let bytes = serde_json::to_vec(session).expect("Session serializes");
        let hlc = self.next_hlc();
        self.store
            .with_mut(|s| s.kv_put(SESSIONS_COLLECTION, &key, bytes, hlc));
        self.by_principal
            .entry(session.principal.clone())
            .or_default()
            .insert(session.id.clone());
    }

    /// The K/V collection name every session record lives under in the
    /// backing [`KeyedStore`] — the raw browse-surface handle a `pillar kv`
    /// / portal K/V browse view reads directly, alongside
    /// [`SessionRegistry::kv_keys`].
    #[must_use]
    pub fn kv_collection(&self) -> &'static str {
        SESSIONS_COLLECTION
    }

    /// Every live K/V key currently stored in the sessions collection
    /// (`principal\0id`, one per non-tombstoned session) — the generic
    /// `pillar kv` / portal K/V browse-surface enumeration over this
    /// registry's backing store, via [`KeyedStore::kv_keys`].
    #[must_use]
    pub fn kv_keys(&self) -> Vec<String> {
        self.store.with(|s| s.kv_keys(SESSIONS_COLLECTION))
    }

    /// Mint a session for `principal` at slot `id`, valid from `issued_at`
    /// until (exclusive) `expiry`. Stamped with the CURRENT global epoch as
    /// its generation, and any prior revocation stamp on this exact slot is
    /// cleared — minting into a reused slot always produces a genuinely new,
    /// unrevoked generation, never a survivor of an earlier sweep.
    ///
    /// Called on a successful node-side custody login (see
    /// [`crate::login::IdentityStore::login`]); this module does not itself
    /// re-verify the login chain.
    pub fn mint(
        &mut self,
        principal: impl Into<String>,
        id: impl Into<String>,
        issued_at: u64,
        expiry: u64,
    ) -> Session {
        self.mint_with_origin(principal, id, issued_at, expiry, "unknown")
    }

    /// Mint a session exactly as [`SessionRegistry::mint`], additionally
    /// stamping the device/origin (`origin`, e.g. a user agent, device
    /// label, or client IP) the login was observed from — the "device
    /// inventory" column of `session ls`. `last_seen` is initialized to
    /// `issued_at`.
    pub fn mint_with_origin(
        &mut self,
        principal: impl Into<String>,
        id: impl Into<String>,
        issued_at: u64,
        expiry: u64,
        origin: impl Into<String>,
    ) -> Session {
        let principal = principal.into();
        let id = id.into();
        let session = Session {
            id,
            principal,
            origin: origin.into(),
            issued_at,
            last_seen: issued_at,
            expiry,
            mint_epoch: self.rev_epoch,
            revoked_epoch: None,
        };
        self.put(&session);
        session
    }

    /// Record activity on `principal`'s `id` session as of logical time
    /// `now` — advances its `last_seen` watermark. A no-op (returns `false`)
    /// if no such slot exists; never resurrects a revoked/expired session
    /// (its record is updated but its admission state is untouched).
    pub fn touch(&mut self, principal: &str, id: &str, now: u64) -> bool {
        match self.get(principal, id) {
            Some(mut session) => {
                session.last_seen = now;
                self.put(&session);
                true
            }
            None => false,
        }
    }

    /// Individually revoke session `id` of `principal` (`revoke <id>`):
    /// bumps the global epoch and stamps that exact slot's current
    /// generation as revoked at the new epoch, atomically.
    ///
    /// # Errors
    ///
    /// [`RevokeError::NoSuchSession`] if no session with that id exists for
    /// that principal.
    pub fn revoke_one(&mut self, principal: &str, id: &str) -> Result<(), RevokeError> {
        let mut session = self.get(principal, id).ok_or(RevokeError::NoSuchSession)?;
        self.rev_epoch += 1;
        session.revoked_epoch = Some(self.rev_epoch);
        self.put(&session);
        Ok(())
    }

    /// Atomic sign-out-everywhere for `principal` (`revoke-all`): bumps the
    /// global epoch ONCE and stamps every currently-active session slot
    /// belonging to `principal` as revoked at that same new epoch — a single
    /// epoch-stamped sweep, not one bump per session.
    ///
    /// A session minted for `principal` AFTER this call (into any slot,
    /// including a swept one) carries a strictly later `mint_epoch` and so is
    /// never counted among the swept set — the fresh mint is a genuinely new
    /// session, never a survivor.
    pub fn revoke_all(&mut self, principal: &str) {
        self.rev_epoch += 1;
        let new_epoch = self.rev_epoch;
        let ids: Vec<String> = self
            .by_principal
            .get(principal)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        for id in ids {
            if let Some(mut session) = self.get(principal, &id) {
                if session.revoked_epoch.is_none() {
                    session.revoked_epoch = Some(new_epoch);
                    self.put(&session);
                }
            }
        }
    }

    /// Selective sign-out-everywhere-but-here for `principal` (`revoke
    /// --all-but-current`): bumps the global epoch ONCE and stamps every
    /// currently-active session slot belonging to `principal` EXCEPT
    /// `keep_id` as revoked at that same new epoch — a single epoch-stamped
    /// sweep, exactly like [`SessionRegistry::revoke_all`], with one slot
    /// exempted. `keep_id` need not currently exist or be active; the sweep
    /// simply never touches that id.
    ///
    /// As with `revoke_all`, a session minted for `principal` AFTER this
    /// call (into any slot, including a swept one) carries a strictly later
    /// `mint_epoch` and so is never counted among the swept set.
    pub fn revoke_all_but_current(&mut self, principal: &str, keep_id: &str) {
        self.rev_epoch += 1;
        let new_epoch = self.rev_epoch;
        let ids: Vec<String> = self
            .by_principal
            .get(principal)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        for id in ids {
            if id == keep_id {
                continue;
            }
            if let Some(mut session) = self.get(principal, &id) {
                if session.revoked_epoch.is_none() {
                    session.revoked_epoch = Some(new_epoch);
                    self.put(&session);
                }
            }
        }
    }

    /// The full session record for `principal`'s `id` slot, if it exists
    /// (whether or not it is currently active) — backs CLI `show`.
    #[must_use]
    pub fn show(&self, principal: &str, id: &str) -> Option<Session> {
        self.get(principal, id)
    }

    /// Every currently-ACTIVE (unrevoked, unexpired at `now`) session
    /// belonging to `principal` — backs CLI `ls`.
    #[must_use]
    pub fn ls(&self, principal: &str, now: u64) -> Vec<Session> {
        self.by_principal
            .get(principal)
            .into_iter()
            .flatten()
            .filter_map(|id| self.get(principal, id))
            .filter(|s| s.is_active(now))
            .collect()
    }
}

/// Why [`SessionView::admit`] refused a bearer action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmitError {
    /// This view's own revocation watermark lags the registry's current one
    /// — a stale, quorum-unconfirmable read. Fail-closed: refuses to admit
    /// rather than fall back to a possibly-outdated grant, mirroring
    /// `pillar_wot_authority::ActError::StaleView` / the spec's
    /// `FailClosedUnderStaleView`.
    StaleView {
        /// This view's own watermark.
        local: u64,
        /// The registry's current (true) watermark.
        current: u64,
    },
    /// The view is fully fresh, but no session exists at that (principal,
    /// id) slot.
    NoSuchSession,
    /// The view is fully fresh and the session exists, but its generation has
    /// been revoked (individually, or swept by a `revoke-all`).
    Revoked,
    /// The view is fully fresh and the session is unrevoked, but it has
    /// expired as of the admission-time clock.
    Expired,
}

/// A snapshot of a bearer action admitted at a specific moment — the
/// counterpart of `pillar_wot_authority::ActedSnapshot` / the spec's ghost
/// `lastAct`, letting tests assert the acted-on session was genuinely active
/// (unrevoked, unexpired) at the exact epoch/time of admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedSnapshot {
    /// The revocation epoch in effect at the moment of admission.
    pub epoch: u64,
    /// The principal the admitted session belonged to.
    pub principal: String,
    /// The session id that was admitted.
    pub id: String,
}

/// A caller's fenced view of a [`SessionRegistry`]'s revocation epoch — the
/// quorum-fresh fenced read off pillar-coordination that
/// [`SessionView::admit`] gates bearer-action admission on. Refines the
/// spec's `freshMark[n]` restated over this registry's single scalar epoch.
#[derive(Clone, Debug, Default)]
pub struct SessionView {
    watermark: u64,
}

impl SessionView {
    /// A brand-new view with an empty (zero) watermark — maximally stale
    /// until it [`refresh`](Self::refresh)es.
    #[must_use]
    pub fn new() -> Self {
        SessionView::default()
    }

    /// This view's current local watermark.
    #[must_use]
    pub fn watermark(&self) -> u64 {
        self.watermark
    }

    /// Catch this view fully up to `registry`'s current revocation epoch — a
    /// quorum-fresh fenced read off pillar-coordination. A view that never
    /// refreshes, or refreshes against a stale replica, simply never re-syncs
    /// and so [`admit`](Self::admit) keeps refusing for staleness.
    pub fn refresh(&mut self, registry: &SessionRegistry) {
        self.watermark = registry.rev_epoch();
    }

    /// Attempt to admit a bearer action against session `id` of `principal`
    /// (revoke-before-act): succeeds only when this view's watermark exactly
    /// equals `registry`'s current one (a fully caught-up, quorum-fresh
    /// fenced read) AND the session, under that (necessarily current, since
    /// fencing forces equality) view, exists, is unrevoked, and is unexpired
    /// at `now`.
    ///
    /// Freshness unconfirmable (a lagging watermark) always REFUSES — never
    /// falls back to the session's last-known state — mirroring the spec's
    /// `FailClosedUnderStaleView`.
    ///
    /// # Errors
    ///
    /// See [`AdmitError`] — one variant per failing conjunct, checked in
    /// order: staleness, existence, revocation, expiry.
    pub fn admit(
        &self,
        registry: &SessionRegistry,
        principal: &str,
        id: &str,
        now: u64,
    ) -> Result<AdmittedSnapshot, AdmitError> {
        let current = registry.rev_epoch();
        if self.watermark != current {
            return Err(AdmitError::StaleView {
                local: self.watermark,
                current,
            });
        }
        let session = registry
            .show(principal, id)
            .ok_or(AdmitError::NoSuchSession)?;
        if session.is_revoked() {
            return Err(AdmitError::Revoked);
        }
        if session.is_expired(now) {
            return Err(AdmitError::Expired);
        }
        Ok(AdmittedSnapshot {
            epoch: current,
            principal: principal.to_owned(),
            id: id.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minted session admits under a fresh view; a subsequent `revoke <id>`
    /// makes every later bearer action against it fail closed.
    #[test]
    fn revoke_one_then_bearer_action_fails_closed() {
        let mut reg = SessionRegistry::new();
        reg.mint("alice", "s1", 0, 1000);

        let mut view = SessionView::new();
        view.refresh(&reg);
        assert!(view.admit(&reg, "alice", "s1", 10).is_ok());

        reg.revoke_one("alice", "s1").unwrap();
        view.refresh(&reg);
        assert_eq!(
            view.admit(&reg, "alice", "s1", 10),
            Err(AdmitError::Revoked)
        );
    }

    /// `revoke-all` leaves no admitting session for the principal: every
    /// pre-existing session is swept, while a session minted AFTER the sweep
    /// (even reusing an old slot id) is a genuinely new generation and
    /// admits.
    #[test]
    fn revoke_all_leaves_no_admitting_session_but_fresh_mint_is_new() {
        let mut reg = SessionRegistry::new();
        reg.mint("alice", "s1", 0, 1000);
        reg.mint("alice", "s2", 0, 1000);
        // Unrelated principal must be untouched by alice's sweep.
        reg.mint("bob", "s1", 0, 1000);

        reg.revoke_all("alice");

        let mut view = SessionView::new();
        view.refresh(&reg);
        assert_eq!(
            view.admit(&reg, "alice", "s1", 10),
            Err(AdmitError::Revoked)
        );
        assert_eq!(
            view.admit(&reg, "alice", "s2", 10),
            Err(AdmitError::Revoked)
        );
        // bob's session is unrelated to alice's revoke-all and still admits.
        assert!(view.admit(&reg, "bob", "s1", 10).is_ok());
        assert!(
            reg.ls("alice", 10).is_empty(),
            "no active session survives revoke-all"
        );

        // A concurrently-/subsequently-minted session into the SAME slot id
        // is a strictly newer generation, never a survivor of the sweep.
        let fresh = reg.mint("alice", "s1", 20, 1000);
        assert!(
            fresh.mint_epoch > 0,
            "fresh mint carries the post-sweep epoch"
        );
        assert!(!fresh.is_revoked());
        view.refresh(&reg);
        assert!(view.admit(&reg, "alice", "s1", 20).is_ok());
    }

    /// An expired session admits nothing, even though it was never revoked.
    #[test]
    fn expired_session_admits_nothing() {
        let mut reg = SessionRegistry::new();
        reg.mint("alice", "s1", 0, 100);

        let mut view = SessionView::new();
        view.refresh(&reg);
        assert!(view.admit(&reg, "alice", "s1", 99).is_ok());
        assert_eq!(
            view.admit(&reg, "alice", "s1", 100),
            Err(AdmitError::Expired)
        );
        assert_eq!(
            view.admit(&reg, "alice", "s1", 500),
            Err(AdmitError::Expired)
        );
        assert!(!reg.show("alice", "s1").unwrap().is_revoked());
    }

    /// A bearer action under a non-quorum-fresh (stale) revocation view is
    /// refused fail-closed, even though the session itself would otherwise
    /// still admit.
    #[test]
    fn non_quorum_fresh_view_refuses_fail_closed() {
        let mut reg = SessionRegistry::new();
        reg.mint("alice", "s1", 0, 1000);

        let mut view = SessionView::new();
        view.refresh(&reg); // watermark == 0, matches current rev_epoch() == 0

        // A revocation happens elsewhere that this view has not observed —
        // unrelated to alice's own session, but it still bumps the single
        // global epoch this view is fenced against.
        reg.mint("bob", "s-bob", 0, 1000);
        reg.revoke_one("bob", "s-bob").unwrap(); // bumps rev_epoch to 1

        assert_eq!(
            view.admit(&reg, "alice", "s1", 10),
            Err(AdmitError::StaleView {
                local: 0,
                current: 1
            })
        );

        // Refreshing catches the view up and it now sees reality plainly:
        // alice's own session is untouched and admits.
        view.refresh(&reg);
        assert!(view.admit(&reg, "alice", "s1", 10).is_ok());
    }

    /// Revocation is epoch-honored: an action evaluated after a revocation
    /// is judged against the CURRENT epoch, not the mint-time one, and is
    /// refused — the revocation is never missed just because the session was
    /// minted at an earlier epoch.
    #[test]
    fn revocation_honors_current_epoch_not_mint_epoch() {
        let mut reg = SessionRegistry::new();
        // Churn the epoch a bit before minting, so mint_epoch is nonzero.
        reg.mint("alice", "warmup", 0, 1000);
        reg.revoke_one("alice", "warmup").unwrap();

        let minted = reg.mint("alice", "s1", 0, 1000);
        assert_eq!(minted.mint_epoch, reg.rev_epoch());

        let mut view = SessionView::new();
        view.refresh(&reg);
        assert!(view.admit(&reg, "alice", "s1", 10).is_ok());

        reg.revoke_one("alice", "s1").unwrap();
        let after_revoke_epoch = reg.rev_epoch();
        assert!(after_revoke_epoch > minted.mint_epoch);

        view.refresh(&reg);
        assert_eq!(
            view.admit(&reg, "alice", "s1", 10),
            Err(AdmitError::Revoked)
        );
        assert_eq!(
            reg.show("alice", "s1").unwrap().revoked_epoch(),
            Some(after_revoke_epoch)
        );
    }

    /// Minting is idempotent-fresh per call: re-minting the same slot always
    /// resets any prior revocation stamp, never inherits it.
    #[test]
    fn remint_into_revoked_slot_clears_prior_revocation() {
        let mut reg = SessionRegistry::new();
        reg.mint("alice", "s1", 0, 1000);
        reg.revoke_one("alice", "s1").unwrap();
        assert!(reg.show("alice", "s1").unwrap().is_revoked());

        let remint = reg.mint("alice", "s1", 5, 1000);
        assert!(!remint.is_revoked());
        assert!(reg.show("alice", "s1").unwrap().is_active(10));
    }

    /// `revoke_one` on a nonexistent slot is refused and does not bump the
    /// epoch.
    #[test]
    fn revoke_one_unknown_session_is_refused() {
        let mut reg = SessionRegistry::new();
        assert_eq!(
            reg.revoke_one("alice", "ghost"),
            Err(RevokeError::NoSuchSession)
        );
        assert_eq!(reg.rev_epoch(), 0);
    }

    /// The K/V browse surface (`kv_collection`/`kv_keys`) is a real
    /// projection over the SAME backing store `mint`/`revoke_one` write to —
    /// a session's key appears the moment it is minted and is gone (no
    /// longer live) is not the contract here (sessions are never
    /// K/V-tombstoned, only revoked in place), but a distinct principal's
    /// slot is a distinct key, proving the storage-consumer swap onto the
    /// shared K/V surface actually holds real per-session records, not an
    /// opaque blob.
    #[test]
    fn kv_browse_surface_lists_live_session_keys() {
        let mut reg = SessionRegistry::new();
        reg.mint("alice", "s1", 0, 1000);
        reg.mint("alice", "s2", 0, 1000);
        reg.mint("bob", "s1", 0, 1000);

        assert_eq!(reg.kv_collection(), "sessions");
        let keys = reg.kv_keys();
        assert_eq!(keys.len(), 3, "one live K/V key per minted session");
        // Keys are `principal\0id` — every minted (principal, id) pair
        // appears exactly once.
        assert!(keys
            .iter()
            .any(|k| k.starts_with("alice") && k.ends_with("s1")));
        assert!(keys
            .iter()
            .any(|k| k.starts_with("alice") && k.ends_with("s2")));
        assert!(keys
            .iter()
            .any(|k| k.starts_with("bob") && k.ends_with("s1")));

        // Revoking does not remove the key from the browse surface — the
        // record is still live in the K/V surface, only its `revoked_epoch`
        // field changed.
        reg.revoke_one("alice", "s1").unwrap();
        assert_eq!(reg.kv_keys().len(), 3);
    }

    /// `mint_with_origin` stamps the device/origin; the legacy `mint`
    /// defaults to `"unknown"`; `touch` advances `last_seen` without
    /// disturbing `issued_at`/mint generation/admission.
    #[test]
    fn mint_with_origin_stamps_device_and_touch_advances_last_seen() {
        let mut reg = SessionRegistry::new();

        let legacy = reg.mint("alice", "s1", 0, 1000);
        assert_eq!(legacy.origin, "unknown");
        assert_eq!(legacy.last_seen, 0);

        let phone = reg.mint_with_origin("alice", "s2", 0, 1000, "iphone-15/198.51.100.7");
        assert_eq!(phone.origin, "iphone-15/198.51.100.7");
        assert_eq!(phone.last_seen, 0);
        assert_eq!(phone.issued_at, 0);

        assert!(reg.touch("alice", "s2", 42));
        let touched = reg.show("alice", "s2").unwrap();
        assert_eq!(touched.last_seen, 42, "touch advances last_seen");
        assert_eq!(touched.issued_at, 0, "touch never changes issued_at");
        assert_eq!(touched.origin, "iphone-15/198.51.100.7");
        assert!(touched.is_active(43), "touch does not itself admit/revoke");

        assert!(
            !reg.touch("alice", "ghost", 42),
            "touching a nonexistent slot is a no-op, not an error"
        );
    }

    /// `revoke_all_but_current` sweeps every OTHER active session for the
    /// principal under one epoch, leaving `keep_id` untouched and still
    /// admitting — while an unrelated principal is entirely unaffected. A
    /// subsequent fresh mint into a swept slot is a genuinely new
    /// generation, exactly as `revoke_all` guarantees.
    #[test]
    fn revoke_all_but_current_keeps_only_the_named_session() {
        let mut reg = SessionRegistry::new();
        reg.mint("alice", "s1", 0, 1000);
        reg.mint("alice", "s2", 0, 1000);
        reg.mint("alice", "s3", 0, 1000);
        reg.mint("bob", "s1", 0, 1000);

        let epoch_before = reg.rev_epoch();
        reg.revoke_all_but_current("alice", "s2");
        assert_eq!(
            reg.rev_epoch(),
            epoch_before + 1,
            "revoke_all_but_current is a single atomic epoch bump"
        );

        let mut view = SessionView::new();
        view.refresh(&reg);
        assert_eq!(
            view.admit(&reg, "alice", "s1", 10),
            Err(AdmitError::Revoked)
        );
        assert!(
            view.admit(&reg, "alice", "s2", 10).is_ok(),
            "the kept (current) session must still admit"
        );
        assert_eq!(
            view.admit(&reg, "alice", "s3", 10),
            Err(AdmitError::Revoked)
        );
        // bob is untouched by alice's sweep.
        assert!(view.admit(&reg, "bob", "s1", 10).is_ok());

        let active: Vec<String> = reg.ls("alice", 10).into_iter().map(|s| s.id).collect();
        assert_eq!(
            active,
            vec!["s2".to_string()],
            "only the kept session remains active"
        );

        // A fresh mint into a swept slot is a strictly newer generation.
        let fresh = reg.mint("alice", "s1", 20, 1000);
        assert!(fresh.mint_epoch > 0);
        assert!(!fresh.is_revoked());
    }

    /// `revoke_all_but_current` naming a `keep_id` that does not exist (or
    /// belongs to no active session) is not an error — it degrades to a full
    /// `revoke_all` of every session the principal actually holds.
    #[test]
    fn revoke_all_but_current_with_unknown_keep_id_revokes_everything() {
        let mut reg = SessionRegistry::new();
        reg.mint("alice", "s1", 0, 1000);
        reg.mint("alice", "s2", 0, 1000);

        reg.revoke_all_but_current("alice", "no-such-slot");

        let mut view = SessionView::new();
        view.refresh(&reg);
        assert_eq!(
            view.admit(&reg, "alice", "s1", 10),
            Err(AdmitError::Revoked)
        );
        assert_eq!(
            view.admit(&reg, "alice", "s2", 10),
            Err(AdmitError::Revoked)
        );
    }
}
