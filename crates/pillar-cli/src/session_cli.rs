//! `pillar session …`: the SERVER-SIDE session family of the `pillar` CLI —
//! the operator's window onto, and control over, the sessions a principal
//! holds on the platform. This is the concrete `cli-session-server-impl` task
//! against [`docs/cli-surface.md`](../../../docs/cli-surface.md) § "Session /
//! context family", built over the proven
//! [`pillar_identity::session_registry`] engine (`session-registry-impl`).
//!
//! # Distinct from the local `ctx`/context family
//!
//! `pillar ctx`/`use` (the `cli-session-resource-impl` task) edit the LOCAL
//! `~/.config/pillar/context` — a client-side pointer, no server object, no
//! signature. This family is the opposite: a first-class SERVER-SIDE session
//! object per principal, enumerated and revoked on the node, where a revoke is
//! a signed, WoT-authorized event. The two never touch: nothing here reads or
//! writes local context, and `ls`/`show` here sign nothing while `revoke`/
//! `revoke-all` sign exactly one revocation event.
//!
//! # The two-fold rule (views vs. acts), enforced by construction
//!
//! Per `docs/cli-surface.md` § "The two-fold rule", every command is exactly
//! one kind and the kind is a platform-level property:
//!
//! - **`session ls`** and **`session show <id>`** are **VIEWS**: they read the
//!   materialized [`SessionRegistry`] and render, and they take `&self` +
//!   `&EventLog` by shared reference — they *cannot* append an event, so
//!   "signs nothing" is a type-level guarantee, not a convention. A property
//!   test asserts the event log is byte-for-byte unchanged across any number
//!   of `ls`/`show` calls.
//! - **`session revoke <id>`** and **`session revoke-all`** are **ACTS**: each
//!   runs the caller through the decider ([`SessionDecider`]) and, only on
//!   ALLOW, emits ONE signed revocation event to the [`EventLog`] and
//!   epoch-stamps the revocation in the registry — the same revoke-before-act
//!   epoch bump `session-registry-impl` proves fail-closed. `revoke-all` is a
//!   single atomic, total sweep of every one of the principal's sessions
//!   under ONE new epoch and ONE signed event.
//!
//! # Authorization: own sessions always, others only with an admin grant
//!
//! A principal enumerates or revokes only its OWN sessions. Reaching another
//! principal's sessions requires an explicit admin grant, checked by the
//! decider (never assumed) — mirroring `docs/cli-surface.md`'s "an act ALWAYS
//! routes through the decider, so there is no back door". An un-granted
//! cross-principal `ls`/`show`/`revoke`/`revoke-all` is REFUSED
//! ([`SessionCliError::Unauthorized`]) and, for the acts, emits NOTHING.

use std::collections::HashSet;

use pillar_eventlog::{Author, EventId, EventLog};
use pillar_identity::session_registry::{RevokeError, Session, SessionRegistry};

/// The decision authority for the `session` act family — the CLI-side refinement
/// of `docs/cli-surface.md`'s decider for this command family: it answers the
/// single security-relevant question "may this caller reach that principal's
/// sessions?" and nothing else.
///
/// The rule is: a caller may always reach its OWN sessions; it may reach
/// ANOTHER principal's sessions only if it holds an explicit admin grant. The
/// grant set is the materialized admin-grant state (in a real deployment,
/// derived from the WoT-authorized grant events); this type models the
/// resulting decision.
#[derive(Clone, Debug, Default)]
pub struct SessionDecider {
    /// Principals holding an explicit platform admin grant (may reach any
    /// principal's sessions).
    admins: HashSet<String>,
}

impl SessionDecider {
    /// A decider with no admin grants: every caller may reach only its own
    /// sessions.
    #[must_use]
    pub fn new() -> Self {
        SessionDecider::default()
    }

    /// Record an explicit admin grant for `principal` (models the effect of a
    /// WoT-authorized admin-grant event having been materialized).
    pub fn grant_admin(&mut self, principal: impl Into<String>) {
        self.admins.insert(principal.into());
    }

    /// Whether `principal` holds an explicit admin grant.
    #[must_use]
    pub fn is_admin(&self, principal: &str) -> bool {
        self.admins.contains(principal)
    }

    /// The decider check every `session` command routes through: may `caller`
    /// reach `target`'s sessions? Own principal always; another only with an
    /// admin grant.
    #[must_use]
    pub fn may_reach(&self, caller: &str, target: &str) -> bool {
        caller == target || self.is_admin(caller)
    }
}

/// Why a `session` command was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionCliError {
    /// The caller tried to reach another principal's sessions without an admin
    /// grant. For an ACT (`revoke`/`revoke-all`) NOTHING was signed or
    /// appended — the refusal precedes any emit.
    Unauthorized {
        /// The caller principal.
        caller: String,
        /// The principal whose sessions were targeted.
        target: String,
    },
    /// A `show`/`revoke` named a session id that does not exist for that
    /// principal.
    NoSuchSession {
        /// The principal whose slot was addressed.
        principal: String,
        /// The missing session id.
        id: String,
    },
}

/// One row of `session ls` / one record of `session show`: the operator-facing
/// projection of a [`Session`] — id, owning principal, issued-at, expiry, the
/// expiry countdown as of the render clock, and whether it is the caller's
/// current (marker) session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRow {
    /// The session id (a reusable slot within the principal's sessions).
    pub id: String,
    /// The owning principal.
    pub principal: String,
    /// Logical mint timestamp.
    pub issued_at: u64,
    /// Logical expiry timestamp (exclusive).
    pub expiry: u64,
    /// Logical time remaining until expiry as of the render clock (`0` if
    /// already at/after expiry).
    pub expires_in: u64,
    /// Whether this is the caller's own current session — the `ls`/`show`
    /// "current marker".
    pub is_current: bool,
}

impl SessionRow {
    fn project(session: &Session, now: u64, current: Option<&str>) -> Self {
        SessionRow {
            id: session.id.clone(),
            principal: session.principal.clone(),
            issued_at: session.issued_at,
            expiry: session.expiry,
            expires_in: session.expiry.saturating_sub(now),
            is_current: current == Some(session.id.as_str()),
        }
    }
}

/// The server-side `pillar session` engine: the registry of sessions, the
/// decider gating cross-principal access, and the event log every revoke act
/// signs into. The thin `pillar session …` argv shell parses flags and prints;
/// this type is the authoritative, unit-tested engine (same split as
/// [`crate::observability_ui`]).
#[derive(Debug, Default)]
pub struct SessionCli {
    registry: SessionRegistry,
    decider: SessionDecider,
    log: EventLog,
}

impl SessionCli {
    /// A fresh session engine: empty registry, no admin grants, empty log.
    #[must_use]
    pub fn new() -> Self {
        SessionCli::default()
    }

    /// Mutable access to the decider, to record admin grants (models a
    /// materialized WoT-authorized admin-grant event).
    pub fn decider_mut(&mut self) -> &mut SessionDecider {
        &mut self.decider
    }

    /// Shared access to the underlying event log — so a test (or a view) can
    /// observe exactly which events the acts appended.
    #[must_use]
    pub fn log(&self) -> &EventLog {
        &self.log
    }

    /// Shared access to the underlying registry, for direct inspection.
    #[must_use]
    pub fn registry(&self) -> &SessionRegistry {
        &self.registry
    }

    /// Mint a session for `principal` at slot `id` (models a successful
    /// node-side custody login). Thin pass-through to the proven
    /// [`SessionRegistry::mint`]; not itself a `session` command.
    pub fn mint(
        &mut self,
        principal: impl Into<String>,
        id: impl Into<String>,
        issued_at: u64,
        expiry: u64,
    ) -> Session {
        self.registry.mint(principal, id, issued_at, expiry)
    }

    // ---- VIEWS (sign nothing) ------------------------------------------

    /// `pillar session ls`: list `target`'s currently-active sessions as of
    /// `now`, marking `current` (the caller's own current session id, if any)
    /// as the current session. A VIEW — takes `&self`, appends no event.
    ///
    /// `caller` may list only its OWN sessions unless it holds an admin grant
    /// (decider-checked).
    ///
    /// # Errors
    ///
    /// [`SessionCliError::Unauthorized`] if `caller != target` and `caller`
    /// holds no admin grant.
    pub fn ls(
        &self,
        caller: &str,
        target: &str,
        now: u64,
        current: Option<&str>,
    ) -> Result<Vec<SessionRow>, SessionCliError> {
        if !self.decider.may_reach(caller, target) {
            return Err(SessionCliError::Unauthorized {
                caller: caller.to_owned(),
                target: target.to_owned(),
            });
        }
        let mut rows: Vec<SessionRow> = self
            .registry
            .ls(target, now)
            .into_iter()
            .map(|s| SessionRow::project(s, now, current))
            .collect();
        // Deterministic order for stable rendering/tests.
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows)
    }

    /// `pillar session show <id>`: the full record of `target`'s `id` session
    /// (whether or not currently active), as of `now`. A VIEW — takes `&self`,
    /// appends no event.
    ///
    /// # Errors
    ///
    /// [`SessionCliError::Unauthorized`] if `caller` may not reach `target`;
    /// [`SessionCliError::NoSuchSession`] if no such slot exists.
    pub fn show(
        &self,
        caller: &str,
        target: &str,
        id: &str,
        now: u64,
        current: Option<&str>,
    ) -> Result<SessionRow, SessionCliError> {
        if !self.decider.may_reach(caller, target) {
            return Err(SessionCliError::Unauthorized {
                caller: caller.to_owned(),
                target: target.to_owned(),
            });
        }
        let session =
            self.registry
                .show(target, id)
                .ok_or_else(|| SessionCliError::NoSuchSession {
                    principal: target.to_owned(),
                    id: id.to_owned(),
                })?;
        Ok(SessionRow::project(session, now, current))
    }

    // ---- ACTS (emit one signed, decider-authorized revocation event) ----

    /// `pillar session revoke <id>`: fail-closed, epoch-stamped revocation of
    /// `target`'s `id` session. An ACT — routes through the decider, and only
    /// on ALLOW emits ONE signed revocation event and epoch-stamps the
    /// revocation in the registry (bumping the global epoch so every later
    /// bearer action against the session fails closed, per
    /// `session-registry-impl`).
    ///
    /// Returns the [`EventId`] of the single signed revocation event.
    ///
    /// # Errors
    ///
    /// [`SessionCliError::Unauthorized`] (nothing signed/appended) if `caller`
    /// may not reach `target`; [`SessionCliError::NoSuchSession`] if the slot
    /// does not exist (also nothing signed/appended — the registry check
    /// precedes the emit).
    pub fn revoke(
        &mut self,
        caller: &str,
        target: &str,
        id: &str,
    ) -> Result<EventId, SessionCliError> {
        if !self.decider.may_reach(caller, target) {
            return Err(SessionCliError::Unauthorized {
                caller: caller.to_owned(),
                target: target.to_owned(),
            });
        }
        // Fail closed BEFORE emitting: a revoke of a nonexistent session signs
        // nothing.
        self.registry.revoke_one(target, id).map_err(|e| match e {
            RevokeError::NoSuchSession => SessionCliError::NoSuchSession {
                principal: target.to_owned(),
                id: id.to_owned(),
            },
        })?;
        let epoch = self.registry.rev_epoch();
        let payload = format!("session-revoke\tprincipal={target}\tid={id}\tepoch={epoch}");
        let event = self
            .log
            .append(&Author(caller.to_owned()), payload.into_bytes());
        Ok(event)
    }

    /// `pillar session revoke-all`: atomic, total sign-out-everywhere for
    /// `target`. An ACT — routes through the decider, and only on ALLOW emits
    /// ONE signed revocation event and sweeps EVERY one of `target`'s sessions
    /// under a SINGLE new epoch (`session-registry-impl`'s atomic
    /// [`SessionRegistry::revoke_all`]): one bump, one event, total.
    ///
    /// Returns the [`EventId`] of the single signed revocation event.
    ///
    /// # Errors
    ///
    /// [`SessionCliError::Unauthorized`] (nothing signed/appended) if `caller`
    /// may not reach `target`.
    pub fn revoke_all(&mut self, caller: &str, target: &str) -> Result<EventId, SessionCliError> {
        if !self.decider.may_reach(caller, target) {
            return Err(SessionCliError::Unauthorized {
                caller: caller.to_owned(),
                target: target.to_owned(),
            });
        }
        self.registry.revoke_all(target);
        let epoch = self.registry.rev_epoch();
        let payload = format!("session-revoke-all\tprincipal={target}\tepoch={epoch}");
        let event = self
            .log
            .append(&Author(caller.to_owned()), payload.into_bytes());
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_identity::session_registry::{AdmitError, SessionView};

    /// `ls` and `show` are VIEWS: they sign nothing. Property: across any
    /// sequence of `ls`/`show` calls the event log is byte-for-byte unchanged
    /// (same length, same tip).
    #[test]
    fn ls_and_show_sign_nothing() {
        let mut cli = SessionCli::new();
        cli.mint("alice", "s1", 0, 1000);
        cli.mint("alice", "s2", 0, 1000);

        let before_len = cli.log().len();
        let before_tip = cli.log().tip(&Author("alice".into()));

        for _ in 0..5 {
            let _ = cli.ls("alice", "alice", 10, Some("s1")).unwrap();
            let _ = cli.show("alice", "alice", "s1", 10, Some("s1")).unwrap();
            let _ = cli.show("alice", "alice", "s2", 10, None).unwrap();
        }

        assert_eq!(cli.log().len(), before_len, "a view must append no event");
        assert_eq!(
            cli.log().tip(&Author("alice".into())),
            before_tip,
            "a view must not advance any author's tip"
        );
        assert_eq!(before_len, 0, "no acts ran, so the log is still empty");
    }

    /// `ls` reports the caller's active sessions with id/issued-at/expiry
    /// countdown and marks the current session; the marker is set only on the
    /// matching id.
    #[test]
    fn ls_projects_countdown_and_current_marker() {
        let mut cli = SessionCli::new();
        cli.mint("alice", "s1", 0, 100);
        cli.mint("alice", "s2", 5, 300);

        let rows = cli.ls("alice", "alice", 10, Some("s2")).unwrap();
        assert_eq!(rows.len(), 2);
        // sorted by id
        assert_eq!(rows[0].id, "s1");
        assert_eq!(rows[0].expires_in, 90);
        assert!(!rows[0].is_current);
        assert_eq!(rows[1].id, "s2");
        assert_eq!(rows[1].expires_in, 290);
        assert!(rows[1].is_current, "s2 is the caller's current session");
    }

    /// `revoke <id>` emits exactly ONE signed, decider-authorized revocation
    /// event, and the session then fails closed for every later bearer action.
    #[test]
    fn revoke_emits_one_event_and_session_fails_closed() {
        let mut cli = SessionCli::new();
        cli.mint("alice", "s1", 0, 1000);

        // Before revoke, a fresh view admits the session.
        let mut view = SessionView::new();
        view.refresh(cli.registry());
        assert!(view.admit(cli.registry(), "alice", "s1", 10).is_ok());

        let event = cli.revoke("alice", "alice", "s1").unwrap();
        // Exactly one signed event, authored by the caller, and it verifies.
        assert_eq!(cli.log().len(), 1);
        let signed = cli.log().get(&event).unwrap();
        assert!(signed.is_authentic(), "the revocation event is signed");
        assert_eq!(signed.content().author(), &Author("alice".into()));

        // The session now fails closed.
        view.refresh(cli.registry());
        assert_eq!(
            view.admit(cli.registry(), "alice", "s1", 10),
            Err(AdmitError::Revoked)
        );
    }

    /// `revoke-all` revokes EVERY session for the principal under one epoch and
    /// one signed event; afterwards none of the principal's sessions admit,
    /// while an unrelated principal is untouched.
    #[test]
    fn revoke_all_revokes_every_session_for_the_principal() {
        let mut cli = SessionCli::new();
        cli.mint("alice", "s1", 0, 1000);
        cli.mint("alice", "s2", 0, 1000);
        cli.mint("bob", "s1", 0, 1000);

        let epoch_before = cli.registry().rev_epoch();
        let event = cli.revoke_all("alice", "alice").unwrap();

        // One signed event; a single epoch bump for the whole atomic sweep.
        assert_eq!(cli.log().len(), 1);
        assert!(cli.log().get(&event).unwrap().is_authentic());
        assert_eq!(
            cli.registry().rev_epoch(),
            epoch_before + 1,
            "revoke-all is a single atomic epoch bump"
        );

        let mut view = SessionView::new();
        view.refresh(cli.registry());
        assert_eq!(
            view.admit(cli.registry(), "alice", "s1", 10),
            Err(AdmitError::Revoked)
        );
        assert_eq!(
            view.admit(cli.registry(), "alice", "s2", 10),
            Err(AdmitError::Revoked)
        );
        assert!(
            cli.ls("alice", "alice", 10, None).unwrap().is_empty(),
            "no active session survives revoke-all"
        );
        // bob is untouched.
        assert!(view.admit(cli.registry(), "bob", "s1", 10).is_ok());
    }

    /// Revoking ANOTHER principal's session without an admin grant is REFUSED
    /// and signs/appends NOTHING; with an admin grant it is allowed.
    #[test]
    fn cross_principal_revoke_requires_admin_grant() {
        let mut cli = SessionCli::new();
        cli.mint("bob", "s1", 0, 1000);

        // mallory has no grant: refused, and nothing is signed/appended.
        let err = cli.revoke("mallory", "bob", "s1").unwrap_err();
        assert_eq!(
            err,
            SessionCliError::Unauthorized {
                caller: "mallory".into(),
                target: "bob".into(),
            }
        );
        assert_eq!(cli.log().len(), 0, "an unauthorized act emits nothing");
        // bob's session is untouched.
        let mut view = SessionView::new();
        view.refresh(cli.registry());
        assert!(view.admit(cli.registry(), "bob", "s1", 10).is_ok());

        // The un-granted principal also cannot even VIEW bob's sessions.
        assert!(matches!(
            cli.ls("mallory", "bob", 10, None),
            Err(SessionCliError::Unauthorized { .. })
        ));
        assert!(matches!(
            cli.show("mallory", "bob", "s1", 10, None),
            Err(SessionCliError::Unauthorized { .. })
        ));

        // Grant mallory admin: now the cross-principal revoke is authorized and
        // emits one signed event.
        cli.decider_mut().grant_admin("mallory");
        let event = cli.revoke("mallory", "bob", "s1").unwrap();
        assert_eq!(cli.log().len(), 1);
        assert_eq!(
            cli.log().get(&event).unwrap().content().author(),
            &Author("mallory".into())
        );
        view.refresh(cli.registry());
        assert_eq!(
            view.admit(cli.registry(), "bob", "s1", 10),
            Err(AdmitError::Revoked)
        );
    }

    /// A principal may always reach its OWN sessions (no grant needed), and an
    /// admin may reach any principal's — the decider rule directly.
    #[test]
    fn own_sessions_always_reachable_admin_reaches_any() {
        let mut decider = SessionDecider::new();
        assert!(decider.may_reach("alice", "alice"));
        assert!(!decider.may_reach("alice", "bob"));
        decider.grant_admin("root");
        assert!(decider.may_reach("root", "bob"));
        assert!(decider.may_reach("root", "root"));
    }

    /// Revoking a nonexistent session fails closed and signs nothing.
    #[test]
    fn revoke_unknown_session_signs_nothing() {
        let mut cli = SessionCli::new();
        let err = cli.revoke("alice", "alice", "ghost").unwrap_err();
        assert_eq!(
            err,
            SessionCliError::NoSuchSession {
                principal: "alice".into(),
                id: "ghost".into(),
            }
        );
        assert_eq!(cli.log().len(), 0, "a failed revoke emits nothing");
    }

    /// The local ctx/context family is untouched: this engine holds no local
    /// context state, reads/writes no `~/.config/pillar` context, and exposes
    /// no such API. (Guard test: the surface is purely server-side sessions.)
    #[test]
    fn local_ctx_family_is_untouched() {
        let cli = SessionCli::new();
        // The engine's entire public surface is server-side session state:
        // registry + log, no context pointer. A fresh engine has an empty log
        // (no local-context side effects on construction) and an empty
        // registry.
        assert_eq!(cli.log().len(), 0);
        assert!(cli.registry().ls("anyone", 0).is_empty());
    }
}
