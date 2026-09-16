//! Just-in-time privilege **elevation** — bounded-window, granter-capped
//! scoped authority that AUTO-DROPS, never standing.
//!
//! ROI Priority 1 "User management & lifecycle" roadmap C2: a subject may
//! request a just-in-time elevation to a HIGHER authority level for a bounded
//! window; the elevation is capped by its granter's own effective authority
//! and expires — once past its expiry it admits NOTHING. It is the
//! authority-touching complement of the ordinary time-bounded grant, gated on
//! the SAME `JitElevationIsBounded` invariant proven exhaustively by
//! `specs/GrantAuthority.tla`:
//!
//! ```text
//! JitElevationIsBounded ==
//!     \A g \in grants :
//!         g.kind = "jit" =>
//!             /\ g.level <= g.granterLevel
//!             /\ (now > g.expiry => g \notin LiveGrantsFor(g.subject))
//! ```
//!
//! This module is the executable image of that spec: an authority LATTICE
//! `0 ..= MAX_LEVEL` (0 = no authority), a grow-only ledger of grants each
//! stamping the granter's effective authority at issue time (`granter_level`),
//! and an [`AuthorityLedger`] whose [`AuthorityLedger::eff_auth`] folds only
//! the LIVE grants (not revoked, not expired) into a subject's effective
//! authority. A JIT elevation is [`AuthorityLedger::jit_elevate`]: a grant of
//! `kind = Jit` that (a) may not exceed the granter's current effective
//! authority (the cap), (b) must strictly RAISE the subject (an elevation, not
//! a lateral move), and (c) carries a future expiry after which it silently
//! stops admitting — the auto-drop. No wall-clock daemon sweeps expired
//! grants: expiry is evaluated at read time against `now`, so a JIT elevation
//! is INHERENTLY temporary — it cannot outlive its window even if nothing ever
//! deletes it, which is exactly what "auto-drops, never standing" means.
//!
//! The two invariants that make it "just in time" and not a permanent
//! escalation are asserted directly by [`AuthorityLedger::jit_elevation_is_bounded`]
//! over the whole ledger, mirroring the TLA+ `JitElevationIsBounded` state
//! predicate.

use std::collections::BTreeSet;

/// Top of the bounded authority lattice (`0 ..= MAX_LEVEL`). Mirrors the
/// spec's `MaxLevel` constant. `0` means "no authority" (no ambient level).
pub const MAX_LEVEL: u32 = 8;

/// Whether a grant is an ordinary delegated grant or a just-in-time
/// elevation. Only `Jit` grants are subject to
/// [`AuthorityLedger::jit_elevation_is_bounded`]'s elevation assertion; both
/// kinds obey the same live-set (expiry/revocation) machinery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantKind {
    /// An ordinary, delegated, time-bounded grant.
    Grant,
    /// A just-in-time elevation to a strictly higher level for a bounded
    /// window (roadmap C2).
    Jit,
}

/// A single issued grant. Grow-only: once issued it is never mutated; it
/// leaves the live set only by revocation or by `now` passing its `expiry`.
///
/// `granter_level` STAMPS the granter's effective authority at the exact
/// instant of issue — the fenced fact "this grant was capped by `<=` that".
/// The cap is asserted against this stamp, not the granter's LATER authority,
/// so a granter later losing its own authority never retroactively invalidates
/// the stamp (that cascade is handled by explicit revocation), exactly as the
/// spec's `granterLevel` field does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// Monotone grant id (1-based, allocation order).
    pub id: u64,
    /// The identity that issued (authorised) this grant.
    pub granter: String,
    /// The identity this grant raises.
    pub subject: String,
    /// The authority level this grant confers (`1 ..= MAX_LEVEL`).
    pub level: u32,
    /// Inclusive expiry tick: the grant is dead once `now > expiry`.
    pub expiry: u64,
    /// Ordinary grant vs. JIT elevation.
    pub kind: GrantKind,
    /// The granter's effective authority stamped at issue time (the cap).
    pub granter_level: u32,
}

impl Grant {
    /// A grant is LIVE at `now` iff it is neither revoked nor past its expiry.
    /// (Expiry is inclusive: `expiry = e` is live through `now == e`, dead at
    /// `now == e + 1`.) Revocation is passed in because the ledger owns the
    /// revoked set.
    fn is_live(&self, now: u64, revoked: &BTreeSet<u64>) -> bool {
        !revoked.contains(&self.id) && now <= self.expiry
    }
}

/// Why a [`AuthorityLedger::jit_elevate`] request was refused. Each maps to a
/// guard the spec's `JitElevate` action requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElevationError {
    /// The requested level exceeds the lattice (`> MAX_LEVEL`) or is `0`
    /// (an elevation must confer real authority).
    LevelOutOfRange {
        /// The rejected level.
        requested: u32,
    },
    /// The requested level exceeds the granter's effective authority — the
    /// cap. A JIT elevation can NEVER exceed its granter.
    ExceedsGranter {
        /// The requested level.
        requested: u32,
        /// The granter's current effective authority (the ceiling).
        granter_level: u32,
    },
    /// The requested level does not STRICTLY raise the subject — it is a
    /// lateral move or a demotion, not an elevation.
    NotAnElevation {
        /// The requested level.
        requested: u32,
        /// The subject's current effective authority.
        subject_level: u32,
    },
    /// The expiry is not in the future (`< now`): an elevation issued
    /// already-dead is pointless and refused.
    ExpiryInPast {
        /// The rejected expiry.
        expiry: u64,
        /// The current wall-clock tick.
        now: u64,
    },
}

/// The grow-only authority ledger: every grant ever issued plus the set of
/// revoked grant ids and the current wall-clock `now`. Effective authority is
/// a pure fold over the LIVE grants, so expiry needs no sweeper — a JIT
/// elevation auto-drops the instant `now` passes its window.
#[derive(Clone, Debug, Default)]
pub struct AuthorityLedger {
    grants: Vec<Grant>,
    revoked: BTreeSet<u64>,
    now: u64,
    next_id: u64,
    /// The trust anchor: unconditionally holds `MAX_LEVEL`. `None` = no anchor
    /// (every level derives from a grant chain).
    owner: Option<String>,
}

impl AuthorityLedger {
    /// A fresh ledger at `now = 0` with no grants and an optional trust anchor
    /// (`owner`) that unconditionally holds `MAX_LEVEL`.
    pub fn new(owner: Option<&str>) -> Self {
        AuthorityLedger {
            grants: Vec::new(),
            revoked: BTreeSet::new(),
            now: 0,
            next_id: 1,
            owner: owner.map(str::to_owned),
        }
    }

    /// The current wall-clock tick.
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Advance wall-clock to `t`. Monotone non-decreasing: a request to move
    /// backwards is ignored (time never rewinds), so an expired JIT elevation
    /// can never be revived by winding the clock back.
    pub fn tick_to(&mut self, t: u64) {
        if t > self.now {
            self.now = t;
        }
    }

    /// The live grants naming `s` as subject at the current `now`.
    fn live_grants_for<'a>(&'a self, s: &'a str) -> impl Iterator<Item = &'a Grant> {
        self.grants
            .iter()
            .filter(move |g| g.subject == s && g.is_live(self.now, &self.revoked))
    }

    /// Effective authority of `n`: the trust anchor is unconditionally
    /// `MAX_LEVEL`; anyone else is the max level over their LIVE grants (`0` if
    /// none — no ambient authority). A pure, decidable fold, exactly the
    /// spec's `EffAuth`.
    pub fn eff_auth(&self, n: &str) -> u32 {
        if self.owner.as_deref() == Some(n) {
            return MAX_LEVEL;
        }
        self.live_grants_for(n).map(|g| g.level).max().unwrap_or(0)
    }

    /// Issue an ordinary delegated grant: `granter` confers `level` on
    /// `subject` through `expiry`. Capped at the granter's current effective
    /// authority. Returns the new grant id.
    pub fn grant(
        &mut self,
        granter: &str,
        subject: &str,
        level: u32,
        expiry: u64,
    ) -> Result<u64, ElevationError> {
        if level == 0 || level > MAX_LEVEL {
            return Err(ElevationError::LevelOutOfRange { requested: level });
        }
        if expiry < self.now {
            return Err(ElevationError::ExpiryInPast {
                expiry,
                now: self.now,
            });
        }
        let granter_level = self.eff_auth(granter);
        if level > granter_level {
            return Err(ElevationError::ExceedsGranter {
                requested: level,
                granter_level,
            });
        }
        Ok(self.push(
            granter,
            subject,
            level,
            expiry,
            GrantKind::Grant,
            granter_level,
        ))
    }

    /// Request a JIT elevation: `granter` raises `subject` to `level` for a
    /// bounded window ending at `expiry`. Enforces every `JitElevate` guard:
    /// the level is in-range, the expiry is in the future, the level does not
    /// exceed the granter (the cap), and it STRICTLY raises the subject (a
    /// real elevation). On success the elevation is live only until `now`
    /// passes `expiry` — it auto-drops with no further action. Returns the new
    /// grant id.
    pub fn jit_elevate(
        &mut self,
        granter: &str,
        subject: &str,
        level: u32,
        expiry: u64,
    ) -> Result<u64, ElevationError> {
        if level == 0 || level > MAX_LEVEL {
            return Err(ElevationError::LevelOutOfRange { requested: level });
        }
        if expiry < self.now {
            return Err(ElevationError::ExpiryInPast {
                expiry,
                now: self.now,
            });
        }
        let granter_level = self.eff_auth(granter);
        if level > granter_level {
            return Err(ElevationError::ExceedsGranter {
                requested: level,
                granter_level,
            });
        }
        let subject_level = self.eff_auth(subject);
        if level <= subject_level {
            return Err(ElevationError::NotAnElevation {
                requested: level,
                subject_level,
            });
        }
        Ok(self.push(
            granter,
            subject,
            level,
            expiry,
            GrantKind::Jit,
            granter_level,
        ))
    }

    fn push(
        &mut self,
        granter: &str,
        subject: &str,
        level: u32,
        expiry: u64,
        kind: GrantKind,
        granter_level: u32,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.grants.push(Grant {
            id,
            granter: granter.to_owned(),
            subject: subject.to_owned(),
            level,
            expiry,
            kind,
            granter_level,
        });
        id
    }

    /// Explicitly revoke a grant by id. Grow-only and idempotent: a revoked
    /// grant contributes nothing forever.
    pub fn revoke(&mut self, id: u64) {
        self.revoked.insert(id);
    }

    /// Whether the grant `id` currently admits (is live and contributes to its
    /// subject's effective authority). `false` for an unknown, revoked, or
    /// expired id.
    pub fn admits(&self, id: u64) -> bool {
        self.grants
            .iter()
            .find(|g| g.id == id)
            .map(|g| g.is_live(self.now, &self.revoked))
            .unwrap_or(false)
    }

    /// The executable image of the TLA+ `JitElevationIsBounded` invariant:
    /// EVERY JIT elevation in the ledger is (a) capped by its granter — its
    /// level never exceeds the granter's stamped effective authority — and (b)
    /// bounded in time — once past its expiry it admits nothing (is absent
    /// from its subject's live set). Returns `true` iff both hold for all JIT
    /// grants at the current `now`. A JIT elevation that ever violated either
    /// would be a permanent privilege escalation; this predicate is what
    /// guarantees it is not.
    pub fn jit_elevation_is_bounded(&self) -> bool {
        self.grants
            .iter()
            .filter(|g| g.kind == GrantKind::Jit)
            .all(|g| {
                let capped = g.level <= g.granter_level;
                let bounded = if self.now > g.expiry {
                    // Past its window it must contribute nothing to its subject.
                    !self.live_grants_for(&g.subject).any(|live| live.id == g.id)
                } else {
                    true
                };
                capped && bounded
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchored() -> AuthorityLedger {
        AuthorityLedger::new(Some("owner"))
    }

    #[test]
    fn owner_holds_max_level() {
        let l = anchored();
        assert_eq!(l.eff_auth("owner"), MAX_LEVEL);
        assert_eq!(l.eff_auth("nobody"), 0);
    }

    #[test]
    fn jit_elevation_is_capped_by_granter() {
        let mut l = anchored();
        // owner grants alice level 4 (standing).
        let g = l.grant("owner", "alice", 4, 100).unwrap();
        assert!(l.admits(g));
        assert_eq!(l.eff_auth("alice"), 4);
        // alice may JIT-elevate bob up to her own cap (4), never above.
        assert!(matches!(
            l.jit_elevate("alice", "bob", 5, 50),
            Err(ElevationError::ExceedsGranter {
                requested: 5,
                granter_level: 4
            })
        ));
        let e = l.jit_elevate("alice", "bob", 4, 50).unwrap();
        assert!(l.admits(e));
        assert_eq!(l.eff_auth("bob"), 4);
        assert!(l.jit_elevation_is_bounded());
    }

    #[test]
    fn jit_elevation_auto_drops_at_expiry() {
        let mut l = anchored();
        let e = l.jit_elevate("owner", "carol", 6, 10).unwrap();
        assert_eq!(l.eff_auth("carol"), 6);
        assert!(l.admits(e));
        // Through the window it is live.
        l.tick_to(10);
        assert!(l.admits(e));
        assert_eq!(l.eff_auth("carol"), 6);
        // One tick past expiry it auto-drops — no revoke, no sweeper.
        l.tick_to(11);
        assert!(!l.admits(e));
        assert_eq!(l.eff_auth("carol"), 0, "elevation is never standing");
        assert!(l.jit_elevation_is_bounded());
    }

    #[test]
    fn jit_must_strictly_raise_subject() {
        let mut l = anchored();
        l.grant("owner", "dave", 3, 100).unwrap();
        assert!(matches!(
            l.jit_elevate("owner", "dave", 3, 50),
            Err(ElevationError::NotAnElevation {
                requested: 3,
                subject_level: 3
            })
        ));
    }

    #[test]
    fn expiry_in_past_is_refused() {
        let mut l = anchored();
        l.tick_to(20);
        assert!(matches!(
            l.jit_elevate("owner", "erin", 5, 19),
            Err(ElevationError::ExpiryInPast {
                expiry: 19,
                now: 20
            })
        ));
    }

    #[test]
    fn invariant_holds_across_the_ledger() {
        let mut l = anchored();
        l.grant("owner", "a", 5, 1000).unwrap();
        l.jit_elevate("a", "b", 5, 5).unwrap();
        l.jit_elevate("owner", "c", 7, 8).unwrap();
        for t in 0..=12 {
            l.tick_to(t);
            assert!(l.jit_elevation_is_bounded(), "bounded at now={t}");
        }
    }
}
