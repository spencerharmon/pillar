//! Account lockout + rate limiting over the fail-closed admit path
//! (ROI Priority 1 "User management & lifecycle" roadmap B3).
//!
//! This is a **counter/threshold gate layered on top of** the existing
//! fail-closed key/node-custody admit path ([`crate::key_login`] /
//! `pillar_cli`'s `dispatch_login`) — it introduces **no new authority path
//! and no new TLA+ gate**. The admit decision itself is unchanged: a login
//! still succeeds only if the WoT/nonce/signature preconditions hold. What
//! this module adds is a *throttle in front of* that decision:
//!
//! 1. **Failed-attempt lockout** ([`LockoutGate`]): every DENIED admit for an
//!    identifier increments a per-identifier failure counter; once it reaches
//!    the configured threshold the account is **locked** and every subsequent
//!    admit is refused *before* the underlying admit path is even consulted.
//!    A lockout **auto-expires** after a cooldown (so a genuine user is not
//!    permanently shut out by an attacker), and an **admin can unlock**
//!    immediately ([`LockoutGate::admin_unlock`]). A *successful* admit clears
//!    the counter ([`LockoutGate::record_success`]).
//! 2. **Rate limiting** ([`RateLimiter`]): a token-bucket per (key, class)
//!    caps the request rate on the sensitive unauthenticated endpoints —
//!    login, nonce issuance, and password-reset-request — so an attacker
//!    cannot spin the admit/nonce/reset machinery arbitrarily fast even
//!    below the lockout threshold, and cannot use a flood of *distinct*
//!    identifiers to sidestep the per-identifier lockout.
//!
//! Everything here is pure and deterministic: the caller supplies the current
//! time (`now`, whole seconds), so the same in-memory logic is exercised by
//! plain unit tests and by the live server (which passes a real monotonic
//! clock). No wall-clock read, no I/O, no background timer.

use std::collections::HashMap;

/// The class of a rate-limited request. Each class has its own independent
/// bucket per key, so exhausting the login budget never starves nonce
/// issuance and vice versa.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RequestClass {
    /// A `POST /login` admit attempt.
    Login,
    /// A `GET /nonce` challenge issuance.
    Nonce,
    /// A password-reset-request submission.
    ResetRequest,
}

impl RequestClass {
    /// A stable string tag, for logging / wire reasons.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            RequestClass::Login => "login",
            RequestClass::Nonce => "nonce",
            RequestClass::ResetRequest => "reset-request",
        }
    }
}

/// Tunable thresholds for the lockout gate. Defaults are conservative and
/// match the acceptance test's expectations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockoutPolicy {
    /// Number of consecutive failed admits that trips a lockout. Reaching
    /// exactly this count locks the account.
    pub max_failures: u32,
    /// Seconds a lockout persists before it auto-expires. After this many
    /// seconds past the lock instant the account is admittable again (and the
    /// failure counter is cleared on the next observation).
    pub lockout_secs: u64,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        LockoutPolicy {
            max_failures: 5,
            lockout_secs: 15 * 60,
        }
    }
}

/// The per-identifier failure/lock state.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AttemptState {
    failures: u32,
    /// `Some(instant)` = locked since `instant`; `None` = not locked.
    locked_at: Option<u64>,
}

impl AttemptState {
    fn fresh() -> Self {
        AttemptState {
            failures: 0,
            locked_at: None,
        }
    }
}

/// Why an admit was refused by the gate *before* the underlying admit path
/// ran. A `Locked` outcome is a throttle, never an authority statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockoutRefusal {
    /// The identifier is currently locked out. `retry_after_secs` is the
    /// whole-second cooldown remaining until auto-expiry.
    Locked {
        /// Seconds until the lock auto-expires and admits are allowed again.
        retry_after_secs: u64,
    },
}

/// A per-identifier failed-attempt lockout counter with admin-unlock and
/// auto-expiry, layered in front of the fail-closed admit path.
///
/// The gate is consulted in this order on each admit:
/// 1. [`check`](Self::check) — refuse up front if currently locked (this also
///    performs auto-expiry: an elapsed lock is cleared here).
/// 2. run the underlying admit path (unchanged).
/// 3. On success call [`record_success`](Self::record_success) (clears the
///    counter); on failure call [`record_failure`](Self::record_failure)
///    (increments and possibly locks).
#[derive(Clone, Debug, Default)]
pub struct LockoutGate {
    policy: LockoutPolicy,
    by_id: HashMap<String, AttemptState>,
}

impl LockoutGate {
    /// A gate with the given policy.
    #[must_use]
    pub fn new(policy: LockoutPolicy) -> Self {
        LockoutGate {
            policy,
            by_id: HashMap::new(),
        }
    }

    /// A gate with the default policy.
    #[must_use]
    pub fn with_default_policy() -> Self {
        Self::new(LockoutPolicy::default())
    }

    /// This gate's policy.
    #[must_use]
    pub fn policy(&self) -> LockoutPolicy {
        self.policy
    }

    /// Auto-expire an elapsed lock for `id` at `now`, mutating in place.
    /// Returns the (possibly cleared) state entry, creating a fresh one if
    /// absent. Internal helper shared by `check`/`record_*`.
    fn entry_expired(&mut self, id: &str, now: u64) -> &mut AttemptState {
        let policy = self.policy;
        let state = self
            .by_id
            .entry(id.to_owned())
            .or_insert_with(AttemptState::fresh);
        if let Some(locked_at) = state.locked_at {
            if now.saturating_sub(locked_at) >= policy.lockout_secs {
                // Auto-expiry: the cooldown elapsed — clear the lock AND the
                // counter so the user starts clean.
                state.failures = 0;
                state.locked_at = None;
            }
        }
        state
    }

    /// Whether `id` is currently locked out at `now`. On its own this does not
    /// mutate observable lock state except to auto-expire an elapsed lock.
    ///
    /// # Errors
    ///
    /// [`LockoutRefusal::Locked`] (with the remaining cooldown) if the
    /// identifier is locked; `Ok(())` if an admit may proceed.
    pub fn check(&mut self, id: &str, now: u64) -> Result<(), LockoutRefusal> {
        let policy = self.policy;
        let state = self.entry_expired(id, now);
        match state.locked_at {
            Some(locked_at) => {
                let elapsed = now.saturating_sub(locked_at);
                let retry_after_secs = policy.lockout_secs.saturating_sub(elapsed);
                Err(LockoutRefusal::Locked { retry_after_secs })
            }
            None => Ok(()),
        }
    }

    /// Record a FAILED admit for `id` at `now`: increment the counter and lock
    /// the account if it reaches the threshold. Returns `true` iff this call
    /// transitioned the account into the locked state.
    pub fn record_failure(&mut self, id: &str, now: u64) -> bool {
        let policy = self.policy;
        let state = self.entry_expired(id, now);
        if state.locked_at.is_some() {
            // Already locked — a failure while locked does not extend it.
            return false;
        }
        state.failures = state.failures.saturating_add(1);
        if state.failures >= policy.max_failures {
            state.locked_at = Some(now);
            return true;
        }
        false
    }

    /// Record a SUCCESSFUL admit for `id`: clear its failure counter and any
    /// lock (a success is proof the real user is back).
    pub fn record_success(&mut self, id: &str) {
        self.by_id.remove(id);
    }

    /// Admin action: immediately clear a lockout and the failure counter for
    /// `id`, regardless of remaining cooldown. Returns `true` iff `id` had any
    /// tracked state (was failing or locked) that this cleared.
    pub fn admin_unlock(&mut self, id: &str) -> bool {
        self.by_id.remove(id).is_some()
    }

    /// The current consecutive-failure count for `id` at `now` (0 if none or
    /// after an auto-expiry).
    #[must_use]
    pub fn failure_count(&mut self, id: &str, now: u64) -> u32 {
        self.entry_expired(id, now).failures
    }

    /// Whether `id` is locked at `now` (convenience over [`check`](Self::check)).
    #[must_use]
    pub fn is_locked(&mut self, id: &str, now: u64) -> bool {
        matches!(self.check(id, now), Err(LockoutRefusal::Locked { .. }))
    }
}

/// A token-bucket rate limiter keyed by `(key, class)`. Each bucket refills at
/// `refill_per_sec` tokens/second up to `capacity`; a request consumes one
/// token and is refused when the bucket is empty.
///
/// Keying is caller-chosen: the login/reset gates key by identifier (so one
/// account cannot be hammered and one flooding client cannot mint unbounded
/// nonces), and the nonce gate keys by client address. Deterministic in
/// `now` (whole seconds), so tests drive it without a real clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitPolicy {
    /// Maximum burst — the bucket's token capacity.
    pub capacity: u32,
    /// Steady-state refill rate, tokens per second.
    pub refill_per_sec: u32,
}

impl RateLimitPolicy {
    /// A policy allowing `capacity` burst and `refill_per_sec` steady rate.
    #[must_use]
    pub fn new(capacity: u32, refill_per_sec: u32) -> Self {
        RateLimitPolicy {
            capacity,
            refill_per_sec,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    /// Tokens available, scaled by `SCALE` to allow sub-integer refill.
    tokens: u64,
    last: u64,
}

/// Fixed-point scale so a `refill_per_sec` below one whole token still makes
/// progress between whole-second ticks.
const SCALE: u64 = 1_000;

/// A token-bucket rate limiter over `(key, class)` buckets.
#[derive(Clone, Debug, Default)]
pub struct RateLimiter {
    policies: HashMap<RequestClass, RateLimitPolicy>,
    buckets: HashMap<(String, RequestClass), Bucket>,
}

impl RateLimiter {
    /// An empty limiter with no class policies (every class then unlimited
    /// until a policy is set).
    #[must_use]
    pub fn new() -> Self {
        RateLimiter::default()
    }

    /// Set the policy for `class`. Overwrites any previous policy.
    pub fn set_policy(&mut self, class: RequestClass, policy: RateLimitPolicy) {
        self.policies.insert(class, policy);
    }

    /// Builder-style [`set_policy`](Self::set_policy).
    #[must_use]
    pub fn with_policy(mut self, class: RequestClass, policy: RateLimitPolicy) -> Self {
        self.set_policy(class, policy);
        self
    }

    /// Try to consume one token for `(key, class)` at `now`. Returns `true` if
    /// admitted (a token was available and consumed), `false` if rate-limited.
    /// A class with no configured policy is always admitted.
    pub fn allow(&mut self, key: &str, class: RequestClass, now: u64) -> bool {
        let Some(policy) = self.policies.get(&class).copied() else {
            return true;
        };
        let cap = u64::from(policy.capacity) * SCALE;
        let bucket = self
            .buckets
            .entry((key.to_owned(), class))
            .or_insert(Bucket {
                tokens: cap,
                last: now,
            });
        // Refill for elapsed whole seconds.
        let elapsed = now.saturating_sub(bucket.last);
        if elapsed > 0 {
            let refill = elapsed
                .saturating_mul(u64::from(policy.refill_per_sec))
                .saturating_mul(SCALE);
            bucket.tokens = (bucket.tokens.saturating_add(refill)).min(cap);
            bucket.last = now;
        }
        if bucket.tokens >= SCALE {
            bucket.tokens -= SCALE;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "alice@pillar";

    #[test]
    fn failures_below_threshold_do_not_lock() {
        let mut gate = LockoutGate::new(LockoutPolicy {
            max_failures: 5,
            lockout_secs: 900,
        });
        for i in 0..4 {
            assert!(gate.check(ALICE, 0).is_ok(), "not yet locked at {i}");
            assert!(!gate.record_failure(ALICE, 0), "no lock below threshold");
        }
        assert_eq!(gate.failure_count(ALICE, 0), 4);
        assert!(gate.check(ALICE, 0).is_ok());
    }

    #[test]
    fn threshold_locks_and_subsequent_admits_are_refused_before_the_path() {
        let mut gate = LockoutGate::new(LockoutPolicy {
            max_failures: 3,
            lockout_secs: 600,
        });
        assert!(!gate.record_failure(ALICE, 10));
        assert!(!gate.record_failure(ALICE, 11));
        // The threshold-th failure trips the lock.
        assert!(gate.record_failure(ALICE, 12), "3rd failure locks");
        // Now even a would-be-correct admit is refused up front.
        match gate.check(ALICE, 20) {
            Err(LockoutRefusal::Locked { retry_after_secs }) => {
                assert_eq!(retry_after_secs, 600 - (20 - 12));
            }
            other => panic!("expected Locked, got {other:?}"),
        }
    }

    #[test]
    fn lockout_auto_expires_after_cooldown() {
        let mut gate = LockoutGate::new(LockoutPolicy {
            max_failures: 2,
            lockout_secs: 100,
        });
        gate.record_failure(ALICE, 0);
        assert!(gate.record_failure(ALICE, 0), "locked at t=0");
        assert!(gate.is_locked(ALICE, 50), "still locked mid-cooldown");
        // At/after the cooldown the lock auto-expires and the counter resets.
        assert!(!gate.is_locked(ALICE, 100), "auto-expired at cooldown");
        assert_eq!(gate.failure_count(ALICE, 100), 0, "counter cleared");
        assert!(gate.check(ALICE, 100).is_ok());
    }

    #[test]
    fn admin_unlock_clears_immediately() {
        let mut gate = LockoutGate::new(LockoutPolicy {
            max_failures: 2,
            lockout_secs: 100_000,
        });
        gate.record_failure(ALICE, 0);
        gate.record_failure(ALICE, 0);
        assert!(gate.is_locked(ALICE, 1));
        assert!(gate.admin_unlock(ALICE), "had state to clear");
        assert!(!gate.is_locked(ALICE, 1), "unlocked before cooldown");
        assert_eq!(gate.failure_count(ALICE, 1), 0);
        // Unlocking an unknown/clean id is a no-op.
        assert!(!gate.admin_unlock("nobody@pillar"));
    }

    #[test]
    fn success_clears_the_counter() {
        let mut gate = LockoutGate::with_default_policy();
        gate.record_failure(ALICE, 0);
        gate.record_failure(ALICE, 0);
        assert_eq!(gate.failure_count(ALICE, 0), 2);
        gate.record_success(ALICE);
        assert_eq!(gate.failure_count(ALICE, 0), 0, "success resets");
    }

    #[test]
    fn lockout_is_per_identifier() {
        let mut gate = LockoutGate::new(LockoutPolicy {
            max_failures: 2,
            lockout_secs: 100,
        });
        gate.record_failure(ALICE, 0);
        gate.record_failure(ALICE, 0);
        assert!(gate.is_locked(ALICE, 1));
        // A different account is unaffected.
        assert!(!gate.is_locked("bob@pillar", 1));
        assert!(gate.check("bob@pillar", 1).is_ok());
    }

    #[test]
    fn rate_limiter_allows_burst_then_refuses_until_refill() {
        let mut rl = RateLimiter::new().with_policy(
            RequestClass::Login,
            RateLimitPolicy::new(3, 1), // burst 3, 1/sec
        );
        // Burst of 3 at t=0 all pass.
        for _ in 0..3 {
            assert!(rl.allow(ALICE, RequestClass::Login, 0));
        }
        // 4th at the same instant is refused.
        assert!(!rl.allow(ALICE, RequestClass::Login, 0));
        // Still refused before a full second elapses.
        assert!(!rl.allow(ALICE, RequestClass::Login, 0));
        // One second later, exactly one token has refilled.
        assert!(rl.allow(ALICE, RequestClass::Login, 1));
        assert!(!rl.allow(ALICE, RequestClass::Login, 1));
    }

    #[test]
    fn rate_limiter_classes_and_keys_are_independent() {
        let mut rl = RateLimiter::new()
            .with_policy(RequestClass::Login, RateLimitPolicy::new(1, 0))
            .with_policy(RequestClass::Nonce, RateLimitPolicy::new(1, 0));
        // Exhaust login for alice.
        assert!(rl.allow(ALICE, RequestClass::Login, 0));
        assert!(!rl.allow(ALICE, RequestClass::Login, 0));
        // Nonce for alice is a separate bucket — still available.
        assert!(rl.allow(ALICE, RequestClass::Nonce, 0));
        // Login for a different key is a separate bucket — still available.
        assert!(rl.allow("bob@pillar", RequestClass::Login, 0));
    }

    #[test]
    fn unconfigured_class_is_unlimited() {
        let mut rl = RateLimiter::new();
        for t in 0..1000 {
            assert!(rl.allow(ALICE, RequestClass::ResetRequest, t));
        }
    }

    #[test]
    fn request_class_tags_are_stable() {
        assert_eq!(RequestClass::Login.tag(), "login");
        assert_eq!(RequestClass::Nonce.tag(), "nonce");
        assert_eq!(RequestClass::ResetRequest.tag(), "reset-request");
    }
}
