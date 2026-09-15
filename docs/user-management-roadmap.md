# User-management roadmap — features & their CLI/UI interface

Status: **planned backlog** (design of record for the next user-management epics).
This document is the intent the hive drives from; `ROI.md` refers to it. It extends
the shipped containment model in [`user-management.md`](user-management.md) (the
enrollment↔operational key split, delegated signing, and cryptographic
forced-change/require-change containment) and the credential model in
[`credentials.md`](credentials.md).

## How to read this doc

Each feature below carries a fixed shape so a honeybee can turn it into a task
without re-deriving the design:

- **Why** — the user/operator value.
- **Interface — CLI** — the `pillar …` verb(s), flags, and output. All user-mutating
  verbs ride the sealed control-op tier (`pillar_ops::ControlOp`), authorized by the
  decider and (once A1 lands) **delegated-signed** by the node on the caller's behalf
  — never a bare privileged REST call.
- **Interface — Portal/UI** — the wasm route/component and the HTTP endpoint(s) it
  calls. Endpoints are the existing `/portal/…` ingest surface unless noted.
- **Op / wire** — the `ControlOp`/`PortalOp` variant(s) touched (new variants are
  ADDITIVE and serde-default so a live cell's journal keeps replaying).
- **Gate** — the `pillar_rbac` capability required, and whether it is **step-up**
  gated (fresh WebAuthn assertion) and/or **TLA+**-gated (touches authority, so a
  spec + model-check precedes Rust per the non-negotiable docs→TLA+→Rust method).
- **Depends on** — hard prerequisites.

Capability names follow the existing lattice (`iam:users:write`,
`iam:users:read`, `cell:key-export`, …); new capabilities are called out explicitly.

---

## Group A — Leverage the cryptographic substrate

The delegated-signing kernel (`pillar_web::node_custody::sign_op_for`) and the
entropy-minted enrollment/operational offers already exist and are tested. These
features realize the capstone principle — **a Pillar mutation is never a privileged
REST call to a node** — and add credential lifecycle that a policy-bool system
cannot express.

### A1 — Delegated-signed user administration (retire the `iam_caller_gate` bool)

- **Why:** Today `/portal/users/*` mutates through a privileged REST handler gated by
  the app-level `iam_caller_gate` bool — the documented stopgap antipattern. Route
  every admin user-mutation through a **delegated-signed** `ControlOp::Users(...)` op
  instead: the client is keyless, the node signs on the caller's behalf with their
  unlocked operational key (`sign_op_for`), and the ingest authenticates + authorizes
  the signer. The bool gate demotes to a belt-and-suspenders assertion.
- **Interface — CLI:** unchanged verbs (`pillar user invite|disable|enable|
  require-change|set-password|ls|show`) — they already emit `ControlOp::Users`; this
  makes the PORTAL path converge onto the same signed tier.
- **Interface — Portal/UI:** `iam_console` user actions stop POSTing to
  `/portal/users/{invite,disable,…}` and instead call a single delegated-sign
  endpoint `POST /portal/op` with the serialized unsigned op body; the node
  step-ups, signs, and ingests it. Row actions and results render unchanged.
- **Op / wire:** existing `ControlOp::Users(UserOp::{Invite,Disable,Enable,
  RequireChange,SetPassword})`; new thin endpoint `POST /portal/op` (body = unsigned
  `PillarMessage` signing material + a fresh step-up token).
- **Gate:** `iam:users:write`; **step-up** (each delegated signature consumes a fresh
  single-use `StepUpToken`, already enforced by `sign_op_for`). No new authority ⇒ no
  new TLA+ obligation beyond the existing `UserLifecycle` invariants.
- **Depends on:** shipped kernel. **This is the recommended first slice.**

### A2 — Self-service operational-key rotation

- **Why:** Let any user voluntarily rotate their operational key (post-suspected-
  compromise, periodic hygiene) with no admin involvement, reusing the Slice-6
  ownership-proved rotation as a *user-initiated* action rather than an admin-forced
  one.
- **Interface — CLI:** `pillar identity rotate` (extend the existing verb) — prompts
  for current password, then new password; on success prints the new operational key
  fingerprint and revokes the prior offer.
- **Interface — Portal/UI:** `iam_console` → account menu → "Rotate my key"; a
  `change_password_page`-style dialog reused (current pw → new pw). On success the
  session is cryptographically stale, so dispatch `Logout` with "sign in with your new
  password" (identical to the forced-change flow).
- **Op / wire:** reuses `iam_set_password(force=false)` self-branch → `iam_mint_offer`
  (revoke prior + mint fresh under new password). No new `PortalOp`.
- **Gate:** session-authenticated (proves current pw); no admin capability. Not TLA+
  new (rotation already modeled as `PasswordChanged ⇒ opKey` mint).
- **Depends on:** shipped Slice-6 rotation.

### A3 — Session & device inventory + selective revoke

- **Why:** Sessions are keyed on the admitted subject and revoked wholesale on
  disable; expose them so a user (or admin) can see and kill ONE device without a
  full password reset.
- **Interface — CLI:** `pillar user sessions <handle>` (admin) / `pillar sessions`
  (self) → table `SESSION-ID  ORIGIN  ISSUED-AT  LAST-SEEN`; `pillar sessions revoke
  <session-id>` and `pillar sessions revoke --all`.
- **Interface — Portal/UI:** `iam_console` → "Active sessions" panel (a `data_table`)
  with a per-row **Revoke** and a **Revoke all others** button.
- **Op / wire:** new `ControlOp::Session(SessionOp::{List,Revoke{session_id},
  RevokeAllExcept{keep}})` — the `SessionOp` family already exists over the sealed
  tier; add `List`/selective `Revoke`. Journaled as `PortalOp::SessionRevoked`.
- **Gate:** self for own sessions; `iam:users:write` for another user's. Step-up for
  revoke-all. Session-lifecycle already TLA+-modeled in `SessionRegistry`; extend that
  spec for selective revoke.
- **Depends on:** session metadata (origin/last-seen) recorded at `store_session`.

### A4 — Break-glass recovery via admin quorum (M-of-N)

- **Why:** Recover a user who lost their password WITHOUT a unilateral admin reset —
  an M-of-N quorum of admins (over the WoT authority graph) co-signs a one-time
  recovery enrollment credential.
- **Interface — CLI:** `pillar user recover start <handle>` opens a recovery request;
  each approver runs `pillar user recover approve <request-id>` (step-up); on the Mth
  approval the node mints a single-use enrollment offer and prints/DMs the temp.
- **Interface — Portal/UI:** `iam_console` → "Recovery requests" queue; approvers see
  pending requests and an **Approve** (step-up) action; progress shows `k/M`.
- **Op / wire:** new `ControlOp::Recovery(RecoveryOp::{Start,Approve})`; approvals are
  signed acts appended to `act_log`; the mint reuses the enrollment-offer path.
- **Gate:** new capability `iam:users:recover`; **step-up** per approval; **TLA+**-gated
  (quorum threshold + "a recovered key regains exactly its prior authority, no more").
- **Depends on:** A1 (signed-op tier), attestation/quorum primitives in
  `pillar_trust_artifacts`.

---

## Group B — Standard IAM surface (mostly independent)

### B1 — Self-service password reset via verified email

- **Why:** Remove the admin from the common "I forgot my password" loop — issue a
  time-boxed single-use enrollment credential to a **verified** email, reusing the
  onboarding enrollment-offer machinery.
- **Interface — CLI:** `pillar user reset-request <handle-or-email>` (unauthenticated,
  rate-limited) → "if the address is verified, a reset link was sent". Admin override
  `pillar user reset-request --force`.
- **Interface — Portal/UI:** login page → "Forgot password?" → email entry →
  confirmation; the emailed link opens a `change_password_page` bound to the single-use
  token; on submit, an operational key mints under the new password.
- **Op / wire:** new `PortalOp::ResetTokenIssued{handle, token_hash, expires_at}` +
  reuse `iam_mint_offer` (enrollment) on redeem; token is single-use, hashed at rest.
- **Gate:** no session (identity proven by email possession + token); **rate-limited**;
  email address must carry a verified flag. Token lifecycle TLA+-gated (single-use,
  expiry, no privilege beyond a normal onboarding credential).
- **Depends on:** email-verification state on the user record (B4) + an SMTP/outbound
  channel supplied from infra config (never hardcoded).

### B2 — Credential policy (strength, breach-check, reuse prevention)

- **Why:** Enforce a minimum credential quality at every mint/change.
- **Interface — CLI:** `pillar cell password-policy show` / `… set --min-length …
  --breach-check on --history 5`. Rejections print the failing rule.
- **Interface — Portal/UI:** the change/reset dialogs show a live strength meter and
  the policy rules; server re-validates (client checks are advisory).
- **Op / wire:** policy is a cell resource (`ControlOp` cell-settings family); enforced
  inside `iam_set_password`/`iam_mint_offer` before sealing. Reuse-prevention stores
  salted hashes of the last N operational passwords on the user record.
- **Gate:** `cell:admin` to set policy; enforcement is unconditional. Breach-check uses
  a k-anonymity range query to an external list — endpoint from infra config.
- **Depends on:** none (self-contained); breach-check is optional/config-gated.

### B3 — Account lockout & rate-limiting

- **Why:** Blunt online password guessing. The single-use `StepUpToken` already burns
  on a wrong password; add per-identifier backoff + temporary lockout.
- **Interface — CLI:** `pillar user unlock <handle>` (admin) clears a lockout; `pillar
  user show <handle>` reports `failed-attempts` / `locked-until`.
- **Interface — Portal/UI:** login shows "too many attempts, try again in N minutes";
  `iam_console` row shows a **Locked** badge + **Unlock** action.
- **Op / wire:** per-identifier failure counter + `locked_until` on the auth path
  (in `dispatch_login` before `admit`); `PortalOp::UserUnlocked` for the admin clear.
- **Gate:** `iam:users:write` to unlock. No new authority; no TLA+ (a liveness/rate
  concern, not an authority one) beyond asserting a locked account never admits.
- **Depends on:** none.

### B4 — Passkey lifecycle (list / name / revoke / enforce ≥1)

- **Why:** WebAuthn enrollment exists; make the credentials manageable and let the
  `require_passkey_enrollment` action clear only once ≥1 authenticator is registered.
- **Interface — CLI:** `pillar user passkeys <handle>` → `CRED-ID  NAME  ADDED
  LAST-USED`; `pillar user passkey revoke <cred-id>`; self equivalents `pillar
  passkeys` / `pillar passkey add|revoke|rename`.
- **Interface — Portal/UI:** `iam_console` → "Passkeys" panel; **Add** drives the
  existing `/webauthn/register/*` ceremony; **Rename** / **Revoke** per row;
  last-credential revoke is refused with a clear message.
- **Op / wire:** existing `webauthn_rp` registry + new `PortalOp::PasskeyRevoked` /
  `PasskeyRenamed`; clearing `require_passkey_enrollment` is already wired
  (`iam_passkey_enrolled`) — surface it and enforce the ≥1 rule.
- **Gate:** self, or `iam:users:write` for another user; revoke is **step-up** gated.
- **Depends on:** shipped WebAuthn enrollment.

### B5 — Bulk invite / CSV onboarding

- **Why:** Onboard many users at once over the entropy-mint enrollment path.
- **Interface — CLI:** `pillar user invite --from users.csv` (columns
  `handle,email,force_change,require_passkey`) → per-row `INVITED … TEMP-PASSWORD …`
  or an error line; `--dry-run` validates without minting.
- **Interface — Portal/UI:** `iam_console` → "Bulk invite" → paste/upload CSV →
  preview table → confirm; results table with per-row status and copy-once temps.
- **Op / wire:** a loop over the existing invite op; each row is its own journaled
  `InviteUser` (no new variant). Temps are surfaced once, never stored in the clear.
- **Gate:** `iam:users:write`. No new authority.
- **Depends on:** none.

---

## Group C — AuthZ / org modeling (builds on roles/groups)

### C1 — Time-boxed / expiring role grants

- **Why:** Grants that auto-revoke at a deadline (contractors, temporary elevation).
- **Interface — CLI:** `pillar user grant <handle> <role> --until 2026-12-31T00:00Z`;
  `pillar user grants <handle>` lists `ROLE  GRANTED-BY  EXPIRES`.
- **Interface — Portal/UI:** role assignment dialog gains an optional **Expires** field;
  expired grants render struck-through until the sweep removes them.
- **Op / wire:** extend `ControlOp::Members(MembersOp::AssignRole)` with an optional
  `expires_at`; a periodic sweep emits `RevokeRole` when due (reuses the trust-artifact
  `Predicate::with_quota` budget as a time budget).
- **Gate:** `iam:roles:write`; **TLA+**-gated (an expired grant must confer no
  authority the instant it lapses).
- **Depends on:** a clock/sweep in the node loop.

### C2 — Just-in-time privilege elevation

- **Why:** Request → approve → *temporary* role, fully logged as signed acts.
- **Interface — CLI:** `pillar access request <role> --reason …`; approver `pillar
  access approve <req-id> --ttl 1h`; `pillar access ls` shows pending/active.
- **Interface — Portal/UI:** "Access requests" queue; approvers get **Approve**
  (step-up) with a TTL picker; requester sees status + countdown.
- **Op / wire:** `ControlOp::Access(AccessOp::{Request,Approve})`; approval issues a C1
  expiring grant; every step is an `act_log` signed event (provenance via
  `perform_signed_act`).
- **Gate:** requesting is open; approving needs the role's admin capability + step-up;
  **TLA+**-gated (elevation is bounded and auto-expiring).
- **Depends on:** C1.

### C3 — Delegated (scoped) administration

- **Why:** An admin who can manage only a subgroup, bounded by WoT reachable-depth —
  not the whole cell.
- **Interface — CLI:** `pillar user grant <handle> group-admin@<group>`; scoped verbs
  refuse targets outside the grantee's subtree with a clear reachability message.
- **Interface — Portal/UI:** scoped admins see only their subtree in `iam_console`;
  out-of-scope actions are hidden/disabled.
- **Op / wire:** capability carries a scope (`iam:users:write@<group>`); the decider
  already reasons over WoT depth — bound the catch-all policy to the scope.
- **Gate:** `cell:admin` to delegate; **TLA+**-gated (a scoped admin can never exceed
  its subtree — an authority-containment theorem).
- **Depends on:** roles/groups (shipped).

### C4 — Access-review / attestation campaigns

- **Why:** Periodic "confirm this user still needs this role" using the attestation
  builder — audit hygiene.
- **Interface — CLI:** `pillar access review start --role <r>`; reviewers `pillar
  access review attest <handle> --keep|--revoke`; `pillar access review status`.
- **Interface — Portal/UI:** a review campaign board; each reviewer gets a checklist
  producing `Attest` artifacts; unattested grants are auto-revoked at close.
- **Op / wire:** reuses `build_attestation` (`TrustProof` chain) per decision;
  auto-revoke reuses `RevokeRole`.
- **Gate:** `iam:roles:write`; attestations are signed by the reviewer's capacity.
- **Depends on:** attestation builder (shipped), C1 for auto-revoke.

---

## Group D — Audit & observability

### D1 — Per-user audit timeline

- **Why:** Every user-mgmt op is already a signed `act_log` event with a
  content-addressed `EventId`; expose a filterable per-user history.
- **Interface — CLI:** `pillar user audit <handle> [--since … --kind invite,rotate,…]`
  → `WHEN  ACTOR  ACT  EVENT-CID`.
- **Interface — Portal/UI:** `iam_console` → user detail → "Activity" tab (a
  `data_table` over the filtered act log) with the EventID as provenance.
- **Op / wire:** read-only projection over `act_log`; no new op.
- **Gate:** `iam:users:read` (self may read own). No authority change.
- **Depends on:** none (act log shipped).

### D2 — Security-events feed

- **Why:** Surface new-device sign-in, key rotation, require-change, disable, lockout
  to the user and to an admin panel.
- **Interface — CLI:** `pillar security events [--handle <h>]`.
- **Interface — Portal/UI:** an account "Security" panel (self) + an admin
  cell-wide feed; optional email/DM on high-signal events.
- **Op / wire:** derived from login/session/lifecycle events; no new authority.
- **Gate:** self for own events; `iam:users:read` cell-wide.
- **Depends on:** A3 session metadata for device/origin signals.

### D3 — Anomaly signals (impossible-travel / new-origin)

- **Why:** Flag suspicious logins using the origin/timestamp already recorded per
  session.
- **Interface — CLI:** shown inline in `pillar security events` as a `FLAG` column.
- **Interface — Portal/UI:** a badge on the security feed + optional step-up
  challenge on a flagged login.
- **Op / wire:** a pure heuristic over session origin/time; optionally forces a
  step-up before minting the session.
- **Gate:** none new; may *raise* the auth requirement (step-up), never lower it.
- **Depends on:** A3 session metadata.

---

## Recommended sequencing

1. **A1** — delegated-signed user administration; retires the `iam_caller_gate` bool.
   Completes the epic thesis; the kernel is built and only needs wiring.
2. **B1** — email self-service reset; highest user-visible value, reuses the hardened
   enrollment path (needs B4's verified-email flag + infra-supplied SMTP).
3. **A3** — session/device inventory + selective revoke; unlocks D2/D3.
4. **B3, B2, B4** — lockout, policy, passkey lifecycle (independent hardening).
5. **C1 → C2 → C3 → C4** — org-modeling ladder (each builds on the previous).
6. **A2, A4, D1, D2, D3** — rotation UX, break-glass, and the audit/observability
   surface, slotted as their dependencies land.

Every authority-touching item (A4, C1–C3, and the token-lifecycle in B1) follows the
non-negotiable **docs → TLA+ (model-checked) → Rust** order and lands a change doc
under `docs/` per task. No infrastructure identifiers ever enter this source; SMTP,
breach-list, and any external endpoints are supplied from deployment config.
