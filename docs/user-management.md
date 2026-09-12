# User management (IAM)

This document specifies the pillar node's user-management / IAM surface: user
lifecycle (invite → first sign-in → active → disabled), passwords (temporary,
self-change, rotation, admin reset), roles and groups with role attachment,
administration of other users' security keys, and per-user self-service profile
(name, email, password, keys). It is the design gate for that work: the
invariants here are model-checked in [`specs/UserLifecycle.tla`](../specs/UserLifecycle.tla)
before the Rust lands, per the repo's docs → TLA+ → Rust discipline.

It builds on the existing primitives — do not duplicate them:

- **Password custody** = argon2id nested-AEAD *sealed key offer*
  (`pillar-web/src/node_custody.rs`): the inner KEK is derived from the user's
  password and wraps their operational key; the outer layer is sealed under the
  node secret. There is **no password hash table** — a wrong password fails the
  AEAD open. Login (`NodeCustodyVerifier::admit`) strips the node seal, opens the
  inner layer with the password, and signs a nonce with the operational key.
- **Journal** = every mutation is a `PortalOp` appended to the IPFS-backed
  streaming journal and replayed on boot (`web_serve.rs` `PortalOp` +
  `apply_replayed`). There is no relational DB. Every feature below adds
  `PortalOp` variants and replay arms — that is the durable schema.
- **WebAuthn** credentials are filed by `user_handle`
  (`pillar-web/src/webauthn.rs`); per-user queries already exist.
- **RBAC** (`pillar-rbac`) decides capabilities from policies/grants over a WoT
  graph, with step-up. Today portal "roles" are free-form strings in a
  `members: handle→role` map, unconnected to RBAC capabilities. This design
  bridges them.

## 1. User record

A new in-memory `users: BTreeMap<handle, UserRecord>`, rebuilt from the journal:

```
UserRecord {
  handle:        String,          // stable id / login identifier
  display_name:  String,          // profile
  email:         String,          // profile (may be empty)
  status:        Invited | Active | Disabled,
  roles:         BTreeSet<String>,// role names (see §4)
  groups:        BTreeSet<String>,// group names (see §4)
  force_password_change: bool,    // set on invite/reset/admin-require
  require_passkey_enrollment: bool,// invite-time "must enrol a 2FA passkey"
  password_changed_at:   u64,     // unix secs; for rotation-age policy
  created_at:    u64,             // unix secs
  last_login_at: Option<u64>,     // unix secs
}
```

The existing `members` map is subsumed: replaying `AddMember{handle,role}` /
`SetMemberRole` creates/updates a `UserRecord` (status `Active`, the role added
to `roles`). Old journals therefore upgrade cleanly; the `members` map is kept
as a derived view for existing callers during transition.

## 2. Authentication & passwords

All password writes re-seal the operational key; none introduce a password hash.

### 2.1 Self password change (user knows their current password)
Unlock the operational key with the current password, re-derive a fresh KEK
`argon2id(new_password, new_salt)`, re-wrap the operational key, re-seal under
the node secret, and replace the stored offer.
- Op: `PasswordReseal { handle, sealed_offer, changed_at }`.
- Clears `force_password_change`; stamps `password_changed_at`.
- Endpoint: `POST /portal/profile/password` (self), body carries current + new
  password; the node verifies the current password by performing the unlock
  (a wrong current password fails the AEAD open → 403).

### 2.2 Invite (admin) — Keycloak-style options
Admin provisions a new user. As in Keycloak's "add user", the admin chooses,
per invite, among independent options; the account is created `Invited` and its
operational subkey is sealed under the chosen initial password.
- **Username/handle, display name, email** — the identity fields.
- **Initial password**: either **(a) admin-set** — the admin types the initial
  password directly — or **(b) auto-generated temporary** — the node draws a
  random temp password and returns it **once** to the admin (shown-once,
  delivered out of band; the node never emails it — no mailer, see §8). Either
  way the operational subkey is sealed under that initial password; the admin
  holds the freshly-generated operational key at provisioning time, so no escrow
  is needed.
- **Require password change on first login** (`force_password_change`): a
  per-invite toggle. Default **on** (the Keycloak "Temporary" default) — the
  invitee is forced into §2.1 before any other act. An admin may turn it **off**
  to hand out a permanent admin-set password (an immediately-usable account).
- **Require passkey enrolment** (`require_passkey_enrollment`): an optional
  per-invite toggle. When on, the user is admitted on first sign-in but is
  **contained** (exactly like a forced password change — see §2.4) until they
  enrol a WebAuthn passkey; the containment clears when the first credential is
  registered. This is Keycloak's "Configure OTP / WebAuthn" required action.
- Op: `InviteUser { handle, display_name, email, roles, sealed_offer,
  force_password_change, require_passkey_enrollment, created_at }`.
- The two required actions are **independent** and either/both/neither may be
  attached. An invite with neither is a ready-to-use account.

### 2.3 Rotation policy / "require new password" label
- `force_password_change` is the per-user label. An admin sets it with
  `RequirePasswordChange { handle }` to force a change at next login.
- Optional cell-wide `max_password_age` policy: at login, if
  `now - password_changed_at > max_password_age`, the session is admitted but
  `force_password_change` is treated as set (mandatory change before any other
  act). This is a policy label, not a separate op per user.

### 2.4 First-time / forced sign-in
When a session's user carries an outstanding onboarding **required action** —
`force_password_change` OR `require_passkey_enrollment` — the node admits the
session but **refuses every capability-gated act except the ones that clear the
requirement** (changing the caller's own password; enrolling the caller's own
passkey) plus a read of the caller's own profile, returning
`403 PASSWORD-CHANGE-REQUIRED` or `403 PASSKEY-ENROLLMENT-REQUIRED`
respectively. The console router sees the flags on the `AuthSession` and
redirects to the matching mandatory screen; no console section is reachable
until every required action is cleared. The two gates are symmetric and
independent — a user invited with both must both set a password and enrol a
passkey before the account is usable for anything else.

### 2.5 Admin password reset (user forgot; admin does NOT know the password)
The admin cannot unwrap the user's operational key (only the password or the
node secret can, and the node secret unseals only the outer layer). The reset
(admin-driven OR self-service "forgot password") therefore **re-provisions**:

- **(A) Re-provision (chosen, operator-confirmed).** Reset generates a **new
  operational subkey** for the user, sealed under a new (admin- or user-chosen)
  password, and rotates the user's identity so the old subkey is retired
  (reusing the existing `IdentityRotate` / WoT-revocation machinery). Sets
  `force_password_change` for an admin-driven reset. **The user's already-
  registered 2FA credentials are PRESERVED**: WebAuthn passkeys are filed
  per-`user_handle` (`pillar-web/src/webauthn.rs`), independent of the
  password-sealed operational key, so re-provisioning the key does NOT touch the
  credential registry — the user keeps every enrolled security key. No standing
  secret is introduced.
  - Op: `AdminResetPassword { handle, new_sealed_offer, new_subkey, changed_at }`
    (a self-service forgot-password path shares the same op, gated by an
    out-of-band recovery proof rather than `iam:users:write`).
- **(B) Cell escrow (rejected).** Wrap each user's operational key under a
  cell-held recovery key at provisioning so an admin can unwrap and re-seal.
  Rejected: it introduces a standing escrow secret whose compromise defeats
  every user's password.

## 3. Disable / enable users
`status = Disabled` makes `admit` refuse the login (before any password work),
returning `403 ACCOUNT-DISABLED`. Existing sessions are revoked on disable.
Disabled ≠ deleted (audit trail is retained); re-enable restores `Active`.
- Op: `SetUserStatus { handle, status }`.

## 4. Roles, groups, group-roles

### Roles
A **role** is a named set of RBAC capabilities. A managed `roles: name → {Capability}`
table bridges portal roles to `pillar_rbac`: a user's effective capabilities =
union of the capabilities of their directly-assigned roles and of the roles
attached to their groups. The `RbacDecider` consumes these as derived
`ExplicitGrant`s / policy at authorization time.
- Ops: `DefineRole { name, capabilities }`, `DeleteRole { name }`,
  `AssignRole { handle, role }`, `RevokeRole { handle, role }`.

### Groups (managed) and group-roles
A **group** is a named managed membership (a set of handles) with zero or more
roles attached; members inherit the group's roles' capabilities. This managed
group is distinct from the WoT-derived `pillar_rbac::Group` (a set of subkeys
signed by a common parent) — the managed group is an authorization convenience
that resolves to capabilities, and does not replace the WoT trust structure.
- Ops: `CreateGroup { name }`, `DeleteGroup { name }`,
  `AddToGroup { handle, group }`, `RemoveFromGroup { handle, group }`,
  `AssignGroupRole { group, role }`, `RevokeGroupRole { group, role }`.

### Admin capabilities (gate the IAM surface itself)
`iam:users:write` (invite/disable/profile of others), `iam:roles:write`,
`iam:groups:write`, `iam:credentials:manage` (others' security keys — §5).
Sensitive ones (reset, disable, credential management) require step-up
(a fresh WebAuthn assertion), reusing `StepUpPolicy`.

## 5. Managing other users' security keys (admin)
The WebAuthn primitives are handle-scoped, so admin management is the same
operations authorized by capability instead of self-ownership:
- `POST /iam/users/{handle}/credentials/list` — requires `iam:credentials:manage`.
- `POST /iam/users/{handle}/credentials/revoke` — same capability; the last-key
  confirmation of the self path still applies.
- Enrolling a *hardware* key requires the user's physical authenticator, so an
  admin cannot enroll one on the user's behalf. Instead an admin issues an
  **enrollment invite** the user completes at their own device; the admin can
  always **revoke**.

## 6. Self-service profile
- `GET /portal/profile` — the caller's `UserRecord` (name, email, status, roles,
  groups, key count).
- `PUT /portal/profile` — update `display_name`, `email` (self).
  Op: `SetProfile { handle, display_name, email }`.
- Password: §2.1. Security keys: the existing `CredentialsTile`.

## 7. Frontend surface
- **Profile** section (self): name/email form, password-change form, the
  existing Security keys tile.
- **Users** section (admin, gated on `iam:users:write`): user table
  (handle/name/email/status/roles/groups/last-login), invite dialog (name,
  email, roles, generated temp password shown once), per-user actions
  (disable/enable, require-password-change, reset password, manage roles/groups,
  manage security keys). Supersedes today's `MembersTile`.
- **Roles & Groups** section (admin, gated on `iam:roles:write` /
  `iam:groups:write`): define roles→capabilities, create groups, attach roles to
  groups, manage membership.
- **Forced password change**: a router guard on the `AuthSession`'s
  `force_password_change` flag redirects to a mandatory change screen.
- The client `AuthSession` gains `roles` / `capabilities` / `force_password_change`
  so the console can gate admin sections and enforce the forced-change redirect
  (server still authorizes every act — the client flags are for UX only).

## 8. Email
No mailer exists in the tree. `email` is stored on the profile for display and
future use; invites deliver the temporary password **out of band** (shown to the
admin once). A mail-sending integration is out of scope for this design and, if
added later, must live on the infrastructure side (SMTP creds are a deployment
secret), never embedded in the node source.

## 9. Invariants (model-checked in `specs/UserLifecycle.tla`)
1. **Onboarding required actions are optional and independent**: an invite may
   attach a forced first-login password change and/or a required passkey
   enrolment, or neither. (Design change 2026-09: this supersedes the former
   unconditional "Invited ⇒ force-change"; a forced change is now one optional
   required action, not a property of every invited user.)
2. **Forced-change containment** (`ForcedChangeContained`): while
   `force_password_change` is set, the only acts the user can perform are
   changing their own password and reading their own profile; every other
   capability-gated act is refused.
3. **Required-passkey containment** (`RequiredPasskeyContained`): while
   `require_passkey_enrollment` is set, the user likewise passes no capability
   gate — they may only enrol the passkey (and touch their own profile /
   password); the flag clears when the first credential registers.
4. **Disabled ⇒ no admit**: a `Disabled` user never obtains a session, and
   disabling revokes existing sessions.
5. **Password change requires the current password** — except the admin
   re-provision reset (§2.5A), which requires `iam:users:write` + step-up and
   issues a new subkey.
6. **Capability derivation**: a user's effective capabilities equal the union
   over their roles and their groups' roles; revoking a role/group membership
   removes exactly the capabilities it contributed (no residual grant)
   (`NoAmbientAuthority`).
7. **Last-key revoke needs confirmation** (already shipped): revoking a user's
   sole credential requires explicit confirmation, but is always possible.
8. **Admin credential management is capability-gated**: only a caller with
   `iam:credentials:manage` may list/revoke another user's keys; self-management
   is unchanged.

## 10. Phasing
1. **Shipped**: last-key revoke with confirmation (§9.6).
2. User record + self profile (name/email) + `SetProfile` + `/portal/profile`.
3. Disable/enable + status gate in `admit` + session revocation.
4. Roles + groups + group-roles + RBAC capability bridge + admin gating.
5. Passwords: self-change (§2.1), invite+temp (§2.2), forced-change guard
   (§2.4), rotation label (§2.3).
6. Admin password reset re-provision (§2.5A) — new key under the new password,
   registered 2FA credentials preserved (operator-confirmed).
7. Admin management of others' security keys (§5).
8. Frontend: Profile, Users, Roles & Groups sections; forced-change router guard.
