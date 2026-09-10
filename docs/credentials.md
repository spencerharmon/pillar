# Credentials

A **credential** is a hardware security key or passkey a user registers to prove
control of their identity — as a second factor at login, and (for keys that
support it) to unwrap operational key material. Pillar treats a user's
credentials as a **set**: you may hold *as many as you choose*, all
**simultaneously valid** and each **independently revocable**. There is no
privileged "primary" key; a single portable key is simply the one-element case.

> This document covers **user credentials** (login / second factor). It does not
> cover how a *node* holds its own sealing secret in hardware — a browser cannot
> drive a raw TPM or PKCS#11 module, so those are a separate, host-side concern
> documented in [node-custody.md](node-custody.md).

The credential model's safety claims are proved in
[`specs/WebAuthnCustody.tla`](../specs/WebAuthnCustody.tla), which model-checks a
set of simultaneously-valid records with independent registration, assertion,
and revocation.

## The only user credential kind: a WebAuthn passkey

Every user credential is a **WebAuthn / FIDO2 passkey** — a roaming security key
(YubiKey and similar) or a platform authenticator. It comes in two flavors that
differ only in the **rpId** (relying-party id) the credential is bound to:

| Flavor | Enrolled via | Bound rpId | Portable? |
|--------|--------------|-----------|-----------|
| **Browser passkey** | the portal in a browser (`navigator.credentials`) | the **serving origin's domain** — the browser forces this | roams between browsers on the *same* domain |
| **Portable passkey** | the `pillar webauthn` CLI (native CTAP2) | an **arbitrary domain you choose** (e.g. a stable public domain, or the cell IPNS name) | yes — works from any host, independent of which DNS name the node is served under |

### Why the rpId matters

The browser computes `rpIdHash = SHA-256(rpId)` and binds it into the
credential; at login the rpId must match or the key cannot be located. Two hard
rules follow:

- **A browser can only bind a credential to the domain it is served from.** It
  refuses any rpId that is not a registrable-domain suffix of the page origin
  (you get a `SecurityError`). So to bind a credential to a *different* domain
  you must use the CLI (native CTAP2 has no browser origin check).
- **A credential's rpId is fixed for its life.** Changing the serving domain
  invalidates browser passkeys bound to the old one. That is why a domain
  migration is *enroll-new-then-revoke-old* (below), never an in-place rename.

The portable passkey exists precisely to escape DNS coupling: bind it once to a
stable domain (or the cell IPNS name) and it keeps working no matter what
hostname the node is reached at.

## Managing your credentials

Three operations, available identically in the **portal UI** ("Security keys"
tile) and the **`pillar webauthn` CLI**.

### List

- **UI:** the "Security keys" tile shows every credential with its label, bound
  domain, created time, last-used time, and sign-count.
- **CLI:** `pillar webauthn list`

### Enroll (add)

A new credential becomes valid immediately and **joins** the set; it never
displaces an existing one.

- **UI:** type a label, click **Add a security key**, touch the device. The
  credential is bound to the domain you are visiting the portal on.
- **CLI (portable, choose the domain):**
  `pillar webauthn register --user <handle> --rp-id <domain> --label <name>`

### Revoke

Revocation is **fail-closed and permanent**: a revoked credential never admits
again and is never revived (`RevokedKeyNeverAdmits` / `RevokedStaysDead`).
Revoking one credential leaves every other one untouched.

- **UI:** click **Revoke** on a credential row.
- **CLI:** `pillar webauthn revoke --credential-id <b64url>`

Two guards protect you:

- You may revoke **only your own** credentials (a non-owned id returns
  *not found*, never leaking whether it exists).
- You cannot revoke your **last remaining** credential — that would silently
  drop the second factor you enforce. Enroll a replacement first.

## Step-by-step: create a single portable passkey for a domain

A portable passkey is bound to a domain **you choose** rather than the hostname
the portal happens to be served on, so it keeps working across DNS changes and
from headless hosts. It is created with the CLI (a browser can only bind to its
own origin). With a FIDO2 security key attached to the machine running `pillar`:

1. **Get a session token.** Either sign in —
   ```
   pillar login --domain node.example.com
   ```
   which exports `PILLAR_DOMAIN` / `PILLAR_TOKEN` for subsequent commands — or
   pass `--domain`/`--token` explicitly on each command below.

2. **Register the portable passkey, choosing its rpId (the domain to bind to).**
   ```
   pillar webauthn register \
       --user alice \
       --rp-id keys.example.com \
       --label portable-yubikey
   ```
   `--rp-id keys.example.com` is the domain the credential is bound to; it is
   independent of the node's current serving hostname. (Omit `--rp-id` to accept
   the node-provided default.) Touch the key when it blinks. The command prints
   `REGISTERED <credential-id>`.

3. **Confirm it landed.**
   ```
   pillar webauthn list
   ```
   The new row shows the label `portable-yubikey` and bound domain
   `keys.example.com`.

4. **Log in with it** (from any host that can reach the node), passing the same
   rpId it was bound to:
   ```
   pillar webauthn login --credential-id <credential-id> --rp-id keys.example.com
   ```

That one key is now a fully valid credential. Add more (portable or browser) at
any time; they are all valid together.

## Recommended patterns

- **Always keep a backup.** Enroll at least two authenticators before relying on
  2FA, so a lost key is a revoke — not a lockout. (The last-credential guard
  enforces the floor, but two keys is the real safety margin.)
- **Migrate a domain with no downtime.** Enroll a passkey bound to the new
  domain, verify login on both, then revoke the old-domain credential and cut
  DNS over.
- **Keep a portable break-glass key.** Register a portable passkey bound to a
  stable domain (or the cell IPNS name) for disaster-recovery access that does
  not depend on any particular hostname resolving.

## Safety properties (enforced)

- **SignCountMonotonic** — a stored sign-count only ever increases; a replayed
  or cloned-authenticator assertion with a stale/equal count is refused.
- **ChallengeFreshness** — every challenge is single-use and expires; an
  assertion against a consumed/expired challenge is refused.
- **CrossSurfaceUsability** — a credential registered in the browser admits via
  the CLI and vice-versa; both surfaces read/write the one shared record.
- **RevokedKeyNeverAdmits / RevokedStaysDead** — revocation is terminal.
- **Ownership binding** — during a login the asserted credential must belong to
  the user being admitted; one user's key can never satisfy another's gate.
- **Durable across restart** — enrollments, sign-counts, last-used stamps, and
  revocations are journaled and replayed, so the credential set (and its
  clone-detection state) survives a node restart.
