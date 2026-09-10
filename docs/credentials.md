# Credentials

A **credential** is any hardware- or software-held secret a user registers to
(a) prove control of an identity as a second factor at login, and/or (b) unwrap
operational key material ("custody"). Pillar treats credentials as a **set**:
a user holds *as many as they choose*, of *different kinds*, all
**simultaneously valid**. There is no privileged "primary" credential — a
single portable key is just the special case of a one-element set.

This document is the source of truth for the credential model. Its safety
claims are proved in `specs/WebAuthnCustody.tla` (login/assertion) and
`specs/NodeCustodyLogin.tla` (node-key custody); the multi-credential registry
invariants are specified in `specs/CredentialRegistry.tla`.

> Status: the shared credential record, cross-surface (browser + CLI) WebAuthn
> assertion, per-credential revocation, sign-count clone detection, and the
> optional PRF operational-unlock are implemented and enforced. The rich
> management surface (kind/label/created/last-used metadata, the list endpoint,
> per-kind create, and the portal management table) is the registry phase
> tracked against `specs/CredentialRegistry.tla`; sections below mark
> **[implemented]** vs **[registry phase]** so nothing here is mistaken for a
> capability the node does not yet expose.

## The core principle: a set of simultaneously-valid credentials

Every management pattern a user wants is a consequence of one primitive:
**a user's credentials form a set, each independently valid and independently
revocable.**

- **Backup keys** — register two (or more) authenticators. Losing one leaves
  the others valid; revoke the lost one without disturbing the rest.
- **Domain migrations** — enroll a credential bound to the new domain *before*
  cutting DNS over, run with both valid, then revoke the old one. No lockout
  window.
- **Multiple TPMs** — seal a node's custody to several TPMs so any one machine
  can unwrap; lose a machine, revoke its TPM credential, the node still starts.
- **Mixed kinds** — a browser passkey for daily login, a portable CLI key for
  headless/DR access, and a TPM for the node itself can all be valid at once.

A "single portable credential" is desirable and supported, but it is a
**subset** of "support as many as the user creates." The registry is built for
the general case; portability falls out of it.

## Credential kinds and what each is bound to

Every kind proves possession, but each is *scoped* — bound to something that
must be present for the credential to work. The scope determines portability
and how a migration is performed. **None of the non-browser scopes is a DNS
domain**, and only the browser path is domain-enforced.

| Kind | Backend | Bound to | Portable? | Domain-enforced? |
|------|---------|----------|-----------|------------------|
| Browser passkey | WebAuthn via `navigator.credentials` | **rpId = a registrable suffix of the serving origin** (DNS) | Roaming keys move between browsers on the *same* domain | **Yes** — the browser refuses `rpId` that is not a suffix of the origin |
| Portable passkey | Native CTAP2 (`ctap-hid-fido2`) | **rpId = an arbitrary stable string** (pillar uses the **cell IPNS name**) | Yes — DNS-independent; works anywhere the cell is reachable | No — native CTAP2 has no origin check |
| TPM | `tss-esapi` / tpm2-tss | A **specific TPM chip** + persistent parent (SRK), optionally a **PCR/boot-state** policy | No — sealed blob unseals only on that chip | No |
| PKCS#11 | `cryptoki` | A **specific token** (by label/slot) + PIN + a key object on the device | Tied to that HSM (or a replicated one) | No |

### rpId: the same word, two opposite rules

The `rpId` (relying-party id) is where the "domain" question bites, and it
behaves **oppositely** on the two passkey paths:

- **Browser passkey — `rpId` is DNS and browser-enforced.** The browser
  computes `rpIdHash = SHA-256(rpId)` and binds it into the (non-resident)
  credential id; it *refuses* to run a ceremony whose `rpId` is not a
  registrable-domain suffix of the page's origin (you get a `SecurityError`:
  "The operation is insecure"). Pillar therefore lets the browser default
  `rpId` to the serving origin at both registration and assertion — the two
  must match or the stored credential cannot be located. **Changing the serving
  domain invalidates browser credentials bound to the old one**; that is why a
  domain migration is *enroll-new-then-revoke-old*, not an in-place rename.

- **Portable passkey — `rpId` is an arbitrary, stable KDF label.** Native CTAP2
  has no browser and no origin check, so `rpId` is a free string pillar
  chooses. Pillar uses the **cell IPNS name**, which is stable for the life of
  the cell and independent of any DNS name the cell happens to be served under.
  This is what makes the credential portable: the same physical key unwraps
  custody or logs in from any host that can reach the cell, regardless of
  domain. **The hard rule here is stability, not domain-match**: the PRF
  (`hmac-secret`) output is deterministic in `(credential, rpId, salt)`, so if
  `rpId` ever changed, the derived key-encryption key would change and custody
  unwrap would fail closed. The cell IPNS name is chosen precisely because it
  never changes.

A single physical key *can* serve both roles, but only if one `rpId` satisfies
both rules at once — which forces it to the serving domain and makes it
non-portable. The registry's answer is not to overload one credential: register
**two** records on the same key (a browser-passkey record bound to the domain
and a portable-passkey record bound to the IPNS name). Both are valid; each is
used on its own surface.

## PRF / `hmac-secret`: what it is and where it's used

**PRF** ("pseudo-random function") is the WebAuthn name for the authenticator's
CTAP2 **`hmac-secret`** extension. You give the authenticator a fixed 32-byte
salt; inside the secure element it computes `HMAC(device_secret, salt)` and
returns 32 bytes. It is:

- **Deterministic** in `(credential, salt)` — same inputs, same output, forever.
- **Unextractable** — the HMAC key never leaves the hardware; the output can
  only be *evaluated* by physically exercising the key.
- **Independent of the signature** — it is a side output of the assertion, not
  the ECDSA/Ed25519 signature that proves possession.

Pillar uses the PRF output two ways:

1. **Optional operational-key-unlock on login** — when a browser login yields a
   PRF output, the RP derives a 32-byte unlock secret (`HKDF(prf, credential_id,
   "…/prf-unlock-v1")`). **This is optional**: most authenticators/browsers do
   not implement `prf`, so the second factor is the *verified assertion*, never
   the presence of a PRF output. A login with no PRF output still succeeds; the
   operational unlock is simply absent (`UNLOCKED - <token>`).
2. **`PasskeyCustody` KEK** — the `hmac-secret` output is expanded into the
   key-encryption key that AEAD-unwraps a node's sealing secret. This is what
   lets a hardware key hold node custody. Because the KEK is derived from
   `(credential, rpId, salt)`, the `rpId` stability rule above is a hard
   requirement for this path.

## Management operations

The registry exposes three verbs, at **UI and CLI parity**, over the user's
credential set.

### List **[registry phase]**

Returns every credential the user holds, active and revoked, with metadata:

- credential id (opaque, shown truncated)
- **kind** (browser-passkey / portable-passkey / tpm / pkcs11)
- **label** (user-chosen human name, e.g. "yubikey-blue", "laptop-tpm")
- **bound scope** — the `rpId`/domain for passkeys, the parent handle/PCR for
  TPM, the token label for PKCS#11
- **created** and **last-used** timestamps
- **sign-count** (authenticator counter, for clone-detection visibility)
- **status** — active or revoked

*Currently:* the RP tracks `credential_id`, `cose_public_key`, `prf_salt`,
`sign_count`, `user_handle`, `cell` per record and can enumerate a user's
credential ids (`user_credential_ids`). The kind/label/created/last-used columns
are added in the registry phase.

### Create / enroll **[browser passkey implemented; other kinds registry phase]**

Register a new credential of a chosen kind; it becomes valid immediately and
**joins** the set — it never displaces an existing credential.

- Browser passkey — `POST /webauthn/register/{begin,finish}` drives
  `navigator.credentials.create()`; `rpId` defaults to the serving origin.
  **[implemented]**
- Portable passkey — native CTAP2 enrollment with `rpId` = cell IPNS name
  (default) or an operator-supplied `--domain`. **[registry phase]**
- TPM / PKCS#11 — seal/wrap the sealing secret to the device and store the
  resulting `PasskeyCustody`/`TpmCustody`/`Pkcs11Custody` record. **[registry
  phase]**

### Revoke **[implemented at the RP; UI/CLI surface registry phase]**

Mark one credential dead by id. Revocation is **fail-closed and permanent**:

- a revoked credential never again produces an admitting assertion
  (`RevokedKeyNeverAdmits`), and
- a revoked record is never revived by a later restore
  (`RevokedStaysDead`).

Revoking one credential leaves every other credential in the set untouched —
this is the mechanism behind backup keys and clean migrations.

## Safety properties (enforced today)

- **SignCountMonotonic** — a stored sign-count only ever increases; a replayed
  or cloned-authenticator assertion carrying a stale/equal count is refused.
- **ChallengeFreshness** — every challenge is single-use and expires; an
  assertion against a consumed/expired challenge is refused.
- **CrossSurfaceUsability** — a credential registered on the browser admits via
  native CTAP2 and vice-versa, because both surfaces read/write the one shared
  record.
- **RevokedKeyNeverAdmits / RevokedStaysDead** — revocation is terminal.
- **Ownership binding** — during a pending-2FA login the asserted credential
  must belong to the user being admitted; one user's authenticator can never
  satisfy another's gate.

## Recommended patterns

- **Always register a backup.** Enroll at least two authenticators before
  relying on 2FA, so a lost key is a revoke, not a lockout.
- **Migrate a domain without downtime.** Enroll a browser passkey on the new
  domain, verify login on both, then revoke the old-domain credential and cut
  DNS.
- **Keep a portable break-glass key.** Register a portable passkey bound to the
  cell IPNS name for headless/disaster-recovery access that does not depend on
  any DNS name being resolvable.
- **Redundant node custody.** Seal a node's custody to more than one TPM (or a
  TPM *and* a PKCS#11 token) so no single device failure blocks node start.
