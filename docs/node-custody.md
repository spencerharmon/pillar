# Node custody

*Node custody* is how a **node** holds the secret that seals its own operational
key material — a distinct concern from [user credentials](credentials.md). A
user credential is a security key a *person* logs in with; node custody is how a
*node process* unwraps its sealing secret at start-up on its host. A browser is
never involved and cannot be: browsers can only drive WebAuthn authenticators,
not raw TPMs or PKCS#11 modules.

The node-custody state machine and its login/unlock posture are specified in
[`specs/NodeCustodyLogin.tla`](../specs/NodeCustodyLogin.tla). The backends live
in `crates/pillar-crypto/src/custody.rs` behind the `tpm` / `passkey` / `pkcs11`
Cargo features (all folded into a deployed node's `hsm` build); a backend whose
feature is off fails closed with `CryptoError::Backend`.

## Backends

Each backend unwraps the node's sealing secret from a device present on the
host. What each is bound to determines portability and how you migrate.

| Backend | Struct | Bound to | Portability |
|---------|--------|----------|-------------|
| **TPM 2.0** | `TpmCustody` | a specific TPM chip via a persistent parent (SRK), optionally a PCR/boot-state policy | non-portable; the sealed blob unseals only on that chip (and boot state) |
| **PKCS#11** | `Pkcs11Custody` | a specific token (by label/slot) + user PIN + a key object on the device | tied to that HSM (or a replicated one) |
| **Passkey (hmac-secret)** | `PasskeyCustody` | a FIDO2 authenticator, keyed by `(credential, rpId, salt)` | portable if the same key is present |

- **TPM** — the sealing secret is TPM-sealed under the parent handle and
  unsealed on the device via `tss-esapi` / tpm2-tss. Selected at node bootstrap
  (`pillar node` custody flags), not from any browser.
- **PKCS#11** — the sealing secret is wrapped to a key inside the token; the
  token decrypts it on demand (RSAES-OAEP-SHA256 preferred, PKCS#1 v1.5
  fallback) and the private key never leaves the device.
- **Passkey** — a FIDO2 `hmac-secret` (WebAuthn PRF) output is expanded into the
  key-encryption key that AEAD-unwraps the sealing secret. The `rpId` here is a
  **stable KDF label**, not a DNS binding: the hmac-secret output is
  deterministic in `(credential, rpId, salt)`, so pillar uses the **cell IPNS
  name** as the rpId — a value that never changes and is independent of any DNS
  name the node is served under. If the rpId ever changed, the derived key would
  change and custody unwrap would fail closed.

## PRF / `hmac-secret`

The passkey backend depends on the authenticator's CTAP2 **`hmac-secret`**
extension (the WebAuthn **PRF**). You give the device a fixed 32-byte salt; it
returns `HMAC(device_secret, salt)` computed in-hardware — deterministic in
`(credential, salt)`, unextractable, and independent of the assertion signature.
Pillar expands that output into the AEAD key-encryption key. Only authenticators
that implement `hmac-secret` can serve as a passkey custody backend.

## Redundancy and migration

Because custody is configured per node (not a single global choice), a node can
be sealed to **more than one** device for redundancy — e.g. two TPMs, or a TPM
*and* a PKCS#11 token — so no single device failure blocks node start-up.
Migrating custody is a re-seal: provision the new device, seal to it, verify the
node starts, then retire the old one.
