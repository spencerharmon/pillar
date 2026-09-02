#!/usr/bin/env bash
# Definition-of-done GATE for every security/crypto task (ROI real-crypto rule).
#
# Fails (non-zero) while ANY security-critical crate still uses a
# non-cryptographic stand-in in place of a real primitive. This is the gate
# that must have existed before key-distribution/custody/trust/identity were
# ever marked DONE: no task touching authority, credentials, key distribution,
# sealing, signatures, or content addressing may be DONE while this fails.
#
# Banned stand-ins (the "no-real-crypto convention" this repo must abolish):
#   - DefaultHasher / SipHash used as a KDF, signature, seal, or content hash
#   - FNV-1a content_hash masquerading as a content address (CID)
#   - XOR "sealing" (inner ^ seal_material) in place of public-key recipient sealing
#
# A security crate is DONE only when it routes these through `pillar-crypto`
# (real argon2id, ed25519, x25519 recipient sealing, sha2/blake3 multihash).
set -euo pipefail
cd "$(dirname "$0")/.."

# Security-critical crates: anything doing authority, credentials, key
# distribution, sealing, signing, attestation, identity, or content addressing.
SECURITY_CRATES=(
  pillar-web pillar-trust-artifacts pillar-identity pillar-bootstrap
  pillar-key-distribution pillar-streamdb pillar-cells pillar-eventlog
  pillar-wot-authority pillar-manifest pillar-recovery
)

rc=0
report() { echo "PLACEHOLDER-CRYPTO GATE FAILURE: $1"; rc=1; }

for crate in "${SECURITY_CRATES[@]}"; do
  dir="crates/$crate/src"
  [[ -d "$dir" ]] || continue
  # (1) DefaultHasher anywhere in a security crate = a non-crypto primitive
  #     standing in for a KDF/signature/seal/hash.
  if grep -rnE "DefaultHasher|use std::hash::\{?.*Hasher" "$dir" >/dev/null 2>&1; then
    report "$crate uses DefaultHasher (non-cryptographic) — replace with pillar-crypto"
    grep -rnE "DefaultHasher" "$dir" | sed 's/^/    /'
  fi
  # (2) FNV content_hash masquerading as a content address.
  if grep -rnE "FNV|content_hash|0xcbf2_9ce4|FNV_PRIME|FNV_OFFSET" "$dir" >/dev/null 2>&1; then
    report "$crate uses an FNV/non-cryptographic content hash — content addresses must be a cryptographic multihash"
    grep -rnE "FNV|content_hash|FNV_PRIME|FNV_OFFSET" "$dir" | sed 's/^/    /'
  fi
  # (3) XOR "sealing" in place of public-key recipient sealing.
  if grep -rnE "\^ seal_material|node_sealed *=|inner \^ " "$dir" >/dev/null 2>&1; then
    report "$crate uses XOR 'sealing' — recipient sealing must be real public-key crypto (x25519/HPKE)"
    grep -rnE "\^ seal_material|inner \^ " "$dir" | sed 's/^/    /'
  fi
done

if [[ $rc -ne 0 ]]; then
  echo
  echo "GATE RED: placeholder cryptography present. These crates CANNOT be marked DONE."
  echo "Abolish the stand-ins by routing every primitive through pillar-crypto (real"
  echo "argon2id / ed25519 / x25519 recipient sealing / sha2 multihash)."
else
  echo "GATE GREEN: no placeholder cryptography found in security crates."
fi
exit $rc
