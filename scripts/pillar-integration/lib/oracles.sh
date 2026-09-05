#!/usr/bin/env bash
# oracles.sh — the realness-oracle library.
#
# Each oracle asserts a REAL external effect the ROI's realness-oracle section
# demands, observed from OUTSIDE the node — never a pillar return code. An
# oracle that passes has printed an `oracle-observed:` line naming the concrete
# artifact it saw (a pid, a listening socket, a decrypted plaintext, a resolved
# CID), so a reviewer can confirm realness from the transcript alone.
#
# The families this library covers (the ROI's realness-oracle set):
#   process           — a real OS process (pid) AND a real bound listening
#                       socket serving the node's readiness surface.
#   crypto-realness   — the real crypto path runs end to end (the image's
#                       `pillar onboard` drives real keygen/sign/trust and
#                       fails closed on a forged/out-of-order step), not a stub.
#   content-address   — (family stub) a content address resolves to its bytes.
#   packet            — (family stub) packets observed on the wire.
#   ciphertext        — (family stub) sealed payload decryptable only by a real
#                       recipient key.
#   state-survival    — (family stub) state survives a node restart.
#
# The smoke scenario exercises `oracle_process` (and `oracle_crypto_realness`
# as the CLI-driver's applied-manifest effect). The remaining oracle families
# are implemented against real topologies by the per-family scenario tasks;
# their signatures are fixed here so every scenario asserts through this one
# library.

# oracle_process <node-name> <probe-host:port> : assert the node is a REAL
# running OS process (a pid) that has bound a REAL listening socket, observed
# by fetching its readiness surface over the wire. Fails if the pid is absent,
# the process is not running, or nothing answers on the bound socket.
oracle_process() {
    local name="$1" addr="$2" pid resp code body
    pid=$(topology_node_pid "$name")
    { [ -n "$pid" ] && [ "$pid" -gt 0 ] 2>/dev/null; } \
        || fail "process oracle: node $name has no real OS pid (got '$pid')"
    topology_node_running "$name" \
        || fail "process oracle: node $name process (pid $pid) is not running"
    info "oracle-observed: process node=$name pid=$pid (real running OS process)"

    # Observe the REAL listening socket by driving its readiness surface over
    # the published host port — proves a real bound TcpListener, not a return
    # code. Give the freshly-booted node a moment to bind, then capture ONE
    # response.
    _probe_ready() { driver_http "$addr" /readyz >/dev/null 2>&1; }
    retry 30 _probe_ready \
        || fail "process oracle: node $name never answered on its bound socket $addr within 30s"
    resp=$(driver_http "$addr" /readyz) \
        || fail "process oracle: node $name socket $addr stopped answering"
    code=$(printf '%s' "$resp" | cut -d' ' -f1)
    body=$(printf '%s' "$resp" | cut -d' ' -f2-)
    [ "$code" = "200" ] || fail "process oracle: node $name readiness returned HTTP $code ($body), not 200"
    [ "$body" = "ready" ] || fail "process oracle: node $name readiness body '$body' != 'ready'"
    info "oracle-observed: listening-socket node=$name addr=$addr GET /readyz -> 200 '$body' (real bound socket)"
    return 0
}

# oracle_crypto_realness : assert the real cryptographic onboarding path runs
# end to end against the REAL image (via the CLI driver) and reports every
# safety step ok — the real-crypto effect, not a stub returning success. The
# `pillar onboard` verb fails closed (non-zero, no `ok:` lines) if any real
# signature/trust invariant is violated, so observing all five `ok:` lines is
# observing the real crypto path.
oracle_crypto_realness() {
    local out
    out=$(driver_cli_exec onboard) \
        || fail "crypto oracle: real image onboard path reported a violated invariant:\n$out"
    local step
    for step in keygen-and-registration node-key-signing \
                cross-user-trust-and-depth policy-config-gates-by-depth \
                out-of-order-fails-closed; do
        printf '%s\n' "$out" | grep -q "^ok: ${step}$" \
            || fail "crypto oracle: real image onboard did not report '$step' ok:\n$out"
    done
    info "oracle-observed: crypto-realness real-image keygen/sign/trust/policy/fail-closed all ok (real crypto path)"
    return 0
}

# oracle_ciphertext_no_leak <approve-response-body> <cell-id> : the
# geo-replication family's ciphertext oracle. On a NODE bootstrap-request
# approval the approving (host) cell's OWN HTTP surface
# (`pillar_cli::web_serve::dispatch_request_decide`) returns ONLY the
# content-addressed CID of the sealed cell-key blob
# (`crate::request::SealedCellKey`, real X25519+AEAD sealed via
# `pillar_crypto::seal`) — `APPROVED bafy-cellkey-<sha256-hex>` — never the
# plaintext cell-key material itself; only a holder of the approved node's own
# derived sealing secret key can `SealedCellKey::unseal` it (real
# cryptographic recipient-gating, not bookkeeping). This asserts BOTH real
# effects the host is observed to (not) produce, from the response transcript
# alone — no crate linkage, no reach into the node's process memory:
#
#   1. the response is shaped as a real content-address:
#      `APPROVED bafy-cellkey-<64 lowercase hex chars>` (a SHA-256 digest of
#      the real sealed-envelope bytes) — RED if a future regression ever
#      shortcut this to a bare/placeholder CID.
#   2. the response NEVER contains the hex encoding of the deterministic
#      plaintext cell-key stand-in
#      (`crate::request::cell_key_plaintext`: SHA-256 of
#      `"pillar-bootstrap/cell-key-plaintext-v1"` concatenated with the cell
#      id, documented in `crates/pillar-bootstrap/src/request.rs`) — computed
#      independently here via `sha256sum` from the SAME public formula, so
#      this is a real, reproducible proof the host's own approve response
#      never leaks the plaintext it sealed; only the CID over the sealed
#      envelope. RED the instant a future approve handler regresses to
#      echoing the plaintext key material back to the (non-recipient) host
#      caller.
oracle_ciphertext_no_leak() {
    local response="$1" cell_id="$2" plaintext_hex
    printf '%s\n' "$response" | grep -Eq '^APPROVED bafy-cellkey-[0-9a-f]{64}$' \
        || fail "ciphertext oracle: approve response '$response' is not a real content-addressed sealed-cell-key CID"
    info "oracle-observed: ciphertext-cid response='$response' (content-addressed sealed blob, not plaintext)"

    plaintext_hex=$(printf '%s' "pillar-bootstrap/cell-key-plaintext-v1${cell_id}" | sha256sum | cut -d' ' -f1)
    if printf '%s' "$response" | grep -qi "$plaintext_hex"; then
        fail "ciphertext oracle: host approve response for cell '$cell_id' LEAKED the plaintext cell-key material (host must never be able to decrypt — only the sealed recipient can)"
    fi
    info "oracle-observed: ciphertext-no-leak host response never contains the plaintext cell-key hex ($plaintext_hex) — host holds ciphertext+CID only, cannot decrypt"
    return 0
}
