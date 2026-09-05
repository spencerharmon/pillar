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
#   state-survival    — a killed node, restarted onto its SAME durable store,
#                       rehydrates its materialized view from the persisted,
#                       content-addressed segments (proven: the op count and the
#                       op's CID survive the restart) — never lost.
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

# oracle_streamdb_append <publisher-index> <op-value> <consumer-index...> :
# assert a REAL append converges to the durable store of every consumer node.
# The publisher node gossips <op-value> once to the event-log topic; each
# consumer node must (a) show it really RECEIVED the op over the wire, and
# (b) hold >=1 op in its durable, content-addressed streamdb — the real
# append/persist effect, observed from the node's own transcript and its
# on-disk `ops/` content-addressed store, never a return code.
oracle_streamdb_append() {
    local pub="$1" value="$2"; shift 2
    local -a consumers=("$@")

    info "streamdb-append oracle: node$pub publishing op '$value' to the cell"
    topology_publish_op "$pub" "$value"

    # Wait for the real cross-process gossip convergence on every consumer
    # (publish fires TEST_PUBLISH_DELAY=8s after the swarm settles, then the
    # message propagates the mesh). Poll each consumer's transcript.
    local idx
    for idx in "${consumers[@]}"; do
        _recv() { topology_node_received_op "$idx" "$value"; }
        retry 60 _recv \
            || fail "streamdb-append oracle: node$idx never received op '$value' over the wire within 60s"
        info "oracle-observed: gossip-append node=$idx received op payload='$value' over libp2p (real cross-process convergence)"
    done

    # Each consumer must now hold the op DURABLY as a content-addressed segment.
    for idx in "${consumers[@]}"; do
        local cids ncids
        _has_cid() { cids="$(topology_node_op_cids "$idx")"; [ -n "$cids" ]; }
        retry 30 _has_cid \
            || fail "streamdb-append oracle: node$idx persisted no content-addressed op under its streamdb store"
        cids="$(topology_node_op_cids "$idx")"
        ncids=$(printf '%s\n' "$cids" | grep -c . )
        info "oracle-observed: content-address node=$idx durable ops/ holds $ncids content-addressed segment(s): $(printf '%s ' $cids)(real persisted CID)"
    done
    return 0
}

# oracle_state_survival <node-index> : assert a KILLED node, restarted onto its
# SAME durable store, rehydrates its materialized view from the persisted
# content-addressed segments — the ROI's state-survival oracle. Observes the
# REAL effect from OUTSIDE the node: the durable op set (content-address CIDs)
# and the node's rehydrated op count both SURVIVE the kill+restart unchanged.
# RED if a killed node's state fails to reconverge; GREEN when it does.
oracle_state_survival() {
    local idx="$1"

    # Snapshot the node's durable, content-addressed op set BEFORE the kill.
    local before_cids before_n
    before_cids="$(topology_node_op_cids "$idx" | sort)"
    before_n=$(printf '%s\n' "$before_cids" | grep -c . )
    [ "$before_n" -ge 1 ] \
        || fail "state-survival oracle: node$idx holds no durable op to survive (pre-kill ops=$before_n)"
    info "oracle-observed: pre-kill node=$idx durable store holds $before_n content-addressed op(s)"

    # A REAL crash + recovery: kill the process, restart it onto the SAME
    # named data-dir volume.
    topology_restart_node "$idx"

    # The restarted node must come back READY (rebound socket) AND report, in
    # its fresh boot log, that it reopened the durable store and rehydrated the
    # SAME materialized-view op count from the persisted segments (not zero —
    # zero would be state LOST).
    local addr
    addr="${TOPO_PROBE_ADDRS[$idx]}"
    _ready() { driver_http "$addr" /readyz >/dev/null 2>&1; }
    retry 45 _ready \
        || fail "state-survival oracle: node$idx never became ready again after restart"

    local reopened_ops
    _rehydrated() {
        reopened_ops=$(topology_node_streamdb_ops "$idx")
        [ -n "$reopened_ops" ] && [ "$reopened_ops" -ge "$before_n" ] 2>/dev/null
    }
    retry 30 _rehydrated \
        || fail "state-survival oracle: node$idx did NOT rehydrate its materialized view after restart (reopened ops='${reopened_ops:-}', expected >= $before_n) — state was LOST"
    info "oracle-observed: state-survival node=$idx reopened durable store and rehydrated ops=$reopened_ops (>= $before_n pre-kill) — materialized view SURVIVED the kill"

    # The durable content-addressed op set must be IDENTICAL after recovery —
    # the same segments (same CIDs), rehydrated from the persisted store, not a
    # re-derived-from-nothing empty view.
    local after_cids after_n
    after_cids="$(topology_node_op_cids "$idx" | sort)"
    after_n=$(printf '%s\n' "$after_cids" | grep -c . )
    [ "$after_n" -ge "$before_n" ] \
        || fail "state-survival oracle: node$idx durable op set shrank across restart (before=$before_n after=$after_n) — a lost write"
    if [ "$before_cids" != "$after_cids" ]; then
        # A superset (extra ops arrived from continued gossip) is fine; a
        # DROPPED pre-kill CID is a lost write.
        local missing
        missing="$(comm -23 <(printf '%s\n' "$before_cids") <(printf '%s\n' "$after_cids"))"
        [ -z "$missing" ] \
            || fail "state-survival oracle: node$idx dropped pre-kill content-addressed op(s) across restart: $missing"
    fi
    info "oracle-observed: state-survival node=$idx durable content-addressed op set survived intact (before=$before_n after=$after_n CIDs, no dropped segment) — rehydrated from pinned segments, not lost"
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
