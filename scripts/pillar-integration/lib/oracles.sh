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

# oracle_ipam_operator : assert the real IPAM operator surface
# (`pillar_ipam::operator::IpamOperator`, the ONLY operator surface over IPAM
# that exists today — no `pillar ipam` CLI verb or manifest kind has been
# wired yet; see the ipam scenario's design doc) rejects a double-allocation
# of the same VIP address and enforces topology-scoped pool selection across
# a real multi-site topology. This runs the crate's own acceptance test
# binary (built from the REAL `pillar-ipam`/`pillar-e2e` source under test,
# `--features acceptance`, never a mock) as the realness oracle: a failing
# assertion here means the real compiled operator surface admitted a double
# allocation or picked the wrong site's pool — a real logic effect, not a
# stub return code.
oracle_ipam_operator() {
    local out repo_root
    repo_root="$(cd "$HERE/../.." && pwd)"
    out=$(cd "$repo_root" && cargo test -p pillar-e2e --test ipam_operator_surface --features acceptance 2>&1) \
        || fail "ipam operator oracle: the real IpamOperator acceptance suite failed:\n$out"

    printf '%s\n' "$out" | grep -q "test double_allocation_of_the_same_vip_is_rejected ... ok" \
        || fail "ipam operator oracle: double-allocation-rejected assertion did not report ok:\n$out"
    printf '%s\n' "$out" | grep -q "test topology_scoped_selection_picks_the_correct_site_pool_in_a_multi_site_topology ... ok" \
        || fail "ipam operator oracle: multi-site topology-scoped-selection assertion did not report ok:\n$out"

    info "oracle-observed: ipam-operator double-allocation-rejected AND multi-site topology-scoped-selection both ok (real compiled operator surface)"
    return 0
}
