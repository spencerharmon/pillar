#!/usr/bin/env bash
# Onboarding integration rig — pillar's OWN CI, strictly separate from the
# flux/spray deployment path. Exercises the full onboarding sequence
# end to end:
#
#   keygen -> node-key signing -> cross-user trust -> depth/policy config
#   -> gossipsub discovery -> state convergence
#
# in two real, asserted phases:
#
#   Phase 1 (identity/trust/policy): `pillar onboard` drives the
#   keygen/node-key-signing/cross-user-trust/depth-policy sequence across
#   pillar-identity + pillar-wot-authority + pillar-rbac in one process,
#   asserting every safety invariant (fails loud, non-zero, on the first
#   violated one).
#
#   Phase 2 (gossipsub discovery -> state convergence): spawns THREE
#   independent, rootless `pillar node run` OS processes on ephemeral
#   loopback ports (no containers, no cluster, no root) — a seed peer plus
#   two peers that `--dial` it — waits for real libp2p connections to
#   establish, then has the seed publish a unique nonce once to the
#   event-log gossipsub topic and asserts BOTH other peers actually receive
#   it over the wire: real, observed cross-process convergence, not merely
#   "the code compiles".
#
# Exit 0 = every phase's real effect was observed. Exit !0 = the first
# violated step is printed with diagnostics (including the peers' full logs)
# so a human/bee can see exactly what failed.

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/pillar-onboarding-rig.XXXXXX")"
cleanup() {
    local pid
    for pid in "${PEER_PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1
    done
    for pid in "${PEER_PIDS[@]:-}"; do
        [ -n "$pid" ] && wait "$pid" 2>/dev/null
    done
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

echo "== building pillar-cli =="
cargo build -p pillar-cli 2>"$WORKDIR/build.log" || {
    cat "$WORKDIR/build.log" >&2
    fail "cargo build -p pillar-cli failed"
}
PILLAR_BIN="$here/target/debug/pillar"
[ -x "$PILLAR_BIN" ] || fail "pillar binary not found at $PILLAR_BIN after build"

echo "== phase 1: keygen -> node-key signing -> cross-user trust -> depth/policy config =="
if ! "$PILLAR_BIN" onboard >"$WORKDIR/onboard.log" 2>&1; then
    cat "$WORKDIR/onboard.log" >&2
    fail "pillar onboard reported a violated invariant"
fi
cat "$WORKDIR/onboard.log"
grep -q "^ok: keygen-and-registration$" "$WORKDIR/onboard.log" || fail "onboard did not report keygen-and-registration ok"
grep -q "^ok: node-key-signing$" "$WORKDIR/onboard.log" || fail "onboard did not report node-key-signing ok"
grep -q "^ok: cross-user-trust-and-depth$" "$WORKDIR/onboard.log" || fail "onboard did not report cross-user-trust-and-depth ok"
grep -q "^ok: policy-config-gates-by-depth$" "$WORKDIR/onboard.log" || fail "onboard did not report policy-config-gates-by-depth ok"
grep -q "^ok: out-of-order-fails-closed$" "$WORKDIR/onboard.log" || fail "onboard did not report out-of-order-fails-closed ok"
echo "phase 1: PASS"

echo "== phase 2: gossipsub discovery -> state convergence (3 rootless peers) =="

declare -a PEER_PIDS=()
declare -a PEER_LOGS=()
declare -a PEER_DATA=()

start_peer() {
    # start_peer <name> [--publish <value>] <extra pillar node run args...>
    local name="$1"; shift
    local publish=""
    if [ "${1:-}" = "--publish" ]; then
        publish="$2"
        shift 2
    fi
    local data_dir="$WORKDIR/$name"
    local log="$WORKDIR/$name.log"
    mkdir -p "$data_dir"
    if [ -n "$publish" ]; then
        RUST_LOG=info PILLAR_TEST_PUBLISH="$publish" "$PILLAR_BIN" node run --data-dir "$data_dir" "$@" >"$log" 2>&1 &
    else
        RUST_LOG=info "$PILLAR_BIN" node run --data-dir "$data_dir" "$@" >"$log" 2>&1 &
    fi
    local pid=$!
    PEER_PIDS+=("$pid")
    PEER_LOGS+=("$log")
    PEER_DATA+=("$data_dir")
    echo "$pid"
}

wait_for_pattern() {
    # wait_for_pattern <logfile> <pattern> <timeout-seconds>
    local log="$1" pattern="$2" timeout="$3" waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if grep -qE "$pattern" "$log" 2>/dev/null; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

# --- seed peer: listens on an OS-assigned ephemeral TCP port, will publish a
# unique nonce once (after TEST_PUBLISH_DELAY) so the rig can assert real
# cross-process convergence once the other two peers have joined its mesh ---
nonce="onboarding-rig-nonce-$$-$(date +%s%N)"
seed_pid=$(start_peer node0 --publish "$nonce" --listen /ip4/127.0.0.1/tcp/0)

if ! wait_for_pattern "$WORKDIR/node0.log" 'pillar peer listening' 20; then
    cat "$WORKDIR/node0.log" >&2
    fail "seed peer (node0) never reported a listen address within 20s"
fi

seed_addr_line=$(grep -m1 -E 'pillar peer listening' "$WORKDIR/node0.log")
# tracing's key=value form: address=/ip4/127.0.0.1/tcp/NNNN
seed_multiaddr=$(echo "$seed_addr_line" | grep -oE 'address=[^[:space:]]+' | head -1 | cut -d= -f2-)
[ -n "$seed_multiaddr" ] || fail "could not parse seed peer's listen multiaddr from: $seed_addr_line"
echo "seed peer listening on: $seed_multiaddr"

# --- two peers dial the seed immediately, so they are in its mesh well
# before the seed's delayed publish fires ---
peer1_pid=$(start_peer node1 --listen /ip4/127.0.0.1/tcp/0 --dial "$seed_multiaddr")
peer2_pid=$(start_peer node2 --listen /ip4/127.0.0.1/tcp/0 --dial "$seed_multiaddr")

for log in "$WORKDIR/node1.log" "$WORKDIR/node2.log"; do
    if ! wait_for_pattern "$log" 'pillar peer connection established' 20; then
        echo "--- node0.log ---"; cat "$WORKDIR/node0.log" >&2
        echo "--- node1.log ---"; cat "$WORKDIR/node1.log" >&2
        echo "--- node2.log ---"; cat "$WORKDIR/node2.log" >&2
        fail "$log never reported a real libp2p connection established within 20s"
    fi
done
echo "both peers established a real libp2p connection to the seed"

# --- assert the seed's delayed publish (fired ~3s after its own boot)
# actually reached BOTH independently-dialed peers over the wire ---
if ! wait_for_pattern "$WORKDIR/node1.log" "$nonce" 30; then
    echo "--- node0.log ---"; cat "$WORKDIR/node0.log" >&2
    echo "--- node1.log ---"; cat "$WORKDIR/node1.log" >&2
    fail "node1 never received the seed's published nonce ($nonce) — no real convergence observed"
fi
if ! wait_for_pattern "$WORKDIR/node2.log" "$nonce" 30; then
    echo "--- node0.log ---"; cat "$WORKDIR/node0.log" >&2
    echo "--- node2.log ---"; cat "$WORKDIR/node2.log" >&2
    fail "node2 never received the seed's published nonce ($nonce) — no real convergence observed"
fi

echo "both peers converged on the seed's gossiped nonce: $nonce"
echo "phase 2: PASS"
echo "ALL PHASES PASS"
exit 0
