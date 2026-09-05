#!/usr/bin/env bash
# scenarios/workload-runtime.sh — ROI "pillar-integration" scenario family:
# workload runtime (operator-directed, 2026-08-31).
#
# Drives the REAL published `pillar` image SOLELY through its external
# surfaces (a boot-time environment hook + its unauthenticated HTTP replica
# oracle — never linking a pillar crate) against >=3 real, independent node
# containers, each of which:
#
#   1. FETCHES a real content-addressed image by CID over a live libp2p wire
#      (`/pillar/blob/1.0.0`) from a real external blob-provider process this
#      harness itself stands up (`crates/pillar-e2e/src/bin/blob_provider.rs`,
#      built and run as a genuinely separate OS process — never linked into
#      this script or into `pillar_cli`),
#   2. admits it through the node's real digest-verified controller gate, and
#   3. EXECUTES it as a real supervised OS process bound to a real listening
#      UDP socket (`pillar_controller::RunningWorkload::spawn_process`).
#
# The "image" is a real standalone executable this harness builds from the
# SAME repo (`crates/pillar-e2e/src/bin/udp_echo.rs`), statically linked for
# `x86_64-unknown-linux-musl` so it runs unmodified inside the distroless
# `pillar` image's own filesystem (which carries none of the shared libraries
# a normal dynamically-linked binary would need) — proving a REAL OCI-style
# exec of independently-fetched bytes, not a pre-baked image asset.
#
# Realness oracles asserted (never a return code):
#
#   - process oracle (shared `oracle_process`): every one of the >=3 nodes is
#     a real OS process (pid) with a real bound readiness socket.
#   - content-address oracle (this file): the node's OWN unauthenticated
#     `GET /portal/resource/replicas` HTTP surface reports a REAL running
#     replica (pid>0, a bound UDP port) whose reported content-addressed
#     image digest matches a digest THIS SCRIPT independently recomputes
#     (`sha256sum` of the exact bytes served) — never trusting the node's or
#     the provider's own claim alone.
#   - restart oracle (this file): the replica's real pid is discovered from
#     the node's own external HTTP surface (the node containers run
#     `--pid=host` so their reported pids are directly host-signalable — a
#     deliberate observability choice, not a change to what actually runs),
#     `kill -9`'d for real, and the node's own `RestartPolicy::Always` sweep
#     is observed (via the SAME external oracle) to bring the replica back on
#     a FRESH pid, at the SAME content-addressed digest — a real crash +
#     recovery, not an assumption.
#   - health oracle (this file): a real UDP datagram is round-tripped to the
#     restarted replica's bound socket from a throwaway helper container that
#     joins the node's OWN network namespace (`--network container:<node>`,
#     the same "reach a container's own loopback" pattern
#     `bootstrap-identity-custody.sh`'s `_bic_cli` already established), and
#     the echoed reply is asserted byte-for-byte — proving the replica is not
#     merely a live pid but a genuinely serving application socket.
#
# RED against a stand-in image payload or a modeled `.run()` (no
# `PILLAR_TEST_WORKLOAD`/reconciler wiring existed before
# `pillar-node-workload-runtime-wiring`; the check
# `unknown scenario 'workload-runtime'` / a 404 `/portal/resource/replicas`
# were this scenario's own RED). GREEN against the real fetch+admit+exec path
# proven here end to end.
#
# Claimed surface-inventory entries this scenario exercises (informal
# `pillar-integration/v1` shape):
#   env-hook   PILLAR_TEST_WORKLOAD
#   http-route GET /portal/resource/replicas

# _wr_free_tcp_port : ask the OS for a free localhost TCP port (best-effort;
# the blob-provider binds it for real immediately after, same accepted race as
# every other free-port helper this harness/its acceptance tests use).
_wr_free_tcp_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

# _wr_provider_ready <log-file> : exit 0 once the blob-provider has printed
# both its real PEER id and content-address DIGEST lines.
_wr_provider_ready() {
    grep -q '^PEER ' "$1" 2>/dev/null && grep -q '^DIGEST ' "$1" 2>/dev/null
}

# _wr_node_replicas <web-addr> : the node's own unauthenticated black-box
# replica oracle body (`GET /portal/resource/replicas`) — one `REPLICA …`
# line per live replica, or `REPLICAS 0`. Never a return code: the caller
# greps/parses the real response body.
_wr_node_replicas() {
    local addr="$1" resp
    resp=$(driver_http "$addr" /portal/resource/replicas) || return 1
    printf '%s\n' "$resp" | cut -d' ' -f2-
}

# _wr_replica_field <replicas-body> <field> : pull `pid=`/`port=`/`digest=`
# out of the FIRST `REPLICA …` line of a replica-oracle body. `driver_http`
# strips the real newlines out of its body (`tr -d '\n'`), so the trailing
# `REPLICAS <n>` line runs straight into `digest=<hex>` with no separating
# space; digest is matched as a pure hex run so it stops at that boundary
# instead of swallowing it.
_wr_replica_field() {
    local charclass="[^ ]"
    [ "$2" = digest ] && charclass="[0-9a-f]"
    printf '%s\n' "$1" | grep '^REPLICA ' | head -1 \
        | sed -n "s/.*${2}=\\(${charclass}*\\).*/\\1/p"
}

scenario_workload-runtime() {
    local n="${PILLAR_IT_NODES:-3}"
    [ "$n" -ge 3 ] || fail "workload-runtime: the ROI requires >=3 real nodes (got $n)"

    local repo_root
    repo_root="$(cd "$HERE/../.." && pwd)"

    # --- (1) the real "image": a genuine standalone executable, statically
    # linked for musl so it runs inside the distroless real image's own
    # filesystem with no shared libraries of its own. ---------------------
    info "workload-runtime: building the real udp_echo image (static musl) as this scenario's fetchable content"
    rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
    (cd "$repo_root" && cargo build -p pillar-e2e --bin udp_echo --release --target x86_64-unknown-linux-musl >/dev/null) \
        || fail "workload-runtime: could not build the real udp_echo image binary"
    local udp_echo="$repo_root/target/x86_64-unknown-linux-musl/release/udp_echo"
    [ -x "$udp_echo" ] || fail "workload-runtime: udp_echo binary missing after build"

    # --- (2) the harness's OWN external blob-provider process: a real
    # libp2p peer serving udp_echo's bytes by content address, run as a
    # genuinely separate OS process (never linked into this script or into
    # pillar_cli). ----------------------------------------------------------
    (cd "$repo_root" && cargo build -p pillar-blob-provider --bin blob_provider --release >/dev/null) \
        || fail "workload-runtime: could not build the harness's blob_provider"
    local blob_provider="$repo_root/target/release/blob_provider"

    local provider_port provider_log
    provider_port=$(_wr_free_tcp_port) || fail "workload-runtime: could not claim a free tcp port for the blob-provider"
    # fixtures_init already reclaimed FIXTURE_ROOT's own directory (its
    # `fixtures_teardown quiet` removes it unconditionally); recreate it, the
    # same "mkdir -p before first use" pattern topology.sh's
    # `topology_node_op_cids` already relies on.
    mkdir -p "$FIXTURE_ROOT"
    provider_log="$FIXTURE_ROOT/blob-provider.log"
    "$blob_provider" "$provider_port" "$udp_echo" >"$provider_log" 2>&1 &
    local provider_pid=$!
    # The blob-provider is a real HOST process, not a container, so it lives
    # outside fixtures.sh's label namespace. Chain its teardown onto the
    # harness's OWN already-installed EXIT trap (fixtures_teardown +
    # leak-check) rather than replacing it — capturing/restoring `$?` around
    # our own cleanup commands so `finish`'s own `local rc=$?` still sees the
    # ORIGINAL exit status that triggered this trap, not the exit status of
    # our `kill`/`wait`.
    local orig_exit_trap
    orig_exit_trap="$(trap -p EXIT | sed -n "s/^trap -- '\\(.*\\)' EXIT\$/\\1/p")"
    # shellcheck disable=SC2064
    trap "__wr_exit_rc=\$?; kill $provider_pid >/dev/null 2>&1 || true; wait $provider_pid 2>/dev/null || true; ( exit \$__wr_exit_rc ); $orig_exit_trap" EXIT

    retry 20 _wr_provider_ready "$provider_log" \
        || fail "workload-runtime: blob-provider never announced ready:\n$(cat "$provider_log" 2>/dev/null)"
    local peer digest
    peer=$(grep '^PEER ' "$provider_log" | tail -1 | awk '{print $2}')
    digest=$(grep '^DIGEST ' "$provider_log" | tail -1 | awk '{print $2}')
    [ -n "$peer" ] && [ -n "$digest" ] \
        || fail "workload-runtime: could not parse the blob-provider's PEER/DIGEST from its log"
    info "oracle-observed: blob-provider real libp2p peer=$peer serving content-address digest=$digest over /pillar/blob/1.0.0"

    # Independently recompute the sha256 payload of the digest ourselves —
    # BlobDigest is a multihash (`1220<sha256-hex>`), so its last 64 hex
    # chars are the sha256 of the EXACT bytes served. Never trust the
    # provider's own claim alone.
    local want_sha have_sha
    want_sha=$(sha256sum "$udp_echo" | awk '{print $1}')
    have_sha="${digest: -64}"
    [ "$want_sha" = "$have_sha" ] \
        || fail "workload-runtime: published digest $digest does not carry the real sha256 ($want_sha) of the served image bytes"
    info "oracle-observed: content-address digest=$digest independently verified against sha256($udp_echo)=$want_sha"

    # --- (3) a real host-reachable address every node container can dial:
    # the runtime's host-gateway special address (works identically for
    # podman and docker, rootful or rootless). --------------------------
    "$CONTAINER_RUNTIME" pull busybox >/dev/null 2>&1
    local hostgw_name="pillar-it-blob-host" hostgw_ip
    hostgw_ip=$("$CONTAINER_RUNTIME" run --rm --add-host "${hostgw_name}:host-gateway" busybox \
        sh -c "grep ${hostgw_name} /etc/hosts | awk '{print \$1}'" 2>/dev/null)
    [ -n "$hostgw_ip" ] || fail "workload-runtime: could not resolve the container runtime's host-gateway address"
    local image_ref="blob:/ip4/${hostgw_ip}/tcp/${provider_port}/p2p/${peer}|${digest}"
    info "workload-runtime: image reference (fetchable by every node over live libp2p): $image_ref"

    # --- (4) boot n>=3 REAL, INDEPENDENT node containers, each fetching the
    # SAME image by CID over live libp2p via the boot-time PILLAR_TEST_WORKLOAD
    # hook, admitting it through the full controller gate, and spawning it as
    # a real supervised OS process. `--pid=host` shares the host pid
    # namespace so the replica pid this scenario later observes over the
    # node's own HTTP oracle is directly host-signalable — an observability
    # choice for the restart oracle below, not a change to what actually
    # runs. `TMPDIR` is redirected into the node's own writable data
    # volume because the distroless image ships no `/tmp`. ----------------
    "$CONTAINER_RUNTIME" pull "$PILLAR_IMAGE" >/dev/null 2>&1 \
        || fail "could not pull the real published image $PILLAR_IMAGE"

    local -a names=() health_addrs=() web_addrs=()
    local i name
    for i in $(seq 0 $((n - 1))); do
        name="pillar-it-${FIXTURE_SCENARIO}-node${i}"
        "$CONTAINER_RUNTIME" run -d \
            --name "$name" \
            --label "$FIXTURE_LABEL" \
            --pid=host \
            --add-host "${hostgw_name}:host-gateway" \
            -p "127.0.0.1::${PILLAR_PROBE_PORT}" \
            -p "127.0.0.1::8642" \
            -e "PILLAR_WEB_BIND=0.0.0.0" \
            -e "TMPDIR=/var/lib/pillar/data" \
            -e "PILLAR_TEST_WORKLOAD=web::1::${image_ref}" \
            "$PILLAR_IMAGE" >/dev/null \
            || fail "workload-runtime: node${i} failed to start"
        names+=("$name")
    done

    for name in "${names[@]}"; do
        local haddr waddr
        haddr=$("$CONTAINER_RUNTIME" port "$name" "$PILLAR_PROBE_PORT" 2>/dev/null | head -1)
        waddr=$("$CONTAINER_RUNTIME" port "$name" 8642 2>/dev/null | head -1)
        [ -n "$haddr" ] && [ -n "$waddr" ] \
            || fail "workload-runtime: could not resolve published ports for $name"
        health_addrs+=("$haddr")
        web_addrs+=("$waddr")
    done
    info "workload-runtime: ${#names[@]} real, independent nodes up: ${names[*]}"

    # Every node must be a real running OS process with a real bound
    # readiness socket before we assert its workload replica — the shared
    # process oracle.
    for i in "${!names[@]}"; do
        oracle_process "${names[$i]}" "${health_addrs[$i]}"
    done

    # --- (5) content-address oracle: each node's OWN unauthenticated HTTP
    # surface must report a real running replica whose digest matches. -----
    local -a replica_pids=() replica_ports=()
    for i in "${!names[@]}"; do
        local body pid port rdigest
        _wr_has_replica() {
            body="$(_wr_node_replicas "${web_addrs[$i]}")"
            printf '%s\n' "$body" | grep -q '^REPLICA '
        }
        retry 30 _wr_has_replica \
            || fail "workload-runtime: ${names[$i]} never reconciled a live replica (body: $body)"
        pid=$(_wr_replica_field "$body" pid)
        port=$(_wr_replica_field "$body" port)
        rdigest=$(_wr_replica_field "$body" digest)
        [ -n "$pid" ] && [ "$pid" -gt 0 ] 2>/dev/null \
            || fail "workload-runtime: ${names[$i]} replica has no real pid (body: $body)"
        [ "$rdigest" = "$digest" ] \
            || fail "workload-runtime: ${names[$i]} replica digest '$rdigest' != published '$digest'"
        replica_pids+=("$pid")
        replica_ports+=("$port")
        info "oracle-observed: content-address node=${names[$i]} pid=$pid port=$port digest=$rdigest (real fetch-by-CID + digest-verified admission + real process)"
    done

    # --- (6) restart oracle: kill node0's real replica pid for real, prove
    # the node's own RestartPolicy::Always sweep brings it back on a FRESH
    # pid at the SAME content-addressed digest. ---------------------------
    local victim="${names[0]}" before_pid="${replica_pids[0]}"
    kill -9 "$before_pid" 2>/dev/null \
        || fail "workload-runtime: could not kill replica pid=$before_pid on $victim"
    info "workload-runtime: real-killed $victim's replica (pid=$before_pid)"

    local after_pid after_digest body
    _wr_restarted() {
        body="$(_wr_node_replicas "${web_addrs[0]}")"
        after_pid=$(_wr_replica_field "$body" pid)
        [ -n "$after_pid" ] && [ "$after_pid" -gt 0 ] 2>/dev/null && [ "$after_pid" != "$before_pid" ]
    }
    retry 45 _wr_restarted \
        || fail "workload-runtime: $victim never restarted its killed replica onto a fresh pid within 45s (last body: $body)"
    after_digest=$(_wr_replica_field "$body" digest)
    [ "$after_digest" = "$digest" ] \
        || fail "workload-runtime: $victim restarted replica digest '$after_digest' != published '$digest' (a lost/re-derived content address)"
    info "oracle-observed: restart node=$victim replica pid $before_pid -> $after_pid (fresh, real crash+recovery), digest unchanged=$after_digest"

    # --- (7) health oracle: round-trip a real UDP datagram to the restarted
    # replica's bound socket from a throwaway helper container that joins the
    # node's OWN network namespace (the replica binds 127.0.0.1, reachable
    # only from inside the node's netns) — the same pattern
    # bootstrap-identity-custody.sh's `_bic_cli` uses to reach a booted
    # node's loopback. -------------------------------------------------------
    local after_port reply
    after_port=$(_wr_replica_field "$body" port)
    reply=$("$CONTAINER_RUNTIME" run --rm --network "container:${victim}" busybox \
        sh -c "echo -n pillar-it-workload-runtime-probe | nc -u -w2 127.0.0.1 ${after_port}" 2>/dev/null)
    [ "$reply" = "pillar-it-workload-runtime-probe" ] \
        || fail "workload-runtime: restarted replica on $victim (port $after_port) did not echo the real UDP health probe (got '$reply')"
    info "oracle-observed: health node=$victim udp-echo round-trip on the restarted replica's real bound socket (port $after_port) verbatim"

    info "workload-runtime: ${#names[@]} real, independent nodes each fetched the SAME content-addressed image over live libp2p, admitted + executed it as a real supervised process, and the killed replica restarted onto a fresh pid at the identical digest with a live serving socket"
}
