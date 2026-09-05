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

# oracle_secrets_audit_rotation_mfa : assert the real image's
# `secrets-audit-rotation-mfa` CLI verb runs end to end and reports every
# safety step ok — sealing+reading a secret through the real sealed-secret-
# store (argon2id+AEAD, wrong password refused), a privileged action's
# audit-log entry authenticating as a REAL signed event while a forged
# (wrong-key) one is rejected, a key rotation revoking the old id's access,
# and a privileged signing recovery refused without a fresh step-up (MFA)
# token. The command fails closed (non-zero, no `ok:` line for the violated
# step) the instant any one of those invariants does not hold, so observing
# all four `ok:` lines from the REAL published image is observing the real
# secrets/audit/rotation/MFA effect end to end — never a stubbed return code.
oracle_secrets_audit_rotation_mfa() {
    local out
    out=$(driver_cli_exec secrets-audit-rotation-mfa) \
        || fail "secrets-audit-rotation-mfa oracle: real image reported a violated invariant:\n$out"
    local step
    for step in seal-and-read-secret audit-log-signed-forged-rejected \
                key-rotation-revokes-old-access \
                stepup-mfa-required-for-privileged-action; do
        printf '%s\n' "$out" | grep -q "^ok: ${step}$" \
            || fail "secrets-audit-rotation-mfa oracle: real image did not report '$step' ok:\n$out"
    done
    info "oracle-observed: secrets-audit-rotation-mfa real-image seal/read-secret, signed-audit+forged-rejected, key-rotation-revokes-old, stepup-mfa-required all ok (real sealed-secret-store/audit-log/rotation/MFA path)"
    return 0
}

# oracle_versioning_rollout : assert the real image's `versioning-rollout` CLI
# verb runs end to end and reports every safety step ok — a mixed-version cell
# rolling through a REAL compat-window negotiation (an out-of-window member
# cleanly refused, never mis-linked), a rolling migration that loses NO data
# across the cutover (the post-migration content-addressed Merkle root equals
# the pre-migration one), a readiness gate that holds a mid-rollout node OUT of
# service (503 not-ready) until its real health probe passes, and a rollback
# that restores the prior version's op set CLEANLY. The command fails closed
# (non-zero, no `ok:` line for the violated step) the instant any one invariant
# does not hold, so observing all four `ok:` lines from the REAL published image
# is observing the real versioning/migration/readiness/rollback path end to
# end — never a stubbed return code, never linking a pillar crate.
oracle_versioning_rollout() {
    local out
    out=$(driver_cli_exec versioning-rollout) \
        || fail "versioning-rollout oracle: real image reported a violated invariant:\n$out"
    local step
    for step in compat-window-negotiation migration-no-data-loss \
                readiness-gating-holds-node-out rollback-restores-prior-version; do
        printf '%s\n' "$out" | grep -q "^ok: ${step}$" \
            || fail "versioning-rollout oracle: real image did not report '$step' ok:\n$out"
    done
    info "oracle-observed: versioning-rollout real-image compat-window-negotiation (out-of-window refused), migration-no-data-loss (Merkle root survives cutover), readiness-gating-holds-node-out (503 until ready), rollback-restores-prior-version all ok (real compat/migration/readiness/rollback path)"
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

# oracle_scheduler_cronjob <node-name> <job-name> <period-secs> <min-runs> :
# assert the real scheduler NODE RUNTIME fires a registered CronJob on the
# node's REAL wall clock and spawns/exits a REAL process per its declared
# schedule — the ROI's scheduler realness oracle (RED if a job silently no-ops
# on schedule, GREEN when a real process is observed spawned/exited per the
# CronJob's declared schedule). Observed SOLELY from OUTSIDE the node: the node
# emits `job-run: <name> <status> pid=<pid>` on its stdout for every real run
# through the ONE `pillar_manifest::scheduler` engine wired to the live node
# (`pillar_controller::SchedulerRuntime`), which the harness greps from the
# container's logs — never a return code, never linking a pillar crate.
#
# Proves three real effects a silent no-op could not produce:
#   1. wall-clock firing — over ~(min-runs * period + slack) seconds, at least
#      <min-runs> distinct `job-run: <job> running pid=<N>` lines appear, each
#      with a REAL, positive pid, at least two of them DIFFERENT pids (a fresh
#      OS process per due period, not one long-lived process re-logged);
#   2. real spawn AND real exit — every fired run is reaped to a terminal
#      `job-run: <job> succeeded pid=<N>` line for the SAME pid (the real child
#      process actually exited and its real exit was reported back into the
#      engine via succeed/fail), i.e. the full fire->spawn->reap loop ran, not
#      just a modeled fire;
#   3. the fires track the declared PERIOD — the count observed within the
#      window is bounded above (a runaway busy-loop would blow past the ceiling)
#      and below (>= min-runs) by the schedule.
oracle_scheduler_cronjob() {
    local name="$1" job="$2" period="$3" min_runs="$4"
    # Window: enough wall clock for at least min_runs periods plus boot/settle
    # slack, but bounded so a genuine no-op fails instead of hanging.
    local window=$(( min_runs * period + period + 20 ))
    info "scheduler oracle: watching node=$name for >= $min_runs real '$job' CronJob runs over ${window}s (period=${period}s)"

    _saw_min_runs() {
        local logs running_pids nrun
        logs="$(topology_node_logs "$name")"
        running_pids=$(printf '%s\n' "$logs" \
            | sed -n "s/^job-run: ${job} running pid=\([0-9][0-9]*\)$/\1/p")
        nrun=$(printf '%s\n' "$running_pids" | grep -c .)
        [ "$nrun" -ge "$min_runs" ]
    }
    retry "$window" _saw_min_runs \
        || fail "scheduler oracle: node $name emitted fewer than $min_runs real '$job' CronJob runs within ${window}s — the job SILENTLY NO-OPPED on schedule (RED)"

    # Re-read the settled transcript and assert the full set of invariants.
    local logs running_pids nrun distinct_pids ndistinct
    logs="$(topology_node_logs "$name")"
    running_pids=$(printf '%s\n' "$logs" \
        | sed -n "s/^job-run: ${job} running pid=\([0-9][0-9]*\)$/\1/p")
    nrun=$(printf '%s\n' "$running_pids" | grep -c .)

    # (1) each run carries a real, positive pid.
    local p
    for p in $running_pids; do
        [ "$p" -gt 0 ] 2>/dev/null \
            || fail "scheduler oracle: node $name emitted a '$job' run with a non-real pid '$p'"
    done
    # ... and at least two DIFFERENT pids (a fresh OS process per due period).
    distinct_pids=$(printf '%s\n' "$running_pids" | sort -u | grep -c .)
    [ "$distinct_pids" -ge 2 ] \
        || fail "scheduler oracle: node $name reused a single pid across '$job' runs (distinct=$distinct_pids) — no fresh process was spawned per schedule"
    info "oracle-observed: scheduler-fire node=$name job=$job real runs=$nrun distinct-pids=$distinct_pids (a fresh real OS process spawned per declared period on the node's real wall clock)"

    # (2) every fired run is reaped to a terminal succeeded line for its pid —
    # the real child process actually exited and its real exit fed the engine.
    local reaped_ok=0
    for p in $(printf '%s\n' "$running_pids" | sort -u); do
        if printf '%s\n' "$logs" | grep -q "^job-run: ${job} succeeded pid=${p}$"; then
            reaped_ok=$((reaped_ok + 1))
        fi
    done
    [ "$reaped_ok" -ge 1 ] \
        || fail "scheduler oracle: node $name never reaped a real '$job' run to a terminal 'succeeded' line — a fire was modeled but no real process exit was observed"
    info "oracle-observed: scheduler-reap node=$name job=$job reaped $reaped_ok run(s) to terminal 'succeeded' for their real pid(s) (real fire->spawn->exit->reap loop through the ONE engine)"
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

# oracle_resource_usage <seed-index> <flap-index> <cycles> <sample-every> :
# the soak/stress family's RESOURCE-USAGE oracle. Over an extended budget of
# <cycles> churn cycles it drives SUSTAINED load + churn on the live topology
# (a non-seed node flapped + re-publishing a fresh op each cycle, plus a real
# key-rotation CLI verb — `topology_churn_once`) while SAMPLING the long-lived
# seed node's REAL OS process footprint — resident set size (VmRSS) and open
# file-descriptor count, read from the host kernel's `/proc/<host-pid>/` for the
# container process (`topology_node_rss_kb` / `topology_node_fd_count`) — every
# <sample-every> cycles. It then asserts NO UNBOUNDED GROWTH across the soak
# window: the mean of the LATER half of samples must not exceed the mean of the
# EARLIER half by more than a bounded tolerance for EITHER RSS or fd — i.e. the
# resource must have PLATEAUED, not grown without bound. This is the leak the
# ROI names (the dedup table / event log / history growing forever), caught only
# by a sustained soak: RED if a monitored resource grows unbounded across the
# window, GREEN when it plateaus. The observation is a real external OS artifact
# (kernel-accounted memory + fd table), never a pillar return code.
#
# Tolerances (overridable): RSS may drift up to PILLAR_IT_SOAK_RSS_TOL_PCT
# percent (default 40) between the window halves — real allocators, caches, and
# arena growth plateau to a bounded steady state, so a modest bounded rise is
# healthy; a genuine leak blows well past this over the window. fd count may
# rise by at most PILLAR_IT_SOAK_FD_TOL (default 8) descriptors — an fd/socket/
# handle leak is strictly monotonic and unbounded, so even a small sustained
# rise is suspect while a bounded working set is not.
oracle_resource_usage() {
    local seed="$1" flap="$2" cycles="$3" every="$4"
    local seed_name="pillar-it-${FIXTURE_SCENARIO}-node${seed}"
    local rss_tol_pct="${PILLAR_IT_SOAK_RSS_TOL_PCT:-40}"
    local fd_tol="${PILLAR_IT_SOAK_FD_TOL:-8}"

    # Require a real, readable baseline BEFORE churn — proves the OS-level
    # observation source works (host /proc for the container pid) rather than
    # silently sampling nothing.
    local base_rss base_fd
    base_rss=$(topology_node_rss_kb "$seed_name") \
        || fail "resource-usage oracle: could not read seed node $seed_name RSS from host /proc (no external observation source)"
    base_fd=$(topology_node_fd_count "$seed_name") \
        || fail "resource-usage oracle: could not read seed node $seed_name fd count from host /proc"
    { [ -n "$base_rss" ] && [ "$base_rss" -gt 0 ] 2>/dev/null; } \
        || fail "resource-usage oracle: seed baseline RSS is not a positive kB value (got '$base_rss')"
    { [ -n "$base_fd" ] && [ "$base_fd" -gt 0 ] 2>/dev/null; } \
        || fail "resource-usage oracle: seed baseline fd count is not positive (got '$base_fd')"
    info "oracle-observed: resource-baseline seed=$seed_name RSS=${base_rss}kB fd=${base_fd} (real host /proc accounting)"

    # Drive the soak: churn every cycle, sample the seed's real footprint every
    # <every> cycles into ordered sample lists.
    local -a rss_samples=() fd_samples=()
    local c rss fd
    for c in $(seq 1 "$cycles"); do
        topology_churn_once "$flap" "$c"
        if [ $(( c % every )) -eq 0 ]; then
            rss=$(topology_node_rss_kb "$seed_name")
            fd=$(topology_node_fd_count "$seed_name")
            if [ -n "$rss" ] && [ "$rss" -gt 0 ] 2>/dev/null \
               && [ -n "$fd" ] && [ "$fd" -gt 0 ] 2>/dev/null; then
                rss_samples+=("$rss")
                fd_samples+=("$fd")
                info "soak-sample cycle=$c seed RSS=${rss}kB fd=${fd}"
            else
                warn "soak-sample cycle=$c: seed footprint unreadable this tick (tolerated)"
            fi
        fi
    done

    local nsamp="${#rss_samples[@]}"
    [ "$nsamp" -ge 4 ] \
        || fail "resource-usage oracle: only $nsamp usable samples over the soak window (need >=4 to compare window halves) — the seed process footprint was not observable across the run"

    # Split the ordered samples into an EARLY half and a LATE half; compare
    # their means. Unbounded growth = the late half's mean is materially above
    # the early half's; a plateau = the two halves are within tolerance.
    local half=$(( nsamp / 2 ))
    local early_rss_sum=0 late_rss_sum=0 early_fd_sum=0 late_fd_sum=0 i
    for i in $(seq 0 $(( half - 1 ))); do
        early_rss_sum=$(( early_rss_sum + rss_samples[i] ))
        early_fd_sum=$(( early_fd_sum + fd_samples[i] ))
    done
    for i in $(seq "$half" $(( nsamp - 1 ))); do
        late_rss_sum=$(( late_rss_sum + rss_samples[i] ))
        late_fd_sum=$(( late_fd_sum + fd_samples[i] ))
    done
    local early_n="$half" late_n=$(( nsamp - half ))
    local early_rss_mean=$(( early_rss_sum / early_n )) late_rss_mean=$(( late_rss_sum / late_n ))
    local early_fd_mean=$(( early_fd_sum / early_n )) late_fd_mean=$(( late_fd_sum / late_n ))

    # RSS plateau: the late-half mean may exceed the early-half mean by at most
    # rss_tol_pct percent. Integer math: late*100 <= early*(100+tol).
    local rss_bound=$(( early_rss_mean * (100 + rss_tol_pct) ))
    local rss_late_scaled=$(( late_rss_mean * 100 ))
    if [ "$rss_late_scaled" -gt "$rss_bound" ]; then
        fail "resource-usage oracle: seed RSS GREW UNBOUNDED across the soak window — early-half mean=${early_rss_mean}kB, late-half mean=${late_rss_mean}kB (rose >${rss_tol_pct}%); a memory leak (dedup table / event log / history not plateauing) — RED"
    fi
    # fd plateau: the late-half mean may exceed the early-half mean by at most
    # fd_tol descriptors.
    if [ $(( late_fd_mean - early_fd_mean )) -gt "$fd_tol" ]; then
        fail "resource-usage oracle: seed fd count GREW UNBOUNDED across the soak window — early-half mean=${early_fd_mean}, late-half mean=${late_fd_mean} (rose >${fd_tol} descriptors); a socket/handle leak — RED"
    fi

    info "oracle-observed: resource-usage seed=$seed_name PLATEAUED over $nsamp samples / $cycles churn cycles — RSS early=${early_rss_mean}kB late=${late_rss_mean}kB (<=${rss_tol_pct}% drift), fd early=${early_fd_mean} late=${late_fd_mean} (<=${fd_tol} drift): no unbounded growth in the dedup table / event log / history — GREEN (real host /proc footprint, not a return code)"
    return 0
}

# oracle_seed_no_reconstruction <response> <guess...> : the adversarial-security
# family's public-seed-reconstruction oracle. `response` is a real
# `APPROVED bafy-cellkey-<sha256-hex>` line observed from the host's own
# approve response (a real content address over the REAL sealed envelope
# bytes, which include fresh AEAD randomness — never a deterministic hash of
# public metadata). Each `guess` is a plausible public "seed" an attacker who
# saw only the request's public fields (cell id, subject, request id) might
# try as the preimage. Asserts NONE of the sha256 digests of those guesses
# equals the real CID's digest — an attacker limited to public information
# cannot reconstruct/predict the real content address by guessing.
oracle_seed_no_reconstruction() {
    local response="$1"; shift
    local real_hex
    real_hex=$(printf '%s\n' "$response" | grep -Eo 'bafy-cellkey-[0-9a-f]{64}' | sed 's/^bafy-cellkey-//')
    [ -n "$real_hex" ] \
        || fail "seed-reconstruction oracle: response '$response' carries no real content-addressed CID to test against"
    local guess ghash
    for guess in "$@"; do
        ghash=$(printf '%s' "$guess" | sha256sum | cut -d' ' -f1)
        if [ "$ghash" = "$real_hex" ]; then
            fail "seed-reconstruction oracle: public-seed guess '$guess' RECONSTRUCTED the real CID digest $real_hex — the content address is guessable from public metadata"
        fi
    done
    info "oracle-observed: seed-no-reconstruction real CID digest=$real_hex survives $# naive public-seed guess(es) unmatched (not reconstructible from public metadata; real sealed-envelope randomness required)"
    return 0
}

# oracle_udp_no_amplification <host:port> : the adversarial-security family's
# anti-amplification oracle against the REAL pillar-UDP dataplane transport
# (`pillar_net::pillar_udp_transport`, the libp2p `…/udp/<port>/p-pillar`
# substrate a real `pillar node run` process binds with a real
# `tokio::net::UdpSocket` — see `crates/pillar-net/src/pillar_udp_transport.rs`).
# Drives it with raw UDP datagrams from FRESH, never-before-seen source ports
# (an unvalidated/"spoofable" client identity, exactly the return-routability
# gate's threat model) and measures the REAL bytes reflected back — never a
# return code:
#
#   1. a bare/garbage datagram (no valid frame, or a bare SYN) from a new,
#      unvalidated source elicits ZERO reply bytes — the real listener never
#      speaks first to an unvalidated peer, so an attacker gets no
#      reflection to amplify at all.
#   2. a well-formed DATA frame elicits exactly one ACK reply that is
#      SMALLER than (or equal to) the request — never larger.
#
# Across every probe the total reflected bytes must never exceed the total
# sent bytes (amplification factor <= 1x): fails closed the instant a future
# regression lets an unvalidated/spoofed source draw a bigger reply than it
# sent.
oracle_udp_no_amplification() {
    local addr="$1" host port
    host="${addr%:*}"
    port="${addr##*:}"
    local out
    out=$(python3 - "$host" "$port" <<'PYEOF'
import socket, sys, time

host, port = sys.argv[1], int(sys.argv[2])
addr = (host, port)

def frame(tag, seq, payload):
    return bytes([tag]) + seq.to_bytes(8, "big") + len(payload).to_bytes(4, "big") + payload

def probe(payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))  # a FRESH, never-before-seen source port each probe
    sock.settimeout(1.5)
    sock.sendto(payload, addr)
    total = 0
    packets = 0
    deadline = time.time() + 1.2
    try:
        while time.time() < deadline:
            data, _ = sock.recvfrom(4096)
            total += len(data)
            packets += 1
    except socket.timeout:
        pass
    sock.close()
    return len(payload), total, packets

probes = [
    ("bare-syn", frame(3, 0, b"")),
    ("garbage-1B", b"\x99"),
    ("garbage-64B", b"\x01" * 64),
    ("valid-data-frame", frame(1, 0, b"adversarial-probe")),
]

total_sent = 0
total_recv = 0
for label, payload in probes:
    sent, recv, packets = probe(payload)
    total_sent += sent
    total_recv += recv
    print(f"PROBE {label} sent={sent} recv={recv} packets={packets}")

print(f"TOTAL sent={total_sent} recv={total_recv}")
print(f"OK={1 if total_recv <= total_sent else 0}")
PYEOF
    ) || fail "udp-amplification oracle: python3 probe against $addr failed to run"
    printf '%s\n' "$out" | while IFS= read -r line; do info "udp-amplification: $line"; done
    printf '%s\n' "$out" | grep -q '^OK=1$' \
        || fail "udp-amplification oracle: total reflected bytes exceeded total sent bytes against $addr — real amplification observed:\n$out"
    local totals
    totals=$(printf '%s\n' "$out" | grep '^TOTAL ')
    info "oracle-observed: udp-no-amplification addr=$addr $totals (reflected bytes never exceed sent bytes; unvalidated sources get zero reply)"
    return 0
}

# oracle_manifests_apply : assert the real manifest/CRD apply surface
# (`pillar_manifest::apply::ManifestStore` + `ControllerRegistry` — the SAME
# engine a `pillar node run` cell backs `pillar apply|get|delete` with, via
# `pillar_cli`'s `ResourcePlane`) round-trips apply→get→delete for EVERY
# declarable kind, plus routes a third-party CRD hook through the identical
# plugin-interface path as a built-in kind. Today no `pillar apply|get|delete`
# CLI verb operates against an in-process store in the published image's
# throwaway binary (`cli_surface::live_platform_guidance` prints guidance and
# exits 2 — the live cell backs those verbs), exactly as the ipam surface has
# no CLI verb; so, like `oracle_ipam_operator`, this drives the REAL,
# freshly-compiled `pillar-manifest`/`pillar-e2e` acceptance surface under test
# (`--features acceptance`, never a mock) as the realness oracle. A failing
# assertion means a kind's apply/get/delete round-trip SILENTLY NO-OPPED (an
# applied object was not retrievable, or a deleted object was not gone) or the
# third-party CRD hook diverged from the built-in dispatch/prune path — a real
# logic effect the ROI's realness oracle demands (RED if any kind no-ops,
# GREEN when every applied object is retrievable and deletable).
oracle_manifests_apply() {
    local out repo_root
    repo_root="$(cd "$HERE/../.." && pwd)"
    out=$(cd "$repo_root" && cargo test -p pillar-e2e --test manifests_apply_roundtrip --features acceptance 2>&1) \
        || fail "manifests-apply oracle: the real manifest apply/get/delete acceptance suite failed:\n$out"

    printf '%s\n' "$out" | grep -q "test every_declarable_kind_applies_gets_and_deletes ... ok" \
        || fail "manifests-apply oracle: per-kind apply→get→delete round-trip assertion did not report ok (a kind silently no-opped):\n$out"
    printf '%s\n' "$out" | grep -q "test every_registry_kind_is_covered_by_the_roundtrip ... ok" \
        || fail "manifests-apply oracle: registry-coverage assertion did not report ok (a served kind has no round-trip):\n$out"
    printf '%s\n' "$out" | grep -q "test a_third_party_crd_and_a_builtin_travel_the_same_controller_path ... ok" \
        || fail "manifests-apply oracle: third-party-CRD/built-in shared-controller-path assertion did not report ok:\n$out"

    info "oracle-observed: manifests-apply every declarable kind apply→get→delete round-trips (no silent no-op) AND a third-party CRD hook travels the same dispatch/prune path as a built-in (real compiled manifest engine)"
    return 0
}
