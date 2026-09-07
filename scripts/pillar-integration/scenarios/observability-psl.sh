#!/usr/bin/env bash
# scenarios/observability-psl.sh — ROI "pillar-integration" scenario family:
# observability (operator-directed, 2026-08-31).
#
# Stands up a single REAL `pillar node run` process from the real published
# image with its bootstrap/web HTTP surface published (same
# `PILLAR_WEB_BIND`/`PILLAR_WEB_PORT` mechanism `geo-replication.sh` uses),
# drives it SOLELY over that real HTTP surface (never linking a pillar
# crate), and proves the node's LIVE observability substrate
# (`node-observability-live-surface`, `crates/pillar-observability`,
# `/portal/obs/live/*` in `crates/pillar-cli/src/web_serve.rs`) is genuinely
# fed by the running node's own controller loop:
#
#   1. all five signal kinds (metric, log, trace, profile, metadata) are
#      really ingested from the real node's self-instrumentation (its
#      periodic sampler + per-event log/span) and independently traceable
#      through `/portal/obs/live/kinds` + `/portal/obs/live/explore`;
#   2. PSL select/where/range/correlate queries (`POST
#      /portal/obs/live/query`) run against that real ingested data and
#      return ONLY really-held signals — a query for a predicate no real
#      signal satisfies returns nothing;
#   3. a recording rule (`POST /portal/obs/live/recording`) evaluates across
#      kinds on the node's REAL scheduler engine over the live store and
#      fires, and an alert (`POST /portal/obs/live/alert`) fires on a real
#      threshold but not on an impossible one;
#   4. a dashboard (`POST /portal/obs/live/dashboard`) materializes every
#      panel from the real live store.
#
# RED if a query returns data with no corresponding real ingested signal;
# GREEN when every signal kind is independently traceable to a real workload
# emission. Mirrors `crates/pillar-e2e/tests/observability_live_surface.rs`
# (the in-process acceptance test) but drives the REAL published container
# image end to end, black-box, exactly as this harness's mandate requires.

# _obs_boot_node : boot one real `pillar node run` process (the image's
# default entrypoint, no crate linkage) with its bootstrap/web HTTP surface
# published alongside the existing health probe port. Populates
# OBS_NAME/OBS_HEALTH_ADDR/OBS_WEB_ADDR.
_obs_boot_node() {
    OBS_NAME="pillar-it-${FIXTURE_SCENARIO}-node"
    local cid
    cid=$("$CONTAINER_RUNTIME" run -d \
        --name "$OBS_NAME" \
        --label "$FIXTURE_LABEL" \
        -e PILLAR_WEB_BIND=0.0.0.0 \
        -e PILLAR_WEB_PORT=8642 \
        -p "127.0.0.1::8643" \
        -p "127.0.0.1::8642" \
        "$PILLAR_IMAGE" 2>&1) \
        || fail "observability node failed to start: $cid"
    OBS_HEALTH_ADDR=$("$CONTAINER_RUNTIME" port "$OBS_NAME" 8643 2>/dev/null | head -1)
    OBS_WEB_ADDR=$("$CONTAINER_RUNTIME" port "$OBS_NAME" 8642 2>/dev/null | head -1)
    [ -n "$OBS_HEALTH_ADDR" ] || fail "could not resolve published health port for observability node"
    [ -n "$OBS_WEB_ADDR" ] || fail "could not resolve published web port for observability node"
    info "observability-psl: node up as $OBS_NAME (health=$OBS_HEALTH_ADDR web=$OBS_WEB_ADDR)"
}

# _obs_wait_ready : block until both the health and bootstrap-web surfaces
# answer, proving the real process is up before we start driving it.
_obs_wait_ready() {
    retry 30 bash -c "curl -s -m 2 -o /dev/null http://${OBS_HEALTH_ADDR}/readyz" \
        || fail "node at $OBS_HEALTH_ADDR never answered /readyz within 30s"
    retry 30 bash -c "curl -s -m 2 -o /dev/null http://${OBS_WEB_ADDR}/bootstrap/status" \
        || fail "node at $OBS_WEB_ADDR never answered /bootstrap/status within 30s"
}

# _obs_bootstrap_and_login : bootstrap a fresh cell + first user over the real
# HTTP surface, then perform the real nonce+login handshake. Echoes the
# resulting session bearer.
_obs_bootstrap_and_login() {
    local cell_id="obs-psl-cell" user="dana" password="dana-pass-1!" reply code body
    reply=$(driver_http_post "$OBS_WEB_ADDR" /bootstrap/create-cell "$cell_id") \
        || fail "create-cell to $OBS_WEB_ADDR unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "create-cell '$cell_id' refused: $code $body"
    info "oracle-observed: bootstrap-cell cell=$cell_id -> $body (real create-cell HTTP effect)" >&2

    reply=$(driver_http_post "$OBS_WEB_ADDR" /bootstrap/create-user "${user}"$'\n'"${password}") \
        || fail "create-user to $OBS_WEB_ADDR unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "create-user '$user' refused: $code $body"
    info "oracle-observed: bootstrap-user cell=$cell_id user=$user -> $body (real create-user HTTP effect)" >&2

    local nonce_reply nonce_id session
    nonce_reply=$(curl -s -m 10 "http://${OBS_WEB_ADDR}/nonce") \
        || fail "GET /nonce to $OBS_WEB_ADDR unreachable"
    nonce_id=$(printf '%s' "$nonce_reply" | awk '{print $2}')
    [ -n "$nonce_id" ] || fail "malformed nonce reply from $OBS_WEB_ADDR: $nonce_reply"

    reply=$(driver_http_post "$OBS_WEB_ADDR" /login "${user}"$'\n'"${password}"$'\n'"${nonce_id}") \
        || fail "POST /login to $OBS_WEB_ADDR unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    session=$(printf '%s\n' "$reply" | sed -n '2p')
    [ "$code" = "200" ] || fail "login for '$user' at $OBS_WEB_ADDR refused: $code"
    [ -n "$session" ] || fail "login for '$user' at $OBS_WEB_ADDR returned no X-Pillar-Session bearer"
    info "oracle-observed: login cell=$cell_id user=$user (real nonce+login handshake, session issued)" >&2
    printf '%s' "$session"
}

# _obs_kinds_count <token> <kind> : print the real-ingested count for one
# signal kind off `GET /portal/obs/live/kinds`.
_obs_kinds_count() {
    local token="$1" kind="$2" out line
    out=$(curl -s -m 10 "http://${OBS_WEB_ADDR}/portal/obs/live/kinds?token=${token}") \
        || fail "GET /portal/obs/live/kinds unreachable"
    line=$(printf '%s\n' "$out" | grep "^KIND ${kind} " || true)
    [ -n "$line" ] || { echo 0; return; }
    printf '%s\n' "$line" | grep -o 'COUNT [0-9]*' | awk '{print $2}'
}

# _obs_wait_all_kinds_ingested <token> : block until every one of the five
# signal kinds shows a real, non-zero ingested count — the node's real
# self-metrics ticker (every 15s: metric+profile+metadata each tick, plus a
# per-tick log+span) needs at least one full tick to populate every kind.
_obs_wait_all_kinds_ingested() {
    local token="$1" kind all_ready=1 attempt
    for attempt in $(seq 1 60); do
        all_ready=1
        for kind in metric log trace profile metadata; do
            local count
            count=$(_obs_kinds_count "$token" "$kind")
            [ -n "$count" ] && [ "$count" -gt 0 ] 2>/dev/null || { all_ready=0; break; }
        done
        [ "$all_ready" -eq 1 ] && return 0
        sleep 2
    done
    return 1
}

scenario_observability-psl() {
    # (1) a REAL running node with its bootstrap/web HTTP surface published.
    _obs_boot_node
    _obs_wait_ready
    oracle_process "$OBS_NAME" "$OBS_HEALTH_ADDR"

    # (2) bootstrap a cell + first user, then log in for a real session
    # bearer — driven entirely over the real HTTP surface.
    local token
    token=$(_obs_bootstrap_and_login)

    # The live surface's auth gate holds: no token -> 401.
    local unauth_code
    unauth_code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "http://${OBS_WEB_ADDR}/portal/obs/live/kinds") \
        || fail "GET /portal/obs/live/kinds (unauth) unreachable"
    [ "$unauth_code" = "401" ] || fail "live surface must require an admitted session; got $unauth_code"
    info "oracle-observed: live-surface-auth-gate unauthenticated /portal/obs/live/kinds refused with 401"

    # (3) wait for the node's REAL self-instrumentation to independently
    # ingest every one of the five signal kinds (never fabricated by this
    # harness — the node's own controller loop feeds them).
    _obs_wait_all_kinds_ingested "$token" \
        || fail "not all five signal kinds (metric/log/trace/profile/metadata) were really ingested within 120s"
    info "oracle-observed: all-five-kinds-ingested node=$OBS_NAME has real non-zero counts for every signal kind"

    # For each kind: the kinds-endpoint count and the explore-endpoint record
    # count must agree — every kind's data is independently traceable to a
    # real ingested signal, never phantom.
    local kind
    for kind in metric log trace profile metadata; do
        local count explore records
        count=$(_obs_kinds_count "$token" "$kind")
        explore=$(curl -s -m 10 "http://${OBS_WEB_ADDR}/portal/obs/live/explore?token=${token}&kind=${kind}") \
            || fail "GET /portal/obs/live/explore?kind=${kind} unreachable"
        records=$(printf '%s\n' "$explore" | grep -c '^SIGNAL ' || true)
        [ "$records" -eq "$count" ] \
            || fail "explore for $kind must surface exactly the ingested signals: count=$count records=$records"
        info "oracle-observed: kind-traceable kind=$kind count=$count explore-records=$records"
    done

    # (4) PSL select/where/range over the live data: a query for a really
    # ingested kind returns real signals, every one of which the explore
    # ground-truth also holds — never phantom data.
    local q_metric metric_hits
    q_metric=$(curl -s -m 10 -X POST --data-binary "${token}"$'\n'"select: metrics range: now-100000s" \
        "http://${OBS_WEB_ADDR}/portal/obs/live/query") \
        || fail "PSL metric query unreachable"
    metric_hits=$(printf '%s\n' "$q_metric" | grep -c '^SIGNAL ' || true)
    [ "$metric_hits" -gt 0 ] || fail "PSL select over real ingested metrics returned no signals: $q_metric"

    local explore_metric held_ids id line
    explore_metric=$(curl -s -m 10 "http://${OBS_WEB_ADDR}/portal/obs/live/explore?token=${token}&kind=metric") \
        || fail "GET /portal/obs/live/explore?kind=metric unreachable"
    held_ids=$(printf '%s\n' "$explore_metric" | grep '^SIGNAL ' | awk '{print $2}')
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        id=$(printf '%s\n' "$line" | awk '{print $2}')
        printf '%s\n' "$held_ids" | grep -qx "$id" \
            || fail "PSL returned signal $id that is NOT really held — phantom data (RED)"
    done < <(printf '%s\n' "$q_metric" | grep '^SIGNAL ')
    info "oracle-observed: psl-select-real-data every PSL-returned metric signal is really held by the live store"

    # A correlate query centered on the trace kind groups real trace spans
    # sharing a correlation id.
    local q_corr
    q_corr=$(curl -s -m 10 -X POST --data-binary "${token}"$'\n'"select: traces range: now-100000s correlate: { window: 100000s, anchor: traces }" \
        "http://${OBS_WEB_ADDR}/portal/obs/live/query") \
        || fail "PSL correlate query unreachable"
    printf '%s\n' "$q_corr" | grep -q '^GROUP ' \
        || fail "a correlate query over live traces must produce at least one group: $q_corr"
    info "oracle-observed: psl-correlate real trace spans grouped by correlation id"

    # A query for a WHERE no real signal satisfies returns nothing.
    local q_none
    q_none=$(curl -s -m 10 -X POST --data-binary "${token}"$'\n'"select: metrics where: metric = this-metric-never-emitted range: now-100000s" \
        "http://${OBS_WEB_ADDR}/portal/obs/live/query") \
        || fail "PSL empty query unreachable"
    printf '%s\n' "$q_none" | grep -q '^SIGNAL ' \
        && fail "a PSL query with no matching real signal must return nothing (no fabrication): $q_none"
    info "oracle-observed: psl-where-no-match query for an unemitted metric correctly returned nothing"

    # (5) a recording rule evaluates across kinds on the node's REAL
    # scheduler engine over the live store, and fires with a real derived
    # value reflecting the really-ingested logs.
    local rule derived_line
    rule=$(curl -s -m 10 -X POST --data-binary "${token}"$'\n'"log-rate|log-count|select: logs range: now-100000s|log_count" \
        "http://${OBS_WEB_ADDR}/portal/obs/live/recording") \
        || fail "recording rule unreachable"
    printf '%s\n' "$rule" | grep -q 'FIRED true' \
        || fail "the recording rule must fire on the live store: $rule"
    derived_line=$(printf '%s\n' "$rule" | grep '^DERIVED ' || true)
    [ -n "$derived_line" ] || fail "recording rule response missing DERIVED line: $rule"
    printf '%s\n' "$derived_line" | grep -qE '[1-9]' \
        || fail "the derived metric must reflect real ingested logs (non-zero): $derived_line"
    info "oracle-observed: recording-rule fired on real scheduler engine over the live store: $derived_line"

    # An alert whose predicate trips on the real log volume (count > 0) fires
    # a notification; one whose threshold no real value can trip does not.
    local alert
    alert=$(curl -s -m 10 -X POST --data-binary "${token}"$'\n'"logs-present|select: logs range: now-100000s|gt|0" \
        "http://${OBS_WEB_ADDR}/portal/obs/live/alert") \
        || fail "alert unreachable"
    printf '%s\n' "$alert" | grep -q '^ALERT ' \
        || fail "an alert over real live logs must fire a notification: $alert"
    info "oracle-observed: alert-fires alert on real log volume fired: $alert"

    local quiet
    quiet=$(curl -s -m 10 -X POST --data-binary "${token}"$'\n'"impossible|select: logs range: now-100000s|gt|1000000" \
        "http://${OBS_WEB_ADDR}/portal/obs/live/alert") \
        || fail "quiet alert unreachable"
    printf '%s\n' "$quiet" | grep -q '^ALERT ' \
        && fail "an alert no real value trips must NOT fire: $quiet"
    info "oracle-observed: alert-quiet an impossible threshold correctly fired nothing"

    # (6) a dashboard materializes every panel from the real live store.
    local panels dash
    panels="metrics=select: metrics range: now-100000s"$'\n'"logs=select: logs range: now-100000s"$'\n'"traces=select: traces range: now-100000s"
    dash=$(curl -s -m 10 -X POST --data-binary "${token}"$'\n'"${panels}" \
        "http://${OBS_WEB_ADDR}/portal/obs/live/dashboard") \
        || fail "dashboard unreachable"
    local panel header count
    for panel in metrics logs traces; do
        header=$(printf '%s\n' "$dash" | grep "^PANEL ${panel} " || true)
        [ -n "$header" ] || fail "missing panel $panel: $dash"
        count=$(printf '%s\n' "$header" | grep -o 'COUNT [0-9]*' | awk '{print $2}')
        [ -n "$count" ] && [ "$count" -gt 0 ] 2>/dev/null \
            || fail "dashboard panel $panel must materialize real live data; got count=$count"
        info "oracle-observed: dashboard-panel panel=$panel count=$count (materialized from the real live store)"
    done

    info "observability-psl: all five signal kinds independently traceable, PSL select/where/range/correlate proven against real data, recording rule + alerts fired on the real scheduler engine, and dashboard panels materialized from the real live store"
}
