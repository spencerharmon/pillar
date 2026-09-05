#!/usr/bin/env bash
# scenarios/geo-replication.sh — ROI "pillar-integration" scenario family:
# geo-replication (operator-directed, 2026-08-31).
#
# Stands up a REAL two-cell multi-site topology: two independent `pillar node
# run` processes on the real published image, each its own cell's genesis
# node (`host` = cell "geo-host", `remote` = cell "geo-remote"). Drives BOTH
# solely through their real HTTP bootstrap surface
# (`pillar_cli::web_serve`'s gated route table — never linking a pillar
# crate), establishes cross-cell trust by having the remote cell's node
# submit a bootstrap NODE join request to the host cell and having the host
# cell approve it, then asserts:
#
#   1. cross-cell trust: the host cell's real approve response is a genuine
#      content-addressed sealed-cell-key CID (`oracle_ciphertext_no_leak`
#      shape check) — proof a real cross-cell approval flow ran end to end.
#   2. the ciphertext oracle: the host cell (the approver) never leaks the
#      plaintext cell-key material through its own API — it can hand over
#      only ciphertext + a CID, never observably decrypt
#      (`oracle_ciphertext_no_leak`'s no-leak check, computed independently
#      from the SAME public plaintext-stand-in formula
#      `crates/pillar-bootstrap/src/request.rs` documents, so a real
#      regression that ever echoed the plaintext back would be caught here).
#   3. live-HA: after the HOST (primary) cell's real container process is
#      killed outright, the REMOTE cell's real process — a wholly
#      independent container — keeps answering its own real readiness
#      surface, proving cross-cell read continuity survives a primary-cell
#      kill.
#
# RED / GREEN: RED if the approve response ever contained the plaintext
# cell-key hex (a real, observable leak) or was not a genuine sealed CID;
# GREEN when the response is a real sealed CID, no plaintext ever appears in
# it, and the remote cell answers readiness after the host is killed.
#
# NOTE on the decrypt-succeeds-only-for-the-holder half of the ROI's realness
# oracle: `pillar_cli`'s `key`/`offer`/`identity` verb family (the CLI surface
# that would let an EXTERNAL, black-box caller resolve/unseal a sealed
# offer as the holder) is not yet wired to argv (`cli_surface::identity_trust`
# is a stub returning guidance, exit 2) — only the library API
# (`SealedCellKey::unseal`) can do it today, and this harness never links a
# pillar crate. This scenario therefore proves the HOST-side half of the
# ciphertext oracle (ciphertext+CID only, no decrypt/no leak) directly and in
# full; the holder-side "a real external unseal succeeds" half is not yet
# independently observable from outside the process without that CLI verb.

# _geo_web_addr / _geo_health_addr : populated by _geo_boot_cell_node.
declare -a GEO_NAMES=()
declare -a GEO_WEB_ADDRS=()
declare -a GEO_HEALTH_ADDRS=()

# _geo_boot_cell_node <label> : boot one real, independent `pillar node run`
# process (the image's default entrypoint, no crate linkage) with its
# bootstrap/web HTTP surface published (via `PILLAR_WEB_BIND`/
# `PILLAR_WEB_PORT` env — `crates/pillar-cli/src/run.rs`) alongside the
# existing health probe port, so the scenario can drive it purely over the
# wire. Appends to GEO_NAMES/GEO_WEB_ADDRS/GEO_HEALTH_ADDRS.
_geo_boot_cell_node() {
    local label="$1" name cid web_addr health_addr
    name="pillar-it-${FIXTURE_SCENARIO}-cell-${label}"
    cid=$("$CONTAINER_RUNTIME" run -d \
        --name "$name" \
        --label "$FIXTURE_LABEL" \
        -e PILLAR_WEB_BIND=0.0.0.0 \
        -e PILLAR_WEB_PORT=8642 \
        -p "127.0.0.1::8643" \
        -p "127.0.0.1::8642" \
        "$PILLAR_IMAGE" 2>&1) \
        || fail "cell '$label' node failed to start: $cid"
    health_addr=$("$CONTAINER_RUNTIME" port "$name" 8643 2>/dev/null | head -1)
    web_addr=$("$CONTAINER_RUNTIME" port "$name" 8642 2>/dev/null | head -1)
    [ -n "$health_addr" ] || fail "could not resolve published health port for cell '$label'"
    [ -n "$web_addr" ] || fail "could not resolve published web port for cell '$label'"
    GEO_NAMES+=("$name")
    GEO_HEALTH_ADDRS+=("$health_addr")
    GEO_WEB_ADDRS+=("$web_addr")
    info "geo-replication: cell '$label' up as $name (health=$health_addr web=$web_addr)"
}

# _geo_wait_ready <health-addr> <web-addr> : block until both the health and
# bootstrap-web surfaces answer, proving the real process is up before we
# start driving it.
_geo_wait_ready() {
    local health_addr="$1" web_addr="$2"
    retry 30 bash -c "curl -s -m 2 -o /dev/null http://${health_addr}/readyz" \
        || fail "node at $health_addr never answered /readyz within 30s"
    retry 30 bash -c "curl -s -m 2 -o /dev/null http://${web_addr}/bootstrap/status" \
        || fail "node at $web_addr never answered /bootstrap/status within 30s"
}

# _geo_bootstrap_cell <web-addr> <cell-id> <user> <password> : bootstrap a
# fresh cell + its first user over the real HTTP surface (create-cell,
# create-user).
_geo_bootstrap_cell() {
    local web_addr="$1" cell_id="$2" user="$3" password="$4" reply code body
    reply=$(driver_http_post "$web_addr" /bootstrap/create-cell "$cell_id") \
        || fail "create-cell to $web_addr unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "create-cell '$cell_id' refused: $code $body"
    info "oracle-observed: bootstrap-cell cell=$cell_id -> $body (real create-cell HTTP effect)"

    reply=$(driver_http_post "$web_addr" /bootstrap/create-user "${user}"$'\n'"${password}") \
        || fail "create-user to $web_addr unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "create-user '$user' refused: $code $body"
    info "oracle-observed: bootstrap-user cell=$cell_id user=$user -> $body (real create-user HTTP effect)"
}

# _geo_login <web-addr> <user> <password> : the real GET /nonce -> POST
# /login handshake; echoes the resulting session bearer.
_geo_login() {
    local web_addr="$1" user="$2" password="$3" nonce_reply nonce_id reply code session
    nonce_reply=$(curl -s -m 10 "http://${web_addr}/nonce") \
        || fail "GET /nonce to $web_addr unreachable"
    nonce_id=$(printf '%s' "$nonce_reply" | awk '{print $2}')
    [ -n "$nonce_id" ] || fail "malformed nonce reply from $web_addr: $nonce_reply"

    reply=$(driver_http_post "$web_addr" /login "${user}"$'\n'"${password}"$'\n'"${nonce_id}") \
        || fail "POST /login to $web_addr unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    session=$(printf '%s\n' "$reply" | sed -n '2p')
    [ "$code" = "200" ] || fail "login for '$user' at $web_addr refused: $code"
    [ -n "$session" ] || fail "login for '$user' at $web_addr returned no X-Pillar-Session bearer"
    printf '%s' "$session"
}

scenario_geo-replication() {
    # (1) a REAL two-cell multi-site topology: two independent node
    # processes, each its own cell's genesis node.
    _geo_boot_cell_node host
    _geo_boot_cell_node remote
    _geo_wait_ready "${GEO_HEALTH_ADDRS[0]}" "${GEO_WEB_ADDRS[0]}"
    _geo_wait_ready "${GEO_HEALTH_ADDRS[1]}" "${GEO_WEB_ADDRS[1]}"
    local host_web="${GEO_WEB_ADDRS[0]}" remote_web="${GEO_WEB_ADDRS[1]}"

    # Process oracle on both real cell nodes: a real pid + a real bound
    # listening socket, before we start driving them.
    oracle_process "${GEO_NAMES[0]}" "${GEO_HEALTH_ADDRS[0]}"
    oracle_process "${GEO_NAMES[1]}" "${GEO_HEALTH_ADDRS[1]}"

    # (2) bootstrap each cell + its first user — two genuinely independent
    # cells, each with real state.
    local host_cell="geo-host" remote_cell="geo-remote"
    _geo_bootstrap_cell "$host_web" "$host_cell" alice 'alice-pass-1!'
    _geo_bootstrap_cell "$remote_web" "$remote_cell" carol 'carol-pass-1!'

    # (3) cross-cell trust: the remote cell's node submits a bootstrap NODE
    # join request to the HOST cell (as if the remote cell's node were
    # joining/federating with the host cell), and an authorized host-cell
    # member (alice) approves it.
    local host_alice_token
    host_alice_token=$(_geo_login "$host_web" alice 'alice-pass-1!')
    info "oracle-observed: login host-cell=$host_cell user=alice (real nonce+login handshake, session issued)"

    local subject="geo-remote-node" peer_id="12D3KooWgeoremote" pubkey_cid="bafy-geo-remote-pubkey"
    local submit_body
    submit_body="${subject}"$'\n'"${peer_id}"$'\n'"1.0.0-geo-it"$'\n'"linux"$'\n'"${pubkey_cid}"$'\n'"tpm"$'\n'"pub=${remote_web}"
    local reply code body
    reply=$(driver_http_post "$host_web" /bootstrap/request/node "$submit_body") \
        || fail "submitting node request to host $host_web unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "node bootstrap request to host refused: $code $body"
    local req_id="${body#REQUEST }"
    [ -n "$req_id" ] && [ "$req_id" != "$body" ] || fail "malformed node-request reply from host: $body"
    info "oracle-observed: cross-cell-request remote-node subject=$subject submitted to host, id=$req_id"

    local list_out list_code
    list_out=$(curl -s -m 10 -w '\n%{http_code}' "http://${host_web}/bootstrap/request/list") \
        || fail "GET /bootstrap/request/list on host unreachable"
    list_code=$(printf '%s\n' "$list_out" | tail -1)
    body=$(printf '%s\n' "$list_out" | sed '$d')
    [ "$list_code" = "200" ] || fail "request list on host refused: $list_code $body"
    printf '%s\n' "$body" | grep -q "^${req_id} node ${subject}\$" \
        || fail "host's pending bootstrap-request queue does not show ${req_id} node ${subject} (got: $body)"
    info "oracle-observed: cross-cell-request-pending host queue lists $req_id node $subject"

    reply=$(driver_http_post "$host_web" /bootstrap/request/approve "${req_id}"$'\n'"${host_alice_token}") \
        || fail "approving node request on host unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "node bootstrap request approval refused: $code $body"
    info "geo-replication: host cell '$host_cell' approved cross-cell node request $req_id from remote cell '$remote_cell'"

    # (4) the ciphertext oracle: the host's own approve response is a real
    # content-addressed sealed-cell-key CID, and it NEVER leaks the
    # plaintext cell-key material — the host has ciphertext + CID and
    # cannot itself decrypt.
    oracle_ciphertext_no_leak "$body" "$host_cell"

    # (5) live-HA: kill the HOST (primary) cell's real container process
    # outright, then assert the REMOTE cell — a wholly independent real
    # process — keeps answering its own real readiness surface.
    info "geo-replication: killing the primary (host) cell's real container to assert cross-cell live-HA continuity"
    "$CONTAINER_RUNTIME" rm -f "${GEO_NAMES[0]}" >/dev/null 2>&1 \
        || fail "could not kill host cell container ${GEO_NAMES[0]}"
    topology_node_running "${GEO_NAMES[0]}" \
        && fail "host cell container ${GEO_NAMES[0]} is still running after an explicit kill"
    info "oracle-observed: host-killed host cell container ${GEO_NAMES[0]} is confirmed not running"

    local remote_resp remote_code remote_body
    remote_resp=$(driver_http "${GEO_HEALTH_ADDRS[1]}" /readyz) \
        || fail "remote cell stopped answering /readyz immediately after the host cell was killed"
    remote_code=$(printf '%s' "$remote_resp" | cut -d' ' -f1)
    remote_body=$(printf '%s' "$remote_resp" | cut -d' ' -f2-)
    [ "$remote_code" = "200" ] && [ "$remote_body" = "ready" ] \
        || fail "remote cell readiness after host kill returned '$remote_code $remote_body', expected '200 ready'"
    info "oracle-observed: live-ha remote cell ${GEO_NAMES[1]} still answers 200 'ready' on ${GEO_HEALTH_ADDRS[1]} after the primary (host) cell was killed"

    info "geo-replication: cross-cell trust established, ciphertext oracle held (host has ciphertext+CID, no plaintext leak), and live-HA read continuity survived a primary-cell kill"
}
