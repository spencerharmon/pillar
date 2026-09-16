#!/usr/bin/env bash
# scenarios/data-layer-single-substrate.sh — ROI Priority 1 acceptance scenario:
# "The data layer must be dogfooded: one substrate the cell writes and the
# portal inspects" (operator, 2026-09-16).
#
# This is the TERMINAL ACCEPTANCE scenario for the per-plane keyed-store
# migrations (sessions-kv / rbac-document / quota-sql / wot-trust / iam-plane).
# Each of those leaves passed its own crate-unit check while changing NOTHING an
# operator could observe on a live cell — a running cell held disconnected
# private keyed stores (the session registry's own, and a fresh empty one the
# portal's Explore panels browsed), so the panels rendered EMPTY against a live
# cell. This scenario owns the SEAM between those leaves that none of them owned:
# it proves, black-box over a real >=3-node topology's external HTTP surfaces
# only (never linking a pillar crate), that the substrate the cell WRITES on its
# live paths is the SAME substrate the portal INSPECTS.
#
# The oracles (each prints an `oracle-observed:` line naming the concrete real
# effect it saw, so a reviewer can confirm realness from the transcript alone):
#
#   surfacing (single-substrate) — a session created through the REAL login API
#       (`GET /nonce` -> `POST /login`) appears in the portal's kv browse of the
#       live cell (`GET /portal/data/kv/collections` lists `sessions`, and
#       `GET /portal/data/kv/keys?collection=sessions` enumerates its key). If
#       the session registry still wrote a PRIVATE store (the pre-consolidation
#       false-DONE), `sessions` would never appear in the portal browse and this
#       oracle would be RED — exactly the empty-panel-over-a-populated-plane
#       defect the ROI names.
#
#   empty-iff-empty — a keyed collection NOBODY has written is empty in the same
#       browse surface (an Explore panel is empty IFF its plane is empty). An
#       empty panel over a populated plane is the defect; a non-empty panel over
#       an empty plane would be a phantom second store. Both are RED here.
#
#   multi-node realness — the surfacing oracle is asserted against EACH of the
#       real >=3 topology nodes' own bootstrapped cell + portal, and a process
#       oracle on every node confirms a real pid + bound socket, so the single-
#       substrate property holds on real running image nodes, not one stub host.
#
# RED if a live session never surfaces in the portal browse (two stores), if an
# untouched collection is non-empty (phantom store), or if a node is not a real
# process; GREEN when every node's live session surfaces in ITS portal browse
# over one substrate and the empty plane reads empty. Sourced by run-scenario.sh,
# which has already sourced the lib layer and run fixtures_init.

# Per-node published web (bootstrap/portal) addresses, index-aligned with
# TOPO_NODES. `topology_boot` publishes only the health probe port; this
# scenario needs each node's web surface too, so it boots its own cell nodes
# with the web port published (the geo-replication pattern).
declare -a DLSS_NAMES=()
declare -a DLSS_WEB_ADDRS=()
declare -a DLSS_HEALTH_ADDRS=()

# _dlss_boot_node <index> : boot one real, independent `pillar node run`
# process (the image's default entrypoint, no crate linkage) with BOTH its
# health probe (8643) and its bootstrap/portal web surface (8642, via
# PILLAR_WEB_BIND/PILLAR_WEB_PORT) published, so the scenario drives it purely
# over the wire. Appends to DLSS_NAMES/DLSS_WEB_ADDRS/DLSS_HEALTH_ADDRS.
_dlss_boot_node() {
    local idx="$1" name cid web_addr health_addr
    name="pillar-it-${FIXTURE_SCENARIO}-node${idx}"
    cid=$("$CONTAINER_RUNTIME" run -d \
        --name "$name" \
        --label "$FIXTURE_LABEL" \
        -e PILLAR_WEB_BIND=0.0.0.0 \
        -e PILLAR_WEB_PORT=8642 \
        -p "127.0.0.1::8643" \
        -p "127.0.0.1::8642" \
        "$PILLAR_IMAGE" 2>&1) \
        || fail "node$idx failed to start: $cid"
    health_addr=$("$CONTAINER_RUNTIME" port "$name" 8643 2>/dev/null | head -1)
    web_addr=$("$CONTAINER_RUNTIME" port "$name" 8642 2>/dev/null | head -1)
    [ -n "$health_addr" ] || fail "could not resolve published health port for node$idx"
    [ -n "$web_addr" ] || fail "could not resolve published web port for node$idx"
    DLSS_NAMES+=("$name")
    DLSS_HEALTH_ADDRS+=("$health_addr")
    DLSS_WEB_ADDRS+=("$web_addr")
    # Keep the topology arrays populated so the shared process oracle works.
    TOPO_NODES+=("$name")
    TOPO_PROBE_ADDRS+=("$health_addr")
    info "data-layer-single-substrate: node$idx up as $name (health=$health_addr web=$web_addr)"
}

# _dlss_wait_ready <health-addr> <web-addr> : block until both the health and
# bootstrap/portal web surfaces answer, proving the real process is up.
_dlss_wait_ready() {
    local health_addr="$1" web_addr="$2"
    retry 30 bash -c "curl -s -m 2 -o /dev/null http://${health_addr}/readyz" \
        || fail "node at $health_addr never answered /readyz within 30s"
    retry 30 bash -c "curl -s -m 2 -o /dev/null http://${web_addr}/bootstrap/status" \
        || fail "node at $web_addr never answered /bootstrap/status within 30s"
}

# _dlss_bootstrap_cell <web-addr> <cell-id> <user> <password> : bootstrap a
# fresh cell + its first user over the real HTTP surface.
_dlss_bootstrap_cell() {
    local web_addr="$1" cell_id="$2" user="$3" password="$4" reply code body
    reply=$(driver_http_post "$web_addr" /bootstrap/create-cell "$cell_id") \
        || fail "create-cell to $web_addr unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "create-cell '$cell_id' refused: $code $body"

    reply=$(driver_http_post "$web_addr" /bootstrap/create-user "${user}"$'\n'"${password}") \
        || fail "create-user to $web_addr unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "create-user '$user' refused: $code $body"
    info "oracle-observed: bootstrap cell=$cell_id user=$user (real create-cell/create-user HTTP effect)"
}

# _dlss_login <web-addr> <user> <password> : the real GET /nonce -> POST /login
# handshake; echoes the resulting X-Pillar-Session bearer. This is the live cell
# WRITE path under test — a successful login MINTS a server-side session, which
# (post-consolidation) lands in the shared keyed-store substrate.
_dlss_login() {
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

# _dlss_browse <web-addr> <token> <path-with-query> : GET a portal data-browse
# route with the session bearer as the `token=` query param the browse routes
# gate on. Prints "<http-code>\n<body>" (body may be multi-line). Fails only on
# an unreachable HTTP layer.
_dlss_browse() {
    local web_addr="$1" token="$2" route="$3" sep out code body
    case "$route" in
        *\?*) sep='&' ;;
        *)    sep='?' ;;
    esac
    out=$(curl -s -m 10 -w '\n%{http_code}' "http://${web_addr}${route}${sep}token=${token}" 2>/dev/null) \
        || return 1
    code=$(printf '%s' "$out" | tail -1)
    body=$(printf '%s' "$out" | sed '$d')
    printf '%s\n%s' "$code" "$body"
}

# oracle_single_substrate_session_surfaces <web-addr> <token> : the surfacing +
# single-substrate oracle. Asserts a session minted by the real login on this
# node's live cell appears in THIS node's portal kv browse (the `sessions`
# collection is listed AND its key is enumerable) — proof the registry write and
# the portal read hit ONE keyed-store substrate, not two disconnected stores.
oracle_single_substrate_session_surfaces() {
    local web_addr="$1" token="$2" out code body
    out=$(_dlss_browse "$web_addr" "$token" "/portal/data/kv/collections") \
        || fail "single-substrate oracle: kv/collections on $web_addr unreachable"
    code=$(printf '%s\n' "$out" | sed -n '1p')
    body=$(printf '%s\n' "$out" | tail -n +2)
    [ "$code" = "200" ] || fail "single-substrate oracle: kv/collections on $web_addr returned $code ($body)"
    printf '%s\n' "$body" | grep -qx "sessions" \
        || fail "single-substrate oracle: the live session did NOT surface in the portal kv browse on $web_addr (collections: $(printf '%s' "$body" | tr '\n' ',')) — the session plane and the portal browse are TWO stores, not one"

    out=$(_dlss_browse "$web_addr" "$token" "/portal/data/kv/keys?collection=sessions") \
        || fail "single-substrate oracle: kv/keys(sessions) on $web_addr unreachable"
    code=$(printf '%s\n' "$out" | sed -n '1p')
    body=$(printf '%s\n' "$out" | tail -n +2)
    [ "$code" = "200" ] || fail "single-substrate oracle: kv/keys(sessions) on $web_addr returned $code ($body)"
    [ -n "$(printf '%s' "$body" | tr -d '[:space:]')" ] \
        || fail "single-substrate oracle: the sessions collection surfaced but is EMPTY on $web_addr — the live login write is invisible to the portal (empty panel over a populated plane)"
    info "oracle-observed: single-substrate node-web=$web_addr sessions-collection-surfaced key=$(printf '%s' "$body" | head -1) (one keyed-store substrate: registry write == portal read)"
}

# oracle_empty_iff_empty <web-addr> <token> : the empty-iff-empty oracle. A
# keyed collection NOBODY wrote must read EMPTY in the same browse surface — an
# Explore panel is empty IFF its plane is empty. A non-empty result would be a
# phantom second store; a `sessions`-style always-empty would be the disconnect.
oracle_empty_iff_empty() {
    local web_addr="$1" token="$2" out code body
    out=$(_dlss_browse "$web_addr" "$token" "/portal/data/kv/keys?collection=__dlss_never_written__") \
        || fail "empty-iff-empty oracle: kv/keys on $web_addr unreachable"
    code=$(printf '%s\n' "$out" | sed -n '1p')
    body=$(printf '%s\n' "$out" | tail -n +2)
    [ "$code" = "200" ] || fail "empty-iff-empty oracle: kv/keys on $web_addr returned $code ($body)"
    [ -z "$(printf '%s' "$body" | tr -d '[:space:]')" ] \
        || fail "empty-iff-empty oracle: an unwritten collection is NON-empty on $web_addr ($body) — a phantom second store"
    info "oracle-observed: empty-iff-empty node-web=$web_addr unwritten-collection-empty (no phantom store; panel empty IFF plane empty)"
}

# oracle_plane_collections_share_substrate <web-addr> <token> : the multi-plane
# single-substrate oracle. The RBAC-grant, quota, and web-of-trust planes each
# project their live web write as a resource-event into the SAME keyed-store
# substrate the portal browses (see WebAuthContext::project_plane_event). This
# oracle asserts each plane's Document collection (`rbac_grants`, `quota_ledger`,
# `wot_edges`) is BROWSABLE through the portal doc-browse route on this live node
# — the same substrate handle, one keyed op-log. With no grant/quota/edge issued
# yet on this fresh node the collections read empty (empty-iff-empty over the doc
# surface); the code-level surfacing of a real issued grant/quota/edge is proven
# by the `rbac_quota_wot_planes_surface_in_the_one_substrate` regression test
# over the real WebAuthContext control-op path.
oracle_plane_collections_share_substrate() {
    local web_addr="$1" token="$2" plane out code body
    for plane in rbac_grants quota_ledger wot_edges; do
        out=$(_dlss_browse "$web_addr" "$token" "/portal/data/doc/ids?collection=${plane}") \
            || fail "plane-substrate oracle: doc/ids(${plane}) on $web_addr unreachable"
        code=$(printf '%s\n' "$out" | sed -n '1p')
        body=$(printf '%s\n' "$out" | tail -n +2)
        [ "$code" = "200" ] \
            || fail "plane-substrate oracle: doc/ids(${plane}) on $web_addr returned $code ($body) — the ${plane} plane is NOT browsable on the portal's single substrate"
        [ -z "$(printf '%s' "$body" | tr -d '[:space:]')" ] \
            || fail "plane-substrate oracle: the unwritten ${plane} plane is NON-empty on $web_addr ($body) — a phantom second store"
        info "oracle-observed: plane-substrate node-web=$web_addr plane=${plane} browsable-on-single-substrate (one keyed op-log; empty IFF plane empty)"
    done
}

scenario_data-layer-single-substrate() {
    local n="${PILLAR_IT_NODES:-3}"
    [ "$n" -ge 3 ] || fail "data-layer-single-substrate: the ROI requires >=3 real nodes (got $n)"

    # The single-substrate consolidation is a BEHAVIOR change (a live-login
    # session now surfaces in the portal browse), not a new CLI verb, so
    # `image_require_verb` cannot detect whether the published image already
    # carries it. Build the reproducible image-under-test from THIS working
    # tree's flake so the scenario asserts against the code under review — the
    # same black-box contract (a real OCI image, driven only over its wire).
    # An explicit operator override (`PILLAR_IT_PREBUILT=1`, e.g. CI already
    # published the tree) skips the build and drives `$PILLAR_IMAGE` as-is.
    if [ -z "${PILLAR_IT_PREBUILT:-}" ]; then
        image_build_local
    fi

    # (1) a REAL >=3-node topology on the real published image, each node its own
    # cell genesis with BOTH health + portal web surfaces published.
    local i
    for ((i = 0; i < n; i++)); do
        _dlss_boot_node "$i"
    done
    for i in "${!DLSS_NAMES[@]}"; do
        _dlss_wait_ready "${DLSS_HEALTH_ADDRS[$i]}" "${DLSS_WEB_ADDRS[$i]}"
    done
    info "data-layer-single-substrate: ${#DLSS_NAMES[@]} real nodes up"

    # (2) process oracle on every real node: a real pid + a real bound listening
    # socket, before we drive any browse surface.
    for i in "${!DLSS_NAMES[@]}"; do
        oracle_process "${DLSS_NAMES[$i]}" "${DLSS_HEALTH_ADDRS[$i]}"
    done

    # (3) THE single-substrate acceptance: on EACH real node, bootstrap a cell +
    # user, log in over the real HTTP surface (the live WRITE that mints a
    # server-side session), then assert through THAT node's portal browse surface
    # that the session surfaces in the shared keyed-store substrate, and that an
    # unwritten collection reads empty.
    for i in "${!DLSS_NAMES[@]}"; do
        local web="${DLSS_WEB_ADDRS[$i]}"
        local cell="dlss-cell-${i}" user="op${i}" pass="op${i}-pass-1!"
        _dlss_bootstrap_cell "$web" "$cell" "$user" "$pass"

        local token
        token=$(_dlss_login "$web" "$user" "$pass")
        info "oracle-observed: login node=$i cell=$cell user=$user (real nonce+login handshake, server-side session minted)"

        oracle_single_substrate_session_surfaces "$web" "$token"
        oracle_empty_iff_empty "$web" "$token"
        oracle_plane_collections_share_substrate "$web" "$token"
    done

    info "data-layer-single-substrate: on ${#DLSS_NAMES[@]} real nodes, every live-login session surfaced in ITS portal browse over ONE keyed-store substrate; the RBAC/quota/WoT plane collections are browsable on that SAME substrate; no second store, panel empty IFF plane empty"
}
