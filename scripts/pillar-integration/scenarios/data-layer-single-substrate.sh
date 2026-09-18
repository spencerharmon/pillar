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
#   plane surfacing (RBAC grant / quota / WoT trust edge) — a REAL grant is
#       issued via `pillar grant add`, a REAL quota mutation via `pillar attest
#       build --quota`, and a REAL WoT trust edge via `pillar trust`, each
#       through the genuinely external `pillar` CLI binary `docker exec`'d
#       INTO the running node container (never linked in-process) using a
#       real signing credential minted over `POST /portal/profile/cli-config`
#       (the same turnkey path an operator's browser session uses) — then each
#       mutation is asserted to surface as a signed resource-event in the
#       portal's `/portal/data/doc/ids`/`doc/get` browse of the SAME live
#       node, and its surfaced event is verified real (hash-matches-id +
#       signature-valid) via `/portal/data/log/verify`.
#
# RED if a live session never surfaces in the portal browse (two stores), if an
# untouched collection is non-empty (phantom store), if a node is not a real
# process, or if an externally-issued grant/quota/trust-edge does not surface
# with a verifying signature/CID in the same substrate; GREEN when every
# node's live session surfaces in ITS portal browse over one substrate, the
# empty plane reads empty, and every externally-issued plane mutation
# surfaces + verifies. Sourced by run-scenario.sh, which has already sourced
# the lib layer and run fixtures_init.

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
# single-substrate oracle (PRE-mutation half). The RBAC-grant, quota, and
# web-of-trust planes each project their live web write as a resource-event
# into the SAME keyed-store substrate the portal browses (see
# WebAuthContext::project_plane_event). This oracle asserts each plane's
# Document collection (`rbac_grants`, `quota_ledger`, `wot_edges`) is BROWSABLE
# through the portal doc-browse route on this live node — the same substrate
# handle, one keyed op-log. With no grant/quota/edge issued yet on this fresh
# node the collections read empty (empty-iff-empty over the doc surface). The
# REAL, externally-issued mutation half (a real grant/quota/edge actually
# surfacing, non-empty, signature/CID-verified) is
# `oracle_plane_mutations_surface_externally`, below.
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

# _dlss_cli_config <web-addr> <token> : mint a real, turnkey `pillar` CLI
# credential over the SAME `POST /portal/profile/cli-config` route a real
# operator's browser session uses (never a fabricated key) and print the
# resulting `config.yaml` text (banner + yaml) to stdout. Fails only on an
# unreachable HTTP layer or a non-200 response.
_dlss_cli_config() {
    local web_addr="$1" token="$2" reply code
    reply=$(driver_http_post "$web_addr" /portal/profile/cli-config "$token") \
        || fail "cli-config export: POST /portal/profile/cli-config on $web_addr unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    [ "$code" = "200" ] \
        || fail "cli-config export: POST /portal/profile/cli-config on $web_addr returned $code"
    printf '%s\n' "$reply" | tail -n +3
}

# _dlss_cli_exec <node-name> <config-path-in-container> <pillar-args...> :
# run the REAL `pillar` binary already baked into the running node's own
# image, `docker exec`'d INTO that running container (a genuinely external
# surface — never a linked crate, never an in-process call) with
# `PILLAR_CONFIG` pointed at the credential file `_dlss_cli_config` produced,
# so the CLI dials the node's real resource-op tier over its real loopback
# listener using a real minted signing key. Prints the CLI's combined output;
# returns its real exit code.
_dlss_cli_exec() {
    local name="$1" cfg="$2"
    shift 2
    "$CONTAINER_RUNTIME" exec -e "PILLAR_CONFIG=${cfg}" "$name" /bin/pillar "$@" 2>&1
}

# oracle_plane_mutations_surface_externally <node-name> <web-addr> <token> :
# THE externally-issued plane-mutation oracle the DoD requires. Issues a REAL
# grant (`pillar grant add`), a REAL quota mutation (`pillar attest build
# --quota`), and a REAL WoT trust edge (`pillar trust`) against this live
# node, each via the real `pillar` CLI binary `docker exec`'d into the node's
# OWN running container using a credential minted over the real
# `/portal/profile/cli-config` HTTP surface — never an in-process call, never
# a linked crate. Each mutation's resulting event is then asserted to SURFACE
# in the portal's `/portal/data/doc/ids`/`doc/get` browse of the SAME live
# node (not merely an empty check), and the surfaced event's CID is verified
# REAL — `hash-matches-id: true` and `signature-valid: true` — via
# `/portal/data/log/verify`. RED if any CLI act is refused, if the
# resulting event never surfaces in the doc browse, or if its CID fails
# hash/signature verification; GREEN when every plane's externally-issued
# mutation surfaces and verifies on the SAME substrate the session already
# proved.
oracle_plane_mutations_surface_externally() {
    local name="$1" web_addr="$2" token="$3"
    local cfg_text cfg_file cfg_in_container
    cfg_text=$(_dlss_cli_config "$web_addr" "$token")
    cfg_file="$(mktemp "${TMPDIR:-/tmp}/pillar-it-cli-config.XXXXXX.yaml")"
    printf '%s\n' "$cfg_text" >"$cfg_file"
    # The node image is distroless (no /tmp) — its only guaranteed-writable
    # directory is the WorkingDir the flake creates (`var/lib/pillar/data`).
    cfg_in_container="/var/lib/pillar/data/pillar-it-cli-config-$$.yaml"
    "$CONTAINER_RUNTIME" cp "$cfg_file" "${name}:${cfg_in_container}" \
        || fail "plane-mutation oracle: docker cp of the minted CLI credential into $name failed"
    rm -f "$cfg_file"
    info "oracle-observed: cli-config minted for node=$name (real POST /portal/profile/cli-config turnkey credential, docker-cp'd into the running node)"

    local subject="dlss-grantee-$$" out

    # (1) REAL grant, issued via the real `pillar grant add` CLI verb docker-
    # exec'd into the live node.
    out=$(_dlss_cli_exec "$name" "$cfg_in_container" grant add "data:write" --to "$subject") \
        || fail "plane-mutation oracle: real 'pillar grant add' on $name refused:\n$out"
    info "oracle-observed: grant-add node=$name subject=$subject cap=data:write (real docker-exec'd pillar CLI act): $out"
    out=$(_dlss_browse "$web_addr" "$token" "/portal/data/doc/get?collection=rbac_grants&id=${subject}:data:write&field=event.subject") \
        || fail "plane-mutation oracle: doc/get(rbac_grants) on $web_addr unreachable"
    local code body
    code=$(printf '%s\n' "$out" | sed -n '1p')
    body=$(printf '%s\n' "$out" | tail -n +2)
    [ "$code" = "200" ] && [ "$(printf '%s' "$body" | tr -d '[:space:]')" = "$subject" ] \
        || fail "plane-mutation oracle: the real grant-add did NOT surface in the portal doc browse on $web_addr (code=$code body=$body) — the RBAC plane and the portal are TWO stores, not one"
    _dlss_verify_surfaced_event "$web_addr" "$token" rbac_grants "${subject}:data:write" "grant-add"

    # (2) REAL quota mutation, issued via `pillar attest build --quota` (a
    # signed act carrying a quota budget, per web_serve.rs's
    # TrustOp::AttestBuild handling).
    out=$(_dlss_cli_exec "$name" "$cfg_in_container" attest build --as self --subject "$subject" \
        --allow read "dlss-resource-$$" --quota "dlss=5" --in "dlss-scope-$$") \
        || fail "plane-mutation oracle: real 'pillar attest build --quota' on $name refused:\n$out"
    info "oracle-observed: attest-build node=$name subject=$subject quota=dlss=5 (real docker-exec'd pillar CLI act): $out"
    local attest_cid
    attest_cid=$(printf '%s\n' "$out" | grep '^CID ' | head -1 | awk '{print $2}')
    [ -n "$attest_cid" ] \
        || fail "plane-mutation oracle: 'pillar attest build --quota' on $name printed no CID:\n$out"
    out=$(_dlss_browse "$web_addr" "$token" "/portal/data/doc/get?collection=quota_ledger&id=${attest_cid}&field=event.subject") \
        || fail "plane-mutation oracle: doc/get(quota_ledger) on $web_addr unreachable"
    code=$(printf '%s\n' "$out" | sed -n '1p')
    body=$(printf '%s\n' "$out" | tail -n +2)
    [ "$code" = "200" ] && [ "$(printf '%s' "$body" | tr -d '[:space:]')" = "$subject" ] \
        || fail "plane-mutation oracle: the real quota mutation did NOT surface in the portal doc browse on $web_addr (code=$code body=$body) — the quota plane and the portal are TWO stores, not one"
    _dlss_verify_surfaced_event "$web_addr" "$token" quota_ledger "$attest_cid" "attest-build"

    # (3) REAL WoT trust edge, issued via `pillar trust <subject>`.
    out=$(_dlss_cli_exec "$name" "$cfg_in_container" trust "$subject" --depth 1) \
        || fail "plane-mutation oracle: real 'pillar trust' on $name refused:\n$out"
    info "oracle-observed: trust-edge node=$name subject=$subject (real docker-exec'd pillar CLI act): $out"
    # The edge's doc id is `<actor>->{subject}` where <actor> is the minted
    # CLI signer's own subject (its ed25519 public key hex) — read it back
    # off the cfg's `identity.signer_public_hex:` line rather than
    # re-deriving the hex ourselves.
    local signer_hex edge_id
    signer_hex=$(printf '%s\n' "$cfg_text" | grep 'signer-public-hex:' | head -1 | awk '{print $2}' | tr -d '"')
    [ -n "$signer_hex" ] \
        || fail "plane-mutation oracle: could not read signer_public_hex back out of the minted cli-config"
    edge_id="${signer_hex}->${subject}"
    out=$(_dlss_browse "$web_addr" "$token" "/portal/data/doc/get?collection=wot_edges&id=${edge_id}&field=event.subject") \
        || fail "plane-mutation oracle: doc/get(wot_edges) on $web_addr unreachable"
    code=$(printf '%s\n' "$out" | sed -n '1p')
    body=$(printf '%s\n' "$out" | tail -n +2)
    [ "$code" = "200" ] && [ "$(printf '%s' "$body" | tr -d '[:space:]')" = "$subject" ] \
        || fail "plane-mutation oracle: the real trust edge did NOT surface in the portal doc browse on $web_addr (code=$code body=$body id=$edge_id) — the WoT plane and the portal are TWO stores, not one"
    _dlss_verify_surfaced_event "$web_addr" "$token" wot_edges "$edge_id" "trust-edge"

    "$CONTAINER_RUNTIME" exec "$name" rm -f "$cfg_in_container" >/dev/null 2>&1 || true
    info "oracle-observed: plane-mutation node=$name every externally-issued grant/quota/trust-edge surfaced in the portal's doc browse on the SAME substrate as the live session, and every surfaced event verified (hash-matches-id + signature-valid)"
}

# _dlss_verify_surfaced_event <web-addr> <token> <collection> <id> <label> :
# read the surfaced document's `event.event_cid` field back through the
# portal doc-browse surface, then verify that event for real via
# `/portal/data/log/verify?collection=<c>&event_id=<hex>` — asserting BOTH
# `hash-matches-id: true` and `signature-valid: true` are present in the
# response, i.e. the surfaced row is tied to a genuinely signed,
# content-addressed act in the SAME log-inspection tier every other
# collection uses (`project_plane_event` indexes the plane's signed act into
# `log_index` under `collection` — see web_serve.rs), not a placeholder
# string.
_dlss_verify_surfaced_event() {
    local web_addr="$1" token="$2" collection="$3" id="$4" label="$5" out code body cid
    out=$(_dlss_browse "$web_addr" "$token" "/portal/data/doc/get?collection=${collection}&id=${id}&field=event.event_cid") \
        || fail "$label verify: doc/get(${collection}) event_cid on $web_addr unreachable"
    code=$(printf '%s\n' "$out" | sed -n '1p')
    body=$(printf '%s\n' "$out" | tail -n +2)
    cid=$(printf '%s' "$body" | tr -d '[:space:]')
    [ "$code" = "200" ] && [ -n "$cid" ] \
        || fail "$label verify: no event_cid surfaced for ${collection}/${id} on $web_addr (code=$code body=$body)"
    out=$(_dlss_browse "$web_addr" "$token" "/portal/data/log/verify?collection=${collection}&event_id=${cid}") \
        || fail "$label verify: log/verify on $web_addr unreachable"
    code=$(printf '%s\n' "$out" | sed -n '1p')
    body=$(printf '%s\n' "$out" | tail -n +2)
    [ "$code" = "200" ] \
        || fail "$label verify: log/verify(${collection},${cid}) on $web_addr returned $code ($body)"
    printf '%s\n' "$body" | grep -q '^hash-matches-id: true$' \
        || fail "$label verify: log/verify(${collection},${cid}) did not report hash-matches-id: true:\n$body"
    printf '%s\n' "$body" | grep -q '^signature-valid: true$' \
        || fail "$label verify: log/verify(${collection},${cid}) did not report signature-valid: true:\n$body"
    info "oracle-observed: ${label}-verified event_id=$cid hash-matches-id=true signature-valid=true (real content-addressed, signed event, log-inspection tier)"
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

        # (4) THE externally-issued plane-mutation acceptance: a REAL grant,
        # quota mutation, and WoT trust edge, each issued via the real
        # `pillar` CLI docker-exec'd into THIS live node (never in-process),
        # each asserted to surface in the portal doc browse of the SAME node
        # with a verifying signature/CID.
        oracle_plane_mutations_surface_externally "${DLSS_NAMES[$i]}" "$web" "$token"
    done

    info "data-layer-single-substrate: on ${#DLSS_NAMES[@]} real nodes, every live-login session surfaced in ITS portal browse over ONE keyed-store substrate; the RBAC/quota/WoT plane collections are browsable on that SAME substrate, an externally-issued grant/quota/trust-edge on each node surfaced with a verified signature/CID, and no second store; panel empty IFF plane empty"
}
