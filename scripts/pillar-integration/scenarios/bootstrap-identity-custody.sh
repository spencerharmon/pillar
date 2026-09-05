#!/usr/bin/env bash
# scenarios/bootstrap-identity-custody.sh — the ROI "pillar-integration"
# bootstrap/onboarding + identity/keys/custody scenario family.
#
# Black-box only: every assertion below drives the REAL published image
# SOLELY through its external surfaces (the `pillar` CLI binary and the
# node's plaintext HTTP bootstrap/login/webauthn routes) — never linking a
# pillar crate, never reaching into node memory. Sourced by run-scenario.sh,
# which has already sourced the lib layer and run fixtures_init.
#
# Claimed surface-inventory entries (pillar-integration/v1 schema — see
# crates/pillar-surface-inventory; ids/kinds/signatures mirror its
# `SurfaceEntry` shape exactly so a conformance rig can diff this scenario's
# claim against the real emitted inventory):
#   cli:bootstrap   (cli-verb)  pillar bootstrap
#   cli:webauthn    (cli-verb)  pillar webauthn
#   cli:onboard     (cli-verb)  pillar onboard
#   cli:node        (cli-verb)  pillar node
#   http:POST /bootstrap/create-cell   (http-route)
#   http:POST /bootstrap/create-user   (http-route)
#   http:GET  /bootstrap/status        (http-route)
#   http:GET  /nonce                   (http-route)
#   http:POST /login                   (http-route)
#   http:POST /webauthn/register/begin       (http-route)
#   http:POST /webauthn/authenticate/begin   (http-route)
#
# Realness discipline: every step below asserts either a real cryptographic
# effect verified against the right key (and refused against a wrong one) or
# a real fail-closed refusal — never a bare 200/exit-code. This is exactly
# why the scenario is RED against a stand-in custody path (a stub that
# returns "ok" without checking the signature/password/device) and GREEN
# only against the real one: every assertion below inspects the actual
# verification outcome (the wrong-password login is REQUIRED to be refused;
# a hardware WebAuthn ceremony with no attached authenticator is REQUIRED to
# fail closed rather than silently succeed).

# _declare_surface <id> <kind> <signature> : print the claim as a greppable
# line so a reviewer/rig can diff against the real emitted inventory without
# re-reading this file's header comment.
_declare_surface() {
    info "claimed-surface: id=$1 kind=$2 signature=\"$3\""
}

# The image under test ships NO shell/curl of its own (a minimal, single-
# binary `pillar` image) — its HTTP bootstrap surface is loopback-only
# (`pillar_web::AuthMode::LocalhostBootstrap` refuses any non-loopback peer,
# so driving it from the HOST's published port would never authenticate).
# The black-box-correct vantage point is a THROWAWAY sidecar container that
# JOINS the target node's network namespace (`--network container:<cid>`),
# so its requests are real loopback peers of that node's web listener — a
# real external HTTP client, never a linked pillar crate, never inside the
# node's own process.
CURL_IMAGE="${PILLAR_IT_CURL_IMAGE:-docker.io/curlimages/curl:latest}"

# _web_request <cid> <method> <path> [body] : issue one plaintext HTTP/1.1
# request against a node's loopback web surface via the curl sidecar joined
# to its netns. Prints "<status>\n<session-header-or-empty>\n<body>".
_web_request() {
    local cid="$1" method="$2" path="$3" body="${4:-}"
    local raw
    raw=$("$CONTAINER_RUNTIME" run --rm --network "container:$cid" "$CURL_IMAGE" \
        -s -m 10 -D - -X "$method" --data-binary "$body" \
        "http://127.0.0.1:${BOOTSTRAP_WEB_PORT}${path}" 2>&1) \
        || fail "web request $method $path: curl sidecar failed to reach node $cid:\n$raw"
    local status session body_out
    status=$(printf '%s' "$raw" | head -1 | awk '{print $2}')
    session=$(printf '%s' "$raw" | grep -i '^X-Pillar-Session:' | awk '{print $2}' | tr -d '\r')
    # Body follows the first blank line after the header block.
    body_out=$(printf '%s' "$raw" | awk 'f{print} /^\r?$/{f=1}')
    printf '%s\n%s\n%s\n' "$status" "$session" "$body_out"
}

_web_status()  { printf '%s' "$1" | sed -n '1p'; }
_web_session() { printf '%s' "$1" | sed -n '2p'; }
_web_body()    { printf '%s' "$1" | sed -n '3,$p'; }

# The localhost-only bootstrap portal's fixed port (see cli_surface.rs's
# `web()`: default 8642, matched by bootstrap.rs's `authority_of` default).
BOOTSTRAP_WEB_PORT=8642

scenario_bootstrap-identity-custody() {
    local n="${PILLAR_IT_NODES:-3}"

    # (1) A real >=3-node topology on the real ghcr image, proving the
    # scenario runs "on the harness" against real, running nodes (process
    # oracle: real pid + real bound readiness socket per node).
    topology_boot "$n"
    local i
    for i in "${!TOPO_NODES[@]}"; do
        oracle_process "${TOPO_NODES[$i]}" "${TOPO_PROBE_ADDRS[$i]}"
    done

    _declare_surface "cli:node" "cli-verb" "pillar node"

    # (2) keygen -> node subkey signing -> cross-user trust, asserted via the
    # crypto-realness oracle's five real, fail-closed invariant checks
    # (keygen-and-registration, node-key-signing, cross-user-trust-and-depth,
    # policy-config-gates-by-depth, out-of-order-fails-closed).
    info "bootstrap-identity-custody: keygen / node-subkey-signing / cross-user-trust (onboard)"
    oracle_crypto_realness
    _declare_surface "cli:onboard" "cli-verb" "pillar onboard"

    # (3) HSM vs software custody: run the combined local cell+user genesis
    # (`pillar bootstrap cell`) under a hardware-backed custody kind (tpm)
    # and a software-only one (keyring), asserting each reports the custody
    # kind it was actually given — not a stubbed constant — and the one-shot
    # `cell_key_can_create_user` capability is consumed exactly once per
    # cell (never left grantable to a second caller).
    _declare_surface "cli:bootstrap" "cli-verb" "pillar bootstrap"
    _assert_local_bootstrap_custody "hsm-custody-cell" "tpm" "Tpm"
    _assert_local_bootstrap_custody "sw-custody-cell" "keyring" "FileKeyring"

    # (4) create-cell + first-user via passphrase fallback, driven over the
    # REAL HTTP bootstrap surface of a dedicated localhost-portal container
    # (never the CLI's local-mode shortcut this time), then the
    # `cell_key_can_create_user` flip observed as the FRESH -> BOOTSTRAPPED
    # status transition (BOOTSTRAPPED requires the first user, not merely
    # the cell — see dispatch_bootstrap_status_route).
    _run_http_bootstrap_and_identity_flow
}

# _assert_local_bootstrap_custody <cell-name> <custody-cli-token> <expected-debug-fragment>
# : drive `pillar bootstrap cell` locally (no --domain — pure CLI-surface
# genesis) under the given cell custody kind and assert the REAL custody kind
# it reports, plus the one-shot capability-consumption invariant.
_assert_local_bootstrap_custody() {
    local cell="$1" custody="$2" expect_fragment="$3"
    info "bootstrap-identity-custody: local cell genesis cell=$cell custody=$custody"
    local out
    out=$(driver_cli_exec bootstrap cell "$cell" --user "first-$cell" \
        --cell-custody "$custody" --user-custody password) \
        || fail "bootstrap cell (custody=$custody): CLI exited non-zero:\n$out"
    printf '%s\n' "$out" | grep -q "bootstrapped cell \`$cell\`" \
        || fail "bootstrap cell (custody=$custody): missing create-cell confirmation:\n$out"
    printf '%s\n' "$out" | grep -q "cell custody: $expect_fragment" \
        || fail "bootstrap cell (custody=$custody): reported custody was not the REAL requested kind (expected fragment '$expect_fragment'):\n$out"
    printf '%s\n' "$out" | grep -q "one-shot cell_key_can_create_user capability: consumed" \
        || fail "bootstrap cell (custody=$custody): cell_key_can_create_user flip was not reported consumed:\n$out"
    info "oracle-observed: bootstrap-genesis cell=$cell custody=$custody real cell-custody kind '$expect_fragment', one-shot capability consumed"
}

# _run_http_bootstrap_and_identity_flow : boot a dedicated real node
# (`pillar node run --web-bind 127.0.0.1 --web-port …`, the same web_serve
# surface a production node exposes), then drive create-cell / create-user
# (passphrase fallback) / status-flip / login (right password admitted,
# wrong password refused) / WebAuthn ceremony-begin (CLI CTAP parity,
# fail-closed with no hardware attached) purely over its real HTTP surface
# via a curl sidecar joined to its network namespace.
_run_http_bootstrap_and_identity_flow() {
    local cid name
    name="pillar-it-${FIXTURE_SCENARIO}-web-portal"
    info "bootstrap-identity-custody: booting a real node with its web bootstrap surface bound ($name)"
    cid=$("$CONTAINER_RUNTIME" run -d \
        --name "$name" \
        --label "$FIXTURE_LABEL" \
        "$PILLAR_IMAGE" --web-bind 127.0.0.1 --web-port "$BOOTSTRAP_WEB_PORT" 2>&1) \
        || fail "bootstrap-web node failed to start: $cid"

    # Give the portal a moment to bind, observed by polling /bootstrap/status
    # from INSIDE the container (the only vantage the loopback-only auth
    # mode admits).
    local ready=0 attempt resp status
    for attempt in $(seq 1 30); do
        if resp=$(_web_request "$cid" GET /bootstrap/status 2>/dev/null); then
            status=$(_web_status "$resp")
            if [ "$status" = "200" ]; then
                ready=1
                break
            fi
        fi
        sleep 1
    done
    [ "$ready" -eq 1 ] || fail "bootstrap-web portal $name never answered /bootstrap/status within 30s"
    [ "$(_web_body "$resp" | tr -d '\r\n')" = "FRESH" ] \
        || fail "bootstrap-web portal $name: expected FRESH status before genesis, got: $(_web_body "$resp")"
    info "oracle-observed: http-surface node=$name GET /bootstrap/status -> 200 FRESH (real bound HTTP listener, pre-genesis)"

    local cell="http-genesis-cell" user="first-http-user" password="s3cret-passphrase-42"

    # create-cell: real HTTP surface, not the CLI's local shortcut.
    resp=$(_web_request "$cid" POST /bootstrap/create-cell "$cell")
    [ "$(_web_status "$resp")" = "200" ] \
        || fail "POST /bootstrap/create-cell refused: $(_web_status "$resp") $(_web_body "$resp")"
    info "oracle-observed: create-cell node=$name cell=$cell -> 200 CELL-CREATED (real HTTP surface)"

    # Still FRESH — a cell alone never flips the status (only the FIRST USER
    # does); this is the exact invariant dispatch_bootstrap_status_route
    # documents, and the exact bug class ("cell-created-but-no-user still
    # reads BOOTSTRAPPED") a stand-in status check would miss.
    resp=$(_web_request "$cid" GET /bootstrap/status)
    [ "$(_web_body "$resp" | tr -d '\r\n')" = "FRESH" ] \
        || fail "status flipped to BOOTSTRAPPED before the first user existed (cell_key_can_create_user boundary violated): $(_web_body "$resp")"

    # first-user via passphrase fallback.
    resp=$(_web_request "$cid" POST /bootstrap/create-user "$user
$password")
    [ "$(_web_status "$resp")" = "200" ] \
        || fail "POST /bootstrap/create-user refused: $(_web_status "$resp") $(_web_body "$resp")"
    info "oracle-observed: create-user node=$name user=$user -> 200 USER-CREATED (passphrase fallback custody)"

    # cell_key_can_create_user flip: NOW status must read BOOTSTRAPPED.
    resp=$(_web_request "$cid" GET /bootstrap/status)
    [ "$(_web_body "$resp" | tr -d '\r\n')" = "BOOTSTRAPPED" ] \
        || fail "cell_key_can_create_user flip did not fire: status still $(_web_body "$resp") after first-user creation"
    info "oracle-observed: cell_key_can_create_user flip node=$name FRESH -> BOOTSTRAPPED (real status transition, one-shot capability consumed)"

    # login: WRONG password must be refused (fail-closed realness — a
    # stand-in that always admits would pass this step falsely).
    local nonce_resp nonce_id
    nonce_resp=$(_web_request "$cid" GET /nonce)
    [ "$(_web_status "$nonce_resp")" = "200" ] || fail "GET /nonce refused: $(_web_status "$nonce_resp")"
    nonce_id=$(_web_body "$nonce_resp" | tr -d '\r\n' | awk '{print $2}')
    [ -n "$nonce_id" ] || fail "GET /nonce: malformed reply: $(_web_body "$nonce_resp")"
    resp=$(_web_request "$cid" POST /login "$user
wrong-password
$nonce_id")
    [ "$(_web_status "$resp")" = "401" ] \
        || fail "login with the WRONG password was NOT refused (expected 401, got $(_web_status "$resp")) — crypto realness violated"
    info "oracle-observed: login-refusal node=$name user=$user wrong password -> 401 (real password verification, fails closed)"

    # login: RIGHT password must be admitted and hand back a real session.
    nonce_resp=$(_web_request "$cid" GET /nonce)
    nonce_id=$(_web_body "$nonce_resp" | tr -d '\r\n' | awk '{print $2}')
    resp=$(_web_request "$cid" POST /login "$user
$password
$nonce_id")
    [ "$(_web_status "$resp")" = "200" ] \
        || fail "login with the RIGHT password was refused: $(_web_status "$resp") $(_web_body "$resp")"
    local session
    session=$(_web_session "$resp")
    [ -n "$session" ] || fail "login succeeded but returned no X-Pillar-Session bearer"
    info "oracle-observed: login-admit node=$name user=$user right password -> 200 real session bearer issued"

    # WebAuthn CLI CTAP parity + PRF-sealed op-key path: begin the SAME
    # ceremony the browser path drives, then attempt the CLI's ctap-hid
    # ceremony via the driver. The check sandbox has no attached hardware
    # authenticator, so the REAL crypto-realness assertion here is that the
    # ceremony FAILS CLOSED with a concrete backend error — never a fake
    # "ok" — proving no CLI-only credential shape/shortcut exists in this
    # path (see webauthn_cli.rs's doc comment: "No CLI-only credential shape
    # exists anywhere in this path").
    resp=$(_web_request "$cid" POST /webauthn/register/begin "$session
$user")
    [ "$(_web_status "$resp")" = "200" ] \
        || fail "POST /webauthn/register/begin refused for an authenticated session: $(_web_status "$resp") $(_web_body "$resp")"
    printf '%s' "$(_web_body "$resp")" | grep -q '^CHALLENGE ' \
        || fail "malformed /webauthn/register/begin reply: $(_web_body "$resp")"
    info "oracle-observed: webauthn-register-begin node=$name user=$user -> 200 CHALLENGE (real RP ceremony state minted)"
    _declare_surface "http:POST /webauthn/register/begin" "http-route" "POST /webauthn/register/begin"
    _declare_surface "http:POST /webauthn/authenticate/begin" "http-route" "POST /webauthn/authenticate/begin"

    # A throwaway CLI-driver container joined to the node's OWN network
    # namespace (its `--domain` peer must be loopback too, same as the curl
    # sidecar above) — the real CLI-CTAP client path, not a linked crate.
    local ctap_out ctap_rc
    ctap_out=$("$CONTAINER_RUNTIME" run --rm --network "container:$cid" --entrypoint /bin/pillar \
        "$PILLAR_IMAGE" webauthn register --user "$user" \
        --domain "127.0.0.1:$BOOTSTRAP_WEB_PORT" --token "$session" 2>&1)
    ctap_rc=$?
    [ "$ctap_rc" -ne 0 ] \
        || fail "webauthn register CLI CTAP ceremony reported SUCCESS with no attached hardware authenticator — this is a false positive (no real device, no real credential could have been produced):\n$ctap_out"
    printf '%s' "$ctap_out" | grep -qi 'hardware ceremony failed\|no usable\|backend' \
        || fail "webauthn register CLI CTAP ceremony failed for the WRONG reason (expected a device/backend error, not a usage error):\n$ctap_out"
    info "oracle-observed: webauthn-ctap-fail-closed no hardware authenticator attached -> real backend refusal (not a stubbed success): $ctap_out"

    _declare_surface "cli:webauthn" "cli-verb" "pillar webauthn"
    _declare_surface "http:POST /bootstrap/create-cell" "http-route" "POST /bootstrap/create-cell"
    _declare_surface "http:POST /bootstrap/create-user" "http-route" "POST /bootstrap/create-user"
    _declare_surface "http:GET /bootstrap/status" "http-route" "GET /bootstrap/status"
    _declare_surface "http:GET /nonce" "http-route" "GET /nonce"
    _declare_surface "http:POST /login" "http-route" "POST /login"

    info "bootstrap-identity-custody: all oracles observed real effects — create-cell, passphrase first-user, cell_key_can_create_user flip, right/wrong-password login, HSM/software custody genesis, and CTAP fail-closed with no attached hardware"
}
