#!/usr/bin/env bash
# scenarios/adversarial-security.sh — ROI "pillar-integration" scenario family:
# adversarial/security (operator-directed, 2026-08-31).
#
# Boots ONE real `pillar node run` process from the real published image, its
# bootstrap/web HTTP surface AND its real pillar-UDP dataplane listener both
# published, and ATTACKS the real cell through those external surfaces only
# (no pillar crate linked). Every attack below is proven REJECTED by
# observing the real external effect of the attempt — never a code-inspection
# claim:
#
#   1. FORGERY — a syntactically-plausible but forged session bearer
#      presented to the real approve route is refused by the real session
#      verifier (`DENIED not-authenticated`), never admitted.
#   2. REPLAY — a bootstrap request already decided once is refused a SECOND
#      decision (`DENIED already-decided`, HTTP 409) by the real request
#      queue's terminal-state check — a replayed decision never re-applies.
#   3. UNAUTHORIZED RBAC APPLY — a privileged portal "apply" (a real signed
#      act, `POST /portal/members/add`, gated through the same `pillar_rbac`
#      WoT/RBAC decider the CLI acts use) attempted with NO credential at all
#      is refused (401/403), never silently admitted.
#   4. WRONG-KEY DECRYPT ATTEMPT — the host cell's own real approve response
#      is a content-addressed sealed-cell-key CID; it never leaks the
#      plaintext material only the real recipient key could decrypt
#      (`oracle_ciphertext_no_leak`, independently reproduced from the same
#      public formula) — an attacker without the real key gets ciphertext
#      only.
#   5. PUBLIC-SEED-RECONSTRUCTION ATTEMPT against a real CID — naive guesses
#      of the CID's preimage built ONLY from public request metadata (cell
#      id, subject, request id) never reproduce the real digest
#      (`oracle_seed_no_reconstruction`) — the real sealed envelope's fresh
#      randomness defeats prediction.
#   6. SPOOFED-SOURCE AMPLIFICATION against the real pillar-UDP dataplane
#      (`pillar_net::pillar_udp_transport`, a real bound `tokio::net::UdpSocket`
#      libp2p transport) — raw datagrams from fresh, never-before-seen,
#      unvalidated source ports never draw a reply bigger than they sent
#      (`oracle_udp_no_amplification`): the anti-amplification bound holds.
#
# RED if any attack above is silently admitted (a forged token accepted, a
# stale decision re-applied, an unauthenticated actor's act honored, a
# plaintext leaked, a CID guessed, or a reflected UDP reply outweighing the
# request); GREEN when every attack is observably rejected. Sourced by
# run-scenario.sh, which has already sourced the lib layer and run
# fixtures_init.

ADV_NAME=""
ADV_HEALTH_ADDR=""
ADV_WEB_ADDR=""
ADV_UDP_ADDR=""

# _adv_boot_node : boot ONE real `pillar node run` process (the image's
# default entrypoint, no crate linkage) with its bootstrap/web HTTP surface
# AND its real pillar-UDP dataplane listener both published, so the scenario
# can drive it purely over the wire.
_adv_boot_node() {
    ADV_NAME="pillar-it-${FIXTURE_SCENARIO}-cell"
    local cid
    cid=$("$CONTAINER_RUNTIME" run -d \
        --name "$ADV_NAME" \
        --label "$FIXTURE_LABEL" \
        -e PILLAR_WEB_BIND=0.0.0.0 \
        -e PILLAR_WEB_PORT=8642 \
        -e "PILLAR_LISTEN=/ip4/0.0.0.0/tcp/4001 /ip4/0.0.0.0/udp/4002/unix/p-pillar" \
        -p "127.0.0.1::8643" \
        -p "127.0.0.1::8642" \
        -p "127.0.0.1::4002/udp" \
        "$PILLAR_IMAGE" 2>&1) \
        || fail "adversarial-security: node failed to start: $cid"
    ADV_HEALTH_ADDR=$("$CONTAINER_RUNTIME" port "$ADV_NAME" 8643 2>/dev/null | head -1)
    ADV_WEB_ADDR=$("$CONTAINER_RUNTIME" port "$ADV_NAME" 8642 2>/dev/null | head -1)
    ADV_UDP_ADDR=$("$CONTAINER_RUNTIME" port "$ADV_NAME" 4002/udp 2>/dev/null | head -1)
    [ -n "$ADV_HEALTH_ADDR" ] || fail "could not resolve published health port"
    [ -n "$ADV_WEB_ADDR" ] || fail "could not resolve published web port"
    [ -n "$ADV_UDP_ADDR" ] || fail "could not resolve published pillar-UDP port"
    info "adversarial-security: cell up as $ADV_NAME (health=$ADV_HEALTH_ADDR web=$ADV_WEB_ADDR pillar-udp=$ADV_UDP_ADDR)"
}

_adv_wait_ready() {
    retry 30 bash -c "curl -s -m 2 -o /dev/null http://${ADV_HEALTH_ADDR}/readyz" \
        || fail "node at $ADV_HEALTH_ADDR never answered /readyz within 30s"
    retry 30 bash -c "curl -s -m 2 -o /dev/null http://${ADV_WEB_ADDR}/bootstrap/status" \
        || fail "node at $ADV_WEB_ADDR never answered /bootstrap/status within 30s"
}

# _adv_bootstrap_cell <cell-id> <user> <password> : bootstrap a fresh cell +
# its first (genesis) user over the real HTTP surface.
_adv_bootstrap_cell() {
    local cell_id="$1" user="$2" password="$3" reply code body
    reply=$(driver_http_post "$ADV_WEB_ADDR" /bootstrap/create-cell "$cell_id") \
        || fail "create-cell unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "create-cell '$cell_id' refused: $code $body"
    info "oracle-observed: bootstrap-cell cell=$cell_id -> $body (real create-cell HTTP effect)"

    reply=$(driver_http_post "$ADV_WEB_ADDR" /bootstrap/create-user "${user}"$'\n'"${password}") \
        || fail "create-user unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "create-user '$user' refused: $code $body"
    info "oracle-observed: bootstrap-user cell=$cell_id user=$user -> $body (real create-user HTTP effect)"
}

# _adv_login <user> <password> : the real GET /nonce -> POST /login handshake;
# echoes "<session> <consumed-nonce-id>" so a caller can attempt to REPLAY the
# consumed nonce afterwards.
_adv_login() {
    local user="$1" password="$2" nonce_reply nonce_id reply code session
    nonce_reply=$(curl -s -m 10 "http://${ADV_WEB_ADDR}/nonce") \
        || fail "GET /nonce unreachable"
    nonce_id=$(printf '%s' "$nonce_reply" | awk '{print $2}')
    [ -n "$nonce_id" ] || fail "malformed nonce reply: $nonce_reply"

    reply=$(driver_http_post "$ADV_WEB_ADDR" /login "${user}"$'\n'"${password}"$'\n'"${nonce_id}") \
        || fail "POST /login unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    session=$(printf '%s\n' "$reply" | sed -n '2p')
    [ "$code" = "200" ] || fail "login for '$user' refused: $code"
    [ -n "$session" ] || fail "login for '$user' returned no X-Pillar-Session bearer"
    printf '%s %s' "$session" "$nonce_id"
}

scenario_adversarial-security() {
    # (0) a REAL single-cell topology on the real ghcr image, with BOTH the
    # bootstrap/web HTTP surface and the real pillar-UDP dataplane published.
    _adv_boot_node
    _adv_wait_ready
    oracle_process "$ADV_NAME" "$ADV_HEALTH_ADDR"

    local cell_id="adv-cell"
    _adv_bootstrap_cell "$cell_id" alice 'alice-pass-1!'

    local login_out alice_token consumed_nonce
    login_out=$(_adv_login alice 'alice-pass-1!')
    alice_token=$(printf '%s' "$login_out" | awk '{print $1}')
    consumed_nonce=$(printf '%s' "$login_out" | awk '{print $2}')
    info "oracle-observed: login cell=$cell_id user=alice (real nonce+login handshake, session issued)"

    # --- ATTACK 1: FORGERY — a syntactically-plausible but forged session
    # bearer submitted to the real approve route must be refused by the real
    # session verifier, never admitted.
    local subject="adv-node" peer_id="12D3KooWadvnode" pubkey_cid="bafy-adv-nodekey"
    local submit_body reply code body
    submit_body="${subject}"$'\n'"${peer_id}"$'\n'"1.0.0-adv-it"$'\n'"linux"$'\n'"${pubkey_cid}"$'\n'"tpm"$'\n'"pub=/ip4/203.0.113.9/tcp/4001"
    reply=$(driver_http_post "$ADV_WEB_ADDR" /bootstrap/request/node "$submit_body") \
        || fail "submitting node request unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "node bootstrap request refused: $code $body"
    local req_id="${body#REQUEST }"
    [ -n "$req_id" ] && [ "$req_id" != "$body" ] || fail "malformed node-request reply: $body"
    info "adversarial-security: submitted real pending request id=$req_id subject=$subject"

    local forged_token="${alice_token}-forged-$$"
    reply=$(driver_http_post "$ADV_WEB_ADDR" /bootstrap/request/approve "${req_id}"$'\n'"${forged_token}") \
        || fail "forged-token approve attempt unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "401" ] && printf '%s\n' "$body" | grep -q "not-authenticated" \
        || fail "FORGERY ADMITTED: a forged session bearer '$forged_token' was not refused 401/not-authenticated (got: $code $body)"
    info "oracle-observed: forgery-rejected forged bearer refused $code '$body' (real session verifier never admits a forged credential)"

    # --- ATTACK 3 (checked here, before the legitimate approval, so the
    # request is still pending): UNAUTHORIZED RBAC APPLY — a privileged
    # portal "apply" (a real signed act gated through the same pillar_rbac
    # WoT/RBAC decider the CLI acts use) attempted with NO credential at all
    # must be refused, never silently admitted.
    reply=$(driver_http_post "$ADV_WEB_ADDR" /portal/members/add $'\n'"mallory"$'\n'"admin") \
        || fail "unauthenticated portal apply attempt unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    case "$code" in
        401|403) : ;;
        *) fail "UNAUTHORIZED APPLY ADMITTED: an unauthenticated portal:members:write act was not refused 401/403 (got: $code $body)" ;;
    esac
    printf '%s\n' "$body" | grep -Eqi "not-authenticated|forbidden|refused|unauthorized" \
        || fail "UNAUTHORIZED APPLY ADMITTED: refusal body did not name an authorization failure (got: $body)"
    info "oracle-observed: unauthorized-rbac-apply-rejected unauthenticated 'portal:members:write' act refused $code '$body' (real pillar_rbac WoT decider never admits a credential-less actor)"

    # --- Now legitimately approve the pending request as the real genesis
    # member (alice), observing the real ciphertext oracle's artifacts —
    # setup for attacks 4 and 5.
    reply=$(driver_http_post "$ADV_WEB_ADDR" /bootstrap/request/approve "${req_id}"$'\n'"${alice_token}") \
        || fail "legitimate approve unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "legitimate approval by the real genesis member was refused: $code $body"
    info "adversarial-security: host cell '$cell_id' legitimately approved request $req_id -> $body"
    local approve_body="$body"

    # --- ATTACK 2: REPLAY — the SAME request decision replayed a second time
    # must be refused (the real request queue's terminal-state check), never
    # silently re-applied.
    reply=$(driver_http_post "$ADV_WEB_ADDR" /bootstrap/request/approve "${req_id}"$'\n'"${alice_token}") \
        || fail "replayed approve attempt unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "409" ] && printf '%s\n' "$body" | grep -q "already-decided" \
        || fail "REPLAY ADMITTED: re-deciding request $req_id a second time was not refused 409/already-decided (got: $code $body)"
    info "oracle-observed: replay-rejected re-decision of request $req_id refused $code '$body' (real terminal-state check; a replayed decision never re-applies)"

    # A second, independent replay proof: the nonce already consumed by
    # alice's login must never be honored again either.
    reply=$(driver_http_post "$ADV_WEB_ADDR" /login "alice"$'\n''alice-pass-1!'$'\n'"${consumed_nonce}") \
        || fail "replayed-nonce login attempt unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "401" ] && printf '%s\n' "$body" | grep -q "bad-nonce" \
        || fail "REPLAY ADMITTED: reusing consumed nonce $consumed_nonce was not refused 401/bad-nonce (got: $code $body)"
    info "oracle-observed: nonce-replay-rejected reusing consumed nonce=$consumed_nonce refused $code '$body' (real single-use nonce check)"

    # --- ATTACK 4: WRONG-KEY DECRYPT ATTEMPT — the host's own approve
    # response never leaks the plaintext only the real recipient key could
    # decrypt; an attacker without that key gets ciphertext+CID only.
    oracle_ciphertext_no_leak "$approve_body" "$cell_id"

    # --- ATTACK 5: PUBLIC-SEED-RECONSTRUCTION ATTEMPT against the real CID —
    # naive guesses built only from public request metadata never reproduce
    # the real digest.
    oracle_seed_no_reconstruction "$approve_body" \
        "$cell_id" \
        "$subject" \
        "$req_id" \
        "${cell_id}${subject}" \
        "${subject}${req_id}" \
        "cell-key" \
        "${cell_id}-cell-key" \
        "$pubkey_cid" \
        ""

    # --- ATTACK 6: SPOOFED-SOURCE AMPLIFICATION against the real pillar-UDP
    # dataplane — raw datagrams from fresh, unvalidated source ports never
    # draw a reply bigger than they sent.
    oracle_udp_no_amplification "$ADV_UDP_ADDR"

    info "adversarial-security: every attack (forgery, replay x2, unauthorized apply, wrong-key decrypt, seed reconstruction, UDP amplification) was observably rejected by the real cell"
}
