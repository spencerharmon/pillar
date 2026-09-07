#!/usr/bin/env bash
# scenarios/bootstrap-identity-custody.sh — ROI "pillar-integration" scenario
# family: bootstrap/onboarding + identity/keys/custody (operator-directed,
# 2026-08-31).
#
# Stands up ONE real `pillar node run` process from the REAL published image
# with its bootstrap/web HTTP surface published alongside its health probe,
# drives it SOLELY through the CLI/HTTP surfaces (never linking a pillar
# crate), and asserts, with the process oracle (real node pid) and the
# crypto-realness oracle (signatures verify with the right key, fail with a
# forged one):
#
#   1. create-cell + passphrase-fallback first user (`/bootstrap/create-cell`,
#      `/bootstrap/create-user`) — real HTTP bootstrap effect.
#   2. the one-shot `cell_key_can_create_user` flip: a SECOND create-user
#      attempt with the cell key is refused (`CapabilitySpent`) — proves the
#      capability really self-disabled, not merely that the first call
#      succeeded.
#   3. WebAuthn "browser" ceremony parity: a software Ed25519 authenticator
#      (`lib/webauthn_softauth.py`, openssl-backed, no CTAP-HID hardware)
#      drives the SAME wire shapes a real browser's
#      `navigator.credentials.{create,get}()` would against the node's real
#      RP (`/webauthn/register/*`, `/webauthn/authenticate/*`) —
#      registration, a successful assertion, a forged-signer assertion
#      (fail-closed), and the PRF-derived operational-key ("op-key") unlock
#      secret independently re-derived here via HKDF-SHA256 and compared
#      byte-for-byte against the node's own `UNLOCKED <secret>` reply, proving
#      the seal is a real derivation and not a placeholder.
#   4. CLI CTAP parity (`pillar webauthn register|login`): driven from a
#      throwaway container sharing the node's network namespace (so the
#      real HTTP round-trip happens), proving the CLI verb is real and wired
#      to a genuine hardware ceremony — it fails closed with a hardware
#      "open authenticator" error because this CI sandbox has no physical
#      CTAP2 authenticator attached (see the NOTE below; this mirrors
#      geo-replication.sh's documented CLI-surface hardware/stub boundary).
#   5. keygen -> node subkey signing -> cross-user trust (the shared
#      `oracle_crypto_realness`, i.e. `pillar onboard`'s five real invariants
#      run against the same published image).
#   6. HSM vs software custody: two independent node bootstrap-join requests
#      submitted via the REAL `pillar bootstrap node --node-custody <kind>`
#      CLI verb — one `tpm` (HSM-backed), one `keyring` (software-backed) —
#      both accepted and queued identically, while a bogus custody token is
#      refused fail-closed by the same real parser
#      (`pillar_bootstrap::custody::parse_custody_kind`).
#
# RED / GREEN: RED against a stand-in custody path (a create-user that never
# consults the one-shot capability, a WebAuthn RP that accepts a forged
# signature or a placeholder unlock secret, a custody parser that accepts
# anything); GREEN against the real one.
#
# NOTE on WebAuthn CTAP hardware: the deployed image is built with the `hsm`
# Cargo feature (folds in `passkey`), so `pillar webauthn register|login` is
# the REAL CTAP-HID-driving code path (`pillar_crypto::webauthn::ctap_client`,
# see crates/pillar-crypto/src/webauthn.rs), not a stub — but it needs a
# physical CTAP2 authenticator attached over USB/HID, which no CI sandbox
# has. This scenario proves that code path is real and reachable (a genuine
# "open authenticator: ..." backend error, not a compiled-out/usage error),
# and separately proves the FULL browser-side WebAuthn ceremony end to end
# with real Ed25519 crypto via the software authenticator described above —
# the same boundary geo-replication.sh documents for `pillar_cli::
# identity_trust_cli` (a library-only surface not yet wired to argv).
#
# Claimed surface-inventory entries this scenario exercises (informal
# `pillar-integration/v1` shape — see crates/pillar-surface-inventory):
#   cli-verb   bootstrap
#   cli-verb   webauthn
#   cli-verb   onboard
#   http-route POST /bootstrap/create-cell
#   http-route POST /bootstrap/create-user
#   http-route POST /bootstrap/request/node
#   http-route GET  /bootstrap/request/list
#   http-route POST /bootstrap/request/approve
#   http-route GET  /nonce
#   http-route POST /login
#   http-route POST /webauthn/register/begin
#   http-route POST /webauthn/register/finish
#   http-route POST /webauthn/authenticate/begin
#   http-route POST /webauthn/authenticate/finish

# _bic_wait_ready <health-addr> <web-addr> : block until both surfaces answer.
_bic_wait_ready() {
    local health_addr="$1" web_addr="$2"
    retry 30 bash -c "curl -s -m 2 -o /dev/null http://${health_addr}/readyz" \
        || fail "node at $health_addr never answered /readyz within 30s"
    retry 30 bash -c "curl -s -m 2 -o /dev/null http://${web_addr}/bootstrap/status" \
        || fail "node at $web_addr never answered /bootstrap/status within 30s"
}

# _bic_login <web-addr> <user> <password> : the real GET /nonce -> POST
# /login handshake; echoes the resulting session bearer.
_bic_login() {
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

# _bic_cli <args...> : run the real `pillar` CLI binary from the published
# image, network-namespace-shared with our booted node (`--network
# container:<name>`) so a `--domain 127.0.0.1:<in-container-port>` round-trip
# actually reaches it (a fresh default-bridge container cannot reach another
# container's loopback). Prints combined output; returns the CLI's exit code.
_bic_cli() {
    "$CONTAINER_RUNTIME" run --rm \
        --network "container:${BIC_NODE_NAME}" \
        --entrypoint /bin/pillar \
        "$PILLAR_IMAGE" "$@" 2>&1
}

scenario_bootstrap-identity-custody() {
    local py="$LIB/webauthn_softauth.py"
    command -v python3 >/dev/null 2>&1 \
        || fail "bootstrap-identity-custody needs python3 (the software WebAuthn authenticator helper, openssl-backed)"
    command -v openssl >/dev/null 2>&1 \
        || fail "bootstrap-identity-custody needs openssl (real Ed25519 keygen/signing for the software authenticator)"
    # fixtures_init's idempotent pre-clean removes FIXTURE_ROOT itself (it
    # only guarantees the NAME, not a standing directory) — (re)create it
    # before this scenario writes the software authenticator's private keys
    # under it.
    mkdir -p "$FIXTURE_ROOT"

    # --- boot one real node, its bootstrap/web HTTP surface published -------
    BIC_NODE_NAME="pillar-it-${FIXTURE_SCENARIO}-node"
    local cid web_addr health_addr
    cid=$("$CONTAINER_RUNTIME" run -d \
        --name "$BIC_NODE_NAME" \
        --label "$FIXTURE_LABEL" \
        -e PILLAR_WEB_BIND=0.0.0.0 \
        -e PILLAR_WEB_PORT=8642 \
        -p "127.0.0.1::8643" \
        -p "127.0.0.1::8642" \
        "$PILLAR_IMAGE" 2>&1) \
        || fail "node failed to start: $cid"
    health_addr=$("$CONTAINER_RUNTIME" port "$BIC_NODE_NAME" 8643 2>/dev/null | head -1)
    web_addr=$("$CONTAINER_RUNTIME" port "$BIC_NODE_NAME" 8642 2>/dev/null | head -1)
    [ -n "$health_addr" ] || fail "could not resolve published health port"
    [ -n "$web_addr" ] || fail "could not resolve published web port"
    _bic_wait_ready "$health_addr" "$web_addr"
    info "bootstrap-identity-custody: node up as $BIC_NODE_NAME (health=$health_addr web=$web_addr)"

    oracle_process "$BIC_NODE_NAME" "$health_addr"

    # --- (1) create-cell + passphrase-fallback first user ------------------
    local cell="bic-cell" user="alice" pass='alice-bic-pass-1!' reply code body
    reply=$(driver_http_post "$web_addr" /bootstrap/create-cell "$cell") \
        || fail "create-cell to $web_addr unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "create-cell '$cell' refused: $code $body"
    info "oracle-observed: bootstrap-create-cell cell=$cell -> $body (real create-cell HTTP effect)"

    reply=$(driver_http_post "$web_addr" /bootstrap/create-user "${user}"$'\n'"${pass}") \
        || fail "create-user to $web_addr unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "create-user '$user' (passphrase fallback) refused: $code $body"
    info "oracle-observed: bootstrap-first-user-passphrase-fallback user=$user -> $body (real create-user HTTP effect)"

    # --- (2) the one-shot cell_key_can_create_user flip ---------------------
    # A second cell-key create-user MUST now be refused: the capability
    # self-disabled the instant the first user was created.
    reply=$(driver_http_post "$web_addr" /bootstrap/create-user "bob"$'\n'"bob-bic-pass-1!") \
        || fail "second create-user to $web_addr unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "409" ] || fail "expected the one-shot cell_key_can_create_user capability to already be spent (409), got $code $body"
    printf '%s' "$body" | grep -q "CapabilitySpent" \
        || fail "second create-user was refused ($code) but not for the expected CapabilitySpent reason: $body"
    info "oracle-observed: cell-key-can-create-user-flip second create-user refused ($code $body) — the one-shot capability really self-disabled after the first user"

    # --- login as alice (passphrase) for the WebAuthn ceremonies below ------
    local token
    token=$(_bic_login "$web_addr" "$user" "$pass")
    info "oracle-observed: login user=$user (real nonce+login handshake, session issued)"

    # --- (3) WebAuthn browser registration: real Ed25519 credential --------
    local keyfile="${FIXTURE_ROOT}/webauthn-alice.pem" cred_id="bic-cred-alice-1"
    python3 "$py" genkey "$keyfile" || fail "software authenticator keygen failed"

    reply=$(driver_http_post "$web_addr" /webauthn/register/begin "${token}"$'\n'"${user}") \
        || fail "webauthn register/begin unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "webauthn register/begin refused: $code $body"
    local challenge_b64
    challenge_b64=$(printf '%s' "$body" | awk '{print $2}')
    [ -n "$challenge_b64" ] || fail "malformed register/begin reply: $body"

    local attestation_b64
    attestation_b64=$(python3 "$py" register-attestation "$keyfile" "$cred_id" 0) \
        || fail "building the software authenticator's attestation object failed"

    reply=$(driver_http_post "$web_addr" /webauthn/register/finish "${token}"$'\n'"${user}"$'\n'"${challenge_b64}"$'\n'"${attestation_b64}") \
        || fail "webauthn register/finish unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "webauthn register/finish refused: $code $body"
    info "oracle-observed: webauthn-browser-register real Ed25519 attestation accepted -> $body (real RP parse_attestation + COSE-key extraction)"
    # The wire credential id is base64url (the node echoes it in `REGISTERED
    # <b64>`); use the SAME encoded form the RP expects on every subsequent
    # authenticate call (the raw `$cred_id` string is only this scenario's
    # own label / the HKDF salt input, never the wire field).
    local cred_id_b64
    cred_id_b64=$(printf '%s' "$body" | awk '{print $2}')
    [ -n "$cred_id_b64" ] || fail "malformed register/finish reply: $body"

    # --- (3b) WebAuthn browser authenticate: real assertion + PRF unlock ---
    reply=$(driver_http_post "$web_addr" /webauthn/authenticate/begin "$token") \
        || fail "webauthn authenticate/begin unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "webauthn authenticate/begin refused: $code $body"
    local challenge2_b64
    challenge2_b64=$(printf '%s' "$body" | awk '{print $2}')
    [ -n "$challenge2_b64" ] || fail "malformed authenticate/begin reply: $body"

    local ad_b64 cdj_b64 sig_b64
    { read -r ad_b64; read -r cdj_b64; read -r sig_b64; } < <(python3 "$py" sign-assertion "$keyfile" "$challenge2_b64" https://pillar.local 1) \
        || fail "software authenticator failed to sign the assertion"

    local prf_output_b64
    prf_output_b64=$(python3 -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode())")

    reply=$(driver_http_post "$web_addr" /webauthn/authenticate/finish "${token}"$'\n'"${challenge2_b64}"$'\n'"${cred_id_b64}"$'\n'"${ad_b64}"$'\n'"${cdj_b64}"$'\n'"${sig_b64}"$'\n'"${prf_output_b64}") \
        || fail "webauthn authenticate/finish unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "webauthn authenticate/finish refused: $code $body"
    local unlock_b64 expected_unlock_b64
    unlock_b64=$(printf '%s' "$body" | awk '{print $2}')
    [ -n "$unlock_b64" ] || fail "malformed authenticate/finish reply: $body"
    expected_unlock_b64=$(python3 "$py" unlock-expect "$cred_id" "$prf_output_b64")
    [ "$unlock_b64" = "$expected_unlock_b64" ] \
        || fail "op-key unlock secret mismatch: node returned $unlock_b64, independently-recomputed HKDF-SHA256(prf_output,credential_id)=$expected_unlock_b64"
    info "oracle-observed: op-key-sealed-under-prf-derived-key node UNLOCKED=$unlock_b64 matches the independently-recomputed HKDF-SHA256(prf-output,credential-id) (real derivation, not a placeholder)"

    # --- (3c) crypto-realness: a forged (wrong-signer) assertion fails closed
    local mallory_keyfile="${FIXTURE_ROOT}/webauthn-mallory.pem"
    python3 "$py" genkey "$mallory_keyfile" || fail "mallory keygen failed"
    reply=$(driver_http_post "$web_addr" /webauthn/authenticate/begin "$token") \
        || fail "webauthn authenticate/begin (forged case) unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "webauthn authenticate/begin (forged case) refused: $code $body"
    local challenge3_b64
    challenge3_b64=$(printf '%s' "$body" | awk '{print $2}')

    local fad_b64 fcdj_b64 fsig_b64
    { read -r fad_b64; read -r fcdj_b64; read -r fsig_b64; } < <(python3 "$py" sign-assertion "$mallory_keyfile" "$challenge3_b64" https://pillar.local 2) \
        || fail "mallory failed to sign the forged assertion"

    reply=$(driver_http_post "$web_addr" /webauthn/authenticate/finish "${token}"$'\n'"${challenge3_b64}"$'\n'"${cred_id_b64}"$'\n'"${fad_b64}"$'\n'"${fcdj_b64}"$'\n'"${fsig_b64}"$'\n'"${prf_output_b64}") \
        || fail "webauthn authenticate/finish (forged case) unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "401" ] || fail "a forged assertion signed by a DIFFERENT Ed25519 key must be rejected (401), got $code $body"
    info "oracle-observed: webauthn-crypto-realness forged assertion (wrong signer, credential '$cred_id') correctly rejected ($code $body) — real signature verification, not a stub"

    # --- (4) CLI CTAP parity: the real hardware-ceremony code path ----------
    # `pillar webauthn register` on the real (hsm-featured) published image
    # drives the real ctap-hid backend; with no physical authenticator
    # attached it fails closed with a genuine backend "open authenticator"
    # error (not a usage/stub error), proving the code path is real and wired
    # — see the NOTE at the top of this file.
    local ctap_out ctap_rc
    ctap_out=$(_bic_cli webauthn register --user "$user" --domain "127.0.0.1:8642" --token "$token") 2>&1
    ctap_rc=$?
    [ "$ctap_rc" -ne 0 ] || fail "CLI CTAP register unexpectedly succeeded with no hardware authenticator attached: $ctap_out"
    printf '%s' "$ctap_out" | grep -qi "hardware ceremony failed\|open authenticator" \
        || fail "CLI CTAP register failed for an unexpected reason (expected a real hardware/backend error): $ctap_out"
    info "oracle-observed: webauthn-cli-ctap-parity real hardware-ceremony code path reached and failed closed with no physical authenticator attached ($ctap_out)"

    # --- (5) keygen -> node subkey signing -> cross-user trust --------------
    oracle_crypto_realness

    # --- (6) HSM vs software custody -----------------------------------------
    local hsm_out hsm_rc
    hsm_out=$(_bic_cli bootstrap node --domain "127.0.0.1:8642" --node-custody tpm --peer-id "12D3KooWbicHsmNode" --pubkey-cid "bafy-bic-hsm-pubkey") 2>&1
    hsm_rc=$?
    [ "$hsm_rc" -eq 0 ] || fail "HSM (tpm) custody node bootstrap request failed: $hsm_out"
    printf '%s' "$hsm_out" | grep -q "submitted node bootstrap request" \
        || fail "HSM (tpm) custody node bootstrap request did not report success: $hsm_out"
    info "oracle-observed: hsm-custody real \`pillar bootstrap node --node-custody tpm\` request accepted: $hsm_out"

    local sw_out sw_rc
    sw_out=$(_bic_cli bootstrap node --domain "127.0.0.1:8642" --node-custody keyring --peer-id "12D3KooWbicSwNode" --pubkey-cid "bafy-bic-sw-pubkey") 2>&1
    sw_rc=$?
    [ "$sw_rc" -eq 0 ] || fail "software (keyring) custody node bootstrap request failed: $sw_out"
    printf '%s' "$sw_out" | grep -q "submitted node bootstrap request" \
        || fail "software (keyring) custody node bootstrap request did not report success: $sw_out"
    info "oracle-observed: software-custody real \`pillar bootstrap node --node-custody keyring\` request accepted: $sw_out"

    local list_out list_code
    list_out=$(curl -s -m 10 -w '\n%{http_code}' "http://${web_addr}/bootstrap/request/list") \
        || fail "GET /bootstrap/request/list unreachable"
    list_code=$(printf '%s\n' "$list_out" | tail -1)
    body=$(printf '%s\n' "$list_out" | sed '$d')
    [ "$list_code" = "200" ] || fail "request list refused: $list_code $body"
    printf '%s\n' "$body" | grep -q "node node-12D3KooWbicHsmNode" \
        || fail "pending-request queue does not list the HSM (tpm) node request (got: $body)"
    printf '%s\n' "$body" | grep -q "node node-12D3KooWbicSwNode" \
        || fail "pending-request queue does not list the software (keyring) node request (got: $body)"
    info "oracle-observed: hsm-vs-software-custody-both-queued host queue lists both the HSM and software custody node requests independently"

    local bogus_out bogus_rc
    bogus_out=$(_bic_cli bootstrap node --domain "127.0.0.1:8642" --node-custody bogus-custody-kind --peer-id "12D3KooWbicBogusNode" --pubkey-cid "bafy-bic-bogus-pubkey") 2>&1
    bogus_rc=$?
    [ "$bogus_rc" -eq 0 ] && fail "a bogus custody token must be refused, not accepted: $bogus_out"
    printf '%s' "$bogus_out" | grep -qi "unknown custody" \
        || fail "a bogus custody token was refused but not for the expected reason (expected 'unknown custody'): $bogus_out"
    info "oracle-observed: custody-parser-fail-closed a bogus --node-custody token was refused by the real parser (pillar_bootstrap::custody::parse_custody_kind): $bogus_out"

    info "bootstrap-identity-custody: create-cell + passphrase-fallback first user, the one-shot cell_key_can_create_user flip, WebAuthn browser register/authenticate (real Ed25519 + PRF-derived op-key unlock, forged-signer rejection), CLI CTAP parity (real hardware code path, fails closed with no device attached), keygen/node-subkey-signing/cross-user-trust (onboard), and HSM-vs-software custody (real parser, fail-closed on garbage) — all verified against the real published image"
}
