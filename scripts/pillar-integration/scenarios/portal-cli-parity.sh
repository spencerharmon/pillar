#!/usr/bin/env bash
# scenarios/portal-cli-parity.sh — ROI "pillar-integration" scenario family:
# web portal / CLI parity (operator-directed, 2026-08-31).
#
# Stands up ONE real `pillar node run` process from the REAL published image
# with its bootstrap/web HTTP (portal) surface published alongside its health
# probe, drives it SOLELY through its external surfaces (HTTP + a real browser;
# never linking a pillar crate), and asserts, against the REAL served surface
# inventory:
#
#   1. Web-portal / CLI PARITY, driven off the REAL surface inventory the
#      running node serves at `GET /surface-inventory` (the black-box source of
#      truth the `pillar surface-inventory` CLI verb and this route both emit,
#      read from the live verb/route/manifest/wire registries — never a
#      hand-maintained catalog). For every CLI verb the inventory reports, an
#      equivalent portal (HTTP-route) path must exist, and for every portal
#      route family a CLI counterpart (or a recorded, reasoned single-surface
#      exception). `lib/portal_cli_parity.py` applies the SAME declarative
#      parity map the in-tree Rust detector
#      (`pillar_surface_inventory::surface_parity`) does, so a parity gap is a
#      REAL detected diff against the live served surfaces, not a checklist.
#      RED if any CLI verb or HTTP route in the inventory has no portal/CLI
#      counterpart; GREEN when every entry pairs.
#
#   2. The Yew portal LOGIN end to end through a REAL headless browser
#      (Chromium via Selenium WebDriver, `lib/portal_login_e2e.py`) against the
#      real running node: it loads the actual portal HTML (`GET /`), types the
#      identifier+password into the real `#identifier`/`#password` fields,
#      submits, and asserts the browser transitions into the authenticated
#      `#portal` view — the SAME login a human performs, driven by a real DOM
#      automation engine, not a hand-crafted request.
#
# RED / GREEN: RED if a CLI verb or HTTP route in the inventory has no
# portal/CLI counterpart (a real parity gap), or if the real browser never
# reaches the authenticated portal view; GREEN when every inventory entry pairs
# AND the browser login lands in the portal.
#
# It is deliberately black-box: it never links a pillar crate, observing only
# the container, the served inventory JSON, and a real browser's DOM.

# _pcp_wait_ready <health-addr> <web-addr> : block until both surfaces answer.
_pcp_wait_ready() {
    local health_addr="$1" web_addr="$2"
    retry 30 bash -c "curl -s -m 2 -o /dev/null http://${health_addr}/readyz" \
        || fail "node at $health_addr never answered /readyz within 30s"
    retry 30 bash -c "curl -s -m 2 -o /dev/null http://${web_addr}/bootstrap/status" \
        || fail "node at $web_addr never answered /bootstrap/status within 30s"
}

# _pcp_ensure_image : the parity/login surfaces this scenario asserts
# (`/surface-inventory`, the `surface-inventory` CLI verb) are NEW code, so a
# previously-published `$PILLAR_IMAGE` may predate them. This scenario must
# test the REAL bytes of the CODE UNDER TEST, so: probe the currently-selected
# image for the new surface; if it is ABSENT, build a fresh local image from
# THIS worktree's source (real image bytes, no stale catalog) and repoint
# `$PILLAR_IMAGE` at it. If the selected image already serves it (a
# republished image), use it as-is. Echoes nothing; sets PILLAR_IMAGE.
_pcp_ensure_image() {
    # Does the selected image already know the `surface-inventory` verb?
    if "$CONTAINER_RUNTIME" run --rm --entrypoint /bin/pillar "$PILLAR_IMAGE" \
        surface-inventory >/dev/null 2>&1; then
        info "portal-cli-parity: selected image $PILLAR_IMAGE already serves the surface-inventory surface — using it"
        return 0
    fi
    info "portal-cli-parity: $PILLAR_IMAGE predates the surface-inventory surface — building a local image from this worktree's source"

    # The repo root is two levels up from scripts/pillar-integration/.
    local repo_root
    repo_root="$(cd "$HERE/../.." && pwd)"
    [ -f "$repo_root/Cargo.toml" ] \
        || fail "portal-cli-parity: cannot locate the crate root to build a local image (looked in $repo_root)"

    command -v cargo >/dev/null 2>&1 \
        || fail "portal-cli-parity: the selected image lacks the surface under test and cargo is not available to build a local one"

    info "portal-cli-parity: cargo build -p pillar-cli (release) — compiling the binary under test"
    ( cd "$repo_root" && cargo build --release -p pillar-cli ) \
        || fail "portal-cli-parity: cargo build -p pillar-cli failed"
    local bin="$repo_root/target/release/pillar"
    [ -x "$bin" ] || fail "portal-cli-parity: built binary not found at $bin"

    # Package the fresh binary into a minimal local image whose runtime
    # contract mirrors the flake image (entrypoint `pillar node run`, the same
    # PILLAR_* env), on a glibc base matching the dynamically-linked binary.
    local ctxdir="${FIXTURE_ROOT}/img"
    mkdir -p "$ctxdir"
    cp "$bin" "$ctxdir/pillar"
    cat >"$ctxdir/Containerfile" <<'EOF'
FROM docker.io/library/debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY pillar /bin/pillar
ENV PILLAR_DATA_DIR=/var/lib/pillar/data \
    PILLAR_IDENTITY_KEY=/var/lib/pillar/data/identity.key \
    PILLAR_LISTEN=/ip4/0.0.0.0/tcp/0
WORKDIR /var/lib/pillar
RUN mkdir -p /var/lib/pillar/data
ENTRYPOINT ["/bin/pillar", "node", "run"]
EOF
    local local_tag="localhost/pillar-it-portal-cli-parity:under-test"
    info "portal-cli-parity: building local image $local_tag (real bytes of the code under test)"
    "$CONTAINER_RUNTIME" build -t "$local_tag" "$ctxdir" >/dev/null 2>&1 \
        || fail "portal-cli-parity: building the local image from the worktree binary failed"
    PILLAR_IMAGE="$local_tag"
    export PILLAR_IMAGE
    # Prove the freshly-built image really serves the new surface before we run.
    "$CONTAINER_RUNTIME" run --rm --entrypoint /bin/pillar "$PILLAR_IMAGE" \
        surface-inventory >/dev/null 2>&1 \
        || fail "portal-cli-parity: the locally-built image still does not serve the surface-inventory surface"
    info "portal-cli-parity: using locally-built image $PILLAR_IMAGE"
}

scenario_portal-cli-parity() {
    local parity_py="$LIB/portal_cli_parity.py"
    local login_py="$LIB/portal_login_e2e.py"
    command -v python3 >/dev/null 2>&1 \
        || fail "portal-cli-parity needs python3 (the parity checker + browser login driver)"
    command -v curl >/dev/null 2>&1 \
        || fail "portal-cli-parity needs curl (to fetch the served surface inventory)"

    mkdir -p "$FIXTURE_ROOT"

    # Ensure the image under test actually serves the (new) parity surfaces.
    _pcp_ensure_image

    # --- boot one real node, its bootstrap/web (portal) HTTP surface published
    PCP_NODE_NAME="pillar-it-${FIXTURE_SCENARIO}-node"
    local cid web_addr health_addr
    cid=$("$CONTAINER_RUNTIME" run -d \
        --name "$PCP_NODE_NAME" \
        --label "$FIXTURE_LABEL" \
        -e PILLAR_WEB_BIND=0.0.0.0 \
        -e PILLAR_WEB_PORT=8642 \
        -p "127.0.0.1::8643" \
        -p "127.0.0.1::8642" \
        "$PILLAR_IMAGE" 2>&1) \
        || fail "node failed to start: $cid"
    health_addr=$("$CONTAINER_RUNTIME" port "$PCP_NODE_NAME" 8643 2>/dev/null | head -1)
    web_addr=$("$CONTAINER_RUNTIME" port "$PCP_NODE_NAME" 8642 2>/dev/null | head -1)
    [ -n "$health_addr" ] || fail "could not resolve published health port"
    [ -n "$web_addr" ] || fail "could not resolve published web port"
    _pcp_wait_ready "$health_addr" "$web_addr"
    info "portal-cli-parity: node up as $PCP_NODE_NAME (health=$health_addr web=$web_addr)"

    # process oracle: a real node pid + a real bound listening socket.
    oracle_process "$PCP_NODE_NAME" "$health_addr"

    # --- (1) PARITY against the REAL served surface inventory ---------------
    local inv_file="${FIXTURE_ROOT}/surface-inventory.json" code
    code=$(curl -s -m 10 -o "$inv_file" -w '%{http_code}' \
        "http://${web_addr}/surface-inventory" 2>/dev/null) \
        || fail "GET /surface-inventory to $web_addr unreachable"
    [ "$code" = "200" ] \
        || fail "the running node did not serve GET /surface-inventory (HTTP $code) — the real image must expose the inventory for a black-box parity check"
    grep -q '"schema": *"pillar-integration/v1"' "$inv_file" \
        || fail "served inventory is not a pillar-integration/v1 document: $(head -c 200 "$inv_file")"
    info "oracle-observed: surface-inventory-served node=$PCP_NODE_NAME entries=$(grep -c '"id":' "$inv_file") (real GET /surface-inventory from the running image)"

    # The parity oracle: RED (exit 1) on any CLI/portal gap, GREEN (exit 0)
    # when every inventory entry pairs. Driven off the REAL served inventory.
    if ! python3 "$parity_py" "$inv_file"; then
        fail "portal-cli-parity: the REAL served surface inventory has a parity gap (see parity-gap lines above) — a CLI verb or HTTP route with no portal/CLI counterpart"
    fi
    info "oracle-observed: portal-cli-parity GREEN — every CLI verb and portal route family in the REAL served inventory pairs against a counterpart"

    # --- bootstrap a cell + first user so the portal can be logged into ------
    local cell="pcp-cell" user="alice" pass='alice-pcp-pass-1!' reply body
    reply=$(driver_http_post "$web_addr" /bootstrap/create-cell "$cell") \
        || fail "create-cell to $web_addr unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "create-cell '$cell' refused: $code $body"

    reply=$(driver_http_post "$web_addr" /bootstrap/create-user "${user}"$'\n'"${pass}") \
        || fail "create-user to $web_addr unreachable"
    code=$(printf '%s\n' "$reply" | sed -n '1p')
    body=$(printf '%s\n' "$reply" | sed -n '3p')
    [ "$code" = "200" ] || fail "create-user '$user' refused: $code $body"
    info "oracle-observed: portal-bootstrap cell=$cell user=$user created (real HTTP bootstrap effect)"

    # --- (2) Yew portal LOGIN e2e via a REAL headless browser ---------------
    # Selenium + a headless Chromium DOM automation engine loads the real
    # portal HTML and performs the SAME login a human does. If the browser
    # stack is genuinely unavailable this is a hard failure (the ROI requires
    # a real browser-automation driver) — never a silent skip.
    if ! python3 -c "import selenium" >/dev/null 2>&1; then
        fail "portal-cli-parity: python selenium is required for the real browser portal-login e2e but is not importable"
    fi
    command -v chromedriver >/dev/null 2>&1 \
        || fail "portal-cli-parity: chromedriver is required for the real browser portal-login e2e but was not found on PATH"

    if ! python3 "$login_py" "http://${web_addr}" "$user" "$pass"; then
        fail "portal-cli-parity: the real headless-browser portal login for '$user' never reached the authenticated portal view (see diagnostics above)"
    fi
    info "portal-cli-parity: all oracles observed real external effects (parity GREEN + real browser login reached the portal) on the real node"
}
