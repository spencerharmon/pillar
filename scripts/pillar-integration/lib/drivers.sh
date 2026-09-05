#!/usr/bin/env bash
# drivers.sh — the driver layer.
#
# Thin black-box clients that drive pillar SOLELY through its external
# surfaces, with NO shared state with pillar internals. Every driver execs the
# real published binary or speaks a real wire protocol to a running node; none
# reaches into pillar's process memory or links its crates.
#
#   driver_cli_exec   — run the real `pillar` CLI binary FROM the published
#                       image (entrypoint override), the manifest-applier /
#                       CLI-exec client. Used to APPLY a manifest / drive a CLI
#                       verb against the real image bytes under test.
#   driver_http       — GET a running node's real HTTP surface (its readiness/
#                       liveness probe served by health.rs over a real
#                       TcpListener) and print status+body.
#
# The raw pillar-UDP + libp2p driver the ROI enumerates is layered on this same
# contract by the wire-oracle scenario families; the smoke scenario needs only
# the CLI-exec and HTTP drivers.

# driver_cli_exec <pillar-args...> : run `pillar <args>` using the REAL
# published image's binary (a fresh throwaway container, entrypoint overridden
# to /bin/pillar). Exercises the real image bytes through the CLI surface with
# no linkage to pillar internals. Prints the CLI's combined output; returns its
# exit code.
driver_cli_exec() {
    "$CONTAINER_RUNTIME" run --rm --entrypoint /bin/pillar "$PILLAR_IMAGE" "$@" 2>&1
}

# driver_http <host:port> <path> : GET a running node's HTTP probe surface.
# Prints "<http-code> <body>" on one line; returns 0 iff the request completed
# (HTTP layer answered), non-zero on a connection failure.
driver_http() {
    local addr="$1" path="$2" out code body
    out=$(curl -s -m 5 -w '\n%{http_code}' "http://${addr}${path}" 2>/dev/null) || return 1
    code=$(printf '%s' "$out" | tail -1)
    body=$(printf '%s' "$out" | sed '$d' | tr -d '\n')
    printf '%s %s\n' "$code" "$body"
}
