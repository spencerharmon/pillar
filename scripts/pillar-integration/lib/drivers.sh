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

# driver_http_post <host:port> <path> <body-data> : POST a running node's
# bootstrap/login HTTP surface (`pillar_cli::web_serve`'s gated route table —
# create-cell, create-user, nonce, login, bootstrap-request submit/list/
# approve/reject). Speaks the wire framing those routes document directly, so
# the geo-replication (and any future cross-cell) scenario drives a real node
# process's real HTTP surface with NO linkage to pillar internals — same
# black-box boundary as `driver_http`/`driver_cli_exec`.
#
# Prints THREE lines: `<http-code>`, the `X-Pillar-Session` bearer (or empty),
# then the response body (verbatim, may itself contain embedded newlines —
# always the LAST line(s) of output, so a caller does
# `IFS= read -r code; IFS= read -r session; body=$(cat)`-style parsing, or for
# the common single-line-body case, `sed -n '3p'`). Returns 0 iff the request
# completed (HTTP layer answered), non-zero on a connection failure.
driver_http_post() {
    local addr="$1" path="$2" data="$3" hdrfile out code session
    hdrfile="$(mktemp "${TMPDIR:-/tmp}/pillar-it-http-hdr.XXXXXX")"
    out=$(curl -s -m 10 -D "$hdrfile" -X POST --data-binary "$data" "http://${addr}${path}" 2>/dev/null)
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        rm -f "$hdrfile"
        return 1
    fi
    code=$(head -1 "$hdrfile" | awk '{print $2}')
    session=$(grep -i '^X-Pillar-Session:' "$hdrfile" | tr -d '\r' | cut -d' ' -f2-)
    rm -f "$hdrfile"
    printf '%s\n%s\n%s\n' "$code" "$session" "$out"
}
