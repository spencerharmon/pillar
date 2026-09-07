#!/usr/bin/env bash
# common.sh — shared helpers for the pillar black-box integration harness.
#
# This is sourced by every harness layer (fixtures, topology, drivers,
# oracles) and by the run-scenario.sh entrypoint. It carries NO state shared
# with pillar internals: the harness only ever observes pillar through its
# external surfaces (container lifecycle, listening sockets, the CLI, HTTP),
# exactly as the ROI's black-box mandate requires.
#
# All output is line-oriented so an external caller (a bee, CI) can grep the
# transcript for the exact effect that was observed.

# --- logging ---------------------------------------------------------------

# The harness prints structured, greppable lines. Everything an oracle
# actually OBSERVES is printed as `oracle-observed: <what> <detail>` so a
# reviewer can confirm the harness asserted a real external effect and not a
# return code.
log()   { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
info()  { log "INFO  $*"; }
warn()  { log "WARN  $*" >&2; }
fail()  { log "FAIL  $*" >&2; exit 1; }

# --- container runtime resolution ------------------------------------------
#
# The topology fabric drives a real OCI runtime. containerlab is the preferred
# fabric when present (it gives the impairment matrix — tc/netem — the ROI's
# scenario families need), but for the smoke scenario a plain rootless
# podman/docker topology suffices and is what runs in the check sandbox. The
# runtime is resolved ONCE here and exported.
resolve_container_runtime() {
    if [ -n "${PILLAR_IT_RUNTIME:-}" ]; then
        command -v "$PILLAR_IT_RUNTIME" >/dev/null 2>&1 \
            || fail "PILLAR_IT_RUNTIME=$PILLAR_IT_RUNTIME not found on PATH"
        CONTAINER_RUNTIME="$PILLAR_IT_RUNTIME"
    elif command -v podman >/dev/null 2>&1; then
        CONTAINER_RUNTIME=podman
    elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        CONTAINER_RUNTIME=docker
    else
        fail "no usable container runtime (podman or working docker) found — the black-box topology fabric needs one"
    fi
    export CONTAINER_RUNTIME
    info "container runtime: $CONTAINER_RUNTIME"
}

# The real published image under test. Defaults to the ghcr image the
# container-image-ghcr-publish task publishes; overridable so a scenario can
# pin an immutable :<version> tag or a local build.
PILLAR_IMAGE="${PILLAR_IMAGE:-ghcr.io/spencerharmon/pillar:latest}"
export PILLAR_IMAGE

# The node's in-container readiness/liveness probe port (health.rs binds
# 0.0.0.0:8643; `GET /readyz` = substantive readiness, `GET /healthz` =
# liveness). The topology fabric publishes this to an ephemeral host port so
# the process/HTTP oracle can observe the real listening socket from outside
# the container.
PILLAR_PROBE_PORT="${PILLAR_PROBE_PORT:-8643}"
export PILLAR_PROBE_PORT

# retry <timeout-seconds> <cmd...> : run cmd until it exits 0 or the timeout
# elapses. Used by oracles/fixtures to wait on a real converging effect
# instead of sleeping a fixed amount.
retry() {
    local timeout="$1"; shift
    local waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if "$@"; then return 0; fi
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}
