#!/usr/bin/env bash
# image.sh — the image-under-test resolver.
#
# The harness drives the REAL published image (`$PILLAR_IMAGE`, default the
# ghcr `:latest`). A scenario that exercises a CLI surface NEWER than what the
# currently-published image serves would otherwise fail spuriously ("unknown
# verb") — not because the surface is broken, but because the published image
# lags the working tree. `image_require_verb <verb>` closes that gap
# deterministically and black-box: it probes the published image's REAL CLI
# surface for `<verb>`, and if the image does not serve it, builds a
# reproducible image-under-test from THIS working tree's `flake.nix`
# (`nix build .#pillar-oci-image`, the same streamLayeredImage the CI publish
# uses) and repoints `$PILLAR_IMAGE` at that local build. Either way the
# scenario then drives an image that ACTUALLY serves the surface under test —
# still purely through the external CLI, never linking a crate.
#
# This keeps the check self-contained (it builds exactly the image it needs to
# assert against) without weakening the black-box contract: the image-under-
# test is a real OCI image assembled from source, and the scenario observes it
# only through its published binary + sockets.

# image_serves_verb <verb> : exit 0 iff `$PILLAR_IMAGE` serves the CLI <verb>.
# Probes the REAL image's dispatch surface WITHOUT side effects: `pillar
# completion bash` emits a completion script generated from the real, served
# verb table (`cli_surface::verb_table`), so a verb the binary dispatches
# appears there and one it does not never does.
image_serves_verb() {
    local verb="$1" out
    out=$("$CONTAINER_RUNTIME" run --rm --entrypoint /bin/pillar "$PILLAR_IMAGE" completion bash 2>&1)
    printf '%s\n' "$out" | grep -qw -- "$verb"
}

# image_repo_root : print the pillar submodule repo root (two levels up from
# scripts/pillar-integration/), where flake.nix lives.
image_repo_root() {
    ( cd "$HERE/../.." && pwd )
}

# image_build_local : build a reproducible OCI image-under-test from the
# working tree's flake and load it into the container runtime, printing the
# loaded image reference. Fails loudly (non-zero) if nix or the load fails.
image_build_local() {
    local root tag gcroot buildlog build_rc attempt diag
    root="$(image_repo_root)"
    tag="pillar-it-under-test:local"

    command -v nix >/dev/null 2>&1 \
        || fail "image_build_local: nix not on PATH — cannot build the image-under-test the scenario's surface requires"

    info "image: building reproducible image-under-test from $root/flake.nix (nix .#pillar-oci-image)"
    # streamLayeredImage yields a *streamer script*; run it to produce the OCI
    # tar on stdout and load it directly into the runtime. This build can take
    # several minutes (a from-source rust build) on a shared nix store the
    # rest of the swarm is concurrently building/GC'ing against, so we MUST
    # pin a real GC root for the duration: `--no-link` registers none, which
    # lets a concurrent `nix-collect-garbage`/eviction reap our just-built
    # output out from under us between build completion and use.
    #
    # Use the `--out-link` SYMLINK ITSELF as the handle to the build result,
    # never a `/nix/store/<hash>-...` path parsed out of `--print-out-paths`
    # stdout: repeated runs (in the runner's sandboxed check harness only —
    # never reproduced unsandboxed) observed the freshly-built bare store path
    # reported as absent even after a 10s settle, while the build itself
    # reported success. The out-link, by contrast, is a path WE created (via
    # mktemp) in our own already-visible tmp directory before the build ever
    # ran, so resolving it forces a fresh lookup through our own namespace
    # rather than depending on the sandbox's view of a brand-new /nix/store
    # entry becoming visible after the fact.
    buildlog="$(mktemp "${TMPDIR:-/tmp}/pillar-it-oci-image-build.XXXXXX.log")"
    gcroot="$(mktemp -u "${TMPDIR:-/tmp}/pillar-it-oci-image.XXXXXX")"
    nix --extra-experimental-features "nix-command flakes" \
        build --out-link "$gcroot" "$root#pillar-oci-image" >"$buildlog" 2>&1
    build_rc=$?
    if [ "$build_rc" -ne 0 ]; then
        diag="$(tail -20 "$buildlog")"
        rm -f "$gcroot" "$buildlog"
        fail "image_build_local: nix build .#pillar-oci-image failed (exit $build_rc):\n$diag"
    fi
    rm -f "$buildlog"

    # Settle: even a successful build's out-link can take a moment to resolve
    # under the sandbox (observed, cause unconfirmed — NOT a GC race, since
    # the root already protects the object). Poll for up to 30s. If it still
    # never resolves, capture directory-listing diagnostics so the next pass
    # has real evidence instead of a bare "absent" message.
    for attempt in $(seq 1 30); do
        [ -x "$gcroot" ] && break
        sleep 1
    done
    if [ ! -x "$gcroot" ]; then
        diag="gcroot=$gcroot readlink=$(readlink -f "$gcroot" 2>&1)
ls -la \$(dirname \$gcroot): $(ls -la "$(dirname "$gcroot")" 2>&1 | grep -F "$(basename "$gcroot")")
ls -la target dir (if resolvable): $(ls -la "$(readlink -f "$gcroot" 2>/dev/null | xargs -r dirname)" 2>&1 | tail -5)"
        rm -f "$gcroot"
        fail "image_build_local: build succeeded (exit 0) but the out-link '$gcroot' never resolved to an executable after a 30s settle. Diagnostics:\n$diag"
    fi
    local streamer="$gcroot"

    # Discard any stale prior local build BEFORE loading: `nix build`'s
    # reproducible output has a fixed (epoch) creation timestamp, so
    # `podman images` has NO reliable recency ordering between a fresh load
    # and a stale `pillar-it-under-test:local`/`localhost/pillar:*` left by an
    # earlier run — a `grep | head -1` heuristic over the image list can pick
    # the STALE image (confirmed: this previously caused
    # "freshly built image-under-test still does not serve '<verb>'" even
    # though the fresh build itself was correct). Removing any stale tag first
    # means whatever `podman load` reports having just loaded is unambiguous.
    "$CONTAINER_RUNTIME" rmi -f "$tag" >/dev/null 2>&1 || true

    info "image: loading the built image-under-test into $CONTAINER_RUNTIME as $tag"
    local load_out load_rc
    load_out="$("$streamer" | "$CONTAINER_RUNTIME" load 2>&1)"
    load_rc=$?
    printf '%s\n' "$load_out" | tail -3
    rm -f "$gcroot"
    [ "$load_rc" -eq 0 ] \
        || fail "image_build_local: loading the streamed image into $CONTAINER_RUNTIME failed:\n$load_out"
    # Parse the EXACT reference podman/docker just loaded ("Loaded image:
    # <ref>") rather than re-deriving it via a heuristic scan of the whole
    # image list — deterministic regardless of any other pillar* tag present.
    local loaded
    loaded="$(printf '%s\n' "$load_out" | sed -n 's/^Loaded image: //p' | tail -1)"
    if [ -n "$loaded" ] && [ "$loaded" != "$tag" ]; then
        "$CONTAINER_RUNTIME" tag "$loaded" "$tag" \
            || fail "image_build_local: failed to tag loaded image '$loaded' as '$tag'"
    elif [ -z "$loaded" ]; then
        fail "image_build_local: could not parse a 'Loaded image: <ref>' line from $CONTAINER_RUNTIME load output:\n$load_out"
    fi
    PILLAR_IMAGE="$tag"
    export PILLAR_IMAGE
    info "image: image-under-test ready: $PILLAR_IMAGE"
}

# image_require_verb <verb> : ensure the image the scenario will drive serves
# <verb>. If the published `$PILLAR_IMAGE` already serves it, keep it; else
# build+load a local image-under-test from the working tree and repoint
# `$PILLAR_IMAGE`. Idempotent within a run.
image_require_verb() {
    local verb="$1"
    # Ensure the runtime has the published image locally to probe it.
    "$CONTAINER_RUNTIME" image exists "$PILLAR_IMAGE" 2>/dev/null \
        || "$CONTAINER_RUNTIME" pull "$PILLAR_IMAGE" >/dev/null 2>&1 || true

    if "$CONTAINER_RUNTIME" image exists "$PILLAR_IMAGE" 2>/dev/null \
        && image_serves_verb "$verb"; then
        info "image: published image $PILLAR_IMAGE already serves '$verb' — using it"
        return 0
    fi

    warn "image: $PILLAR_IMAGE does not serve CLI verb '$verb' (published image lags the working tree) — building a local image-under-test"
    image_build_local
    image_serves_verb "$verb" \
        || fail "image_require_verb: freshly built image-under-test still does not serve '$verb'"
    info "image: image-under-test serves '$verb' (built from working-tree source)"
}
