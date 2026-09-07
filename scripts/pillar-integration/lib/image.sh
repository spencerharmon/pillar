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
    local root tag streamer
    root="$(image_repo_root)"
    tag="pillar-it-under-test:local"

    command -v nix >/dev/null 2>&1 \
        || fail "image_build_local: nix not on PATH — cannot build the image-under-test the scenario's surface requires"

    info "image: building reproducible image-under-test from $root/flake.nix (nix .#pillar-oci-image)"
    # streamLayeredImage yields a *streamer script*; run it to produce the OCI
    # tar on stdout and load it directly into the runtime.
    streamer="$(nix --extra-experimental-features "nix-command flakes" \
        build --no-link --print-out-paths "$root#pillar-oci-image" 2>&1 | tail -1)" \
        || fail "image_build_local: nix build .#pillar-oci-image failed:\n$streamer"
    [ -x "$streamer" ] \
        || fail "image_build_local: expected an executable streamer at '$streamer'"

    info "image: loading the built image-under-test into $CONTAINER_RUNTIME as $tag"
    "$streamer" | "$CONTAINER_RUNTIME" load 2>&1 | tail -3 \
        || fail "image_build_local: loading the streamed image into $CONTAINER_RUNTIME failed"
    # streamLayeredImage's config names the image; retag to our stable local
    # ref so the topology fabric can reference it deterministically.
    local built
    built="$("$CONTAINER_RUNTIME" images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
        | grep -E '^(localhost/)?pillar' | head -1)"
    if [ -n "$built" ] && [ "$built" != "$tag" ]; then
        "$CONTAINER_RUNTIME" tag "$built" "$tag" >/dev/null 2>&1 || true
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
