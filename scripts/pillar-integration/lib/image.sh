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
    local root tag streamer gcroot build_err build_rc
    root="$(image_repo_root)"
    tag="pillar-it-under-test:local"

    command -v nix >/dev/null 2>&1 \
        || fail "image_build_local: nix not on PATH — cannot build the image-under-test the scenario's surface requires"

    info "image: building reproducible image-under-test from $root/flake.nix (nix .#pillar-oci-image)"
    # streamLayeredImage yields a *streamer script*; run it to produce the OCI
    # tar on stdout and load it directly into the runtime.
    #
    # Anchor the build output under a REAL GC root (`--out-link`) for the whole
    # lifetime of this function. `--no-link --print-out-paths` leaves the result
    # unrooted, so on a busy shared build host the store path can be garbage-
    # collected between the print and the `[ -x ]`/run — the recurring
    # 'expected an executable streamer' failure. The GC root pins it until we
    # remove the link at function end (via the RETURN trap below).
    #
    # CRITICAL — the out-link MUST live on a path the HOST nix-daemon can see.
    # `nix build --out-link L` registers an *indirect* GC root: a symlink in
    # `/nix/var/nix/gcroots/auto/<hash>` pointing at the ABSOLUTE path of L,
    # which the daemon dereferences (host-side) to find the rooted store path.
    # Under the beehive DoD check-sandbox (bwrap, LOCALS.md 'DoD Check: sandbox')
    # `$TMPDIR`/`/tmp` is the jail's PRIVATE tmpfs, so an out-link under $TMPDIR
    # yields an auto-gcroot symlink pointing at `/tmp/...` that does NOT EXIST on
    # the host — the daemon sees a dangling root, treats the path as unrooted,
    # and a GC pass during the ~11-13min from-scratch build collects the streamer
    # before `[ -x ]` runs (the deterministic 'expected an executable streamer'
    # failure). The submodule checkout `$root`, by contrast, is bind-mounted into
    # the jail at its TRUE host absolute path, so an out-link under $root produces
    # an auto-gcroot the host daemon CAN resolve. Anchor there, never $TMPDIR.
    local gcdir
    gcdir="$(mktemp -d "$root/.pillar-it-gcroot.XXXXXX")"
    gcroot="$gcdir/streamer"
    # shellcheck disable=SC2064
    trap "rm -rf -- '$gcdir'" RETURN
    # Capture stdout (the store path) and stderr SEPARATELY so a diagnostic
    # stderr line can never be mistaken for the printed store path. stdout is the
    # out-path; stderr is captured to a temp file for the failure message.
    build_err="$(mktemp "${TMPDIR:-/tmp}/pillar-it-build-err.XXXXXX")"
    streamer="$(nix --extra-experimental-features "nix-command flakes" \
        build --out-link "$gcroot" --print-out-paths "$root#pillar-oci-image" \
        2>"$build_err")"
    build_rc=$?
    if [ "$build_rc" -ne 0 ]; then
        local err_txt; err_txt="$(cat "$build_err")"; rm -f -- "$build_err"
        fail "image_build_local: nix build .#pillar-oci-image failed:\n$err_txt"
    fi
    rm -f -- "$build_err"
    # `--print-out-paths` may emit multiple paths (one per output); take the last
    # non-empty stdout line as the streamer store path.
    streamer="$(printf '%s\n' "$streamer" | sed '/^$/d' | tail -1)"
    # Diagnostics: prove the GC root is anchored where the HOST daemon can see it.
    # Logs the resolved out-link absolute path, whether the symlink now resolves,
    # and the auto-gcroot the daemon registered for it (host-visible target). If a
    # future run regresses, this pinpoints whether the anchor survived the jail.
    info "image: gcroot out-link=$gcroot resolves-to=$(readlink -f "$gcroot" 2>/dev/null || echo '<none>')"
    if [ -d /nix/var/nix/gcroots/auto ]; then
        local _autoroot
        _autoroot="$(grep -rl -- "$gcdir" /nix/var/nix/gcroots/auto 2>/dev/null | head -1 || true)"
        info "image: gcroot auto-registration=${_autoroot:-<none-found>}"
    fi
    # Belt-and-suspenders: even with the root anchored, re-REALISE the store path
    # immediately before the executable check so a path collected in a race window
    # is rebuilt/substituted (cheap when already present) rather than failing the
    # guard. This makes the streamer's presence a computed fact, not an assumption.
    if [ -n "$streamer" ] && [ ! -x "$streamer" ]; then
        warn "image: streamer '$streamer' not executable after build — re-realising the store path"
        nix --extra-experimental-features "nix-command flakes" \
            build --out-link "$gcroot" "$root#pillar-oci-image" >/dev/null 2>&1 || true
    fi
    [ -x "$streamer" ] \
        || fail "image_build_local: expected an executable streamer at '$streamer'"

    info "image: loading the built image-under-test into $CONTAINER_RUNTIME as $tag"
    # Capture the runtime's load output and adopt the EXACT ref it just loaded —
    # never a `head -1` guess among pre-existing `pillar*` images (a stale
    # `pillar-it-under-test:local` from a prior run sorts before
    # `localhost/pillar:latest` and would be adopted instead, leaving
    # `$PILLAR_IMAGE` on an image that does not serve the verb under test — a
    # non-deterministic, cache-dependent DoD failure). Both podman and docker
    # print a `Loaded image[(s)]: <ref>` line naming the concrete loaded ref.
    local load_out loaded
    load_out="$("$streamer" | "$CONTAINER_RUNTIME" load 2>&1)" \
        || fail "image_build_local: loading the streamed image into $CONTAINER_RUNTIME failed:\n$load_out"
    printf '%s\n' "$load_out" | tail -3 | while IFS= read -r l; do info "image: load: $l"; done
    loaded="$(printf '%s\n' "$load_out" \
        | sed -n 's/^Loaded image[s]*: *//p' | head -1)"
    # The flake's `pillar-oci-image` has a FIXED name/tag (`pillar:latest`), so a
    # runtime that does not print a Loaded-image line still lands it at
    # `localhost/pillar:latest` (podman) or `pillar:latest` (docker); fall back
    # to that fixed ref rather than guessing.
    if [ -z "$loaded" ]; then
        if "$CONTAINER_RUNTIME" image exists localhost/pillar:latest 2>/dev/null; then
            loaded="localhost/pillar:latest"
        else
            loaded="pillar:latest"
        fi
    fi
    "$CONTAINER_RUNTIME" image exists "$loaded" 2>/dev/null \
        || fail "image_build_local: could not resolve the freshly-loaded image ref (parsed '$loaded') from:\n$load_out"
    info "image: adopting freshly-loaded ref '$loaded' and retagging to $tag"
    if [ "$loaded" != "$tag" ]; then
        "$CONTAINER_RUNTIME" tag "$loaded" "$tag" >/dev/null 2>&1 \
            || fail "image_build_local: could not retag '$loaded' -> '$tag'"
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
