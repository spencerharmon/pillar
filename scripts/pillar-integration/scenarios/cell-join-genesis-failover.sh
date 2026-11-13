#!/usr/bin/env bash
# Three independently initialized nodes; only genesis bootstraps a cell.
scenario_cell-join-genesis-failover() {
    # Test the checkout, not a possibly older published :latest. CI can supply
    # its immutable image explicitly to avoid rebuilding it.
    if [ "$PILLAR_IMAGE" = ghcr.io/spencerharmon/pillar:latest ]; then
        image_build_local || fail "could not build image under test"
    fi
    mkdir -p "$FIXTURE_ROOT" || fail "could not create fixture directory"
    python3 "$LIB/cell_join_genesis_failover.py" \
        "$CONTAINER_RUNTIME" "$PILLAR_IMAGE" "$FIXTURE_LABEL" "$FIXTURE_ROOT" \
        || fail "cell join / genesis failover oracle failed"
}
