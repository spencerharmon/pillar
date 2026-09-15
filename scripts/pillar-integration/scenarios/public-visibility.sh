#!/usr/bin/env bash
# scenarios/public-visibility.sh — the public-visibility scenario family.
#
# ROI Priority 1 "Streamdb performance is a standing, self-perpetuating
# discipline" (operator, 2026-09-14): "a public target is a real entry in the
# integration/pillar-integration-scenario catalog, not a synthetic microbench
# only." This is that real entry: it drives >=3 real nodes on the REAL
# published image through EXTERNAL surfaces ONLY and asserts the realness
# oracles that prove `public` is a real, DISTINCT visibility class which leaves
# the encrypted default intact:
#
#   1. boot a real >=3-node topology on the real ghcr image; a process oracle
#      on every node confirms each is a real running OS process with a real
#      bound listening socket (the real image nodes, not a stub);
#   2. drive the real image's `public-visibility` CLI verb (the streamdb
#      visibility-class surface), which runs the REAL production
#      `pillar_streamdb::IpfsPersistentStream` op path + the REAL
#      `pillar_rbac::RbacDecider` and asserts, from its transcript alone:
#        - create a public collection + write a record; a SEPARATE keyless
#          reader reads it back recovering CLEARTEXT (the at-rest/on-wire bytes
#          are plaintext for public) while its Ed25519 signature verifies and
#          its CID resolves;
#        - an unauthorized write is RBAC-refused (fail-closed), a granted one
#          allowed;
#        - a CONTRAST cell-encrypted collection is NOT readable by the keyless
#          reader (ciphertext at rest), only by the cell member holding the
#          group key — proving public is a real, distinct class that leaves the
#          encrypted default intact;
#   3. tear the topology down IDEMPOTENTLY even on failure; a leak-detector
#      pass confirms zero residue.
#
# RED if any oracle is unobserved (a public op unreadable keyless, an
# unauthorized write admitted, or the cell-encrypted default leaked/keyless-
# readable) — the verb exits non-zero and the scenario fails loud. GREEN when
# every oracle held. It is black-box: it drives ONLY the real image's external
# CLI + node surfaces and observes only their transcripts — it never links a
# pillar crate. Sourced by run-scenario.sh, which has already sourced the lib
# layer and run fixtures_init.
#
# Inventory claims (surface-inventory-emitter entries this scenario exercises):
#   - cli:public-visibility  (the real streamdb visibility-class decision verb)
#   - cli:node               (the real image node the topology boots)
# proven by the `public_visibility` and `process` oracles respectively.

# scenario_public-visibility_claims : declare the surface-inventory entries this
# scenario CLAIMS, printed as greppable `inventory-claim:` lines so the
# conformance rig / a reviewer can confirm every claim targets a real inventory
# entry and is proven by a named real oracle.
scenario_public-visibility_claims() {
    info "inventory-claim: cli:public-visibility proven-by=public_visibility (real streamdb public/cell-encrypted op path + RBAC decider)"
    info "inventory-claim: cli:node proven-by=process (real image node process + bound socket)"
}

scenario_public-visibility() {
    local n="${PILLAR_IT_NODES:-3}"

    # Declare the inventory entries this scenario claims BEFORE asserting, so
    # the claim is on record even if an oracle fails.
    scenario_public-visibility_claims

    # Ensure the image the scenario drives ACTUALLY serves the visibility-class
    # CLI surface (`public-visibility`). If the published image lags the working
    # tree, this builds a reproducible image-under-test from the flake and
    # repoints $PILLAR_IMAGE at it — the scenario stays black-box.
    image_require_verb public-visibility

    # (1) real >=3-node topology on the real ghcr image.
    topology_boot "$n"

    # Every node must be a real running process with a bound readiness socket —
    # reuse the process oracle as the liveness gate, proving the topology ran
    # the REAL image (not a stubbed host).
    local i
    for i in "${!TOPO_NODES[@]}"; do
        oracle_process "${TOPO_NODES[$i]}" "${TOPO_PROBE_ADDRS[$i]}"
    done

    # (2) THE public-visibility assertion: the real streamdb visibility-class
    # op path + real RBAC decider prove public is a DISTINCT, keyless-readable
    # class (signed + content-addressed) whose unauthorized writes are still
    # refused, and the cell-encrypted default stays sealed. This is the
    # scenario's defining oracle — RED if any invariant is unobserved.
    info "public-visibility: driving the real streamdb visibility-class surface via the public-visibility CLI verb on the real image"
    oracle_public_visibility

    info "public-visibility: real image proved public is a distinct visibility class (keyless-readable cleartext, unauthorized write RBAC-refused, encrypted default intact) across ${#TOPO_NODES[@]} real nodes"
}
