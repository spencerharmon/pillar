#!/usr/bin/env bash
# scenarios/trust-rbac.sh — the trust/WoT/RBAC scenario family.
#
# ROI "pillar-integration" trust/WoT/RBAC family: on the real black-box
# harness, exercise the certify -> trust -> attest -> revoke pipeline over the
# REAL WoT-authority + RBAC-decider surfaces, and assert an UNAUTHORIZED
# manifest `apply` IS rejected — a real 403/denial from the real decider, never
# a mocked check.
#
#   1. boot a real >=3-node topology on the real ghcr image;
#   2. drive the real image's `apply-authz` CLI verb (the trust/RBAC surface):
#      it runs the real certify/trust/attest/revoke trust-artifact pipeline,
#      projects the live grants into the SINGLE real RbacDecider over the real
#      WotAuthority, and decides real `apply` requests — the apply-authz oracle
#      asserts the UNGRANTED stranger's apply is DENIED with a real fail-closed
#      403 (and a revoked grant flips the operator's apply to denied);
#   3. a process oracle on every node confirms the real image nodes are real
#      running OS processes with real bound listening sockets;
#   4. tear the topology down; a leak-detector pass confirms zero residue.
#
# RED if an unauthorized apply is silently admitted (the apply-authz oracle
# fails, exiting non-zero); GREEN when it is rejected. It is black-box: it
# drives ONLY the real image's external CLI surface and observes only its
# transcript — it never links a pillar crate. Sourced by run-scenario.sh, which
# has already sourced the lib layer and run fixtures_init.
#
# Inventory claims (surface-inventory-emitter entries this scenario exercises):
#   - cli:apply-authz  (the real trust/RBAC authorization decision CLI verb)
#   - cli:node         (the real image node the topology boots)
# proven by the `apply_authz` and `process` oracles respectively.

# scenario_trust-rbac_claims : declare the surface-inventory entries this
# scenario CLAIMS (the PillarIntegration.tla ClaimsTargetRealSurface relation),
# printed as greppable `inventory-claim:` lines so the conformance rig / a
# reviewer can confirm every claim targets a real inventory entry and is proven
# by a named real oracle.
scenario_trust-rbac_claims() {
    info "inventory-claim: cli:apply-authz proven-by=apply_authz (real WoT/RBAC decider denies unauthorized apply)"
    info "inventory-claim: cli:node proven-by=process (real image node process + bound socket)"
}

scenario_trust-rbac() {
    local n="${PILLAR_IT_NODES:-3}"

    # Declare the inventory entries this scenario claims BEFORE asserting, so
    # the claim is on record even if an oracle fails.
    scenario_trust-rbac_claims

    # Ensure the image the scenario drives ACTUALLY serves the trust/RBAC
    # authorization CLI surface (`apply-authz`). If the published image lags
    # the working tree, this builds a reproducible image-under-test from the
    # flake and repoints $PILLAR_IMAGE at it — the scenario stays black-box.
    image_require_verb apply-authz

    # (1) real >=3-node topology on the real ghcr image.
    topology_boot "$n"

    # (2) THE trust/RBAC assertion: an unauthorized `apply` is rejected by the
    # real decider with a real 403 (and a revoked grant is denied too). This is
    # the scenario's defining oracle — RED if an unauthorized apply is admitted.
    info "trust-rbac: driving the real trust/WoT/RBAC surfaces via the apply-authz CLI verb"
    oracle_apply_authz

    # (3) process oracle on every node: a real pid + a real listening socket,
    # confirming the topology ran the real image (not a stubbed decision host).
    local i
    for i in "${!TOPO_NODES[@]}"; do
        oracle_process "${TOPO_NODES[$i]}" "${TOPO_PROBE_ADDRS[$i]}"
    done

    info "trust-rbac: real decider rejected the unauthorized apply on ${#TOPO_NODES[@]} real nodes"
}
