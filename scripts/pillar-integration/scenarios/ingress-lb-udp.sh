#!/usr/bin/env bash
# scenarios/ingress-lb-udp.sh — ROI "pillar-integration" scenario family:
# ingress / LB / pillar-UDP (operator-directed, 2026-08-31).
#
# The packet oracle observes the WIRE. This scenario stands the REAL
# `pillar ingress-lb-udp serve` external surface up from the published image
# (the wired `pillar_net::UdpDataplane` on the real binary) in front of real
# UDP echo backends, drives real client datagrams at the bound VIP, and
# ATTRIBUTES each reply to the concrete backend that served it — proving, on
# the wire and never by a return code:
#
#   1. LB ALGORITHM DISTRIBUTION — for EVERY algorithm (RoundRobin, LeastConn,
#      ConsistentHash) real client datagrams are distributed across >=3 DISTINCT
#      backends, matching the declared algorithm's shape (source attribution
#      across every declared backend) — `oracle_packet_lb_distribution`.
#   2. SESSION AFFINITY — with `affinity sticky`, one stable client is PINNED to
#      a single backend while independent clients still spread across the pool
#      — `oracle_packet_lb_affinity`.
#   3. ACTIVE-HEALTH FAILOVER — killing one real backend makes the real active
#      health probe remove it, and every subsequent reply comes from a
#      surviving backend (traffic fails over on the wire) —
#      `oracle_packet_lb_failover`.
#   4. pillar-UDP FORCING FUNCTIONS — the ROI's transport-internal demands that
#      are unobservable from a single VIP's echo replies (exactly-once under
#      duplication, TTL-bounded forwarding under loops, anti-amplification under
#      spoofed sources, erasure-coded bulk surviving K-of-N loss, congestion
#      posture on a lossy multipath link, per-link transport selection flipping
#      under bad shaping) — each proven by a REAL compiled pillar-net
#      acceptance/regression suite — `oracle_pillar_udp_forcing_functions`.
#
# RED when distribution / failover / affinity is unobserved on the wire, or a
# forcing-function suite fails; GREEN when the packet oracle confirms every
# effect under the impairment matrix. Teardown reaps the real host echo
# backends (host-pids) and the serve container, leaving zero residue.
#
# Sourced by run-scenario.sh, which has already sourced the lib layer and run
# fixtures_init. It observes pillar SOLELY through its external surfaces (the
# CLI `ingress-lb-udp serve` verb, real bound UDP sockets, and — for the
# transport-internal invariants — the real compiled acceptance suites); it
# never links a pillar crate.

# The number of real backends. >=4 so that after a failover kill there are still
# >=2 survivors AND >=3 distinct backends for the distribution floor.
INGRESS_LB_UDP_BACKENDS="${INGRESS_LB_UDP_BACKENDS:-4}"

scenario_ingress-lb-udp() {
    # fixtures_init's idempotent pre-clean removes FIXTURE_ROOT; re-create it so
    # this scenario can stage its manifests + host-pids ledger there.
    mkdir -p "$FIXTURE_ROOT"

    # The published image must serve the `ingress-lb-udp` CLI verb; if it lags
    # the working tree, build a reproducible image-under-test from flake.nix.
    image_require_verb ingress-lb-udp

    # Spawn the real host UDP echo backends (recorded in host-pids, reaped by
    # fixtures_teardown). Each echoes "<id>:<payload>" so the oracle can
    # attribute a reply to the backend that served it, and echoes the health
    # probe verbatim so an active-health backend stays healthy.
    local n="$INGRESS_LB_UDP_BACKENDS"
    [ "$n" -ge 4 ] || fail "ingress-lb-udp: needs >=4 real backends for the distribution+failover matrix (got $n)"
    info "ingress-lb-udp: spawning $n real UDP echo backends"

    local i line id addr pid
    local backends_csv="" first_id="" first_pid=""
    for i in $(seq 1 "$n"); do
        id="b${i}"
        line=$(_packet_echo_backend "$id")     # "<id> <ip:port> <pid>"
        addr=$(printf '%s' "$line" | awk '{print $2}')
        pid=$(printf '%s' "$line" | awk '{print $3}')
        [ -n "$addr" ] && [ -n "$pid" ] || fail "ingress-lb-udp: echo backend $id did not report addr+pid: '$line'"
        info "ingress-lb-udp: backend $id at $addr (pid $pid)"
        if [ -z "$backends_csv" ]; then
            backends_csv="${id}=${addr}"
            first_id="$id"; first_pid="$pid"
        else
            backends_csv="${backends_csv},${id}=${addr}"
        fi
    done

    # (1) Distribution for EVERY LB algorithm — source attribution across every
    # declared backend on the wire.
    local algo
    for algo in round-robin least-conn consistent-hash; do
        oracle_packet_lb_distribution "$algo" "$backends_csv"
    done

    # (2) Sticky session affinity — one client pinned, independent clients
    # spread.
    oracle_packet_lb_affinity "$backends_csv"

    # (3) Active-health failover — kill the FIRST backend (its real host pid)
    # and prove traffic fails over to the survivors on the wire. Do this LAST
    # among the wire oracles so the killed backend does not perturb the
    # distribution/affinity/amplification runs above.
    oracle_packet_lb_failover "$first_pid" "$first_id" "$backends_csv"

    # (4) pillar-UDP forcing functions — the transport-internal invariants
    # proven by the real compiled pillar-net acceptance/regression suites.
    oracle_pillar_udp_forcing_functions

    info "ingress-lb-udp: every LB algorithm distributed across >=3 backends, sticky affinity pinned a client, active-health failover was observed on the wire, and every pillar-UDP forcing function (exactly-once, TTL-bounded forwarding, anti-amplification, erasure-coded K-of-N, congestion posture, transport selection) was proven by a real compiled suite"
}
