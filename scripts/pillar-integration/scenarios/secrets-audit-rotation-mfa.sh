#!/usr/bin/env bash
# scenarios/secrets-audit-rotation-mfa.sh — the "pillar-integration" scenario
# family covering secrets/audit/rotation/MFA (operator-directed, 2026-08-31).
#
# Drives the REAL published image's `pillar secrets-audit-rotation-mfa` CLI
# verb (real cross-crate cryptography — never a stub) through the harness's
# CLI driver, exactly as `smoke` drives `pillar onboard` via
# `oracle_crypto_realness`. No multi-node topology is needed: every effect
# under test (the sealed-secret-store escrow, the signed audit-log view, key
# rotation, and step-up-gated MFA recovery) is exercised in-process by the
# real image's own binary, run fresh in a throwaway container.
#
#   RED  if a privileged action is admitted without a real signed audit
#        entry, or without a valid step-up (MFA) token.
#   GREEN when the real image's `pillar secrets-audit-rotation-mfa` reports
#        every one of its four safety invariants held.
scenario_secrets-audit-rotation-mfa() {
    info "secrets-audit-rotation-mfa: driving the real image's sealed-secret-store/audit-log/rotation/MFA CLI verb"
    oracle_secrets_audit_rotation_mfa
    info "secrets-audit-rotation-mfa: every oracle observed a real sealed-secret-store/audit-log/rotation/MFA effect"
}
