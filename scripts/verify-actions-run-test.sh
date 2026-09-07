#!/usr/bin/env bash
# verify-actions-run-test.sh — regression test for scripts/verify-actions-run.sh.
#
# Proves the Gitea-Actions-run verifier makes the RIGHT success/failure/pending
# decision, without needing the real Gitea host or a token. It drives the
# script's built-in, fixture-based `--self-test` mode, which feeds canned JSON
# bodies (scripts/testdata/verify-actions-run/*.json) — the exact shape of the
# native Gitea Actions run-list API `/api/v1/repos/{owner}/{repo}/actions/runs`
# (NOT the retired `/actions/tasks` GitHub-compat surface) — through the same
# parse/exit-code contract used against the live host:
#
#   1. a matching run with conclusion=success        -> exit 0
#   2. a matching run with conclusion=failure        -> non-zero (1)
#   3. no run for the requested workflow             -> non-zero (1)
#   4. a matching run still in_progress/queued        -> exit 2 (pending)
#
# This is the RED-then-GREEN regression: run against the tree BEFORE the
# auth-aware `/actions/runs` verifier existed the script errored on the wrong
# endpoint (HTTP 404, unauthenticated); WITH the current script every case
# decides correctly, as its self-test asserts. Uses only bash + jq, present in
# the harness image; no network, no token.
#
# Exit 0 = every case behaved as expected. Exit !0 = the first mismatch, printed.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/verify-actions-run.sh"

fail() { echo "FAIL: $1" >&2; exit 1; }

[ -x "$SCRIPT" ] || fail "verify-actions-run.sh missing or not executable at $SCRIPT"
command -v jq >/dev/null 2>&1 || fail "jq required"
[ -d "$HERE/testdata/verify-actions-run" ] || fail "missing fixtures dir $HERE/testdata/verify-actions-run"

# Delegate to the script's own fixture-driven self-test, which exercises the
# real parsing/exit-code contract against every case above and exits 0 iff all
# assertions pass.
if "$SCRIPT" --self-test; then
    echo "PASS: verify-actions-run.sh made the correct decision in every case"
    exit 0
fi
fail "verify-actions-run.sh --self-test reported a mismatch"
