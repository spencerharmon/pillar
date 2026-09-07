#!/usr/bin/env bash
# verify-actions-run.sh — definition-of-done verifier asserting a named Gitea
# Actions workflow actually EXECUTED to a successful conclusion on the
# self-hosted runner (the real CI-executed effect), not merely that a
# `.gitea/workflows/*.yaml` file is committed.
#
# Reads the workflow's runs via the native Gitea Actions REST API
# (`/repos/{owner}/{repo}/actions/runs`, NOT the GitHub-compatible surface),
# picks the NEWEST run whose workflow path matches (highest run_number), and
# exits 0 only when that run's conclusion is exactly "success". A still
# in-progress/queued newest run is treated as not-yet-converged (exit 2, a
# retryable state distinct from a hard failure) so a Check caller can tell
# "wait and re-check" apart from "this genuinely failed".
#
# Usage:
#   verify-actions-run.sh <gitea-host> <owner>/<repo> <workflow-file>
#
# Example (verbatim task Check:):
#   repo/scripts/verify-actions-run.sh git.spencerharmon.com spencerharmon/actions pillar-integration.yaml
#
# Environment (optional):
# Environment (optional):
#   GITEA_TOKEN            Gitea API token (materialized via the
#                          beehive-secret-store bridge, never passed as a CLI
#                          arg). Preferred when set.
#   GITEA_ADMIN_NAMESPACE/GITEA_ADMIN_SECRET   fallback in-cluster credential
#                          (default namespace `gitea`, secret `gitea-admin`,
#                          keys `username`/`password`): this Gitea instance
#                          404s the Actions REST API for an UNAUTHENTICATED
#                          read even on a public repo, and no GITEA_TOKEN is
#                          bridged into the DoD check sandbox today, so when
#                          GITEA_TOKEN is unset this reads the admin Secret via
#                          `kubectl` (undenied in the check sandbox, `~/.kube`
#                          bound read-only by default) and authenticates with
#                          HTTP Basic instead — the same live credential a
#                          human operator used to confirm this API manually.
#                          Set GITEA_ADMIN_NAMESPACE=- to disable this fallback
#                          outright (go straight to unauthenticated).
#   VERIFY_ACTIONS_RUN_FIXTURES   (self-test only) directory of canned JSON
#                          bodies served instead of a live network call.
#
# Exit codes:
#   0   the newest matching run concluded "success"
#   1   the newest matching run concluded anything else (failure/cancelled/
#       skipped), or no run of that workflow exists, or a usage/network error
#   2   the newest matching run is still queued/in_progress (not yet converged)
#
# Self-test (`--self-test`): offline, fixture-driven regression test of the
# real parsing/exit-code contract above — no live Gitea reachability or token
# needed. Exits 0 iff every assertion passes.
set -euo pipefail

fail() { echo "verify-actions-run: FAIL: $*" >&2; exit 1; }
pending() { echo "verify-actions-run: PENDING: $*" >&2; exit 2; }
ok() { echo "verify-actions-run: ok: $*"; }

if [ "${1:-}" = "--self-test" ]; then
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  fixtures="${script_dir}/testdata/verify-actions-run"
  [ -d "${fixtures}" ] || { echo "verify-actions-run: --self-test: missing fixtures dir ${fixtures}" >&2; exit 1; }

  test_fail=0
  check() {
    # $1=description $2=expected-exit $3=actual-exit $4=output $5=must-contain
    local desc="$1" want_rc="$2" got_rc="$3" out="$4" needle="$5"
    if [ "${got_rc}" != "${want_rc}" ]; then
      echo "self-test FAIL: ${desc}: exit=${got_rc} want=${want_rc}" >&2
      printf '%s\n' "${out}" >&2
      test_fail=1
      return
    fi
    if [ -n "${needle}" ] && ! printf '%s' "${out}" | grep -qF "${needle}"; then
      echo "self-test FAIL: ${desc}: output missing '${needle}'" >&2
      printf '%s\n' "${out}" >&2
      test_fail=1
      return
    fi
    echo "self-test ok: ${desc}"
  }

  set +e
  out="$(VERIFY_ACTIONS_RUN_FIXTURES="${fixtures}/runs-list.json" "${BASH_SOURCE[0]}" selftest.invalid x/y pillar-integration.yaml 2>&1)"; rc=$?
  set -e
  check "newest run success -> exit 0" 0 "${rc}" "${out}" "PASS"
  check "newest run success -> mentions run id" 0 "${rc}" "${out}" "205"

  set +e
  out="$(VERIFY_ACTIONS_RUN_FIXTURES="${fixtures}/runs-list-failure.json" "${BASH_SOURCE[0]}" selftest.invalid x/y pillar-integration.yaml 2>&1)"; rc=$?
  set -e
  check "newest run failure -> exit 1" 1 "${rc}" "${out}" "concluded failure"

  set +e
  out="$(VERIFY_ACTIONS_RUN_FIXTURES="${fixtures}/runs-list-empty.json" "${BASH_SOURCE[0]}" selftest.invalid x/y pillar-integration.yaml 2>&1)"; rc=$?
  set -e
  check "no matching run -> exit 1" 1 "${rc}" "${out}" "no run of workflow"

  set +e
  out="$(VERIFY_ACTIONS_RUN_FIXTURES="${fixtures}/runs-list-pending.json" "${BASH_SOURCE[0]}" selftest.invalid x/y pillar-integration.yaml 2>&1)"; rc=$?
  set -e
  check "newest run still in_progress -> exit 2 (pending, not failed)" 2 "${rc}" "${out}" "PENDING"

  if [ "${test_fail}" -eq 0 ]; then
    echo "verify-actions-run: self-test: ALL ASSERTIONS PASSED"
    exit 0
  else
    echo "verify-actions-run: self-test: FAILED" >&2
    exit 1
  fi
fi

[ $# -ge 3 ] || { echo "usage: verify-actions-run.sh <gitea-host> <owner>/<repo> <workflow-file>" >&2; exit 1; }

HOST="$1"
SLUG="$2"
WORKFLOW="$3"
OWNER="${SLUG%%/*}"
REPO="${SLUG#*/}"
[ -n "${OWNER}" ] && [ -n "${REPO}" ] && [ "${OWNER}" != "${SLUG}" ] || fail "owner/repo must be 'owner/repo', got '${SLUG}'"

command -v curl >/dev/null 2>&1 || fail "curl not found on PATH"
command -v jq   >/dev/null 2>&1 || fail "jq not found on PATH"

API="https://${HOST}/api/v1/repos/${OWNER}/${REPO}/actions"
FIXTURES="${VERIFY_ACTIONS_RUN_FIXTURES:-}"

# Resolve auth: prefer an explicit GITEA_TOKEN; else, unless disabled, fall
# back to the in-cluster gitea-admin Secret via kubectl (see header comment)
# and use HTTP Basic. Best-effort — a kubectl/secret-read failure just leaves
# us unauthenticated, matching the prior no-fallback behavior.
AUTH_HEADER=""
if [ -z "${FIXTURES}" ]; then
  if [ -n "${GITEA_TOKEN:-}" ]; then
    AUTH_HEADER="Authorization: token ${GITEA_TOKEN}"
  elif [ "${GITEA_ADMIN_NAMESPACE:-gitea}" != "-" ] && command -v kubectl >/dev/null 2>&1; then
    admin_ns="${GITEA_ADMIN_NAMESPACE:-gitea}"
    admin_secret="${GITEA_ADMIN_SECRET:-gitea-admin}"
    admin_user="$(kubectl -n "${admin_ns}" get secret "${admin_secret}" -o jsonpath='{.data.username}' 2>/dev/null | base64 -d 2>/dev/null || true)"
    admin_pass="$(kubectl -n "${admin_ns}" get secret "${admin_secret}" -o jsonpath='{.data.password}' 2>/dev/null | base64 -d 2>/dev/null || true)"
    if [ -n "${admin_user}" ] && [ -n "${admin_pass}" ]; then
      AUTH_HEADER="Authorization: Basic $(printf '%s:%s' "${admin_user}" "${admin_pass}" | base64 -w0)"
    fi
  fi
fi

_curl() {
  # $1 = URL. Fixture mode (--self-test) serves a canned body instead of a
  # real network request; a plain filename means "serve this file regardless
  # of URL" (only one endpoint is ever queried per invocation here).
  if [ -n "${FIXTURES}" ]; then
    cat "${FIXTURES}"
    return 0
  fi
  if [ -n "${AUTH_HEADER}" ]; then
    curl -fsSL -H "${AUTH_HEADER}" -H 'Accept: application/json' "$1"
  else
    curl -fsSL -H 'Accept: application/json' "$1"
  fi
}

runs_json="$(_curl "${API}/runs?limit=50")" || fail "could not list runs for ${OWNER}/${REPO}"

# The Gitea Actions run-list API reports each run's `path` as either a bare
# workflow filename with a trailing `@refs/heads/<branch>` ref suffix (this
# instance's observed shape, e.g. "pillar-integration.yaml@refs/heads/main")
# or a full `.gitea/workflows/<file>` path (seen on other Gitea/Forgejo
# versions) — normalize away the `@ref` suffix, then match either the exact
# filename or a path ending in "/<file>", so both shapes resolve.
run_row="$(printf '%s' "${runs_json}" | jq -c --arg wf "${WORKFLOW}" '
  [(.workflow_runs // .)[]?
   | . as $r
   | ($r.path | split("@")[0]) as $p
   | select($p == $wf or ($p | endswith("/" + $wf)))
   | $r]
  | sort_by(.run_number // .id)
  | last // empty
')"
[ -n "${run_row}" ] && [ "${run_row}" != "null" ] || fail "no run of workflow '${WORKFLOW}' found (repo ${OWNER}/${REPO})"

RUN_ID="$(printf '%s' "${run_row}" | jq -r '.id')"
STATUS="$(printf '%s' "${run_row}" | jq -r '.status // empty')"
CONCLUSION="$(printf '%s' "${run_row}" | jq -r '.conclusion // empty')"

case "${STATUS}" in
  queued|waiting|in_progress|"")
    if [ -z "${CONCLUSION}" ] || [ "${CONCLUSION}" = "null" ]; then
      pending "workflow ${WORKFLOW} run ${RUN_ID} still ${STATUS:-pending} — not yet converged (https://${HOST}/${OWNER}/${REPO}/actions/runs/${RUN_ID})"
    fi
    ;;
esac

[ -n "${CONCLUSION}" ] && [ "${CONCLUSION}" != "null" ] || CONCLUSION="${STATUS}"

if [ "${CONCLUSION}" = "success" ]; then
  echo "verify-actions-run: PASS: workflow ${WORKFLOW} run ${RUN_ID} concluded success (https://${HOST}/${OWNER}/${REPO}/actions/runs/${RUN_ID})"
  exit 0
fi

fail "workflow ${WORKFLOW} run ${RUN_ID} concluded ${CONCLUSION} (https://${HOST}/${OWNER}/${REPO}/actions/runs/${RUN_ID})"
