#!/usr/bin/env bash
# verify-actions-run.sh — assert a named Gitea Actions workflow's latest run
# against a given ref actually completed SUCCESSFULLY.
#
# This asserts the REAL CI-executed effect of the pillar-integration workflow
# (`.gitea/workflows/pillar-integration.yml`) — a dispatched run that booted the
# black-box integration harness and finished green — not merely that a workflow
# YAML file was committed. It queries the Gitea Actions HTTP API with curl+jq
# (neither denied by the check sandbox; skopeo/gh are not needed), so it runs
# wherever curl and jq are present.
#
# The API surface used is Gitea's list-workflow-runs endpoint:
#   GET /api/v1/repos/{owner}/{repo}/actions/tasks
# (the `tasks` endpoint enumerates action runs with their workflow filename,
# head branch, and conclusion). The newest matching run for the requested
# workflow file + ref decides the exit code.
#
# Usage: verify-actions-run.sh [HOST] [OWNER/REPO] [WORKFLOW_FILE] [REF]
#   HOST           Gitea host (no scheme).            default: example.com
#   OWNER/REPO     repository slug.                   default: example/pillar
#   WORKFLOW_FILE  workflow filename under .gitea/.   default: pillar-integration.yml
#   REF            branch/ref the run targeted.       default: main
#
# Auth: if $GITEA_TOKEN (or $GITEA_API_TOKEN) is set it is sent as an
# `Authorization: token <t>` header, so private repos and higher rate limits
# work; public repos need no token.
#
# Exit 0  = the newest run for (WORKFLOW_FILE, REF) has conclusion `success`.
# Exit !0 = no such run, the run is still running/queued, or it failed — with a
#           diagnostic naming what was found.
set -euo pipefail

HOST="${1:-example.com}"
SLUG="${2:-example/pillar}"
WORKFLOW="${3:-pillar-integration.yml}"
REF="${4:-main}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "FAIL: required tool '$1' not found" >&2; exit 3; }; }
need curl
need jq

OWNER="${SLUG%%/*}"
REPO="${SLUG##*/}"
if [[ -z "$OWNER" || -z "$REPO" || "$OWNER" == "$SLUG" ]]; then
  echo "FAIL: OWNER/REPO must be 'owner/repo' (got '$SLUG')" >&2
  exit 3
fi

REF_SHORT="${REF#refs/heads/}"
REF_SHORT="${REF_SHORT#refs/tags/}"

base="https://${HOST}/api/v1/repos/${OWNER}/${REPO}"

hdrs=(-H 'Accept: application/json')
tok="${GITEA_TOKEN:-${GITEA_API_TOKEN:-}}"
[[ -n "$tok" ]] && hdrs+=(-H "Authorization: token ${tok}")

body="$(mktemp)"
trap 'rm -f "$body"' EXIT

# Gitea exposes action runs under .../actions/tasks (paginated, newest first).
code=$(curl -fsSL -o "$body" -w '%{http_code}' "${hdrs[@]}" \
  "${base}/actions/tasks?page=1&limit=50" 2>/dev/null || echo "000")

if [[ "$code" != "200" ]]; then
  echo "FAIL: ${base}/actions/tasks returned HTTP ${code}" >&2
  head -c 400 "$body" >&2 || true
  exit 1
fi

# Normalise: Gitea returns either {"workflow_runs":[...]} or {"tasks":[...]}
# depending on version; accept either and also a bare array.
runs_json=$(jq -c '(.workflow_runs // .tasks // .) // []' "$body" 2>/dev/null || echo '[]')

# Select runs whose workflow filename matches WORKFLOW and head ref matches REF,
# newest first (the API already returns newest-first; we keep that order).
# Field names differ across Gitea versions, so match defensively on any of the
# plausible workflow-name / head-branch keys.
match=$(jq -c --arg wf "$WORKFLOW" --arg ref "$REF_SHORT" '
  [ .[]
    | . as $r
    | ( ($r.workflow_id // $r.workflow // $r.name // "") | tostring ) as $wfname
    | ( ($r.head_branch // $r.ref // $r.branch // "") | tostring ) as $branch
    | ( ($r.status // "") | tostring ) as $status
    | ( ($r.conclusion // $r.result // "") | tostring ) as $concl
    | select(
        ($wfname | endswith($wf)) or ($wfname == $wf)
      )
    | select(
        ($branch == $ref) or ($branch | endswith("/" + $ref))
        or ($ref == "")
      )
    | { wfname: $wfname, branch: $branch, status: $status, conclusion: $concl }
  ]' <<<"$runs_json" 2>/dev/null || echo '[]')

count=$(jq 'length' <<<"$match" 2>/dev/null || echo 0)
if [[ "$count" -eq 0 ]]; then
  echo "FAIL: no Gitea Actions run found for workflow '${WORKFLOW}' on ref '${REF_SHORT}' at ${HOST}/${OWNER}/${REPO}" >&2
  echo "      (queried ${base}/actions/tasks; ${count} matching run(s))" >&2
  exit 1
fi

newest=$(jq -c '.[0]' <<<"$match")
status=$(jq -r '.status' <<<"$newest")
concl=$(jq -r '.conclusion' <<<"$newest")

# Gitea uses `success`/`failure`/... in either `.conclusion` or, for older
# versions, a terminal `.status` of `success`. Treat either as authoritative.
if [[ "$concl" == "success" || "$status" == "success" ]]; then
  echo "OK: ${WORKFLOW} on ${REF_SHORT} — latest run succeeded (status=${status} conclusion=${concl})"
  exit 0
fi

echo "FAIL: latest ${WORKFLOW} run on ${REF_SHORT} did not succeed (status=${status} conclusion=${concl})" >&2
exit 2
