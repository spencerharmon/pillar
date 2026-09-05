#!/usr/bin/env bash
# verify-actions-run-test.sh — regression test for scripts/verify-actions-run.sh.
#
# Proves the Gitea-Actions-run verifier makes the RIGHT success/failure
# decision, without needing the real Gitea host. It stands up a tiny local HTTP
# server that speaks the Gitea `/api/v1/repos/{owner}/{repo}/actions/tasks`
# surface with a scripted response, points verify-actions-run.sh at it, and
# asserts its exit code for each case:
#
#   1. a matching run with conclusion=success        -> exit 0
#   2. a matching run with conclusion=failure        -> non-zero
#   3. no run for the requested workflow/ref         -> non-zero
#
# This is the RED-then-GREEN regression: run against the tree BEFORE
# verify-actions-run.sh existed the script is absent and every case errors out;
# WITH the script the success case passes and the failure/absent cases fail, as
# asserted below. Uses only python3 (stdlib http.server) + curl/jq, all present
# in the harness image.
#
# Exit 0 = every case behaved as expected. Exit !0 = the first mismatch, printed.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/verify-actions-run.sh"

fail() { echo "FAIL: $1" >&2; exit 1; }
info() { echo "INFO: $1"; }

[ -x "$SCRIPT" ] || fail "verify-actions-run.sh missing or not executable at $SCRIPT"
command -v python3 >/dev/null 2>&1 || fail "python3 required for the mock server"
command -v curl >/dev/null 2>&1 || fail "curl required"
command -v jq >/dev/null 2>&1 || fail "jq required"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/verify-actions-run-test.XXXXXX")"
SERVER_PID=""
cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" >/dev/null 2>&1
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# The mock server reads $WORKDIR/response.json and serves it for any GET under
# /api/v1/... — so a test case just writes the JSON body it wants Gitea to
# return, then invokes the script.
cat > "$WORKDIR/server.py" <<'PY'
import http.server, os, sys
BODY_FILE = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            with open(BODY_FILE, "rb") as f:
                body = f.read()
        except OSError:
            body = b"[]"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):  # quiet
        pass
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
port = srv.server_address[1]
with open(BODY_FILE + ".port", "w") as f:
    f.write(str(port))
srv.serve_forever()
PY

# The script hard-codes https:// and port 443 is unavailable to a test, so we
# run the mock over plain HTTP and rewrite the base URL by overriding curl via a
# shim on PATH that maps https://HOST/... to http://127.0.0.1:PORT/...
: > "$WORKDIR/response.json"
python3 "$WORKDIR/server.py" "$WORKDIR/response.json" &
SERVER_PID=$!
for _ in $(seq 1 50); do [ -f "$WORKDIR/response.json.port" ] && break; sleep 0.1; done
PORT="$(cat "$WORKDIR/response.json.port")"
[ -n "$PORT" ] || fail "mock server did not report a port"

mkdir -p "$WORKDIR/bin"
cat > "$WORKDIR/bin/curl" <<EOF
#!/usr/bin/env bash
# Rewrite the script's https://<host>/... target to the local mock, preserving
# every other curl arg so the real client behaviour (flags, exit codes) is used.
args=()
for a in "\$@"; do
  case "\$a" in
    https://*) args+=( "http://127.0.0.1:${PORT}/\${a#https://*/}" ) ;;
    *) args+=( "\$a" ) ;;
  esac
done
exec /usr/bin/curl "\${args[@]}"
EOF
chmod +x "$WORKDIR/bin/curl"
[ -x /usr/bin/curl ] || fail "expected /usr/bin/curl for the shim to delegate to"

run_case() {
    local desc="$1" body="$2" want="$3"
    printf '%s' "$body" > "$WORKDIR/response.json"
    local rc=0
    PATH="$WORKDIR/bin:$PATH" "$SCRIPT" example.com example/pillar pillar-integration.yml main >/dev/null 2>&1 || rc=$?
    if [ "$want" = "success" ]; then
        [ "$rc" -eq 0 ] || fail "$desc: expected exit 0, got $rc"
    else
        [ "$rc" -ne 0 ] || fail "$desc: expected non-zero exit, got 0"
    fi
    info "$desc: exit=$rc (as expected)"
}

# Case 1: a matching run that SUCCEEDED -> exit 0.
run_case "matching run success" \
  '{"workflow_runs":[{"name":"pillar-integration.yml","head_branch":"main","status":"success","conclusion":"success"}]}' \
  success

# Case 2: a matching run that FAILED -> non-zero.
run_case "matching run failed" \
  '{"workflow_runs":[{"name":"pillar-integration.yml","head_branch":"main","status":"failure","conclusion":"failure"}]}' \
  failure

# Case 3: only an unrelated workflow / ref -> non-zero (no matching run).
run_case "no matching run" \
  '{"workflow_runs":[{"name":"ci.yml","head_branch":"main","status":"success","conclusion":"success"}]}' \
  failure

echo "PASS: verify-actions-run.sh made the correct decision in every case"
