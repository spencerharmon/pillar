#!/usr/bin/env bash
# Model-check every Pillar TLA+ spec. Exit non-zero on any invariant violation.
# Hermetic: no private infrastructure, safe to run in public GitHub Actions.
set -euo pipefail
cd "$(dirname "$0")"

# Locate tla2tools.jar.
JAR="${TLA_TOOLS_JAR:-}"
if [[ -z "$JAR" ]]; then
  if [[ -f "$HOME/.local/lib/tla/tla2tools.jar" ]]; then
    JAR="$HOME/.local/lib/tla/tla2tools.jar"
  else
    mkdir -p .tools
    JAR=".tools/tla2tools.jar"
    if [[ ! -f "$JAR" ]]; then
      echo "fetching tla2tools.jar ..."
      curl -fsSL -o "$JAR" \
        https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
    fi
  fi
fi

# spec name : extra TLC flags
declare -A SPECS=(
  [CoordinationCore]="-deadlock"
  [Registration]="-deadlock"
)

rc=0
for spec in "${!SPECS[@]}"; do
  echo "== TLC: $spec =="
  log="/tmp/tlc-$spec.log"
  # Redirect TLC's own output straight to the log file (rather than piping it
  # live through `grep -q`) so a NUL-byte-free, fully-flushed log always
  # exists before we inspect it. Piping `tee | grep -q` here is a documented
  # footgun under `set -o pipefail`: `grep -q` exits (and closes its stdin)
  # the instant it finds a match, which can raise SIGPIPE in the upstream
  # `tee`/`java` stages; with pipefail that SIGPIPE can outrank grep's own
  # zero exit status, so the pipeline as a whole intermittently reports
  # non-zero *even though TLC succeeded* (verified: the same captured log
  # greps clean every time when inspected as a plain file afterward).
  if java -cp "$JAR" tlc2.TLC ${SPECS[$spec]} -config "$spec.cfg" "$spec.tla" \
       > "$log" 2>&1; then
    tlc_rc=0
  else
    tlc_rc=$?
  fi
  if [[ "$tlc_rc" -eq 0 ]] && grep -qE 'No error has been found' "$log"; then
    echo "   OK"
  else
    echo "   FAILED — invariant violation or model error in $spec"
    tail -30 "$log" || true
    rc=1
  fi
  rm -f "${spec}_TTrace_"*.tla
  rm -rf states
done
exit $rc
