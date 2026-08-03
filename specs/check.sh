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
)

rc=0
for spec in "${!SPECS[@]}"; do
  echo "== TLC: $spec =="
  if java -cp "$JAR" tlc2.TLC ${SPECS[$spec]} -config "$spec.cfg" "$spec.tla" \
       2>&1 | tee "/tmp/tlc-$spec.log" | grep -qE 'No error has been found'; then
    echo "   OK"
  else
    echo "   FAILED — invariant violation or model error in $spec"
    tail -30 "/tmp/tlc-$spec.log" || true
    rc=1
  fi
  rm -f "${spec}_TTrace_"*.tla
  rm -rf states
done
exit $rc
