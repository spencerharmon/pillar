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

# spec name : extra TLC flags. Order is fixed so output is deterministic.
SPECS=(CoordinationCore Registration StreamingDB StreamdbIpfsStore StreamdbPersistence EventDAG IPAM WoTAuthority WebKeyAuth AntiEntropy Bootstrap Observability ObsIngestionSubstrate PSLCore IdentityLogin KeyDistribution Recovery Cells NodeCustodyLogin WebAuthnCustody BootstrapRequest LoginToken NamingAuthorityPlane GlobalIdentity SessionRegistry TrustArtifacts PillarUDP VersioningCompat SchedulerController PillarIntegration)
declare -A FLAGS=(
  [CoordinationCore]="-deadlock"
  [Registration]="-deadlock"
  [StreamingDB]="-deadlock"
  [StreamdbIpfsStore]="-deadlock"
  [StreamdbPersistence]="-deadlock"
  [EventDAG]="-deadlock"
  [IPAM]="-deadlock"
  [WoTAuthority]="-deadlock"
  [WebKeyAuth]="-deadlock"
  [AntiEntropy]="-deadlock"
  [Bootstrap]="-deadlock"
  [Observability]="-deadlock"
  [ObsIngestionSubstrate]="-deadlock"
  [PSLCore]="-deadlock"
  [IdentityLogin]="-deadlock"
  [KeyDistribution]="-deadlock"
  [Recovery]="-deadlock"
  [Cells]="-deadlock"
  [NodeCustodyLogin]="-deadlock"
  [WebAuthnCustody]="-deadlock"
  [BootstrapRequest]="-deadlock"
  [LoginToken]="-deadlock"
  [NamingAuthorityPlane]="-deadlock"
  [GlobalIdentity]="-deadlock"
  [SessionRegistry]="-deadlock"
  [TrustArtifacts]="-deadlock"
  [PillarUDP]="-deadlock"
  [VersioningCompat]=""
  [SchedulerController]="-deadlock"
  [PillarIntegration]="-deadlock"
)

rc=0
for spec in "${SPECS[@]}"; do
  echo "== TLC: $spec =="
  log="/tmp/tlc-$spec.log"
  # Run TLC to a log file first, THEN inspect it. Piping java directly into
  # `grep -q` makes grep close the pipe on first match, java takes SIGPIPE, and
  # under `set -o pipefail` the whole pipeline reports failure even though the
  # model check passed. Decoupling the run from the match avoids that.
  set +e
  java -cp "$JAR" tlc2.TLC ${FLAGS[$spec]} -config "$spec.cfg" "$spec.tla" \
    >"$log" 2>&1
  set -e
  if grep -qE 'No error has been found' "$log"; then
    echo "   OK"
  else
    echo "   FAILED — invariant violation or model error in $spec"
    tail -30 "$log" || true
    rc=1
  fi
  rm -f "${spec}_TTrace_"*.tla "${spec}_TTrace_"*.bin
  rm -rf states
done

# Schema round-trip conformance test (the executable half of the
# pillar-integration rig contract): parse a fixture surface-inventory +
# scenario-declaration document, re-serialise it, assert equality.
echo "== round-trip: schema_roundtrip_test.py =="
if python3 schema_roundtrip_test.py >/tmp/rig-schema-roundtrip.log 2>&1; then
  echo "   OK"
else
  echo "   FAILED — schema round-trip test"
  tail -40 /tmp/rig-schema-roundtrip.log || true
  rc=1
fi

exit $rc
