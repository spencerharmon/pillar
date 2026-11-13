#!/bin/bash
# Runs INSIDE the assembled pillar OCI image (podman, see migration-image.nix).
# Uses ONLY the image's own tools: pillar, bash, GNU tar, coreutils, jq.
# Builds an isolated real legacy cell, takes a verified whole-tree backup,
# converts it (crash + resume), and writes /work/result.json.
set -euo pipefail

W=/work
D=$W/cell
B=$W/backup
R=$W/restore
PW='image migration check unlock factor'
WEB=18742
UDP=18744
export HOME=$W/home
mkdir -p "$HOME" "$B" "$R"

# --- tools ------------------------------------------------------------------
for t in pillar bash tar sha256sum du df jq timeout; do
  command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 1; }
done
tarv=$(tar --version)
[[ $tarv == *"GNU tar"* ]] || { echo "tar is not GNU tar: $tarv" >&2; exit 1; }
[[ $(printf abc | sha256sum) == ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad* ]]
[[ $(jq -n -c '{a:(1+1)}') == '{"a":2}' ]]

# A plain array (not a shell function) so `env ... &` is ONE process: a
# backgrounded function would fork a subshell and `kill $!` would orphan the
# real node, which keeps holding the data-dir lock.
NODE_ENV=(PILLAR_DATA_DIR="$D" PILLAR_IDENTITY_KEY="$D/identity.key"
  PILLAR_LISTEN=/ip4/127.0.0.1/tcp/0
  PILLAR_WEB_BIND=127.0.0.1 PILLAR_WEB_PORT=$WEB
  PILLAR_HEALTH_BIND=127.0.0.1 PILLAR_HEALTH_PORT=0
  PILLAR_RESOURCE_OP_UDP_BIND=127.0.0.1:$UDP
  PILLAR_PUBLIC_RESOURCE_OP_ADDR=127.0.0.1:$UDP RUST_LOG=error)

start_node() {
  env "${NODE_ENV[@]}" pillar node run >"$W/node.log" 2>&1 &
  NODE=$!
  for _ in $(seq 1 300); do
    kill -0 "$NODE" 2>/dev/null || { cat "$W/node.log" >&2; echo "node exited" >&2; exit 1; }
    if (exec 3<>"/dev/tcp/127.0.0.1/$WEB") 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  echo "node readiness timed out" >&2; exit 1
}

stop_node() { kill -KILL "$NODE"; wait "$NODE" || true; }

login() {
  local out line
  out=$(pillar login --domain 127.0.0.1:$WEB --user alice --password "$PW")
  while IFS= read -r line; do
    [[ $line == "export PILLAR_TOKEN="* ]] && { printf '%s' "${line#export PILLAR_TOKEN=}"; return 0; }
  done <<<"$out"
  echo "login exported no token: $out" >&2; return 1
}

field() { # field <key> <text>
  local line
  while IFS= read -r line; do
    [[ $line == "$1"* ]] && { printf '%s' "${line#"$1"}" | tr -d ' '; return 0; }
  done <<<"$2"
  echo "$1 missing" >&2; return 1
}

# --- isolated real legacy cell ---------------------------------------------
# A pre-existing streamdb/ without cell-credentials.json selects the legacy
# (device-derived) cell credentials exactly as an upgraded legacy node does.
mkdir -p "$D/streamdb"
start_node
pillar bootstrap cell neutral-cell --user alice --password "$PW" --domain 127.0.0.1:$WEB
TOKEN=$(login)
pillar config export --domain 127.0.0.1:$WEB --token "$TOKEN" --out "$W/legacy.yaml"
cat >"$W/rp.yaml" <<'EOF'
apiVersion: pillar.dev/v1
kind: RetentionPolicy
metadata:
  name: legacy-retained
spec:
  signalKind: Metric
  window: 2592000
EOF
PILLAR_CONFIG=$W/legacy.yaml pillar apply -f "$W/rp.yaml"
stop_node
[[ ! -e $D/cell-credentials.json ]]

plan=$(pillar node migrate-legacy-cell --data-dir "$D" --plan)
[[ $plan == *"LEGACY CELL"* && $plan == *CONTRACT* ]] || { echo "$plan" >&2; exit 1; }
ops=$(field "ops:" "$plan")
root=$(field "root:" "$plan")
(( ops > 2 ))

# --- verified whole-tree backup --------------------------------------------
df -P "$D" "$B" >"$W/df.txt"
need_kb=$(du -sk "$D" | cut -f1)
avail_kb=$(tail -n1 "$W/df.txt" | tr -s ' ' | cut -d' ' -f4)
(( avail_kb > 2 * need_kb ))
shopt -s globstar dotglob nullglob
(cd "$D" && for f in **; do if [[ -f $f ]]; then sha256sum "$f"; fi; done) >"$B/files.sha256"
tar --one-file-system --numeric-owner -C "$D" -cpf "$B/cell.tar" .
(cd "$B" && sha256sum cell.tar >cell.tar.sha256 && sha256sum -c cell.tar.sha256)
tar -C "$R" -xpf "$B/cell.tar"
(cd "$R" && sha256sum --quiet -c "$B/files.sha256")
files=$(wc -l <"$B/files.sha256")
(( files > 0 ))

# --- acknowledged conversion: refusal, crash, refused boot, resume -----------
if pillar node migrate-legacy-cell --data-dir "$D" --apply 2>/dev/null; then
  echo "apply without acknowledgement succeeded" >&2; exit 1
fi
[[ ! -e $D/legacy-cell-migration.json ]]
if PILLAR_LEGACY_MIGRATION_CRASH_AT=partial \
   pillar node migrate-legacy-cell --data-dir "$D" --apply --acknowledge-cell-id-change; then
  echo "injected crash did not abort" >&2; exit 1
fi
crash_state=$(jq -r .state "$D/legacy-cell-migration.json")
[[ $crash_state == staged ]]
if refused=$(env "${NODE_ENV[@]}" timeout 30 pillar node run 2>&1); then
  echo "node booted an incomplete migration" >&2; exit 1
fi
[[ $refused == *"legacy cell migration is incomplete"* ]] || { echo "$refused" >&2; exit 1; }
converted=$(pillar node migrate-legacy-cell --data-dir "$D" --apply --acknowledge-cell-id-change)
[[ $converted == *"CONVERTED $ops ops (root $root)"* ]] || { echo "$converted" >&2; exit 1; }
again=$(pillar node migrate-legacy-cell --data-dir "$D" --apply --acknowledge-cell-id-change)
[[ $again == *"ALREADY CONVERTED"* ]]
m=$D/legacy-cell-migration.json
[[ $(jq -r .state "$m") == committed ]]
[[ $(jq -r .legacy_ops "$m") == "$ops" ]]
[[ $(jq -r .legacy_root "$m") == "$root" ]]
# Legacy stream untouched (rollback source).
(cd "$D" && sha256sum --quiet -c <(jq -rR 'select(test("  streamdb/"))' "$B/files.sha256"))

# Converted node boots, the retained admin logs in, and the legacy resource is
# served under the new cell credentials (fresh export).
start_node
TOKEN=$(login)
pillar config export --domain 127.0.0.1:$WEB --token "$TOKEN" --out "$W/converted.yaml"
got=$(PILLAR_CONFIG=$W/converted.yaml pillar get RetentionPolicy legacy-retained)
[[ $got == *"name: legacy-retained"* && $got == *"window: 2592000"* ]] || { echo "$got" >&2; exit 1; }
stop_node

jq -n --arg ops "$ops" --arg root "$root" --arg crash "$crash_state" \
  --arg tar "$(tar --version | head -n1)" --arg files "$files" \
  --arg sha "$(cut -d' ' -f1 "$B/cell.tar.sha256")" \
  --arg newcell "$(jq -r .new_cell_id "$m")" \
  '{ops:($ops|tonumber), root:$root, crash_state:$crash, state:"committed",
    tar:$tar, backup_files:($files|tonumber), backup_sha256:$sha, new_cell_id:$newcell}' \
  >"$W/result.json"
cat "$W/result.json"
