# Enroll a Real Node Into a Cell

`pillar bootstrap node` proves possession of the joining daemon's existing
`identity.key`. The first-user administrator approves that request on the issuing node.
The joining CLI then retrieves a recipient-sealed bundle and installs
`enrollment.sealed` in its own data directory. On restart the daemon loads the
cell credentials and replays the bundled portal snapshot, including CLI signer
admissions present **at approval time**.

This is not a peer-ID registration shortcut. Do not copy another daemon's
identity, invent a peer ID, reconstruct credentials from names, or manually admit
resource signers. Fresh daemons generate their own identities and random cell
credentials; the enrollment flow supplies the approved cell material.

Pre-enrollment releases derived solo cell credentials from device identity.
Those existing streams remain readable on upgrade, but approval refuses to
distribute that legacy material because it includes device-private bytes. This
procedure requires a cell initialized by an enrollment-capable release. Migration
of an existing legacy cell is not implemented; do not delete its storage to bypass
the refusal. The sealed bundle is an approval-time snapshot, not continuous
replication or a key-rotation/revocation protocol.

## Transport and Trust

The bootstrap, login, and config-export CLI HTTP client does **not** implement
TLS. Use loopback on the issuer or an authenticated SSH local forward to its
loopback HTTP listener. Do not send passwords, bearer tokens, exported configs,
or enrollment exchanges over untrusted plaintext HTTP. An HTTPS ingress does
not make this client TLS-capable; `bootstrap node` rejects `https://` endpoints.
The sealed response protects recipient confidentiality, but does not by itself
authenticate the issuer. Verify SSH host keys through your trusted provisioning
channel; never disable host-key checking.

The exported CLI config contains a cell seed and a scoped signing secret. Keep it
mode `0600`, outside source control and the Nix store. Approval needs a current
authorized `PILLAR_TOKEN`; resource `apply`/`get` instead use the exported signing
credential over pillar-UDP.

## Two NixOS Machines

The following commands use neutral example hostnames `node1.example.com` (issuer)
and `node2.example.com` (joiner), and the SSH user `operator`. Substitute your
deployment's names. Both machines must already have the same enrollment-capable
`pillar` installed in `/run/current-system/sw/bin/pillar`, with a NixOS-managed
`pillar.service` running as `pillar`, a persistent `/var/lib/pillar` data
directory, and these environment settings:

```nix
systemd.services.pillar.environment = {
  PILLAR_DATA_DIR = "/var/lib/pillar";
  PILLAR_WEB_BIND = "127.0.0.1";
  PILLAR_WEB_PORT = "8642";
  PILLAR_RESOURCE_OP_UDP_BIND = "127.0.0.1:8644";
  PILLAR_PUBLIC_RESOURCE_OP_ADDR = "127.0.0.1:8644";
};
```

The service's `ExecStart` must run `pillar node run`, and must use that same data
directory and its default `identity.key`. Preserve your existing listen, dial,
swarm, and other runtime settings. If using a custom identity location, pass
`--identity-key /your/actual/path` to **both** enrollment commands below. The
loopback UDP setting makes the resource verification local to each host; SSH
TCP forwarding is not a UDP tunnel. Do not expose the HTTP listener publicly.

On **each host**, start the provisioned service once so it creates its identity:

```sh
sudo systemctl start pillar.service
sudo systemctl is-active pillar.service
sudo -u pillar test -s /var/lib/pillar/identity.key
```

Use a fresh, unbootstrapped joining data directory. Do not run `bootstrap cell`
on node2: that would initialize a different cell rather than request membership.
Do not delete existing data or credentials to force enrollment into an unrelated
cell. Installation is fail-closed when existing state conflicts.

### Bootstrap and Export on Node1

In an interactive Bash session on **node1**, initialize the issuer only if it
does not already have a cell and first user. Existing cells skip the first
`bootstrap cell` command and log in as their authorized enrollment administrator.

```bash
umask 077
read -r -s -p 'Cell administrator password: ' PILLAR_PASSWORD
printf '\n'
export PILLAR_PASSWORD
pillar bootstrap cell example-cell --user alice \
  --password "$PILLAR_PASSWORD" --domain 127.0.0.1:8642
eval "$(pillar login --domain 127.0.0.1:8642 --user alice)"
unset PILLAR_PASSWORD
pillar config export --domain 127.0.0.1:8642 \
  --out "$HOME/pillar-enrollment-config.yaml"
chmod 600 "$HOME/pillar-enrollment-config.yaml"
```

Export **before approval** so this credential's signer admission is in the
enrollment snapshot. Exporting a new signer after approval does not retroactively
add it to an already sealed bundle. Keep this node1 shell for the approval step.

### Submit From Node2

In a dedicated terminal on **node2**, keep this authenticated SSH forward running:

```sh
ssh -N -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes \
  -L 127.0.0.1:18642:127.0.0.1:8642 operator@node1.example.com
```

In another Bash session on **node2**, submit using the daemon's existing identity:

```bash
request_output=$(sudo -u pillar /run/current-system/sw/bin/pillar \
  bootstrap node --domain 127.0.0.1:18642 --data-dir /var/lib/pillar) || exit 1
printf '%s\n' "$request_output"
request_id=$(printf '%s\n' "$request_output" | sed -n 's/^REQUEST \([0-9][0-9]*\)$/\1/p')
case "$request_id" in
  ''|*[!0-9]*) printf 'Invalid request ID\n' >&2; exit 1 ;;
esac
printf 'Review request %s on node1\n' "$request_id"
```

Keep this shell: `request_id` is needed for completion. Submission may run while
the joining daemon is live; completion may not.

### Approve on Node1

Back in the authenticated **node1** shell, inspect the pending queue. Check the
request ID and joining subject against the joining machine through your trusted
operator channel, rather than approving an unsolicited request.

```bash
pillar bootstrap request list --domain 127.0.0.1:8642
read -r -p 'Verified node2 request ID: ' request_id
case "$request_id" in
  ''|*[!0-9]*) printf 'Invalid request ID\n' >&2; exit 1 ;;
esac
pillar bootstrap request approve "$request_id" --domain 127.0.0.1:8642
unset PILLAR_TOKEN
sudo systemctl restart pillar.service
sudo systemctl is-active pillar.service
```

Approval prints `APPROVED <id>`, not plaintext cell keys. Restarting node1 here
demonstrates that the approved sealed bundle is durable before retrieval. Wait
for its HTTP listener to be ready if the service has only just started. A stale
session must be replaced with a fresh login for further administrative actions.

### Complete and Restart Node2

In the **node2** shell that holds the request ID, stop the joining service before
completion. The daemon holds an exclusive enrollment lock; do not remove the lock
file or try to install under a live process.

```bash
sudo systemctl stop pillar.service
sudo -u pillar /run/current-system/sw/bin/pillar bootstrap node complete \
  "$request_id" --domain 127.0.0.1:18642 --data-dir /var/lib/pillar
sudo -u pillar test -s /var/lib/pillar/enrollment.sealed
sudo stat -c '%a %U %n' /var/lib/pillar/enrollment.sealed
sudo systemctl start pillar.service
sudo systemctl is-active pillar.service
```

Expect `600 pillar` for the installed file. If completion fails, inspect the
error before restarting; a pending request cannot install an enrollment. Retrying
the identical approved bundle is supported, but replacing a different installed
bundle is refused. Keep the original identity, data directory, and service
options across every restart.

### Verify the Existing Credential on Node2

On **node2**, transfer only the operator's exported CLI config over SSH. Never
transfer the issuer's daemon identity or manually populate node2's cell files.
Because both examples advertise the same loopback UDP address, the config already
targets the local node2 process. If your deployment uses different resource-op
addresses, change **only** `identity.addr` to node2's reachable UDP endpoint;
leave the cell ID, cell seed, and both signer fields unchanged.

```bash
umask 077
scp -o StrictHostKeyChecking=yes \
  operator@node1.example.com:pillar-enrollment-config.yaml \
  "$HOME/pillar-enrollment-config.yaml"
chmod 600 "$HOME/pillar-enrollment-config.yaml"
export PILLAR_CONFIG="$HOME/pillar-enrollment-config.yaml"
unset PILLAR_RESOURCE_OP_ADDR PILLAR_CELL_ID_HEX PILLAR_CELL_SEED_HEX
unset PILLAR_SIGNER_PUBLIC_HEX PILLAR_SIGNER_SECRET_HEX PILLAR_TOKEN
printf '%s\n' \
  'apiVersion: pillar.dev/v1' 'kind: RetentionPolicy' \
  'metadata:' '  name: enrollment-check' 'spec:' \
  '  signalKind: Metric' '  window: 2592000' > "$HOME/enrollment-check.yaml"
pillar apply -f "$HOME/enrollment-check.yaml"
pillar get RetentionPolicy enrollment-check
sudo systemctl restart pillar.service
sudo systemctl is-active pillar.service
pillar get RetentionPolicy enrollment-check
printf '%s\n' \
  'apiVersion: pillar.dev/v1' 'kind: RetentionPolicy' \
  'metadata:' '  name: enrollment-after-restart' 'spec:' \
  '  signalKind: Metric' '  window: 604800' > "$HOME/enrollment-after-restart.yaml"
pillar apply -f "$HOME/enrollment-after-restart.yaml"
pillar get RetentionPolicy enrollment-after-restart
```

The first resource must retain its exact name, signal kind, and window after the
restart; the second apply must work with the same config and no new login,
export, or signer admission. Wait for daemon readiness before issuing resource
commands after a restart. Stop the SSH forwarding terminal when enrollment is
finished. This procedure proves bootstrap snapshot transfer and local durability,
not ongoing cross-node resource replication.

## Automated Check

From the Pillar repository root:

```sh
cargo test -p pillar-cli --test bootstrap_node_enrollment
```

In the beehive worktree used for this implementation, the equivalent is:

```sh
beehive submodule worktree exec pillar bee-bootstrap-node-real-cell-enrollment -- cargo test -p pillar-cli --test bootstrap_node_enrollment
```

There is no `acceptance` feature gate or ignored test. The tests launch actual
node processes in separate temporary directories on separate ports, and use
per-child environments. They cover forged request JSON, unauthorized retrieval,
bad approval tokens, pending completion with no installed file, live-daemon lock
refusal, issuer restart before retrieval, endpoint-only config retargeting,
exact CLI resource reads, joining-node restart and a fresh write, and rejection
of a valid but unknown signer. They do not reconstruct daemon identities or copy
cell keys/admissions into the joining node from test code.
