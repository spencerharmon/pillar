# NixOS Module

Import the flake's `nixosModules.default` to run the flake-built binary as the
unprivileged `pillar` user. For example, in a NixOS configuration with a `pillar`
flake input:

```nix
{
  imports = [ pillar.nixosModules.default ];
  services.pillar = {
    enable = true;
    listen = [ "/ip4/0.0.0.0/tcp/4001" ];
    externalAddresses = [ "/dns4/node.example.com/tcp/4001" ];
    seeds = [ "/dns4/seed.example.com/tcp/4001" ];
    webBind = "127.0.0.1";
    publicResourceOpAddress = "node.example.com:8644";
    resourceOpBind = "0.0.0.0:8644";
    openFirewall = true;
    extraEnv.RUST_LOG = "info";
  };
}
```

The web surface is disabled by default; health and resource-op binds default to
loopback. Unlike the CLI's ephemeral default, the module listens on TCP 4001.
`openFirewall` defaults to false. When enabled it opens configured TCP/UDP
multiaddr ports, non-loopback health/web ports, and resource-op/PSL UDP ports
when the web surface is enabled. It never opens outbound seed/dial or advertised
ports. Port zero cannot be automatically opened. Keep HTTP behind an authenticated
tunnel or TLS proxy; opening a firewall is not transport authentication.

`externalAddresses` is a list of strings (default `[]`) containing externally
reachable libp2p multiaddrs to advertise. The module joins the list with commas
into `PILLAR_EXTERNAL_ADDRESSES`; the default produces an empty string. These
advertisements do not change `listen` or any other bind, and do not open firewall
ports even with `openFirewall = true`. Arrange external routing/NAT separately.
This is distinct from `publicResourceOpAddress`, which advertises the resource-op
endpoint rather than libp2p addresses. Use the typed option, not an `extraEnv`
override of `PILLAR_EXTERNAL_ADDRESSES` (which the module rejects).

Outside NixOS, repeat `--external-address <multiaddr>` on `pillar node run`, or
set `PILLAR_EXTERNAL_ADDRESSES` to a comma/whitespace-separated list. Explicit
flags replace the entire environment list. Unset or empty environment means no
explicit advertisements; malformed multiaddrs are rejected at startup. Addresses
are registered before the first identify exchange, independently of UPnP (which
can still advertise automatically mapped addresses). These are operator-confirmed
routes, not reachability probes: configure forwarding to the actual listeners,
and only advertise transports the node serves. Private swarms do not serve QUIC.

Options mirror node flags: `dataDir`, `identityKey`, `listen`, `externalAddresses`, `dial`, `seeds`,
`swarmKeyFile`, `upnp`, `webBind`, `webPort`, `healthBind`, `healthPort`.
Environment-only controls are `resourceOpBind`, `publicResourceOpAddress`,
`publicHost` (fallback), `pslUdpBind`, `pslQuicBind`, `ingressLbUdpManifest`, and
`disableMetrics`. `extraEnv` supplies additional variables such as `RUST_LOG`
and the integration-only `PILLAR_TEST_*` hooks. Use typed options rather than
environment overrides for listeners so firewall rules match. `package` may be
overridden; the default is this flake's `packages.<system>.pillar`.
When using a runtime `ingressLbUdpManifest`, declare its inbound UDP ports in
`ingressUdpPorts` for automatic firewall rules. A pre-start check rejects invalid
IP/socket binds instead of permitting the daemon's wildcard fallback.

Systemd manages `dataDir` (default `/var/lib/pillar`, configurable beneath
`/var/lib`) as a persistent `StateDirectory`, mode 0700. Identity and cell state
survive service restarts and upgrades. The default identity is
`<dataDir>/identity.key`; an external identity must be pre-provisioned and
readable by `pillar`. Never place private keys or passwords in Nix expressions,
`extraEnv`, or store paths. Provision `swarmKeyFile` at runtime, readable only by
the service; null joins the public swarm. The unit cannot read `/home`, and
cannot write outside its state directory. Runtime secrets can live under `/run`.

The unit drops capabilities, prevents privilege escalation, isolates temporary
files/devices, and protects the host filesystem/kernel. Deployments requiring
hardware custody or privileged workloads must explicitly review and override
the relevant `systemd.services.pillar.serviceConfig` restrictions (for example,
device visibility); those privileges are not silently granted to every node.

For cell creation and enrollment, follow [the enrollment guide](bootstrap-node-enrollment.md).
Use the configured data directory and identity path with both `bootstrap node`
and `bootstrap node complete`. Approval does not install state into the joiner:
stop the joining service, complete enrollment as `pillar`, then start it again.
Keep its original identity, listener, and seed configuration.

## Evaluation Regression

```sh
nix eval .#checks.x86_64-linux.nixos-module-eval.drvPath
```

This fast check evaluates the exported NixOS module without compiling Pillar or
booting VMs. It checks external-address defaults, comma-separated environment
mapping, list/string type enforcement, rejection of `extraEnv` overrides, and
unchanged binds and firewall rules with advertisements configured (both with and
without `openFirewall`). It is also included in `nix flake check`.

## VM Regression

```sh
nix build .#checks.x86_64-linux.nixos-module
```

The test boots two NixOS machines with firewalls enabled and a generated private
swarm key. It checks systemd hardening, non-default listeners, a custom data/key
path, seed/identify connectivity, real bootstrap request/approval/completion,
issuer restart before retrieval, a cross-VM UDP write using the issuer's exported
credential, and durable reads/writes on the joiner after restart with the issuer
stopped. This tests enrollment and persistence, not ongoing resource replication.
The NixOS test needs a Linux builder with virtualization support (`kvm`); no
external seed, deployment hostname, or production secret is used.
