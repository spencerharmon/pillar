{ config, lib, pkgs, ... }:
let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.pillar;
  nullableString = description: mkOption {
    type = types.nullOr types.str;
    default = null;
    inherit description;
  };
  socketType = types.strMatching "([[][0-9a-fA-F:]+[]]|[0-9.]+):[0-9]+";
  optionalEnv = name: value: lib.optionalAttrs (value != null) { ${name} = value; };
  environment = {
    PILLAR_DATA_DIR = cfg.dataDir;
    PILLAR_IDENTITY_KEY = cfg.identityKey;
    PILLAR_LISTEN = lib.concatStringsSep "," cfg.listen;
    PILLAR_EXTERNAL_ADDRESSES = lib.concatStringsSep "," cfg.externalAddresses;
    PILLAR_DIAL = lib.concatStringsSep "," cfg.dial;
    PILLAR_SEED_NODE = lib.concatStringsSep "," cfg.seeds;
    PILLAR_UPNP = lib.boolToString cfg.upnp;
    PILLAR_WEB_PORT = toString cfg.webPort;
    PILLAR_HEALTH_BIND = cfg.healthBind;
    PILLAR_HEALTH_PORT = toString cfg.healthPort;
    PILLAR_RESOURCE_OP_UDP_BIND = cfg.resourceOpBind;
  }
  // optionalEnv "PILLAR_SWARM_KEY" cfg.swarmKeyFile
  // optionalEnv "PILLAR_WEB_BIND" cfg.webBind
  // optionalEnv "PILLAR_PUBLIC_RESOURCE_OP_ADDR" cfg.publicResourceOpAddress
  // optionalEnv "PILLAR_PUBLIC_HOST" cfg.publicHost
  // optionalEnv "PILLAR_PSL_UDP_BIND" cfg.pslUdpBind
  // optionalEnv "PILLAR_PSL_QUIC_BIND" cfg.pslQuicBind
  // optionalEnv "PILLAR_INGRESS_LB_UDP_MANIFEST" cfg.ingressLbUdpManifest
  // lib.optionalAttrs cfg.disableMetrics { PILLAR_DISABLE_METRICS = "1"; };
  multiaddrPorts = protocol: lib.concatMap (addr:
    let matched = builtins.match ".*/${protocol}/([0-9]+)(/.*)?" addr;
        parts = lib.splitString "/" addr;
        host = if builtins.length parts > 2 then builtins.elemAt parts 2 else "";
    in lib.optional (matched != null && !isLoopback host) (lib.toInt (builtins.head matched))
  ) cfg.listen;
  socketPort = address: lib.toInt (lib.last (lib.splitString ":" address));
  isLoopback = address: address == "::1" || address == "[::1]"
    || lib.hasPrefix "[::1]:" address || lib.hasPrefix "127." address;
  exposed = address: address != null && !isLoopback address;
  webEnabled = cfg.webBind != null;
  tcpPorts = multiaddrPorts "tcp"
    ++ lib.optional (exposed cfg.webBind) cfg.webPort
    ++ lib.optional (exposed cfg.healthBind) cfg.healthPort;
  udpPorts = multiaddrPorts "udp" ++ cfg.ingressUdpPorts ++ lib.optionals webEnabled (
    lib.optional (exposed cfg.resourceOpBind) (socketPort cfg.resourceOpBind)
    ++ lib.optional (exposed cfg.pslUdpBind) (socketPort cfg.pslUdpBind)
    ++ lib.optional (exposed cfg.pslQuicBind) (socketPort cfg.pslQuicBind)
  );
in {
  options.services.pillar = {
    enable = mkEnableOption "the Pillar node";
    package = mkOption {
      type = types.package;
      description = "Pillar package supplied by the flake.";
    };
    dataDir = mkOption {
      type = types.strMatching "/var/lib/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*";
      default = "/var/lib/pillar";
      description = "Persistent data directory under /var/lib, managed by systemd StateDirectory.";
    };
    identityKey = mkOption {
      type = types.str;
      default = "${cfg.dataDir}/identity.key";
      defaultText = lib.literalExpression ''"\${config.services.pillar.dataDir}/identity.key"'';
      description = "Runtime identity key path. An external key must already exist and be readable by pillar.";
    };
    listen = mkOption {
      type = types.nonEmptyListOf types.str;
      default = [ "/ip4/0.0.0.0/tcp/4001" ];
      description = "Listen multiaddrs. Fixed ports are required with openFirewall.";
    };
    externalAddresses = mkOption {
      type = types.listOf types.str;
      default = [];
      example = [ "/dns4/node.example.com/tcp/4001" ];
      description = "Externally reachable libp2p multiaddrs to advertise, passed comma-separated in PILLAR_EXTERNAL_ADDRESSES. Does not change listener binds or open firewall ports.";
    };
    dial = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Peer multiaddrs to dial at startup (without DHT seed registration).";
    };
    seeds = mkOption {
      type = types.listOf types.str;
      default = [];
      example = [ "/dns4/seed.example.com/tcp/4001" ];
      description = "Federation seed multiaddrs (--seed-node). Empty uses the binary's public seeds unless a private swarm key is set.";
    };
    swarmKeyFile = nullableString "Runtime private swarm key file, readable by pillar. Never put secrets in the Nix store. Null joins the public swarm.";
    upnp = mkEnableOption "UPnP/NAT-PMP port mapping";
    webBind = nullableString "Web listener IP; null disables the web and resource-op surfaces. Use loopback behind an authenticated proxy/tunnel.";
    webPort = mkOption { type = types.port; default = 8642; description = "Web listener TCP port."; };
    healthBind = mkOption { type = types.str; default = "127.0.0.1"; description = "Health listener IP."; };
    healthPort = mkOption { type = types.port; default = 8643; description = "Health listener TCP port."; };
    resourceOpBind = mkOption {
      type = socketType;
      default = "127.0.0.1:8644";
      description = "Resource-op UDP socket address (IPv6 requires brackets), enabled with webBind.";
    };
    publicResourceOpAddress = nullableString "Advertised host:port for exported resource-op client configurations.";
    publicHost = nullableString "Fallback advertised host when publicResourceOpAddress is null (binary appends port 8644).";
    pslUdpBind = mkOption {
      type = types.nullOr socketType;
      default = null;
      description = "Optional PSL UDP socket address, enabled with webBind.";
    };
    pslQuicBind = mkOption {
      type = types.nullOr socketType;
      default = null;
      description = "Optional PSL QUIC socket address, enabled with webBind.";
    };
    ingressLbUdpManifest = nullableString "Runtime ingress load-balancer UDP manifest path.";
    ingressUdpPorts = mkOption {
      type = types.listOf types.port;
      default = [];
      description = "Inbound UDP ports in the runtime ingress manifest; required with openFirewall because Nix cannot inspect a runtime file.";
    };
    disableMetrics = mkEnableOption "disabling the default self-metrics producer";
    extraEnv = mkOption {
      type = types.attrsOf types.str;
      default = {};
      example = { RUST_LOG = "info"; };
      description = "Additional environment, including test hooks. Use typed options for listeners so firewall rules stay consistent. Values are public in the Nix store, not secrets.";
    };
    openFirewall = mkEnableOption "firewall rules for configured TCP/UDP listeners (not advertised or outbound addresses)";
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.intersectAttrs (environment // {
          PILLAR_SWARM_KEY = ""; PILLAR_WEB_BIND = ""; PILLAR_SEED_MULTIADDR = "";
          PILLAR_PSL_UDP_BIND = ""; PILLAR_PSL_QUIC_BIND = "";
          PILLAR_PUBLIC_RESOURCE_OP_ADDR = ""; PILLAR_PUBLIC_HOST = "";
          PILLAR_INGRESS_LB_UDP_MANIFEST = ""; PILLAR_DISABLE_METRICS = "";
        }) cfg.extraEnv == {};
        message = "services.pillar.extraEnv must not override typed node/listener options.";
      }
      {
        assertion = !cfg.openFirewall || lib.all (port: port > 0 && port <= 65535) (tcpPorts ++ udpPorts);
        message = "services.pillar.openFirewall requires fixed listener ports in 1..65535.";
      }
      {
        assertion = !cfg.openFirewall || cfg.ingressLbUdpManifest == null || cfg.ingressUdpPorts != [];
        message = "services.pillar.openFirewall requires ingressUdpPorts for a runtime ingressLbUdpManifest.";
      }
    ];
    users.groups.pillar = {};
    users.users.pillar = { isSystemUser = true; group = "pillar"; };
    environment.systemPackages = [ cfg.package ];
    networking.firewall = mkIf cfg.openFirewall {
      allowedTCPPorts = lib.unique tcpPorts;
      allowedUDPPorts = lib.unique udpPorts;
    };
    systemd.services.pillar = {
      description = "Pillar node";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      environment = environment // cfg.extraEnv;
      serviceConfig = {
        # The daemon falls back to a wildcard resource-op bind on invalid input.
        # Reject malformed sockets before it can silently widen exposure.
        ExecStartPre = "${pkgs.python3}/bin/python3 ${pkgs.writeText "pillar-validate-binds.py" ''
          import ipaddress
          import os

          for name in ("PILLAR_WEB_BIND", "PILLAR_HEALTH_BIND"):
              if name in os.environ:
                  ipaddress.ip_address(os.environ[name])
          for name in ("PILLAR_RESOURCE_OP_UDP_BIND", "PILLAR_PSL_UDP_BIND", "PILLAR_PSL_QUIC_BIND"):
              if name in os.environ:
                  host, port = os.environ[name].rsplit(":", 1)
                  ipaddress.ip_address(host.removeprefix("[").removesuffix("]"))
                  if not 0 <= int(port) <= 65535:
                      raise ValueError(f"Invalid port in {name}")
        ''}";
        ExecStart = "${cfg.package}/bin/pillar node run";
        User = "pillar";
        Group = "pillar";
        StateDirectory = lib.removePrefix "/var/lib/" cfg.dataDir;
        StateDirectoryMode = "0700";
        WorkingDirectory = cfg.dataDir;
        UMask = "0077";
        Restart = "on-failure";
        RestartSec = 5;
        NoNewPrivileges = true;
        CapabilityBoundingSet = "";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        LockPersonality = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
      };
    };
  };
}
