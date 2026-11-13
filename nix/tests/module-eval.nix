{ pkgs, self }:
let
  inherit (pkgs) lib;
  evaluate = settings: (self.inputs.nixpkgs.lib.nixosSystem {
    system = pkgs.stdenv.hostPlatform.system;
    modules = [
      self.nixosModules.default
      {
        # Evaluation only: avoid evaluating/building the Rust package closure.
        services.pillar = { enable = true; package = pkgs.hello; } // settings;
        system.stateVersion = "25.05";
      }
    ];
  }).config;
  addresses = [
    "/dns4/node.example.com/tcp/24001"
    "/ip4/192.0.2.1/udp/24002/quic-v1"
  ];
  defaults = evaluate {};
  advertised = evaluate { externalAddresses = addresses; };
  listeners = {
    listen = [ "/ip4/0.0.0.0/tcp/14001" "/ip6/::/udp/14002/quic-v1" ];
    webBind = "127.0.0.1";
    healthBind = "0.0.0.0";
    resourceOpBind = "0.0.0.0:18644";
    openFirewall = true;
  };
  baseline = evaluate listeners;
  configured = evaluate (listeners // { externalAddresses = addresses; });
  environment = config: config.systemd.services.pillar.environment;
  firewall = config: {
    tcp = lib.sort builtins.lessThan config.networking.firewall.allowedTCPPorts;
    udp = lib.sort builtins.lessThan config.networking.firewall.allowedUDPPorts;
  };
  rejects = value: !(builtins.tryEval (builtins.deepSeq
    (evaluate { externalAddresses = value; }).services.pillar.externalAddresses true)).success;
  failures = lib.runTests {
    testDefault = { expr = defaults.services.pillar.externalAddresses; expected = []; };
    testDefaultEnvironment = { expr = (environment defaults).PILLAR_EXTERNAL_ADDRESSES; expected = ""; };
    testMapping = {
      expr = (environment configured).PILLAR_EXTERNAL_ADDRESSES;
      expected = "/dns4/node.example.com/tcp/24001,/ip4/192.0.2.1/udp/24002/quic-v1";
    };
    testBindsUnchanged = {
      expr = builtins.removeAttrs (environment configured) [ "PILLAR_EXTERNAL_ADDRESSES" ];
      expected = builtins.removeAttrs (environment baseline) [ "PILLAR_EXTERNAL_ADDRESSES" ];
    };
    testDefaultBindsUnchanged = {
      expr = builtins.removeAttrs (environment advertised) [ "PILLAR_EXTERNAL_ADDRESSES" ];
      expected = builtins.removeAttrs (environment defaults) [ "PILLAR_EXTERNAL_ADDRESSES" ];
    };
    testListenerFirewall = {
      expr = firewall configured;
      expected = { tcp = [ 8643 14001 ]; udp = [ 14002 18644 ]; };
    };
    testFirewallUnchanged = { expr = firewall configured; expected = firewall baseline; };
    testFirewallClosedByDefault = {
      expr = firewall advertised;
      expected = { tcp = []; udp = []; };
    };
    testRejectString = { expr = rejects "/dns4/node.example.com/tcp/24001"; expected = true; };
    testRejectNonStringElement = { expr = rejects [ 24001 ]; expected = true; };
    testRejectNull = { expr = rejects null; expected = true; };
    testExtraEnvCannotOverride = {
      expr = lib.any (entry: !entry.assertion && entry.message ==
        "services.pillar.extraEnv must not override typed node/listener options.")
        (evaluate { extraEnv.PILLAR_EXTERNAL_ADDRESSES = builtins.head addresses; }).assertions;
      expected = true;
    };
  };
in
assert lib.assertMsg (failures == []) (builtins.toJSON failures);
pkgs.runCommand "pillar-nixos-module-eval" {} ''
  touch "$out"
''
