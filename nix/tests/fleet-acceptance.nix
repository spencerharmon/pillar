{ self, lib, ... }:
let
  node = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    services.pillar = {
      enable = true;
      listen = [ "/ip4/0.0.0.0/tcp/14001" ];
      swarmKeyFile = "/run/pillar-test/swarm.key";
      webBind = "0.0.0.0";
      webPort = 18642;
      healthBind = "0.0.0.0";
      healthPort = 18643;
      resourceOpBind = "0.0.0.0:18644";
      publicResourceOpAddress = "127.0.0.1:18644";
      openFirewall = true;
      extraEnv.RUST_LOG = "info";
    };
    # Provision the runtime-only private swarm key before starting the service.
    systemd.services.pillar.wantedBy = lib.mkForce [ ];
    environment.systemPackages = [ pkgs.curl pkgs.openssl ];
    virtualisation.memorySize = 2048;
    # TCG traps unsupported instructions; masking CPUID under KVM is not enough.
    virtualisation.qemu.options = [ "-machine accel=tcg" "-cpu Westmere,-aes,-pclmulqdq" ];
  };
in {
  name = "pillar-fleet-acceptance";
  nodes.node1 = node;
  nodes.node2 = {
    imports = [ node ];
    services.pillar.seeds = [ "/dns4/node1/tcp/14001" ];
  };
  nodes.node3 = {
    imports = [ node ];
    # The survivors have a direct path, including after both restart.
    services.pillar.seeds = [ "/dns4/node1/tcp/14001" "/dns4/node2/tcp/14001" ];
  };
  testScript = builtins.readFile ./fleet-acceptance.py;
}
