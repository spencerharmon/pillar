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
    # Install the shared test-only key before starting either node.
    systemd.services.pillar.wantedBy = lib.mkForce [];
    environment.systemPackages = [ pkgs.curl ];
    virtualisation.memorySize = 2048;
  };
in {
  name = "pillar-nixos-module";
  nodes.node1 = node;
  nodes.node2 = {
    imports = [ node ];
    services.pillar = {
      dataDir = "/var/lib/pillar-joiner";
      identityKey = "/var/lib/pillar-joiner/node.key";
      seeds = [ "/dns4/node1/tcp/14001" ];
    };
  };
  testScript = ''
    import re
    import shlex

    start_all()

    def ready(machine):
        machine.wait_for_unit("pillar.service")
        machine.wait_until_succeeds("curl -fsS http://127.0.0.1:18643/readyz | grep -Fx ready")
        machine.wait_until_succeeds("curl -fsS http://127.0.0.1:18642/bootstrap/status")

    def login(machine):
        output = machine.succeed("pillar login --domain 127.0.0.1:18642 --user alice --password 'VM enrollment password'")
        return shlex.split(next(line.split("=", 1)[1] for line in output.splitlines() if line.startswith("export PILLAR_TOKEN=")))[0]

    with subtest("hardened services and configured firewall listeners"):
        key = node1.succeed("pillar swarm generate").strip()
        for machine in (node1, node2):
            machine.succeed("install -d -o pillar -g pillar -m 0700 /run/pillar-test")
            machine.succeed("printf '%s\\n' " + shlex.quote(key) + " > /run/pillar-test/swarm.key")
            machine.succeed("chown pillar:pillar /run/pillar-test/swarm.key; chmod 0600 /run/pillar-test/swarm.key")
            machine.succeed("systemctl start pillar")
            ready(machine)
            assert machine.succeed("systemctl show pillar -p User --value").strip() == "pillar"
            assert machine.succeed("systemctl show pillar -p ProtectSystem --value").strip() == "strict"
            assert machine.succeed("systemctl show pillar -p NoNewPrivileges --value").strip() == "yes"
        node2.succeed("curl -fsS http://node1:18643/healthz | grep -Fx alive")
        assert node2.succeed("curl -fsS http://node1:18642/bootstrap/status").strip() == "FRESH"
        node1.succeed("test $(stat -c %a /var/lib/pillar) = 700")
        node2.succeed("test $(stat -c '%a:%U' /var/lib/pillar-joiner/node.key) = 600:pillar")
        identity = node2.succeed("sha256sum /var/lib/pillar-joiner/node.key")

    with subtest("seed dial establishes real federation connectivity"):
        node2.wait_until_succeeds("journalctl -u pillar --no-pager | grep -F 'learned peer from identify; added to DHT routing table'")
        logs = node1.succeed("journalctl -u pillar --no-pager -o cat")
        peer_match = re.search(r"peer identity loaded.*peer_id[= ]+(12D3KooW\w+)", logs)
        assert peer_match is not None, logs
        peer1 = peer_match.group(1)
        node2.wait_until_succeeds("journalctl -u pillar --no-pager -o cat | grep -F 'connection established' | grep -F " + shlex.quote(peer1))
        node1.succeed("pillar bootstrap cell example-cell --user alice --password 'VM enrollment password' --domain 127.0.0.1:18642")
        token = login(node1)
        node1.succeed("PILLAR_TOKEN=" + shlex.quote(token) + " pillar config export --domain 127.0.0.1:18642 --out /root/client.yaml")

    with subtest("request, approve, and install identity-bound enrollment"):
        join = "sudo -u pillar pillar bootstrap node"
        args = " --domain node1:18642 --data-dir /var/lib/pillar-joiner --identity-key /var/lib/pillar-joiner/node.key"
        output = node2.succeed(join + args)
        request_match = re.search(r"^REQUEST (\d+)$", output, re.M)
        assert request_match is not None, output
        request = request_match.group(1)
        approved = node1.succeed("PILLAR_TOKEN=" + shlex.quote(token) + " pillar bootstrap request approve " + request + " --domain 127.0.0.1:18642")
        assert approved.strip() == "APPROVED " + request
        node1.succeed("systemctl restart pillar")
        ready(node1)
        node2.fail(join + " complete " + request + args)
        node2.succeed("systemctl stop pillar")
        node2.succeed(join + " complete " + request + args)
        node2.succeed("test $(stat -c '%a:%U' /var/lib/pillar-joiner/enrollment.sealed) = 600:pillar")
        node2.succeed("systemctl start pillar")
        ready(node2)
        assert node2.succeed("curl -fsS http://127.0.0.1:18642/bootstrap/status").strip() == "BOOTSTRAPPED"

    with subtest("issuer credential works on joiner over firewall-open UDP"):
        client = node1.succeed("cat /root/client.yaml")
        # Only retarget the endpoint, preserving cell seed and admitted signer.
        assert "127.0.0.1:18644" in client
        remote_client = client.replace("127.0.0.1:18644", "node2:18644")
        node1.succeed("printf %s " + shlex.quote(remote_client) + " > /root/remote.yaml")
        manifest = "apiVersion: pillar.dev/v1\nkind: RetentionPolicy\nmetadata:\n  name: enrollment-check\nspec:\n  signalKind: Metric\n  window: 2592000\n"
        node1.succeed("printf %s " + shlex.quote(manifest) + " > /root/policy.yaml")
        output = node1.succeed("PILLAR_CONFIG=/root/remote.yaml pillar apply -f /root/policy.yaml")
        assert "OK" in output and "PillarUdp" in output
        node2.succeed("printf %s " + shlex.quote(client) + " > /root/client.yaml; chmod 0600 /root/client.yaml")
        node1.succeed("systemctl stop pillar")
        get = "PILLAR_CONFIG=/root/client.yaml pillar get RetentionPolicy enrollment-check"
        before = node2.succeed(get)
        assert "enrollment-check" in before and "2592000" in before and "Metric" in before
        node2.succeed("systemctl restart pillar")
        ready(node2)
        assert node2.succeed(get) == before
        assert node2.succeed("sha256sum /var/lib/pillar-joiner/node.key") == identity
        assert node2.succeed("cat /root/client.yaml") == client
        node2.succeed("printf %s " + shlex.quote(manifest.replace("enrollment-check", "after-restart")) + " > /root/policy.yaml")
        assert "OK" in node2.succeed("PILLAR_CONFIG=/root/client.yaml pillar apply -f /root/policy.yaml")
  '';
}
