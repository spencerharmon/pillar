# checks.x86_64-linux.native-service — the packaged pillar node under
# `nixosModules.default`, two VMs on a baseline x86-64 CPU (TCG, Westmere with
# AES-NI/PCLMUL removed: no AVX/AVX2/FMA/BMI/AES-NI), so the flake package's
# actual execution — not compiler flags — proves compatibility. Neutral
# hostnames (node1/node2) and test-owned credentials only.
{ self, nixpkgs, lib, ... }:
let
  baseConfig = {
    enable = true;
    listen = [ "/ip4/0.0.0.0/tcp/14001" ];
    swarmKeyFile = "/run/pillar-test/swarm.key";
    webBind = "0.0.0.0";
    webPort = 18642;
    healthBind = "0.0.0.0";
    healthPort = 18643;
    resourceOpBind = "0.0.0.0:18644";
    openFirewall = true;
    extraEnv.RUST_LOG = "info";
  };

  # Evaluation-time configuration failures: the module must refuse these
  # before anything is built or started.
  evalAssertions = extra: let
    sys = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        self.nixosModules.default
        { services.pillar = baseConfig // extra;
          boot.loader.grub.enable = false;
          fileSystems."/".device = "none";
          system.stateVersion = "24.05"; }
      ];
    };
  in map (a: a.message) (builtins.filter (a: !a.assertion) sys.config.assertions);
  rejected = {
    ephemeralPortFirewall = evalAssertions { listen = [ "/ip4/0.0.0.0/tcp/0" ]; };
    extraEnvOverride = evalAssertions { extraEnv.PILLAR_WEB_BIND = "0.0.0.0"; };
    manifestWithoutPorts = evalAssertions { ingressLbUdpManifest = "/run/pillar-test/ingress.yaml"; };
  };
  accepted = evalAssertions { };
  evalOk =
    assert accepted == [ ];
    assert lib.all (v: v != [ ]) (lib.attrValues rejected);
    true;

  node = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    services.pillar = baseConfig;
    # The test installs the test-owned swarm key before the first start.
    systemd.services.pillar.wantedBy = lib.mkForce [ ];
    environment.systemPackages = [ pkgs.curl pkgs.python3 ];
    virtualisation.memorySize = 2048;
    virtualisation.qemu.options = [ "-machine accel=tcg" "-cpu Westmere,-aes,-pclmulqdq" ];
  };
in
{
  name = "pillar-native-service";
  nodes.node1 = node;
  nodes.node2 = {
    imports = [ node ];
    services.pillar = {
      dataDir = "/var/lib/pillar-joiner";
      identityKey = "/var/lib/pillar-joiner/node.key";
      seeds = [ "/dns4/node1/tcp/14001" ];
    };
  };
  # Evaluation-time configuration failures are asserted when the script is built.
  testScript = assert evalOk; ''
    import re
    import shlex

    PW = "native service test password"
    start_all()

    def ready(m):
        m.wait_for_unit("pillar.service")
        m.wait_until_succeeds("curl -fsS http://127.0.0.1:18643/readyz | grep -Fx ready")
        m.wait_until_succeeds("curl -fsS http://127.0.0.1:18642/bootstrap/status")

    def status(m):
        return m.succeed("curl -fsS http://127.0.0.1:18642/bootstrap/status").strip()

    def portal_login(m):
        nonce = m.succeed("curl -fsS http://127.0.0.1:18642/nonce").split()[1]
        body = "alice\n" + PW + "\n" + nonce
        headers = m.succeed("curl -fsS -D - -o /dev/null --data-binary " + shlex.quote(body) + " http://127.0.0.1:18642/login")
        match = re.search(r"^X-Pillar-Session: *(\S+)", headers, re.M | re.I)
        assert match is not None, headers
        return match.group(1)

    def cli_token(m):
        out = m.succeed("pillar login --domain 127.0.0.1:18642 --user alice --password " + shlex.quote(PW))
        return shlex.split(next(l.split("=", 1)[1] for l in out.splitlines() if l.startswith("export PILLAR_TOKEN=")))[0]

    def dashboard(m, token, ident):
        return m.execute("curl -fsS " + shlex.quote("http://127.0.0.1:18642/portal/obs/dashboard/get?token=" + token + "&id=" + ident))

    def peer_id(m):
        logs = m.succeed("journalctl -u pillar --no-pager -o cat")
        match = re.search(r"peer identity loaded.*peer_id[= ]+(12D3KooW\w+)", logs)
        assert match is not None, logs
        return match.group(1)

    with subtest("baseline CPU without AVX/AVX2/FMA/BMI/AES-NI"):
        for m in (node1, node2):
            cpuinfo = m.succeed("cat /proc/cpuinfo")
            flags = set(next(l.split(":", 1)[1] for l in cpuinfo.splitlines() if l.startswith("flags")).split())
            forbidden = {"avx", "avx2", "fma", "bmi1", "bmi2", "aes", "pclmulqdq"}
            assert not flags & forbidden, flags & forbidden

    with subtest("hardened units start the packaged node with persistent state"):
        key = node1.succeed("pillar swarm generate").strip()
        for m in (node1, node2):
            m.succeed("install -d -o pillar -g pillar -m 0700 /run/pillar-test")
            m.succeed("printf '%s\\n' " + shlex.quote(key) + " > /run/pillar-test/swarm.key")
            m.succeed("chown pillar:pillar /run/pillar-test/swarm.key; chmod 0600 /run/pillar-test/swarm.key")
            m.succeed("systemctl start pillar")
            ready(m)
            assert m.succeed("systemctl show pillar -p User --value").strip() == "pillar"
            assert m.succeed("systemctl show pillar -p ProtectSystem --value").strip() == "strict"
            assert m.succeed("systemctl show pillar -p NoNewPrivileges --value").strip() == "yes"
            exe = m.succeed("readlink -f /proc/$(systemctl show pillar -p MainPID --value)/exe").strip()
            assert exe.startswith("/nix/store/") and exe.endswith("/bin/pillar"), exe
            # Secrets are runtime files: the key never appears in the unit.
            assert key not in m.succeed("systemctl cat pillar")
        node1.succeed("test $(stat -c %a:%U /var/lib/pillar) = 700:pillar")
        node2.succeed("test $(stat -c '%a:%U' /var/lib/pillar-joiner/node.key) = 600:pillar")

    with subtest("distinct identities federate over the seed"):
        peer1, peer2 = peer_id(node1), peer_id(node2)
        assert peer1 != peer2
        id1 = node1.succeed("sha256sum < /var/lib/pillar/identity.key")
        id2 = node2.succeed("sha256sum < /var/lib/pillar-joiner/node.key")
        assert id1 != id2
        node2.wait_until_succeeds("journalctl -u pillar --no-pager -o cat | grep -F 'connection established' | grep -F " + shlex.quote(peer1))
        assert status(node2) == "FRESH"

    with subtest("node1 owns an existing cell"):
        # Under TCG the CLI's client read timeout can expire while the node
        # finishes the (slow, emulated) KDF work; the node's state is the oracle.
        rc, out = node1.execute("pillar bootstrap cell example-cell --user alice --password " + shlex.quote(PW) + " --domain 127.0.0.1:18642 2>&1")
        print(rc, out)
        node1.wait_until_succeeds("curl -fsS http://127.0.0.1:18642/bootstrap/status | grep -Fx BOOTSTRAPPED")
        token = cli_token(node1)

    join = "sudo -u pillar pillar bootstrap node"
    args = " --domain node1:18642 --data-dir /var/lib/pillar-joiner --identity-key /var/lib/pillar-joiner/node.key"

    with subtest("unauthorized join is rejected"):
        out = node2.succeed(join + args)
        match = re.search(r"^REQUEST (\d+)$", out, re.M)
        assert match is not None, out
        request = match.group(1)
        node2.succeed("systemctl stop pillar")
        rc, out = node2.execute(join + " complete " + request + args + " 2>&1")
        assert rc != 0 and "DENIED" in out, out
        rc, out = node2.execute("PILLAR_TOKEN=forged-token pillar bootstrap request approve " + request + " --domain node1:18642 2>&1")
        assert rc != 0, out
        rc, out = node2.execute(join + " complete " + request + args + " 2>&1")
        assert rc != 0, out
        node2.succeed("test ! -e /var/lib/pillar-joiner/enrollment.sealed")
        node2.succeed("systemctl start pillar")
        ready(node2)
        assert status(node2) == "FRESH"
        node2.fail("curl -fsS --data-binary 'alice\n" + PW + "\n0' http://127.0.0.1:18642/login")

    with subtest("approved second node joins the existing cell"):
        approved = node1.succeed("PILLAR_TOKEN=" + shlex.quote(token) + " pillar bootstrap request approve " + request + " --domain 127.0.0.1:18642")
        assert approved.strip() == "APPROVED " + request
        node2.succeed("systemctl stop pillar")
        node2.succeed(join + " complete " + request + args)
        node2.succeed("test $(stat -c '%a:%U' /var/lib/pillar-joiner/enrollment.sealed) = 600:pillar")
        node2.succeed("systemctl start pillar")
        ready(node2)
        assert status(node2) == "BOOTSTRAPPED"
        assert node2.succeed("sha256sum < /var/lib/pillar-joiner/node.key") == id2
        assert peer_id(node2) == peer2

    with subtest("data written on node1 is visible through node2's portal"):
        token2 = portal_login(node2)
        token1 = portal_login(node1)
        saved = node1.succeed("curl -fsS --data-binary " + shlex.quote(token1 + "\nreplicated: written-on-node1") + " http://127.0.0.1:18642/portal/obs/dashboard")
        ident = saved.split()[1]
        node2.wait_until_succeeds("curl -fsS " + shlex.quote("http://127.0.0.1:18642/portal/obs/dashboard/get?token=" + token2 + "&id=" + ident) + " | grep -F written-on-node1", timeout=600)

    with subtest("state persists across an isolated restart"):
        node1.succeed("systemctl stop pillar")
        node2.succeed("systemctl restart pillar")
        ready(node2)
        assert status(node2) == "BOOTSTRAPPED"
        token2 = portal_login(node2)
        rc, body = dashboard(node2, token2, ident)
        assert rc == 0 and "written-on-node1" in body, body
        assert node2.succeed("sha256sum < /var/lib/pillar-joiner/node.key") == id2

    def expect_start_failure(m, needle):
        m.succeed("systemctl stop pillar; systemctl reset-failed pillar || true")
        since = m.succeed("date +%s").strip()
        m.execute("systemctl start pillar")
        m.wait_until_succeeds("journalctl -u pillar --no-pager -o cat --since @" + since + " | grep -F " + shlex.quote(needle))
        # The unit's process exited non-zero (systemd schedules a restart).
        m.wait_until_succeeds("test $(systemctl show pillar -p NRestarts --value) -gt 0")
        m.succeed("systemctl stop pillar; systemctl reset-failed pillar || true")

    def dropin(m, text):
        m.succeed("mkdir -p /run/systemd/system/pillar.service.d")
        m.succeed("printf '[Service]\\n%s\\n' " + shlex.quote(text) + " > /run/systemd/system/pillar.service.d/fail.conf")
        m.succeed("systemctl daemon-reload")

    with subtest("listener and configuration failures fail the unit"):
        m = node2
        dropin(m, "Environment=PILLAR_WEB_BIND=not-an-address")
        expect_start_failure(m, "does not appear to be an IPv4 or IPv6 address")
        dropin(m, "Environment=PILLAR_SWARM_KEY=/run/pillar-test/missing.key")
        expect_start_failure(m, "missing.key")
        m.succeed("rm /run/systemd/system/pillar.service.d/fail.conf; systemctl daemon-reload")
        m.succeed("systemd-run --unit squatter -p DynamicUser=yes $(command -v python3) -m http.server 18642 --bind 0.0.0.0")
        m.wait_for_open_port(18642)
        expect_start_failure(m, "web UI bind")
        m.succeed("systemctl stop squatter")
        m.succeed("systemctl start pillar")
        ready(m)
        assert status(m) == "BOOTSTRAPPED"
  '';
}
