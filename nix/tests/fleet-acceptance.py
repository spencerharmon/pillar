import hashlib
import re
import secrets
import shlex
import time
from urllib.parse import urlencode

nodes = (node1, node2, node3)
password = secrets.token_hex(24)
tokens = {}
dataset = []
queries = []
start_all()


def ready(machine):
    machine.wait_for_unit("pillar.service")
    machine.wait_until_succeeds(
        "curl -fsS http://127.0.0.1:18643/readyz | grep -Fx ready", timeout=600
    )
    machine.wait_until_succeeds("curl -fsS http://127.0.0.1:18642/bootstrap/status")
    assert machine.succeed("systemctl show pillar -p NRestarts --value").strip() == "0"


def http(machine, method, path, body="", query=None):
    if query:
        path += "?" + urlencode(query)
    return machine.succeed(
        "curl -fsS --max-time 120 -X " + method + " --data-binary "
        + shlex.quote(body) + " " + shlex.quote("http://127.0.0.1:18642" + path)
    )


def login(machine):
    nonce = http(machine, "GET", "/nonce").split()[1]
    headers = machine.succeed(
        "curl -fsS --max-time 120 -D - -o /dev/null --data-binary "
        + shlex.quote(f"alice\n{password}\n{nonce}") + " http://127.0.0.1:18642/login"
    )
    match = re.search(r"^X-Pillar-Session: *(\S+)", headers, re.M | re.I)
    assert match, headers
    tokens[machine.name] = match.group(1)
    return match.group(1)


def cli(machine, *args):
    return machine.succeed("PILLAR_CONFIG=/root/client.yaml pillar " + shlex.join(args))


def audit_write(machine, collection, *args):
    reply = cli(machine, *args)
    match = re.search(r"EVENT-CID (1220[0-9a-f]{64})", reply)
    assert match, reply
    cid = match.group(1)
    for verb in ("show", "verify"):
        query = ("log", verb, collection, cid)
        expected = cli(machine, *query)
        assert cid in expected, expected
        if verb == "verify":
            assert "signature-valid: true" in expected and "hash-matches-id: true" in expected
        queries.append((query, expected))
    return reply


def write(machine, phase):
    # Compare complete objects, not just names, counts or the last replicated CID.
    for number in range(3):
        value = f"{phase}-{number}-" + secrets.token_hex(2048 * (number + 1))
        name = f"{phase}-{number}"
        text = http(machine, "POST", "/portal/obs/dashboard",
                    f"{tokens[machine.name]}\n{name}: {value}")
        cid = text.split()[1]
        assert re.fullmatch(r"1220[0-9a-f]{64}", cid), text
        expected = http(machine, "GET", "/portal/obs/dashboard/get",
                        query={"token": tokens[machine.name], "id": cid})
        assert f"OBS-DASHBOARD-NAME {name}\n" in expected
        assert f"OBS-DASHBOARD-CONTENT {value}\n" in expected
        dataset.append(("/portal/obs/dashboard/get", "id", cid, expected))
    content = f"{phase}\nlayout={secrets.token_hex(1024)}"
    text = http(machine, "POST", "/portal/layout", f"{tokens[machine.name]}\n{content}")
    cid = text.split()[1]
    assert re.fullmatch(r"1220[0-9a-f]{64}", cid), text
    expected = http(machine, "GET", "/portal/layout", query={"token": tokens[machine.name], "cid": cid})
    assert content in expected
    dataset.append(("/portal/layout", "cid", cid, expected))

    value = secrets.token_hex(256)
    audit_write(machine, "fleet-kv", "kv", "put", "fleet-kv", phase, value)
    queries.append((("kv", "get", "fleet-kv", phase), value + "\n"))
    audit_write(machine, "fleet-doc", "doc", "put", "fleet-doc", phase, "value", value)
    queries.append((("doc", "get", "fleet-doc", phase, "value"), value + "\n"))
    audit_write(machine, phase, "sql", "create-view", phase, "fleet-doc", "--eq", "value", value)
    query = ("sql", "view", phase)
    expected = cli(machine, *query)
    assert value in expected
    queries.append((query, expected))
    for visibility in ("public", "sealed"):
        flags = ("--recipient", recipient) if visibility == "sealed" else ()
        reply = audit_write(machine, "__objects", "object", "put", visibility, value, *flags)
        cid = reply.split()[1]
        query = ("object", "cat", cid, "--secret", secret) if flags else ("object", "cat", cid)
        assert cli(machine, *query) == value + "\n"
        queries.append((query, value + "\n"))
        proof = cli(machine, "object", "verify", cid)
        assert "hash-matches-cid: true" in proof and "signature-valid: true" in proof, proof
        queries.append((("object", "verify", cid), proof))
        if flags:
            envelope = cli(machine, "object", "cat", cid)
            assert envelope.startswith("SEALED ") and value not in envelope
            queries.append((("object", "cat", cid), envelope))
    manifest = (f"apiVersion: pillar.dev/v1\nkind: RetentionPolicy\nmetadata:\n  name: {phase}\n"
                "spec:\n  signalKind: Metric\n  window: 2592000\n")
    machine.succeed("printf %s " + shlex.quote(manifest) + " > /root/policy.yaml")
    assert "OK" in cli(machine, "apply", "-f", "/root/policy.yaml")
    query = ("get", "RetentionPolicy", phase)
    expected = cli(machine, *query)
    assert phase in expected and "2592000" in expected
    queries.append((query, expected))


def verify(machines, phase):
    for machine in machines:
        # A single bounded deadline covers the entire fixture on this machine.
        deadline = time.monotonic() + 600
        for path, key, cid, expected in dataset:
            while True:
                try:
                    actual = http(machine, "GET", path, query={"token": tokens[machine.name], key: cid})
                    assert actual == expected, f"{machine.name}: different content for {cid}"
                    break
                except Exception:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(2)
        for query, expected in queries:
            while True:
                try:
                    assert cli(machine, *query) == expected, f"{machine.name}: different result for {query}"
                    break
                except Exception:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(2)
        digest = hashlib.sha256("".join(e[2] + e[3] for e in dataset).encode()).hexdigest()
        print(f"oracle-observed: {phase} {machine.name} full-fixture={len(dataset)} "
              f"CID-identical reads sha256={digest}; data-plane checks={len(queries)}", flush=True)


with subtest("three native module services on a no-AVX/no-AES CPU"):
    key = node1.succeed("pillar swarm generate").strip()
    identities = []
    for machine in nodes:
        cpuinfo = machine.succeed("cat /proc/cpuinfo")
        flags = set(next(line.split(":", 1)[1] for line in cpuinfo.splitlines() if line.startswith("flags")).split())
        assert not flags & {"avx", "avx2", "fma", "bmi1", "bmi2", "aes", "pclmulqdq"}, flags
        assert {"ssse3", "sse4_1", "sse4_2", "popcnt"} <= flags, flags
        machine.succeed("install -d -o pillar -g pillar -m 0700 /run/pillar-test")
        machine.succeed("printf '%s\n' " + shlex.quote(key) + " > /run/pillar-test/swarm.key")
        machine.succeed("chown pillar:pillar /run/pillar-test/swarm.key; chmod 0600 /run/pillar-test/swarm.key")
        machine.succeed("systemctl start pillar")
        ready(machine)
        assert machine.succeed("systemctl show pillar -p User --value").strip() == "pillar"
        assert machine.succeed("systemctl show pillar -p ProtectSystem --value").strip() == "strict"
        assert machine.succeed("systemctl show pillar -p NoNewPrivileges --value").strip() == "yes"
        exe = machine.succeed("readlink -f /proc/$(systemctl show pillar -p MainPID --value)/exe").strip()
        packaged = machine.succeed("readlink -f $(command -v pillar)").strip()
        assert exe == packaged and exe.startswith("/nix/store/") and exe.endswith("/bin/pillar"), exe
        identities.append(machine.succeed("sha256sum < /var/lib/pillar/identity.key"))
        assert http(machine, "GET", "/bootstrap/status").strip() == "FRESH"
    assert len(set(identities)) == 3

    # An independent object recipient, never a daemon's identity or cell key.
    node1.succeed("openssl genpkey -algorithm X25519 -outform DER -out /root/recipient.der")
    secret = node1.succeed("tail -c 32 /root/recipient.der | od -An -v -tx1 | tr -d ' \n'").strip()
    recipient = node1.succeed("openssl pkey -inform DER -in /root/recipient.der -pubout -outform DER | tail -c 32 | od -An -v -tx1 | tr -d ' \n'").strip()
    assert len(secret) == len(recipient) == 64

with subtest("genesis bootstrap and pre-enrollment full cell fixture"):
    # TCG may outlast the CLI HTTP timeout during the KDF. Submit exactly once
    # and require actual bootstrapped state plus a successful independent login.
    rc, output = node1.execute("pillar bootstrap cell fleet-cell --user alice --password "
                               + shlex.quote(password) + " --domain 127.0.0.1:18642 2>&1")
    print(rc, output)
    node1.wait_until_succeeds("curl -fsS http://127.0.0.1:18642/bootstrap/status | grep -Fx BOOTSTRAPPED", timeout=600)
    admin = login(node1)
    node1.succeed("PILLAR_TOKEN=" + shlex.quote(admin)
                  + " pillar config export --domain 127.0.0.1:18642 --out /root/client.yaml")
    client = node1.succeed("cat /root/client.yaml")
    assert "127.0.0.1:18644" in client
    # Only the supported exported client credential is copied, never cell state.
    for machine in nodes:
        machine.succeed("umask 077; printf %s " + shlex.quote(client) + " > /root/client.yaml")
    write(node1, "before-join")

with subtest("both independent joiners require node-join approval"):
    join = "sudo -u pillar pillar bootstrap node"
    args = " --domain node1:18642 --data-dir /var/lib/pillar --identity-key /var/lib/pillar/identity.key"
    for machine in (node2, node3):
        output = machine.succeed(join + args)
        match = re.search(r"^REQUEST (\d+)$", output, re.M)
        assert match, output
        request = match.group(1)
        assert http(machine, "GET", "/bootstrap/status").strip() == "FRESH"
        nonce = http(machine, "GET", "/nonce").split()[1]
        machine.fail("curl -fsS --data-binary " + shlex.quote(f"alice\n{password}\n{nonce}")
                     + " http://127.0.0.1:18642/login")
        machine.succeed("systemctl stop pillar")
        rc, output = machine.execute(join + " complete " + request + args + " 2>&1")
        assert rc != 0 and "DENIED" in output, output
        machine.succeed("test ! -e /var/lib/pillar/enrollment.sealed")
        approved = node1.succeed("PILLAR_TOKEN=" + shlex.quote(admin)
                                 + " pillar bootstrap request approve " + request + " --domain 127.0.0.1:18642")
        assert approved.strip() == "APPROVED " + request
        machine.succeed(join + " complete " + request + args)
        machine.succeed("test $(stat -c '%a:%U' /var/lib/pillar/enrollment.sealed) = 600:pillar")
        machine.succeed("systemctl start pillar")
        ready(machine)
        assert http(machine, "GET", "/bootstrap/status").strip() == "BOOTSTRAPPED"
        assert machine.succeed("sha256sum < /var/lib/pillar/identity.key") == identities[nodes.index(machine)]
        login(machine)
    verify(nodes, "snapshot")

with subtest("post-enrollment live replication to all three nodes"):
    write(node1, "after-join")
    verify(nodes, "live-replication")

with subtest("genesis shutdown leaves two independently writable login portals"):
    # Power off the whole issuer VM, eliminating HTTP and transport fallback.
    node1.shutdown()
    for machine in (node2, node3):
        machine.fail("curl -fsS --connect-timeout 2 --max-time 5 http://node1:18642/bootstrap/status")
        login(machine)
    verify((node2, node3), "genesis-offline")
    for machine in (node2, node3):
        write(machine, "survivor-" + machine.name)
        verify((node2, node3), "survivor-" + machine.name + "-write")

with subtest("both survivors recover durably without genesis"):
    # Read each survivor in isolation so replication cannot repair missing state.
    for machine in (node2, node3):
        machine.succeed("systemctl stop pillar")
    for machine in (node2, node3):
        machine.succeed("systemctl start pillar")
        ready(machine)
        assert http(machine, "GET", "/bootstrap/status").strip() == "BOOTSTRAPPED"
        assert machine.succeed("sha256sum < /var/lib/pillar/identity.key") == identities[nodes.index(machine)]
        login(machine)
        verify((machine,), "isolated-survivor-restart")
        machine.succeed("systemctl stop pillar")
    for machine in (node2, node3):
        machine.succeed("systemctl start pillar")
        ready(machine)
        login(machine)
    verify((node2, node3), "survivor-restart")
