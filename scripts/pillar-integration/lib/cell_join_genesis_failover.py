#!/usr/bin/env python3
"""Black-box enrollment and failover: OCI lifecycle, shipped CLI, and HTTP only."""

import hashlib
import json
from http.client import HTTPConnection, HTTPException
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from urllib.parse import urlencode


def main():
    runtime, image, label, root = sys.argv[1:]
    prefix = "pillar-it-cell-join-" + secrets.token_hex(4)
    nodes = [f"{prefix}-node{i}" for i in range(3)]
    volumes = [f"{prefix}-data{i}" for i in range(3)]
    network = prefix + "-net"
    password = secrets.token_hex(24)
    web = []
    tokens = {}
    dataset = []
    queries = []
    # Independent client recipient, generated with a standard external crypto
    # tool. Never read or copy a daemon's private identity/cell material.
    private = subprocess.run(["openssl", "genpkey", "-algorithm", "X25519", "-outform", "DER"],
                             check=True, capture_output=True).stdout
    public = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                            input=private, check=True, capture_output=True).stdout
    recipient, secret = public[-32:].hex(), private[-32:].hex()

    def run(*args, check=True):
        result = subprocess.run([runtime, *args], text=True, capture_output=True, timeout=120)
        if check and result.returncode:
            # Do not print argv: it can carry a password/session bearer.
            raise AssertionError(f"container command failed: {result.stdout}\n{result.stderr}")
        return result

    def http(i, method, path, body="", query=None):
        if query:
            path += "?" + urlencode(query)
        connection = HTTPConnection(web[i], timeout=10)
        try:
            connection.request(method, path, body.encode())
            response = connection.getresponse()
            return response.status, response.read().decode(), response.getheader("X-Pillar-Session")
        finally:
            connection.close()

    def ok(i, method, path, body="", query=None):
        status, text, _ = http(i, method, path, body, query)
        assert status == 200, f"node{i} {path}: HTTP {status}: {text}"
        return text

    def wait(description, predicate):
        deadline = time.monotonic() + 60
        last = None
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except (OSError, HTTPException, AssertionError) as error:
                last = error
            time.sleep(0.5)
        raise AssertionError(f"timed out: {description}: {last}")

    def cli(i, *args, token=None):
        env = ["-e", f"PILLAR_TOKEN={token}"] if token else []
        return run("exec", *env, nodes[i], "/bin/pillar", *args).stdout

    def login(i):
        nonce = ok(i, "GET", "/nonce").split()[1]
        status, text, token = http(i, "POST", "/login", f"alice\n{password}\n{nonce}")
        assert status == 200 and token, f"node{i} login: {status}: {text}"
        tokens[i] = token
        return token

    def read(i, entry):
        path, key, cid, expected = entry
        return ok(i, "GET", path, query={"token": tokens[i], key: cid}) == expected

    def audit_write(i, collection, *args):
        reply = cli(i, *args)
        match = re.search(r"EVENT-CID (1220[0-9a-f]{64})", reply)
        assert match, reply
        cid = match.group(1)
        for verb in ("show", "verify"):
            query = ("log", verb, collection, cid)
            expected = cli(i, *query)
            assert cid in expected, expected
            if verb == "verify":
                assert "signature-valid: true" in expected and "hash-matches-id: true" in expected
            queries.append((query, expected))
        return reply

    def write(i, phase):
        # Multiple objects, including multiline and large values, preclude a
        # name-only or last-object-only replication oracle.
        for number in range(3):
            value = f"{phase}-{number}-" + secrets.token_hex(2048 * (number + 1))
            name = f"{phase}-{number}"
            text = ok(i, "POST", "/portal/obs/dashboard", f"{tokens[i]}\n{name}: {value}")
            cid = text.split()[1]
            assert re.fullmatch(r"1220[0-9a-f]{64}", cid), text
            expected = ok(i, "GET", "/portal/obs/dashboard/get",
                          query={"token": tokens[i], "id": cid})
            assert f"OBS-DASHBOARD-NAME {name}\n" in expected
            assert f"OBS-DASHBOARD-CONTENT {value}\n" in expected
            dataset.append(("/portal/obs/dashboard/get", "id", cid, expected))
        content = f"{phase}\nlayout={secrets.token_hex(1024)}"
        text = ok(i, "POST", "/portal/layout", f"{tokens[i]}\n{content}")
        cid = text.split()[1]
        assert re.fullmatch(r"1220[0-9a-f]{64}", cid), text
        expected = ok(i, "GET", "/portal/layout", query={"token": tokens[i], "cid": cid})
        assert content in expected
        dataset.append(("/portal/layout", "cid", cid, expected))

        value = secrets.token_hex(256)
        audit_write(i, "failover-kv", "kv", "put", "failover-kv", phase, value)
        queries.append((("kv", "get", "failover-kv", phase), value + "\n"))
        audit_write(i, "failover-doc", "doc", "put", "failover-doc", phase, "value", value)
        queries.append((("doc", "get", "failover-doc", phase, "value"), value + "\n"))
        audit_write(i, phase, "sql", "create-view", phase, "failover-doc", "--eq", "value", value)
        query = ("sql", "view", phase)
        expected = cli(i, *query)
        assert value in expected
        queries.append((query, expected))
        for visibility in ("public", "sealed"):
            flags = ("--recipient", recipient) if visibility == "sealed" else ()
            reply = audit_write(i, "__objects", "object", "put", visibility, value, *flags)
            cid = reply.split()[1]
            query = ("object", "cat", cid, "--secret", secret) if flags else ("object", "cat", cid)
            assert cli(i, *query) == value + "\n"
            queries.append((query, value + "\n"))
            proof = cli(i, "object", "verify", cid)
            assert "hash-matches-cid: true" in proof and "signature-valid: true" in proof, proof
            queries.append((("object", "verify", cid), proof))
            if flags:
                envelope = cli(i, "object", "cat", cid)
                assert envelope.startswith("SEALED ") and value not in envelope
                queries.append((("object", "cat", cid), envelope))
        manifest = (f"apiVersion: pillar.dev/v1\nkind: RetentionPolicy\nmetadata:\n  name: {phase}\n"
                    "spec:\n  signalKind: Metric\n  window: 2592000\n")
        Path(root, phase + ".yaml").write_text(manifest)
        cli(i, "apply", "-f", f"/client/{phase}.yaml")
        query = ("get", "RetentionPolicy", phase)
        expected = cli(i, *query)
        assert phase in expected and "2592000" in expected
        queries.append((query, expected))

    def verify(indices, phase):
        for i in indices:
            for entry in dataset:
                wait(f"{phase} node{i} CID {entry[2]}", lambda: read(i, entry))
            for query, expected in queries:
                wait(f"{phase} node{i} {query[:3]}", lambda: cli(i, *query) == expected)
            digest = hashlib.sha256("".join(e[2] + e[3] for e in dataset).encode()).hexdigest()
            print(f"oracle-observed: {phase} node{i} full-fixture={len(dataset)} "
                  f"CID-identical reads sha256={digest}; data-plane checks={len(queries)}", flush=True)

    try:
        run("network", "create", "--internal", "--label", label, network)
        # Private transport key is fixture configuration, not a copied cell key.
        key = Path(root) / "swarm.key"
        key.write_text("pillar-swarm/v1:" + secrets.token_hex(32) + "\n")
        key.chmod(0o600)
        for i in range(3):
            run("volume", "create", "--label", label, volumes[i])
            dials = ",".join(f"/dns4/{nodes[j]}/tcp/4001" for j in range(i))
            run("run", "-d", "--name", nodes[i], "--label", label, "--network", network,
                "-v", f"{volumes[i]}:/var/lib/pillar/data", "-v", f"{key}:/swarm.key:ro",
                "-v", f"{root}:/client", "-e", "PILLAR_CONFIG=/client/config.yaml",
                "-e", "PILLAR_RESOURCE_OP_UDP_BIND=127.0.0.1:8644",
                "-e", "PILLAR_PUBLIC_RESOURCE_OP_ADDR=127.0.0.1:8644",
                "-e", "PILLAR_SWARM_KEY=/swarm.key", "-e", "PILLAR_LISTEN=/ip4/0.0.0.0/tcp/4001",
                "-e", f"PILLAR_DIAL={dials}", "-e", "PILLAR_WEB_BIND=0.0.0.0",
                "-e", "PILLAR_WEB_PORT=8642", "-p", "127.0.0.1::8642", image)
            web.append(run("port", nodes[i], "8642").stdout.strip())
            wait(f"node{i} ready", lambda: ok(i, "GET", "/bootstrap/status").strip() == "FRESH")
            pid = int(run("inspect", nodes[i], "--format", "{{.State.Pid}}").stdout)
            assert pid > 0
            print(f"oracle-observed: real node{i} pid={pid}", flush=True)

        cli(0, "bootstrap", "cell", "failover-cell", "--user", "alice", "--password", password,
            "--domain", "127.0.0.1:8642")
        output = cli(0, "login", "--domain", "127.0.0.1:8642", "--user", "alice", "--password", password)
        admin = re.search(r"^export PILLAR_TOKEN=(.+)$", output, re.MULTILINE).group(1)
        cli(0, "config", "export", "--domain", "127.0.0.1:8642", "--out", "/client/config.yaml", token=admin)
        login(0)
        write(0, "before-join")

        for i in (1, 2):
            output = cli(i, "bootstrap", "node", "--domain", f"{nodes[0]}:8642",
                         "--data-dir", "/var/lib/pillar/data")
            request_id = re.search(r"^REQUEST (\d+)$", output, re.MULTILINE).group(1)
            assert ok(i, "GET", "/bootstrap/status").strip() == "FRESH"
            nonce = ok(i, "GET", "/nonce").split()[1]
            assert http(i, "POST", "/login", f"alice\n{password}\n{nonce}")[0] != 200
            output = cli(0, "bootstrap", "request", "approve", request_id,
                         "--domain", "127.0.0.1:8642", token=admin)
            assert f"APPROVED {request_id}" in output
            run("stop", "-t", "2", nodes[i])
            run("run", "--rm", "--label", label, "--network", network,
                "-v", f"{volumes[i]}:/var/lib/pillar/data", "--entrypoint", "/bin/pillar", image,
                "bootstrap", "node", "complete", request_id, "--domain", f"{nodes[0]}:8642",
                "--data-dir", "/var/lib/pillar/data")
            run("start", nodes[i])
            wait(f"node{i} enrolled", lambda: ok(i, "GET", "/bootstrap/status").strip() == "BOOTSTRAPPED")
            login(i)
            print(f"oracle-observed: node{i} joined via approved request {request_id}; own portal login", flush=True)

        identities = [ok(i, "GET", "/portal/status", query={"token": tokens[i]}).splitlines()[0]
                      for i in range(3)]
        verify(range(3), "snapshot")
        assert len(set(identities)) == 3, identities
        write(0, "after-join")
        verify(range(3), "live-replication")
        run("stop", "-t", "2", nodes[0])
        assert run("inspect", nodes[0], "--format", "{{.State.Running}}").stdout.strip() == "false"
        print("oracle-observed: genesis stopped; no issuer fallback", flush=True)
        for i in (1, 2):
            login(i)  # Fresh session from each survivor, never a genesis token.
        verify((1, 2), "genesis-offline")
        for i in (1, 2):
            write(i, f"survivor-{i}")
            verify((1, 2), f"survivor-{i}-write")
        # Isolate one survivor so both accept causally concurrent writes from
        # the same client. Each sees its own event before the other's event.
        address = json.loads(run("inspect", nodes[2]).stdout)[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        run("network", "disconnect", network, nodes[2])
        for i in (1, 2):
            phase = f"partition-{i}"
            value = secrets.token_hex(256)
            audit_write(i, "failover-kv", "kv", "put", "failover-kv", phase, value)
            queries.append((("kv", "get", "failover-kv", phase), value + "\n"))
            audit_write(i, "failover-doc", "doc", "put", "failover-doc", phase, "value", value)
            queries.append((("doc", "get", "failover-doc", phase, "value"), value + "\n"))
            audit_write(i, phase, "sql", "create-view", phase, "failover-doc", "--eq", "value", value)
            reply = audit_write(i, "__objects", "object", "put", "public", value)
            queries.append((("object", "cat", reply.split()[1]), value + "\n"))
        run("network", "connect", "--ip", address, "--alias", nodes[2], network, nodes[2])
        web[2] = run("port", nodes[2], "8642").stdout.strip()
        verify((1, 2), "concurrent-survivor-audit")
        # Durable recovery on both survivors with genesis still unavailable.
        for i in (1, 2):
            run("restart", "-t", "2", nodes[i])
            wait(f"node{i} restart", lambda: ok(i, "GET", "/bootstrap/status").strip() == "BOOTSTRAPPED")
            login(i)
        verify((1, 2), "survivor-restart")
    except Exception:
        for node in nodes:
            logs = run("logs", "--tail", "40", node, check=False)
            print(f"diagnostic {node}:\n{logs.stdout}\n{logs.stderr}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
