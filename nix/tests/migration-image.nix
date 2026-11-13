# checks.x86_64-linux.migration-image — executes the ASSEMBLED pillar OCI image
# (packages.pillar-oci-image, the artifact build-image publishes) under podman
# in a VM. Inside the image, using only the image's own tools, it builds an
# isolated real legacy cell, takes a verified whole-tree GNU tar backup,
# performs the acknowledged conversion with an injected crash + resume, and
# asserts the retained op count/root (nix/tests/migration-image.sh). The
# image's node-run defaults (entrypoint/env) are asserted unchanged.
{ self, image, ... }:
{
  name = "pillar-migration-image";
  nodes.machine = { ... }: {
    virtualisation.podman.enable = true;
    virtualisation.memorySize = 3072;
    virtualisation.diskSize = 4096;
  };
  testScript = ''
    import json
    start_all()
    machine.succeed("${image} | podman load")
    cfg = json.loads(machine.succeed("podman image inspect localhost/pillar:latest"))[0]["Config"]
    assert cfg["Entrypoint"] == ["/bin/pillar", "node", "run"], cfg
    env = set(cfg["Env"])
    for e in ["PILLAR_DATA_DIR=/var/lib/pillar/data",
              "PILLAR_IDENTITY_KEY=/var/lib/pillar/data/identity.key",
              "PILLAR_LISTEN=/ip4/0.0.0.0/tcp/0"]:
        assert e in env, cfg
    assert cfg["WorkingDir"] == "/var/lib/pillar", cfg
    machine.succeed("mkdir -p /work && cp ${./migration-image.sh} /work/migrate.sh")
    out = machine.succeed(
        "podman run --rm --network host -v /work:/work "
        "--entrypoint /bin/bash localhost/pillar:latest /work/migrate.sh 2>&1",
        timeout=1200)
    print(out)
    r = json.loads(machine.succeed("cat /work/result.json"))
    assert r["state"] == "committed" and r["crash_state"] == "staged", r
    assert r["ops"] > 2 and len(r["root"]) > 0, r
    assert "GNU tar" in r["tar"] and r["backup_files"] > 0, r
  '';
}
