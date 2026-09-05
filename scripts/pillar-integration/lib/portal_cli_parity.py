#!/usr/bin/env python3
"""portal_cli_parity.py — the web-portal / CLI surface-parity gap detector,
run by the pillar-integration `portal-cli-parity` scenario against the REAL
surface inventory a running node serves at `GET /surface-inventory`.

It is the black-box twin of the in-tree Rust detector
(`pillar_surface_inventory::surface_parity`): it consumes the SAME
`pillar-integration/v1` inventory the real image emits and applies the SAME
declarative parity map, so a parity gap it reports is a REAL detected diff
against the live served surfaces — a CLI verb with no portal counterpart, or a
portal route family with no CLI counterpart — never a hand-maintained
checklist. The Rust acceptance test
(`crates/pillar-e2e/tests/portal_cli_parity.rs`) keeps this map and the Rust
one in agreement (both must be GREEN against the real registries); this script
is what an EXTERNAL, black-box caller uses to assert the same thing over the
wire.

Usage:  portal_cli_parity.py <inventory.json>
Reads the `pillar-integration/v1` inventory document from the given file (or
`-` for stdin). Prints one `parity-observed: ...` line per paired surface and,
on any gap, one `parity-gap: ...` line per gap. Exit 0 = GREEN (every CLI verb
and portal route family pairs); exit 1 = RED (>=1 gap) — the RED/GREEN oracle.
"""

import json
import sys

# (cli-verb, portal-route-prefix) pairs — a CLI verb and the portal route
# family that is its counterpart. Mirrors PARITY_MAP's ParityRule::Paired.
PAIRED = [
    ("surface-inventory", "/surface-inventory"),
    ("bootstrap", "/bootstrap"),
    ("webauthn", "/webauthn"),
    ("login", "/login"),
    ("session", "/portal/sessions"),
    ("identity", "/portal/identity"),
    ("user", "/portal/members"),
    ("domain", "/portal/domains"),
    ("attest", "/portal/attestations"),
    ("trust", "/portal/trust-graph"),
    ("obs", "/portal/obs"),
    ("key", "/portal/custody"),
    ("apply", "/portal/resource"),
    ("space", "/portal/topology"),
    ("request", "/bootstrap/request"),
]

# CLI verbs deliberately without a portal route (ParityRule::CliOnly).
CLI_ONLY = {
    "--web", "node", "offer", "grant", "caps", "revoke", "audit", "cell",
    "peer", "lease", "stream", "render", "onboard",
    "secrets-audit-rotation-mfa", "explain", "completion", "get", "describe",
}

# Portal route families deliberately without a CLI verb (ParityRule::PortalOnly).
PORTAL_ONLY = ["/nonce", "/portal/status", "/portal/layout", "/"]


def route_path(entry):
    sig = entry.get("signature", "")
    parts = sig.split(" ", 1)
    return parts[1] if len(parts) == 2 else ""


def route_under(paths, prefix):
    if prefix == "/":
        return any(p == "/" for p in paths)
    return any(p.startswith(prefix) for p in paths)


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: portal_cli_parity.py <inventory.json|->\n")
        return 2
    raw = sys.stdin.read() if sys.argv[1] == "-" else open(sys.argv[1]).read()
    doc = json.loads(raw)
    if doc.get("schema") != "pillar-integration/v1":
        sys.stderr.write(
            "parity-gap: inventory is not a pillar-integration/v1 document "
            "(schema=%r)\n" % doc.get("schema")
        )
        return 1

    entries = doc.get("surface_inventory", [])
    cli_verbs = sorted(
        e["id"][len("cli:"):] for e in entries if e.get("kind") == "cli-verb"
    )
    route_paths = sorted(
        {route_path(e) for e in entries if e.get("kind") == "http-route"}
    )

    gaps = []

    # 1. Every declared pairing must still match the served tables.
    for verb, prefix in PAIRED:
        if verb not in cli_verbs:
            gaps.append(
                "parity map names CLI verb `%s` but it is not served (stale mapping)"
                % verb
            )
        if not route_under(route_paths, prefix):
            gaps.append(
                "parity map names portal route prefix `%s` but no served route "
                "starts with it (stale mapping)" % prefix
            )
        if verb in cli_verbs and route_under(route_paths, prefix):
            print("parity-observed: cli `%s` <-> portal `%s`" % (verb, prefix))
    for prefix in PORTAL_ONLY:
        if not route_under(route_paths, prefix):
            gaps.append(
                "parity map names portal route prefix `%s` but no served route "
                "starts with it (stale mapping)" % prefix
            )

    paired_verbs = {v for v, _ in PAIRED}

    # 2. Every served CLI verb must be covered (paired or recorded CLI-only).
    for verb in cli_verbs:
        if verb not in paired_verbs and verb not in CLI_ONLY:
            gaps.append(
                "CLI verb `%s` has no portal counterpart (no rule pairs it and "
                "it is not recorded CLI-only)" % verb
            )

    # 3. Every served portal route must be covered (paired or portal-only).
    paired_prefixes = [p for _, p in PAIRED] + PORTAL_ONLY
    for path in route_paths:
        covered = False
        for prefix in paired_prefixes:
            if prefix == "/":
                if path == "/":
                    covered = True
                    break
            elif path.startswith(prefix):
                covered = True
                break
        if not covered:
            gaps.append(
                "portal route `%s` has no CLI counterpart (no rule pairs it and "
                "it is not recorded portal-only)" % path
            )

    if gaps:
        for g in gaps:
            sys.stderr.write("parity-gap: %s\n" % g)
        return 1

    print(
        "parity-observed: GREEN — every one of %d CLI verbs and %d portal route "
        "families pairs against a served counterpart"
        % (len(cli_verbs), len(route_paths))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
