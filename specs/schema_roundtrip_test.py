#!/usr/bin/env python3
"""Schema round-trip conformance test for the pillar-integration rig contract.

Parses the fixture surface-inventory + scenario-declaration document into the
rig's in-memory model, re-serialises it through the SAME canonical serialiser,
and asserts byte-for-byte equality against the canonicalised fixture. This is
the executable half of the `pillar-integration-spec` contract (the TLA+ model
`PillarIntegration.tla` is the other half): it pins the on-disk schema so any
drift in the parse<->serialise pair is caught.

It also validates the two cross-checks the schema itself must satisfy, mirroring
the TLA+ invariants `ClaimsTargetRealSurface` and `Gate1_NoOrphan`:
  * every scenario claim targets a REAL inventory entry (no dangling claim);
  * no inventory entry is orphaned (every entry claimed by some scenario).

Run standalone (`python3 schema_roundtrip_test.py`) or under unittest; exits
non-zero on any failure. Uses only the Python standard library so it runs in the
hermetic check sandbox with no third-party install.
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixtures", "rig-schema.json")

# ---- the rig's in-memory model -------------------------------------------

VALID_ORACLES = {
    "packet",
    "ciphertext",
    "process",
    "content-address",
    "crypto-realness",
    "state-survival",
}

VALID_KINDS = {"cli-verb", "http-route", "manifest-kind", "wire-op"}


class SchemaError(ValueError):
    pass


def parse(doc):
    """Parse the raw JSON doc into the canonical rig model (nested dict/list).

    Raises SchemaError on any structural violation so a malformed document can
    never silently round-trip.
    """
    if doc.get("schema") != "pillar-integration/v1":
        raise SchemaError("unknown or missing schema tag")

    inventory = []
    seen_ids = set()
    for entry in doc["surface_inventory"]:
        eid = entry["id"]
        if eid in seen_ids:
            raise SchemaError("duplicate inventory id: %r" % eid)
        seen_ids.add(eid)
        if entry["kind"] not in VALID_KINDS:
            raise SchemaError("bad surface kind: %r" % entry["kind"])
        inventory.append(
            {"id": eid, "kind": entry["kind"], "signature": entry["signature"]}
        )

    scenarios = []
    seen_sc = set()
    for sc in doc["scenarios"]:
        sid = sc["id"]
        if sid in seen_sc:
            raise SchemaError("duplicate scenario id: %r" % sid)
        seen_sc.add(sid)
        if sc["oracle"] not in VALID_ORACLES:
            raise SchemaError("unknown oracle: %r" % sc["oracle"])
        skip = sc["skip"]
        if skip is not None:
            skip = {"reason": skip["reason"], "deadline": skip["deadline"]}
        scenarios.append(
            {
                "id": sid,
                "claims": list(sc["claims"]),
                "oracle": sc["oracle"],
                "skip": skip,
            }
        )

    return {
        "schema": "pillar-integration/v1",
        "surface_inventory": inventory,
        "scenarios": scenarios,
    }


def serialize(model):
    """Canonical serialiser: sorted keys, fixed 2-space indent, trailing NL.

    Serialisation is the inverse of parse() over the canonical fixture, so
    parse->serialize is the identity on a canonical document.
    """
    return json.dumps(model, indent=2, sort_keys=True) + "\n"


def canonicalize_raw(raw_text):
    """Canonicalise arbitrary fixture text the same way serialize() emits, so
    the equality assertion is about STRUCTURE, not incidental whitespace."""
    return serialize(json.loads(raw_text))


# ---- cross-checks (mirror the TLA+ coverage-gate invariants) --------------


def claims_target_real_surface(model):
    ids = {e["id"] for e in model["surface_inventory"]}
    for sc in model["scenarios"]:
        for c in sc["claims"]:
            if c not in ids:
                raise SchemaError(
                    "scenario %r claims unknown surface %r" % (sc["id"], c)
                )


def no_orphan_surface(model):
    claimed = set()
    for sc in model["scenarios"]:
        claimed.update(sc["claims"])
    for e in model["surface_inventory"]:
        if e["id"] not in claimed:
            raise SchemaError("orphan inventory entry (Gate 1): %r" % e["id"])


class SchemaRoundTripTest(unittest.TestCase):
    def setUp(self):
        with open(FIXTURE, "r", encoding="utf-8") as fh:
            self.raw = fh.read()
        self.model = parse(json.loads(self.raw))

    def test_roundtrip_is_identity(self):
        """parse -> serialize equals the canonicalised fixture, byte for byte."""
        emitted = serialize(self.model)
        canonical = canonicalize_raw(self.raw)
        self.assertEqual(
            emitted,
            canonical,
            "schema round-trip is NOT the identity: parse/serialize drift",
        )

    def test_second_roundtrip_is_stable(self):
        """serialize is idempotent: re-parsing the emitted text and
        re-serialising yields the same bytes (no accumulating drift)."""
        once = serialize(self.model)
        twice = serialize(parse(json.loads(once)))
        self.assertEqual(once, twice, "serialisation is not idempotent")

    def test_claims_target_real_surface(self):
        claims_target_real_surface(self.model)  # raises on violation

    def test_no_orphan_surface(self):
        no_orphan_surface(self.model)  # raises on violation

    def test_malformed_is_rejected(self):
        """A claim on a non-existent surface must be REJECTED, proving the
        check has teeth (it would FAIL to catch drift if it accepted anything)."""
        bad = json.loads(self.raw)
        bad["scenarios"][0]["claims"].append("cli:does-not-exist")
        with self.assertRaises(SchemaError):
            claims_target_real_surface(parse(bad))


if __name__ == "__main__":
    # Return a non-zero exit on any failure so check.sh can gate on it.
    result = unittest.main(exit=False, verbosity=2).result
    sys.exit(0 if result.wasSuccessful() else 1)
