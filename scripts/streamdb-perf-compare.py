#!/usr/bin/env python3
"""Compare StreamDB timings; only --update-baseline may create/change a baseline."""

import argparse
import json
import math
from pathlib import Path
import sys


WORKLOAD_FIELDS = ("op_count", "fold_count", "payload_bytes", "samples")
RAW_METRICS = (
    "public_op_ns", "encrypted_op_ns", "public_fold_ns", "encrypted_fold_ns",
)
DELTA_METRICS = ("op_delta_pct", "fold_delta_pct")
METRICS = RAW_METRICS + DELTA_METRICS
REPORT_KEYS = ("schema_version",) + WORKLOAD_FIELDS + METRICS


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"nonfinite JSON number: {value}")


def load_json(path):
    return json.loads(
        Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )


def exact_keys(value, keys, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    missing = set(keys) - value.keys()
    extra = value.keys() - set(keys)
    if missing or extra:
        raise ValueError(
            f"{label}: missing keys {sorted(missing)}, extra keys {sorted(extra)}"
        )


def finite_number(value, label):
    if type(value) not in (int, float):
        raise ValueError(f"{label} must be a finite number (not bool)")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError(f"{label} must be a finite number")


def validate_report(report):
    exact_keys(report, REPORT_KEYS, "measurement")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise ValueError("schema_version must be integer 1")
    for key in WORKLOAD_FIELDS:
        if type(report[key]) is not int or report[key] <= 0:
            raise ValueError(f"{key} must be a positive integer")
    if report["samples"] < 3 or report["samples"] % 2 == 0:
        raise ValueError("samples must be odd and >= 3")
    for key in METRICS:
        finite_number(report[key], key)
        if key in RAW_METRICS and report[key] <= 0:
            raise ValueError(f"{key} must be positive")
        if key in DELTA_METRICS and report[key] <= -100:
            raise ValueError(f"{key} must be > -100")
    for operation in ("op", "fold"):
        key = f"{operation}_delta_pct"
        expected = (
            report[f"encrypted_{operation}_ns"] / report[f"public_{operation}_ns"]
            - 1
        ) * 100
        if not math.isfinite(expected) or not math.isclose(
            report[key], expected, rel_tol=0, abs_tol=0.001
        ):
            raise ValueError(f"{key} is inconsistent with raw timings")
    return report


def validate_baseline(baseline, report):
    exact_keys(baseline, ("measurement", "limits"), "baseline")
    measurement = validate_report(baseline["measurement"])
    limits = baseline["limits"]
    exact_keys(limits, METRICS, "limits")
    for key in METRICS:
        finite_number(limits[key], f"limits.{key}")
        if key in RAW_METRICS and limits[key] <= 0:
            raise ValueError(f"limits.{key} must be positive")
        if key in DELTA_METRICS and limits[key] < 0:
            raise ValueError(f"limits.{key} must be >= 0")
        if limits[key] < measurement[key]:
            raise ValueError(f"limits.{key} is below baseline measurement")
    for key in WORKLOAD_FIELDS:
        if measurement[key] != report[key]:
            raise ValueError(f"workload mismatch: {key}")
    return baseline


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("baseline", metavar="BASELINE", type=Path)
    parser.add_argument("report", metavar="REPORT", type=Path)
    args = parser.parse_args(argv)
    try:
        report = validate_report(load_json(args.report))
        if args.update_baseline:
            baseline = {
                "measurement": report,
                "limits": {
                    key: report[key] * 1.25 if key in RAW_METRICS
                    else max(0, report[key]) + 10
                    for key in METRICS
                },
            }
            # Validate derived limits too: finite inputs can overflow on scaling.
            validate_baseline(baseline, report)
            content = json.dumps(baseline, indent=2, allow_nan=False) + "\n"
            args.baseline.write_text(content, encoding="utf-8")
            print(f"Updated baseline: {args.baseline}")
            return 0
        baseline = validate_baseline(load_json(args.baseline), report)
        failed = False
        for key in METRICS:
            value, target = report[key], baseline["limits"][key]
            regression = value > target
            failed |= regression
            unit = "ns" if key in RAW_METRICS else "percentage points"
            print(
                f"{key}: value={value:.9g} target={target:.9g} "
                f"headroom={target - value:.9g} {unit} "
                f"{'FAIL' if regression else 'PASS'}"
            )
        return 1 if failed else 0
    except (OSError, ValueError, UnicodeError, OverflowError, RecursionError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
