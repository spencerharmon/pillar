#!/usr/bin/env python3
"""Stdlib-only schema and CLI regression tests for the StreamDB comparator."""

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("streamdb-perf-compare.py")
SPEC = importlib.util.spec_from_file_location("streamdb_perf_compare", SCRIPT)
compare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare)


def measurement():
    return {
        "schema_version": 1,
        "op_count": 2000,
        "fold_count": 2000,
        "payload_bytes": 1024,
        "samples": 7,
        "public_op_ns": 100.0,
        "encrypted_op_ns": 110.0,
        "public_fold_ns": 200.0,
        "encrypted_fold_ns": 220.0,
        "op_delta_pct": 10.0,
        "fold_delta_pct": 10.0,
    }


def refresh_deltas(report):
    for operation in ("op", "fold"):
        report[f"{operation}_delta_pct"] = (
            report[f"encrypted_{operation}_ns"] / report[f"public_{operation}_ns"]
            - 1
        ) * 100


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.baseline_path = Path(self.temp.name) / "baseline.json"
        self.report_path = Path(self.temp.name) / "report.json"
        self.report = measurement()
        self.baseline = {
            "measurement": measurement(),
            "limits": {
                "public_op_ns": 125.0,
                "encrypted_op_ns": 137.5,
                "public_fold_ns": 250.0,
                "encrypted_fold_ns": 275.0,
                "op_delta_pct": 20.0,
                "fold_delta_pct": 20.0,
            },
        }
        self.write_inputs()

    def write_inputs(self):
        self.report_path.write_text(json.dumps(self.report), encoding="utf-8")
        self.baseline_path.write_text(json.dumps(self.baseline), encoding="utf-8")

    def run_main(self, update=False):
        stdout, stderr = io.StringIO(), io.StringIO()
        args = (["--update-baseline"] if update else []) + [
            str(self.baseline_path), str(self.report_path),
        ]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = compare.main(args)
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_malformed(self):
        self.write_inputs()
        status, stdout, stderr = self.run_main()
        self.assertEqual(status, 2, (stdout, stderr))
        self.assertEqual(stdout, "")
        self.assertIn("error:", stderr)

    def cli(self, *options):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *options,
             str(self.baseline_path), str(self.report_path)],
            capture_output=True, text=True, check=False,
        )

    def test_pass_prints_all_six_metrics_without_changing_baseline(self):
        before = self.baseline_path.read_bytes()
        status, stdout, stderr = self.run_main()
        self.assertEqual(status, 0, stderr)
        self.assertEqual(len(stdout.splitlines()), 6)
        for key in compare.METRICS:
            self.assertIn(f"{key}: value=", stdout)
        self.assertEqual(stdout.count("target="), 6)
        self.assertEqual(stdout.count("headroom="), 6)
        self.assertEqual(self.baseline_path.read_bytes(), before)

    def test_each_raw_profile_regresses_independently(self):
        for key in compare.RAW_METRICS:
            with self.subTest(key=key):
                self.report = measurement()
                self.report[key] = self.baseline["limits"][key] + 1
                refresh_deltas(self.report)
                # Isolate raw failures from the separate overhead ceilings.
                for delta in compare.DELTA_METRICS:
                    self.baseline["limits"][delta] = 1000
                self.write_inputs()
                status, stdout, stderr = self.run_main()
                self.assertEqual(status, 1, stderr)
                failures = [line for line in stdout.splitlines() if "FAIL" in line]
                self.assertEqual(len(failures), 1)
                self.assertTrue(failures[0].startswith(key + ":"))
                self.assertEqual(len(stdout.splitlines()), 6)

    def test_isolated_delta_growth_with_all_raw_metrics_within_limits(self):
        for operation in ("op", "fold"):
            with self.subTest(operation=operation):
                self.report = measurement()
                self.report[f"encrypted_{operation}_ns"] *= 1.15
                refresh_deltas(self.report)
                for key in compare.RAW_METRICS:
                    self.assertLessEqual(self.report[key], self.baseline["limits"][key])
                self.write_inputs()
                status, stdout, stderr = self.run_main()
                self.assertEqual(status, 1, stderr)
                failures = [line for line in stdout.splitlines() if "FAIL" in line]
                self.assertEqual(len(failures), 1)
                self.assertTrue(failures[0].startswith(f"{operation}_delta_pct:"))

    def test_inclusive_limits(self):
        for key in compare.METRICS:
            self.baseline["limits"][key] = self.report[key]
        self.write_inputs()
        self.assertEqual(self.run_main()[0], 0)

    def test_every_required_key_in_report_measurement_and_limits(self):
        original = copy.deepcopy(self.baseline)
        for location, keys in (
            ("report", compare.REPORT_KEYS),
            ("measurement", compare.REPORT_KEYS),
            ("limits", compare.METRICS),
            ("baseline", ("measurement", "limits")),
        ):
            for key in keys:
                with self.subTest(location=location, key=key):
                    self.report = measurement()
                    self.baseline = copy.deepcopy(original)
                    target = self.report if location == "report" else (
                        self.baseline if location == "baseline" else self.baseline[location]
                    )
                    del target[key]
                    self.assert_malformed()

    def test_invalid_numeric_values_in_every_metric(self):
        original = copy.deepcopy(self.baseline)
        for location in ("report", "measurement", "limits"):
            for key in compare.METRICS:
                bad_values = [float("nan"), float("inf"), -float("inf"),
                              True, False, "10", None, [], {}, 10 ** 400]
                bad_values += [0, -1] if key in compare.RAW_METRICS else (
                    [-1] if location == "limits" else [-100, -101]
                )
                for value in bad_values:
                    with self.subTest(location=location, key=key, value=value):
                        self.report = measurement()
                        self.baseline = copy.deepcopy(original)
                        target = self.report if location == "report" else self.baseline[location]
                        target[key] = value
                        self.assert_malformed()

    def test_invalid_counts_and_schema(self):
        for location in ("report", "measurement"):
            for key in ("schema_version",) + compare.WORKLOAD_FIELDS:
                invalid = [True, False, 0, -1, 1.0, "7", None,
                           float("nan"), float("inf")]
                if key == "samples":
                    invalid += [1, 2, 4, 8]
                if key == "schema_version":
                    invalid += [2]
                for value in invalid:
                    with self.subTest(location=location, key=key, value=value):
                        self.report = measurement()
                        self.baseline["measurement"] = measurement()
                        target = self.report if location == "report" else self.baseline[location]
                        target[key] = value
                        self.assert_malformed()

    def test_workload_mismatch_for_every_field(self):
        for key in compare.WORKLOAD_FIELDS:
            with self.subTest(key=key):
                self.report = measurement()
                self.report[key] += 2
                self.assert_malformed()

    def test_inconsistent_deltas_and_absolute_only_tolerance(self):
        for location in ("report", "measurement"):
            for key in compare.DELTA_METRICS:
                for offset in (0.002, -0.002):
                    with self.subTest(location=location, key=key, offset=offset):
                        self.report = measurement()
                        self.baseline["measurement"] = measurement()
                        target = self.report if location == "report" else self.baseline[location]
                        target[key] += offset
                        self.assert_malformed()
        report = measurement()
        report["op_delta_pct"] += 0.0009
        compare.validate_report(report)
        report["encrypted_op_ns"] = 1e12
        refresh_deltas(report)
        report["op_delta_pct"] += 0.1
        with self.assertRaises(ValueError):
            compare.validate_report(report)

    def test_negative_noise_and_zero_delta_are_valid(self):
        for encrypted in (90.0, 100.0):
            with self.subTest(encrypted=encrypted):
                self.report["encrypted_op_ns"] = encrypted
                self.report["encrypted_fold_ns"] = encrypted * 2
                refresh_deltas(self.report)
                self.write_inputs()
                self.assertEqual(self.run_main()[0], 0)
                self.assertEqual(self.run_main(update=True)[0], 0)
                updated = compare.load_json(self.baseline_path)
                for key in compare.DELTA_METRICS:
                    self.assertEqual(updated["limits"][key], 10)
        self.baseline["measurement"] = copy.deepcopy(self.report)
        for key in compare.DELTA_METRICS:
            self.baseline["limits"][key] = 0
        self.write_inputs()
        self.assertEqual(self.run_main()[0], 0)

    def test_limits_cannot_be_below_measurement(self):
        for key in compare.METRICS:
            with self.subTest(key=key):
                old = self.baseline["limits"][key]
                self.baseline["limits"][key] = self.baseline["measurement"][key] - 1
                self.assert_malformed()
                self.baseline["limits"][key] = old

    def test_extra_keys_and_non_object_containers(self):
        original = copy.deepcopy(self.baseline)
        for location in ("report", "baseline", "measurement", "limits"):
            for value in ([], None, 1, "object", {"extra": 1}):
                with self.subTest(location=location, value=value):
                    self.report = measurement()
                    self.baseline = copy.deepcopy(original)
                    if isinstance(value, dict):
                        target = self.report if location == "report" else (
                            self.baseline if location == "baseline" else self.baseline[location]
                        )
                        target.update(value)
                    elif location == "report":
                        self.report = value
                    elif location == "baseline":
                        self.baseline = value
                    else:
                        self.baseline[location] = value
                    self.assert_malformed()

    def test_malformed_json_and_duplicate_keys_at_every_level(self):
        for path in (self.report_path, self.baseline_path):
            for text in ("", "{", "{} {}", '{"x":1,}', "NaN", "Infinity", "-Infinity"):
                with self.subTest(path=path.name, text=text):
                    self.write_inputs()
                    path.write_text(text, encoding="utf-8")
                    self.assertEqual(self.run_main()[0], 2)
        for path, original, needle in (
            (self.report_path, self.report, '"public_op_ns": 100.0'),
            (self.report_path, self.report, '"schema_version": 1'),
            (self.baseline_path, self.baseline, '"public_op_ns": 100.0'),
            (self.baseline_path, self.baseline, '"public_op_ns": 125.0'),
            (self.baseline_path, self.baseline, '"measurement":'),
        ):
            with self.subTest(path=path.name, needle=needle):
                self.write_inputs()
                duplicate = needle + " {}, " + needle if needle.endswith(":") else (
                    needle + ", " + needle
                )
                path.write_text(json.dumps(original).replace(needle, duplicate, 1), encoding="utf-8")
                status, _, stderr = self.run_main()
                self.assertEqual(status, 2)
                self.assertIn("duplicate JSON key", stderr)
        self.write_inputs()
        self.report_path.write_text(
            json.dumps(self.report).replace('"public_op_ns": 100.0', '"public_op_ns": 1e999'),
            encoding="utf-8",
        )
        self.assertEqual(self.run_main()[0], 2)

    def test_explicit_update_cli_creates_and_replaces_baseline(self):
        self.baseline_path.unlink()
        for existing in (False, True):
            with self.subTest(existing=existing):
                if existing:
                    self.baseline_path.write_text("old invalid baseline", encoding="utf-8")
                result = self.cli("--update-baseline")
                self.assertEqual(result.returncode, 0, result.stderr)
                updated = compare.load_json(self.baseline_path)
                self.assertEqual(updated["measurement"], self.report)
                self.assertEqual(updated["limits"], self.baseline["limits"])
                result = self.cli()
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_baseline_cli_never_bootstraps(self):
        self.baseline_path.unlink()
        result = self.cli()
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.baseline_path.exists())

    def test_missing_report_cli_compare_and_update(self):
        before = self.baseline_path.read_bytes()
        self.report_path.unlink()
        for options in ((), ("--update-baseline",)):
            result = self.cli(*options)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(self.baseline_path.read_bytes(), before)

    def test_invalid_update_never_touches_baseline(self):
        invalid_reports = []
        for key in compare.REPORT_KEYS:
            report = measurement()
            del report[key]
            invalid_reports.append(json.dumps(report))
        report = measurement()
        report["op_delta_pct"] = 15
        invalid_reports.append(json.dumps(report))
        report = measurement()
        for key in compare.RAW_METRICS:
            report[key] = 1.7e308
        refresh_deltas(report)
        invalid_reports.append(json.dumps(report))
        invalid_reports += ["{", '{"x": 1, "x": 2}', "NaN"]
        for existing in (True, False):
            for text in invalid_reports:
                with self.subTest(existing=existing, text=text):
                    if existing:
                        self.baseline_path.write_bytes(b"keep exactly\n")
                    else:
                        self.baseline_path.unlink(missing_ok=True)
                    self.report_path.write_text(text, encoding="utf-8")
                    self.assertEqual(self.run_main(update=True)[0], 2)
                    if existing:
                        self.assertEqual(self.baseline_path.read_bytes(), b"keep exactly\n")
                    else:
                        self.assertFalse(self.baseline_path.exists())

    def test_regression_cli_exit_one(self):
        self.report["encrypted_op_ns"] = 130
        refresh_deltas(self.report)
        self.write_inputs()
        self.assertEqual(self.cli().returncode, 1)


if __name__ == "__main__":
    unittest.main()
