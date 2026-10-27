import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dashboard_data import coverage_notes
from dashboard_export import review_data, review_json
from differ import compare_with_lockfile
from isolation import IsolationError, _runtime, preflight
from lockfile import load_lockfile, save_lockfile
from schema import load_report, validate_lock, validate_report


FIXTURES = ROOT / "tests" / "fixtures" / "phase9"


class Phase9UnitTests(unittest.TestCase):
    def test_unsupported_platforms_refuse_before_target_execution(self):
        with patch("isolation.sys.platform", "darwin"):
            with self.assertRaisesRegex(IsolationError, "Linux only"):
                _runtime()
        with patch("isolation.sys.platform", "win32"):
            with self.assertRaisesRegex(IsolationError, "Linux only"):
                _runtime()
        with patch("isolation.os.geteuid", return_value=0):
            with self.assertRaisesRegex(IsolationError, "unprivileged"):
                _runtime()
        with patch("isolation.sys.version_info", (3, 13)):
            with self.assertRaisesRegex(IsolationError, "CPython 3.14"):
                _runtime()
        with patch("isolation.shutil.which", return_value=None):
            with self.assertRaisesRegex(IsolationError, "Bubblewrap is missing"):
                _runtime()
        with patch("isolation.subprocess.run", return_value=SimpleNamespace(
                returncode=0, stdout="cpython 3 13\n")):
            with self.assertRaisesRegex(IsolationError, "/usr/bin/python3 must be"):
                _runtime()
        with patch("isolation._runtime", return_value=("/usr/bin/bwrap", "/usr/bin/python3")), \
                patch("isolation.subprocess.run", return_value=SimpleNamespace(
                    returncode=1, stderr="operation not permitted")):
            with self.assertRaisesRegex(IsolationError, "user namespaces and AppArmor"):
                preflight()

    def test_saved_lock_versions_round_trip_and_coverage(self):
        for version, name in (("1.0", "lock_1_0.json"),
                              ("1.1", "lock_1_1.json"),
                              ("2.0", "lock_2_0.json")):
            lock = load_lockfile(FIXTURES / name)
            self.assertEqual(lock["schema_version"], version)
            with tempfile.TemporaryDirectory() as folder:
                target = Path(folder) / name
                save_lockfile(lock, target)
                self.assertEqual(load_lockfile(target), lock)
            if version != "2.0":
                self.assertNotIn("capabilities_by_horizon", lock)
        old = load_lockfile(FIXTURES / "lock_1_0.json")
        report = load_report(FIXTURES / "report_complete_2_0.json")
        self.assertIn("Old lock:", " ".join(coverage_notes(report, old)))
        bad = copy.deepcopy(old)
        bad["schema_version"] = "9.0"
        with self.assertRaisesRegex(ValueError, "unsupported"):
            validate_lock(bad)

    def test_reports_keep_health_and_evidence_requirements(self):
        complete = load_report(FIXTURES / "report_complete_2_0.json")
        incomplete = load_report(FIXTURES / "report_incomplete_2_0.json")
        legacy = load_report(FIXTURES / "report_legacy.json")
        self.assertEqual((complete["verdict"], incomplete["verdict"], legacy["verdict"]),
                         ("CLEAN", "INCOMPLETE", "INCOMPLETE"))
        self.assertNotIn("CLEAN", review_json(review_data(legacy)))
        for key in ("run_health", "events", "canary_evidence"):
            bad = copy.deepcopy(complete)
            del bad[key]
            with self.assertRaises(ValueError):
                validate_report(bad)
        for key in ("execution_backend", "transmission_status"):
            bad = copy.deepcopy(complete)
            del bad[key]
            with self.assertRaisesRegex(ValueError, "containment or transmission"):
                validate_report(bad)
        bad = copy.deepcopy(complete)
        del bad["run_health"]["0"]["network_isolated"]
        with self.assertRaisesRegex(ValueError, "invalid report hour"):
            validate_report(bad)
        bad = copy.deepcopy(complete)
        bad["verdict"] = "CLEAN"
        bad["run_health"]["0"]["complete"] = False
        with self.assertRaisesRegex(ValueError, "cannot be clean"):
            validate_report(bad)
        bad = copy.deepcopy(complete)
        bad["canary_evidence"]["0"] = [{"name": "TOKEN", "channel": "network_attempt",
                                         "event_id": 1}]
        with self.assertRaisesRegex(ValueError, "evidence reference"):
            validate_report(bad)
        bad = copy.deepcopy(complete)
        bad["schema_version"] = "9.0"
        with self.assertRaisesRegex(ValueError, "unsupported"):
            validate_report(bad)

    def test_old_lock_comparison_does_not_invent_time_coverage(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "sample.py"
            target.write_text("pass\n", encoding="utf-8")
            runs = {"target_script": str(target), "horizons_tested": [0],
                    "runs": {"0": {"complete": True, "backend": "bubblewrap",
                                    "network_isolated": True, "events": [], "summary": {}}}}
            old = compare_with_lockfile(load_lockfile(FIXTURES / "lock_1_0.json"), runs)
            current = compare_with_lockfile(load_lockfile(FIXTURES / "lock_2_0.json"), runs)
            self.assertEqual(old["verdict"], "WARNING")
            self.assertEqual(old["temporal_coverage_missing"], [0])
            self.assertEqual(current["verdict"], "CLEAN")


if __name__ == "__main__":
    unittest.main()
