import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from isolation import preflight
from package_runner import exercise_spec, run_package_horizons
from runner import run_in_sandbox
from test_6 import wheel


def marked_processes(marker):
    found = []
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            if marker.encode() in path.read_bytes():
                found.append(path)
        except OSError:
            pass
    return found


class Phase9IntegrationTests(unittest.TestCase):
    def test_preflight_and_clock_coverage(self):
        self.assertEqual(preflight()[1], "/usr/bin/python3")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "clock.py"
            path.write_text(textwrap.dedent("""
                import datetime, json, os, time
                before = time.time()
                time.sleep(3600)
                print(json.dumps({'time': time.time(),
                                  'datetime': datetime.datetime.now(datetime.timezone.utc).timestamp(),
                                  'monotonic': time.monotonic(),
                                  'perf_counter': time.perf_counter(),
                                  'time_ns': time.time_ns() / 1e9,
                                  'clock_gettime': time.clock_gettime(time.CLOCK_REALTIME),
                                  'mtime': os.path.getmtime(__file__),
                                  'sleep_delta': time.time() - before}))
            """), encoding="utf-8")
            original = (path.read_bytes(), path.stat().st_mtime_ns)
            real_start = time.time()
            run = run_in_sandbox(path, offset_hours=72, backdate_mtime_hours=24)
            self.assertTrue(run["complete"], run["stderr"])
            values = json.loads(run["stdout"].strip())
            self.assertGreater(values["time"] - real_start, 72 * 3600)
            self.assertAlmostEqual(values["datetime"], values["time"], delta=5)
            self.assertGreater(values["sleep_delta"], 3599)
            self.assertLess(abs(values["time_ns"] - real_start), 20)
            self.assertLess(abs(values["clock_gettime"] - real_start), 20)
            self.assertLess(values["mtime"], real_start - 23 * 3600)
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), original)

    def test_package_timeout_setup_failure_and_cleanup(self):
        marker = "waketrace-phase9-" + uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix="phase9-stage-root-") as stage_root, \
                tempfile.TemporaryDirectory() as folder:
            path = wheel(folder, "phase9-pkg", "1.0", "phase9_mod", f"""
                import signal, subprocess, sys
                subprocess.Popen([sys.executable, '-S', '-c', 'import time; time.sleep(60)', {marker!r}])
                signal.pause()
            """)
            original = (path.read_bytes(), path.stat().st_mtime_ns)
            spec = exercise_spec("import", module="phase9_mod", distribution="phase9-pkg")
            with patch.object(tempfile, "tempdir", stage_root):
                run = run_package_horizons(path, spec, [0], timeout_sec=0.5)["runs"]["0"]
            self.assertTrue(run["timed_out"])
            self.assertFalse(run["complete"])
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), original)
            missing = wheel(folder, "missing-dep", "1.0", "missing_mod", "pass\n",
                            requires=("nonexistent-phase9-dependency==9999",))
            with patch.object(tempfile, "tempdir", stage_root):
                failed = run_package_horizons(
                    missing, exercise_spec("import", module="missing_mod", distribution="missing-dep"),
                    [0], setup_timeout_sec=20)["runs"]["0"]
            self.assertFalse(failed["complete"])
            self.assertEqual(failed["failure_stage"], "setup")
            self.assertEqual(list(Path(stage_root).iterdir()), [])
        time.sleep(0.1)
        self.assertEqual(marked_processes(marker), [])

    def test_parent_interruption_reaps_descendants(self):
        marker = "waketrace-phase9-" + uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix="phase9-stage-root-") as stage_root, \
                tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "interrupt.py"
            path.write_text(f"""import signal, subprocess, sys
subprocess.Popen([sys.executable, '-S', '-c', 'import time; time.sleep(60)', {marker!r}])
signal.pause()
""", encoding="utf-8")
            original = (path.read_bytes(), path.stat().st_mtime_ns)
            driver = "import sys; sys.path.insert(0, sys.argv[2]); " \
                     "from runner import run_in_sandbox; run_in_sandbox(sys.argv[1], timeout_sec=30)"
            child = subprocess.Popen([sys.executable, "-c", driver, str(path), str(ROOT)],
                                     cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True,
                                     env={**os.environ, "TMPDIR": stage_root})
            try:
                time.sleep(1)
                child.send_signal(signal.SIGINT)
                child.communicate(timeout=10)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
            self.assertNotEqual(child.returncode, 0)
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), original)
            self.assertEqual(list(Path(stage_root).iterdir()), [])
        time.sleep(0.1)
        self.assertEqual(marked_processes(marker), [])


if __name__ == "__main__":
    unittest.main()
