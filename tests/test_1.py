import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import time


HOOK_DIR = Path(__file__).resolve().parents[1] / "sandbox_hooks"


def run_child(code, work_dir, settings=None):
    env = {key: val for key, val in os.environ.items() if not key.startswith("WAKETRACE_")}
    log_path = Path(work_dir) / "trace.jsonl"
    env.update({
        "PYTHONPATH": os.pathsep.join(filter(None, (str(HOOK_DIR), env.get("PYTHONPATH")))),
        "WAKETRACE_ACTIVE": "1",
        "WAKETRACE_LOG_PATH": str(log_path),
        "WAKETRACE_PROJECT_ROOT": str(work_dir),
    })
    env.update(settings or {})
    start = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)], cwd=work_dir, env=env,
        capture_output=True, text=True, timeout=5,
    )
    elapsed = time.monotonic() - start
    assert result.returncode == 0, f"child failed:\n{result.stdout}{result.stderr}"
    events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    return elapsed, events


def test_instant_72_hour_warp():
    with tempfile.TemporaryDirectory() as tmp:
        elapsed, events = run_child("""
            import datetime
            import time
            
            t0 = time.time()
            m0 = time.monotonic()
            p0 = time.perf_counter()
            d0 = datetime.datetime.now()
            u0 = datetime.datetime.utcnow()
            time.sleep(259200)
            assert time.time() - t0 >= 259200
            assert time.monotonic() - m0 >= 259200
            assert time.perf_counter() - p0 >= 259200
            assert (datetime.datetime.now() - d0).total_seconds() >= 259200
            assert (datetime.datetime.utcnow() - u0).total_seconds() >= 259200
        """, tmp, {"WAKETRACE_OFFSET_SEC": "12"})
        assert elapsed < 2.0, f"72-hour sleep took {elapsed:.2f}s"
        sleep_events = [ev for ev in events if ev["action"] == "sleep_skipped"]
        assert len(sleep_events) == 1
        assert sleep_events[0]["virtual_offset_sec"] == 259212.0


def test_stealth_scrubbing():
    with tempfile.TemporaryDirectory() as tmp:
        run_child("""
            import os
            import sys

            assert not any(key.startswith('WAKETRACE_') for key in os.environ)
            assert not any(os.path.abspath(p) == os.path.abspath(%r) for p in sys.path)
        """ % str(HOOK_DIR), tmp, {"WAKETRACE_EXTRA_MARKER": "hidden"})
        env = os.environ.copy()
        env.update({
            "PYTHONPATH": str(HOOK_DIR),
            "WAKETRACE_ACTIVE": "0",
            "WAKETRACE_LOG_PATH": str(Path(tmp, "inactive.jsonl")),
        })
        result = subprocess.run(
            [sys.executable, "-c", "import os; assert os.environ['WAKETRACE_ACTIVE'] == '0'"],
            cwd=tmp, env=env, capture_output=True, text=True, timeout=5,
        )
        assert result.returncode == 0, result.stderr
        assert not Path(tmp, "inactive.jsonl").exists()


def test_environment_reads():
    with tempfile.TemporaryDirectory() as tmp:
        _, events = run_child("""
            import os

            assert os.getenv('FAKE_API_KEY') == 'sk-test-12345'
            assert os.environ.get('FAKE_API_KEY') == 'sk-test-12345'
            assert os.environ['FAKE_API_KEY'] == 'sk-test-12345'
        """, tmp, {"FAKE_API_KEY": "sk-test-12345"})
        reads = [ev for ev in events if ev["category"] == "env" and
                 ev["action"] == "env_read" and ev["target"] == "FAKE_API_KEY"]
        assert len(reads) >= 3
        assert all(ev["extra"]["found"] is True and "value" not in ev["extra"]
                   for ev in reads)


def test_file_network_process_and_native_audit():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, ".env").write_text("DUMMY=yes\n", encoding="utf-8")
        _, events = run_child("""
            import ctypes
            import os
            import socket
            import subprocess
            import sys
            
            with open('.env', encoding='utf-8') as fp:
                assert fp.read() == 'DUMMY=yes\\n'
            try:
                socket.create_connection(('93.184.216.34', 80), timeout=1.0)
            except PermissionError:
                pass
            else:
                raise AssertionError('outside network connection was not blocked')
            with socket.socket() as server:
                server.bind(('127.0.0.1', 0))
                server.listen(1)
                with socket.create_connection(server.getsockname(), timeout=1.0):
                    client, _ = server.accept()
                    client.close()
            subprocess.run([sys.executable, '-c', 'pass'], check=True)
            if os.name != 'nt':
                ctypes.CDLL(None)
        """, tmp, {"WAKETRACE_BLOCK_NET": "1"})
        assert any(ev["category"] == "file" and ev["action"] == "file_open" and
                   ev["target"] == ".env" for ev in events)
        assert any(ev["category"] == "net" and ev["extra"]["blocked"] is True
                   for ev in events)
        assert any(ev["category"] == "net" and ev["extra"]["blocked"] is False
                   for ev in events)
        assert any(ev["category"] == "process" and ev["action"] == "proc_exec"
                   for ev in events)
        if os.name != "nt":
            assert any(ev["category"] == "native" and ev["action"] == "dlopen"
                       for ev in events)