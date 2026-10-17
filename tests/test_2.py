import base64
import os
from pathlib import Path
import sys
import tempfile
import textwrap
from urllib.parse import quote


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runner import backdate_files, check_for_leaks, generate_canaries, run_in_sandbox, run_multi_horizon


def make_script(folder, code):
    path = Path(folder) / "sample.py"
    path.write_text(textwrap.dedent(code), encoding="utf-8")
    return path


def test_canaries_and_encodings():
    first = generate_canaries()
    second = generate_canaries()
    assert set(first) == {
        "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN",
        "STRIPE_SECRET_KEY", "DATABASE_URL",
    }
    assert all (first[key] != second[key] for key in first)
    value = first["DATABASE_URL"]
    for form in (value, base64.b64encode(value.encode()).decode(),
                 value.encode().hex(), quote(value)):
        assert check_for_leaks(f"prefix {form} suffix", first) == ["DATABASE_URL"]
    assert check_for_leaks("nothing here", first) == []
    assert set(generate_canaries(["MY_SECRET"])) == {"MY_SECRET"}


def test_backdate_restores_files_and_directories():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        folder = root / "package"
        folder.mkdir()
        file = folder / "code.py"
        file.write_text("pass\n", encoding="utf-8")
        skipped = root / "__pycache__"
        skipped.mkdir()
        cache = skipped / "old.pyc"
        cache.write_bytes(b"old")
        paths = [root, folder, file, skipped, cache]
        before = {path: (path.stat().st_atime_ns, path.stat().st_mtime_ns)
                  for path in paths}
        try:
            with backdate_files(root, 3600):
                assert file.stat().st_mtime_ns == before[file][1] - 3600 * 10**9
                assert folder.stat().st_mtime_ns == before[folder][1] - 3600 * 10**9
                assert cache.stat().st_mtime_ns == before[cache][1]
                raise RuntimeError("pretend the child crashed")
        except RuntimeError:
            pass
        for path in (root, folder, file):
            assert (path.stat().st_atime_ns, path.stat().st_mtime_ns) == before[path]
        with backdate_files(root, 0):
            assert file.stat().st_mtime_ns == before[file][1]


def test_single_run_summary_and_cleanup():
    with tempfile.TemporaryDirectory() as tmp:
        script = make_script(tmp, """
            import ctypes
            import os
            import socket
            import subprocess
            import sys
            import time
            
            with open('.env', encoding='utf-8') as fp:
                assert 'OPENAI_API_KEY=' in fp.read()
            with open('written.txt', 'w', encoding='utf-8') as fp:
                fp.write(os.environ['OPENAI_API_KEY'])
            try:
                socket.create_connection(('example.com', 443), timeout=0.2)
            except PermissionError:
                pass
            subprocess.run([sys.executable, '-c', 'pass'], check=True)
            if os.name != 'nt':
                ctypes.CDLL(None)
            time.sleep(3600)
            print('finished')
        """)
        result = run_in_sandbox(script, offset_hours=24, backdate_mtime_hours=1)
        summary = result["summary"]
        assert result["exit_code"] == 0, result["stderr"]
        assert not result["timed_out"]
        assert result["wall_time_sec"] < 3
        assert result["virtual_elapsed_sec"] >= 25 * 3600
        assert "finished" in result["stdout"]
        assert str(Path(tmp, ".env")) in summary["files_read"]
        assert str(Path(tmp, "written.txt")) in summary["files_written"]
        assert "OPENAI_API_KEY" in summary["env_vars_read"]
        assert any(item["blocked"] for item in summary["network_attempts"])
        assert summary["processes_spawned"]
        assert any("python" in cmd for cmd in summary["processes_spawned"])
        assert summary["sleeps_skipped"] == {"count": 1, "total_sec": 3600.0}
        assert "OPENAI_API_KEY" in summary["observed_canaries"]
        if os.name != "nt":
            assert summary["native_libs_loaded"]
        assert not Path(tmp, ".env").exists()
        assert not list(Path(tmp).glob("__pycache__"))


def test_existing_env_and_timeout():
    with tempfile.TemporaryDirectory() as tmp:
        env_file = Path(tmp, ".env")
        env_file.write_text("KEEP=original\n", encoding="utf-8")
        script = make_script(tmp, """
            import time
            with open('.env', encoding='utf-8') as fp:
                print(fp.read().strip(), flush=True)
            for _ in range(20):
                time.sleep(0.05)
        """)
        before = script.stat().st_mtime_ns
        result = run_in_sandbox(script, timeout_sec=0.4, backdate_mtime_hours=2)
        assert result["timed_out"]
        assert result["exit_code"] is None
        assert "KEEP=original" not in result["stdout"]
        assert "OPENAI_API_KEY=" in result["stdout"]
        assert env_file.read_text(encoding="utf-8") == "KEEP=original\n"
        assert script.stat().st_mtime_ns == before


def test_output_leak_without_file_write():
    with tempfile.TemporaryDirectory() as tmp:
        script = make_script(tmp, """
            import base64
            import os
            with open('.env', encoding='utf-8') as fp:
                fp.read()
            value = os.environ['GITHUB_TOKEN']
            print(base64.b64encode(value.encode()).decode())
        """)
        result = run_in_sandbox(script)
        assert result["exit_code"] == 0, result["stderr"]
        assert result["summary"]["observed_canaries"] == ["GITHUB_TOKEN"]
        assert not Path(tmp, ".env").exists()


def test_executable_package():
    with tempfile.TemporaryDirectory() as tmp:
        package = Path(tmp, "package")
        package.mkdir()
        Path(package, "__main__.py").write_text("print('package ran')\n", encoding="utf-8")
        result = run_in_sandbox(package)
        assert result["exit_code"] == 0, result["stderr"]
        assert result["stdout"].strip() == "package ran"


def test_mtime_age_and_multi_horizon_trigger():
    with tempfile.TemporaryDirectory() as tmp:
        script = make_script(tmp, """
            import os
            import socket
            import time
            
            age = time.time() - os.path.getmtime(__file__)
            if age > 12 * 3600:
                os.environ['OPENAI_API_KEY']
                try:
                    socket.create_connection(('example.com', 443), timeout=0.2)
                except PermissionError:
                    pass
            print(int(age))
        """)
        original = script.stat().st_mtime_ns
        aged = run_in_sandbox(script, backdate_mtime_hours=24)
        assert aged["exit_code"] == 0, aged["stderr"]
        assert int(aged["stdout"].strip()) >= 24 * 3600
        assert script.stat().st_mtime_ns == original

        matrix = run_multi_horizon(script, horizons_hours=[24, 0, 1])
        assert matrix["horizons_tested"] == [24, 0, 1]
        assert set(matrix["runs"]) == {"24", "0", "1"}
        assert matrix["time_bomb_detected"]
        assert matrix["first_trigger_hour"] == 24
        assert not matrix["runs"]["0"]["summary"]["network_attempts"]
        assert matrix["runs"]["24"]["summary"]["network_attempts"]
        assert not run_multi_horizon(script, horizons_hours=[0, 1])["time_bomb_detected"]
        assert run_multi_horizon(script, horizons_hours=[0.0, 24.0])["first_trigger_hour"] == 24.0


if __name__ == "__main__":
    tests = (
        ("fresh canaries and encodings", test_canaries_and_encodings),
        ("timestamp restoration", test_backdate_restores_files_and_directories),
        ("single run summary and cleanup", test_single_run_summary_and_cleanup),
        ("existing .env and timeout", test_existing_env_and_timeout),
        ("encoded output leak", test_output_leak_without_file_write),
        ("executable package", test_executable_package),
        ("file age and multi-horizon trigger", test_mtime_age_and_multi_horizon_trigger),
    )
    failed = 0
    for label, test in tests:
        try:
            test()
            print(f"PASS: {label}")
        except Exception as exc:
            failed += 1
            print(f"FAIL: {label}: {exc}")
    raise SystemExit(1 if failed else 0)