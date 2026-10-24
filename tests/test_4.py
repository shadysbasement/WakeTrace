import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def project_copy(folder):
    for name in ("main.py", "runner.py", "isolation.py", "lockfile.py", "differ.py",
                 "package_input.py", "package_runner.py", "schema.py"):
        shutil.copy2(ROOT / name, folder / name)
    for subdir, names in {
        "sandbox_hooks": ("sitecustomize.py", "launch.py"),
        "demo_pkgs": ("clean_v1.py", "trojan_v2.py"),
    }.items():
        dest = folder / subdir
        dest.mkdir()
        for name in names:
            shutil.copy(ROOT / subdir / name, dest / name)


def cli(folder, *args, plain=False):
    command = [sys.executable]
    if plain:
        command.append("-S")
    command.extend(("main.py", *map(str, args)))
    return subprocess.run(command, cwd=folder, capture_output=True, text=True,
                          timeout=30)


def test_lock(folder):
    result = cli(folder, "lock", "demo_pkgs/clean_v1.py", "-o", "baseline.json",
                 "--horizons", "0,24", plain=True)
    assert result.returncode == 0, result.stderr + result.stdout
    lock = json.loads((folder / "baseline.json").read_text(encoding="utf-8"))
    assert lock["schema_version"] == "2.0"
    assert lock["horizons_locked"] == [0, 24]
    assert len(lock["sha256"]) == 64
    assert "Behavioral lock" in result.stdout


def test_clean(folder):
    result = cli(folder, "verify", "demo_pkgs/clean_v1.py", "-b", "baseline.json",
                 "-r", "clean.json", "--horizons", "0,24,72")
    assert result.returncode == 0, result.stderr + result.stdout
    report = json.loads((folder / "clean.json").read_text(encoding="utf-8"))
    assert report["verdict"] == "WARNING"
    assert report["risk_score"] == 0.0
    assert report["candidate_capabilities"]
    assert "activity" in report["horizon_breakdown"]["72"]


def test_trojan(folder):
    result = cli(folder, "verify", "demo_pkgs/trojan_v2.py", "-b", "baseline.json",
                 "-r", "trojan.json", "--horizons", "0,24,72,168")
    assert result.returncode == 1, result.stderr + result.stdout
    report = json.loads((folder / "trojan.json").read_text(encoding="utf-8"))
    assert report["verdict"] == "BLOCKED"
    assert report["risk_score"] >= 40.0
    assert report["horizon_breakdown"]["0"]["risk_score"] == 0.0
    assert report["horizon_breakdown"]["72"]["risk_score"] >= 40.0
    assert any(f["item"] == "OPENAI_API_KEY" for f in report["findings"])
    assert any(f["category"] == "canary_evidence" and f["item"] == "OPENAI_API_KEY"
               for f in report["findings"])


def test_demo(folder):
    result = cli(folder, "demo")
    assert result.returncode == 0, result.stderr + result.stdout
    assert (folder / "behavior.lock.json").is_file()
    report_path = folder / "reports" / "latest_report.json"
    assert report_path.is_file()
    assert json.loads(report_path.read_text(encoding="utf-8"))["verdict"] == "BLOCKED"
    assert "Open the saved report JSON" in result.stdout


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        project_copy(folder)
        tests = (("CLI lock with plain-text fallback", test_lock),
                 ("clean self-check", test_clean),
                 ("72-hour trojan blocked", test_trojan),
                 ("one-command demo", test_demo))
        failed = 0
        for label, test in tests:
            try:
                test(folder)
                print(f"PASS: {label}")
            except Exception as exc:
                failed += 1
                print(f"FAIL: {label}: {exc}")
    raise SystemExit(1 if failed else 0)
