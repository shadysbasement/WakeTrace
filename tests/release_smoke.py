"""Build a clean snapshot and exercise each installed distribution."""

import json
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def run(command, cwd, env=None, expected=0, timeout=180):
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            capture_output=True, timeout=timeout)
    if result.returncode != expected:
        raise AssertionError(f"exit {result.returncode}, expected {expected}: {command}\n"
                             f"stdout: {result.stdout[-1000:]}\nstderr: {result.stderr[-1000:]}")
    print(f"PASS exit {expected}: {' '.join(map(str, command[:3]))}", flush=True)
    return result


def make_wheel(folder, version, code):
    path = folder / f"release_probe-{version}-py3-none-any.whl"
    dist = f"release_probe-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("release_probe.py", code)
        archive.writestr(dist + "/METADATA",
                         f"Metadata-Version: 2.1\nName: release-probe\nVersion: {version}\n")
        archive.writestr(dist + "/WHEEL",
                         "Wheel-Version: 1.0\nGenerator: release-smoke\n"
                         "Root-Is-Purelib: true\nTag: py3-none-any\n")
        archive.writestr(dist + "/RECORD", "")
    return path


def smoke_gate(command, root, env):
    inputs = root / "phase10-input"
    output = root / "phase10-output"
    inputs.mkdir()
    output.mkdir()
    baseline, candidate = inputs / "baseline.py", inputs / "candidate.py"
    baseline.write_text("print('clean fixture')\n")
    candidate.write_text("print('clean fixture')\n")
    lock = inputs / "baseline.lock.json"
    run([str(command), "lock", str(baseline), "-o", str(lock), "--horizons", "0"], root, env=env)
    import hashlib
    fingerprint = hashlib.sha256(baseline.read_bytes()).hexdigest()
    plan = {"schema_version": "1.0", "revision": "release_smoke",
            "candidate": {"type": "script", "path": str(candidate), "sha256": fingerprint},
            "baseline": {"path": str(baseline), "sha256": fingerprint,
                         "locks": {"clean": str(lock)},
                         "manifest": str(inputs / "approval.json"),
                         "signature": str(inputs / "approval.sig")},
            "scenarios": [{"id": "clean", "args": []}], "horizons": [0],
            "output": {"result": str(output / "result.json"),
                       "summary": str(output / "summary.md")}}
    plan_path = inputs / "plan.json"
    plan_path.write_text(json.dumps(plan))
    draft = run([str(command), "gate-manifest-template", str(plan_path),
                 "--input-root", str(root), "--output-root", str(output)], root, env=env)
    manifest = json.loads(draft.stdout)
    now = datetime.now(timezone.utc)
    manifest.update(approved_by="Local release fixture", approved_at=now.isoformat(),
                    expires_at=(now + timedelta(hours=1)).isoformat())
    Path(plan["baseline"]["manifest"]).write_text(json.dumps(manifest))
    private, public = inputs / "fixture-private.pem", inputs / "fixture-public.pem"
    run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
         "-out", str(private)], root, env=env)
    run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], root, env=env)
    run(["openssl", "dgst", "-sha256", "-sign", str(private),
         "-out", plan["baseline"]["signature"], plan["baseline"]["manifest"]], root, env=env)
    run([str(command), "gate", str(plan_path), "--input-root", str(root),
         "--output-root", str(output), "--approval-key", str(public)], root, env=env)
    assert json.loads((output / "result.json").read_text())["decision"] == "PASS"
    run([str(command), "gate-show", str(output / "result.json")], root, env=env)


def smoke_install(artifact, root, dashboard=False):
    root.mkdir()
    name = "wheel-env" if artifact.suffix == ".whl" else "sdist-env"
    env_root = root / name
    run([sys.executable, "-m", "venv", str(env_root)], root)
    python = env_root / "bin" / "python"
    command = env_root / "bin" / "waketrace"
    spec = str(artifact) + ("[dashboard]" if dashboard else "")
    run([str(python), "-m", "pip", "install", spec], root, timeout=300)
    clean_env = {key: value for key, value in os.environ.items()
                 if key not in ("PYTHONPATH", "PYTHONHOME")}
    result = run([str(python), "-c", "import main; print(main.__file__)"], root,
                 env=clean_env)
    assert str(env_root) in result.stdout and str(ROOT) not in result.stdout
    run([str(command), "--help"], root, env=clean_env)
    run([str(command), "preflight"], root, env=clean_env)
    smoke_gate(command, root, clean_env)
    run([str(command), "demo"], root, env=clean_env, timeout=90)
    report = json.loads((root / "reports" / "latest_report.json").read_text())
    assert report["schema_version"] == "2.0" and report["verdict"] == "BLOCKED"
    assert "sk-proj-wake-" not in json.dumps(report)
    examples = Path(run([str(python), "-c", "import demo_pkgs; print(demo_pkgs.__path__[0])"],
                        root, env=clean_env).stdout.strip())
    lock = root / f"{name}-script.lock.json"
    saved = root / f"{name}-script.report.json"
    run([str(command), "lock", str(examples / "clean_v1.py"),
         "-o", str(lock), "--horizons", "0,24"], root, env=clean_env)
    run([str(command), "verify", str(examples / "trojan_v2.py"), "-b", str(lock),
         "-r", str(saved), "--horizons", "0,24,72"], root, env=clean_env,
        expected=1)
    assert json.loads(saved.read_text())["verdict"] == "BLOCKED"
    trusted = make_wheel(root, "1.0", "print('trusted')\n")
    changed = make_wheel(root, "2.0", "import os, time\n"
                         "if time.time() - os.path.getmtime(__file__) > 48*3600:\n"
                         "    print(os.environ['OPENAI_API_KEY'])\n")
    pkg_lock = root / f"{name}-package.lock.json"
    pkg_report = root / f"{name}-package.report.json"
    run([str(command), "lock", str(trusted), "-o", str(pkg_lock),
         "--exercise", "import", "--module", "release_probe", "--horizons", "0"],
        root, env=clean_env, timeout=120)
    run([str(command), "verify", str(changed), "-b", str(pkg_lock),
         "-r", str(pkg_report), "--horizons", "0,72"], root,
        env=clean_env, expected=1, timeout=120)
    assert json.loads(pkg_report.read_text())["verdict"] == "BLOCKED"
    sys.path.insert(0, str(ROOT / "tests"))
    from test_6 import sdist, source_tree
    source = source_tree(root, root / "host-marker")
    archive = sdist(root, source)
    run([str(command), "lock", str(archive), "-o", str(root / f"{name}-source.lock.json"),
         "--exercise", "import", "--module", "source_mod", "--horizons", "0"],
        root, env=clean_env, timeout=120)
    assert not (root / "host-marker").exists()
    if dashboard:
        (root / "behavior.lock.json").unlink()
        (root / "reports" / "latest_report.json").unlink()
        code = ("from importlib.util import find_spec; from streamlit.testing.v1 import AppTest; "
                "app=AppTest.from_file(find_spec('dashboard').origin, default_timeout=15).run(); "
                "assert not app.exception; "
                "app=next(button for button in app.button if button.label == 'Run included demo').click().run(); "
                "assert not app.exception and app.select_slider[0].value == 72")
        run([str(python), "-c", code], root, env=clean_env, timeout=90)
        assert (root / "behavior.lock.json").is_file()
        assert (root / "reports" / "latest_report.json").is_file()


def main():
    os.environ["PIP_CONSTRAINT"] = str(ROOT / "constraints-release.txt")
    with tempfile.TemporaryDirectory(prefix="waketrace-release-") as folder:
        root = Path(folder)
        snapshot = root / "snapshot"
        snapshot.mkdir()
        for name in ("pyproject.toml", "README.md", "requirements.txt", "constraints-release.txt"):
            shutil.copy2(ROOT / name, snapshot / name)
        for path in ROOT.glob("*.py"):
            shutil.copy2(path, snapshot / path.name)
        for name in ("sandbox_hooks", "demo_pkgs"):
            shutil.copytree(ROOT / name, snapshot / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        dist = root / "dist"
        run([sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(dist)],
            snapshot, timeout=180)
        wheel = next(dist.glob("*.whl"))
        archive = next(dist.glob("*.tar.gz"))
        with zipfile.ZipFile(wheel) as data:
            names = data.namelist()
            assert all(any(name.endswith(required) for name in names) for required in
                       ("sandbox_hooks/sitecustomize.py", "sandbox_hooks/launch.py",
                        "sandbox_hooks/package_launch.py", "demo_pkgs/clean_v1.py",
                        "demo_pkgs/trojan_v2.py"))
        with tarfile.open(archive, "r:gz") as data:
            names = data.getnames()
            assert all(any(name.endswith(required) for name in names) for required in
                       ("sandbox_hooks/sitecustomize.py", "sandbox_hooks/launch.py",
                        "sandbox_hooks/package_launch.py", "demo_pkgs/clean_v1.py",
                        "demo_pkgs/trojan_v2.py"))
        smoke_install(wheel, root / "wheel-work", dashboard=True)
        smoke_install(archive, root / "sdist-work")
    print("PASS release smoke: wheel and sdist", flush=True)


if __name__ == "__main__":
    main()
