import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from differ import compare_with_lockfile
from lockfile import build_lock_data
from package_input import inspect, tree_files
from package_runner import exercise_spec, run_package_horizons

ROOT = Path(__file__).resolve().parents[1]


def wheel(folder, name, version, module, code, requires=(), entry=None, tag="py3-none-any"):
    path = Path(folder, f"{name.replace('-', '_')}-{version}-{tag}.whl")
    dist = f"{name.replace('-', '_')}-{version}.dist-info"
    metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    metadata += "".join(f"Requires-Dist: {item}\n" for item in requires)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(module + ".py", textwrap.dedent(code))
        archive.writestr(dist + "/METADATA", metadata)
        archive.writestr(dist + "/WHEEL", f"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: {tag}\n")
        archive.writestr(dist + "/RECORD", "")
        if entry:
            archive.writestr(dist + "/entry_points.txt", f"[console_scripts]\n{entry} = {module}:main\n")
    return path


def source_tree(folder, marker):
    root = Path(folder, "source_pkg")
    root.mkdir()
    (root / "pyproject.toml").write_text('''[build-system]
requires = []
build-backend = "backend"
backend-path = ["."]
[project]
name = "source-pkg"
version = "1.0"
''', encoding="utf-8")
    (root / "source_mod.py").write_text("print('source exercise')\n", encoding="utf-8")
    (root / "backend.py").write_text(textwrap.dedent(f'''
        import os
        from pathlib import Path
        import zipfile

        def get_requires_for_build_wheel(config_settings=None):
            return []

        def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
            dest = Path(metadata_directory, 'source_pkg-1.0.dist-info')
            dest.mkdir()
            (dest / 'METADATA').write_text('Metadata-Version: 2.1\\nName: source-pkg\\nVersion: 1.0\\n')
            (dest / 'WHEEL').write_text('Wheel-Version: 1.0\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n')
            return dest.name

        def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
            try:
                Path({str(marker)!r}).write_text('escaped')
            except OSError:
                pass
            name = 'source_pkg-1.0-py3-none-any.whl'
            with zipfile.ZipFile(Path(wheel_directory, name), 'w') as z:
                z.write('source_mod.py')
                z.writestr('source_pkg-1.0.dist-info/METADATA', 'Metadata-Version: 2.1\\nName: source-pkg\\nVersion: 1.0\\n')
                z.writestr('source_pkg-1.0.dist-info/WHEEL', 'Wheel-Version: 1.0\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n')
                z.writestr('source_pkg-1.0.dist-info/RECORD', '')
            return name
    '''), encoding="utf-8")
    return root


def sdist(folder, source):
    path = Path(folder, "source_pkg-1.0.tar.gz")
    with tarfile.open(path, "w:gz") as archive:
        for file in sorted(source.iterdir()):
            archive.add(file, arcname="source_pkg-1.0/" + file.name)
        data = b"Metadata-Version: 2.1\nName: source-pkg\nVersion: 1.0\n"
        info = tarfile.TarInfo("source_pkg-1.0/PKG-INFO")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return path


def test_delayed_wheels_and_cli():
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        clean = wheel(folder, "sample-pkg", "1.0", "different_import", "print('clean')\n")
        delayed = wheel(folder, "sample-pkg", "2.0", "different_import", '''
            import os, time
            if time.time() - os.path.getmtime(__file__) >= 48 * 3600:
                print(os.environ['OPENAI_API_KEY'])
        ''')
        lock_path, report_path = folder / "lock.json", folder / "report.json"
        lock_cmd = subprocess.run([sys.executable, str(ROOT / "main.py"), "lock", str(clean),
                                   "-o", str(lock_path), "--exercise", "import", "--module",
                                   "different_import", "--horizons", "0,24"],
                                   capture_output=True, text=True, timeout=90)
        assert lock_cmd.returncode == 0, lock_cmd.stderr
        lock = json.loads(lock_path.read_text())
        assert lock["artifact"]["kind"] == "wheel" and lock["schema_version"] == "2.0"
        assert lock["setup"]["target"]["version"] == "1.0"
        assert lock["exercise"]["module"] == "different_import"
        verify_cmd = subprocess.run([sys.executable, str(ROOT / "main.py"), "verify", str(delayed),
                                    "-b", str(lock_path), "-r", str(report_path),
                                    "--horizons", "0,24,72"],
                                    capture_output=True, text=True, timeout=120)
        assert verify_cmd.returncode == 1, verify_cmd.stderr
        report = json.loads(report_path.read_text())
        assert report["verdict"] == "BLOCKED" and report["exercise"] == lock["exercise"]
        assert any(f["is_delayed_trigger"] and f["first_seen_hour"] == 72
                   for f in report["findings"])
        assert "sk-proj-wake-" not in json.dumps(report)
        assert "/work/venv/" in json.dumps(report)
        assert "/tmp/waketrace-package-" not in json.dumps(report)


def test_source_tree_and_sdist_build_contained():
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        marker = folder / "host-only-marker"
        source = source_tree(folder, marker)
        spec = exercise_spec("import", module="source_mod", distribution="source-pkg")
        before = {p.name: p.stat().st_mtime_ns for p in source.iterdir()}
        for target in (source, sdist(folder, source)):
            result = run_package_horizons(target, spec, [0], setup_timeout_sec=40)
            run = result["runs"]["0"]
            assert run["complete"], run["stderr"] + str(run["setup"])
            assert run["setup"]["build_result"] == "installed"
            assert run["setup"]["target"]["name"] == "source-pkg"
            assert "source exercise" in run["stdout"]
        assert not marker.exists()
        assert {p.name: p.stat().st_mtime_ns for p in source.iterdir()} == before


def test_console_command_and_reuse():
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        target = wheel(folder, "entry-pkg", "1.0", "entry_mod", '''
            import os
            def main():
                print('entry', os.environ.get('MODE'), __name__)
        ''', entry="entry-tool")
        console = exercise_spec("console", entry="entry-tool", env={"MODE": "check"},
                                distribution="entry-pkg")
        result = run_package_horizons(target, console, [0])
        assert result["runs"]["0"]["complete"], result["runs"]["0"]["stderr"]
        assert "entry check" in result["runs"]["0"]["stdout"]
        lock = build_lock_data(result)
        repeated = run_package_horizons(target, lock["exercise"], [0])
        report = compare_with_lockfile(lock, repeated)
        assert report["verdict"] == "CLEAN"
        command = exercise_spec("command", argv=["python", "-m", "entry_mod"],
                                distribution="entry-pkg")
        run = run_package_horizons(target, command, [0])["runs"]["0"]
        assert run["complete"], run["stderr"]
        assert "entry_mod" not in run["stderr"]


def test_dependencies_and_comparability():
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        house = folder / "wheels"
        house.mkdir()
        wheel(house, "helper-pkg", "1.0", "helper_mod", "VALUE = 1\n")
        wheel(house, "helper-pkg", "2.0", "helper_mod", "VALUE = 2\n")
        v1 = wheel(folder, "needs-pkg", "1.0", "needs_mod", "import helper_mod\n",
                   requires=["helper-pkg == 1.0"])
        v2 = wheel(folder, "needs-pkg", "2.0", "needs_mod", "import helper_mod\n",
                   requires=["helper-pkg == 2.0"])
        spec = exercise_spec("import", module="needs_mod", distribution="needs-pkg")
        baseline = run_package_horizons(v1, spec, [0], house)
        assert baseline["runs"]["0"]["complete"], baseline["runs"]["0"]["stderr"]
        lock = build_lock_data(baseline)
        assert any(d["name"] == "helper-pkg" and d["version"] == "1.0" and
                   d["origin"]["archive_info"]["hashes"]["sha256"]
                   for d in lock["setup"]["dependencies"])
        changed = run_package_horizons(v2, spec, [0], house)
        assert changed["runs"]["0"]["complete"], changed["runs"]["0"]["stderr"]
        report = compare_with_lockfile(lock, changed)
        assert report["verdict"] == "INCOMPLETE"
        assert "dependencies differ at +0h" in report["comparability_issues"]
        empty = folder / "empty"
        empty.mkdir()
        missing = run_package_horizons(v1, spec, [0], empty)["runs"]["0"]
        assert not missing["complete"] and missing["failure_stage"] == "setup"
        assert "No matching distribution" in missing["error"]


def test_fingerprint_directory_and_file_age():
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        source = folder / "executable"
        source.mkdir()
        (folder / "sibling.txt").write_text("host-only")
        (source / "__main__.py").write_text(
            "from pathlib import Path\nassert not Path('/work/sibling.txt').exists()\nprint('hello')\n")
        first = inspect(source)["sha256"]
        os.utime(source / "__main__.py", None)
        assert inspect(source)["sha256"] == first
        (source / "another.py").write_text("x = 1\n")
        assert inspect(source)["sha256"] != first
        assert tree_files(source) == sorted(tree_files(source))
        from runner import run_multi_horizon
        runs = run_multi_horizon(source, [0])
        assert runs["runs"]["0"]["complete"]
        assert build_lock_data(runs)["sha256"] == inspect(source)["sha256"]
        lock_path, report_path = folder / "dir.lock.json", folder / "dir.report.json"
        locked = subprocess.run([sys.executable, str(ROOT / "main.py"), "lock", str(source),
                                 "-o", str(lock_path), "--horizons", "0"],
                                 capture_output=True, text=True, timeout=30)
        checked = subprocess.run([sys.executable, str(ROOT / "main.py"), "verify", str(source),
                                   "-b", str(lock_path), "-r", str(report_path),
                                   "--horizons", "0"], capture_output=True, text=True, timeout=30)
        assert locked.returncode == 0, locked.stderr
        assert checked.returncode == 0, checked.stderr
        assert json.loads(report_path.read_text())["verdict"] == "CLEAN"
        age_wheel = wheel(folder, "age-pkg", "1.0", "age_mod", '''
            import os, time
            if time.time() - os.path.getmtime(__file__) > 12 * 3600:
                print('AGED')
        ''')
        original = age_wheel.stat().st_mtime_ns
        spec = exercise_spec("import", module="age_mod", distribution="age-pkg")
        fresh = run_package_horizons(age_wheel, spec, [0], file_age_hours=0)
        aged = run_package_horizons(age_wheel, spec, [0], file_age_hours=24)
        assert "AGED" not in fresh["runs"]["0"]["stdout"]
        assert "AGED" in aged["runs"]["0"]["stdout"]
        assert age_wheel.stat().st_mtime_ns == original


def test_invalid_inputs_and_fail_closed():
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        invalid = folder / "bad.tar.gz"
        invalid.write_bytes(b"not a tarball")
        try:
            inspect(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid archive accepted")
        private = folder / "private-tree"
        private.mkdir()
        (private / "__main__.py").write_text("print('ok')\n")
        (private / ".env").write_text("SECRET=host\n")
        try:
            inspect(private)
        except ValueError:
            pass
        else:
            raise AssertionError("private source file was staged")
        wheel_path = wheel(folder, "fail-pkg", "1.0", "fail_mod", "print('ok')\n",
                        tag="cp310-cp310-manylinux_2_17_x86_64")
        spec = exercise_spec("import", module="fail_mod", distribution="fail-pkg")
        incompatible = run_package_horizons(wheel_path, spec, [0])["runs"]["0"]
        assert not incompatible["complete"] and incompatible["failure_stage"] == "setup"
        valid = wheel(folder, "entry-pkg", "1.0", "entry_mod", "print('ok')\n")
        bad_entry = exercise_spec("console", entry="missing", distribution="entry-pkg")
        run = run_package_horizons(valid, bad_entry, [0])["runs"]["0"]
        assert not run["complete"] and run["failure_stage"] == "exercise"
        timeout = run_package_horizons(valid, spec, [0], setup_timeout_sec=0.001)["runs"]["0"]
        assert not timeout["complete"] and timeout["failure_stage"] == "setup"
        slow = wheel(folder, "slow-pkg", "1.0", "slow_mod", "import signal\nsignal.pause()\n")
        slow_spec = exercise_spec("import", module="slow_mod", distribution="slow-pkg")
        slow_run = run_package_horizons(slow, slow_spec, [0], timeout_sec=0.2)["runs"]["0"]
        assert not slow_run["complete"] and slow_run["failure_stage"] == "exercise"
        assert slow_run["timed_out"]


def test_missing_build_requirement_and_cli_failure_report():
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        source = source_tree(folder, folder / "host-only")
        pyproject = source / "pyproject.toml"
        pyproject.write_text(pyproject.read_text().replace(
            "requires = []", 'requires = ["missing-offline-build-tool==1"]'))
        spec = exercise_spec("import", module="source_mod", distribution="source-pkg")
        run = run_package_horizons(source, spec, [0])["runs"]["0"]
        assert not run["complete"] and run["failure_stage"] == "setup"
        assert "missing-offline-build-tool" in run["error"]
        clean = wheel(folder, "clean-pkg", "1.0", "clean_mod", "print('clean')\n")
        broken = wheel(folder, "clean-pkg", "2.0", "clean_mod", "print('candidate')\n",
                       requires=["missing-runtime-dep==1"])
        lock = folder / "lock.json"
        report = folder / "report.json"
        base = subprocess.run([sys.executable, str(ROOT / "main.py"), "lock", str(clean),
                               "-o", str(lock), "--exercise", "import", "--module", "clean_mod",
                               "--horizons", "0"], capture_output=True, text=True, timeout=90)
        assert base.returncode == 0, base.stderr
        result = subprocess.run([sys.executable, str(ROOT / "main.py"), "verify", str(broken),
                                "-b", str(lock), "-r", str(report), "--horizons", "0"],
                                capture_output=True, text=True, timeout=90)
        assert result.returncode == 2, result.stderr
        saved = json.loads(report.read_text())
        assert saved["verdict"] == "INCOMPLETE"
        assert saved["run_health"]["0"]["stage"] == "setup"


def test_exercise_override_requires_flag():
    with tempfile.TemporaryDirectory() as temp:
        folder = Path(temp)
        target = wheel(folder, "override-pkg", "1.0", "override_mod", "print('ok')\n")
        lock = folder / "lock.json"
        report = folder / "report.json"
        base = subprocess.run([sys.executable, str(ROOT / "main.py"), "lock", str(target),
                               "-o", str(lock), "--exercise", "import", "--module", "override_mod",
                               "--horizons", "0"], capture_output=True, text=True, timeout=90)
        assert base.returncode == 0, base.stderr
        command = [sys.executable, str(ROOT / "main.py"), "verify", str(target),
                   "-b", str(lock), "-r", str(report), "--horizons", "0",
                   "--exercise", "command", "--test-argv", '["python", "-m", "override_mod"]']
        denied = subprocess.run(command, capture_output=True, text=True, timeout=90)
        assert denied.returncode == 2 and "--override-exercise" in denied.stderr
        allowed = subprocess.run(command + ["--override-exercise"], capture_output=True,
                                 text=True, timeout=90)
        assert allowed.returncode == 2, allowed.stderr
        saved = json.loads(report.read_text())
        assert saved["exercise_overridden"] and saved["verdict"] == "INCOMPLETE"
        assert "exercise differs from baseline" in " ".join(saved["comparability_issues"])


if __name__ == "__main__":
    tests = (test_delayed_wheels_and_cli, test_source_tree_and_sdist_build_contained,
             test_console_command_and_reuse, test_dependencies_and_comparability,
             test_fingerprint_directory_and_file_age, test_invalid_inputs_and_fail_closed,
             test_missing_build_requirement_and_cli_failure_report,
             test_exercise_override_requires_flag)
    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS: {test.__name__}")
        except Exception as exc:
            failed += 1
            print(f"FAIL: {test.__name__}: {exc}")
    raise SystemExit(bool(failed))
