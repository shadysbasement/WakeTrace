import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys


PYTHON = "/usr/bin/python3"
ENV = Path("/work/venv")
SETUP = Path("/trace/setup.json")


def write_setup(data):
    SETUP.write_text(json.dumps(data), encoding="utf-8")


def run(command, env, timeout):
    result = subprocess.run(command, env=env, cwd="/work", capture_output=True,
                            text=True, timeout=timeout, check=False)
    if result.returncode:
        output = result.stderr or result.stdout
        missing = re.search(r"No matching distribution found for ([A-Za-z0-9_.-]+(?:==[A-Za-z0-9_.-]+)?)",
                            output, re.I)
        if missing:
            detail = f"No matching distribution found for {missing[1]} in the local wheelhouse"
        elif "not a supported wheel on this platform" in output:
            detail = "wheel is incompatible with the isolated Python runtime"
        else:
            detail = f"offline package setup command failed (exit {result.returncode})"
        raise RuntimeError(detail)
    return result


def dependencies(site, target_name, report):
    installed = []
    origins = {}
    try:
        data = json.loads(Path(report).read_text(encoding="utf-8"))
        for item in data.get("install", []):
            metadata = item.get("metadata", {})
            key = re.sub(r"[-_.]+", "-", metadata.get("name", "")).lower()
            origins[key] = item.get("download_info", {})
    except (OSError, ValueError):
        pass
    for dist in importlib.metadata.distributions(path=[str(site)]):
        name = dist.metadata.get("Name")
        if not name or name.lower() == "pip":
            continue
        key = re.sub(r"[-_.]+", "-", name).lower()
        item = {"name": key, "version": dist.version, "origin": origins.get(key)}
        installed.append(item)
    installed.sort(key=lambda item: item["name"])
    targets = [item for item in installed if item["name"] == target_name]
    if len(targets) != 1:
        raise RuntimeError("installed distribution metadata does not match target")
    return targets[0], [item for item in installed if item["name"] != target_name]


def main():
    artifact, target_name, exercise_json, setup_timeout, file_age = sys.argv[1:]
    exercise = json.loads(exercise_json)
    result = {"ok": False, "stage": "setup", "error": None, "python": sys.version.split()[0],
              "target": None, "dependencies": [], "build_result": "failed"}
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "TMPDIR": "/tmp",
           "LANG": "C.UTF-8", "PIP_CONFIG_FILE": "/dev/null", "PIP_NO_INDEX": "1",
           "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONNOUSERSITE": "1"}
    try:
        timeout = float(setup_timeout)
        run([PYTHON, "-m", "venv", str(ENV)], env, timeout)
        pip = str(ENV / "bin/python")
        run([pip, "-m", "pip", "install", "--no-index", "--find-links=/wheels",
             "--no-input", "--disable-pip-version-check", "--report", "/work/install.json",
             artifact], env, timeout)
        site = next((ENV / "lib").glob("python*/site-packages"))
        target, deps = dependencies(site, target_name, "/work/install.json")
        expected = exercise.get("distribution")
        if expected and target["name"] != expected:
            raise RuntimeError("installed distribution name differs from expected")
        result.update(ok=True, stage="exercise", target=target, dependencies=deps,
                      build_result="installed")
        write_setup(result)
        age = float(file_age)
        if age > 0:
            shift = int(age * 3600 * 1_000_000_000)
            for folder, dirs, names in os.walk(site):
                for name in names:
                    path = Path(folder, name)
                    if path.is_symlink() or not path.is_file():
                        continue
                    stat = path.stat()
                    os.utime(path, ns=(stat.st_atime_ns - shift, stat.st_mtime_ns - shift))
        with open("/work/.env", "w", encoding="utf-8") as output:
            for name in os.environ.get("WAKETRACE_CANARY_NAMES", "").split(","):
                if name and name in os.environ:
                    output.write(f"{name}={os.environ[name]}\n")
        child = os.environ.copy()
        child.update({"PATH": "/work/venv/bin:/usr/bin:/bin", "PYTHONPATH": "/hook",
                      "WAKETRACE_ACTIVE": "1", "WAKETRACE_PROJECT_ROOT": "/work",
                      "PYTHONDONTWRITEBYTECODE": "1"})
        result["stage"] = "containment"
        os.execve(pip, [pip, "/hook/package_exercise.py", exercise_json], child)
    except Exception as exc:
        message = str(exc) if isinstance(exc, (RuntimeError, subprocess.TimeoutExpired)) \
            else f"setup failed ({type(exc).__name__})"
        result.update(ok=False, error=message)
        write_setup(result)
        print(f"WakeTrace setup failed: {message}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
