import ast
from datetime import datetime, timezone
import hashlib
import json
import os
import shlex
import tempfile
from urllib.parse import urlsplit

from runner import run_multi_horizon
from schema import validate_lock


CAPABILITY_NAMES = (
    "files_read", "files_written", "env_vars_read", "network_hosts",
    "processes_spawned", "native_libs_loaded",
)


def _inside(path, root):
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def normalize_path(path_str, project_root=None):
    path = os.fspath(path_str).replace("\\", "/")
    root = os.path.abspath(project_root) if project_root is not None else None
    full = os.path.abspath(os.path.join(root or os.getcwd(), path))
    places = (("<PROJECT>", root), ("<TEMP>", tempfile.gettempdir()),
              ("<HOME>", os.path.expanduser("~")))
    for label, folder in places:
        if folder and _inside(full, os.path.abspath(folder)):
            tail = os.path.relpath(full, folder)
            return label if tail == "." else label + "/" + tail.replace("\\", "/")
    return full.replace("\\", "/")


def get_file_sha256(filepath):
    if os.path.isdir(filepath):
        from package_input import inspect
        return inspect(filepath)["sha256"]
    digest = hashlib.sha256()
    with open(filepath, "rb") as fp:
        for chunk in iter(lambda: fp.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _network_host(target):
    try:
        address = ast.literal_eval(str(target))
        if isinstance(address, tuple) and address:
            return str(address[0]).lower()
    except (SyntaxError, ValueError, TypeError):
        pass
    try:
        return (urlsplit(str(target)).hostname or str(target)).lower()
    except ValueError:
        return str(target).lower()


def _run_items(result):
    if "runs" in result:
        return [(hour, result["runs"][str(hour)])
                for hour in result["horizons_tested"]]
    return [(result.get("offset_hours", 0), result)]


def _project_root(result, project_root=None):
    if project_root is not None:
        return os.path.abspath(project_root)
    target = result["target_script"]
    if os.path.isabs(target):
        return os.path.dirname(target)
    for _, run in _run_items(result):
        for path in run["summary"].get("files_read", []):
            if os.path.basename(path) == target and os.path.isfile(path):
                return os.path.dirname(os.path.abspath(path))
            if (os.path.basename(path) == "__main__.py" and
                    os.path.basename(os.path.dirname(path)) == target):
                return os.path.dirname(os.path.dirname(os.path.abspath(path)))
    return os.getcwd()


def _target_path(result, root):
    target = result["target_script"]
    return os.path.abspath(target if os.path.isabs(target) else
                           os.path.join(root, target))


def _summary_caps(summary, root, target=None):
    self_path = normalize_path(target, root) if target else None
    return {
        "files_read": {norm for p in summary.get("files_read", [])
                       if (norm := normalize_path(p, root)) != self_path},
        "files_written": {normalize_path(p, root) for p in summary.get("files_written", [])},
        "env_vars_read": set(summary.get("env_vars_read", [])),
        "network_hosts": {_network_host(item["target"] if isinstance(item, dict)
                                        else item)
                         for item in summary .get("network_attempts", [])},
        "processes_spawned": set(summary.get("processes_spawned", [])),
        "native_libs_loaded": set(summary.get("native_libs_loaded", [])),
    }


def build_lock_data(run_result: dict, project_root=None):
    if any(not run.get("complete", False) for _, run in _run_items(run_result)):
        raise ValueError("cannot lock incomplete sandbox runs")
    root = _project_root(run_result, project_root)
    target = _target_path(run_result, root)
    caps = {name: set() for name in CAPABILITY_NAMES}
    by_hour = {}
    for hour, run in _run_items(run_result):
        current = _summary_caps(run['summary'], root, target)
        by_hour[str(hour)] = {name: sorted(values) for name, values in current.items()}
        for name, values in current.items():
            caps[name].update(values)
    result = {
        "schema_version": "2.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "execution_backend": next((run.get("backend") for _, run in _run_items(run_result)), None),
        "target_script": os.path.basename(target),
        "sha256": get_file_sha256(target),
        "horizons_locked": sorted({hour for hour, _ in _run_items(run_result)}),
        "capabilities": {name: sorted(values) for name, values in caps.items()},
        'capabilities_by_horizon': by_hour,
        'temporal_coverage': 'observed_horizons',
    }
    if "artifact" in run_result:
        first = _run_items(run_result)[0][1]["setup"]
        snapshots = [(run["setup"].get("target"), run["setup"].get("dependencies"),
                      run["setup"].get("python")) for _, run in _run_items(run_result)]
        if any(snapshot != snapshots[0] for snapshot in snapshots[1:]):
            raise ValueError("package setup differs across baseline horizons")
        result.update(artifact=run_result["artifact"],
                      wheelhouse=run_result["wheelhouse"],
                      exercise=run_result["exercise"],
                      file_age_hours=run_result["file_age_hours"],
                      setup={"target": first["target"],
                             "dependencies": first["dependencies"],
                             "python": first["python"],
                             "build_result": first["build_result"]})
    elif "file_age_hours" in run_result:
        result["file_age_hours"] = run_result["file_age_hours"]
    return validate_lock(result)


def save_lockfile(lock_data, lock_path="behavior.lock.json"):
    validate_lock(lock_data)
    path = os.fspath(lock_path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(lock_data, fp, indent=2, ensure_ascii=False)
        fp.write("\n")
    return path


def load_lockfile(lock_path="behavior.lock.json"):
    with open(lock_path, encoding="utf-8") as fp:
        lock_data = json.load(fp)
    validate_lock(lock_data)
    if lock_data['schema_version'] in ('1.0', '1.1'):
        old = lock_data['capabilities']['processes_spawned']
        names = []
        for command in old:
            try:
                parts = shlex.split(command)
            except ValueError:
                parts = command.split()
            if parts:
                names.append(os.path.basename(parts[0]))
        lock_data['capabilities']['processes_spawned'] = sorted(set(names))
    return lock_data


def create_lockfile_for_script(target_script, lock_path="behavior.lock.json",
                               horizons_hours=None):
    result = run_multi_horizon(target_script, horizons_hours=[0] if horizons_hours is None
                               else horizons_hours)
    lock_data = build_lock_data(result, os.path.dirname(os.path.abspath(target_script)))
    save_lockfile(lock_data, lock_path)
    return lock_data
