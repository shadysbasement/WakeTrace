"""Strict, bounded input contract for the admission gate"""

import hashlib
import json
import math
from pathlib import Path
import re

from differ import policy_config
from package_input import inspect
from package_runner import SECRET, exercise_spec


HEX = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,39}\Z")
LIMITS = {"timeout": 10, "setup_timeout": 60, "memory_mb": 512,
          "output_mb": 8, "write_mb": 32, "process_limit": 2048}
MAX_LIMITS = {"timeout": 120, "setup_timeout": 180, "memory_mb": 2048,
              "output_mb": 16, "write_mb": 256, "process_limit": 2048}


def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode()).hexdigest()


def keys(data, allowed, label):
    if not isinstance(data, dict) or set(data) - set(allowed):
        raise ValueError(f"invalid or unknown {label} fields")


def inside(path, root):
    return path == root or root in path.parents


def input_path(value, root, must_exist=True):
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError("input path must be a short string")
    path = Path(value).expanduser().absolute()
    if ".." in path.parts:
        raise ValueError("input path may not contain parent traversal")
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("input paths may not use symlinks")
    path = path.resolve(strict=must_exist)
    if not inside(path, root) or must_exist and not path.exists():
        raise ValueError("input path is missing or outside the permitted root")
    return str(path)


def output_path(value, root):
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError("output path must be a short string")
    path = Path(value).expanduser().absolute()
    if ".." in path.parts:
        raise ValueError("output path may not contain parent traversal")
    if any(part.is_symlink() for part in (path.parent, *path.parent.parents)):
        raise ValueError("output path may not use symlinks")
    path = path.resolve(strict=False)
    if not inside(path, root) or path == root or path.is_symlink() or \
            path.exists() and not path.is_file():
        raise ValueError("output path is unsafe, existing, or outside the output root")
    return str(path)


def load(path, input_root, output_root, require_approval=True):
    source = Path(path)
    if source.stat().st_size > 65536:
        raise ValueError("gate plan exceeds size limit")
    data = json.loads(source.read_text(encoding="utf-8"))
    keys(data, ("schema_version", "revision", "candidate", "baseline", "scenarios",
                "horizons", "file_age_hours", "wheelhouse", "limits", "observer",
                "policy", "output"), "plan")
    if data.get("schema_version") != "1.0" or not isinstance(data.get("revision"), str) or \
            not ID.fullmatch(data["revision"]):
        raise ValueError("unsupported gate plan version or revision")
    input_root = Path(input_root).expanduser().resolve(strict=True)
    output_root = Path(output_root).expanduser().resolve(strict=True)
    if not input_root.is_dir() or not output_root.is_dir():
        raise ValueError("gate roots must be directories")
    candidate = data.get("candidate")
    keys(candidate, ("type", "path", "sha256"), "candidate")
    if candidate.get("type") not in ("script", "script_bundle", "package") or not isinstance(candidate.get("sha256"), str) or \
            not HEX.fullmatch(candidate["sha256"]):
        raise ValueError("candidate type or SHA-256 is invalid")
    candidate = {**candidate, "path": input_path(candidate.get("path"), input_root)}
    info = inspect(candidate["path"])
    expected_kind = {"script": "script", "script_bundle": "executable_directory"}
    if candidate["type"] in expected_kind and info["kind"] != expected_kind[candidate["type"]] or \
            candidate["type"] == "package" and info["kind"] not in ("wheel", "sdist", "source_tree"):
        raise ValueError("candidate type does not match its artifact")
    baseline = data.get("baseline")
    keys(baseline, ("path", "sha256", "locks", "manifest", "signature"), "baseline")
    if not isinstance(baseline.get("sha256"), str) or not HEX.fullmatch(baseline["sha256"]):
        raise ValueError("baseline SHA-256 is invalid")
    baseline = {**baseline, "path": input_path(baseline.get("path"), input_root),
                "manifest": input_path(baseline.get("manifest"), input_root, require_approval),
                "signature": input_path(baseline.get("signature"), input_root, require_approval)}
    base_info = inspect(baseline["path"])
    if candidate["type"] in expected_kind and base_info["kind"] != expected_kind[candidate["type"]] or \
            candidate["type"] == "package" and base_info["kind"] not in ("wheel", "sdist", "source_tree"):
        raise ValueError("baseline and candidate types differ")
    horizons = data.get("horizons")
    if not isinstance(horizons, list) or not 1 <= len(horizons) <= 8 or \
            any(isinstance(h, bool) or not isinstance(h, (int, float)) or
                not math.isfinite(h) or not 0 <= h <= 8760 for h in horizons) or \
            len(set(horizons)) != len(horizons):
        raise ValueError("horizons must contain 1-8 unique hours in 0-8760")
    scenarios = data.get("scenarios")
    if not isinstance(scenarios, list) or not 1 <= len(scenarios) <= 8 or \
            len(scenarios) * len(horizons) > 32:
        raise ValueError("gate needs 1-8 scenarios and at most 32 runs per artifact")
    checked = []
    for scenario in scenarios:
        keys(scenario, ("id", "args", "env", "exercise"), "scenario")
        if not isinstance(scenario.get("id"), str) or not ID.fullmatch(scenario["id"]):
            raise ValueError("scenario ID is invalid")
        if candidate["type"] != "package":
            args = scenario.get("args", [])
            env = scenario.get("env", {})
            if "exercise" in scenario or not isinstance(args, list) or len(args) > 20 or \
                    any(not isinstance(x, str) or len(x) > 256 or SECRET.search(x) for x in args):
                raise ValueError("script scenario needs bounded args")
            if not isinstance(env, dict) or len(env) > 20 or any(
                    not isinstance(k, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) or
                    k.startswith("WAKETRACE_") or k in ("PATH", "HOME", "PYTHONPATH", "PYTHONHOME") or
                    not isinstance(v, str) or len(v) > 256 or SECRET.search(k) or SECRET.search(v)
                    for k, v in env.items()):
                raise ValueError("script environment must contain bounded nonsecret settings")
            checked.append({"id": scenario["id"], "args": args, "env": env})
        else:
            if "args" in scenario:
                raise ValueError("package scenario uses exercise, not args")
            spec = scenario.get("exercise")
            keys(spec, ("mode", "module", "entry", "argv", "args", "env", "distribution"), "exercise")
            exercise = exercise_spec(spec.get("mode"), spec.get("module"), spec.get("entry"),
                                     spec.get("argv"), spec.get("args"), spec.get("env"),
                                     spec.get("distribution"))
            strings = list(exercise["args"]) + list(exercise["argv"] or []) + \
                list(exercise["env"].values())
            if len(exercise["args"]) > 20 or len(exercise["argv"] or []) > 20 or \
                    len(exercise["env"]) > 20 or any(len(value) > 256 for value in strings):
                raise ValueError("package exercise inputs exceed gate limits")
            checked.append({"id": scenario["id"], "exercise": exercise})
    if len({s["id"] for s in checked}) != len(checked):
        raise ValueError("scenario IDs repeat")
    locks = baseline.get("locks")
    if not isinstance(locks, dict) or set(locks) != {s["id"] for s in checked}:
        raise ValueError    ("baseline must name one lock per scenario")
    baseline["locks"] = {key: input_path(value, input_root) for key, value in locks.items()}
    age = data.get("file_age_hours", 0)
    if isinstance(age, bool) or not isinstance(age, (int, float)) or not math.isfinite(age) or not 0 <= age <= 8760:
        raise ValueError("invalid file age")
    limits = data.get("limits", {})
    keys(limits, LIMITS, "limits")
    limits = {**LIMITS, **limits}
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 < v <= MAX_LIMITS[k]
           or k in ("memory_mb", "output_mb", "write_mb", "process_limit") and not isinstance(v, int)
           for k, v in limits.items()):
        raise ValueError("invalid resource limit")
    observer = data.get("observer", {"mode": "strace", "required": True})
    if observer != {"mode": "strace", "required": True}:
        raise ValueError("host strace observer is required")
    policy = policy_config(data.get("policy"))
    wheelhouse = data.get("wheelhouse")
    if wheelhouse is not None:
        wheelhouse = input_path(wheelhouse, input_root)
        if not Path(wheelhouse).is_dir():
            raise ValueError("wheelhouse must be a directory")
    if candidate["type"] != "package" and wheelhouse is not None:
        raise ValueError("script plan cannot use a wheelhouse")
    output = data.get("output")
    keys(output, ("result", "summary"), "output")
    output = {name: output_path(output.get(name), output_root) for name in ("result", "summary")}
    if len(set(output.values())) != 2:
        raise ValueError("gate outputs overlap")
    protected = {str(source.resolve(strict=True)), candidate["path"], baseline["path"],
                 baseline["manifest"], baseline["signature"], *baseline["locks"].values()}
    if any(out in protected for out in output.values()):
        raise ValueError("gate output overlaps a plan or approved input")
    for item in (candidate["path"], baseline["path"], wheelhouse):
        if item and Path(item).is_dir() and any(inside(Path(out), Path(item)) for out in output.values()):
            raise ValueError("gate output overlaps an input tree")
    return {"schema_version": "1.0", "revision": data["revision"],
            "candidate": candidate, "baseline": baseline, "scenarios": checked,
            "horizons": horizons, "file_age_hours": age, "wheelhouse": wheelhouse,
            "limits": limits, "observer": observer, "policy": policy, "output": output}
