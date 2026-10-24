import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from isolation import _base_command, limits, preflight, process_quota, stop_tree
from package_input import canonical, file_hash, inspect, stage, wheelhouse
from runner import (_output_events, _public_events, _public_summary, _read_trace, _redact,
                    _risk_actions, _summarize, generate_canaries)


IDENT = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")
ENTRY = re.compile(r"^[A-Za-z_][\w.-]*$")
SECRET = re.compile(r"(?i)(password|secret|token|api[_-]?key|credential|authorization|"
                    r"sk-[a-z0-9-]{8,}|ghp_[a-z0-9]+|AKIA[A-Z0-9]+|://[^/ ]+@)")


def exercise_spec(mode, module=None, entry=None, argv=None, args=None, env=None, distribution=None):
    args = list(args or [])
    env = dict(env or {})
    if mode not in ("import", "console", "command"):
        raise ValueError("exercise mode must be import, console, or command")
    if mode == "import" and (not module or not IDENT.fullmatch(module)):
        raise ValueError("import exercise needs a valid module name")
    if mode == "console" and (not entry or not ENTRY.fullmatch(entry)):
        raise ValueError("console exercise needs a valid entry point name")
    if mode == "command" and (not argv or not isinstance(argv, list) or
                              not all(isinstance(a, str) for a in argv) or
                              "/" in argv[0]):
        raise ValueError("command exercise needs argv starting with a simple executable name")
    if any(not isinstance(a, str) or SECRET.search(a) for a in args + list(argv or [])):
        raise ValueError("exercise arguments must be nonsecret strings")
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) or
           k.startswith("WAKETRACE_") or k in ("PATH", "HOME", "PYTHONPATH", "PYTHONHOME") or
           not isinstance(v, str) or SECRET.search(k) or SECRET.search(v)
           for k, v in env.items()):
        raise ValueError("exercise environment must contain nonsecret string settings")
    return {"mode": mode, "module": module if mode == "import" else None,
            "entry": entry if mode == "console" else None,
            "argv": argv if mode == "command" else None,
            "args": args, "env": env, "distribution": canonical(distribution) if distribution else None}


def _run_one(info, wheels, exercise, hours, age, timeout, setup_timeout,
             memory_mb, output_mb, write_mb, process_limit, observer=False):
    bwrap, python = preflight()
    hook = Path(__file__).resolve().parent / "sandbox_hooks"
    if not (hook / "sitecustomize.py").is_file() or not (hook / "package_launch.py").is_file():
        raise FileNotFoundError("WakeTrace package hook or launcher is missing")
    canaries = generate_canaries()
    with tempfile.TemporaryDirectory(prefix="waketrace-package-") as temp:
        root = Path(temp)
        input_dir, wheel_dir = root / "input", root / "wheels"
        artifact = stage(info, input_dir)
        wheel_dir.mkdir()
        for item in wheels["wheels"]:
            source = Path(wheels["source"], item["file"])
            target = wheel_dir / item["file"]
            shutil.copyfile(source, target)
            if file_hash(target) != item["sha256"]:
                raise ValueError("wheelhouse file changed while staging")
        trace = root / "events.jsonl"
        setup = root / "setup.json"
        trace.touch()
        setup.touch()
        cmd = _base_command(bwrap, str(input_dir), str(trace), str(hook), write_mb)
        cmd += ["--ro-bind", str(wheel_dir), "/wheels", "--bind", str(setup), "/trace/setup.json"]
        env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "TMPDIR": "/tmp",
               "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
               "WAKETRACE_OFFSET_SEC": str(float(hours) * 3600),
               "WAKETRACE_BLOCK_NET": "1", "WAKETRACE_LOG_PATH": "/trace/events.jsonl",
               "WAKETRACE_CANARY_NAMES": ",".join(canaries)}
        env.update(canaries)
        for key, value in env.items():
            cmd.extend(("--setenv", key, value))
        target = "/input" if artifact == "." else "/input/" + artifact
        cmd += ["--", python, "-S", "/hook/package_launch.py", target,
                canonical(info["name"]), json.dumps(exercise, separators=(",", ":")),
                str(setup_timeout), str(age)]
        if observer:
            from observer import command
            observer_prefix = root / "observer"
            cmd = command(cmd, observer_prefix)
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            start = time.monotonic()
            with process_quota(process_limit) as cgroup:
                quota_mode = "private_cgroup_v2" if cgroup else "user_rlimit_nproc"
                process = subprocess.Popen(cmd, env={}, stdout=out, stderr=err,
                                           close_fds=True, start_new_session=True,
                                           preexec_fn=limits(setup_timeout * 2 + timeout,
                                                             memory_mb, min(write_mb, output_mb),
                                                             process_limit, cgroup))
                timed_out = False
                setup_deadline = start + setup_timeout * 2
                exercise_deadline = None
                try:
                    while process.poll() is None:
                        now = time.monotonic()
                        if exercise_deadline is None:
                            try:
                                ready = json.loads(setup.read_text(encoding="utf-8"))
                            except (OSError, ValueError):
                                ready = None
                            if isinstance(ready, dict) and "ok" in ready:
                                exercise_deadline = now + (timeout if ready["ok"] else 1)
                        if now >= (exercise_deadline or setup_deadline):
                            timed_out = True
                            break
                        time.sleep(0.02)
                    exit_code = None if timed_out else process.returncode
                finally:
                    stop_tree(process)
            wall = round(time.monotonic() - start, 4)
            out.seek(0)
            err.seek(0)
            stdout = out.read(output_mb * 1024 * 1024).decode(errors="replace")
            stderr = err.read(output_mb * 1024 * 1024).decode(errors="replace")
        try:
            setup_data = json.loads(setup.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            setup_data = {"ok": False, "stage": "setup", "error": "setup record missing or invalid"}
        events, trace_ok, trace_reason = _read_trace(trace)
        _output_events(events, stdout, stderr)
        summary = _summarize(events, stdout, stderr, canaries, "/work")
        summary = _public_summary(summary, canaries, "/work", "/work")
        if observer:
            from observer import summarize
            observation = summarize(observer_prefix)
        for item in summary['canary_evidence']:
            item['horizon'] = hours
    setup_data["error"] = _redact(setup_data.get("error"), canaries) if setup_data.get("error") else None
    target_meta = setup_data.get("target") or {}
    if setup_data.get("ok") and (target_meta.get("version") != info["version"] or
                                 canonical(target_meta.get("name", "")) != canonical(info["name"])):
        setup_data.update(ok=False, stage="metadata", error="installed package name/version differs from input")
    complete = bool(setup_data.get("ok") and trace_ok and not timed_out and exit_code == 0)
    if not setup_data.get("ok"):
        stage_name = setup_data.get("stage", "setup")
    elif not trace_ok and not timed_out:
        stage_name = "trace"
    else:
        stage_name = "exercise"
    if complete:
        error = None
    elif timed_out:
        error = "timeout"
    elif setup_data.get("error"):
        error = setup_data["error"]
    elif not trace_ok:
        error = trace_reason
    else:
        error = f"exercise exited with {exit_code}"
    return {"target_script": os.path.basename(info["source"]), "offset_hours": hours,
            "wall_time_sec": wall, "virtual_elapsed_sec": max(
                (ev.get("virtual_offset_sec", 0) for ev in events), default =0),
            "exit_code": exit_code, "timed_out": timed_out, "complete": complete,
            "error": error, "failure_stage": None if complete else stage_name,
            "setup": setup_data, "backend": "bubblewrap", "network_isolated": True,
            "process_limit_mode": quota_mode,
            "stdout": _redact(stdout, canaries), "stderr": _redact(stderr, canaries),
            "events": _public_events(events, canaries), "summary": summary,
            **({"observer": observation} if observer else {})}


def run_package_horizons(path, exercise, horizons_hours=None, wheelhouse_path=None,
                         file_age_hours=0, timeout_sec=10, setup_timeout_sec=60,
                         memory_mb=512, output_mb=8, write_limit_mb=256,
                         process_limit=2048, observer=False):
    info = inspect(path)
    if info["kind"] not in ("wheel", "sdist", "source_tree"):
        raise ValueError("package runner needs a wheel, sdist, or pyproject source tree")
    if not isinstance(exercise, dict) or exercise.get("mode") not in ("import", "console", "command"):
        raise ValueError("valid exercise specification required")
    checked = exercise_spec(exercise["mode"], exercise.get("module"),
                            exercise.get("entry"), exercise.get("argv"),
                            exercise.get("args"), exercise.get("env"),
                            exercise.get("distribution"))
    if checked != exercise:
        raise ValueError("exercise specification is invalid or contains unsupported fields")
    wheels = wheelhouse(wheelhouse_path)
    horizons = [0, 24, 72, 168] if horizons_hours is None else list(horizons_hours)
    if not horizons or len(set(horizons)) != len(horizons) or any(
        not isinstance(h, (int, float)) or not math.isfinite(h) or h < 0 for h in horizons):
        raise ValueError("horizons must be unique non-negative finite hours")
    if not math.isfinite(file_age_hours) or file_age_hours < 0:
        raise ValueError("file age must be non-negative finite hours")
    if not math.isfinite(timeout_sec) or timeout_sec <= 0 or \
            not math.isfinite(setup_timeout_sec) or setup_timeout_sec <= 0:
        raise ValueError("setup and exercise timeouts must be positive finite seconds")
    runs = {}
    for hour in horizons:
        runs[str(hour)] = _run_one(info, wheels, exercise, hour, file_age_hours,
                                   timeout_sec, setup_timeout_sec, memory_mb,
                                   output_mb, write_limit_mb, process_limit, observer)
    base = _risk_actions(runs[str(0)]["summary"]) if 0 in horizons else None
    triggers = [hour for hour in horizons if hour > 0 and base is not None and
                _risk_actions(runs[str(hour)]["summary"]) - base]
    return {"target_script": info["source"], "artifact": {k: v for k, v in info.items() if k != "files"},
            "wheelhouse": wheels, "exercise": exercise, "file_age_hours": file_age_hours,
            "horizons_tested": horizons, "runs": runs,
            "time_bomb_detected": bool(triggers),
            "first_trigger_hour": min(triggers) if triggers else None}
