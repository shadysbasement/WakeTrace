import ast
import base64
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
import time
from urllib.parse import quote, urlsplit

from isolation import _base_command, limits, preflight, process_quota, stop_tree


DEFAULT_KEYS = (
    "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN",
    "STRIPE_SECRET_KEY", "DATABASE_URL",
)
SKIP_DIRS = {".git", "__pycache__", "venv", ".venv", "node_modules",
             ".ssh", ".aws", ".gnupg", ".kube"}
SKIP_FILES = {".env", ".npmrc", ".pypirc", ".gitconfig"}


def generate_canaries(seed_Names=None):
    prefixes = {
        "AWS_SECRET_ACCESS_KEY": "AKIA_WAKE_",
        "OPENAI_API_KEY": "sk-proj-wake-",
        "GITHUB_TOKEN": "ghp_wake_",
        "STRIPE_SECRET_KEY": "sk_test_wake_",
        "DATABASE_URL": "postgresql://wake:wake_",
    }
    canaries = {}
    for name in DEFAULT_KEYS if seed_Names is None else seed_Names:
        token = secrets.token_hex(6)
        value = prefixes.get(name, "wake_") + token
        if name == "DATABASE_URL":
            value += "@localhost/wake"
        canaries[name] = value
    return canaries


def check_for_leaks(text_blob, canaries_dict):
    text_blob = str(text_blob)
    leaked = []
    for name, value in canaries_dict.items():
        forms = (value, base64.b64encode(value.encode()).decode(),
                 value.encode().hex(), quote(value), quote(value, safe=""))
        if any(form in text_blob for form in forms):
            leaked.append(name)
    return sorted(leaked)


@contextmanager
def backdate_files(target_dir, shift_seconds):
    if shift_seconds <= 0:
        yield
        return

    orig_times = {}
    shift_ns = round(shift_seconds * 1_000_000_000)
    def collect(path):
        if os.path.islink(path):
            return
        st = os.stat(path)
        orig_times[path] = (st.st_atime_ns, st.st_mtime_ns)
        if os.path.isdir(path):
            with os.scandir(path) as entries:
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False) and entry.name in SKIP_DIRS:
                        continue
                    collect(entry.path)

    collect(target_dir)

    try:
        for path, (atime, mtime) in orig_times.items():
            os.utime(path, ns=(atime - shift_ns, mtime - shift_ns))
        yield
    finally:
        #puttin directories at the last cuz the child may have created files in them
        for path in sorted(orig_times, key=lambda p: os.fspath(p).count(os.sep), reverse=True):
            if os.path.exists(path):
                os.utime(path, ns=orig_times[path])


def _file_path(path, root):
    return os.path.normpath(os.path.join(root, path))


def _is_write(extra):
    mode = extra.get("mode", "")
    flags = extra.get("flags", 0)
    return any(ch in mode for ch in "wax+") or isinstance(flags, int) and bool(
        flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
    )


def _command(ev):
    target = str(ev.get("target", ""))
    if (ev.get("extra") or {}).get("event") != "subprocess.Popen":
        return target
    try:
        args = ast.literal_eval(ev["extra"]["raw_args"])
        return shlex.join(map(str, args)) if isinstance(args, (list, tuple)) else str(args)
    except (KeyError, SyntaxError, ValueError, TypeError, IndexError):
        return target


def _summarize(events, stdout, stderr, canaries, root):
    reads, writes, env_reads = set(), set(), set()
    nets, procs, libs = set(), set(), set()
    evidence = []
    def add(name, channel, stage, event_id=None, status='unknown', **details):
        item = {'name': name, 'channel': channel, 'stage': stage,
                'event_id': event_id, 'status': status}
        item.update(details)
        if item not in evidence:
            evidence.append(item)
    sleeps = []
    for ev in events:
        category = ev.get("category")
        target = str(ev.get("target", ""))
        extra = ev.get("extra") or {}
        if category == "file" and ev.get("action") == "file_open":
            path = _file_path(target, root)
            if _is_write(extra):
                writes.add(path)
            else:
                reads.add(path)
        elif category == "env" and ev.get("action") == "env_read":
            env_reads.add(target)
            if target in canaries and extra.get('found'):
                add(target, 'environment_read', 'read', ev.get('id'))
        elif category == "net":
            nets.add((target, bool(extra.get("blocked", False))))
            for name in check_for_leaks(target, canaries):
                add(name, 'network_attempt', 'prepared_request' if
                    extra.get('audit_event') == 'urllib.Request' else 'connection_attempt',
                    ev.get('id'), 'blocked' if extra.get('blocked') else 'allowed',
                    hook_status='blocked' if extra.get('blocked') else 'allowed',
                    os_status='unknown', blocker='WakeTrace hook' if extra.get('blocked') else None)
        elif category == "process":
            procs.add(_command(ev))
            for name in check_for_leaks(extra.get('raw_args', ''), canaries):
                add(name, 'process_argument', 'spawn_attempt', ev.get('id'))
        elif category == "native" and ev.get("action") == "dlopen":
            libs.add(target)
        elif category == "canary" and ev.get("action") == "written_value":
            if target in canaries:
                add(target, 'written_file', 'shutdown_scan', ev.get('id'))
        elif category == "time" and ev.get("action") == "sleep_skipped":
            try:
                amount = float(target)
                if math.isfinite(amount):
                    sleeps.append(amount)
            except ValueError:
                pass

    for name in check_for_leaks(stdout, canaries):
        event = next((e['id'] for e in events if e.get('category') == 'output' and
                      e.get('target') == 'stdout'), None)
        add(name, 'stdout', 'captured_output', event)
    for name in check_for_leaks(stderr, canaries):
        event = next((e['id'] for e in events if e.get('category') == 'output' and
                      e.get('target') == 'stderr'), None)
        add(name, 'stderr', 'captured_output', event)
    return {
        "files_read": sorted(reads),
        "files_written": sorted(writes),
        "env_vars_read": sorted(env_reads),
        "network_attempts": [dict(target=t, blocked=b) for t, b in sorted(nets)],
        "processes_spawned": sorted(procs),
        "native_libs_loaded": sorted(libs),
        "sleeps_skipped": {"count": len(sleeps), "total_sec": sum(sleeps)},
        "canary_evidence": evidence,
        "observed_canaries": sorted({item['name'] for item in evidence}),
    }


def _stage(source, work, limit_mb):
    copied = 0
    for folder, dirs, files in os.walk(source):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS and
                   not os.path.islink(os.path.join(folder, name))]
        relative = os.path.relpath(folder, source)
        dest = work if relative == "." else os.path.join(work, relative)
        os.makedirs(dest, exist_ok=True)
        for name in files:
            src = os.path.join(folder, name)
            if name in SKIP_FILES or name.startswith(".env") or os.path.islink(src):
                continue
            if os.path.isfile(src):
                copied += os.path.getsize(src)
                if copied > limit_mb * 1024 * 1024:
                    raise ValueError("staged input exceeds the writable workspace limit")
                shutil.copy2(src, os.path.join(dest, name))


def _redact(value, canaries):
    value = str(value)
    for name, secret in canaries.items():
        forms = (secret, base64.b64encode(secret.encode()).decode(),
                 secret.encode().hex(), quote(secret), quote(secret, safe=""))
        for form in forms:
            value = value.replace(form, f"<CANARY:{name}>")
    value = re.sub(r"https?://[^\s'\"]+", lambda match:
                   re.sub(r"//[^/@]+@", "//<redacted>@", 
                   match.group(0).split("?", 1)[0]) +
            ("?<redacted>" if "?" in match.group(0) else ""),
            value)
    value = re.sub(r"(?i)(\b(?:--?[\w-]*(?:password|secret|token|api[-_]?key|credential)"
                   r"[\w-]*[= ]|(?:PASSWORD|SECRET|TOKEN|API_KEY|CREDENTIAL)=))(\S+)",
                   lambda match: match.group(1) + "<redacted>", value)
    return value


def _public_events(events, canaries):
    public = []
    allowed = {'file': {'mode', 'flags'}, 'env': {'found'},
               'net': {'blocked', 'audit_event'}, 'process': {'event'},
                'native': {'event'}, 'time': {'new_offset_sec'},
                'canary': {'path'}, 'output': {'length'}, 'health': set()}
    for ev in events:
        item = {key: ev[key] for key in ('id', 'ts_real', 'ts_warped',
                                         'virtual_offset_sec', 'category', 'action')
                if key in ev}
        source = ev.get('source') or {}
        if source.get('status') == 'known' and isinstance(source.get('path'), str) and \
                source['path'].startswith(('<PROJECT>/', '<PACKAGE>/')) and \
                isinstance(source.get('line'), int) and source['line'] > 0:
            item['source'] = {'status': 'known', 'path': _redact(source['path'][:256], canaries),
                              'line': source['line'], 'function':str(source.get('function', 'unknown'))[:80]}
        else:
            reason = source.get('reason')
            if reason not in ('hook lifecycle or shutdown scan', 'no target frame',
                              'captured stream'):
                reason = 'no trustworthy target frame'
            item['source'] = {'status': 'unknown', 'reason': reason}
        if item.get('category') == 'net':
            item['target'] = _network_name(ev.get('target', ''))
        elif item.get('category') == 'process':
            item['target'] = os.path.basename(str(ev.get('target', '')))
        elif item.get('category') == 'health':
            item['target'] = 'hook'
        elif item.get('category') == 'canary':
            item['target'] = ev['target'] if ev['target'] in canaries else '<unknown-canary>'
        elif item.get('category') == 'native':
            item['target'] = os.path.basename(str(ev.get('target', '')))
        else:
            target = str(ev.get('target', ''))
            if target.startswith('/work/venv/lib/') and '/site-packages/' in target:
                target = '<PACKAGE>/' + target.split('/site-packages/', 1)[1]
            elif target.startswith('/work/'):
                target = '<PROJECT>/' + target[6:]
            elif item.get('category') == 'file' and not os.path.isabs(target):
                target = '<PROJECT>/' + os.path.normpath(target).replace('\\', '/')
            item["target"] = _redact(target, canaries)
        extra = {key: value for key, value in (ev.get('extra') or {}).items()
                 if key in allowed.get(item.get('category'), set())}
        if item.get('category') == 'canary' and isinstance(extra.get('path'), str):
            extra['path'] = _redact(extra['path'].replace('/work/', '<PROJECT>/'), canaries)
        clean = {}
        for key, value in extra.items():
            if key in ('found', 'blocked') and isinstance(value, bool):
                clean[key] = value
            elif key in ('flags', 'length') and isinstance(value, int) and not isinstance(value, bool):
                clean[key] = value
            elif key == 'mode' and isinstance(value, str) and re.fullmatch('[rwaxt+b]{1,8}', value):
                clean[key] = value
            elif key == 'audit_event' and value in ('urllib.Request', 'socket.connect', 'socket.sendto'):
                clean[key] = value
            elif key == 'event' and value in ('subprocess.Popen', 'os.system', 'os.exec',
                                              'os.spawn', 'os.posix_spawn', 'ctypes.dlopen',
                                              'ctypes.dlsym'):
                clean[key] = value
            elif key == 'path' and isinstance(value,str):
                clean[key] = _redact(value[:512], canaries)
            elif key == 'new_offset_sec' and isinstance(value, (int, float)) and math.isfinite(value):
                clean[key] = value
        item['extra'] = clean
        public.append(item)
    return public


def _public_summary(summary, canaries, stage, original):
    for key in ("files_read", "files_written"):
        summary[key] = [_redact(original + path[len(stage):] if path == stage or
                                path.startswith(stage + os.sep) else path, canaries)
                                for path in summary[key]]
    summary["network_attempts"] = [
        {"target": _network_name(item["target"]), "blocked": item["blocked"]}
        for item in summary["network_attempts"]]
    summary['env_vars_read'] = [name if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', name)
                                else '<redacted-env-name>' for name in summary['env_vars_read']]
    summary["processes_spawned"] = [os.path.basename(_process_name(_redact(cmd, canaries)))
                                    for cmd in summary["processes_spawned"]]
    summary['native_libs_loaded'] = [os.path.basename(_redact(path, canaries))
                                     for path in summary['native_libs_loaded']]
    return summary


MAX_EVENTS = 5000


def _output_events(events, stdout, stderr):
    for channel, value in (('stdout', stdout), ('stderr', stderr)):
        if value:
            events.append({'id': len(events)+ 1, 'category': 'output',
                           'action': 'captured', 'target': channel,
                           'extra': {'length': len(value)},
                           'source': {'status': 'unknown', 'reason': 'captured stream'}})


def _read_trace(path):
    events = []
    valid = True
    reason = None
    try:
        with open(path, encoding="utf-8", errors="replace") as fp:
            for line in fp:
                if len(events) >= MAX_EVENTS:
                    valid = False
                    reason = 'event limit exceeded'
                    break
                if len(line) > 262144:
                    valid = False
                    reason = 'trace event too large'
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    valid = False
                    reason = 'trace parse failure'
                    continue
                if not isinstance(event, dict) or not {"category", "action", "target", "id"} <= event.keys() \
                        or not isinstance(event.get('id'), int) or isinstance(event.get('id'), bool) \
                        or not all (isinstance(event.get(k), str) for k in ('category', 'action', 'target')) \
                        or event.get('category') not in ('health', 'file', 'env', 'net',
                                                         'process', 'native', 'canary', 'time') \
                        or not isinstance(event.get('extra', {}), dict) \
                        or not isinstance(event.get('source', {}), dict) \
                        or not isinstance(event.get('virtual_offset_sec', 0), (int, float)) \
                        or not math.isfinite(event.get('virtual_offset_sec', 0)) \
                        or event['id'] <= 0 \
                        or event['id'] != len(events) + 1:
                    valid = False
                    reason = 'invalid or out-of-order trace event'
                else:
                    events.append(event)
    except OSError:
        return [], False, 'trace missing'
    ready = any(ev["category"] == "health" and ev["action"] == "hook_ready"
                for ev in events)
    done = any(ev["category"] == "health" and ev["action"] == "hook_done"
               for ev in events)
    if any(ev['category'] == 'health' and ev['action'] == 'canary_scan_incomplete'
           for ev in events):
           valid = False
           reason = 'canary file scan exceeded limit'
    if not ready or not done:
        reason = reason or 'hook start/end missing'
    return events, valid and ready and done, reason


def run_in_sandbox(target_script, offset_hours=0.0, timeout_sec=10, block_net=True,
                   allow_hosts=None, extra_args=None, custom_canaries=None,
                   backdate_mtime_hours=0.0, memory_mb=512, output_mb=8,
                   write_limit_mb=32, process_limit=2048, observer=False,
                   extra_env=None):
    target_script = os.path.abspath(target_script)
    is_script = os.path.isfile(target_script)
    is_package = os.path.isdir(target_script) and os.path.isfile(
        os.path.join(target_script, "__main__.py"))
    if not (is_script or is_package):
        raise FileNotFoundError(f"Target script or executable package not found: {target_script}")
    if is_package:
        from package_input import inspect
        info = inspect(target_script)
        for name in info["files"]:
            parts = Path(name).parts
            if any(part in SKIP_DIRS for part in parts[:-1]) or \
                    parts[-1] in SKIP_FILES or parts[-1].startswith(".env"):
                raise ValueError(f"executable directory contains unstaged file: {name}")
    hook_dir = Path(__file__).resolve().parent / "sandbox_hooks"
    if not (hook_dir / "sitecustomize.py").is_file():
        raise FileNotFoundError(f"WakeTrace hook not found in {hook_dir}")
    bwrap, python = preflight()
    root = os.path.dirname(target_script)
    canaries = (dict(custom_canaries) if isinstance(custom_canaries, dict) else
                generate_canaries(custom_canaries))
    with tempfile.TemporaryDirectory(prefix="waketrace-") as temp:
        work = os.path.join(temp, "work")
        trace = os.path.join(temp, "trace")
        os.mkdir(work)
        os.mkdir(trace)
        if is_package:
            package_copy = os.path.join(work, os.path.basename(target_script))
            os.mkdir(package_copy)
            _stage(target_script, package_copy, write_limit_mb)
        else:
            _stage(root, work, write_limit_mb)
        dummy_env = os.path.join(work, ".env")
        with open(dummy_env, "w", encoding="utf-8") as fp:
            fp.writelines(f"{key}={value}\n" for key, value in canaries.items())
        log_path = os.path.join(trace, "events.jsonl")
        Path(log_path).touch()
        env = {
            "PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "TMPDIR": "/tmp",
            "LANG": "C.UTF-8", "PYTHONPATH": "/hook", "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "WAKETRACE_ACTIVE": "1", "WAKETRACE_OFFSET_SEC": str(float(offset_hours) * 3600),
            "WAKETRACE_BLOCK_NET": "1" if block_net else "0",
            "WAKETRACE_PROJECT_ROOT": "/work", "WAKETRACE_LOG_PATH": "/trace/events.jsonl",
            "WAKETRACE_CANARY_NAMES": ",".join(canaries),
        }
        if allow_hosts is not None:
            env["WAKETRACE_ALLOW_HOSTS"] = ",".join(allow_hosts)
        env.update(canaries)
        if extra_env:
            env.update(extra_env)
        target = os.path.basename(target_script)
        cmd = _base_command(bwrap, work, log_path, hook_dir, write_limit_mb)
        for key, val in env.items():
            cmd += ["--setenv", key, str(val)]
        cmd += ["--", python, "-S", "/hook/launch.py", "/input", target,
                *(extra_args or [])]
        if observer:
            from observer import command
            observer_prefix = Path(temp) / "observer"
            cmd = command(cmd, observer_prefix)
        with backdate_files(work, float(backdate_mtime_hours) * 3600):
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                start = time.monotonic()
                with process_quota(process_limit) as cgroup:
                    quota_mode = "private_cgroup_v2" if cgroup else "user_rlimit_nproc"
                    process = subprocess.Popen(cmd, env={}, stdout=out, stderr=err,
                                               close_fds=True, start_new_session=True,
                                               preexec_fn=limits(timeout_sec, memory_mb,
                                                                 min(output_mb, write_limit_mb),
                                                                 process_limit, cgroup))
                    timed_out = False
                    try:
                        exit_code = process.wait(timeout=timeout_sec)
                    except subprocess.TimeoutExpired:
                        timed_out, exit_code = True, None
                    finally:
                        stop_tree(process)
                wall_time = round(time.monotonic() - start, 4)
                out.seek(0)
                err.seek(0)
                stdout = out.read(output_mb * 1024 * 1024).decode(errors="replace")
                stderr = err.read(output_mb * 1024 * 1024).decode(errors="replace")
        events, trace_ok, trace_reason = _read_trace(log_path)
        _output_events(events, stdout, stderr)
        summary = _summarize(events, stdout, stderr, canaries, "/work")
        summary = _public_summary(summary, canaries, "/work", root)
        if observer:
            from observer import summarize
            observation = summarize(observer_prefix)
    complete = trace_ok and not timed_out and exit_code == 0
    public_events = _public_events(events, canaries)
    for item in summary['canary_evidence']:
        item['horizon'] = offset_hours
    return {
        "target_script": os.path.basename(target_script),
        "offset_hours": offset_hours, "wall_time_sec": wall_time,
        "virtual_elapsed_sec": max((ev.get("virtual_offset_sec", 0) for ev in events), default=0),
        "exit_code": exit_code, "timed_out": timed_out,
        "complete": complete, "failure_stage": None if complete else
            ('timeout' if timed_out else 'trace' if not trace_ok else 'execution'),
        "error": None if complete else
            ("timeout" if timed_out else trace_reason if not trace_ok else
             f"target exited with {exit_code}"),
        "backend": "bubblewrap", "network_isolated": True,
        "process_limit_mode": quota_mode,
        "stdout": _redact(stdout, canaries), "stderr": _redact(stderr, canaries),
        "events": public_events, "summary": summary,
        **({"observer": observation} if observer else {}),
    }


def _network_name(target):
    try:
        address = ast.literal_eval(target)
        if isinstance(address, tuple) and address:
            target = str(address[0])
    except (SyntaxError, ValueError, TypeError):
        pass
    try:
        host = urlsplit(target).hostname or target
    except ValueError:
        return '<unknown-host>'
    return host.lower() if len(host) <= 253 and re.fullmatch(r'[A-Za-z0-9.:-]+', host) \
        else '<unknown-host>'


def _process_name(command):
    try:
        parts = shlex.split(command)
    except ValueError:
        return command
    return parts[0] if parts else command


def _risk_actions(summary):
    risks = {("net", _network_name(item["target"]))
             for item in summary["network_attempts"]}
    risks.update(("process", _process_name(cmd))
                 for cmd in summary["processes_spawned"])
    risks.update(("env", name) for name in summary["env_vars_read"]
                 if any(word in name.upper() for word in
                        ("SECRET", "TOKEN", "API_KEY", "PASSWORD", "DATABASE_URL", "CREDENTIAL")))
    risks.update(("canary", item['name'], item['channel'])
                 for item in summary.get('canary_evidence', []))
    return risks


def run_multi_horizon(target_script, horizons_hours=None, timeout_sec=10,
                      block_net=True, allow_hosts=None, extra_args=None,
                      memory_mb=512, output_mb=8, write_limit_mb=32,
                      process_limit=2048, backdate_mtime_hours=0.0,
                      observer=False, extra_env=None):
    horizons = [0, 1, 24, 72, 168] if horizons_hours is None else list(horizons_hours)
    if not horizons or len(horizons) != len(set(horizons)) or any(
            isinstance(h, bool) or not isinstance(h, (int, float)) or
            not math.isfinite(h) or h < 0 for h in horizons):
        raise ValueError('horizons must be unique non-negative finite hours')
    runs = {}
    for hours in horizons:
        runs[str(hours)] = run_in_sandbox(
            target_script, offset_hours=hours, timeout_sec=timeout_sec,
            block_net=block_net, allow_hosts=allow_hosts, extra_args=extra_args,
            memory_mb=memory_mb, output_mb=output_mb,
            write_limit_mb=write_limit_mb, process_limit=process_limit,
            backdate_mtime_hours=backdate_mtime_hours,
            observer=observer,
            extra_env=extra_env,
        )
    zero = next((hours for hours in horizons if hours == 0), None)
    baseline = _risk_actions(runs[str(zero)]["summary"]) if zero is not None else None
    triggers = [hours for hours in horizons if hours > 0 and baseline is not None and
                _risk_actions(runs[str(hours)]["summary"]) - baseline]
    return {
        "target_script": os.path.abspath(target_script),
        "file_age_hours": backdate_mtime_hours,
        "horizons_tested": horizons,
        "runs": runs,
        "time_bomb_detected": bool(triggers),
        "first_trigger_hour": min(triggers) if triggers else None,
    }