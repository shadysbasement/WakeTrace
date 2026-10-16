import os


def _install():
    import atexit
    import base64
    import datetime
    import functools
    import json
    import socket
    import sys
    import threading
    import time
    from urllib.parse import quote, urlsplit

    def number(name, default):
        try:
            return float(os.environ.get(name, default))
        except (TypeError, ValueError):
            return default

    log_path = os.path.abspath(os.environ.get(
        "WAKETRACE_LOG_PATH", os.path.join(os.getcwd(), "waketrace_trace.jsonl")
    ))
    initial_offset = number("WAKETRACE_OFFSET_SEC", 0.0)
    sleep_threshold = max(0.0, number("WAKETRACE_SLEEP_THRESHOLD", 0.1))
    block_net = os.environ.get("WAKETRACE_BLOCK_NET", "0") == "1"
    allow_hosts = {
        host.strip().lower() for host in
        os.environ.get("WAKETRACE_ALLOW_HOSTS", "127.0.0.1,localhost,::1").split(",")
        if host.strip()
    }
    project_root = os.path.normcase(os.path.abspath(
        os.environ.get("WAKETRACE_PROJECT_ROOT", os.getcwd())
    ))
    canary_names = os.environ.get("WAKETRACE_CANARY_NAMES", "").split(",")
    canaries = {name: os.environ[name] for name in canary_names if name in os.environ}
    for key in list(os.environ):
        if key.startswith("WAKETRACE_"):
            del os.environ[key]

    hook_dir = os.path.normcase(os.path.abspath(os.path.dirname(__file__)))
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    log_fp = open(log_path, "a", encoding="utf-8", buffering=1)
    atexit.register(log_fp.close)

    orig_time = time.time
    orig_monotonic = time.monotonic
    orig_perf_counter = time.perf_counter
    orig_sleep = time.sleep
    real_datetime = datetime.datetime
    orig_env_getitem = os.environ.__class__.__getitem__
    skipped_sleep = 0.0
    lock = threading.Lock()
    tls = threading.local()
    sequence = 0

    def source():
        frame = sys._getframe(2)
        try:
            for _ in range(32):
                if frame is None:
                    break
                path = frame.f_code.co_filename
                if path.startswith('/work/venv/') and '/site-packages/' in path:
                    return {'status': 'known', 'path': '<PACKAGE>' +
                            path.split('/site-packages/', 1)[1],
                            'line': frame.f_lineno, 'function': frame.f_code.co_name}
                if path.startswith('/work/') and not path.startswith('/work/venv/'):
                    return {'status': 'known', 'path': '<PROJECT>/' + path[6:],
                            'line': frame.f_lineno, 'function': frame.f_code.co_name}
                frame = frame.f_back
            return {'status': 'unknown', 'reason': 'no target frame'}
        finally:
            del frame

    def offset():
        with lock:
            return initial_offset + skipped_sleep

    def get_warped_time():
        return orig_time() + offset()

    def log_event(category, action, target, extra=None):
        nonlocal sequence
        if getattr(tls, "in_hook", False):
            return
        tls.in_hook = True
        try:
            real = orig_time()
            shift = offset()
            event = {
                'id': sequence + 1,
                "ts_real": real,
                "ts_warped": real + shift,
                "virtual_offset_sec": shift,
                "category": category,
                "action": action,
                "target": str(target),
                "extra": extra or {},
                'source': source() if category not in ('health', 'canary') else
                          {'status': 'unknown', 'reason': 'hook lifecycle or shutdown scan'},  
            }
            with lock:
                sequence += 1
                event['id'] = sequence
                log_fp.write(json.dumps(event, ensure_ascii=False) + "\n")
        finally:
            tls.in_hook = False

    def warped_clock(real_fn):
        @functools.wraps(real_fn)
        def clock():
            return real_fn() + offset()

        clock.__module__ = "time"
        return clock

    @functools.wraps(orig_sleep)
    def warped_sleep(secs):
        nonlocal skipped_sleep
        if secs >= sleep_threshold and secs >= 0:
            with lock:
                skipped_sleep += float(secs)
                new_offset = initial_offset + skipped_sleep
            log_event("time", "sleep_skipped", str(secs), {"new_offset_sec": new_offset})
            return None
        return orig_sleep(secs)

    time.time = warped_clock(orig_time)
    time.monotonic = warped_clock(orig_monotonic)
    time.perf_counter = warped_clock(orig_perf_counter)
    time.sleep = warped_sleep
    time.sleep.__module__ = "time"

    class _WarpedDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.fromtimestamp(get_warped_time(), tz)

        @classmethod
        def utcnow(cls):
            return cls.fromtimestamp(get_warped_time(), datetime.timezone.utc).replace(tzinfo=None)

    _WarpedDatetime.__name__ = "datetime"
    _WarpedDatetime.__qualname__ = "datetime"
    _WarpedDatetime.__module__ = "datetime"
    datetime.datetime = _WarpedDatetime

    def env_getitem(self, key):
        if getattr(tls, "in_hook", False):
            return orig_env_getitem(self, key)
        try:
            value = orig_env_getitem(self, key)
        except KeyError:
            log_event("env", "env_read", key, {"found": False})
            raise
        log_event("env", "env_read", key, {"found": True})
        return value

    os.environ.__class__.__getitem__ = env_getitem

    def inside(path, root):
        try:
            return os.path.commonpath((path, root)) == root
        except ValueError:
            return False

    ignored = tuple(os.path.normcase(os.path.abspath(p)) for p in
                    (sys.prefix, sys.base_prefix, hook_dir))

    def audit_hook(event, args):
        if getattr(tls, "in_hook", False):
            return
        if event == "open":
            path, mode, flags = args
            if isinstance(path, int):
                return
            path_str = os.fsdecode(os.fspath(path))
            full_path = os.path.normcase(os.path.abspath(path_str))
            write = isinstance(mode, str) and any(ch in mode for ch in "wax+")
            if isinstance(flags, int):
                write = write or bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT |
                                               os.O_TRUNC | os.O_APPEND))
            parts = full_path.split(os.sep)
            dotfile = os.path.basename(full_path).startswith(".") or any(
                part in (".ssh", ".aws") for part in parts
            )
            internal = any(inside(full_path, root) for root in ignored)
            if internal and not inside(full_path, project_root) and not write \
                    and not dotfile and not full_path.endswith(".pth"):
                return
            log_event("file", "file_open", path_str, {"mode": str(mode), "flags": flags})
        elif event in ("socket.connect", "socket.sendto", "urllib.Request"):
            address = args[1] if event != "urllib.Request" and len(args) > 1 else args[0]
            if event == "urllib.Request":
                address = getattr(address, "full_url", address)
                host = urlsplit(str(address)).hostname or ""
            else:
                host = str(address[0]) if isinstance(address, tuple) else str(address)
            target = str(address)
            blocked = block_net and host.lower() not in allow_hosts
            log_event("net", "socket_connect", target, {
                "blocked": blocked, "audit_event": event,
            })
            if blocked:
                raise PermissionError(f"WakeTrace sandbox blocked network connection to {target}")
        elif event in ("os.system", "subprocess.Popen", "os.exec", "os.spawn", "os.posix_spawn"):
            target = args[0] if args else "unknown"
            command_args = args[0] if event == "os.system" else args[1] if len(args) > 1 else target
            log_event("process", "proc_exec", target, {
                "event": event, "raw_args": repr(command_args),
            })
        elif event in ("ctypes.dlopen", "ctypes.dlsym"):
            log_event("native", "dlopen", args[0] if args else "unknown", {"event": event})

    sys.addaudithook(audit_hook)
    log_event("health", "hook_ready", "sitecustomize")
    real_create_connection = socket.create_connection

    def create_connection(address, *args, **kwargs):
        host = str(address[0]) if isinstance(address, tuple) else str(address)
        if block_net and host.lower() not in allow_hosts:
            log_event("net", "socket_connect", str(address), {"blocked": True})
            raise PermissionError(f"WakeTrace sandbox blocked network connection to {host}")
        return real_create_connection(address, *args, **kwargs)

    socket.create_connection = create_connection

    def finish():
        if canaries:
            forms = {}
            for name, value in canaries.items():
                forms[name] = [part.encode() for part in (
                    value, base64.b64encode(value.encode()).decode(),
                    value.encode().hex(), quote(value), quote(value, safe=""))]
            found = set()
            scan_incomplete = False
            tls.in_hook = True
            try:
                for folder, _, files in os.walk(project_root):
                    for name in files:
                        if name == ".env":
                            continue
                        path = os.path.join(folder, name)
                        try:
                            if os.path.getsize(path) > 32 * 1024 * 1024:
                                scan_incomplete = True
                                continue
                            with open(path, "rb") as fp:
                                data = fp.read(32 * 1024 * 1024)
                        except OSError:
                            continue
                        for key, values in forms.items():
                            if any(value in data for value in values):
                                found.add((key, path))
            finally:
                tls.in_hook = False
            for name, path in sorted(found):
                log_event("canary", "written_value", name, {'path': path})
            if scan_incomplete:
                log_event('health', 'canary_scan_incomplete', 'file exceeds scan limit')
        log_event("health", "hook_done", "sitecustomize")

    atexit.register(finish)
    sys.path[:] = [p for p in sys.path if os.path.normcase(os.path.abspath(p)) != hook_dir]


if os.environ.get("WAKETRACE_ACTIVE") == "1":
    try:
        _install()
    except Exception as exc:
        raise SystemExit(f"WakeTrace hook failed to start: {exc}") from exc

