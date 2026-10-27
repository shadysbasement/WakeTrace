from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import uuid

if sys.platform == "linux":
    import resource


class IsolationError(OSError):
    pass


def _quota_parent():
    root = Path("/sys/fs/cgroup")
    try:
        entry = next(line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                     if line.startswith("0::"))
    except (OSError, StopIteration):
        return None
    current = root / entry.lstrip("/")
    for parent in (current, *current.parents):
        if parent == root:
            break
        try:
            enabled = (parent / "cgroup.subtree_control").read_text().split()
            if "pids" in enabled and os.access(parent, os.W_OK):
                return parent
        except OSError:
            continue
    return None


@contextmanager
def process_quota(limit):
    """Use a private cgroup when a delegated v2 PID controller is available."""
    parent = _quota_parent()
    group = None
    if parent is not None:
        candidate = parent / ("waketrace-" + uuid.uuid4().hex)
        created = False
        try:
            candidate.mkdir(mode=0o700)
            created = True
            (candidate / "pids.max").write_text(str(limit))
            group = candidate
        except OSError:
            if created:
                candidate.rmdir()
    try:
        yield group
    finally:
        if group is not None:
            kill = group / "cgroup.kill"
            if kill.exists():
                kill.write_text("1")
            for _ in range(100):
                try:
                    group.rmdir()
                    break
                except OSError:
                    time.sleep(0.01)
            else:
                raise IsolationError("private process cgroup did not become empty")


def _runtime():
    if sys.platform != "linux":
        raise IsolationError("contained execution supports Linux only; no secure backend is available for this OS")
    if os.geteuid() == 0:
        raise IsolationError("run WakeTrace as an unprivileged user, not root")
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14):
        raise IsolationError("the CLI needs CPython 3.14 for the supported release gate")
    bwrap = shutil.which("bwrap")
    python = Path("/usr/bin/python3")
    if not bwrap:
        raise IsolationError("Bubblewrap is missing; install the bubblewrap system package")
    if not python.is_file():
        raise IsolationError("/usr/bin/python3 is missing; install the system Python 3.14 runtime")
    if not Path("/usr/lib").is_dir():
        raise IsolationError("system runtime libraries are unavailable")
    result = subprocess.run([str(python), "-S", "-c",
                             "import sys; print(sys.implementation.name, *sys.version_info[:2])"],
                             capture_output=True, text=True, timeout=5, check=False)
    if result.returncode or result.stdout.strip() != "cpython 3 14":
        raise IsolationError("/usr/bin/python3 must be CPython 3.14 for the supported release gate")
    return bwrap, str(python)


def _base_command(bwrap, work=None, trace=None, hook=None, write_limit_mb=32):
    cmd = [
        bwrap, "--unshare-user", "--unshare-pid", "--unshare-net",
        "--unshare-ipc", "--unshare-uts", "--die-with-parent",
        "--new-session", "--clearenv", "--ro-bind", "/usr", "/usr",
    ]
    # The ELF loader can live under /usr/lib64 (Ubuntu) or /usr/lib (Arch).
    # Recreate the host's runtime layout instead of guessing where /lib64 points.
    for path in (Path("/bin"), Path("/sbin"), Path("/lib"), Path("/lib64")):
        if path.is_symlink():
            cmd += ["--symlink", os.readlink(path), str(path)]
        elif path.is_dir():
            cmd += ["--ro-bind", str(path), str(path)]
    cmd += [
        "--dir", "/etc",
        "--dev", "/dev", "--proc", "/proc", "--size",
        str(write_limit_mb * 1024 * 1024), "--tmpfs", "/tmp",
        "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/nonexistent",
        "--setenv", "TMPDIR", "/tmp", "--setenv", "LANG", "C.UTF-8",
    ]
    cache = Path("/etc/ld.so.cache")
    if cache.is_file():
        cmd += ["--ro-bind", str(cache), str(cache)]
    if work is not None:
        cmd += ["--ro-bind", str(work), "/input", "--size",
                str(write_limit_mb * 1024 * 1024), "--tmpfs", "/work",
                "--chdir", "/work"]
    if trace is not None:
        cmd += ["--dir", "/trace", "--bind", str(trace), "/trace/events.jsonl"]
    if hook is not None:
        cmd += ["--ro-bind", str(hook), "/hook"]
    return cmd


def preflight():
    bwrap, python = _runtime()
    cmd = _base_command(bwrap) + ["--", python, "-S", "-c",
                                  "import os, socket; assert not os.path.exists('/home');"
                                  "assert os.geteuid() != 0; "
                                  "s=socket.socket();"
                                  "assert s.connect_ex(('127.0.0.1', 1)) != 0"]
    try:
        result = subprocess.run(cmd, env={}, capture_output=True, text=True,
                                timeout=5, close_fds=True)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IsolationError(f"Bubblewrap preflight failed: {exc}") from exc
    if result.returncode:
        raise IsolationError("Bubblewrap preflight failed; check unprivileged user namespaces and AppArmor: "
                             + result.stderr.strip()[:300])
    return bwrap, python


def limits(cpu_sec, memory_mb, file_mb, process_limit, cgroup=None):
    def apply():
        if cgroup is not None:
            (cgroup / "cgroup.procs").write_text("0")
        resource.setrlimit(resource.RLIMIT_CPU, (max(1, int(cpu_sec) + 1),
                                                max(1, int(cpu_sec) + 1)))
        resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        if cgroup is None:
            resource.setrlimit(resource.RLIMIT_NPROC, (process_limit, process_limit))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def stop_tree(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()
