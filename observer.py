"""Keep track of what a program does during a gate check,
strace watches Bubblewrap and its child processes from outside the sandbox and
the messy raw logs stay in a pvt temp folder; so basically only the summary is kept.
"""

from collections import Counter
from pathlib import Path
import re
import shutil


CALL = re.compile(r"^(?:\[pid\s+\d+\]\s+)?([a-zA-Z_][a-zA-Z_0-9]*)\(")
MAX_BYTES = 32 * 1024 * 1024
MAX_LINES = 250000
TRACKED = {"execve", "execveat", "clone", "clone3", "fork", "vfork",
           "open", "openat", "openat2", "creat", "connect", "sendto",
           "sendmsg", "socket"}


def preflight():
    path = shutil.which("strace")
    if not path:
        raise ValueError("required host syscall observer strace is missing")
    return path


def command(cmd, prefix):
    return [preflight(), "-ff", "-qq", "-e", "trace=process,file,network",
            "-e", "raw=all",
            "-o", str(prefix), "--", *cmd]


def summarize(prefix):
    files = list(Path(prefix).parent.glob(Path(prefix).name + ".*"))
    if not files:
        return {"healthy": False, "reason": "observer produced no process traces"}
    counts = Counter()
    size = lines = 0
    for path in files:
        if not path.name.rsplit(".", 1)[-1].isdigit() or not path.is_file():
            return {"healthy": False, "reason": "observer output name is invalid"}
        size += path.stat().st_size
        if size > MAX_BYTES:
            return {"healthy": False, "reason": "observer output exceeded size limit"}
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                lines += 1
                if lines > MAX_LINES or len(line) > 16384:
                    return {"healthy": False, "reason": "observer output exceeded line limit"}
                match = CALL.match(line)
                if match and match[1] in TRACKED:
                    counts[match[1]] += 1
    if not counts["execve"]:
        return {"healthy": False, "reason": "observer missed process start"}
    return {"healthy": True, "source": "host strace/ptrace", "processes": len(files),
            "syscalls": {name: counts[name] for name in sorted(TRACKED)},
            "raw_bytes_discarded": size}