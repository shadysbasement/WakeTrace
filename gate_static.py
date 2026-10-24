"""bounded source hints for clock paths the runtime cant certify"""

from pathlib import Path
import re
import tarfile
import zipfile

from package_input import inspect


PATTERNS = {
    "time.time_ns": (rb"\btime_ns\s*\(", "ERROR"),
    "time.clock_gettime": (rb"\bclock_gettime(?:_ns)?\s*\(", "ERROR"),
    "date.today": (rb"\bdate\.today\s*\(", "ERROR"),
    "native clock access": (rb"\b(?:CLOCK_REALTIME|clock_gettime|libc\.time)\b", "ERROR"),
    "ctypes native time": (rb"\bCDLL\s*\([^)]*\)\.time\s*\(", "ERROR"),
    "startup hooks skipped": (rb"['\"]-S['\"]", "ERROR"),
    "native library access": (rb"\bctypes\b", "REVIEW"),
    "child process": (rb"\b(?:subprocess|os\.system)\b", "REVIEW"),
}
MAX_SOURCE = 10 * 1024 * 1024


def sources(path):
    info = inspect(path)
    source = Path(path)
    if info["kind"] == "script":
        yield source.name, source.read_bytes()
    elif info["kind"] in ("source_tree", "executable_directory"):
        for name in info["files"]:
            if name.endswith(".py"):
                yield name, (source / name).read_bytes()
    elif info["kind"] == "wheel":
        with zipfile.ZipFile(source) as archive:
            for name in archive.namelist():
                if name.endswith(".py"):
                    yield name, archive.read(name)
    elif info["kind"] == "sdist":
        with tarfile.open(source, "r:gz") as archive:
            for member in archive.getmembers():
                if member.isfile() and member.name.endswith(".py"):
                    yield member.name, archive.extractfile(member).read()


def hints(path):
    found = {}
    total = 0
    for name, code in sources(path):
        total += len(code)
        if total > MAX_SOURCE:
            raise ValueError("Python source exceeds static hint budget")
        for label, (pattern, decision) in PATTERNS.items():
            if re.search(pattern, code):
                found[label] = {"hint": label, "source": "static source text",
                                "disposition": decision}
    return list(found.values())