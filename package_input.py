import hashlib
import os
from pathlib import Path
import re
import shutil
import tarfile
import tomllib
import zipfile

MAX_ARTIFACT_MB = 64
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
PRIVATE_DIRS = {".git", ".ssh", ".aws", ".gnupg", ".kube", "venv", ".venv",
                "__pycache__", "node_modules"}
PRIVATE_FILES = {".env", ".npmrc", ".pypirc", ".gitconfig"}


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_files(root):
    files = []
    total = 0
    for folder, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            path = Path(folder, name)
            if path.is_symlink():
                raise ValueError(f"symlink is unsupported in package input: {path}")
            if name in PRIVATE_DIRS or name in PRIVATE_FILES or name.startswith(".env"):
                raise ValueError(f"private file or directory is unsupported in package input: {path}")
        for name in names:
            path = Path(folder, name)
            if not path.is_file():
                raise ValueError(f"non-regular package file: {path}")
            total += path.stat().st_size
            if total > MAX_ARTIFACT_MB * 1024 * 1024:
                raise ValueError("package tree exceeds size limit")
            files.append(path.relative_to(root).as_posix())
    return sorted(files)


def tree_hash(root, files):
    digest = hashlib.sha256()
    for name in files:
        if (root / name).is_symlink():
            raise ValueError(f"symlink appeared while hashing: {name}")
        data = (root / name).read_bytes()
        digest.update(len(name.encode()).to_bytes(8, "big"))
        digest.update(name.encode())
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _safe_name(name):
    parts = name.rstrip("/").split("/")
    return bool(name) and not name.startswith("/") and all(
        part not in ("", ".", "..") and ":" not in part for part in parts
    ) and "\\" not in name


def _wheel(path):
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if not entries or len(entries) > 10000:
                raise ValueError("wheel has no files or too many files")
            seen = set()
            for entry in entries:
                if not _safe_name(entry.filename) or entry.filename in seen:
                    raise ValueError("unsafe or duplicate wheel member")
                seen.add(entry.filename)
                if entry.file_size > MAX_ARTIFACT_MB * 1024 * 1024:
                    raise ValueError("wheel member exceeds size limit")
                if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("wheel symlink is unsupported")
            if sum(item.file_size for item in entries) > MAX_ARTIFACT_MB * 1024 * 1024:
                raise ValueError("wheel expands beyond size limit")
            metadata = [name for name in seen if name.endswith(".dist-info/METADATA")]
            if len(metadata) != 1:
                raise ValueError("wheel must have one distribution metadata file")
            data = archive.read(metadata[0]).decode("utf-8")
    except (zipfile.BadZipFile, UnicodeError, OSError) as exc:
        raise ValueError(f"invalid wheel: {exc}") from exc
    name = re.search(r"^Name:\s*(.+)$", data, re.M)
    version = re.search(r"^Version:\s*(.+)$", data, re.M)
    if not name or not version or not NAME.fullmatch(name[1]) or not version[1].strip():
        raise ValueError("wheel metadata lacks valid name or version")
    return name[1].strip(), version[1].strip()


def _sdist(path):
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > 10000:
                raise ValueError("sdist has no files or too many files")
            seen = set()
            projects = []
            total = 0
            for member in members:
                if not _safe_name(member.name) or member.name in seen:
                    raise ValueError("unsafe or duplicate sdist member")
                seen.add(member.name)
                if not (member.isfile() or member.isdir()):
                    raise ValueError("sdist links and special files are unsupported")
                total += member.size
                if total > MAX_ARTIFACT_MB * 1024 * 1024:
                    raise ValueError("sdist expands beyond size limit")
                if member.name.count("/") == 1 and member.name.endswith("/pyproject.toml"):
                    projects.append(member)
            if len(projects) != 1 or len({m.name.split("/")[0] for m in members}) != 1:
                raise ValueError("sdist needs one top-level project with pyproject.toml")
            data = archive.extractfile(projects[0]).read()
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"invalid sdist: {exc}") from exc
    return _project(data)


def _project(data):
    try:
        project = tomllib.loads(data.decode("utf-8"))["project"]
        name, version = project["name"], project["version"]
    except (UnicodeError, KeyError, ValueError, TypeError) as exc:
        raise ValueError("pyproject.toml needs static project name and version") from exc
    if not isinstance(name, str) or not NAME.fullmatch(name) or not isinstance(version, str) or not version:
        raise ValueError("invalid project name or version")
    return name, version


def inspect(path):
    source = Path(path).expanduser().absolute()
    if any(part.is_symlink() for part in (source, *source.parents)):
        raise ValueError("symlink package input is unsupported")
    if source.is_dir():
        files = tree_files(source)
        if "pyproject.toml" in files:
            kind = "source_tree"
            name, version = _project((source / "pyproject.toml").read_bytes())
        elif "__main__.py" in files:
            kind, name, version = "executable_directory", source.name, None
        else:
            raise ValueError("directory needs pyproject.toml or __main__.py")
        fingerprint = tree_hash(source, files)
    elif source.is_file():
        if source.stat().st_size > MAX_ARTIFACT_MB * 1024 * 1024:
            raise ValueError("artifact exceeds size limit")
        if source.name.endswith(".whl"):
            kind = "wheel"
            name, version = _wheel(source)
        elif source.name.endswith(".tar.gz"):
            kind = "sdist"
            name, version = _sdist(source)
        elif source.suffix == ".py":
            kind, name, version = "script", source.stem, None
        else:
            raise ValueError("supported inputs: .py, executable directory, .whl, .tar.gz, or pyproject source tree")
        fingerprint = file_hash(source)
        files = None
    else:
        raise FileNotFoundError(f"package input not found: {source}")
    return {"kind": kind, "source": str(source), "name": name,
            "version": version, "sha256": fingerprint, "files": files}


def stage(info, destination):
    source = Path(info["source"])
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    if info["files"] is None:
        target = destination /source.name
        shutil.copyfile(source, target)
        if file_hash(target) != info["sha256"]:
            raise ValueError("artifact changed while staging")
        return source.name
    for name in info["files"]:
        if (source / name).is_symlink():
            raise ValueError(f"symlink appeared while staging: {name}")
        if (source / name).stat().st_size > MAX_ARTIFACT_MB * 1024 * 1024:
            raise ValueError("package file grew beyond size limit while staging")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    if tree_hash(destination, info["files"]) != info["sha256"]:
        raise ValueError("package files changed while staging")
    return "."


def wheelhouse(path):
    if path is None:
        return {"source": None, "wheels": []}
    root = Path(path).expanduser().absolute()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("wheelhouse must be a local directory")
    wheels = []
    for item in sorted(root.iterdir()):
        if item.is_symlink() or not item.is_file() or item.suffix != ".whl":
            raise ValueError(f"wheelhouse may contain only regular wheels: {item.name}")
        name, version = _wheel(item)
        wheels.append({"file": item.name, "name": canonical(name),
                       "version": version, "sha256": file_hash(item)})
    return{"source": str(root), "wheels": wheels}