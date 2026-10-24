"""building a gate plan from the protected CI configuration and one checked out artifact"""

import argparse
import json
from pathlib import Path

from gate import atomic
from gate_plan import inside, keys, load
from package_input import inspect


def checked(root, relative, must_exist = True):
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("configuration paths must be relative")
    if ".." in Path(relative).parts:
        raise ValueError("configuration path may not contain parent traversal")
    path = (root / relative).absolute()
    if not inside(path, root) or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("configuration path escapes its checkout or uses a symlink")
    return str(path.resolve(strict=must_exist))


def prepare(template, trusted_root, candidate_root, candidate_path, output_root):
    trusted_root = Path(trusted_root).resolve(strict=True)
    candidate_root = Path(candidate_root).resolve(strict=True)
    output_root = Path(output_root).resolve(strict=True)
    source = Path(checked(trusted_root, template))
    if source.stat().st_size > 65536:
        raise ValueError("gate template exceeds size limit")
    data = json.loads(source.read_text(encoding="utf-8"))
    keys(data, ("schema_version", "revision", "candidate_type", "baseline", "scenarios",
                "horizons", "file_age_hours", "wheelhouse", "limits", "observer", "policy"),
        "protected template")
    if data.get("schema_version") != "1.0":
        raise ValueError("unsupported gate template")
    baseline = data["baseline"]
    keys(baseline, ("path", "locks", "manifest", "signature"), "template baseline")
    candidate = checked(candidate_root, candidate_path)
    base = checked(trusted_root, baseline["path"])
    result = {"schema_version": "1.0", "revision": data["revision"],
              "candidate": {"type": data["candidate_type"], "path": candidate,
                            "sha256": inspect(candidate)["sha256"]},
              "baseline": {"path": base, "sha256": inspect(base)["sha256"],
                           "locks": {sid: checked(trusted_root, path)
                                     for sid, path in baseline["locks"].items()},
                           "manifest": checked(trusted_root, baseline["manifest"], False),
                           "signature": checked(trusted_root, baseline["signature"], False)},
              "scenarios": data["scenarios"], "horizons": data["horizons"],
              "file_age_hours": data.get("file_age_hours", 0),
              "wheelhouse": checked(trusted_root, data["wheelhouse"]) if data.get("wheelhouse") else None,
              "limits": data.get("limits", {}), "observer": data.get("observer", {"mode": "strace", "required": True}),
              "policy": data.get("policy", {}),
              "output": {"result": str(output_root / "gate-result.json"),
                         "summary": str(output_root / "gate-summary.md")}}
    path = output_root / "gate-plan.json"
    atomic(path, json.dumps(result, indent=2) + "\n")
    load(path, output_root.parent, output_root, require_approval=False)
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", required=True)
    parser.add_argument("--trusted-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--candidate-path", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    print(prepare(args.template, args.trusted_root, args.candidate_root,
                  args.candidate_path, args.output_root))


if __name__ == "__main__":
    main()
