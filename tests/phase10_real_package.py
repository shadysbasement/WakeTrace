"""Local evaluation of two already-downloaded real wheel files.

Example: python tests/phase10_real_package.py /tmp/idna-3.19.whl /tmp/idna-3.20.whl
The key created here is a test fixture, not organizational approval.
"""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_10 import decide, sign
from package_input import inspect
from package_runner import exercise_spec, run_package_horizons
from lockfile import build_lock_data, save_lockfile


def evaluate(baseline_wheel, candidate_wheel):
    with tempfile.TemporaryDirectory(prefix="waketrace-real-package-") as temp:
        root = Path(temp)
        (root / "out").mkdir()
        baseline = root / Path(baseline_wheel).name
        candidate = root / Path(candidate_wheel).name
        shutil.copy2(baseline_wheel, baseline)
        shutil.copy2(candidate_wheel, candidate)
        if inspect(baseline)["name"] != inspect(candidate)["name"]:
            raise ValueError("package distribution names differ")
        module = inspect(baseline)["name"].replace("-", "_")
        exercises = {
            "import": exercise_spec("import", module=module, distribution=module),
            "encode": exercise_spec("command", argv=["python", "-c",
                                   f"import {module}; print({module}.encode('example.com'))"],
                                    distribution=module),
        }
        locks = {}
        for sid, exercise in exercises.items():
            lock = root / f"{sid}.lock.json"
            save_lockfile(build_lock_data(run_package_horizons(baseline, exercise, [0])), lock)
            locks[sid] = str(lock)
        plan = {"schema_version": "1.0", "revision": "local_real_package_1",
                "candidate": {"type": "package", "path": str(candidate),
                              "sha256": inspect(candidate)["sha256"]},
                "baseline": {"path": str(baseline), "sha256": inspect(baseline)["sha256"],
                             "locks": locks, "manifest": str(root / "approval.json"),
                             "signature": str(root / "approval.sig")},
                "scenarios": [{"id": sid, "exercise": exercise} for sid, exercise in exercises.items()],
                "horizons": [0], "output": {"result": str(root / "out/result.json"),
                                            "summary": str(root / "out/summary.md")}}
        plan_path = root / "plan.json"
        plan_path.write_text(json.dumps(plan))
        private, public = root / "fixture-private.pem", root / "fixture-public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", str(private)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sign(plan_path, root, private)
        decision, result = decide(plan_path, root, public)
        return {"baseline": {"name": baseline.name, "sha256": plan["baseline"]["sha256"]},
                "candidate": {"name": candidate.name, "sha256": plan["candidate"]["sha256"]},
                "decision": decision, "failure_stage": result["failure_stage"],
                "scenarios": [{"id": s["id"], "decision": s["decision"],
                               "score": s["risk_score"]} for s in result["scenarios"]]}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: phase10_real_package.py BASELINE_WHEEL CANDIDATE_WHEEL")
    print(json.dumps(evaluate(sys.argv[1], sys.argv[2]), indent=2))
