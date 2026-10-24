import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gate import EXIT, gate, manifest_template
from gate import stage_exact
from gate_plan import load
from gate_prepare import prepare
from gate_schema import validate_result
from lockfile import build_lock_data, save_lockfile
from package_input import inspect
from runner import run_in_sandbox, run_multi_horizon
from package_runner import exercise_spec, run_package_horizons
from test_6 import sdist, source_tree, wheel


def setup_case(root, baseline_code="print('ok')\n", candidate_code=None, hours=None):
    root = Path(root)
    out = root / "out"
    out.mkdir()
    baseline = root / "baseline.py"
    candidate = root / "candidate.py"
    baseline.write_text(baseline_code)
    candidate.write_text(baseline_code if candidate_code is None else candidate_code)
    hours = hours or [0]
    lock = root / "baseline.lock.json"
    save_lockfile(build_lock_data(run_multi_horizon(baseline, hours)), lock)
    plan = {"schema_version": "1.0", "revision": "rev1",
            "candidate": {"type": "script", "path": str(candidate),
                          "sha256": inspect(candidate)["sha256"]},
            "baseline": {"path": str(baseline), "sha256": inspect(baseline)["sha256"],
                         "locks": {"main": str(lock)}, "manifest": str(root / "approval.json"),
                         "signature": str(root / "approval.sig")},
            "scenarios": [{"id": "main", "args": []}], "horizons": hours,
            "output": {"result": str(out / "result.json"), "summary": str(out / "summary.md")}}
    plan_path = root / "plan.json"
    plan_path.write_text(json.dumps(plan))
    private = root / "private.pem"
    public = root / "public.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                    "rsa_keygen_bits:2048", "-out", str(private)], check=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sign(plan_path, root, private)
    return plan, plan_path, public, private


def sign(plan_path, root, private):
    plan = load(plan_path, root, Path(root) / "out", require_approval=False)
    manifest = manifest_template(plan)
    now = datetime.now(timezone.utc)
    manifest.update(approved_by="Fixture reviewer", approved_at=now.isoformat(),
                    expires_at=(now + timedelta(days=1)).isoformat())
    path = Path(root, "approval.json")
    path.write_text(json.dumps(manifest, sort_keys=True))
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private),
                    "-out", str(Path(root, "approval.sig")), str(path)], check=True)


def decide(plan_path, root, public):
    decision = gate(plan_path, root, Path(root, "out"), public)
    result = json.loads(Path(root, "out", "result.json").read_text())
    assert result["exit_code"] == EXIT[decision]
    return decision, result


def test_four_decision_and_evidence():
    with tempfile.TemporaryDirectory() as temp:
        plan, path, public, private = setup_case(temp)
        decision, result = decide(path, temp, public)
        assert decision == "PASS" and result["scenarios"][0]["coverage"][0]["observer_healthy"]
        assert os.stat(Path(temp, "out", "result.json")).st_mode & 0o777 == 0o600
        candidate = Path(plan["candidate"]["path"])
        candidate.write_text("import os\nprint(os.environ['OPENAI_API_KEY'])\n")
        plan["candidate"]["sha256"] = inspect(candidate)["sha256"]
        path.write_text(json.dumps(plan))
        decision, result = decide(path, temp, public)
        assert decision == "REVIEW" and result["scenarios"][0]["verify_verdict"] == "WARNING"
        summary = Path(temp, "out", "summary.md").read_text()
        assert "Scenario main" in summary and "evidence" in summary
        candidate.write_text("import socket\ns=socket.socket()\ntry: s.connect(('127.0.0.1', 9))\nexcept OSError: pass\n")
        plan["candidate"]["sha256"] = inspect(candidate)["sha256"]
        path.write_text(json.dumps(plan))
        decision, result = decide(path, temp, public)
        assert decision == "BLOCK", result["failure_stage"]
        Path(temp, "approval.sig").write_bytes(b"tampered")
        decision, result = decide(path, temp, public)
        assert decision == "ERROR" and "signature" in result["failure_stage"]


def test_missing_horizon_and_changed_candidate_fail_closed():
    with tempfile.TemporaryDirectory() as temp:
        plan, path, public, private = setup_case(temp)
        plan["horizons"] = [0, 72]
        path.write_text(json.dumps(plan))
        sign(path, temp, private)
        assert decide(path, temp, public)[0] == "ERROR"
        plan["horizons"] = [0]
        candidate = Path(plan["candidate"]["path"])
        candidate.write_text("print('changed')\n")
        path.write_text(json.dumps(plan))
        sign(path, temp, private)
        assert decide(path, temp, public)[0] == "ERROR"


def test_unsupported_clocks_are_coverage_errors():
    with tempfile.TemporaryDirectory() as temp:
        plan, path, public, private = setup_case(temp)
        candidate = Path(plan["candidate"]["path"])
        for code, hint in (("import time\nprint(time.time_ns())\n", "time.time_ns"),
                           ("import subprocess\nsubprocess.run(['python3', '-S', '-c', 'print(1)'])\n",
                            "startup hooks skipped")):
            candidate.write_text(code)
            plan["candidate"]["sha256"] = inspect(candidate)["sha256"]
            path.write_text(json.dumps(plan))
            decision, result = decide(path, temp, public)
            assert decision == "ERROR"
            assert hint in {item["hint"] for item in result["static_hints"]}


def test_plan_and_approval_rejections():
    with tempfile.TemporaryDirectory() as temp:
        plan, path, public, private = setup_case(temp)
        plan["scenarios"].append(dict(plan["scenarios"][0]))
        path.write_text(json.dumps(plan))
        try:
            load(path, temp, Path(temp, "out"))
            assert False, "duplicate scenario accepted"
        except ValueError:
            pass
        assert gate(path, temp, Path(temp, "out"), public) == "ERROR"
        assert json.loads(Path(temp, "out", "gate-error.json").read_text())["decision"] == "ERROR"
        plan["scenarios"].pop()
        plan["unknown_security_field"] = True
        path.write_text(json.dumps(plan))
        try:
            load(path, temp, Path(temp, "out"))
            assert False, "unknown field accepted"
        except ValueError:
            pass
        del plan["unknown_security_field"]
        plan["baseline"]["sha256"] = "0" * 64
        path.write_text(json.dumps(plan))
        assert decide(path, temp, public)[0] == "ERROR"
        plan["baseline"]["sha256"] = inspect(plan["baseline"]["path"])["sha256"]
        path.write_text(json.dumps(plan))
        manifest_path = Path(temp, "approval.json")
        manifest = json.loads(manifest_path.read_text())
        manifest["expires_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        manifest_path.write_text(json.dumps(manifest))
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private),
                        "-out", str(Path(temp, "approval.sig")), str(manifest_path)], check=True)
        assert decide(path, temp, public)[0] == "ERROR"
        lock_path = Path(plan["baseline"]["locks"]["main"])
        old = json.loads(lock_path.read_text())
        old["schema_version"] = "1.0"
        old.pop("capabilities_by_horizon")
        old.pop("temporal_coverage")
        lock_path.write_text(json.dumps(old))
        sign(path, temp, private)
        assert decide(path, temp, public)[0] == "ERROR"


def test_staging_swap_observer_gap_trace_and_timeout():
    with tempfile.TemporaryDirectory() as temp:
        plan, path, public, private = setup_case(temp)
        candidate = Path(plan["candidate"]["path"])
        original_stage = __import__("gate").stage

        def swap(info, destination):
            candidate.write_text("print('swapped')\n")
            return original_stage(info, destination)

        with patch("gate.stage", side_effect=swap):
            try:
                stage_exact(candidate, plan["candidate"]["sha256"], Path(temp, "copy"))
                assert False, "candidate swap accepted"
            except ValueError:
                pass
        candidate.write_text("print('ok')\n")
        with patch("observer.summarize", return_value={"healthy": False, "reason": "missing"}):
            assert decide(path, temp, public)[0] == "ERROR"
        candidate.write_text("open('/trace/events.jsonl', 'a').write('{broken\\n')\n")
        plan["candidate"]["sha256"] = inspect(candidate)["sha256"]
        path.write_text(json.dumps(plan))
        decision, result = decide(path, temp, public)
        assert decision == "ERROR" and result["scenarios"][0]["decision"] == "ERROR"
        candidate.write_text("while True: pass\n")
        plan["candidate"]["sha256"] = inspect(candidate)["sha256"]
        plan["limits"] = {"timeout": 2}
        path.write_text(json.dumps(plan))
        sign(path, temp, private)
        decision, result = decide(path, temp, public)
        assert decision == "ERROR" and result["scenarios"][0]["decision"] == "ERROR"


def test_protected_template_prepares_exact_candidate():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        trusted, candidate_root, output = root / "trusted", root / "candidate", root / "output"
        trusted.mkdir()
        candidate_root.mkdir()
        output.mkdir()
        baseline = trusted / "baseline.py"
        candidate = candidate_root / "candidate.py"
        baseline.write_text("print('ok')\n")
        candidate.write_text("print('update')\n")
        lock = trusted / "baseline.lock.json"
        save_lockfile(build_lock_data(run_multi_horizon(baseline, [0])), lock)
        template = {"schema_version": "1.0", "revision": "rev1", "candidate_type": "script",
                    "baseline": {"path": "baseline.py", "locks": {"main": "baseline.lock.json"},
                                 "manifest": "approval.json", "signature": "approval.sig"},
                    "scenarios": [{"id": "main", "args": []}], "horizons": [0]}
        (trusted / "template.json").write_text(json.dumps(template))
        path = prepare("template.json", trusted, candidate_root, "candidate.py", output)
        plan = load(path, root, output, require_approval=False)
        assert plan["candidate"]["sha256"] == inspect(candidate)["sha256"]
        assert not (trusted / "approval.json").exists()
        try:
            prepare("template.json", trusted, candidate_root, "../trusted/baseline.py", output)
            assert False, "candidate path traversal accepted"
        except ValueError:
            pass


def test_saved_gate_result_rejects_bad_evidence_and_display_text():
    with tempfile.TemporaryDirectory() as temp:
        plan, path, public, private = setup_case(temp)
        candidate = Path(plan["candidate"]["path"])
        candidate.write_text("import os\nprint(os.environ['OPENAI_API_KEY'])\n")
        plan["candidate"]["sha256"] = inspect(candidate)["sha256"]
        path.write_text(json.dumps(plan))
        decision, result = decide(path, temp, public)
        assert decision == "REVIEW" and validate_result(result) == result
        import copy
        bad = copy.deepcopy(result)
        bad["scenarios"][0]["findings"][0]["evidence_ids"] = [{"horizon": 0, "event_id": 999999}]
        try:
            validate_result(bad)
            assert False, "missing evidence accepted"
        except ValueError:
            pass
        bad = copy.deepcopy(result)
        first = next(events for events in bad["scenarios"][0]["events"].values() if events)
        first[0]["action"] = "<script>"
        try:
            validate_result(bad)
            assert False, "malicious display label accepted"
        except ValueError:
            pass


def test_gate_preserved_host_file_and_nanosecond_times():
    with tempfile.TemporaryDirectory() as temp:
        plan, path, public, private = setup_case(temp)
        sentinel = Path(temp, "host-sentinel")
        sentinel.write_bytes(b"untouched")
        stamp = sentinel.stat().st_mtime_ns - 123456789
        os.utime(sentinel, ns=(stamp, stamp))
        before = sentinel.stat()
        candidate = Path(plan["candidate"]["path"])
        candidate.write_text("from pathlib import Path\ntry:\n"
                             f"    Path({str(sentinel)!r}).write_text('changed')\n"
                             "except OSError:\n    pass\n")
        plan["candidate"]["sha256"] = inspect(candidate)["sha256"]
        path.write_text(json.dumps(plan))
        decision, result = decide(path, temp, public)
        assert decision in ("REVIEW", "BLOCK"), result["failure_stage"]
        after = sentinel.stat()
        assert (after.st_atime_ns, after.st_mtime_ns) == (before.st_atime_ns, before.st_mtime_ns)
        assert sentinel.read_bytes() == b"untouched"


def test_sigterm_returns_error_and_removed_host_traces():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        plan, path, public, private = setup_case(root)
        candidate = Path(plan["candidate"]["path"])
        candidate.write_text("while True: pass\n")
        plan["candidate"]["sha256"] = inspect(candidate)["sha256"]
        plan["limits"] = {"timeout": 30}
        path.write_text(json.dumps(plan))
        sign(path, root, private)
        host_temp = root / "host-temp"
        host_temp.mkdir()
        env = os.environ.copy()
        env["TMPDIR"] = str(host_temp)
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve().parents[1] / "main.py"),
                                    "gate", str(path), "--input-root", str(root),
                                    "--output-root", str(root / "out"),
                                    "--approval-key", str(public)],
                                    env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(1)
        process.send_signal(signal.SIGTERM)
        out, err = process.communicate(timeout=15)
        assert process.returncode == 2, (out, err)
        assert json.loads((root / "out/result.json").read_text())["decision"] == "ERROR"
        assert not list(host_temp.glob("waketrace-gate-*"))
        assert not list(host_temp.glob("waketrace-*"))


def test_package_scenarios_attribute_block():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "out").mkdir()
        baseline = wheel(root, "sample-pkg", "1.0", "sample_mod",
                         "def main():\n    print('ok')\n", entry="sample")
        candidate = wheel(root, "sample-pkg", "2.0", "sample_mod",
                          "def main():\n    import socket\n    s=socket.socket()\n    try: s.connect(('127.0.0.1',9))\n    except OSError: pass\n", entry="sample")
        exercises = {
            "import": exercise_spec("import", module="sample_mod", distribution="sample-pkg"),
            "command": exercise_spec("command", argv=["python", "-c", "import sample_mod"],
                                     distribution="sample-pkg"),
            "console": exercise_spec("console", entry="sample", distribution="sample-pkg"),
        }
        locks = {}
        for sid, exercise in exercises.items():
            path = root / f"{sid}.lock.json"
            save_lockfile(build_lock_data(run_package_horizons(baseline, exercise, [0])), path)
            locks[sid] = str(path)
        plan = {"schema_version": "1.0", "revision": "rev1",
                "candidate": {"type": "package", "path": str(candidate), "sha256": inspect(candidate)["sha256"]},
                "baseline": {"path": str(baseline), "sha256": inspect(baseline)["sha256"],
                             "locks": locks, "manifest":str(root / "approval.json"),
                             "signature": str(root / "approval.sig")},
                "scenarios": [{"id": sid, "exercise": spec} for sid, spec in exercises.items()],
                "horizons": [0],
                "output": {"result": str(root / "out/result.json"),
                           "summary": str(root / "out/summary.md")}}
        path = root / "plan.json"
        path.write_text(json.dumps(plan))
        private, public = root / "private.pem", root / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", str(private)], check=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sign(path, root, private)
        decision, result = decide(path, root, public)
        assert decision == "BLOCK", result["failure_stage"]
        assert [(s["id"], s["decision"]) for s in result["scenarios"]] == \
               [("import", "PASS"), ("command", "PASS"), ("console", "BLOCK")]
        plan["scenarios"][0]["exercise"] = exercises["console"]
        path.write_text(json.dumps(plan))
        sign(path, root, private)
        assert decide(path, root, public)[0] == "ERROR"


def test_source_tree_and_sdist_admission():
    for kind in ("source_tree", "sdist"):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "out").mkdir()
            base_dir, candidate_dir = root / "base", root / "changed"
            base_dir.mkdir()
            candidate_dir.mkdir()
            baseline_tree = source_tree(base_dir, root / "host-marker")
            candidate_tree = candidate_dir / "source-pkg"
            shutil.copytree(baseline_tree, candidate_tree)
            (candidate_tree / "source_mod.py").write_text("print('changed package')\n")
            if kind == "sdist":
                baseline = sdist(base_dir, baseline_tree)
                candidate = sdist(candidate_dir, candidate_tree)
            else:
                baseline, candidate = baseline_tree, candidate_tree
            exercise = exercise_spec("import", module="source_mod", distribution="source-pkg")
            lock = root / "base.lock.json"
            save_lockfile(build_lock_data(run_package_horizons(baseline, exercise, [0])), lock)
            plan = {"schema_version": "1.0", "revision": "rev1",
                    "candidate": {"type": "package", "path": str(candidate), "sha256": inspect(candidate)["sha256"]},
                    "baseline": {"path": str(baseline), "sha256": inspect(baseline)["sha256"],
                                  "locks": {"main": str(lock)}, "manifest": str(root / "approval.json"),
                                  "signature": str(root / "approval.sig")},
                    "scenarios": [{"id": "main", "exercise": exercise}], "horizons": [0],
                    "output": {"result": str(root / "out/result.json"),
                               "summary": str(root / "out/summary.md")}}
            path = root / "plan.json"
            path.write_text(json.dumps(plan))
            private, public = root / "private.pem", root / "public.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                            "rsa_keygen_bits:2048", "-out", str(private)], check=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            sign(path, root, private)
            decision, result = decide(path, root, public)
            assert decision == "PASS", (kind, result["failure_stage"])
            assert not (root / "host-marker").exists()


def test_script_bundle_config_and_environment_scenarios():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "out").mkdir()
        baseline, candidate = root / "base" / "bundle", root / "updated" / "bundle"
        baseline.parent.mkdir()
        candidate.parent.mkdir()
        baseline.mkdir()
        candidate.mkdir()
        for folder in (baseline, candidate):
            (folder / "config.json").write_text('{"enabled": true}')
        (baseline / "__main__.py").write_text("import os\nfrom pathlib import Path\n"
            "print(Path(__file__).with_name('config.json').read_text(), os.getenv('MODE'))\n")
        (candidate / "__main__.py").write_text("import os\nfrom pathlib import Path\n"
            "print(Path(__file__).with_name('config.json').read_text(), os.getenv('MODE'))\n"
            "if os.getenv('MODE') == 'armed':\n   open('note', 'w').write('synthetic')\n")
        scenarios = [{"id": "quiet", "args": [], "env": {"MODE": "quiet"}},
                     {"id": "armed", "args": [], "env": {"MODE": "armed"}}]
        locks = {}
        for scenario in scenarios:
            path = root / f"{scenario['id']}.lock.json"
            save_lockfile(build_lock_data(run_multi_horizon(
                baseline, [0], extra_env=scenario["env"])), path)
            locks[scenario["id"]] = str(path)
        plan = {"schema_version": "1.0", "revision": "rev1",
                "candidate": {"type": "script_bundle", "path": str(candidate),
                              'sha256': inspect(candidate)["sha256"]},
                "baseline": {"path": str(baseline), "sha256": inspect(baseline)["sha256"],
                             "locks": locks, "manifest": str(root / "approval.json"),
                             "signature": str(root / "approval.sig")},
                "scenarios": scenarios, "horizons": [0],
                "output": {"result": str(root / "out/result.json"),
                           "summary": str(root / "out/summary.md")}}
        plan_path = root / "plan.json"
        plan_path.write_text(json.dumps(plan))
        private, public = root / "private.pem", root / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", str(private)], check=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sign(plan_path, root, private)
        decision, result = decide(plan_path, root, public)
        assert decision == "REVIEW", result["failure_stage"]
        assert [(s["id"], s["decision"]) for s in result["scenarios"]] == \
               [("quiet", "PASS"), ("armed", "REVIEW")], [(s["id"], s["findings"]) for s in result["scenarios"]]


def test_host_observer_sees_native_attempts_without_host_access():
    with tempfile.TemporaryDirectory() as temp:
        host = Path(temp, "host-sentinel")
        host.write_text("untouched")
        target = Path(temp, "native.py")
        target.write_text(
            "import ctypes, socket, struct\n"
            "libc = ctypes.CDLL(None)\n"
            f"fd = libc.open({str(host)!r}.encode(), 0)\n"
            "sock = libc.socket(2, 1, 0)\n"
            "addr = struct.pack('=HH4s8s', 2, socket.htons(9), "
            "socket.inet_aton('127.0.0.1'), b'\\0' * 8)\n"
            "connected = libc.connect(sock, ctypes.c_char_p(addr), len(addr))\n"
            "print(fd, connected)\n")
        result = run_in_sandbox(target, observer=True)
        assert result["complete"], result["stderr"]
        assert result["stdout"].strip() == "-1 -1"
        assert result["observer"]["healthy"]
        assert result["observer"]["syscalls"]["connect"] >= 1
        assert host.read_text() == "untouched"
        assert str(host) not in json.dumps(result["observer"])


def test_missing_package_dependency_is_gate_error():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "out").mkdir()
        house = root / "wheels"
        house.mkdir()
        wheel(house, "helper-pkg", "1.0", "helper_mod", "VALUE = 1\n")
        baseline = wheel(root, "needs-pkg", "1.0", "needs_mod",
                         "import helper_mod\n", requires=["helper-pkg == 1.0"])
        candidate = wheel(root, "needs-pkg", "2.0", "needs_mod",
                          "import helper_mod\n", requires=["helper-pkg == 2.0"])
        exercise = exercise_spec("import", module="needs_mod", distribution="needs_pkg")
        lock = root / "baseline.lock.json"
        save_lockfile(build_lock_data(run_package_horizons(baseline, exercise, [0], house)), lock)
        plan = {"schema_version": "1.0", "revision": "rev1",
                "candidate": {"type": "package", "path": str(candidate),
                              "sha256": inspect(candidate)["sha256"]},
                "baseline": {"path": str(baseline), "sha256": inspect(baseline)["sha256"],
                             "locks": {"main": str(lock)}, "manifest": str(root / "approval.json"),
                             "signature": str(root / "approval.sig")},
                "scenarios": [{"id": "main", "exercise": exercise}],
                "horizons": [0], "wheelhouse": str(house),
                "output": {"result": str(root / "out/result.json"),
                           "summary": str(root / "out/summary.md")}}
        path = root / "plan.json"
        path.write_text(json.dumps(plan))
        private, public = root / "private.pem", root / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:2048", "-out", str(private)], check=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sign(path, root, private)
        decision, result = decide(path, root, public)
        assert decision == "ERROR", result["failure_stage"]
        assert result["scenarios"][0]["decision"] == "ERROR"


if __name__ == "__main__":
    test_four_decision_and_evidence()
    test_missing_horizon_and_changed_candidate_fail_closed()
    test_unsupported_clocks_are_coverage_errors()
    test_plan_and_approval_rejections()
    test_staging_swap_observer_gap_trace_and_timeout()
    test_protected_template_prepares_exact_candidate()
    test_saved_gate_result_rejects_bad_evidence_and_display_text()
    test_gate_preserved_host_file_and_nanosecond_times()
    test_sigterm_returns_error_and_removed_host_traces()
    test_package_scenarios_attribute_block()
    test_source_tree_and_sdist_admission()
    test_script_bundle_config_and_environment_scenarios()
    test_host_observer_sees_native_attempts_without_host_access()
    test_missing_package_dependency_is_gate_error()
