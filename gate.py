"""this makes signed-baseline admission decisions, separate from the legacy verify verdicts"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import tempfile

from differ import compare_with_lockfile
from gate_plan import digest, keys, load
from gate_schema import validate_result
from gate_static import hints as static_hints
from isolation import preflight
from lockfile import load_lockfile
from observer import preflight as observer_preflight
from package_input import inspect, stage, wheelhouse
from package_runner import run_package_horizons
from runner import run_multi_horizon
from schema import validate_report


SCOPE = "linux-x86_64-cpython3.14-bwrap-strace"
EXIT = {"PASS": 0, "BLOCK": 1, "ERROR": 2, "REVIEW": 3}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def atomic(path, content):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".waketrace-gate-", dir=target.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, target)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def json_file(path):
    if Path(path).stat().st_size > 262144:
        raise ValueError("manifest or lock exceeds gate size limit")
    return json.loads(Path(path).read_text(encoding="utf-8"))


def scenario_hashes(plan):
    wheels = wheelhouse(plan["wheelhouse"])["wheels"]
    return {s["id"]: digest({"scenario": s, "horizons": plan["horizons"],
                             "file_age_hours": plan["file_age_hours"],
                             "wheelhouse": wheels, "limits": plan["limits"]})
            for s in plan["scenarios"]}


def manifest_template(plan):
    base = plan["baseline"]
    return {"schema_version": "1.0", "scope": SCOPE,
            "revision": plan["revision"], "baseline_sha256": base["sha256"],
            "lock_sha256": {sid: sha256(path) for sid, path in base["locks"].items()},
            "scenario_sha256": scenario_hashes(plan),
            "policy_sha256": digest(plan["policy"]),
            "approved_by": "REPLACE_WITH_REVIEWER", "approved_at": "REPLACE_WITH_UTC_TIME",
            "expires_at": "REPLACE_WITH_UTC_TIME"}


def approval(plan, public_key):
    baseline = plan["baseline"]
    key_hash = sha256(public_key)
    manifest_hash = sha256(baseline["manifest"])
    result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public_key),
                            "-signature", baseline["signature"], baseline["manifest"]],
                            capture_output=True, text=True, timeout=10, check=False)
    if result.returncode:
        raise ValueError("baseline manifest signature is invalid")
    if sha256(public_key) != key_hash or sha256(baseline["manifest"]) != manifest_hash:
        raise ValueError("approval key or manifest changed during verification")
    data = json_file(baseline["manifest"])
    expected = manifest_template(plan)
    keys(data, expected, "approval manifest")
    if set(data) != set(expected):
        raise ValueError("approval manifest fields are missing")
    for name in ("schema_version", "scope", "revision", "baseline_sha256",
                 "lock_sha256", "scenario_sha256", "policy_sha256"):
        if data[name] != expected[name]:
            raise ValueError(f"approval manifest {name} does not match this plan")
    if not isinstance(data["approved_by"], str) or not re.fullmatch(r"[A-Za-z0-9 .@_-]{1,120}", data["approved_by"]) or \
            data["approved_by"] == "REPLACE_WITH_REVIEWER":
        raise ValueError("approval needs a named reviewer")
    try:
        approved = datetime.fromisoformat(data["approved_at"])
        expires = datetime.fromisoformat(data["expires_at"])
    except (TypeError, ValueError) as exc:
        raise ValueError("approval times are invalid") from exc
    now = datetime.now(timezone.utc)
    if approved.tzinfo is None or expires.tzinfo is None or \
            approved > now or expires <= now or expires - approved > \
            timedelta(days=90):
        raise ValueError("approval is expired, future-dated, or too long-lived")
    return {"manifest_sha256": manifest_hash,
            "trusted_key_sha256": key_hash, "reviewer": data["approved_by"],
            "expires_at": data["expires_at"], "lock_sha256": data["lock_sha256"],
            "scenario_sha256": data["scenario_sha256"]}


def stage_exact(path, expected, directory):
    before = inspect(path)
    if before["sha256"] != expected:
        raise ValueError("submitted artifact SHA-256 does not match plan")
    destination = Path(directory, Path(path).name) if before["files"] is not None else Path(directory)
    name = stage(before, destination)
    staged = destination if name == "." else destination / name
    if inspect(staged)["sha256"] != expected or inspect(path)["sha256"] != expected:
        raise ValueError("artifact changed during staging")
    return staged


def run(path, plan, scenario):
    limits = plan["limits"]
    if plan["candidate"]["type"] != "package":
        return run_multi_horizon(path, plan["horizons"], timeout_sec=limits["timeout"],
                                 extra_args=scenario["args"], extra_env=scenario["env"],
                                 memory_mb=limits["memory_mb"],
                                 output_mb=limits["output_mb"], write_limit_mb=limits["write_mb"],
                                 process_limit=limits["process_limit"],
                                 backdate_mtime_hours=plan["file_age_hours"], observer=True)
    return run_package_horizons(path, scenario["exercise"], plan["horizons"],
                                plan["wheelhouse"], plan["file_age_hours"], limits["timeout"],
                                limits["setup_timeout"], limits["memory_mb"], limits["output_mb"],
                                limits["write_mb"], limits["process_limit"], observer=True)


def health(runs, hours):
    if runs.get("horizons_tested") != hours:
        raise ValueError("required horizon list was not executed")
    for hour in hours:
        item = runs["runs"].get(str(hour))
        if not item or not item.get("complete") or item.get("backend") != "bubblewrap" or \
                item.get("network_isolated") is not True:
            raise ValueError(f"run incomplete or isolation failed at +{hour:g}h")
        if not item.get("observer", {}).get("healthy"):
            raise ValueError(f"host observer incomplete at +{hour:g}h")


def event_index(report):
    wanted = {hour: set() for hour in report["events"]}
    for finding in report["findings"]:
        for ref in finding["evidence_ids"]:
            hour = str(int(ref["horizon"])) if float(ref["horizon"]).is_integer() else str(ref["horizon"])
            wanted[hour].add(ref["event_id"])
    return {hour: [{"id": e["id"], "category": e["category"], "action": e["action"]}
                   for e in events if e ["id"] in wanted[hour]]
            for hour, events in report["events"].items()}


def evaluate(plan, public_key, scenarios, hints, state):
    if platform.machine() != "x86_64":
        raise ValueError("gate supports x86_64 only")
    approval_info = approval(plan, public_key)
    state["approval"] = approval_info
    preflight()
    observer_preflight()
    base = plan["baseline"]
    if inspect(base["path"])["sha256"] != base["sha256"]:
        raise ValueError("approved baseline artifact has changed")
    if inspect(plan["candidate"]["path"])["sha256"] != plan["candidate"]["sha256"]:
        raise ValueError("candidate artifact has changed")
    decisions = []
    with tempfile.TemporaryDirectory(prefix="waketrace-gate-") as temp:
        base_stage = stage_exact(base["path"], base["sha256"], Path(temp, "baseline"))
        candidate_stage = stage_exact(plan["candidate"]["path"],
                                      plan["candidate"]["sha256"], Path(temp, "candidate"))
        hints.extend(static_hints(candidate_stage))
        for scenario in plan["scenarios"]:
            exercise = scenario.get("exercise") or {}
            if exercise.get("mode") == "command" and "-S" in (exercise.get("argv") or []):
                hints.append({"hint": "command skips Python startup hooks",
                              "source": "gate plan", "disposition": "ERROR"})
        for scenario in plan["scenarios"]:
            sid = scenario["id"]
            if Path(base["locks"][sid]).stat().st_size > 262144:
                raise ValueError(f"baseline lock exceeds gate size limit for {sid}")
            if sha256(base["locks"][sid]) != approval_info["lock_sha256"][sid]:
                raise ValueError(f"approved lock changed before execution for {sid}")
            lock = load_lockfile(base["locks"][sid])
            if lock["schema_version"] != "2.0" or lock["horizons_locked"] != sorted(plan["horizons"]) or \
                    lock.get("execution_backend") != "bubblewrap" or lock["sha256"] != base["sha256"]:
                raise ValueError(f"baseline lock coverage or identity is invalid for {sid}")
            if plan["candidate"]["type"] == "package" and (lock.get("exercise") != scenario["exercise"] or
                    lock.get("file_age_hours") != plan["file_age_hours"]):
                raise ValueError(f"baseline exercise or file age differs for {sid}")
            baseline_runs = run(base_stage, plan, scenario)
            health(baseline_runs, plan["horizons"])
            baseline_report = compare_with_lockfile(lock, baseline_runs, policy=plan["policy"])
            validate_report(baseline_report)
            if baseline_report["verdict"] != "CLEAN" or baseline_report["temporal_coverage_missing"] or \
                    baseline_report["comparability_issues"]:
                raise ValueError(f"approved baseline no longer reproduces for {sid}")
            candidate_runs = run(candidate_stage, plan, scenario)
            report = compare_with_lockfile(lock, candidate_runs, policy=plan["policy"])
            validate_report(report)
            if report["verdict"] == "INCOMPLETE" or report["temporal_coverage_missing"] or \
                    report["comparability_issues"]:
                scenarios.append({"id": sid, "decision": "ERROR", "verify_verdict": report["verdict"],
                                  "risk_score": report["risk_score"], "threshold": report["policy"]["block_threshold"],
                                  "coverage": [{"hour": h,
                                                "baseline_complete": baseline_runs["runs"][str(h)]["complete"],
                                                "candidate_complete": candidate_runs["runs"][str(h)]["complete"],
                                                "observer_healthy": candidate_runs["runs"][str(h)].get("observer", {}).get("healthy", False)}
                                                for h in plan["horizons"]],
                                   "findings": [], "events": event_index(report)})
                raise ValueError(f"candidate evidence or coverage incomplete for {sid}")
            try:
                health(candidate_runs, plan["horizons"])
            except ValueError:
                scenarios.append({"id": sid, "decision": "ERROR", "verify_verdict": report["verdict"],
                                  "risk_score": report["risk_score"], "threshold": report["policy"]["block_threshold"],
                                  "coverage": [{"hour": h,
                                                "baseline_complete": True,
                                                "candidate_complete": candidate_runs["runs"][str(h)]["complete"],
                                                "observer_healthy": candidate_runs["runs"][str(h)].get("observer", {}).get("healthy", False)}
                                                for h in plan["horizons"]],
                                  "findings": [], "events": event_index(report)})
                raise
            decision = {"CLEAN": "PASS", "WARNING": "REVIEW", "BLOCKED": "BLOCK"}[report["verdict"]]
            coverage = []
            for hour in plan["horizons"]:
                b = baseline_runs["runs"][str(hour)]["observer"]
                c = candidate_runs["runs"][str(hour)]["observer"]
                def extra(names):
                    return sum(max(0, c["syscalls"][name] - b["syscalls"][name]) for name in names)
                delta_net = extra(("connect", "sendto", "sendmsg"))
                delta_exec = extra(("execve", "execveat", "clone", "clone3", "fork", "vfork"))
                delta_file = extra(("open", "openat", "openat2", "creat"))
                if delta_net:
                    decision = "BLOCK"
                elif (delta_exec or delta_file) and decision == "PASS":
                    decision = "REVIEW"
                coverage.append({"hour": hour, "baseline_complete": True,
                                 "candidate_complete": True, "observer_healthy": True,
                                 "baseline_observer": b, "candidate_observer": c,
                                 "extra_network_attempts": delta_net,
                                 "extra_process_starts": delta_exec,
                                 "extra_file_opens": delta_file})
            decisions.append(decision)
            scenarios.append({"id": sid, "decision": decision, "verify_verdict": report["verdict"],
                              "risk_score": report["risk_score"],
                              "threshold": report["policy"]["block_threshold"],
                              "coverage": coverage,
                              "findings": [{"category": f["category"], "rule": f["rule"],
                                            "points": f["points"], "first_seen_hour": f["first_seen_hour"],
                                            "evidence_ids": f["evidence_ids"]} for f in report["findings"]],
                              "events": event_index(report)})
            if sha256(base["locks"][sid]) != approval_info["lock_sha256"][sid]:
                      raise ValueError(f"approved lock changed during execution for {sid}")
        if inspect(base["path"])["sha256"] != base["sha256"] or \
                inspect(plan["candidate"]["path"])["sha256"] != plan["candidate"]["sha256"]:
            raise ValueError("artifact changed after execution")
        if scenario_hashes(plan) != approval_info["scenario_sha256"] or \
                sha256(base["manifest"]) != approval_info["manifest_sha256"]:
            raise ValueError("approved scenario inputs changed during execution")
    if any(h["disposition"] == "ERROR" for h in hints):
        raise ValueError("candidate uses a clock or startup mode outside virtual-time coverage")
    decision = "BLOCK" if "BLOCK" in decisions else "REVIEW" if "REVIEW" in decisions or hints else "PASS"
    return decision, scenarios, approval_info


def save_result(plan, decision, scenarios, approval_info, reason=None, hints=None):
    result = {"schema_version": "1.0", "decision": decision, "exit_code": EXIT[decision],
              "created_at": datetime.now(timezone.utc).isoformat(),
              "plan_sha256": digest(plan), "effective_plan": plan,
              "candidate_sha256": plan["candidate"]["sha256"],
              "baseline_sha256": plan["baseline"]["sha256"],
              "approval": approval_info, "scenarios": scenarios,
              "failure_stage": reason if decision == "ERROR" else None,
              "static_hints": hints or [],
              "scope": SCOPE,
              "limitations": ["only executed paths and configured horizons were observed",
                              "python time_ns, clock_gettime and native clocks may remain real",
                              "blocked syscall attempts do not prove transmission"]}
    validate_result(result)
    atomic(plan["output"]["result"], json.dumps(result, indent=2, ensure_ascii=True) + "\n")
    lines = [f"# WakeTrace admission: {decision}", "", f"Candidate SHA-256: `{result['candidate_sha256']}`",
             f"Baseline SHA-256: `{result['baseline_sha256']}`", f"Plan SHA-256: `{result['plan_sha256']}`", ""]
    if reason:
        safe_reason = re.sub(r"[\\`*_{}\[\]()#+.!<>]", lambda m: "\\" + m.group(),
                             "".join(ch for ch in reason if ch.isprintable()))
        lines += [f"Failure: {safe_reason}", ""]
    for item in scenarios:
        lines += [f"## Scenario {item['id']}: {item['decision']}", "",
                  f"Score {item['risk_score']} / block threshold {item['threshold']}.", ""]
        for coverage in item["coverage"]:
            lines += [f"- +{coverage['hour']:g}h: baseline complete={coverage['baseline_complete']}, "
                      f"candidate complete={coverage['candidate_complete']}, "
                      f"host observer healthy={coverage['observer_healthy']}; "
                      f"extra network attempts={coverage.get('extra_network_attempts', 'unknown')}, "
                      f"process starts={coverage.get('extra_process_starts', 'unknown')}, "
                      f"file opens={coverage.get('extra_file_opens', 'unknown')}."]
        for finding in item["findings"]:
            refs = ", ".join(f"+{ref['horizon']:g}h/#{ref['event_id']}"
                             for ref in finding["evidence_ids"])
            lines += [f"- {finding['rule']} at +{finding['first_seen_hour']:g}h: "
                      f"{finding['points']} points; evidence {refs or 'none'}."]
        lines.append("")
    for hint in hints or []:
        lines += [f"- Coverage hint: {hint['hint']} ({hint['disposition']}; static source text)"]
    lines += ["", "A blocked network request is an attempt, not confirmed delivery.", ""]
    atomic(plan["output"]["summary"], "\n".join(lines))
    return result


def gate(plan_path, input_root, output_root, public_key):
    try:
        plan = load(plan_path, input_root, output_root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        root = Path(output_root).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise ValueError("gate output root is not a directory") from exc
        failure = {"schema_version": "1.0", "decision": "ERROR", "exit_code": 2,
                   "failure_stage": "plan validation: " + str(exc)[:300],
                   "plan_sha256": None, "scenarios": []}
        atomic(root / "gate-error.json", json.dumps(failure, indent=2) + "\n")
        atomic(root / "gate-summary.md", "# WakeTrace admission: ERROR\n\nPlan validation failed.\n")
        return "ERROR"
    scenarios = []
    hints = []
    state = {}
    previous_term = signal.getsignal(signal.SIGTERM)
    def interrupt(signum, frame):
        raise KeyboardInterrupt("gate interrupted")
    signal.signal(signal.SIGTERM, interrupt)
    try:
        decision, scenarios, approval_info = evaluate(plan, public_key, scenarios, hints, state)
        reason = None
    except KeyboardInterrupt:
        decision, approval_info = "ERROR", state.get("approval")
        reason = "gate interrupted"
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        decision, approval_info = "ERROR", state.get("approval")
        reason = str(exc)[:300]
    finally:
        signal.signal(signal.SIGTERM, previous_term)
    save_result(plan, decision, scenarios, approval_info, reason, hints)
    return decision
