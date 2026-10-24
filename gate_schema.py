"""this is validation for the saved admission results, the legacy reports remain separate."""

import math
import re

from gate_plan import digest


EXIT = {"PASS": 0, "BLOCK": 1, "ERROR": 2, "REVIEW": 3}
HEX = re.compile(r"[0-9a-f]{64}\Z")


def validate_result(data):
    if not isinstance(data, dict) or data.get("schema_version") != "1.0":
        raise ValueError("unsupported gate result schema")
    decision = data.get("decision")
    if decision not in EXIT or data.get("exit_code") != EXIT[decision]:
        raise ValueError("gate decision and exit code disagree")
    plan = data.get("effective_plan")
    if not isinstance(plan, dict) or data.get("plan_sha256") != digest(plan):
        raise ValueError("gate effective plan digest is invalid")
    if data.get("candidate_sha256") != plan.get("candidate", {}).get("sha256") or \
            data.get("baseline_sha256") != plan.get("baseline", {}).get("sha256"):
        raise ValueError("gate artifact digests disagree with plan")
    if data.get("scope") != "linux-x86_64-cpython3.14-bwrap-strace":
        raise ValueError("gate scope is invalid")
    scenarios = data.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) > len(plan.get("scenarios", [])):
        raise ValueError("gate scenarios are invalid")
    ids = [s.get("id") for s in scenarios if isinstance(s, dict)]
    if len(ids) != len(scenarios) or len(ids) != len(set(ids)) or \
            any(not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", sid) for sid in ids) or \
            any(sid not in {item["id"] for item in plan["scenarios"]} for sid in ids):
        raise ValueError("gate scenario IDs are invalid")
    for scenario in scenarios:
        if scenario.get("decision") not in EXIT:
            raise ValueError("gate scenario decision is invalid")
        if any(isinstance(scenario.get(name), bool) or not isinstance(scenario.get(name), (int, float)) or
               not math.isfinite(scenario[name]) for name in ("risk_score", "threshold")):
            raise ValueError("gate score is invalid")
        coverage = scenario.get("coverage")
        if not isinstance(coverage, list) or any(not isinstance(c, dict) for c in coverage) or \
                [c.get("hour") for c in coverage] != plan["horizons"]:
            raise ValueError("gate horizon coverage is invalid")
        for item in coverage:
            if not all(isinstance(item.get(name), bool) for name in
                       ("baseline_complete", "candidate_complete", "observer_healthy")):
                raise ValueError("gate run health is invalid")
        events = scenario.get("events")
        if not isinstance(events, dict):
            raise ValueError("gate evidence index is invalid")
        ids_by_hour = {}
        for hour in plan["horizons"]:
            event_list = events.get(str(int(hour)) if float(hour).is_integer() else str(hour))
            if not isinstance(event_list, list):
                raise ValueError("gate event hour is missing")
            event_ids = [e.get("id") for e in event_list if isinstance(e, dict)]
            if len(event_ids) != len(event_list) or len(event_ids) != len(set(event_ids)) or \
                    any(not isinstance(i, int) or isinstance(i, bool) or i <= 0 for i in event_ids):
                raise ValueError("gate event IDs are invalid")
            if any(not isinstance(e.get("category"), str) or not isinstance(e.get("action"), str) or
                    not re.fullmatch(r"[A-Za-z_]{1,50}", e["category"]) or
                    not re.fullmatch(r"[A-Za-z_]{1,50}", e["action"]) for e in event_list):
                raise ValueError("gate event labels are invalid")
            ids_by_hour[hour] = set(event_ids)
        if not isinstance(scenario.get("findings"), list):
            raise ValueError("gate findings are invalid")
        for finding in scenario["findings"]:
            if not isinstance(finding, dict) or not isinstance(finding.get("evidence_ids"), list):
                raise ValueError("gate finding is invalid")
            if not isinstance(finding.get("rule"), str) or not isinstance(finding.get("category"), str) or \
                    not re.fullmatch(r"[A-Za-z_]{1,50}", finding["rule"]) or \
                    not re.fullmatch(r"[A-Za-z_]{1,50}", finding["category"]):
                raise ValueError("gate finding label is invalid")
            for ref in finding["evidence_ids"]:
                if not isinstance(ref, dict) or ref.get("horizon") not in ids_by_hour or \
                        ref.get("event_id") not in ids_by_hour[ref["horizon"]]:
                    raise ValueError("gate finding references missing evidence")
    if decision == "PASS" and (data.get("static_hints") or len(scenarios) != len(plan["scenarios"]) or
            any(s["decision"] != "PASS" or any(not c["baseline_complete"] or
                not c["candidate_complete"] or not c["observer_healthy"]
                for c in s["coverage"]) for s in scenarios)):
        raise ValueError("incomplete gate cannot pass")
    approval = data.get("approval")
    if decision != "ERROR":
        if not isinstance(approval, dict) or any(not isinstance(approval.get(name), str) or
                not HEX.fullmatch(approval[name]) for name in
                ("manifest_sha256", "trusted_key_sha256")) or \
                not isinstance(approval.get("reviewer"), str) or \
                not isinstance(approval.get("expires_at"), str) or \
                not isinstance(approval.get("lock_sha256"), dict) or \
                not isinstance(approval.get("scenario_sha256"), dict) or \
                set(approval.get("lock_sha256", {})) != set(ids) or \
                set(approval.get("scenario_sha256", {})) != set(ids) or \
                any(not isinstance(v, str) or not HEX.fullmatch(v) for v in
                    (*approval["lock_sha256"].values(), *approval["scenario_sha256"].values())):
            raise ValueError("decision lacks valid baseline approval")
    return data
