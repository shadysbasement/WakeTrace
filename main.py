import argparse
import json
import math
from pathlib import Path
import shutil
import sys
import tempfile

from differ import compare_with_lockfile, policy_config
from lockfile import build_lock_data, load_lockfile, save_lockfile
from runner import run_multi_horizon
from package_input import inspect
from package_runner import exercise_spec, run_package_horizons

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    Console = Panel = Table = None


ROOT = Path(__file__).resolve().parent
DEFAULT_LOCK = Path.cwd() / "behavior.lock.json"
DEFAULT_REPORT = Path.cwd() / "reports" / "latest_report.json"
console = Console() if Console else None


def say(message):
    if console:
        console.print(message)
    else:
        print(message)


def show_table(title, headers, rows):
    if console:
        table = Table(title=title, show_lines=True)
        for header in headers:
            table.add_column(header)
        for row in rows:
            table.add_row(*(str(value) for value in row))
        console.print(table)
        return
    print(f"\n{title}")
    values = [[str(value) for value in row] for row in rows]
    widths = [max([len(header), *(len(row[i]) for row in values)])
              for i, header in enumerate(headers)]
    line = " | ".join(header.ljust(widths[i]) for i, header in enumerate(headers))
    print(line)
    print("-+-".join("-" * width for width in widths))
    for row in values:
        print(" | ".join(value.ljust(widths[i]) for i, value in enumerate(row)))


def banner(verdict, score):
    message = f"{verdict} | risk score: {score:.1f} / 100"
    if console:
        color = {"CLEAN": "green", "WARNING": "yellow", "BLOCKED": "red",
                 "INCOMPLETE": "yellow"}[verdict]
        console.print(Panel(message, style=color))
    else:
        print(f"\n[{message}]")


def hours_arg(value):
    try:
        hours = [float(part.strip()) for part in value.split(",")]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("horizons must be comma-separated numbers") from exc
    if not hours or any(not math.isfinite(hour) or hour < 0 for hour in hours):
        raise argparse.ArgumentTypeError("horizons must be non-negative finite numbers")
    if len(set(hours)) != len(hours):
        raise argparse.ArgumentTypeError("horizons must not repeat")
    return [int(hour) if hour.is_integer() else hour for hour in hours]


def positive_float(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("enter a number greater than zero") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("enter a number greater than zero")
    return number


def positive_int(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("enter a positive whole number") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("enter a positive whole number")
    return number


def hour_label(hour):
    return f"+{hour:g}h"


def check_runs(runs):
    failed = [f"{hour_label(hour)} ({runs['runs'][str(hour)].get('error') or 'incomplete'})"
              for hour in runs["horizons_tested"]
              if not runs["runs"][str(hour)].get("complete", False)]
    if failed:
        raise ValueError("sandbox run failed at " + ", ".join(failed))


def make_lock(script, output, horizons, timeout, allow_net=False,
              memory_mb=512, output_mb=8, write_limit_mb=32, process_limit=2048,
              file_age_hours=0):
    if allow_net:
        raise ValueError("--allow-net is unavailable in contained mode")
    runs = run_multi_horizon(script, horizons_hours=horizons, timeout_sec=timeout,
                             memory_mb=memory_mb, output_mb=output_mb,
                             write_limit_mb=write_limit_mb, process_limit=process_limit,
                             backdate_mtime_hours=file_age_hours)
    check_runs(runs)
    lock = build_lock_data(runs)
    save_lockfile(lock, output)
    rows = [("Script", lock["target_script"]),
            ("Execution", lock["execution_backend"]),
            ("SHA-256 (short)", lock["sha256"][:12]),
            ("SHA-256 (full)", lock["sha256"]),
            ("Horizons", ", ".join(hour_label(h) for h in lock["horizons_locked"]))]
    for name in ("files_read", "files_written", "env_vars_read", "network_hosts",
                 "processes_spawned"):
        items = lock["capabilities"][name]
        rows.append((name, f"{len(items)}: {', '.join(items) if items else 'none'}"))
    show_table("Behavioral lock", ("Field", "Value"), rows)
    say(f"Saved lockfile: {output}")
    return lock


def verify(script, baseline, report_path, horizons, timeout, threshold,
           memory_mb=512, output_mb=8, write_limit_mb=32, process_limit=2048,
           file_age_hours=None, policy=None):
    lock = load_lockfile(baseline)
    if file_age_hours is None:
        file_age_hours = lock.get("file_age_hours", 0)
    runs = run_multi_horizon(script, horizons_hours=horizons, timeout_sec=timeout,
                             memory_mb=memory_mb, output_mb=output_mb,
                             write_limit_mb=write_limit_mb, process_limit=process_limit,
                             backdate_mtime_hours=file_age_hours)
    report = compare_with_lockfile(lock, runs, block_threshold=threshold,
                                   report_out_path=report_path, policy=policy)
    for hour in runs["horizons_tested"]:
        run = runs["runs"][str(hour)]
        score = report["horizon_breakdown"][f"{hour:g}"]["risk_score"]
        status = "INCOMPLETE" if not run['complete'] else "ALERT" if score else "CLEAN"
        say(f"{hour_label(hour)} {run['wall_time_sec']:.2f}s [{status}]")
    rows = [(f["category"], f["item"], hour_label(f["first_seen_hour"]),
             "Yes" if f["is_delayed_trigger"] else "No", f["points"], f["reason"])
             for f in report["findings"]]
    show_table("Behavioral Diff & Findings", ("Category", "Item / Target", "First Seen",
                "Delayed Time-Bomb?", "Points", "Reason"), rows)
    banner(report["verdict"], report["risk_score"])
    say(f"Saved report: {report_path}")
    return report


def _exercise_from_args(args, distribution):
    if args.exercise is None:
        raise ValueError("package lock needs --exercise import, console, or command")
    try:
        argv = json.loads(args.test_argv) if args.test_argv else None
    except json.JSONDecodeError as exc:
        raise ValueError("--test-argv must be a JSON array of strings") from exc
    env = {}
    for item in args.env or []:
        if "=" not in item:
            raise ValueError("--env needs NAME=VALUE")
        name, value = item.split("=", 1)
        env[name] = value
    return exercise_spec(args.exercise, args.module, args.entry, argv,
                         args.arg, env, distribution)


def _package_runs(path, exercise, args, wheelhouse, age):
    return run_package_horizons(
        path, exercise, args.horizons, wheelhouse, age, args.timeout,
        args.setup_timeout, args.memory_mb, args.output_mb,
        args.write_mb if args.write_mb is not None else 256, args.process_limit)


def _package_lock(args):
    info = inspect(args.target_script)
    exercise = _exercise_from_args(args, info["name"])
    runs = _package_runs(args.target_script, exercise, args, args.wheelhouse,
                         args.file_age_hours or 0)
    check_runs(runs)
    lock = build_lock_data(runs)
    save_lockfile(lock, args.output)
    show_table("Behavioral lock", ("Field", "Value"), [
        ("Artifact", f"{info['name']} {info['version']} ({info['kind']})"),
        ("SHA-256", info["sha256"]), ("Exercise", json.dumps(exercise)),
        ("Horizons", ", ".join(hour_label(h) for h in args.horizons)),
        ("File age", f"{args.file_age_hours or 0}h"),
        ("Dependencies", json.dumps(lock["setup"]["dependencies"]))])
    say(f"Saved lockfile: {args.output}")
    return lock


def _package_verify(args):
    lock = load_lockfile(args.baseline)
    if "artifact" not in lock:
        raise ValueError("package candidate needs a package baseline lockfile")
    if args.exercise is not None or args.module or args.entry or args.test_argv or args.arg or args.env:
        if not args.override_exercise:
            raise ValueError("changing the baseline exercise needs --override-exercise")
        choice = _exercise_from_args(args, lock["artifact"]["name"])
    else:
        choice = lock["exercise"]
    if args.file_age_hours is not None and args.file_age_hours != lock["file_age_hours"] \
            and not args.override_file_age:
        raise ValueError("changing baseline file age needs --override-file-age")
    age = lock["file_age_hours"] if args.file_age_hours is None else args.file_age_hours
    source = lock["wheelhouse"]["source"] if args.wheelhouse is None else args.wheelhouse
    if args.wheelhouse is not None and args.wheelhouse != lock["wheelhouse"]["source"] \
            and not args.override_wheelhouse:
        raise ValueError("changing baseline wheelhouse needs --override-wheelhouse")
    runs = _package_runs(args.target_script, choice, args, source, age)
    report = compare_with_lockfile(lock, runs, block_threshold=args.threshold,
                                   report_out_path=args.report, policy=args.policy_data)
    show_table("Package comparison", ("Field", "Value"), [
        ("Baseline", f"{lock['artifact']['name']} {lock['artifact']['version']}"),
        ("Candidate", f"{runs['artifact']['name']} {runs['artifact']['version']}"),
        ("SHA-256", runs["artifact"]["sha256"]),
        ("Exercise", json.dumps(choice)),
        ("Horizons", ", ".join(hour_label(h) for h in args.horizons)),
        ("File age", f"{age}h"),
        ("Dependency issues", ", ".join(report["comparability_issues"]) or "none")])
    banner(report["verdict"], report["risk_score"])
    say(f"Saved report: {args.report}")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="WakeTrace behavioral time-warp checker")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("preflight", help="verify the system isolation backend")
    gate_cmd = commands.add_parser("gate", help="run a signed-baseline admission gate")
    gate_cmd.add_argument("plan", type=Path)
    gate_cmd.add_argument("--input-root", type=Path, required=True)
    gate_cmd.add_argument("--output-root", type=Path, required=True)
    gate_cmd.add_argument("--approval-key", type=Path, required=True)
    show_cmd = commands.add_parser("gate-show", help="inspect a saved gate result and evidence IDs")
    show_cmd.add_argument("result", type=Path)
    template_cmd = commands.add_parser("gate-manifest-template", help="print an unsigned baseline approval draft")
    template_cmd.add_argument("plan", type=Path)
    template_cmd.add_argument("--input-root", type=Path, required=True)
    template_cmd.add_argument("--output-root", type=Path, required=True)
    lock_cmd = commands.add_parser("lock", help="record trusted behavior")
    lock_cmd.add_argument("target_script", type=Path)
    lock_cmd.add_argument("-o", "--output", type=Path, default=DEFAULT_LOCK)
    lock_cmd.add_argument("--horizons", type=hours_arg, default=hours_arg("0,24"))
    lock_cmd.add_argument("--timeout", type=positive_float, default=10)
    lock_cmd.add_argument("--allow-net", action="store_true",
                          help="unsupported in contained mode; kept to reject old unsafe commands")
    verify_cmd = commands.add_parser("verify", help="compare a script with a lockfile")
    verify_cmd.add_argument("target_script", type=Path)
    verify_cmd.add_argument("-b", "--baseline", type=Path, default=DEFAULT_LOCK)
    verify_cmd.add_argument("--horizons", type=hours_arg, default=hours_arg("0,24,72,168"))
    verify_cmd.add_argument("-r", "--report", type=Path, default=DEFAULT_REPORT)
    verify_cmd.add_argument("--threshold", type=positive_float)
    verify_cmd.add_argument('--policy', type=Path, help='validated JSON risk policy')
    verify_cmd.add_argument("--timeout", type=positive_float, default=10)
    for command in (lock_cmd, verify_cmd):
        command.add_argument("--memory-mb", type=positive_int, default=512)
        command.add_argument("--output-mb", type=positive_int, default=8)
        command.add_argument("--write-mb", type=positive_int)
        command.add_argument("--process-limit", type=positive_int, default=2048)
        command.add_argument("--file-age-hours", type=float)
        command.add_argument("--setup-timeout", type=positive_float, default=60)
        command.add_argument("--wheelhouse", type=Path)
        command.add_argument("--exercise", choices=("import", "console", "command"))
        command.add_argument("--module")
        command.add_argument("--entry")
        command.add_argument("--test-argv", help='JSON argv, e.g. ["python","-m","checks"]')
        command.add_argument("--arg", action="append")
        command.add_argument("--env", action="append", help="nonsecret NAME=VALUE")
    verify_cmd.add_argument("--override-exercise", action="store_true")
    verify_cmd.add_argument("--override-file-age", action="store_true")
    verify_cmd.add_argument("--override-wheelhouse", action="store_true")
    demo_cmd = commands.add_parser("demo", help="run the included time-bomb example")
    demo_cmd.add_argument("--strict-exit", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "gate-show":
            from gate_schema import validate_result
            result = validate_result(json.loads(args.result.read_text(encoding="utf-8")))
            print(f"Admission: {result['decision']}")
            for item in result["scenarios"]:
                print(f"Scenario {item['id']}: {item['decision']} (score {item['risk_score']})")
                for coverage in item["coverage"]:
                    print(f" +{coverage['hour']:g}h: baseline={coverage['baseline_complete']} "
                          f"candidate={coverage['candidate_complete']} observer={coverage['observer_healthy']} "
                          f"extra network={coverage.get('extra_network_attempts', 'unknown')} "
                          f"process={coverage.get('extra_process_starts', 'unknown')} "
                          f"files={coverage.get('extra_file_opens', 'unknown')}")
                for finding in item["findings"]:
                    refs = ", ".join(f"+{ref['horizon']:g}h/#{ref['event_id']}"
                                     for ref in finding["evidence_ids"])
                    print(f" {finding['rule']}: {finding['points']} points; evidence {refs or 'none'}")
                    for ref in finding["evidence_ids"]:
                        hour = str(int(ref["horizon"])) if float(ref["horizon"]).is_integer() else str(ref["horizon"])
                        event = next(e for e in item["events"][hour] if e["id"] == ref["event_id"])
                        print(f"     #{event['id']}: {event['category']}/{event['action']}")
            return 0
        if args.command == "gate":
            from gate import EXIT, gate
            decision = gate(args.plan, args.input_root, args.output_root, args.approval_key)
            say(f"Admission: {decision}")
            return EXIT[decision]
        if args.command == "gate-manifest-template":
            from gate import manifest_template
            from gate_plan import load
            plan = load(args.plan, args.input_root, args.output_root, require_approval=False)
            print(json.dumps(manifest_template(plan), indent=2))
            return 0
        if args.command == "preflight":
            from isolation import preflight
            bwrap, python = preflight()
            say(f"Isolation ready: {bwrap}; sandbox Python: {python}")
            return 0
        if args.command == 'verify':
            args.policy_data = json.loads(args.policy.read_text(encoding='utf-8')) if args.policy else None
            if args.policy_data is not None:
                policy_config(args.policy_data)
        if args.command in ("lock", "verify"):
            if args.file_age_hours is not None and (not math.isfinite(args.file_age_hours) or
                                                    args.file_age_hours < 0):
                raise ValueError("file age must be a non-negative finite number")
            kind = inspect(args.target_script)["kind"]
            if kind in ("wheel", "sdist", "source_tree"):
                if args.command == "lock":
                    if args.allow_net:
                        raise ValueError("--allow-net is unavailable in contained mode")
                    _package_lock(args)
                    return 0
                report = _package_verify(args)
                return 2 if report["verdict"] == "INCOMPLETE" else \
                    1 if report["verdict"] == "BLOCKED" else 0
        if args.command == "lock":
            make_lock(args.target_script, args.output, args.horizons, args.timeout,
                      args.allow_net, args.memory_mb, args.output_mb, args.write_mb or 32,
                      args.process_limit, args.file_age_hours or 0)
            return 0
        if args.command == "verify":
            report = verify(args.target_script, args.baseline, args.report,
                            args.horizons, args.timeout, args.threshold,
                            args.memory_mb, args.output_mb, args.write_mb or 32,
                            args.process_limit, args.file_age_hours, args.policy_data)
            return 2 if report["verdict"] == "INCOMPLETE" else \
                1 if report["verdict"] == "BLOCKED" else 0
        with tempfile.TemporaryDirectory(prefix="waketrace-demo-") as temp:
            demo = Path(temp)
            # Fresh copies make the file-age trigger relative to this demo run.
            for name in ("clean_v1.py", "trojan_v2.py"):
                shutil.copyfile(ROOT / "demo_pkgs" / name, demo / name)
            config = ROOT / "demo_pkgs" / "demo_config.json"
            if config.is_file():
                shutil.copyfile(config, demo / config.name)
            make_lock(demo / "clean_v1.py", DEFAULT_LOCK, [0, 24], 10)
            report = verify(demo / "trojan_v2.py", DEFAULT_LOCK,
                            DEFAULT_REPORT, [0, 24, 72, 168], 10, 40.0)
        say("Open the saved report JSON to inspect the time-horizon findings.")
        return 1 if args.strict_exit and report["verdict"] == "BLOCKED" else 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"WakeTrace error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
