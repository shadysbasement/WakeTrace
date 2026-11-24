"""Run WakeTrace against a real incident's monthly date trigger adaptation."""

import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def horizons(now=None):
    """Choose one horizon on the next 15th, with adjacent-day controls."""
    now = now or datetime.now(timezone.utc)
    year, month = now.year, now.month
    while True:
        trigger = datetime(year, month, 15, 12, tzinfo=timezone.utc)
        if (trigger - now).total_seconds() >= 48 * 3600:
            break
        month += 1
        if month == 13:
            year, month = year + 1, 1
    active = math.ceil((trigger - now).total_seconds() / 3600)
    return [0, active - 24, active, active + 24]


def run(output_dir):
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    lock_path = output_dir / 'behavior.lock.json'
    report_path = output_dir / 'report.json'
    hours = horizons()
    hour_arg = ','.join(map(str, hours))
    commands = (
        ([sys.executable, str(ROOT / 'main.py'), 'lock', str(HERE / 'baseline.py'),
          '-o', str(lock_path), '--horizons', hour_arg], 0),
        ([sys.executable, str(ROOT / 'main.py'), 'verify', str(HERE / 'candidate.py'),
          '-b', str(lock_path), '-r', str(report_path), '--horizons', hour_arg], 1),
    )
    for command, expected in commands:
        result = subprocess.run(command, cwd=output_dir, capture_output=True, text=True, timeout=120)
        if result.returncode != expected:
            raise RuntimeError(f"WakeTrace exited {result.returncode}: {result.stderr or result.stdout}")
    report = json.loads(report_path.read_text(encoding='utf-8'))
    before = report['horizon_breakdown'][str(hours[1])]['risk_score']
    active = report['horizon_breakdown'][str(hours[2])]['risk_score']
    delayed = [finding for finding in report['findings']
               if finding['first_seen_hour'] == hours[2] and finding['points'] > 0]
    if before != 0 or active <= 0 or not delayed or report['verdict'] != 'BLOCKED':
        raise RuntimeError('The report did not show a clean pre-trigger horizon and blocked trigger horizon.')
    print(f"Before +{hours[1]}h: risk {before:g}/100")
    print(f"On the 15th +{hours[2]}h: risk {active:g}/100; {len(delayed)} new findings")
    print(f"Verdict: {report['verdict']}")
    print(f"Report: {report_path}")
    return report, hours


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('incident_monthly_output'))
    args = parser.parse_args(argv)
    try:
        run(args.output)
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f'Incident demo failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
