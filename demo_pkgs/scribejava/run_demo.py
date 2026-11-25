"""Exercise the real clean and malicious ScribeJava JARs in containment."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
HASHES = {
    '8.3.3': 'b21eacc12983b0de585b05ef307b35f012e48f2898a4acdba529bbb0d379c443',
    '8.3.5': 'dbf92d66441f795dae60182002248bf167779dd1e856b4daf62e9eeded307c17',
}

sys.path.insert(0, str(ROOT))
from java_scribe_runner import next_fifteenth_horizons


def run(output_dir):
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    for version, expected in HASHES.items():
        jar = HERE / f'scribejava-core-{version}.jar'
        if hashlib.sha256(jar.read_bytes()).hexdigest() != expected:
            raise ValueError(f'ScribeJava {version} JAR hash mismatch')
    lock_path = output_dir / 'behavior.lock.json'
    report_path = output_dir / 'report.json'
    hours = next_fifteenth_horizons()
    hour_arg = ','.join(map(str, hours))
    commands = (
        ([sys.executable, str(ROOT / 'main.py'), 'lock',
          str(HERE / 'scribejava-core-8.3.3.jar'), '-o', str(lock_path),
          '--exercise', 'scribejava-oauth', '--horizons', hour_arg], 0),
        ([sys.executable, str(ROOT / 'main.py'), 'verify',
          str(HERE / 'scribejava-core-8.3.5.jar'), '-b', str(lock_path),
          '-r', str(report_path), '--horizons', hour_arg], 1),
    )
    for command, expected in commands:
        result = subprocess.run(command, cwd=output_dir, capture_output=True,
                                text=True, timeout=120, check=False)
        if result.returncode != expected:
            raise RuntimeError(f'WakeTrace exited {result.returncode}: '
                               f'{result.stderr or result.stdout}')
    report = json.loads(report_path.read_text(encoding='utf-8'))
    before = report['horizon_breakdown'][str(hours[1])]['risk_score']
    active = report['horizon_breakdown'][str(hours[2])]['risk_score']
    after = report['horizon_breakdown'][str(hours[3])]['risk_score']
    delayed = [finding for finding in report['findings']
               if finding['first_seen_hour'] == hours[2] and finding['points'] > 0]
    if before != 0 or active <= 0 or after != 0 or not delayed or \
            report['verdict'] != 'BLOCKED' or \
            not all(health['complete'] and health['network_isolated']
                    for health in report['run_health'].values()):
        raise RuntimeError('The real JAR exercise did not produce the expected date-gated result')
    print(f"Real JAR: io.github.leetcrunch:scribejava-core:8.3.5")
    print(f"Before the 15th +{hours[1]}h: risk {before:g}/100")
    print(f"On the 15th +{hours[2]}h: risk {active:g}/100; {len(delayed)} new findings")
    print(f"After the 15th +{hours[3]}h: risk {after:g}/100")
    print(f"Verdict: {report['verdict']} · prepared request blocked inside sandbox")
    print(f'Report: {report_path}')
    return report, hours


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('reports/scribejava-real'))
    args = parser.parse_args(argv)
    try:
        run(args.output)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f'ScribeJava demo failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
