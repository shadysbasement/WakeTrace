import json
import math
import os
import tempfile

from lockfile import (CAPABILITY_NAMES, _project_root, _run_items, _summary_caps,
                      _target_path, get_file_sha256)
from schema import validate_lock, validate_report

DEFAULT_WEIGHTS = {
    'file_read_normal': 5, 'file_read_sensitive': 35,
    'file_write_normal': 15, 'file_write_sensitive': 45,
    'env_read_normal': 2, 'env_read_sensitive': 25,
    'network_host': 40, 'process_spawn': 40, 'native_lib': 25,
    'canary_stdout': 10, 'canary_stderr': 10, 'canary_written_file': 25,
    'canary_process_argument': 45, 'canary_network_attempt': 80,
    'timing_shift': 35,
}
SENSITIVE_ENV_PATTERNS = ('SECRET', 'TOKEN', 'PASSWORD', 'API_KEY', 'CREDENTIAL',
                          'DATABASE_URL', 'AUTH')
SENSITIVE_FILE_PATTERNS = ('.env', '.ssh', 'id_rsa', 'id_ed25519', '.aws',
                           'credentials', '.npmrc', '.pypirc', '.gitconfig',
                           '/etc/shadow', '.kube')
TIME_BOMB_MULTIPLIER = 1.5
BLOCK_THRESHOLD = 40.0
POLICY_KEYS = {'weights', 'block_threshold', 'sensitive_env_patterns',
               'sensitive_file_patterns'}
CANARY_CHANNELS = {'stdout', 'stderr', 'written_file', 'process_argument',
                   'network_attempt'}


def is_sensitive_env(name, patterns=SENSITIVE_ENV_PATTERNS):
    return any(part.upper() in name.upper() for part in patterns)


def is_sensitive_file(path, patterns=SENSITIVE_FILE_PATTERNS):
    return any(part.lower() in path.lower() for part in patterns)


def _hour_key(hour):
    return str(int(hour)) if float(hour).is_integer() else str(hour)


def policy_config(policy=None, weights=None, block_threshold=None,
                  sensitive_env_patterns=None, sensitive_file_patterns=None):
    data = dict(policy or {})
    if set(data) - POLICY_KEYS:
        raise ValueError('unknown policy keys: ' + ', '.join(sorted(set(data) - POLICY_KEYS)))
    if weights is not None:
        data['weights'] = weights
    if block_threshold is not None:
        data['block_threshold'] = block_threshold
    if sensitive_env_patterns is not None:
        data['sensitive_env_patterns'] = sensitive_env_patterns
    if sensitive_file_patterns is not None:
        data['sensitive_file_patterns'] = sensitive_file_patterns
    changed = data.get('weights', {})
    if not isinstance(changed, dict) or set(changed) - set(DEFAULT_WEIGHTS):
        raise ValueError('invalid policy weight names')
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or
           not math.isfinite(v) or not 0 <= v <= 1000 for v in changed.values()):
        raise ValueError('policy weights must be finite numbers from 0 to 1000')
    threshold = data.get('block_threshold', BLOCK_THRESHOLD)
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or \
            not math.isfinite(threshold) or not 0 < threshold <= 100:
        raise ValueError('policy block_threshold must be between 0 and 100')
    for key in ('sensitive_env_patterns', 'sensitive_file_patterns'):
        value = data.get(key)
        if value is not None and (not isinstance(value, list) or not value or
                                  any(not isinstance(x, str) or not x or len(x) > 80 for x in value)):
            raise ValueError(f'policy {key} must be a nonempty list of short strings')
    return {'weights': {**DEFAULT_WEIGHTS, **changed}, 'block_threshold': threshold,
            'sensitive_env_patterns': data.get('sensitive_env_patterns', list(SENSITIVE_ENV_PATTERNS)),
            'sensitive_file_patterns': data.get('sensitive_file_patterns', list(SENSITIVE_FILE_PATTERNS))}


def _kind(category, item, policy):
    if category == 'files_read':
        return  'file_read_sensitive' if is_sensitive_file(item, policy['sensitive_file_patterns']) else 'file_read_normal'
    if category == 'files_written':
        return 'file_write_sensitive' if is_sensitive_file(item, policy['sensitive_file_patterns']) else 'file_write_normal'
    if category == 'env_vars_read':
        return 'env_read_sensitive' if is_sensitive_env(item, policy['sensitive_env_patterns']) else 'env_read_normal'
    return {'network_hosts': 'network_host', 'processes_spawned': 'process_spawn',
            'native_libs_loaded': 'native_lib'}[category]


def _refs(run, category, item, hour):
    refs = []
    mapping = {'files_read': ('file', 'file_open'), 'files_written': ('file', 'file_open'),
               'env_vars_read': ('env', 'env_read'), 'network_hosts': ('net', None),
               'processes_spawned': ('process', None), 'native_libs_loaded': ('native', None)}
    cat, action = mapping[category]
    for ev in run.get('events', []):
        if ev.get('category') != cat or action and ev.get('action') != action:
            continue
        target = str(ev.get('target', ''))
        if category in ('files_read', 'files_written') and target != item:
            continue
        if category == 'env_vars_read' and target != item:
            continue
        if category == 'network_hosts' and target != item:
            continue
        if category == 'processes_spawned' and os.path.basename(item) != target:
            continue
        if category == 'native_libs_loaded' and target != item:
            continue
        if category == 'files_written' and not any(c in str(ev.get('extra', {}).get('mode', '')) for c in 'wax+'):
            continue
        if category == 'files_read' and any(c in str(ev.get('extra', {}).get('mode', '')) for c in 'wax+'):
            continue
        refs.append({'horizon': hour, 'event_id': ev['id']})
    return refs[:8]


def _finding(category, item, hour, seen, kind, policy, refs, change='new'):
    factor = TIME_BOMB_MULTIPLIER if hour > 0 and change == 'new' else 1.0
    base = policy['weights'][kind]
    points = round(base*factor, 1)
    return {'category': category, 'item': item, 'change': change, 'rule': kind,
            'severity': 'CRITICAL' if kind == 'canary_network_attempt' else
                        'HIGH' if points >= 30 else 'MEDIUM' if points >= 15 else 'LOW',
            'base_points': base, 'multiplier': factor, 'points': points,
            'first_seen_hour': hour, 'seen_at_hours': sorted(seen),
            'is_delayed_trigger': hour > 0 and change == 'new',
            'evidence_ids': refs, 'reason': f"{change.replace('_', ' ')} {category}: {item} first observed at +{_hour_key(hour)}h"}


def _save(report, path):
    validate_report(report)
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.waketrace-report-', dir=folder, text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fp:
            json.dump(report, fp, indent=2, ensure_ascii=False)
            fp.write('\n')
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def compare_with_lockfile(lock_data, multi_horizon_result, project_root=None,
                          weights=None, block_threshold=None, report_out_path=None,
                          sensitive_env_patterns=None, sensitive_file_patterns=None,
                          policy=None):
    validate_lock(lock_data)
    config = policy_config(policy, weights, block_threshold,
                           sensitive_env_patterns, sensitive_file_patterns)
    if bool(lock_data.get('artifact')) != bool(multi_horizon_result.get('artifact')):
        raise ValueError('script and package lockfiles cannot be mixed')
    root = _project_root(multi_horizon_result, project_root)
    target = _target_path(multi_horizon_result, root)
    runs = _run_items(multi_horizon_result)
    base = lock_data['capabilities']
    temporal = lock_data.get('capabilities_by_horizon')
    by_hour = {hour: _summary_caps(run['summary'], root, target) for hour, run in runs}
    observed = {}
    for hour, caps in by_hour.items():
        for category, values in caps.items():
            for item in values:
                observed.setdefault((category, item), set()).add(hour)
    findings = []
    coverage = []
    run_map = dict(runs)
    ignore_noise = sensitive_env_patterns is None and not (
        isinstance(policy, dict) and 'sensitive_env_patterns' in policy)
    ignored_env = []
    for (category, item), seen in sorted(observed.items()):
        if ignore_noise and category == 'env_vars_read' and item in ('SSLKEYLOGFILE', 'SSL_CERT_DIR',
                'SSL_CERT_FILE', 'REQUEST_METHOD'):
            ignored_env.append(item)
            continue
        first = min(seen)
        refs = [ref for hour in sorted(seen) for ref in _refs(run_map[hour], category, item, hour)]
        if item not in base[category]:
            findings.append(_finding(category, item, first, seen, _kind(category, item, config), config, refs))
        elif temporal:
            base_first = min((float(h) for h, caps in temporal.items() if item in caps[category]), default=None)
            common = sorted(set(by_hour) & {float(h) for h in temporal})
            comparable = first in common and (first < base_first or base_first in by_hour) if base_first is not None else False
            if base_first is not None and first != base_first and comparable:
                finding = _finding(category, item, first, seen, 'timing_shift', config , refs, 'timing_shift')
                finding['baseline_first_seen_hour'] = base_first
                findings.append(finding)
    canary_seen = {}
    for hour, run in runs:
        if temporal is None or str(hour) not in temporal:
            coverage.append(hour)
        for item in run['summary'].get('canary_evidence', []):
            channel = item.get('channel')
            if channel not in CANARY_CHANNELS:
                continue
            key = (item['name'], channel, item['stage'], item['status'])
            entry = canary_seen.setdefault(key, {'hours': set(), 'refs': []})
            entry['hours'].add(hour)
            if item.get('event_id'):
                entry['refs'].append({'horizon': hour, 'event_id': item['event_id']})
    for (name, channel, stage, status), entry in sorted(canary_seen.items()):
        seen = entry['hours']
        finding = _finding('canary_evidence', name, min(seen), seen,
                           'canary_' + channel, config, entry['refs'][:16])
        finding.update(channel=channel, action_stage=stage, status=status)
        if channel == 'network_attempt':
            finding['reason'] = f'Attempted outbound canary request for {name} ({status}); transmission unconfirmed'
        elif channel in ('stdout', 'stderr'):
            finding['reason'] = f'Canary {name} observed in {channel}; output exposure'
        findings.append(finding)
    issues = []
    if 'file_age_hours' in multi_horizon_result and multi_horizon_result['file_age_hours'] != lock_data.get('file_age_hours', 0):
        issues.append('file age differs from baseline')
    if 'artifact' in multi_horizon_result:
        if lock_data['exercise'] != multi_horizon_result['exercise']:
            issues.append('exercise differs from baseline')
        if lock_data['wheelhouse']['wheels'] != multi_horizon_result['wheelhouse']['wheels']:
            issues.append('local wheelhouse differs from baseline')
        if lock_data['artifact']['name'] != multi_horizon_result['artifact']['name']:
            issues.append('distribution name differs from baseline')
        for hour, run in runs:
            setup = run.get('setup') or {}
            for key in ('dependencies', 'python'):
                if setup.get(key) != lock_data['setup'].get(key):
                    issues.append(f'{key} differ at +{_hour_key(hour)}h')
    incomplete = any(not run.get('complete', False) for _, run in runs) or bool(issues)
    score = min(100.0, round(sum(f['points'] for f in findings), 1))
    blocked = score >= config['block_threshold'] or any(f['rule'] == 'canary_network_attempt' and
              f['base_points'] >= config['block_threshold'] for f in findings)
    verdict = 'INCOMPLETE' if incomplete else 'BLOCKED' if blocked else 'WARNING' if findings or coverage else 'CLEAN'
    report = {
        'schema_version': '2.0', 'target_script': os.path.basename(target),
        'baseline_schema_version': lock_data['schema_version'],
        'baseline_execution_backend': lock_data.get('execution_backend') or 'unknown',
        'execution_backend': next((run.get('backend') for _, run in runs), None),
        'file_hash_changed': get_file_sha256(target) != lock_data['sha256'],
        'horizons_tested': sorted(hour for hour, _ in runs),
        'run_health': {_hour_key(h): {'complete': bool(r.get('complete')), 'stage': r.get('failure_stage') or
                                      ('complete' if r.get('complete') else 'execution'), 'reason': r.get('error'),
                                      'network_isolated': bool(r.get('network_isolated'))} for h, r in runs},
        'events': {_hour_key(h): r.get('events', []) for h, r in runs},
        'canary_evidence': {_hour_key(h): r['summary'].get('canary_evidence', []) for h, r in runs},
        'transmission_status': 'unknown', 'temporal_coverage_missing': coverage,
        'ignored_incidental_env': ignored_env,
        'findings': findings, 'candidate_capabilities': {name: sorted(set().union(*(
            by_hour[h][name] for h in by_hour))) for name in CAPABILITY_NAMES},
        'horizon_breakdown': {}, 'raw_score': round(sum(f['points'] for f in findings), 1),
        'risk_score': score, 'passed': verdict in ('CLEAN', 'WARNING'), 'verdict': verdict,
        'comparability_issues': sorted(set(issues)),
        'policy': {'block_threshold': config['block_threshold'],
                   'weights': config['weights'],
                   'sensitive_env_patterns': config['sensitive_env_patterns'],
                   'sensitive_file_patterns': config['sensitive_file_patterns']},
    }
    for hour, run in runs:
        active = [f for f in findings if hour in f['seen_at_hours']]
        activity = dict(run['summary'])
        activity['files_read'] = sorted(by_hour[hour]['files_read'])
        activity['files_written'] = sorted(by_hour[hour]['files_written'])
        report['horizon_breakdown'][_hour_key(hour)] = {
            'findings': active, 'new_findings': [f for f in active if f['first_seen_hour'] == hour],
            'risk_score': min(100.0, round(sum(f['points'] for f in active), 1)),
            'activity': activity}
    if 'artifact' in multi_horizon_result:
        report.update(baseline_artifact=lock_data['artifact'], candidate_artifact=multi_horizon_result['artifact'],
                      baseline_setup=lock_data['setup'],
                      candidate_setup={_hour_key(h): r.get('setup') for h, r in runs},
                      baseline_exercise=lock_data['exercise'], exercise=multi_horizon_result['exercise'],
                      exercise_overridden=lock_data['exercise'] != multi_horizon_result['exercise'],
                      baseline_file_age_hours=lock_data['file_age_hours'],
                      file_age_hours=multi_horizon_result['file_age_hours'],
                      baseline_wheelhouse=lock_data['wheelhouse'], candidate_wheelhouse=multi_horizon_result['wheelhouse'])
    if report_out_path is not None:
        _save(report, report_out_path)
    else:
        validate_report(report)
    return report
