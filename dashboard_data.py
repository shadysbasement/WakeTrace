"""Small, read-only views of validated WakeTrace reports."""

from datetime import datetime, timezone
from urllib.parse import urlsplit
import re

from schema import CAPABILITIES


def hour_key(hour):
    return str(int(hour)) if float(hour).is_integer() else str(hour)


def hour_label(hour):
    return f"+{hour:g}h"


def safe_text(value):
    """Keep display text useful without exposing URL payloads or private paths."""
    value = str(value if value is not None else "unknown")
    value = re.sub(r'(?:AKIA_WAKE_|sk-proj-wake-|ghp_wake_|sk_test_wake_|wake_)[0-9a-f]{12}',
                   '<redacted canary>', value)
    if '://' in value:
        try:
            parsed = urlsplit(value)
            return parsed.hostname or '<redacted URL>'
        except ValueError:
            return '<redacted URL>'
    value = re.sub(r'(?<!\w)/(?:home|Users|root|tmp|var)/[^\s,;)]*', '<private path>', value)
    return value[:250]


def safe_target(category, value):
    value = str(value or '')
    if re.search(r'(?:AKIA_WAKE_|sk-proj-wake-|ghp_wake_|sk_test_wake_|wake_)[0-9a-f]{12}', value):
        return '<redacted canary>'
    if category == 'file':
        if re.fullmatch(r'(?:<(?:PROJECT|PACKAGE)>|/work)/[A-Za-z0-9_./-]{1,150}', value):
            return value
        return '<redacted path>'
    if category == 'net':
        if '://' in value:
            return safe_text(value)
        return value if re.fullmatch(r'[A-Za-z0-9.:-]{1,253}', value) else '<redacted host>'
    return value if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.:-]{0,100}', value) else '<redacted>'


def event_status(event):
    if event.get('category') != 'net':
        return 'unknown'
    blocked = event.get('extra', {}).get('blocked')
    return 'blocked' if blocked is True else 'allowed' if blocked is False else 'unknown'


def source_label(event):
    source = event.get('source') or {}
    if source.get('status') != 'known':
        return 'source unknown: ' + safe_text(source.get('reason', 'attribution unavailable'))
    path = safe_target('file', source.get('path'))
    line = source.get('line')
    function = safe_text(source.get('function', 'unknown'))
    return f'{path}:{line} · {function}' if isinstance(line, int) and line > 0 else f'{path} · {function}'


def clock_time(value):
    if not isinstance(value, (int, float)):
        return 'not recorded'
    try:
        return datetime.fromtimestamp(value, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OverflowError, OSError, ValueError):
        return 'not recorded'


def event_row(event, hour):
    return {'hour': hour_label(hour), 'id': event.get('id'),
            'real time': clock_time(event.get('ts_real')),
            'warped time': clock_time(event.get('ts_warped')),
            'virtual offset': event.get('virtual_offset_sec'),
            'category': safe_text(event.get('category')),
            'action': safe_text(event.get('action')),
            'target': safe_target(event.get('category'), event.get('target')),
            'status': event_status(event), 'source': source_label(event)}


def horizon_view(report, hour):
    key = hour_key(hour)
    events = report.get('events', {}).get(key, [])
    findings = report.get('findings', [])
    return {'health': report.get('run_health', {}).get(key, {}),
            'events': [event_row(event, hour) for event in events],
            'new': [f for f in findings if f.get('first_seen_hour') == hour],
            'active': [f for f in findings if hour in f.get('seen_at_hours', [])],
            'canaries': report.get('canary_evidence', {}).get(key, []),
            'risk': (report.get('horizon_breakdown') or {}).get(key, {}).get('risk_score')}


def filter_events(rows, category='All', status='All', canary='All'):
    return [row for row in rows if
            (category == 'All' or row['category'] == category) and
            (status == 'All' or row['status'] == status) and
            (canary == 'All' or (canary == 'Network attempts' and row['category'] == 'net') or
             (canary == 'Canary-linked' and row.get('canary_linked')))]


def linked_events(report, finding):
    result = []
    for ref in finding.get('evidence_ids', []):
        hour = ref['horizon']
        event = next((e for e in report['events'][hour_key(hour)]
                      if e['id'] == ref['event_id']), None)
        if event is not None:
            result.append(event_row(event, hour))
    return result


def capability_rows(report, lock):
    baseline = lock.get('capabilities', {}) if lock else {}
    candidate = report.get('candidate_capabilities', {})
    rows = []
    for category in CAPABILITIES:
        old = set(baseline.get(category, []))
        new = set(candidate.get(category, []))
        kind = {'files_read': 'file', 'files_written': 'file', 'env_vars_read': 'env',
                'network_hosts': 'net', 'processes_spawned': 'process',
                'native_libs_loaded': 'native'}[category]
        display = lambda items: ', '.join(safe_target(kind, item) for item in sorted(items)) or 'none observed'
        rows.append({'category': category, 'baseline observed': display(old),
                     'candidate observed': display(new), 'added': display(new - old)})
    return rows


def coverage_notes(report, lock):
    notes = []
    if lock is None:
        notes.append('Lockfile unavailable; baseline comparison cannot be displayed.')
    elif lock.get('schema_version') != '2.0':
        notes.append('Old lock: per-hour baseline timing coverage is unknown.')
    elif report.get('temporal_coverage_missing'):
        notes.append('Baseline did not test: ' + ', '.join(hour_label(h) for h in report['temporal_coverage_missing']))
    for hour in report.get('horizons_tested', []):
        health = report.get('run_health', {}).get(hour_key(hour), {})
        if not health.get('complete'):
            notes.append(f"{hour_label(hour)} incomplete at {safe_text(health.get('stage'))}: {safe_text(health.get('reason'))}")
    for issue in report.get('comparability_issues', []):
        notes.append(safe_text(issue))
    notes.append('Only exercised paths were observed. Unobserved paths have unknown behavior.')
    return notes
