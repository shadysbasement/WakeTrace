"""Redacted, explicit review exports from validated reports."""

from html import escape
import json
import re

from dashboard_data import hour_label, hour_key


def _name(value):
    value = str(value or '')
    if re.search(r'(?:AKIA_WAKE_|sk-proj-wake-|ghp_wake_|sk_test_wake_|wake_)[0-9a-f]{12}', value):
        return '<redacted>'
    return value if re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.:-]{0,100}', value) else '<redacted>'


def _target(category, value):
    value = str(value or '')
    if re.search(r'(?:AKIA_WAKE_|sk-proj-wake-|ghp_wake_|sk_test_wake_|wake_)[0-9a-f]{12}', value):
        return '<redacted>'
    if category == 'net':
        return _name(value)
    if category in ('env', 'process', 'native', 'output', 'health'):
        return _name(value)
    if category == 'file' and value.startswith(('<PROJECT>/', '<PACKAGE>/', '/work/')) and \
            not any(mark in value for mark in ('?', '#', '\n', '\r')):
        return value[:160] if re.fullmatch(r'(?:<(?:PROJECT|PACKAGE)>|/work)/[A-Za-z0-9_./-]{1,150}', value) else '<redacted>'
    return '<redacted>'


def _artifact(data):
    if not isinstance(data, dict):
        return None
    return {key: _name(data.get(key)) for key in ('name', 'version', 'kind', 'sha256')
            if data.get(key) is not None}


def review_data(report, lock=None):
    if report.get('schema_version') == 'legacy':
        return {'verdict': 'INCOMPLETE', 'notice': 'Old report lacks trustworthy evidence. Rerun the check.',
                'limitations': ['Legacy fields were discarded by the report loader.']}
    result = {
        'verdict': report['verdict'],
        'risk_score': report['risk_score'] if report['verdict'] != 'INCOMPLETE' else None,
        'target': _name(report.get('target_script')),
        'baseline_artifact': _artifact(report.get('baseline_artifact')),
        'candidate_artifact': _artifact(report.get('candidate_artifact')),
        'horizons': [], 'findings': [],
        'limitations': [],
        'transmission_status': 'unknown',
    }
    for hour in report['horizons_tested']:
        health = report['run_health'][hour_key(hour)]
        result['horizons'].append({'hour': hour_label(hour), 'complete': health['complete'],
                                   'stage': _name(health.get('stage')),
                                   'events_recorded': len(report['events'][hour_key(hour)])})
    for finding in report['findings']:
        refs = []
        for ref in finding['evidence_ids']:
            hour = ref['horizon']
            event = next((e for e in report['events'][hour_key(hour)]
                          if e['id'] == ref['event_id']), None)
            if event is None:
                continue
            category = event.get('category')
            source = event.get('source') or {}
            refs.append({'hour': hour_label(hour), 'event_id': event['id'],
                         'category': _name(category), 'action': _name(event.get('action')),
                         'target': _target(category, event.get('target')),
                         'status': ('blocked' if event.get('extra', {}).get('blocked') is True else
                                    'allowed' if event.get('extra', {}).get('blocked') is False else 'unknown'),
                         'source': _target('file', source.get('path'))
                         if source.get('status') == 'known' else 'unknown',
                         'line': source.get('line') if isinstance(source.get('line'), int) and
                         source['line'] > 0 else None,
                         'function': _name(source.get('function')) if source.get('status') == 'known' else None})
        result['findings'].append({'category': _name(finding.get('category')),
                                   'item': _target({'network_hosts': 'net', 'files_read': 'file',
                                                    'files_written': 'file', 'env_vars_read': 'env',
                                                    'processes_spawned': 'process', 'canary_evidence': 'env'
                                                    }.get(finding.get('category'), 'native'), finding.get('item')),
                                   'rule': _name(finding.get('rule')),
                                   'severity': _name(finding.get('severity')),
                                   'change': _name(finding.get('change')),
                                   'canary_channel': _name(finding.get('channel')) if finding.get('channel') else None,
                                   'canary_stage': _name(finding.get('action_stage')) if finding.get('action_stage') else None,
                                   'first_observed': hour_label(finding.get('first_seen_hour', 0)),
                                   'base_points': finding.get('base_points'),
                                   'multiplier': finding.get('multiplier'),
                                   'points': finding.get('points'),
                                   'evidence': refs})
    result['limitations'] = ['Only exercised paths were observed. Unobserved paths have unknown behavior.']
    if lock is None:
        result['limitations'].append('Lockfile unavailable; baseline comparison is unknown.')
    elif lock.get('schema_version') != '2.0':
        result['limitations'].append('Old lock: per-hour baseline timing coverage is unknown.')
    if report.get('temporal_coverage_missing'):
        result['limitations'].append('Baseline did not test: ' +
                                     ', '.join(hour_label(h) for h in report['temporal_coverage_missing']))
    for hour in report['horizons_tested']:
        health = report['run_health'][hour_key(hour)]
        if not health['complete']:
            result['limitations'].append(f'{hour_label(hour)} incomplete at {_name(health.get("stage"))}.')
    if report.get('comparability_issues'):
        result['limitations'].append('Candidate setup or exercise differs from baseline; see local report.')
    result['limitations'].append('A blocked or prepared network request is an attempt; transmission is unconfirmed.')
    if report['verdict'] == 'INCOMPLETE':
        result['limitations'].append('This check is INCOMPLETE and cannot support a clean conclusion.')
    return result


def review_json(data):
    return json.dumps(data, indent=2, ensure_ascii=False) + '\n'


def review_html(data):
    lines = ['<!doctype html><html lang="en"><meta charset="utf-8">',
             '<title>WakeTrace review</title><style>body{font:16px system-ui;max-width:850px;margin:2rem auto;padding:0 1rem;line-height:1.5}section{border-top:1px solid #aaa;padding:1rem 0}small{color:#444}code{overflow-wrap:anywhere}</style>',
             '<h1>WakeTrace review</h1>', f'<p><strong>Verdict: {escape(data["verdict"])}</strong></p>']
    if 'notice' in data:
        lines.append(f'<p>{escape(data["notice"])}</p>')
    else:
        lines.append(f'<p>Target: {escape(data["target"])} · Risk score: {escape(str(data["risk_score"] if data["risk_score"] is not None else "not conclusive"))}</p>')
        for artifact_key in ('baseline_artifact', 'candidate_artifact'):
            artifact = data.get(artifact_key)
            if artifact:
                lines.append(f'<p>{escape(artifact_key.replace("_", " ").title())}: ' +
                             escape(' '.join(artifact.values())) + '</p>')
        lines.append('<section><h2>Coverage</h2><ul>')
        for hour in data['horizons']:
            lines.append(f'<li>{escape(hour["hour"])}: {"complete" if hour["complete"] else "incomplete"} · {escape(hour["stage"])} · {hour["events_recorded"]} events</li>')
        lines.append('</ul></section><section><h2>Findings and linked evidence</h2>')
        for finding in data['findings']:
            lines.append(f'<h3>{escape(finding["severity"])} · {escape(finding["category"])} · {escape(finding["item"])}</h3>')
            lines.append(f'<p>Rule {escape(finding["rule"])} · first observed {escape(finding["first_observed"])} · {finding["base_points"]} × {finding["multiplier"]} = {finding["points"]} points</p><ul>')
            if finding['canary_channel']:
                lines.append(f'<p>Canary channel: {escape(finding["canary_channel"])} · stage: {escape(finding["canary_stage"] or "unknown")}</p>')
            for event in finding['evidence']:
                location = event['source'] + (f":{event['line']}" if event['line'] else '')
                lines.append(f'<li>{escape(event["hour"])} event {event["event_id"]}: {escape(event["action"])} · {escape(event["target"])} · {escape(event["status"])} · source {escape(location)}</li>')
            lines.append('</ul>')
        lines.append('</section>')
    lines.append('<section><h2>Limits</h2><ul>')
    for note in data['limitations']:
        lines.append(f'<li>{escape(note)}</li>')
    lines.append('</ul></section></html>')
    return '\n'.join(lines)
