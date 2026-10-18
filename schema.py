import json
import math
import re
from pathlib import Path

CAPABILITIES = ('files_read', 'files_written', 'env_vars_read', 'network_hosts',
                'processes_spawned', 'native_libs_loaded')
VERDICTS = {'CLEAN', 'WARNING', 'BLOCKED', 'INCOMPLETE'}


def hours(values):
    return (isinstance(values, list) and bool(values) and
            all(isinstance(h, (int, float)) and not isinstance(h, bool) and
                math.isfinite(h) and h >= 0 for h in values) and
            len(values) == len(set(values)))


def caps(value):
    return (isinstance(value, dict) and set(value) == set(CAPABILITIES) and
            all(isinstance(value[key], list) and
                all(isinstance(item, str) for item in value[key]) and
                len(value[key]) == len(set(value[key])) for key in CAPABILITIES))


def validate_lock(data):
    if not isinstance(data, dict) or data.get('schema_version') not in ('1.0', '1.1', '2.0'):
        raise ValueError('unsupported lockfile schema version')
    if not caps(data.get('capabilities')) or not hours(data.get('horizons_locked')):
        raise ValueError('invalid lockfile capabilities or horizons')
    if not isinstance(data.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', data['sha256']):
        raise ValueError('invalid lockfile hash')
    if not isinstance(data.get('target_script'), str):
        raise ValueError('invalid lockfile target')
    if data['schema_version'] in ('1.1', '2.0') and 'artifact' in data:
        for field in ('artifact', 'setup', 'exercise', 'wheelhouse', 'file_age_hours'):
            if field not in data:
                raise ValueError(f'package lock missing {field}')
    if data['schema_version'] == '2.0':
        by_hour = data.get('capabilities_by_horizon')
        if not isinstance(by_hour, dict) or set(by_hour) != {str(h) for h in data['horizons_locked']}:
            raise ValueError('invalid per-horizon capabilities')
        if not all(caps(item) for item in by_hour.values()):
            raise ValueError('invalid per-horizon capabilities')
    return data


def validate_report(data):
    if not isinstance(data, dict) or data.get('schema_version') != '2.0':
        raise ValueError('unsupported report schema version')
    if data.get('verdict') not in VERDICTS or not hours(data.get('horizons_tested')):
        raise ValueError('invalid report verdict or horizons')
    if not isinstance(data.get('run_health'), dict) or not isinstance(data.get('events'), dict):
        raise ValueError('report is missing health or events')
    if data.get('execution_backend') != 'bubblewrap' or data.get('transmission_status') != 'unknown':
        raise ValueError('report is missing containment or transmission status')
    if not caps(data.get('candidate_capabilities')) or not isinstance(data.get('findings'), list):
        raise ValueError('report capabilities or findings are invalid')
    if not isinstance(data.get('risk_score'), (int, float)) or isinstance(data['risk_score'], bool) or \
            not math.isfinite(data['risk_score']):
        raise ValueError('report risk score is invalid')
    if not isinstance(data.get('horizon_breakdown', {}), dict) or \
            not isinstance(data.get('temporal_coverage_missing', []), list) or \
            any(not isinstance(h, (int, float)) or isinstance(h, bool) or
                not math.isfinite(h) for h in data.get('temporal_coverage_missing', [])):
        raise ValueError('invalid report coverage')
    for key in ('candidate_artifact', 'baseline_artifact', 'candidate_setup'):
        if key in data and not isinstance(data[key], dict):
            raise ValueError(f'invalid report {key}')
    all_ids = {}
    for h in data['horizons_tested']:
        key = str(int(h)) if float(h).is_integer() else str(h)
        health = data['run_health'].get(key)
        events = data['events'].get(key)
        if not isinstance(health, dict) or not isinstance(health.get('complete'), bool) or \
                not isinstance(health.get('network_isolated'), bool) or not isinstance(events, list):
            raise ValueError(f'invalid report hour {key}')
        ids = [event.get('id') for event in events if isinstance(event, dict)]
        if len(events) > 5002 or len(ids) != len(events) or len(ids) != len(set(ids)) or \
                any(not isinstance(i, int) or isinstance(i, bool) or i <= 0 for i in ids):
            raise ValueError(f'invalid event IDs at +{key}h')
        for event in events:
            if not isinstance(event.get('category'), str) or not isinstance(event.get('action'), str) or \
                    not isinstance(event.get('extra', {}), dict) or \
                    not isinstance(event.get('source', {}), dict):
                raise ValueError(f'invalid event detail at +{key}h')
        all_ids[h] = set(ids)
    for finding in data['findings']:
        if not isinstance(finding, dict) or finding.get('category') not in (*CAPABILITIES, 'canary_evidence'):
            raise ValueError('invalid finding category')
        first = finding.get('first_seen_hour')
        seen = finding.get('seen_at_hours')
        if not isinstance(first, (int, float)) or isinstance(first, bool) or first not in all_ids or \
                not isinstance(seen, list) or not seen or \
                any(not isinstance(hour, (int, float)) or isinstance(hour, bool) or
                    hour not in all_ids for hour in seen) or first not in seen:
            raise ValueError('invalid finding horizons')
        for field in ('base_points', 'multiplier', 'points'):
            value = finding.get(field)
            if value is not None and (not isinstance(value, (int, float)) or
                                      isinstance(value, bool) or not math.isfinite(value)):
                raise ValueError('invalid finding score')
        refs = finding.get('evidence_ids')
        if not isinstance(refs, list):
            raise ValueError('finding evidence references missing')
        for ref in refs:
            if not isinstance(ref, dict) or not isinstance(ref.get('horizon'), (int, float)) or \
                    isinstance(ref.get('horizon'), bool) or ref['horizon'] not in all_ids or \
                    not isinstance(ref.get('event_id'), int) or ref['event_id'] not in all_ids[ref['horizon']]:
                raise ValueError('finding references a missing event')
    evidence = data.get('canary_evidence')
    if not isinstance(evidence, dict) or set(evidence) != {
            str(int(h)) if float(h).is_integer() else str(h) for h in data['horizons_tested']}:
        raise ValueError('invalid canary evidence timeline')
    for h in data['horizons_tested']:
        key = str(int(h)) if float(h).is_integer() else str(h)
        if not isinstance(evidence[key], list):
            raise ValueError('invalid canary evidence')
        for item in evidence[key]:
            if not isinstance(item, dict) or not isinstance(item.get('name'), str) or \
                    item.get('channel') not in ('environment_read', 'stdout', 'stderr',
                                                'written_file', 'process_argument', 'network_attempt') or \
                    item.get('event_id') is not None and item['event_id'] not in all_ids[h]:
                raise ValueError('invalid canary evidence reference')
    if data['verdict'] == 'CLEAN' and any(not x['complete'] for x in data['run_health'].values()):
        raise ValueError('incomplete report cannot be clean')
    if data['verdict'] == 'CLEAN' and any(not x['network_isolated'] for x in data['run_health'].values()):
        raise ValueError('report without network isolation cannot be clean')
    return data


def load_report(path):
    with open(path, encoding='utf-8') as fp:
        data = json.load(fp)
    if isinstance(data, dict) and 'schema_version' not in data and data.get('verdict') in VERDICTS:
        return {'schema_version': 'legacy', 'verdict': 'INCOMPLETE',
                'reason': 'old report lacks trustworthy event and run-health evidence; rerun the check',
                'temporal_coverage': 'unknown', 'transmission_status': 'unknown'}
    return validate_report(data)
