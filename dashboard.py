import math
from pathlib import Path

import streamlit as st

from dashboard_data import (capability_rows, coverage_notes, event_row, event_status,
                            filter_events, horizon_view, hour_key, hour_label,
                            linked_events, safe_text)
from dashboard_export import review_data, review_html, review_json
from differ import compare_with_lockfile
from lockfile import load_lockfile
from package_runner import run_package_horizons
from runner import run_multi_horizon
from schema import load_report

ROOT = Path(__file__).resolve().parent


def local_path(value):
    path = Path(value).expanduser()
    return path if path.is_absolute() else ROOT / path


def parse_hours(value):
    try:
        hours = [float(part.strip()) for part in value.split(',')]
    except ValueError as exc:
        raise ValueError('Enter hours as comma-separated numbers.') from exc
    if not hours or any(not math.isfinite(h) or h < 0 for h in hours) or len(set(hours)) != len(hours):
        raise ValueError('Hours must be unique, non-negative finite numbers.')
    return [int(h) if h.is_integer() else h for h in hours]


def run_check(target_name, lock_name, report_name, hours_text, timeout, setup_timeout,
              memory_mb, output_mb, write_mb, process_limit):
    target = local_path(target_name)
    report_path = local_path(report_name)
    lock_path = local_path(lock_name)
    if not target.exists():
        raise ValueError('Target does not exist: ' + str(target))
    if target == report_path or lock_path == report_path:
        raise ValueError('The report path must differ from the target and lockfile.')
    hours = parse_hours(hours_text)
    lock = load_lockfile(lock_path)
    if 'artifact' in lock:
        runs = run_package_horizons(target, lock['exercise'], hours,
                                    lock['wheelhouse']['source'], lock['file_age_hours'],
                                    timeout, setup_timeout, memory_mb, output_mb,
                                    max(write_mb, 256), process_limit)
    else:
        runs = run_multi_horizon(target, horizons_hours=hours, timeout_sec=timeout,
                                 memory_mb=memory_mb, output_mb=output_mb,
                                 write_limit_mb=write_mb, process_limit=process_limit,
                                 backdate_mtime_hours=lock.get('file_age_hours', 0))
    compare_with_lockfile(lock, runs, report_out_path=report_path)


def finding_title(finding):
    return (f"{safe_text(finding.get('severity'))} · {safe_text(finding.get('category'))} · "
            f"{safe_text(finding.get('item'))} · first observed {hour_label(finding.get('first_seen_hour', 0))}")


def show_findings(report, hour):
    view = horizon_view(report, hour)
    st.subheader('Finding evidence')
    st.caption('Choose a finding to follow every stored evidence ID to its exact event and horizon.')
    findings = report.get('findings', [])
    if not findings:
        st.info('No findings were recorded on the exercised paths.')
        return
    severity = st.selectbox('Finding severity', ['All'] + sorted({safe_text(f.get('severity')) for f in findings}))
    options = [i for i, finding in enumerate(findings)
               if severity == 'All' or finding.get('severity') == severity]
    choice = st.selectbox('Finding', options, format_func=lambda i: finding_title(findings[i]))
    finding = findings[choice]
    st.write('Rule:', safe_text(finding.get('rule')), '· Severity:', safe_text(finding.get('severity')))
    st.write('First observed:', hour_label(finding.get('first_seen_hour', 0)),
             '· Seen at:', ', '.join(hour_label(h) for h in finding.get('seen_at_hours', [])))
    st.write('Score:', finding.get('base_points', '?'), 'base ×', finding.get('multiplier', '?'),
             'timing multiplier =', finding.get('points', '?'), 'points')
    st.write('Change:', safe_text(finding.get('change')), '· Reason:', safe_text(finding.get('reason')))
    if finding.get('change') == 'timing_shift':
        st.write('Baseline first observed:', hour_label(finding['baseline_first_seen_hour']))
    if finding.get('channel'):
        st.write('Canary channel:', safe_text(finding['channel']), '· Stage:',
                 safe_text(finding.get('action_stage')), '· Status:', safe_text(finding.get('status')))
    if finding.get('channel') == 'network_attempt':
        st.warning('Prepared or blocked network request: attempt only. Outbound transmission is unconfirmed.')
    rows = linked_events(report, finding)
    if rows:
        st.dataframe(rows, hide_index=True, use_container_width=True)
        for row in rows:
            st.write(f"{row['hour']} event {row['id']} · {row['action']} · {row['target']} · {row['status']} · {row['source']}")
    else:
        st.info('No event references were supplied for this finding.')
    st.caption('Source locations are report evidence. Source preview is withheld because local source may contain secrets or have changed since the check.')
    if view['canaries']:
        st.write('Canary observations at selected horizon')
        for item in view['canaries']:
            st.write(f"{safe_text(item.get('name'))} · {safe_text(item.get('channel'))} · "
                     f"{safe_text(item.get('stage'))} · {safe_text(item.get('status'))} · "
                     f"event {item.get('event_id') or 'unknown'}")


def show_overview(report, lock, hour):
    verdict = report['verdict']
    complete = sum(bool(x.get('complete')) for x in report['run_health'].values())
    total = len(report['horizons_tested'])
    risky = [f['first_seen_hour'] for f in report['findings'] if f.get('points', 0) > 0]
    first = hour_label(min(risky)) if risky else 'not observed'
    banner = {'CLEAN': st.success, 'WARNING': st.warning, 'BLOCKED': st.error,
              'INCOMPLETE': st.info}[verdict]
    banner(f'{verdict} · ' + ('risk score not conclusive' if verdict == 'INCOMPLETE'
                            else f"risk score {report['risk_score']:g} / 100"))
    st.caption('First observed means first tested horizon with evidence, not the exact activation time.')
    cols = st.columns(3)
    cols[0].metric('First risky observation', first)
    cols[1].metric('Completed horizons', f'{complete} / {total}')
    cols[2].metric('Findings', len(report['findings']))
    st.write('Target:', safe_text(report.get('target_script')))
    if report.get('candidate_artifact'):
        artifact = report['candidate_artifact']
        st.write('Candidate artifact:', safe_text(artifact.get('name')),
                 safe_text(artifact.get('version')), '·', safe_text(artifact.get('kind')))
        st.write('Artifact SHA-256:', safe_text(artifact.get('sha256')))
    st.write('Execution backend:', safe_text(report.get('execution_backend')))
    st.subheader('Risk over tested horizons')
    chart = [{'Horizon': hour_label(h), 'Risk score': (report.get('horizon_breakdown') or {}).get(hour_key(h), {}).get('risk_score')}
             for h in report['horizons_tested']]
    st.bar_chart(chart, x='Horizon', y='Risk score', sort=False)
    st.caption('A partial horizon score is observed evidence only; an incomplete result cannot be read as clean.')
    st.subheader('Coverage and limits')
    for note in coverage_notes(report, lock):
        st.write('•', note)
    st.write('Selected horizon:', hour_label(hour), '· New findings:', len(horizon_view(report, hour)['new']))


def show_timeline(report, hour):
    view = horizon_view(report, hour)
    health = view['health']
    st.subheader(f'Events at {hour_label(hour)}')
    st.write('Run:', 'complete' if health.get('complete') else 'incomplete',
             '· Stage:', safe_text(health.get('stage')),
             '· Reason:', safe_text(health.get('reason')) if health.get('reason') else 'none')
    st.write('New findings:', len(view['new']), '· Active findings:', len(view['active']))
    for finding in view['new']:
        st.write('New:', finding_title(finding))
    if not view['new']:
        st.caption('No findings first appeared at this tested horizon.')
    rows = view['events']
    canary_ids = {item.get('event_id') for item in view['canaries']}
    for row in rows:
        row['canary_linked'] = row['id'] in canary_ids
    categories = ['All'] + sorted({row['category'] for row in rows})
    col1, col2, col3 = st.columns(3)
    category = col1.selectbox('Event category', categories)
    status = col2.selectbox('Blocked status', ['All', 'blocked', 'allowed', 'unknown'])
    canary = col3.selectbox('Canary filter', ['All', 'Canary-linked', 'Network attempts'])
    shown = filter_events(rows, category, status, canary)
    st.write(f'{len(shown)} of {len(rows)} events shown')
    if any(row['real time'] == 'not recorded' for row in shown):
        st.caption('Some timestamps were not recorded; those events follow saved sequence order.')
    page_size = 100
    pages = max(1, math.ceil(len(shown) / page_size))
    page = st.number_input('Timeline page', min_value=1, max_value=pages, value=1)
    if shown:
        page_rows = shown[(page - 1) * page_size:page * page_size]
        st.dataframe([{k: v for k, v in row.items() if k != 'canary_linked'}
                      for row in page_rows],
                     hide_index=True, use_container_width=True)
        picked = st.selectbox('Inspect event', list(range(len(page_rows))),
                              format_func=lambda i: f"Event {page_rows[i]['id']} · {page_rows[i]['category']} · {page_rows[i]['action']}")
        row = page_rows[picked]
        st.write(f"{row['hour']} event {row['id']} · {row['action']} · {row['target']} · {row['status']}")
        st.write('Real time:', row['real time'], '· Warped time:', row['warped time'])
        st.write('Source:', row['source'])
    else:
        st.info('No events match these filters. The verdict and saved report are unchanged.')
    st.caption('Events retain their stored order and IDs. Network status describes an attempt, not confirmed delivery.')


def show_mechanism(report, lock, hour):
    view = horizon_view(report, hour)
    st.subheader('How this check reached its result')
    st.write('1. Injection and containment')
    st.write('Backend:', safe_text(report.get('execution_backend')),
             '· Run health:', 'complete' if view['health'].get('complete') else 'incomplete',
             '· Network isolated:', view['health'].get('network_isolated', 'unknown'))
    st.write('Synthetic canary injection:', 'unknown (the saved report does not record injection directly)')
    st.caption('Bubblewrap contains execution. Python audit hooks provide telemetry, with coverage limits.')
    st.write('2. Time warp')
    offsets = [e['virtual offset'] for e in view['events'] if isinstance(e['virtual offset'], (int, float))]
    st.write('Observed virtual offset:', f'{max(offsets):g} seconds' if offsets else 'unknown')
    sleeps = (report.get('horizon_breakdown') or {}).get(hour_key(hour), {}).get('activity', {}).get('sleeps_skipped', {})
    st.write('Skipped sleeps:', sleeps.get('count', 'not observed'),
             '· Virtual sleep seconds:', sleeps.get('total_sec', 'unknown'))
    st.write('3. Audit event and blocker')
    linked = [row for finding in view['new'] for row in linked_events(report, finding)
              if row['hour'] == hour_label(hour)]
    audited = next((r for r in linked if r['status'] == 'blocked'), None) or \
              (linked[0] if linked else None) or \
              next((r for r in view['events'] if r['category'] not in ('health', 'output')), None)
    if audited:
        st.write(f"Event {audited['id']}: {audited['category']} · {audited['action']} · {audited['target']} · {audited['status']}")
        blocker = next((item.get('blocker') for item in view['canaries']
                        if item.get('event_id') == audited['id'] and item.get('blocker')), None)
        st.write('Reported blocker:', safe_text(blocker) if blocker else 'unknown or not applicable')
    else:
        st.write('No audited action observed at this horizon.')
    st.write('4. Lockfile comparison')
    st.write('Matching baseline horizon:', 'available' if lock and hour_key(hour) in lock.get('capabilities_by_horizon', {})
             else 'unknown or not tested')
    st.write('New findings at this horizon:', len(view['new']))
    for finding in view['new'][:5]:
        st.write(finding_title(finding))
    if not view['new']:
        st.caption('No new finding was recorded here. This does not establish safety for unexercised paths.')


def _exercise_summary(exercise):
    if not isinstance(exercise, dict):
        return 'not recorded'
    fields = [f'{name}: {safe_text(exercise[name])}' for name in ('mode', 'module', 'entry', 'distribution') if exercise.get(name)]
    if exercise.get('argv') or exercise.get('args'):
        fields.append('command arguments hidden')
    if exercise.get('env'):
        fields.append('environment values hidden')
    return ' · '.join(fields) or 'not recorded'


def _dependency_summary(items):
    if not isinstance(items, list):
        return 'unknown'
    return ', '.join(f"{safe_text(item.get('name'))} {safe_text(item.get('version'))}"
                     for item in items if isinstance(item, dict)) or 'none recorded'


def show_compare(report, lock):
    st.subheader('Baseline and candidate')
    left, right = st.columns(2)
    with left:
        st.write('Trusted baseline')
        if lock:
            st.write('Target:', safe_text(lock.get('target_script')), '· Schema:', lock['schema_version'])
            st.write('Hash:', safe_text(lock.get('sha256')))
            st.write('Horizons:', ', '.join(hour_label(h) for h in lock['horizons_locked']))
            st.write('Backend:', safe_text(lock.get('execution_backend')))
            st.write('File age:', lock.get('file_age_hours', 'unknown'))
            if lock.get('artifact'):
                st.write('Package:', safe_text(lock['artifact'].get('name')),
                         safe_text(lock['artifact'].get('version')), safe_text(lock['artifact'].get('kind')))
                st.write('Exercise:', _exercise_summary(lock.get('exercise')))
                setup = lock.get('setup') or {}
                st.write('Python:', safe_text(setup.get('python')))
                st.write('Setup:', safe_text(setup.get('build_result')))
                st.write('Dependencies:', _dependency_summary(setup.get('dependencies')))
                st.write('Wheelhouse wheels:', len((lock.get('wheelhouse') or {}).get('wheels') or []))
        else:
            st.info('Lockfile unavailable for this saved report.')
    with right:
        st.write('Candidate')
        st.write('Target:', safe_text(report.get('target_script')))
        st.write('Hash changed:', report.get('file_hash_changed', 'unknown'))
        st.write('Horizons:', ', '.join(hour_label(h) for h in report['horizons_tested']))
        st.write('Backend:', safe_text(report.get('execution_backend')))
        if report.get('candidate_artifact'):
            item = report['candidate_artifact']
            st.write('Package:', safe_text(item.get('name')), safe_text(item.get('version')),
                     safe_text(item.get('kind')))
            st.write('Hash:', safe_text(item.get('sha256')))
            st.write('Exercise:', _exercise_summary(report.get('exercise')))
            st.write('File age:', report.get('file_age_hours', 'unknown'))
            setup = report.get('candidate_setup') or {}
            for hour in report['horizons_tested']:
                snapshot = setup.get(hour_key(hour)) or {}
                st.write(hour_label(hour), 'setup:', safe_text(snapshot.get('stage', snapshot.get('build_result'))),
                         '· Python:', safe_text(snapshot.get('python')))
                st.write('Dependencies:', _dependency_summary(snapshot.get('dependencies')))
            st.write('Wheelhouse wheels:', len((report.get('candidate_wheelhouse') or {}).get('wheels') or []))
    st.subheader('Capability categories')
    if lock:
        st.dataframe(capability_rows(report, lock), hide_index=True, use_container_width=True)
    st.write('New behavior:', sum(f.get('change') == 'new' for f in report['findings']),
             '· Timing shifts:', sum(f.get('change') == 'timing_shift' for f in report['findings']))
    for note in coverage_notes(report, lock):
        st.write('•', note)
    st.caption('“None observed” means the exercised path did not show it; it does not mean the behavior is safe.')


st.set_page_config(page_title='WakeTrace investigation', layout='wide')
st.title('WakeTrace')
st.caption('Review observed behavior across tested future horizons.')
with st.sidebar:
    st.header('Local files')
    report_name = st.text_input('Report JSON', 'reports/latest_report.json')
    lock_name = st.text_input('Lockfile JSON', 'behavior.lock.json')
    with st.expander('Run a check', expanded=False):
        st.caption('Verification uses the saved trusted lock and the contained runner. A check runs only when you press the button.')
        target_name = st.text_input('Candidate target script or package', 'demo_pkgs/trojan_v2.py')
        hours_text = st.text_input('Hours, comma separated', '0,24,72,168')
        timeout = st.number_input('Seconds per horizon', min_value=0.1, value=10.0)
        setup_timeout = st.number_input('Package setup timeout (seconds)', min_value=0.1, value=60.0)
        memory_mb = st.number_input('Memory limit (MB)', min_value=64, value=512)
        output_mb = st.number_input('Output limit (MB)', min_value=1, value=8)
        write_mb = st.number_input('Writable space (MB)', min_value=1, value=256)
        process_limit = st.number_input('Process limit', min_value=1, value=2048,
                                        help='Private cgroup quota where delegated; otherwise a per-user limit.')
        run_now = st.button('Run contained verification', type='primary')
if run_now:
    try:
        with st.spinner('Running contained checks at selected horizons...'):
            run_check(target_name, lock_name, report_name, hours_text, timeout,
                      setup_timeout, memory_mb, output_mb, write_mb, process_limit)
        st.rerun()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        st.error(f'Check failed: {safe_text(exc)}')
try:
    report = load_report(local_path(report_name))
except (OSError, ValueError, KeyError, TypeError) as exc:
    st.error(f'Cannot open report: {safe_text(exc)}. Choose a valid report or run a check.')
    st.stop()
if report.get('schema_version') == 'legacy':
    st.info('INCOMPLETE · Old report lacks trustworthy event and run-health evidence. Rerun the check.')
    data = review_data(report)
    st.download_button('Download safe rerun notice (HTML)', review_html(data), 'waketrace-review.html', 'text/html')
    st.stop()
try:
    lock = load_lockfile(local_path(lock_name))
except (OSError, ValueError, KeyError, TypeError) as exc:
    lock = None
    st.warning(f'Lockfile unavailable: {safe_text(exc)}. Saved report evidence is still viewable.')
if lock and bool(lock.get('artifact')) != bool(report.get('candidate_artifact')):
    st.warning('Selected lockfile type does not match this saved report. Choose its baseline lockfile.')
    lock = None
if lock and lock.get('artifact') and report.get('baseline_artifact') and \
        lock['artifact'].get('sha256') != report['baseline_artifact'].get('sha256'):
    st.warning('Selected package lockfile does not match this report’s baseline artifact.')
    lock = None
hours = report['horizons_tested']
risky_hours = [f['first_seen_hour'] for f in report['findings'] if f.get('points', 0) > 0]
default_hour = min(risky_hours) if risky_hours else hours[0]
selected = st.select_slider('Investigate tested horizon', options=hours,
                            value=default_hour, format_func=hour_label)
page = st.radio('Review page', ['Overview', 'Investigation', 'Mechanism', 'Compare', 'Export'], horizontal=True)
if page == 'Overview':
    show_overview(report, lock, selected)
elif page == 'Investigation':
    show_timeline(report, selected)
    show_findings(report, selected)
elif page == 'Mechanism':
    show_mechanism(report, lock, selected)
elif page == 'Compare':
    show_compare(report, lock)
else:
    st.subheader('Redacted review export')
    st.caption('Exports use selected display fields. They omit canary values, URL payloads, command arguments, and private paths.')
    data = review_data(report, lock)
    st.download_button('Download printable HTML', review_html(data), 'waketrace-review.html', 'text/html')
    st.download_button('Download redacted JSON', review_json(data), 'waketrace-review.json', 'application/json')
    st.write('Included:', data['verdict'], '·', len(data['findings']), 'findings ·', len(data['horizons']), 'horizons')
