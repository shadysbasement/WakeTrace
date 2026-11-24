"""Incident-derived monthly trigger is exposed by virtual time."""

from datetime import datetime, timedelta, timezone

from examples.incident_monthly.run_demo import horizons, run


def test_monthly_horizons_cross_the_15th_even_at_year_end():
    now = datetime(2026, 12, 31, 23, tzinfo=timezone.utc)
    start, before, active, after = horizons(now)
    assert start == 0
    assert (now + timedelta(hours=before)).day == 14
    assert (now + timedelta(hours=active)).day == 15
    assert (now + timedelta(hours=after)).day == 16


def test_incident_trigger_is_clean_before_and_blocked_on_the_15th(tmp_path):
    report, hours = run(tmp_path)
    assert report['verdict'] == 'BLOCKED'
    assert [report['horizon_breakdown'][str(hour)]['risk_score'] for hour in hours] == \
        [0, 0, 100, 0]
    assert all(item['complete'] and item['network_isolated']
               for item in report['run_health'].values())
    delayed = [finding for finding in report['findings']
               if finding['first_seen_hour'] == hours[2]]
    assert {finding['category'] for finding in delayed} == {'env_vars_read', 'network_hosts'}
    assert any(event['category'] == 'net' and event['target'] == 'example.invalid' and
               event['extra']['blocked'] is True
               for event in report['events'][str(hours[2])])
    assert not any(event['category'] == 'net'
                   for event in report['events'][str(hours[1])])
    saved = (tmp_path / 'report.json').read_text(encoding='utf-8')
    assert 'sk-proj-wake-' not in saved and 'AKIA_WAKE_' not in saved
