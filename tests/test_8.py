import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dashboard_data import (capability_rows, coverage_notes, filter_events, horizon_view, linked_events,
                            safe_text)
from dashboard_export import review_data, review_html, review_json
from schema import load_report, validate_report

DEMO = json.loads((ROOT / 'tests/fixtures/phase8/latest_report.json').read_text())
LOCK = json.loads((ROOT / 'tests/fixtures/phase8/behavior.lock.json').read_text())


class Phase8Tests(unittest.TestCase):
    def test_horizon_events_and_findings(self):
        early = horizon_view(DEMO, 0)
        late = horizon_view(DEMO, 72)
        self.assertEqual(len(early['new']), 0)
        self.assertGreater(len(late['new']), 0)
        self.assertEqual(len(early['events']), 7)
        self.assertEqual(len(late['events']), 13)
        finding = next(f for f in DEMO['findings'] if f['rule'] == 'canary_network_attempt')
        rows = linked_events(DEMO, finding)
        self.assertEqual([(r['hour'], r['id']) for r in rows], [('+72h', 11), ('+168h', 11)])
        self.assertTrue(all(r['status'] == 'blocked' for r in rows))
        self.assertEqual(rows[0]['source'], '<PROJECT>/trojan_v2.py:30 · <module>')
        self.assertIn('source unknown', early['events'][0]['source'])

    def test_filters_do_not_change_verdict(self):
        rows = horizon_view(DEMO, 72)['events']
        self.assertEqual(len(filter_events(rows, 'net', 'blocked')), 1)
        self.assertEqual(len(filter_events(rows, 'file', 'blocked')), 0)
        self.assertEqual(DEMO['verdict'], 'BLOCKED')

    def test_states_and_partial_evidence(self):
        clean = copy.deepcopy(DEMO)
        clean['findings'] = []
        clean['risk_score'] = 0
        clean['verdict'] = 'CLEAN'
        validate_report(clean)
        self.assertEqual(horizon_view(clean, 0)['new'], [])
        warning = copy.deepcopy(DEMO)
        warning['verdict'] = 'WARNING'
        validate_report(warning)
        incomplete = copy.deepcopy(DEMO)
        incomplete['verdict'] = 'INCOMPLETE'
        incomplete['run_health']['72'] = {'complete': False, 'stage': 'trace',
                                          'reason': 'hook missing', 'network_isolated': True}
        incomplete['horizon_breakdown'].pop('72')
        validate_report(incomplete)
        self.assertEqual(len(horizon_view(incomplete, 72)['events']), 13)
        self.assertIn('incomplete', ' '.join(coverage_notes(incomplete, LOCK)))
        self.assertIsNone(review_data(incomplete, LOCK)['risk_score'])
        old_lock = copy.deepcopy(LOCK)
        old_lock['schema_version'] = '1.0'
        old_lock.pop('capabilities_by_horizon')
        self.assertIn('Old lock:', ' '.join(coverage_notes(warning, old_lock)))

    def test_legacy_and_bad_report_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'report.json'
            file.write_text(json.dumps({'verdict': 'CLEAN', 'secret': 'RAW_SECRET'}))
            legacy = load_report(file)
            self.assertEqual(legacy['verdict'], 'INCOMPLETE')
            self.assertNotIn('RAW_SECRET', review_json(review_data(legacy)))
            file.write_text('{bad')
            with self.assertRaises(ValueError):
                load_report(file)
            file.write_text(json.dumps({'schema_version': '9.0'}))
            with self.assertRaises(ValueError):
                load_report(file)
            file.unlink()
            with self.assertRaises(OSError):
                load_report(file)

    def test_malformed_valid_version_is_rejected(self):
        bad = copy.deepcopy(DEMO)
        bad['events']['72'][0]['extra'] = 'not a map'
        with self.assertRaisesRegex(ValueError, 'event detail'):
            validate_report(bad)
        bad = copy.deepcopy(DEMO)
        bad['findings'][0]['first_seen_hour'] = ['72']
        with self.assertRaisesRegex(ValueError, 'finding horizons'):
            validate_report(bad)

    def test_redacted_exports(self):
        report = copy.deepcopy(DEMO)
        report['events']['72'][10]['target'] = 'https://user:pass@example.com/path?token=RAW_SECRET'
        report['events']['72'][10]['extra']['payload'] = 'RAW_SECRET'
        report['events']['72'][10]['source']['path'] = '/home/alice/private.py'
        report['findings'][0]['reason'] = '<script>RAW_SECRET</script>'
        report['findings'][0]['item'] = 'AKIA_WAKE_123456abcdef'
        report['target_script'] = '<script>alert(1)</script>'
        data = review_data(report, LOCK)
        html = review_html(data)
        machine = review_json(data)
        for content in (html, machine):
            self.assertNotIn('RAW_SECRET', content)
            self.assertNotIn('AKIA_WAKE_123456abcdef', content)
            self.assertNotIn('/home/alice', content)
            self.assertNotIn('user:pass', content)
            self.assertNotIn('<script>', content)
            self.assertIn('BLOCKED', content)
        self.assertIn('attempt', html.lower())
        self.assertNotIn('confirmed transmission', html.lower())
        self.assertIn('<private path>', safe_text('/home/alice/x.py'))

    def test_package_identity_and_capability_comparison(self):
        report = copy.deepcopy(DEMO)
        report['candidate_artifact'] = {'name': 'sample-pkg', 'version': '2.0',
                                        'kind': 'wheel', 'sha256': 'a' * 64}
        report['baseline_artifact'] = {'name': 'sample-pkg', 'version': '1.0',
                                       'kind': 'wheel', 'sha256': 'b' * 64}
        lock = copy.deepcopy(LOCK)
        lock['artifact'] = {'name': 'sample-pkg', 'version': '1.0',
                            'kind': 'wheel', 'sha256': 'b' * 64}
        data = review_data(report, lock)
        self.assertEqual(data['candidate_artifact']['version'], '2.0')
        self.assertEqual(data['baseline_artifact']['version'], '1.0')
        rows = capability_rows(report, lock)
        network = next(row for row in rows if row['category'] == 'network_hosts')
        self.assertEqual(network['added'], '93.184.216.34')

    def test_apptest_pages_and_no_implicit_run(self):
        from streamlit.testing.v1 import AppTest
        with (patch('runner.run_multi_horizon', side_effect=AssertionError('runner invoked')),
              patch('package_runner.run_package_horizons', side_effect=AssertionError('runner invoked'))):
            at = AppTest.from_file(str(ROOT / 'dashboard.py'), default_timeout=15).run()
            at.text_input[0].set_value(str(ROOT / 'tests/fixtures/phase8/latest_report.json'))
            at.text_input[1].set_value(str(ROOT / 'tests/fixtures/phase8/behavior.lock.json')).run()
            self.assertFalse(at.exception)
            self.assertEqual(at.select_slider[0].value, 72)
            at.select_slider[0].set_value(0).run()
            at.radio[0].set_value('Investigation').run()
            self.assertFalse(at.exception)
            self.assertTrue(any('0 of' not in x.value for x in at.markdown))
            at.select_slider[0].set_value(72).run()
            self.assertFalse(at.exception)
            at.radio[0].set_value('Mechanism').run()
            self.assertFalse(at.exception)
            at.radio[0].set_value('Compare').run()
            self.assertFalse(at.exception)
            at.radio[0].set_value('Export').run()
            self.assertEqual(len(at.download_button), 2)
            self.assertFalse(at.exception)

    def test_apptest_saved_report_states(self):
        from streamlit.testing.v1 import AppTest
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'review.json'
            at = AppTest.from_file(str(ROOT / 'dashboard.py'), default_timeout=15).run()
            clean = copy.deepcopy(DEMO)
            clean.update(verdict='CLEAN', findings=[], risk_score=0)
            path.write_text(json.dumps(clean))
            at.text_input[0].set_value(str(path)).run()
            self.assertFalse(at.exception)
            self.assertTrue(at.success)
            incomplete = copy.deepcopy(DEMO)
            incomplete['verdict'] = 'INCOMPLETE'
            incomplete['run_health']['72']['complete'] = False
            incomplete['run_health']['72']['stage'] = 'trace'
            incomplete['run_health']['72']['reason'] = 'hook missing'
            incomplete['horizon_breakdown'] = {}
            path.write_text(json.dumps(incomplete))
            at.run()
            self.assertFalse(at.exception)
            self.assertTrue(at.info)
            at.radio[0].set_value('Investigation').run()
            self.assertFalse(at.exception)
            path.write_text(json.dumps({'verdict': 'CLEAN', 'secret': 'RAW_SECRET'}))
            at.run()
            self.assertFalse(at.exception)
            self.assertEqual(len(at.download_button), 1)
            path.write_text('{bad')
            at.run()
            self.assertTrue(at.error)
            self.assertFalse(at.exception)
            path.write_text(json.dumps({'schema_version': '9.0'}))
            at.run()
            self.assertTrue(at.error)
            path.unlink()
            at.run()
            self.assertTrue(at.error)


if __name__ == '__main__':
    unittest.main()
