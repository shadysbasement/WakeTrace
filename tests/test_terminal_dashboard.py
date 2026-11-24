"""Terminal report review stays read-only and keeps evidence redacted."""

from io import StringIO
import copy
import json
import os
from pathlib import Path
import pty
import termios
import tty

from rich.console import Console

from terminal_dashboard import (CATEGORIES, State, event_rows, handle_key,
                                load_data, read_key, render)
from main import main


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / 'tests/fixtures/phase8/latest_report.json'
LOCK = ROOT / 'tests/fixtures/phase8/behavior.lock.json'


def snapshot(report, lock, state):
    output = StringIO()
    console = Console(file=output, width=100, height=36, color_system=None)
    console.print(render(report, lock, state, console.height))
    return output.getvalue()


def test_terminal_pages_and_evidence_navigation():
    report, lock = load_data(REPORT, LOCK)
    state = State()
    assert 'Risk across tested horizons' in snapshot(report, lock, state)
    assert handle_key(state, report, '2')
    assert handle_key(state, report, 'KEY_RIGHT')
    assert handle_key(state, report, 'KEY_RIGHT')
    assert state.hour == 2
    assert 'Events at +72h' in snapshot(report, lock, state)
    assert handle_key(state, report, 'c')
    assert CATEGORIES[state.category] == 'file'
    assert len(event_rows(report, state)) < len(report['events']['72'])
    assert handle_key(state, report, '3')
    assert handle_key(state, report, 'j')
    assert 'Selected finding' in snapshot(report, lock, state)
    assert handle_key(state, report, '4')
    assert handle_key(state, report, 'j')
    assert 'Baseline' in snapshot(report, lock, state)
    assert handle_key(state, report, '5')
    assert 'Limits and comparability' in snapshot(report, lock, state)
    assert not handle_key(state, report, 'q')


def test_terminal_redacts_report_content_and_rejects_invalid_report(tmp_path):
    report = json.loads(REPORT.read_text())
    report['events']['72'][10]['target'] = 'https://user:pass@example.com/private?token=RAW_SECRET'
    report['events']['72'][10]['source']['path'] = '/home/alice/private.py'
    report['findings'][0]['item'] = 'AKIA_WAKE_123456abcdef'
    report['target_script'] = '/home/alice/private.py'
    report_path = tmp_path / 'report.json'
    report_path.write_text(json.dumps(report))
    loaded, lock = load_data(report_path, LOCK)
    output = '\n'.join(snapshot(loaded, lock, State(page=page, hour=2)) for page in range(5))
    assert 'RAW_SECRET' not in output
    assert 'user:pass' not in output
    assert '/home/alice' not in output
    assert 'AKIA_WAKE_123456abcdef' not in output
    assert '<redacted>' in output
    report_path.write_text('{bad')
    try:
        load_data(report_path, LOCK)
    except ValueError:
        pass
    else:
        raise AssertionError('malformed report was accepted')


def test_terminal_cli_reads_saved_report_without_running_target(capsys, monkeypatch):
    import runner
    import package_runner

    def forbidden(*args, **kwargs):
        raise AssertionError('runner invoked')

    monkeypatch.setattr(runner, 'run_multi_horizon', forbidden)
    monkeypatch.setattr(package_runner, 'run_package_horizons', forbidden)
    code = main(['terminal', '--once', '--page', 'findings', '--hour', '72',
                 '--report', str(REPORT), '--lock', str(LOCK)])
    output = capsys.readouterr().out
    assert code == 0
    assert 'Findings' in output
    assert 'Evidence' in output
    assert '+72h' in output


def test_terminal_arrow_keys_do_not_consume_following_input():
    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    try:
        tty.setcbreak(slave)
        os.write(master, b'\x1b[Cj')
        assert read_key(slave) == 'KEY_RIGHT'
        assert read_key(slave) == 'j'
    finally:
        termios.tcsetattr(slave, termios.TCSADRAIN, original)
        os.close(master)
        os.close(slave)


def test_terminal_can_page_through_all_linked_evidence():
    report, lock = load_data(REPORT, LOCK)
    report = copy.deepcopy(report)
    report['findings'][0]['evidence_ids'] = [
        {'horizon': 72, 'event_id': number} for number in range(1, 7)]
    state = State(page=2)
    first = snapshot(report, lock, state)
    assert 'Evidence 1–4 of 6' in first
    assert '+72h #1' in first
    assert handle_key(state, report, ']')
    second = snapshot(report, lock, state)
    assert 'Evidence 5–6 of 6' in second
    assert '+72h #5' in second
    assert '+72h #1' not in second
