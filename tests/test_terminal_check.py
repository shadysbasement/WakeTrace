"""The terminal picker can launch contained checks and open their reports."""

from io import StringIO
from pathlib import Path
import subprocess
import sys
import time

from rich.console import Console

from terminal_dashboard import (State, browser_entries, choose_path,
                                handle_check_key, optional_data, poll_check,
                                render)
from main import main


ROOT = Path(__file__).resolve().parents[1]


def _wait_for_job(state):
    deadline = time.monotonic() + 45
    while state.check.job is not None and time.monotonic() < deadline:
        result = poll_check(state)
        if result is not None:
            return result
        time.sleep(0.05)
    assert state.check.job is None, 'contained check did not finish'
    return None


def test_empty_workspace_opens_picker_and_selects_files(tmp_path, capsys):
    baseline = tmp_path / 'baseline.py'
    candidate = tmp_path / 'candidate.py'
    baseline.write_text('print("safe")\n')
    candidate.write_text('print("candidate")\n')
    report, lock = optional_data(tmp_path / 'missing.json', tmp_path / 'missing-lock.json')
    assert report is lock is None
    state = State(page=5)
    state.check.directory = tmp_path
    output = StringIO()
    Console(file=output, width=100, color_system=None).print(render(None, None, state, 35))
    assert 'Candidate' in output.getvalue()
    assert 'baseline.py' in output.getvalue()
    assert [path.name for path in browser_entries(state.check)] == ['baseline.py', 'candidate.py']
    handle_check_key(state, 'j')
    handle_check_key(state, '\n')
    assert state.check.candidate == candidate
    handle_check_key(state, 'm')
    handle_check_key(state, '\n')
    assert state.check.baseline == baseline
    handle_check_key(state, 'H')
    state.check.input_text = '0,72'
    handle_check_key(state, '\n')
    assert state.check.horizons == '0,72'
    assert main(['terminal', '--once', '--report', str(tmp_path / 'missing.json'),
                 '--lock', str(tmp_path / 'missing-lock.json'),
                 '--directory', str(tmp_path)]) == 0
    assert '6 Check' in capsys.readouterr().out


def test_terminal_creates_lock_and_verifies_candidate_without_overwriting_report(tmp_path):
    state = State(page=5)
    state.check.directory = ROOT / 'examples'
    state.check.output_dir = tmp_path / 'checks'
    state.check.horizons = '0'
    state.check.baseline = ROOT / 'examples' / 'baseline.py'
    state.check.candidate = ROOT / 'examples' / 'candidate.py'
    existing = tmp_path / 'latest_report.json'
    existing.write_text('leave me alone')

    handle_check_key(state, 'L')
    assert state.check.job is not None
    assert _wait_for_job(state) is None
    assert state.check.lock_file is not None
    assert state.check.lock_file.is_file()
    assert state.check.horizons == '0'

    handle_check_key(state, 'v')
    assert state.check.job is not None
    report, lock = _wait_for_job(state)
    assert report['verdict'] == 'CLEAN'
    assert lock is not None
    assert state.page == 0
    assert state.check.latest_report.is_file()
    assert existing.read_text() == 'leave me alone'
    assert not list(state.check.output_dir.glob('*.log'))


def test_existing_lock_sets_tested_horizons():
    state = State(page=5)
    state.check.mode = 2
    choose_path(state, ROOT / 'tests/fixtures/phase8/behavior.lock.json')
    assert state.check.lock_file is not None
    assert state.check.horizons == '0,24,72,168'


def test_cancel_key_stops_a_running_job(tmp_path):
    state = State(page=5)
    output = tmp_path / 'result.json'
    log_path = tmp_path / 'result.log'
    log = log_path.open('wb')
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                               stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    state.check.job = (process, log, 'verify', output, log_path, time.monotonic())
    handle_check_key(state, 'x')
    assert state.check.job is None
    assert process.poll() is not None
    assert not log_path.exists()
