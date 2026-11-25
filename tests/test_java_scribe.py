"""Exercise the original date-gated ScribeJava JAR, not an adaptation."""

from pathlib import Path
import shutil

import pytest

from demo_pkgs.scribejava.run_demo import HASHES, run
from isolation import preflight
from java_scribe_runner import _compiler, inspect_jar
from terminal_dashboard import CheckState, State, browser_entries, check_command, load_data


ROOT = Path(__file__).resolve().parents[1]
JARS = ROOT / 'demo_pkgs' / 'scribejava'


def test_original_jar_metadata_and_terminal_selection():
    clean = JARS / 'scribejava-core-8.3.3.jar'
    malicious = JARS / 'scribejava-core-8.3.5.jar'
    assert inspect_jar(clean)['sha256'] == HASHES['8.3.3']
    assert inspect_jar(malicious)['sha256'] == HASHES['8.3.5']
    assert inspect_jar(malicious)['group'] == 'io.github.leetcrunch'
    state = State(check=CheckState(directory=JARS, baseline=clean))
    assert clean in browser_entries(state.check)
    assert malicious in browser_entries(state.check)
    command, _ = check_command(state, 'lock')
    assert command[-2:] == ['--exercise', 'scribejava-oauth']


def test_real_jar_date_gate_is_detected(tmp_path):
    if not shutil.which('cc') or not shutil.which('java'):
        pytest.skip('Java exercise toolchain is unavailable')
    try:
        _compiler()
    except FileNotFoundError:
        pytest.skip('Java compiler is unavailable')
    try:
        preflight()
    except (OSError, ValueError) as exc:
        pytest.skip(f'Bubblewrap unavailable: {exc}')
    report, hours = run(tmp_path)
    trigger = str(hours[2])
    assert report['candidate_java_artifact']['sha256'] == HASHES['8.3.5']
    assert report['baseline_java_artifact']['sha256'] == HASHES['8.3.3']
    assert report['horizon_breakdown'][trigger]['activity']['network_attempts'] == [
        {'target': 'pastebin.com', 'blocked': True}]
    assert report['horizon_breakdown'][trigger]['risk_score'] == 100
    assert report['events'][trigger][0]['extra']['audit_event'] == 'java_http_client_proxy'
    assert report['transmission_status'] == 'unknown'
    assert 'WT_FAKE_KEY_123456' not in (tmp_path / 'report.json').read_text()
    assert 'WT_FAKE_SECRET_123456' not in (tmp_path / 'report.json').read_text()
    loaded, lock = load_data(tmp_path / 'report.json', tmp_path / 'behavior.lock.json')
    assert loaded['verdict'] == 'BLOCKED' and lock['java_exercise'] == 'scribejava-oauth-sign'
    state = State(check=CheckState(directory=JARS,
                                   candidate=JARS / 'scribejava-core-8.3.5.jar',
                                   lock_file=tmp_path / 'behavior.lock.json'))
    command, _ = check_command(state, 'verify')
    assert str(state.check.candidate) in command
