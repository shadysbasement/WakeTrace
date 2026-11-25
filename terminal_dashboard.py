"""Interactive terminal dashboard for WakeTrace checks and saved reports."""

import argparse
from dataclasses import dataclass, field
import math
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import termios
import time
import tty

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from dashboard_data import (capability_rows, coverage_notes, horizon_view,
                            hour_key, hour_label, safe_text, safe_target)
from dashboard_export import review_data
from lockfile import load_lockfile
from package_input import inspect as inspect_target
from java_scribe_runner import inspect_jar, next_fifteenth_horizons
from schema import load_report


PAGES = ('Overview', 'Timeline', 'Findings', 'Compare', 'Coverage', 'Check')
CATEGORIES = ('All', 'file', 'env', 'net', 'process', 'native', 'output', 'health')
CHECK_MODES = ('Candidate', 'Trusted baseline', 'Existing lock')
VERDICT_STYLES = {'CLEAN': 'green', 'WARNING': 'yellow',
                  'BLOCKED': 'red', 'INCOMPLETE': 'yellow'}


def inspect_any_target(path):
    return inspect_jar(path) if Path(path).suffix.lower() == '.jar' else inspect_target(path)


@dataclass
class CheckState:
    directory: Path = field(default_factory=Path.cwd)
    output_dir: Path = field(default_factory=lambda: Path.cwd() / 'reports' / 'terminal_checks')
    cursor: int = 0
    mode: int = 0
    candidate: Path | None = None
    baseline: Path | None = None
    lock_file: Path | None = None
    latest_report: Path | None = None
    horizons: str = '0,24,72,168'
    module: str = ''
    prompt: str = ''
    input_text: str = ''
    job: object = None


@dataclass
class State:
    page: int = 0
    hour: int = 0
    selected: int = 0
    evidence_page: int = 0
    category: int = 0
    blocked_only: bool = False
    canary_only: bool = False
    message: str = ''
    check: CheckState = field(default_factory=CheckState)


def display(value, style=None):
    """Treat report content as text, never Rich markup."""
    return Text(str(value), style=style)


def load_data(report_path, lock_path):
    report = load_report(report_path)
    if report.get('schema_version') == 'legacy':
        raise ValueError('Old report lacks trustworthy evidence. Rerun the check.')
    try:
        lock = load_lockfile(lock_path)
    except (OSError, ValueError, KeyError, TypeError):
        lock = None
    if lock and bool(lock.get('artifact')) != bool(report.get('candidate_artifact')):
        lock = None
    if lock and lock.get('java_exercise') != report.get('java_exercise'):
        lock = None
    if lock and lock.get('artifact') and report.get('baseline_artifact') and \
            lock['artifact'].get('sha256') != report['baseline_artifact'].get('sha256'):
        lock = None
    if lock and lock.get('java_artifact') and report.get('baseline_java_artifact') and \
            lock['java_artifact'].get('sha256') != report['baseline_java_artifact'].get('sha256'):
        lock = None
    return report, lock


def optional_data(report_path, lock_path):
    """An empty workspace can still open the Check page."""
    try:
        return load_data(report_path, lock_path)
    except FileNotFoundError:
        if Path(report_path).exists():
            raise
        return None, None


def parse_horizons(value):
    try:
        hours = [float(part.strip()) for part in value.split(',')]
    except ValueError as exc:
        raise ValueError('Horizons need comma-separated numbers.') from exc
    if not hours or any(not math.isfinite(hour) or hour < 0 for hour in hours):
        raise ValueError('Horizons must be finite numbers at or above zero.')
    if len(hours) != len(set(hours)):
        raise ValueError('Horizons must not repeat.')
    return [int(hour) if hour.is_integer() else hour for hour in hours]


def browser_entries(check):
    """List navigation directories and supported files, never following symlinks."""
    hidden = {'.git', '.venv', 'venv', '__pycache__', 'node_modules'}
    paths = []
    for path in check.directory.iterdir():
        if path.name in hidden or path.name.startswith('.') or path.is_symlink():
            continue
        if path.is_dir():
            paths.append(path)
        elif path.is_file() and (path.suffix == '.json' if check.mode == 2 else
                                 path.suffix in ('.py', '.whl', '.jar') or path.name.endswith('.tar.gz')):
            paths.append(path)
    return sorted(paths, key=lambda path: (not path.is_dir(), path.name.lower()))


def choose_path(state, path):
    check = state.check
    try:
        if check.mode == 2:
            lock = load_lockfile(path)
            check.lock_file = path.resolve()
            hours = sorted(set(parse_horizons(check.horizons)) | set(lock['horizons_locked']))
            check.horizons = ','.join(f'{hour:g}' for hour in hours)
            state.message = f'Lock selected: {path.name}. Lock horizons included; press H to edit.'
        else:
            info = inspect_any_target(path)
            if info['kind'] == 'java_jar' and check.horizons == '0,24,72,168':
                check.horizons = ','.join(map(str, next_fifteenth_horizons()))
            if check.mode == 0:
                check.candidate = path.resolve()
                state.message = f'Candidate selected: {path.name} ({info["kind"]}).'
            else:
                check.baseline = path.resolve()
                if info['kind'] in ('wheel', 'sdist', 'source_tree') and not check.module:
                    check.module = info['name'].replace('-', '_')
                state.message = f'Trusted baseline selected: {path.name} ({info["kind"]}).'
    except (OSError, ValueError, KeyError, TypeError) as exc:
        state.message = 'Selection failed: ' + safe_text(exc)


def check_command(state, kind):
    check = state.check
    horizons = parse_horizons(check.horizons)
    if kind == 'lock':
        if check.baseline is None:
            raise ValueError('Select a trusted baseline first (m, then Enter).')
        target = check.baseline
    else:
        if check.candidate is None or check.lock_file is None:
            raise ValueError('Select a candidate and an existing or new lock first.')
        target = check.candidate
        baseline = load_lockfile(check.lock_file)
        if bool(baseline.get('java_exercise')) != (target.suffix.lower() == '.jar'):
            raise ValueError('Candidate and lock must both use the ScribeJava JAR exercise.')
        if bool(baseline.get('artifact')) != (inspect_any_target(target)['kind'] in
                                            ('wheel', 'sdist', 'source_tree')):
            raise ValueError('Candidate and lock must both be scripts or both be packages.')
    info = inspect_any_target(target)
    stamp = f'{int(time.time())}-{time.time_ns() % 1_000_000_000:09d}'
    suffix = 'lock.json' if kind == 'lock' else 'report.json'
    output = check.output_dir / f'{target.stem}-{stamp}.{suffix}'
    command = [sys.executable, str(Path(__file__).with_name('main.py')), kind,
               str(target), '--horizons', ','.join(str(hour) for hour in horizons)]
    if kind == 'lock':
        command += ['--output', str(output)]
        if info['kind'] in ('wheel', 'sdist', 'source_tree'):
            if not check.module:
                raise ValueError('Set the package import module with i first.')
            command += ['--exercise', 'import', '--module', check.module]
        elif info['kind'] == 'java_jar':
            command += ['--exercise', 'scribejava-oauth']
    else:
        command += ['--baseline', str(check.lock_file), '--report', str(output)]
    return command, output


def start_check(state, kind):
    check = state.check
    if check.job is not None:
        state.message = 'A check is already running. Press x to cancel it.'
        return
    try:
        command, output = check_command(state, kind)
        check.output_dir.mkdir(parents=True, exist_ok=True)
        log_path = output.with_suffix('.log')
        log = log_path.open('wb')
        try:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        except Exception:
            log.close()
            log_path.unlink(missing_ok=True)
            raise
        check.job = (process, log, kind, output, log_path, time.monotonic())
        state.message = f'{kind.title()} started for {command[3]}.'
    except (OSError, ValueError, KeyError, TypeError) as exc:
        state.message = 'Cannot start: ' + safe_text(exc)


def cancel_check(state):
    job = state.check.job
    if job is None:
        return
    process, log, _, output, log_path, _ = job
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        except ProcessLookupError:
            pass
    log.close()
    log_path.unlink(missing_ok=True)
    output.unlink(missing_ok=True)
    state.check.job = None
    state.message = 'Check cancelled.'


def poll_check(state):
    """Finish a background check; return a new (report, lock) pair if verified."""
    job = state.check.job
    if job is None or job[0].poll() is None:
        return None
    process, log, kind, output, log_path, _ = job
    log.close()
    state.check.job = None
    if kind == 'lock' and process.returncode == 0:
        try:
            loaded = load_lockfile(output)
            state.check.lock_file = output
            state.check.horizons = ','.join(f'{h:g}' for h in loaded['horizons_locked'])
            state.message = f'Lock saved: {output}. Select a candidate and press v.'
            log_path.unlink(missing_ok=True)
            return None
        except (OSError, ValueError, KeyError, TypeError):
            pass
    if kind == 'verify' and output.is_file():
        try:
            report, lock = load_data(output, state.check.lock_file)
            state.page = 0
            state.check.latest_report = output
            state.hour = 0
            risky = [f['first_seen_hour'] for f in report['findings'] if (f.get('points') or 0) > 0]
            if risky:
                state.hour = report['horizons_tested'].index(min(risky))
            state.selected = 0
            state.message = f'{report["verdict"]} · report saved: {output}. Press 6 for another check.'
            log_path.unlink(missing_ok=True)
            return report, lock
        except (OSError, ValueError, KeyError, TypeError):
            pass
    state.message = f'{kind.title()} failed (exit {process.returncode}). Log: {log_path}'
    return None


def apply_prompt(state):
    check = state.check
    value = check.input_text.strip()
    try:
        if check.prompt == 'directory':
            directory = Path(value).expanduser().resolve()
            if not directory.is_dir():
                raise ValueError('Directory does not exist.')
            check.directory, check.cursor = directory, 0
        elif check.prompt == 'horizons':
            parse_horizons(value)
            check.horizons = value
        elif check.prompt == 'output':
            check.output_dir = Path(value).expanduser().resolve()
        elif check.prompt == 'module':
            from package_runner import IDENT
            if not IDENT.fullmatch(value):
                raise ValueError('Enter a Python module name, such as package_name.')
            check.module = value
        state.message = f'{check.prompt.title()} updated.'
        check.prompt = ''
        check.input_text = ''
    except (OSError, ValueError) as exc:
        state.message = safe_text(exc)


def handle_check_key(state, key):
    check = state.check
    if check.prompt:
        if key in ('\r', '\n'):
            apply_prompt(state)
        elif key == 'KEY_ESC':
            check.prompt = ''
            check.input_text = ''
            state.message = 'Input cancelled.'
        elif key in ('\x7f', '\x08'):
            check.input_text = check.input_text[:-1]
        elif len(key) == 1 and key.isprintable():
            check.input_text += key
        return
    if key == 'm':
        check.mode = (check.mode + 1) % len(CHECK_MODES)
        check.cursor = 0
    elif key in ('j', 'KEY_DOWN'):
        check.cursor = min(check.cursor + 1, max(0, len(browser_entries(check)) - 1))
    elif key in ('k', 'KEY_UP'):
        check.cursor = max(0, check.cursor - 1)
    elif key in ('KEY_PGDN', 'KEY_PGUP'):
        delta = 10 if key == 'KEY_PGDN' else -10
        check.cursor = max(0, min(check.cursor + delta, max(0, len(browser_entries(check)) - 1)))
    elif key in ('\x7f', '\x08', 'KEY_LEFT'):
        check.directory = check.directory.parent
        check.cursor = 0
    elif key in ('\r', '\n', ' ', 'KEY_RIGHT'):
        entries = browser_entries(check)
        if entries:
            path = entries[check.cursor]
            if path.is_dir() and key != ' ':
                check.directory, check.cursor = path, 0
            else:
                choose_path(state, path)
    elif key in ('d', 'H', 'o', 'i'):
        check.prompt = {'d': 'directory', 'H': 'horizons',
                        'o': 'output', 'i': 'module'}[key]
        check.input_text = str({'directory': check.directory,
                                'horizons': check.horizons,
                                'output': check.output_dir,
                                'module': check.module}[check.prompt])
    elif key == 'L':
        start_check(state, 'lock')
    elif key == 'v':
        start_check(state, 'verify')
    elif key == 'x':
        cancel_check(state)


def event_rows(report, state):
    hour = report['horizons_tested'][state.hour]
    view = horizon_view(report, hour)
    canary_ids = {item.get('event_id') for item in view['canaries']}
    rows = view['events']
    category = CATEGORIES[state.category]
    if category != 'All':
        rows = [row for row in rows if row['category'] == category]
    if state.blocked_only:
        rows = [row for row in rows if row['status'] == 'blocked']
    if state.canary_only:
        rows = [row for row in rows if row['id'] in canary_ids]
    return rows


def move_selection(state, report, delta):
    if report is None:
        return
    if state.page == 1:
        count = len(event_rows(report, state))
    elif state.page == 2:
        count = len(report['findings'])
    elif state.page == 3:
        count = 6
    else:
        return
    state.selected = max(0, min(state.selected + delta, count - 1))
    state.evidence_page = 0


def handle_key(state, report, key):
    """Apply one keyboard action. Return False when the user quits."""
    if key in ('q', '\x04', '\x03'):
        return False
    if key in ('\t', 'KEY_BTAB'):
        state.page = (state.page + (-1 if key == 'KEY_BTAB' else 1)) % len(PAGES)
        state.selected = 0
        state.evidence_page = 0
    elif key in '123456' and len(key) == 1:
        state.page = int(key) - 1
        state.selected = 0
        state.evidence_page = 0
    elif report is None:
        return True
    elif key in ('h', 'KEY_LEFT'):
        state.hour = max(0, state.hour - 1)
        state.selected = 0
    elif key in ('l', 'KEY_RIGHT'):
        state.hour = min(len(report['horizons_tested']) - 1, state.hour + 1)
        state.selected = 0
    elif key in ('j', 'KEY_DOWN'):
        move_selection(state, report, 1)
    elif key in ('k', 'KEY_UP'):
        move_selection(state, report, -1)
    elif key == 'KEY_PGDN':
        move_selection(state, report, 10)
    elif key == 'KEY_PGUP':
        move_selection(state, report, -10)
    elif key == 'c':
        state.category = (state.category + 1) % len(CATEGORIES)
        state.selected = 0
    elif key == 'b':
        state.blocked_only = not state.blocked_only
        state.selected = 0
    elif key == 'n':
        state.canary_only = not state.canary_only
        state.selected = 0
    elif key in ('[', ']') and state.page == 2 and report['findings']:
        refs = report['findings'][state.selected]['evidence_ids']
        last = max(0, (len(refs) - 1) // 4)
        state.evidence_page = max(0, min(state.evidence_page + (1 if key == ']' else -1), last))
    return True


def overview(report, lock):
    verdict = report['verdict']
    score = ('not conclusive' if verdict == 'INCOMPLETE' else
             f"{report['risk_score']:g} / 100")
    first = [f['first_seen_hour'] for f in report['findings'] if (f.get('points') or 0) > 0]
    complete = sum(bool(item.get('complete')) for item in report['run_health'].values())
    summary = Table.grid(padding=(0, 3), expand=True)
    summary.add_column(ratio=1)
    summary.add_column(ratio=1)
    summary.add_row(display(f"Verdict  {verdict}", VERDICT_STYLES[verdict]),
                    display(f'Risk score  {score}'))
    summary.add_row(display('First risky observation  ' +
                            (hour_label(min(first)) if first else 'not observed')),
                    display(f"Coverage  {complete}/{len(report['horizons_tested'])} complete"))
    summary.add_row(display(f"Findings  {len(report['findings'])}"),
                    display('Execution  ' + safe_text(report.get('execution_backend'))))
    summary.add_row(display('Target  ' + safe_text(report.get('target_script'))),
                    display('Baseline  ' + ('loaded' if lock else 'unavailable')))
    chart = Table(title='Risk across tested horizons', expand=True, show_header=True)
    for name in ('Horizon', 'Run', 'Risk', 'New', 'Events'):
        chart.add_column(name, no_wrap=name != 'Risk')
    for hour in report['horizons_tested']:
        key = hour_key(hour)
        health = report['run_health'][key]
        breakdown = (report.get('horizon_breakdown') or {}).get(key) or {}
        risk = breakdown.get('risk_score') if isinstance(breakdown, dict) else None
        if isinstance(risk, bool) or not isinstance(risk, (int, float)) or not math.isfinite(risk):
            risk = None
        bar = 'observed only' if risk is None else f"{risk:>5g}  {'█' * round(max(0, min(100, risk)) / 5)}"
        new = sum(f.get('first_seen_hour') == hour for f in report['findings'])
        chart.add_row(display(hour_label(hour)),
                      display('complete' if health.get('complete') else 'incomplete',
                              'green' if health.get('complete') else 'yellow'),
                      display(bar, 'red' if risk and risk >= 40 else 'yellow' if risk else 'green'),
                      display(new), display(len(report['events'][key])))
    note = ('First observed is the first tested horizon with evidence, not the exact activation time. '
            'An incomplete horizon cannot support a clean conclusion.')
    return Group(Panel(summary, title='Result', border_style=VERDICT_STYLES[verdict]),
                 chart, display(note, 'dim'))


def timeline(report, state, height):
    hour = report['horizons_tested'][state.hour]
    view = horizon_view(report, hour)
    health = view['health']
    rows = event_rows(report, state)
    state.selected = max(0, min(state.selected, len(rows) - 1))
    page_size = max(3, height - 21)
    start = (state.selected // page_size) * page_size
    table = Table(title=f"Events at {hour_label(hour)}  ·  {len(rows)}/{len(view['events'])} shown",
                  expand=True)
    for name in ('#', 'Category', 'Action', 'Target', 'Status'):
        table.add_column(name, overflow='ellipsis', no_wrap=True)
    for i, row in enumerate(rows[start:start + page_size], start):
        style = 'bold cyan' if i == state.selected else None
        table.add_row(display(row['id'], style), display(row['category'], style),
                      display(row['action'], style), display(row['target'], style),
                      display(row['status'], 'red' if row['status'] == 'blocked' else style))
    if not rows:
        table.add_row('', '', '', 'No events match the current filters.', '')
    header = (f"Run {'complete' if health.get('complete') else 'incomplete'} · "
              f"stage {safe_text(health.get('stage'))} · "
              f"new findings {len(view['new'])} · active {len(view['active'])}")
    filters = (f"Category {CATEGORIES[state.category]} · "
               f"blocked {'on' if state.blocked_only else 'off'} · "
               f"canary {'on' if state.canary_only else 'off'}")
    if rows:
        row = rows[state.selected]
        detail = (f"Event #{row['id']} · {row['hour']} · {row['category']}/{row['action']} · "
                  f"{row['status']}\nTarget  {row['target']}\nSource  {row['source']}\n"
                  f"Real  {row['real time']}    Warped  {row['warped time']}")
    else:
        detail = 'Select another filter or horizon to inspect events.'
    return Group(display(header), display(filters, 'dim'), table,
                 Panel(display(detail), title='Selected evidence'),
                 display('Network status records an attempt; delivery is unconfirmed.', 'dim'))


def findings(report, state, height):
    data = review_data(report)
    rows = data['findings']
    state.selected = max(0, min(state.selected, len(rows) - 1))
    page_size = max(3, height - 21)
    start = (state.selected // page_size) * page_size
    table = Table(title=f'Findings  ·  {len(rows)} total', expand=True)
    for name in ('#', 'Severity', 'Category', 'Item', 'First', 'Points'):
        table.add_column(name, overflow='ellipsis', no_wrap=True)
    for i, row in enumerate(rows[start:start + page_size], start):
        style = 'bold cyan' if i == state.selected else None
        table.add_row(display(i + 1, style), display(row['severity'], style),
                      display(row['category'], style), display(row['item'], style),
                      display(row['first_observed'], style), display(row['points'], style))
    if not rows:
        table.add_row('', '', '', 'No findings recorded.', '', '')
        detail = 'No findings were recorded on the exercised paths.'
    else:
        row = rows[state.selected]
        original = report['findings'][state.selected]
        seen = ', '.join(hour_label(h) for h in original.get('seen_at_hours', []))
        evidence = row['evidence']
        last = max(0, (len(evidence) - 1) // 4)
        state.evidence_page = min(state.evidence_page, last)
        start_ref = state.evidence_page * 4
        refs = '\n'.join(f"{e['hour']} #{e['event_id']} {e['action']} · {e['target']} · "
                         f"{e['status']} · {e['source']}"
                         f"{':' + str(e['line']) if e['line'] else ''}"
                         for e in evidence[start_ref:start_ref + 4])
        evidence_label = (f"Evidence {start_ref + 1}–{min(start_ref + 4, len(evidence))} "
                          f"of {len(evidence)}  ·  [ / ] to browse" if evidence else 'Evidence')
        detail = (f"{row['severity']} · {row['rule']} · first {row['first_observed']} · "
                  f"seen {seen}\nScore  {row['base_points']} × {row['multiplier']} = "
                  f"{row['points']}\nChange  {row['change']}\n"
                  f"{evidence_label}\n{refs or 'No event references supplied.'}")
        if row.get('canary_channel'):
            detail += (f"\nCanary  {row['canary_channel']} · "
                       f"{row.get('canary_stage') or 'unknown'}")
    return Group(table, Panel(display(detail), title='Selected finding'),
                 display('Source preview is withheld; local source may have changed.', 'dim'))


def comparison(report, lock, state):
    if lock is None:
        return Panel(display('Lockfile unavailable. Supply --lock to compare observed capabilities.'),
                     title='Baseline comparison')
    rows = capability_rows(report, lock)
    state.selected = max(0, min(state.selected, len(rows) - 1))
    table = Table(title='Observed capability changes', expand=True)
    table.add_column('Capability', no_wrap=True, min_width=21)
    table.add_column('Added', overflow='ellipsis', no_wrap=True)
    for i, row in enumerate(rows):
        style = 'bold cyan' if i == state.selected else None
        table.add_row(display(row['category'], style), display(row['added'], style))
    row = rows[state.selected]
    detail = (f"Baseline   {row['baseline observed']}\n"
              f"Candidate  {row['candidate observed']}\n"
              f"Added      {row['added']}")
    return Group(table, Panel(display(detail), title=row['category']),
                 display('Only exercised paths were observed.', 'dim'))


def coverage(report, lock):
    table = Table(title='Run coverage', expand=True)
    for name in ('Horizon', 'Complete', 'Stage', 'Reason', 'Network isolated'):
        table.add_column(name, overflow='ellipsis')
    for hour in report['horizons_tested']:
        health = report['run_health'][hour_key(hour)]
        table.add_row(display(hour_label(hour)), display('yes' if health['complete'] else 'no'),
                      display(safe_text(health.get('stage'))),
                      display(safe_text(health.get('reason')) if health.get('reason') else '—'),
                      display('yes' if health.get('network_isolated') else 'no'))
    notes = '\n'.join('• ' + note for note in coverage_notes(report, lock))
    notes += '\n• A blocked or prepared network request is an attempt; transmission is unconfirmed.'
    return Group(table, Panel(display(notes), title='Limits and comparability'))


def check_page(state, height):
    check = state.check
    entries = browser_entries(check)
    check.cursor = max(0, min(check.cursor, len(entries) - 1))
    table = Table(title=f'{CHECK_MODES[check.mode]} · {check.directory}', expand=True)
    table.add_column('', width=2)
    table.add_column('Name', overflow='ellipsis')
    table.add_column('Type', width=12)
    page_size = max(4, height - 21)
    start = check.cursor // page_size * page_size
    for index, path in enumerate(entries[start:start + page_size], start):
        selected = index == check.cursor
        kind = ('source dir' if (path / 'pyproject.toml').is_file() or
                (path / '__main__.py').is_file() else 'directory') if path.is_dir() else \
               ('lock' if check.mode == 2 else 'file')
        table.add_row('›' if selected else '', display(path.name, 'bold cyan' if selected else None), kind)
    if not entries:
        table.add_row('', 'No matching files here. Use d to enter another directory.', '')
    selected = Table.grid(padding=(0, 2), expand=True)
    selected.add_column(width=17)
    selected.add_column(ratio=1)
    selected.add_row('Candidate', display(check.candidate or 'choose in Candidate mode'))
    selected.add_row('Trusted baseline', display(check.baseline or 'choose only a version you trust'))
    selected.add_row('Lockfile', display(check.lock_file or 'select a lock or press L'))
    selected.add_row('Horizons', display(check.horizons + ' hours'))
    selected.add_row('Package module', display(check.module or 'set with i for package locks'))
    selected.add_row('Output', display(check.output_dir))
    if check.job:
        process, _, kind, _, _, started = check.job
        elapsed = time.monotonic() - started
        status = f'{kind.title()} running · {elapsed:.1f}s elapsed · press x to cancel'
    else:
        status = 'Ready. Verify runs each selected horizon inside WakeTrace containment.'
    return Group(Panel(selected, title='Check setup'), table, display(status, 'yellow'))


def render(report, lock, state, height):
    hour = hour_label(report['horizons_tested'][state.hour]) if report else 'No report yet'
    title = Text(' WAKE / TRACE ', style='bold white on blue')
    title.append('   Behavioral time horizon inspector', style='bold')
    nav = Text('  '.join(f"{i + 1} {name}" for i, name in enumerate(PAGES)), style='dim')
    nav.append(f'   {hour}', style='cyan')
    if state.page == 5:
        body = check_page(state, height)
    elif report is None:
        body = Panel(display('No saved report found. Press 6 to choose a candidate and run a check.'),
                     title='Start here')
    elif state.page == 0:
        body = overview(report, lock)
    elif state.page == 1:
        body = timeline(report, state, height)
    elif state.page == 2:
        body = findings(report, state, height)
    elif state.page == 3:
        body = comparison(report, lock, state)
    else:
        body = coverage(report, lock)
    controls = ('1–6 page  Tab next  ←/→ horizon  ↑/↓ select  c category  b blocked  '
                'n canary  [/] evidence  r reload  q quit')
    if state.page == 5:
        controls = ('m mode  ↑/↓ browse  Enter open/select  Space select folder  Backspace parent  '
                    'd directory  H hours  o output  i module  L lock  v verify  x cancel  q quit')
    footer = Text(controls, style='reverse')
    if state.check.prompt:
        footer.append(f'\n{state.check.prompt}> {state.check.input_text}▌', style='bold cyan')
    if state.message:
        footer.append('\n' + state.message, style='yellow')
    return Group(title, nav, body, footer)


def read_key(fd):
    if not select.select([fd], [], [], 0.25)[0]:
        return None
    first = os.read(fd, 1)
    if first != b'\x1b':
        if first[0] < 128:
            return first.decode('utf-8')
        data = first
        for _ in range(3):
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                if not select.select([fd], [], [], 0.02)[0]:
                    return ''
                data += os.read(fd, 1)
        return data.decode('utf-8', errors='ignore')
    if not select.select([fd], [], [], 0.02)[0] or os.read(fd, 1) != b'[':
        return 'KEY_ESC'
    if not select.select([fd], [], [], 0.02)[0]:
        return ''
    direction = os.read(fd, 1)
    if direction in (b'5', b'6'):
        if select.select([fd], [], [], 0.02)[0] and os.read(fd, 1) == b'~':
            return 'KEY_PGUP' if direction == b'5' else 'KEY_PGDN'
        return ''
    return {b'A': 'KEY_UP', b'B': 'KEY_DOWN', b'C': 'KEY_RIGHT',
            b'D': 'KEY_LEFT', b'Z': 'KEY_BTAB'}.get(direction, '')


def run(report_path, lock_path, state, once=False):
    report, lock = optional_data(report_path, lock_path)
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        once = True
    console = Console(force_terminal=not once, color_system=None if once else 'auto')
    if once:
        console.print(render(report, lock, state, console.height))
        return 0
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        with Live(render(report, lock, state, console.height),
                  console=console, screen=True, auto_refresh=False) as live:
            size = console.size
            while True:
                key = read_key(fd)
                completed = poll_check(state)
                if completed is not None:
                    report, lock = completed
                if state.page == 5 and state.check.prompt and key:
                    handle_check_key(state, key)
                elif key == 'r' and state.page != 5:
                    try:
                        active_path = state.check.latest_report or report_path
                        report, lock = load_data(active_path, state.check.lock_file or lock_path)
                        state.hour = min(state.hour, len(report['horizons_tested']) - 1)
                        state.selected = 0
                        state.evidence_page = 0
                        state.message = 'Report reloaded.'
                    except (OSError, ValueError, KeyError, TypeError) as exc:
                        state.message = 'Reload failed: ' + safe_text(exc)
                elif key:
                    if key in ('\t', 'KEY_BTAB', '1', '2', '3', '4', '5', '6',
                               'q', '\x04', '\x03'):
                        if not handle_key(state, report, key):
                            cancel_check(state)
                            break
                    elif state.page == 5:
                        handle_check_key(state, key)
                    elif not handle_key(state, report, key):
                        cancel_check(state)
                        break
                if key or completed is not None or state.check.job or console.size != size:
                    size = console.size
                    live.update(render(report, lock, state, console.height), refresh=True)
    finally:
        cancel_check(state)
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description='Browse targets, run checks, and inspect WakeTrace reports')
    parser.add_argument('--report', type=Path, default=Path('reports/latest_report.json'))
    parser.add_argument('--lock', type=Path, default=Path('behavior.lock.json'))
    parser.add_argument('--page', choices=[name.lower() for name in PAGES])
    parser.add_argument('--hour', type=float, help='initial tested horizon in hours')
    parser.add_argument('--directory', type=Path, default=Path.cwd(), help='start browsing here')
    parser.add_argument('--output-dir', type=Path, default=Path.cwd() / 'reports' / 'terminal_checks')
    parser.add_argument('--once', action='store_true', help='print one screen and exit')
    args = parser.parse_args(argv)
    try:
        report, _ = optional_data(args.report, args.lock)
        page = args.page or ('overview' if report else 'check')
        state = State(page=[name.lower() for name in PAGES].index(page))
        state.check.directory = args.directory.expanduser().resolve()
        if not state.check.directory.is_dir():
            raise ValueError('--directory must be an existing directory')
        state.check.output_dir = args.output_dir.expanduser().resolve()
        try:
            saved_lock = load_lockfile(args.lock)
            state.check.lock_file = args.lock.expanduser().resolve()
            hours = sorted(set(parse_horizons(state.check.horizons)) |
                           set(saved_lock['horizons_locked']))
            state.check.horizons = ','.join(f'{h:g}' for h in hours)
        except (OSError, ValueError, KeyError, TypeError):
            pass
        if report:
            risky = [finding['first_seen_hour'] for finding in report['findings']
                     if (finding.get('points') or 0) > 0]
            if risky:
                state.hour = report['horizons_tested'].index(min(risky))
        if args.hour is not None:
            if report is None or args.hour not in report['horizons_tested']:
                raise ValueError('--hour must be one of the tested horizons: ' +
                                 ', '.join(hour_label(h) for h in
                                           (report['horizons_tested'] if report else [])))
            state.hour = report['horizons_tested'].index(args.hour)
        return run(args.report, args.lock, state, once=args.once)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('WakeTrace terminal error: ' + safe_text(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
