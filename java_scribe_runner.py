"""Contained, purpose-built exercise of ScribeJava core JARs.

The original JAR is loaded only inside Bubblewrap. A trusted HttpClient proxy
records and blocks prepared requests, while an LD_PRELOAD clock shim advances
Java's wall clock. This is an exercised-path detector, not a general Java tracer.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import zipfile

from isolation import _base_command, limits, preflight, process_quota, stop_tree
from runner import _risk_actions


EXERCISE = 'scribejava-oauth-sign'
MARKERS = ('WT_FAKE_API_KEY', 'WT_FAKE_API_SECRET')
CORE_CLASS = 'com/github/scribejava/core/oauth/OAuth20Service.class'
MAX_JAR_BYTES = 8 * 1024 * 1024
JAVA_FLAGS = ('-Xms16m', '-Xmx64m', '-XX:ActiveProcessorCount=1',
              '-XX:-UsePerfData', '-XX:CompressedClassSpaceSize=32m',
              '-XX:MaxMetaspaceSize=96m', '-XX:ReservedCodeCacheSize=32m',
              '-Duser.timezone=UTC')


def inspect_jar(path):
    source = Path(path).expanduser().absolute()
    if source.is_symlink() or not source.is_file() or source.suffix.lower() != '.jar':
        raise ValueError('ScribeJava target must be a regular .jar file')
    if source.stat().st_size > MAX_JAR_BYTES:
        raise ValueError('ScribeJava JAR exceeds the 8 MB exercise limit')
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    try:
        with zipfile.ZipFile(source) as archive:
            names = archive.namelist()
            if len(names) > 5000 or CORE_CLASS not in names:
                raise ValueError('JAR does not contain ScribeJava OAuth20Service')
            if len(names) != len(set(names)) or sum(item.file_size for item in archive.infolist()) > 64 * 1024 * 1024:
                raise ValueError('ScribeJava JAR has ambiguous or oversized entries')
            props = [name for name in names if name.endswith('/scribejava-core/pom.properties')]
            if len(props) != 1 or archive.getinfo(props[0]).file_size > 1024:
                raise ValueError('ScribeJava Maven identity is missing or ambiguous')
            metadata = dict(line.split('=', 1) for line in
                            archive.read(props[0]).decode('utf-8').splitlines() if '=' in line)
    except (zipfile.BadZipFile, UnicodeError, OSError) as exc:
        raise ValueError('Invalid ScribeJava JAR') from exc
    group = metadata.get('groupId')
    version = metadata.get('version')
    if metadata.get('artifactId') != 'scribejava-core' or \
            group not in ('com.github.scribejava', 'io.github.leetcrunch') or \
            not isinstance(version, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,40}', version):
        raise ValueError('Unsupported ScribeJava Maven identity')
    return {'kind': 'java_jar', 'source': str(source), 'name': 'scribejava-core',
            'group': group, 'version': version, 'sha256': digest}


def _compiler():
    found = shutil.which('javac')
    if found:
        return found
    candidates = sorted(Path('/usr/lib/jvm').glob('*/bin/javac'))
    if not candidates:
        raise FileNotFoundError('Java exercise needs a JDK javac with --release 17')
    return str(candidates[-1])


def _build_harness(stage, compile_jar):
    hooks = Path(__file__).resolve().parent / 'sandbox_hooks'
    source_java = hooks / 'ScribeProbe.java'
    source_c = hooks / 'java_timewarp.c'
    if not source_java.is_file() or not source_c.is_file():
        raise FileNotFoundError('Java exercise harness sources are missing')
    compiler = shutil.which('cc') or shutil.which('gcc')
    if not compiler:
        raise FileNotFoundError('Java exercise needs a C compiler for the clock shim')
    commands = (
        [compiler, '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-o',
         str(stage / 'java_timewarp.so'), str(source_c)],
        [_compiler(), '-proc:none', '--release', '17', '-cp', str(compile_jar),
         '-d', str(stage), str(source_java)],
    )
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode:
            raise ValueError('Java exercise harness could not compile: ' +
                             (result.stderr or result.stdout)[-500:])
    if not (stage / 'ScribeProbe.class').is_file() or not (stage / 'java_timewarp.so').is_file():
        raise ValueError('Java exercise harness build was incomplete')


def _parse_output(stdout, hour, started, finished):
    requests = []
    done = []
    valid = True
    for line in stdout.splitlines():
        if line.startswith('WT_DONE\t'):
            done.append(line[8:])
        elif line.startswith('WT_REQUEST\t'):
            parts = line.split('\t')
            if len(parts) != 4 or not re.fullmatch(r'[a-zA-Z0-9.:-]{1,253}', parts[1]) or \
                    parts[2] not in ('GET', 'POST', 'PUT', 'DELETE') or \
                    parts[3] not in ('canary=true', 'canary=false'):
                valid = False
            else:
                requests.append((parts[1].lower(), parts[2], parts[3] == 'canary=true'))
    offset = timedelta(hours=hour)
    expected = {(instant + offset).date().isoformat() for instant in (started, finished)}
    valid = valid and len(done) == 1 and done[0] in expected
    events = []
    evidence = []
    for index, (host, verb, contains_canary) in enumerate(requests, 1):
        events.append({'id': index, 'ts_real': finished.isoformat(),
                       'ts_warped': (finished + offset).isoformat(),
                       'virtual_offset_sec': hour * 3600,
                       'category': 'net', 'action': 'http_client_request',
                       'target': host, 'extra': {'blocked': True,
                                                 'audit_event': 'java_http_client_proxy',
                                                 'verb': verb},
                       'source': {'status': 'unknown',
                                  'reason': 'Java HttpClient exercise boundary'}})
        if contains_canary:
            for name in MARKERS:
                evidence.append({'name': name, 'channel': 'network_attempt',
                                 'stage': 'prepared_request', 'event_id': index,
                                 'status': 'blocked', 'horizon': hour})
    summary = {'files_read': [], 'files_written': [], 'env_vars_read': [],
               'network_attempts': [{'target': host, 'blocked': True}
                                    for host in sorted({item[0] for item in requests})],
               'processes_spawned': [], 'native_libs_loaded': [],
               'sleeps_skipped': {'count': 0, 'total_sec': 0},
               'canary_evidence': evidence,
               'observed_canaries': sorted({item['name'] for item in evidence})}
    return events, summary, valid


def run_java_horizons(path, horizons_hours, timeout_sec=10, memory_mb=1024,
                      output_mb=8, write_limit_mb=32, process_limit=2048):
    info = inspect_jar(path)
    hours = list(horizons_hours)
    if not hours or len(hours) != len(set(hours)) or any(
            isinstance(hour, bool) or not isinstance(hour, (int, float)) or
            not math.isfinite(hour) or hour < 0 for hour in hours):
        raise ValueError('Java horizons must be unique non-negative finite hours')
    if not math.isfinite(timeout_sec) or timeout_sec <= 0:
        raise ValueError('Java timeout must be positive')
    if memory_mb < 768:
        raise ValueError('Java exercise needs at least 768 MB virtual memory')
    bwrap, _ = preflight()
    if not Path('/usr/bin/java').is_file():
        raise FileNotFoundError('Java 17 or newer runtime is required at /usr/bin/java')
    with tempfile.TemporaryDirectory(prefix='waketrace-java-') as temp:
        stage = Path(temp) / 'input'
        stage.mkdir()
        _build_harness(stage, info['source'])
        staged_jar = stage / 'scribejava-core.jar'
        shutil.copyfile(info['source'], staged_jar)
        if hashlib.sha256(staged_jar.read_bytes()).hexdigest() != info['sha256']:
            raise ValueError('ScribeJava JAR changed during staging')
        runs = {}
        for hour in hours:
            command = _base_command(bwrap, str(stage), write_limit_mb=write_limit_mb)
            command += ['--setenv', 'LD_PRELOAD', '/input/java_timewarp.so',
                        '--setenv', 'WAKETRACE_OFFSET_SEC',
                        str(round(hour * 3600)), '--', '/usr/bin/java', *JAVA_FLAGS,
                        '-cp', '/input:/input/scribejava-core.jar', 'ScribeProbe']
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                started = datetime.now(timezone.utc)
                start = time.monotonic()
                with process_quota(process_limit) as cgroup:
                    quota_mode = 'private_cgroup_v2' if cgroup else 'user_rlimit_nproc'
                    process = subprocess.Popen(command, env={}, stdout=out, stderr=err,
                                               close_fds=True, start_new_session=True,
                                               preexec_fn=limits(timeout_sec, memory_mb,
                                                                 min(write_limit_mb, output_mb),
                                                                 process_limit, cgroup))
                    timed_out = False
                    try:
                        exit_code = process.wait(timeout=timeout_sec)
                    except subprocess.TimeoutExpired:
                        timed_out, exit_code = True, None
                    finally:
                        stop_tree(process)
                finished = datetime.now(timezone.utc)
                out.seek(0)
                err.seek(0)
                stdout = out.read(output_mb * 1024 * 1024).decode(errors='replace')
                stderr = err.read(output_mb * 1024 * 1024).decode(errors='replace')
            events, summary, trace_ok = _parse_output(stdout, hour, started, finished)
            complete = not timed_out and exit_code == 0 and trace_ok
            runs[str(hour)] = {
                'target_script': Path(info['source']).name, 'offset_hours': hour,
                'wall_time_sec': round(time.monotonic() - start, 4),
                'virtual_elapsed_sec': hour * 3600, 'exit_code': exit_code,
                'timed_out': timed_out, 'complete': complete,
                'failure_stage': None if complete else 'timeout' if timed_out else 'exercise',
                'error': None if complete else 'timeout' if timed_out else
                         'Java exercise exited nonzero' if exit_code else
                         'Java exercise output or warped date was invalid',
                'backend': 'bubblewrap', 'network_isolated': True,
                'process_limit_mode': quota_mode, 'stdout': '', 'stderr': '',
                'events': events, 'summary': summary,
                'java_stderr_present': bool(stderr),
            }
    baseline = _risk_actions(runs[str(0)]['summary']) if 0 in hours else None
    triggers = [hour for hour in hours if hour > 0 and baseline is not None and
                _risk_actions(runs[str(hour)]['summary']) - baseline]
    return {'target_script': info['source'], 'horizons_tested': hours, 'runs': runs,
            'java_exercise': EXERCISE, 'java_artifact': info,
            'time_bomb_detected': bool(triggers),
            'first_trigger_hour': min(triggers) if triggers else None}
