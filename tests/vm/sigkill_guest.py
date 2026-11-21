#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Collector-SIGKILL guest flow: kill at one boundary, verify recovery.

One scenario per boot: start the collector, hold it at the required
boundary (readiness announcement, durable checkpoint, or finalization
staging), snapshot the independently verified prefix, SIGKILL the
collector, then prove the death, the unchanged prefix, the recovery exits
and the owned cleanup. Refuses host execution before any guest work.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'tests' / 'cli'))
sys.path.insert(0, str(ROOT / 'tests' / 'fuzz'))
from sigkill_verify import (SCENARIOS, MARKERS, RESERVE_BYTES,
                            CAPTURE_INVENTORY, validate_barrier,
                            validate_result)
from test_checkpoint_writer import independent

INPUT_KEYS = ('binary', 'object', 'bridge', 'profile', 'shim')
FAULT = {'readiness': 'none', 'checkpoint': 'checkpoint-2',
         'finalization': 'final-stop'}
DURATIONS = {'readiness': '300', 'checkpoint': '180', 'finalization': '60'}
BOUNDARY_TIMEOUT = {'readiness': 60, 'checkpoint': 240, 'finalization': 240}
MAX_EVENTS_BYTES = str(64 * 1048576)
GATE_PREFIX = 'memveil_sigkill_gate='


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def require_guest(nonce):
    if len(nonce) != 32 or any(c not in '0123456789abcdef' for c in nonce):
        raise ValueError('invalid ownership nonce')
    if GATE_PREFIX + nonce not in Path('/proc/cmdline').read_text().split():
        raise ValueError('owned guest command-line barrier absent')
    if not (Path('/tmp/export')).is_dir():
        raise ValueError('guest export mount absent')


def guest_identity(config):
    try:
        btf = digest('/sys/kernel/btf/vmlinux')
    except OSError:
        btf = 'absent'
    banner = Path('/proc/version').read_text().strip()
    return dict(
        kernel_config_sha256=None, kernel=os.uname().release,
        release=os.uname().release, banner=banner,
        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        btf_sha256=btf,
        inputs={key: digest(config[key]) for key in INPUT_KEYS
                if config.get(key)})


def check_identity(identity, config, inputs, expect_release):
    if identity['inputs'] != inputs:
        raise ValueError('candidate identity changed in guest')
    if identity['release'] != expect_release:
        raise ValueError('guest booted release %s, expected %s'
                         % (identity['release'], expect_release))
    for key in INPUT_KEYS:
        if config.get(key) and digest(config[key]) != inputs[key]:
            raise ValueError('guest input drift: ' + key)


def is_stopped(pid):
    try:
        state = (Path('/proc') / str(pid) / 'status').read_text()
    except FileNotFoundError:
        return False
    return '\nState:\tT' in state


def wait_ready(child, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise ValueError('collector exited before readiness: %s'
                             % child.returncode)
        ready, _, _ = select.select([child.stdout], [], [], 1)
        if ready:
            line = child.stdout.readline()
            if line.startswith(b'ready session='):
                return line.decode('utf-8', 'replace').strip()
            if line == b'':
                raise ValueError('collector closed stdout before readiness')
    raise ValueError('collector readiness absent')


def wait_stopped_at_marker(child, marker, text, seconds):
    marker = Path(marker)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if marker.exists() and marker.read_text() == text \
                and is_stopped(child.pid):
            return
        if child.poll() is not None:
            raise ValueError('collector exited before durable boundary: %s'
                             % child.returncode)
        time.sleep(0.02)
    raise ValueError('boundary %r not reached' % text)


def reserve_proof(scenario, capture):
    """Prove the reserve state the barrier requires. Raises ValueError.

    Readiness/checkpoint barriers prove the 17 MiB allocation is still
    held; the finalization barrier proves finalize() released it, so
    ABSENCE is the proof there. Returns (allocated_bytes_or_None,
    released). Every outcome fails closed with the scenario name, never
    a bare OSError.
    """
    path = Path(capture) / '.finalization-reserve'
    try:
        blocks = path.stat().st_blocks
    except FileNotFoundError:
        if scenario == 'finalization':
            return None, True
        raise ValueError('%s barrier: allocated reserve absent' % scenario)
    except OSError as exc:
        raise ValueError('%s barrier: reserve stat failed: %s'
                         % (scenario, exc))
    if scenario == 'finalization':
        raise ValueError('finalization barrier: reserve still present, '
                         'release unproven')
    return blocks * 512, False


def barrier_present(scenario, capture, name):
    """Presence check that fails closed with the scenario name."""
    try:
        (Path(capture) / name).stat()
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ValueError('%s barrier: cannot stat %s: %s'
                         % (scenario, name, exc))


def snapshot_barrier(scenario, nonce, marker, capture, identity):
    try:
        doc = independent(Path(capture))
    except (AssertionError, KeyError) as exc:
        raise ValueError('independent prefix check failed: %s' % exc)
    except OSError as exc:
        raise ValueError('%s barrier: cannot read durable prefix: %s'
                         % (scenario, exc))
    if doc is None:
        raise ValueError('no durable checkpoint at barrier')
    allocated, released = reserve_proof(scenario, capture)
    try:
        marker_text = Path(marker).read_text()
    except OSError as exc:
        raise ValueError('%s barrier: cannot read marker: %s'
                         % (scenario, exc))
    try:
        checkpoint_digest = digest(Path(capture) / 'checkpoint.json')
    except OSError as exc:
        raise ValueError('%s barrier: cannot digest checkpoint: %s'
                         % (scenario, exc))
    return dict(
        nonce=nonce, scenario=scenario, stopped=True,
        marker=marker_text, ready_observed=True,
        reserve_allocated=allocated, reserve_released=released,
        integrity=doc['capture']['integrity'],
        session_id=doc['session_id'],
        session_json_absent=not barrier_present(scenario, capture,
                                                'session.json'),
        finalizing_present=barrier_present(scenario, capture,
                                           'session.finalizing'),
        checkpoint_sha256=checkpoint_digest,
        identity=identity)


def kill_and_prove(child):
    child.kill()
    child.communicate(timeout=30)
    if child.returncode != -signal.SIGKILL:
        raise ValueError('collector death was not SIGKILL: %s'
                         % child.returncode)
    return child.returncode


def check_reports(run_report, capture, line_count, oracle=None):
    report = {}
    plain = run_report(capture, [])
    report['plain_exit'] = plain.returncode
    if plain.returncode != 2:
        raise ValueError('unfinalized capture did not refuse plain report: %s'
                         % plain.returncode)
    for flags, key in ((['--allow-partial'], 'partial_exit'),
                       (['--allow-partial', '--strict'], 'partial_strict_exit')):
        proc = run_report(capture, ['--format', 'json'] + flags)
        report[key] = proc.returncode
        if proc.returncode != 4:
            raise ValueError('partial recovery exit is %s, want 4'
                             % proc.returncode)
        if key == 'partial_exit':
            if oracle is not None:
                oracle(capture, proc.stdout, proc.returncode)
            parsed = json.loads(proc.stdout.decode('utf-8'))
            report['verified_events'] = parsed['integrity']['verified_events']
            if report['verified_events'] != line_count:
                raise ValueError('recovered count %s disagrees with prefix %s'
                                 % (report['verified_events'], line_count))
    return report


def stray_processes(name):
    found = []
    me = os.getpid()
    for entry in Path('/proc').glob('[0-9]*'):
        if int(entry.name) == me:
            continue
        try:
            raw = (entry / 'cmdline').read_bytes().split(b'\0')
        except OSError:
            continue
        words = [Path(os.fsdecode(word)).name for word in raw if word]
        if name in words:
            found.append(int(entry.name))
    return sorted(found)


def dir_lock_released(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(fd, fcntl.LOCK_UN)
        return True
    finally:
        os.close(fd)


def check_cleanup(scenario, capture, binary_name):
    capture = Path(capture)
    strays = stray_processes(binary_name)
    if strays:
        raise ValueError('collector processes survived: %r' % strays)
    inventory = sorted(p.name for p in capture.iterdir())
    if set(inventory) != set(CAPTURE_INVENTORY[scenario]):
        raise ValueError('capture inventory drift: %r' % inventory)
    if (capture / 'session.json').exists():
        raise ValueError('final session appeared after the kill')
    if not dir_lock_released(str(capture)):
        raise ValueError('capture directory lock still held')
    return dict(session_json_absent=True, stray_processes=[],
                capture_inventory=inventory, dir_lock_released=True)


def ping_round(host='10.0.3.2', count=32):
    proc = subprocess.run(['ping', '-n', '-q', '-c', str(count), '-i', '0.01',
                           '-W', '2', host],
                          capture_output=True, timeout=60,
                          env=dict(os.environ, LC_ALL='C'))
    import re
    match = re.search(rb'(\d+) packets transmitted, (\d+) received',
                      proc.stdout)
    if proc.returncode != 0 or match is None:
        raise ValueError('stimulus ping failed')
    return {'transmitted': match.group(1).decode(),
            'received': match.group(2).decode()}


def stimulus_loop(stop, rounds):
    while not stop.is_set():
        try:
            rounds.append(ping_round())
        except (ValueError, OSError):
            rounds.append({'transmitted': '0', 'received': '0',
                           'error': 'unsupported'})
            stop.wait(5)
        except Exception:
            rounds.append({'transmitted': '0', 'received': '0',
                           'error': 'failed'})
            stop.wait(5)


def export_evidence(export, capture, barrier, result, record_stderr):
    export = Path(export)
    capture = Path(capture)
    extent = int(barrier['integrity']['events_bytes'])
    with open(capture / 'events.ndjson', 'rb') as stream:
        prefix = stream.read(extent)
    if len(prefix) != extent:
        raise ValueError('durable prefix exceeds retained events')
    if hashlib.sha256(prefix).hexdigest() != barrier['integrity']['events_sha256']:
        raise ValueError('exported prefix disagrees with barrier digest')
    (export / 'prefix-events.ndjson').write_bytes(prefix)
    shutil.copyfile(capture / 'checkpoint.json', export / 'checkpoint.json')
    shutil.copyfile(record_stderr, export / 'record.stderr')
    (export / 'barrier.json').write_text(json.dumps(barrier, sort_keys=True)
                                         + '\n')
    (export / 'result.json').write_text(json.dumps(result, sort_keys=True)
                                        + '\n')


def collector_argv(config, capture, scenario):
    argv = [config['binary'], 'record', '--output', str(capture),
           '--duration', DURATIONS[scenario], '--object', config['object'],
           '--profile', config['profile'],
           '--max-events-bytes', MAX_EVENTS_BYTES]
    if config.get('bridge'):
        argv += ['--bridge', config['bridge']]
    return argv


def collector_env(config, marker, scenario):
    env = dict(os.environ, LD_PRELOAD=config['shim'],
               MV_CAPTURE_FAULT=FAULT[scenario], MV_FAULT_MARKER=str(marker))
    env.pop('MEMVEIL_TEST_NO_BPF', None)
    return env


def run_scenario(scenario, nonce, work, export, inputs, identity, spawn,
                 run_report, binary_name, oracle=None, stimulus=True):
    """Drive one kill boundary; shared by the armed guest and self-test.

    spawn(capture, marker) starts the collector and returns the Popen
    handle; run_report(capture, flags) runs the report verb. Both are
    injected so the offline self-test exercises this exact flow.
    """
    if scenario not in SCENARIOS:
        raise ValueError('unknown scenario')
    work = Path(work)
    capture = work / 'capture'
    marker = work / 'reached'
    record_stderr = work / 'record.stderr'
    stop = threading.Event()
    rounds = []
    helper = None
    if stimulus and scenario in ('checkpoint', 'finalization'):
        helper = threading.Thread(target=stimulus_loop, args=(stop, rounds),
                                  daemon=True)
        helper.start()
    child = None
    try:
        child = spawn(capture, marker)
        if child.stdout is None:
            raise ValueError('collector stdout was not piped')
        session = wait_ready(child, BOUNDARY_TIMEOUT['readiness'])
        if scenario == 'readiness':
            child.send_signal(signal.SIGSTOP)
            deadline = time.monotonic() + 10
            while not is_stopped(child.pid):
                if child.poll() is not None:
                    raise ValueError('collector exited at readiness: %s'
                                     % child.returncode)
                if time.monotonic() >= deadline:
                    raise ValueError('collector did not stop at readiness')
                time.sleep(0.01)
            marker.write_text(MARKERS[scenario])
        else:
            wait_stopped_at_marker(child, marker, MARKERS[scenario],
                                   BOUNDARY_TIMEOUT[scenario])
        barrier = snapshot_barrier(scenario, nonce, marker, capture,
                                   identity)
        barrier['ready_session'] = session
        validate_barrier(barrier, nonce, scenario, inputs)
        code = kill_and_prove(child)
        child = None
        try:
            after = independent(capture)
        except (AssertionError, KeyError) as exc:
            raise ValueError('durable prefix failed re-verification across '
                             'the kill: %s' % exc)
        if after is None or after['capture']['integrity'] != barrier['integrity']:
            raise ValueError('durable prefix changed across the kill')
        report = check_reports(run_report, capture,
                               barrier['integrity']['line_count'],
                               oracle=oracle)
        cleanup = check_cleanup(scenario, capture, binary_name)
        result = dict(nonce=nonce, scenario=scenario, killed_by_sigkill=True,
                      collector_returncode=code, integrity=after['capture']['integrity'],
                      checkpoint_sha256=digest(capture / 'checkpoint.json'),
                      report=report, cleanup=cleanup,
                      stimulus=rounds, identity=identity)
        validate_result(result, barrier, inputs)
        export_evidence(export, capture, barrier, result, record_stderr)
        return barrier, result
    finally:
        stop.set()
        if helper is not None:
            helper.join(timeout=70)
        if child is not None:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
            if child.stdout is not None:
                child.stdout.close()


def main():
    config_path, scenario, nonce = sys.argv[1:4]
    export = Path('/tmp/export')
    work = Path('/tmp/memveil-sigkill-' + nonce)
    try:
        require_guest(nonce)
        from report_oracle import accepted_report

        def oracle(capture, out, code):
            accepted_report(capture, out, code, allow_partial=True)

        config = json.loads(Path(config_path).read_text())
        inputs = {key: digest(config[key]) for key in INPUT_KEYS
                  if config.get(key)}
        identity = guest_identity(config)
        expect_release = config['expect_release']
        check_identity(identity, config, inputs, expect_release)
        work.mkdir(mode=0o700, exist_ok=False)

        def spawn(capture, marker):
            err = open(work / 'record.stderr', 'wb')
            proc = subprocess.Popen(
                collector_argv(config, capture, scenario),
                stdout=subprocess.PIPE, stderr=err,
                env=collector_env(config, marker, scenario))
            err.close()
            return proc

        def run_report(capture, flags):
            return subprocess.run([config['binary'], 'report'] + flags
                                  + [str(capture)], capture_output=True,
                                  timeout=120)

        binary_name = Path(config['binary']).name
        barrier, result = run_scenario(scenario, nonce, work, export, inputs,
                                       identity, spawn, run_report,
                                       binary_name, oracle=oracle)
        sys.stdout.write('sigkill-guest: PASS %s prefix=%s count=%s\n'
                         % (scenario, barrier['integrity']['events_sha256'][:16],
                            barrier['integrity']['line_count']))
        return 0
    except Exception as exc:
        sys.stderr.write('sigkill-guest: FAIL %s: %s\n' % (scenario, exc))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
