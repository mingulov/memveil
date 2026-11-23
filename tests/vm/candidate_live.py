#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Installed candidate campaigns in an owned, ephemeral ordinary Linux guest."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import errno
import fcntl
import hashlib
import json
import math
import os
import re
from pathlib import Path
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'tests/perf'))
sys.path.insert(0, str(ROOT / 'tests/confidential/spikes'))
sys.path.insert(0, str(ROOT / 'tests/confidential'))
from support.candidate_input import CandidateInput, load
from compare import assess, compare
from pool_read_oracle import PoolReadOracle, validate_pool

SOAK_SECONDS = 1800
POOL_SECONDS = 4260
TOP_INTERVAL_NS = 10**9
TOP_GAP_TOLERANCE_NS = 500000000
MODES = ('attempt-record-summary', 'live-top-1s', 'journal-summary', 'journal-callers-detail')
JOURNAL_MODES = ('journal-summary', 'journal-callers-detail')
JOURNAL_CAPABILITY = 'conversion-journal'
CAMPAIGN_MODES = ('overhead', 'soak', 'pool')
ARMED_VAR = 'MEMVEIL_VM_LIVE_SOAK'
PERF_ARMED_VAR = 'MEMVEIL_VM_PERF'
ARMED_VARS = {'overhead': PERF_ARMED_VAR, 'soak': ARMED_VAR,
              'pool': ARMED_VAR}
TIMEOUTS = {'soak': SOAK_SECONDS + POOL_SECONDS + 1800, 'overhead': 7200,
            'pool': POOL_SECONDS + 1800}


def schedule():
    return [(mode, pair) for pair in range(5) for mode in MODES]


def product_command(binary, mode, capture, duration):
    """Collector argv for one leg; journal spellings run only when admitted.

    The journal capability and caller flag are the forward product
    contract: journal legs never reach this command unless the
    admission probe judged the capability available, so an older
    build skips those rows instead of failing on unknown flags.
    """
    command = [str(binary), 'top' if mode == 'live-top-1s' else 'record',
               '--output', str(capture), '--duration', str(duration)]
    if mode == 'live-top-1s': command += ['--interval', '1s']
    if mode.startswith('journal-'):
        command += ['--capability', 'conversion-journal']
    else:
        command += ['--capability', 'attempt-trace']
    if mode == 'journal-callers-detail': command += ['--journal-callers']
    return command


class ProductExit(ValueError):
    def __init__(self, code, reason='required product command exit',
                 detail=''):
        message = reason + ' ' + str(code)
        if detail:
            message += ': ' + detail
        super().__init__(message)
        self.product_exit = code
        self.detail = detail


def require_product_exit(code):
    if code != 0:
        raise ProductExit(code)


def validate_duration(required, elapsed, block_bytes, packets):
    if elapsed < required or block_bytes <= 0 or packets <= 0:
        raise ValueError('duration or independent mixed-workload counts unmet')


def checked(command, timeout=60):
    result = subprocess.run(command, capture_output=True, timeout=timeout)
    if result.returncode:
        raise ValueError('required helper failed: ' + Path(command[0]).name)
    return result.stdout


class InstallFailure(ValueError):
    def __init__(self, message, returncode=None, stdout=b'',
                 stderr=b'', log=None):
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.log = log


INSTALL_LOG_NAME = 'install-dpkg.log'
INSTALL_LOG_LIMIT = 65536
INSTALL_TAIL_LINES = 20


def install_guest_deb(deb, local_evidence, timeout=120):
    """Install the sealed .deb in the campaign guest; return dpkg stdout.

    The guest shares the host rootfs by design, so its dpkg
    database tracks almost nothing: unpack succeeds but
    configure refuses on Depends entries (libc6) that exist
    in userspace yet are unknown to dpkg. --force-depends
    converts exactly that refusal into a warning while the
    real dependency stays satisfied by the shared rootfs;
    where dpkg already knows the libraries (a Debian
    rootfs) the flag is a no-op, so no guest-distro probe
    is needed. dpkg-state consequences stay inside the
    ephemeral overlay: the package lands installed with an
    unmet-Depends note, nothing in-guest consults dpkg
    status afterwards (every verifier below hashes files),
    and no apt/dpkg follow-up ever runs before teardown.
    A guest without dpkg refuses with the missing tool
    named instead of guessing another installer.

    Forensics: the full dpkg transcript (bounded) lands in
    local_evidence/INSTALL_LOG_NAME on success and failure
    alike - that mount is host-visible yet outside the
    export/ inventory gate - and the failure message
    carries the stderr tail, so the cause survives in the
    console capture even if the log write itself fails.
    """
    dpkg = shutil.which('dpkg')
    if dpkg is None:
        raise ValueError('guest package installer missing: dpkg not found '
                         'in guest PATH; cannot install the sealed .deb')
    argv = [dpkg, '--force-depends', '-i', str(deb)]
    try:
        result = subprocess.run(argv, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        message = ('guest package install timed out: dpkg -i %s: %s'
                   % (deb, _forensics_tail(exc.stderr or b'')))
        try:
            _write_install_log(local_evidence, argv, 'timeout',
                               exc.stdout or b'', exc.stderr or b'')
        except ValueError as log_exc:
            message += '; ' + str(log_exc)
        raise InstallFailure(
            message, returncode=None, stdout=exc.stdout or b'',
            stderr=exc.stderr or b'',
            log=str(Path(local_evidence) / INSTALL_LOG_NAME))
    if result.returncode:
        message = ('guest package install failed: dpkg exit %d: %s'
                   % (result.returncode, _forensics_tail(result.stderr)))
        try:
            _write_install_log(local_evidence, argv, result.returncode,
                               result.stdout, result.stderr)
        except ValueError as log_exc:
            message += '; ' + str(log_exc)
        raise InstallFailure(
            message, returncode=result.returncode, stdout=result.stdout,
            stderr=result.stderr,
            log=str(Path(local_evidence) / INSTALL_LOG_NAME))
    _write_install_log(local_evidence, argv, 0,
                       result.stdout, result.stderr)
    return result.stdout


def _forensics_tail(stream, lines=INSTALL_TAIL_LINES):
    text = (stream or b'').decode('utf-8', 'replace').splitlines()
    tail = text[-lines:]
    joined = '\n'.join(line for line in tail if line.strip())
    return joined or '(no output)'


def _write_bounded_log(path, argv, status, stdout, stderr, limit):
    """Write one headed transcript; None limit means bounded upstream."""
    header = ('argv: %s\nstatus: %s\n--- stdout ---\n'
              % (argv, status)).encode()
    body = header + (stdout or b'') + b'\n--- stderr ---\n' + (stderr or b'')
    if limit is not None and len(body) > limit:
        body = body[:limit] + b'\n[truncated]\n'
    Path(path).write_bytes(body)


def _write_install_log(local_evidence, argv, status, stdout, stderr):
    log = Path(local_evidence) / INSTALL_LOG_NAME
    try:
        _write_bounded_log(log, argv, status, stdout, stderr,
                           INSTALL_LOG_LIMIT)
    except OSError as exc:
        raise ValueError(
            'guest install forensics unwritable: ' + str(log)) from exc


def inventory():
    from journal_spike import resources
    return {kind: sorted(values) for kind, values in resources().items()}


def settled(before):
    end = time.monotonic() + 30
    while True:
        after = inventory()
        if after == before: return after
        if time.monotonic() >= end:
            raise ValueError('BPF program/map/link cleanup did not settle')
        time.sleep(.25)


def sample(pid):
    process = Path('/proc') / str(pid)
    status = dict(line.split(':', 1) for line in (process / 'status').read_text().splitlines())
    rss = int(status['VmRSS'].split()[0])
    fds = list((process / 'fd').iterdir())
    maps = {}
    for fd in (process / 'fdinfo').iterdir():
        try: fields = dict(line.split(':', 1) for line in fd.read_text().splitlines() if ':' in line)
        except FileNotFoundError: continue
        if 'map_id' in fields:
            maps[fields['map_id'].strip()] = str(int(fields['memlock'])) if 'memlock' in fields else None
    if rss > 256 * 1024:
        raise ValueError('userspace RSS exceeded 256 MiB')
    return {'elapsed_monotonic_ns': str(time.monotonic_ns()), 'rss_kib': str(rss),
            'fd_count': str(len(fds)), 'map_memlock_bytes': maps}


def completed_units(kind, stdout, stderr, pool):
    if kind == 'block':
        match = re.search(rb'(\d+) bytes .* copied', stderr)
        count = 16384 if pool else 16 * 1024 * 1024
        if match is None or int(match[1]) != count: raise ValueError('scratch byte oracle mismatch')
    else:
        match = re.search(rb'(\d+) packets transmitted, (\d+) received', stdout)
        count = 1 if pool else 32
        if match is None or int(match[1]) != count or int(match[2]) != count:
            raise ValueError('peer packet oracle mismatch or loss')
    return count


def operation(disk, kind, pool=False):
    started = time.monotonic_ns()
    if kind == 'block':
        command = ['dd', 'if=' + str(disk), 'of=/dev/null', 'bs=4k' if pool else 'bs=1M',
                   'count=4' if pool else 'count=16', 'iflag=direct,fullblock']
    else:
        command = ['ping', '-n', '-q', '-c', '1' if pool else '32', '-i', '0.01', '-W', '2', '10.0.3.2']
    result = subprocess.run(command, capture_output=True, timeout=30, env=dict(os.environ, LC_ALL='C'))
    if result.returncode: raise ValueError('independent workload helper failed: ' + kind)
    count = completed_units(kind, result.stdout, result.stderr, pool)
    return count, (time.monotonic_ns() - started) / 1e9


def workload(disk, seconds, proc=None, pool_case=False, oracle=None):
    started_ns = time.monotonic_ns()
    started = started_ns / 10**9
    amounts = {'block': 0, 'network': 0}
    latencies = {'block': [], 'network': []}
    samples = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        while time.monotonic() - started < seconds:
            if oracle is not None: oracle.check()
            if proc is not None:
                if proc.poll() is not None: raise ProductExit(proc.returncode, 'collector exited during workload: exit')
                samples.append(sample(proc.pid))
            pending = {kind: pool.submit(operation, disk, kind, pool_case) for kind in amounts}
            for kind, future in pending.items():
                count, elapsed = future.result()
                amounts[kind] += count
                latencies[kind].append(elapsed)
            if pool_case: time.sleep(1)
    ended_ns = time.monotonic_ns()
    elapsed = (ended_ns - started_ns) / 10**9
    validate_duration(seconds, elapsed, amounts['block'], amounts['network'])
    metrics = {}
    for kind in amounts:
        ordered = sorted(latencies[kind])
        metrics[kind] = {'valid': True, 'counts_ok': True, 'throughput': amounts[kind] / elapsed,
                         'p99': ordered[math.ceil(.99 * len(ordered)) - 1],
                         'completed_units': str(amounts[kind]), 'operation_seconds': latencies[kind]}
    return {'elapsed_seconds': elapsed, 'window': {'start_ns': str(started_ns), 'end_ns': str(ended_ns)},
            'metrics': metrics, 'samples': samples}


def run_soak(one, result):
    started = time.monotonic()
    measured_ns = 0
    count = 0
    while measured_ns < SOAK_SECONDS * 10**9:
        observation = one('attempt-record-summary', 60)
        work = observation['workload']
        duration = int(work['window']['end_ns']) - int(work['window']['start_ns'])
        validate_duration(60, duration / 10**9,
                          int(work['metrics']['block']['completed_units']),
                          int(work['metrics']['network']['completed_units']))
        measured_ns += duration
        count += 1
    if count < 2: raise ValueError('soak lacks repeated capture/stop')
    result['mixed_seconds'] = measured_ns / 10**9
    result['campaign_seconds_before_pool'] = time.monotonic() - started
    one('attempt-record-summary', POOL_SECONDS, True)


def run_pool(one, result):
    observation = one('attempt-record-summary', POOL_SECONDS, True)
    result['pool'] = {'legs': 1, 'observation': observation}


def validate_top_refreshes(refreshes, window):
    start, end = int(window['start_ns']), int(window['end_ns'])
    ticks = [int(tick) for tick in refreshes if start <= int(tick) < end]
    if end - start < 60 * 10**9 or len(ticks) < (end - start) // TOP_INTERVAL_NS - 1:
        raise ValueError('live top refresh count does not cover measured window')
    maximum = TOP_INTERVAL_NS + TOP_GAP_TOLERANCE_NS
    if not ticks or ticks[0] - start > maximum or end - ticks[-1] > maximum:
        raise ValueError('live top refresh window edges are uncovered')
    if any(not TOP_INTERVAL_NS - TOP_GAP_TOLERANCE_NS <= b - a <= maximum
           for a, b in zip(ticks, ticks[1:])):
        raise ValueError('live top refresh burst or cadence gap')


def capture_facts(binary, capture, pool=False, oracle=None, window=None, stop_ns=None):
    from support.candidate_input import candidate
    session = candidate.read_json(capture / 'session.json')
    rendered = subprocess.run([str(binary), 'report', '--strict', '--format', 'json', str(capture)],
                              capture_output=True, timeout=120)
    require_product_exit(rendered.returncode)
    report = rendered.stdout
    if len(report) > 16 * 1024 * 1024: raise ValueError('report exceeds document bound')
    parsed = json.loads(report)
    if parsed.get('integrity', {}).get('status') != 'verified': raise ValueError('capture integrity unverified')
    quality = session['quality']
    for channel in ('detail', 'aggregate', 'correlation', 'baseline', 'terminal'):
        value = quality[channel]
        if value.get('loss_count') not in ('0', None): raise ValueError('capture channel loss: ' + channel)
        if value.get('status') not in ('complete_for_scope', 'not_applicable', 'unavailable'):
            raise ValueError('capture channel incomplete: ' + channel)
    kinds, pool_samples = {}, []
    with (capture / 'events.ndjson').open('rb') as stream:
        while True:
            line = stream.readline(65537)
            if not line: break
            if len(line) > 65536: raise ValueError('event exceeds line bound')
            event = json.loads(line)
            kind = event['kind']
            kinds[kind] = kinds.get(kind, 0) + 1
            if kind == 'pool_sample':
                if len(pool_samples) >= 4096 + 64 + 2:
                    raise ValueError('pool sample inventory exceeds source bound')
                pool_samples.append(event['ts_ns'])
    if not kinds.get('bounce_attempt', 0) and not kinds.get('transition_result', 0):
        raise ValueError('capture has no workload observations')
    if pool:
        if window is None or stop_ns is None: raise ValueError('pool measurement boundaries absent')
        validate_pool(pool_samples, window, oracle, stop_ns)
    return {'quality': quality, 'stop': session['stop'], 'kinds': {k: str(v) for k,v in kinds.items()},
            'session_sha256': candidate.digest(capture / 'session.json'),
            'events_sha256': candidate.digest(capture / 'events.ndjson')}


def observe_output(stream, observed):
    while True:
        line = stream.readline(65537)
        if not line: return
        if len(line) > 65536:
            observed['error'] = 'collector output line exceeds bound'
            return
        if b'ready session=' in line: observed['ready'] = True
        if line.startswith(b'--- refresh '):
            if len(observed['refresh_ns']) >= 10000:
                observed['error'] = 'collector refresh inventory exceeds bound'
                return
            observed['refresh_ns'].append(str(time.monotonic_ns()))


COLLECTOR_STDERR_LOG = 'collector-stderr.log'
COLLECTOR_STDERR_LIMIT = 65536
COLLECTOR_STDERR_LOG_LIMIT = COLLECTOR_STDERR_LIMIT + 4096
FORENSICS_WARNINGS_LOG = 'forensics-copy-warnings.log'
OBSERVATIONS_LIMIT = 16 * 1024**2


def _drain_bounded(stream, buf, limit):
    """Drain a pipe into buf keeping the last limit bytes; total."""
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            buf.extend(chunk)
            if len(buf) > limit:
                del buf[:len(buf) - limit]
    except Exception:
        return


def _persist_collector_stderr(work, argv, status, err_reader, err_buf,
                              state):
    """Persist bounded collector stderr for forensics; never raises.

    Joins the drain, writes work/COLLECTOR_STDERR_LOG (the
    buffer is already bound at the drain, so the file keeps
    the tail verbatim), and sets state['collector_stderr_tail'].
    Collector stdout streams through the readiness watcher,
    so the log's stdout section stays empty by design. A
    write failure records state['collector_stderr_log_error']
    and keeps the tail, which the caller also carries in the
    exception message, so the cause survives even when the
    log write itself fails. Failure-path only: passing legs
    keep no such keys.
    """
    try:
        if err_reader is not None:
            err_reader.join(timeout=5)
    except Exception:
        pass
    try:
        captured = bytes(err_buf)
        state['collector_stderr_tail'] = _forensics_tail(captured)
        _write_bounded_log(Path(work) / COLLECTOR_STDERR_LOG, argv,
                           status, b'', captured, None)
    except Exception as exc:
        state['collector_stderr_log_error'] = type(exc).__name__


def leg(binary, disk, mode, work, seconds, pool=False, observation=None, nonce=None):
    state = {} if observation is None else observation
    before = inventory()
    state.update(mode=mode, bpf_before=before, product_exit=None, cleanup_errors=[])
    capture = work / 'capture'
    proc, primary, reader, err_reader, pool_oracle = None, None, None, None, None
    argv, err_buf = None, bytearray()
    try:
        if mode != 'off':
            observed = {'ready': False, 'refresh_ns': [], 'error': None}
            state['output'] = observed
            argv = product_command(binary, mode, capture, seconds + 120)
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            reader = threading.Thread(target=observe_output, args=(proc.stdout, observed), daemon=True)
            reader.start()
            err_reader = threading.Thread(target=_drain_bounded, args=(proc.stderr, err_buf, COLLECTOR_STDERR_LIMIT), daemon=True)
            err_reader.start()
            deadline = time.monotonic() + 60
            while True:
                if proc.poll() is not None:
                    state['product_exit'] = proc.returncode
                    _persist_collector_stderr(work, argv, proc.returncode,
                                              err_reader, err_buf, state)
                    raise ProductExit(proc.returncode, 'collector exited before readiness: exit',
                                      detail=state.get('collector_stderr_tail', ''))
                if observed['error']: raise ValueError(observed['error'])
                if observed['ready']: break
                if time.monotonic() >= deadline: raise ValueError('collector readiness timed out')
                time.sleep(.1)
        if pool:
            pool_oracle = PoolReadOracle(proc, binary, nonce)
            state['pool_oracle'] = pool_oracle.observation
        state['warmup'] = workload(disk, 10, proc, oracle=pool_oracle)
        state['workload'] = workload(disk, seconds, proc, pool_case=pool, oracle=pool_oracle)
        if pool_oracle is not None:
            pool_oracle.check()
            pool_oracle.close()
        if proc is not None:
            state['stop_signal_ns'] = str(time.monotonic_ns())
            proc.send_signal(signal.SIGTERM)
            state['product_exit'] = proc.wait(timeout=30)
            require_product_exit(state['product_exit'])
            reader.join(timeout=5)
            if reader.is_alive() or observed['error']: raise ValueError('collector output inventory incomplete')
            if mode == 'live-top-1s':
                validate_top_refreshes(observed['refresh_ns'], state['workload']['window'])
            state['capture'] = capture_facts(binary, capture, pool, state.get('pool_oracle'),
                                             state['workload']['window'], state['stop_signal_ns'])
        else:
            state['capture'] = None
        state['bpf_after'] = settled(before)
        return state
    except BaseException as exc:
        primary = exc
        if isinstance(exc, ProductExit): state['product_exit'] = exc.product_exit
        if proc is not None and 'collector_stderr_tail' not in state:
            status = proc.returncode if proc.poll() is not None else 'running'
            _persist_collector_stderr(work, argv, status, err_reader,
                                      err_buf, state)
        raise
    finally:
        cleanup_failure = None
        def cleanup(action):
            nonlocal cleanup_failure
            try: action()
            except BaseException as exc:
                state['cleanup_errors'].append(type(exc).__name__)
                if cleanup_failure is None: cleanup_failure = exc
        if pool_oracle is not None: cleanup(pool_oracle.close)
        def stop_product():
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=10)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=10)
        cleanup(stop_product)
        def stop_reader():
            if reader is not None:
                reader.join(timeout=5)
                if reader.is_alive(): raise ValueError('collector output reader cleanup incomplete')
                proc.stdout.close()
        cleanup(stop_reader)
        def stop_err_reader():
            if err_reader is not None:
                err_reader.join(timeout=5)
                if err_reader.is_alive(): raise ValueError('collector stderr reader cleanup incomplete')
                proc.stderr.close()
        cleanup(stop_err_reader)
        def settle(): state['bpf_after'] = settled(before)
        cleanup(settle)
        if primary is None and cleanup_failure is not None: raise cleanup_failure


CAPTURE_LIMITS = {'events.ndjson': 1024**3, 'session.json': 16 * 1024**2,
                  'checkpoint.json': 16 * 1024**2, 'checkpoint.json.tmp': 16 * 1024**2,
                  'session.finalizing': 16 * 1024**2}


def _ensure_dir_mode(path, mode):
    os.chmod(path, mode)
    if stat.S_IMODE(os.stat(path).st_mode) != mode:
        raise ValueError('evidence directory mode differs: ' + str(path))


def _ensure_dir_fd_mode(fd, label, mode):
    os.fchmod(fd, mode)
    if stat.S_IMODE(os.fstat(fd).st_mode) != mode:
        raise ValueError('evidence directory mode differs: ' + label)


def _copy_evidence_file(src_dir_fd, dst_dir_fd, name, limit):
    """Copy one allowlisted evidence file; return its receipt record.

    Fail-closed like the export path always was: the source
    must be an owned regular file reached without aliases,
    the destination is created exclusive with private mode,
    bytes stream bounded by limit, and the enforced mode is
    read back, never assumed. Raises FileNotFoundError when
    the source is absent (the caller decides skip vs fail).
    """
    source_fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=src_dir_fd)
    with os.fdopen(source_fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('failure evidence is not an owned regular file')
        target_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dst_dir_fd)
        with os.fdopen(target_fd, 'wb') as target:
            os.fchmod(target.fileno(), 0o600)
            if stat.S_IMODE(os.fstat(target.fileno()).st_mode) != 0o600:
                raise ValueError('evidence copy mode differs: ' + name)
            digest, count = hashlib.sha256(), 0
            while count < limit:
                data = source.read(min(65536, limit - count))
                if not data: break
                target.write(data); digest.update(data); count += len(data)
        return {'bytes': str(count), 'sha256': digest.hexdigest(), 'truncated': info.st_size > limit}


def retain_capture(work, destination):
    destination.mkdir(mode=0o700)
    _ensure_dir_mode(destination, 0o700)
    copied = {}
    work_fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    dest_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    capture_fd = None
    try:
        try: capture_fd = os.open('capture', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=work_fd)
        except FileNotFoundError: return copied
        for name, limit in CAPTURE_LIMITS.items():
            try:
                copied[name] = _copy_evidence_file(capture_fd, dest_fd,
                                                   name, limit)
            except FileNotFoundError:
                continue
        return copied
    finally:
        if capture_fd is not None: os.close(capture_fd)
        os.close(work_fd); os.close(dest_fd)


def write_observations(path, state):
    data = (json.dumps(state, sort_keys=True) + '\n').encode()
    if len(data) > OBSERVATIONS_LIMIT: raise ValueError('observations exceed document bound')
    with path.open('xb') as stream: stream.write(data)


def copy_leg_forensics(work, forensics):
    """Mirror a leg work dir to host-visible forensics; return warnings.

    Copies the allowlisted capture files plus the leg receipts
    (observations.json, the collector stderr log when present)
    from the overlay work dir to the mount-backed forensics dir,
    enforcing the same 0700/0600 modes the export path uses.
    Copies what exists: absent files are skipped, and every
    per-file or directory failure becomes a warning string,
    never an exception. The caller logs the returned warnings;
    the leg verdict never depends on this copy. A warnings log
    is also left beside the mirror when anything degraded.
    """
    warnings = []
    work, forensics = Path(work), Path(forensics)
    try:
        forensics.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        return ['forensics dir unwritable: %s: %s' % (forensics, exc)]
    try:
        _ensure_dir_mode(forensics, 0o700)
    except (OSError, ValueError) as exc:
        warnings.append('forensics dir mode differs: %s: %s'
                        % (forensics, exc))
    try:
        work_fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        warnings.append('leg work unreadable: %s: %s' % (work, exc))
        _write_forensics_warnings(forensics, warnings)
        return warnings
    try:
        try:
            dest_fd = os.open(forensics, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            warnings.append('forensics dir unreadable: %s: %s'
                            % (forensics, exc))
            _write_forensics_warnings(forensics, warnings)
            return warnings
        try:
            _mirror_capture_dir(work_fd, dest_fd, warnings)
            for name, limit in (('observations.json', OBSERVATIONS_LIMIT),
                                (COLLECTOR_STDERR_LOG,
                                 COLLECTOR_STDERR_LOG_LIMIT)):
                _mirror_one_file(work_fd, dest_fd, name, limit, warnings)
        finally:
            os.close(dest_fd)
    finally:
        os.close(work_fd)
    _write_forensics_warnings(forensics, warnings)
    return warnings


def _mirror_one_file(src_fd, dst_fd, name, limit, warnings):
    try:
        receipt = _copy_evidence_file(src_fd, dst_fd, name, limit)
    except FileNotFoundError:
        return
    except (OSError, ValueError) as exc:
        warnings.append('%s not mirrored: %s' % (name, exc))
        return
    if receipt['truncated']:
        warnings.append('%s exceeds mirror bound; truncated' % name)


def _mirror_capture_dir(work_fd, dest_fd, warnings):
    try:
        capture_fd = os.open('capture', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=work_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        warnings.append('capture dir unreadable: %s' % exc)
        return
    try:
        try:
            os.mkdir('capture', 0o700, dir_fd=dest_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            warnings.append('capture mirror unwritable: %s' % exc)
            return
        else:
            try:
                os.chmod('capture', 0o700, dir_fd=dest_fd)
            except OSError as exc:
                warnings.append('capture mirror unwritable: %s' % exc)
                return
        try:
            cap_fd = os.open('capture', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dest_fd)
        except OSError as exc:
            warnings.append('capture mirror unreadable: %s' % exc)
            return
        try:
            try:
                _ensure_dir_fd_mode(cap_fd, 'capture', 0o700)
            except (OSError, ValueError) as exc:
                warnings.append('capture mirror mode differs: %s' % exc)
            for name, limit in CAPTURE_LIMITS.items():
                _mirror_one_file(capture_fd, cap_fd, name, limit, warnings)
        finally:
            os.close(cap_fd)
    finally:
        os.close(capture_fd)


def _write_forensics_warnings(forensics, warnings):
    if not warnings:
        return
    try:
        (Path(forensics) / FORENSICS_WARNINGS_LOG).write_text(
            ''.join(line + '\n' for line in warnings))
    except OSError:
        pass


def _cleanup_overlay_work(work):
    """Best-effort removal of overlay leg work after its copies landed."""
    try:
        if Path(work).is_symlink():
            raise ValueError('overlay work is an alias')
        shutil.rmtree(work)
    except (OSError, ValueError) as exc:
        print('candidate live campaign: overlay work cleanup failed: %s: %s'
              % (work, exc), file=sys.stderr)


def record_leg(binary, disk, mode, seconds, pool, local, export, ordinal, nonce=None, *, scratch):
    """Run one leg on overlay work, mirroring forensics to the mount.

    The collector records under scratch/leg-N on the
    guest-local overlay (creations on the mount-backed dirs
    map to another uid, which the product's capture-dir
    ownership guard refuses); the export keeps its verified
    shape via retain_capture, and a best-effort mirror of
    the work dir lands at local/leg-N so per-leg forensics
    stay host-visible on success and failure alike. The
    mirror never affects the verdict: copy problems are
    warnings on stderr, and the overlay work is dropped
    only after clean copies on a passing leg.
    """
    work = Path(scratch) / ('leg-' + str(ordinal))
    work.mkdir(mode=0o700)
    _ensure_dir_mode(work, 0o700)
    forensics = Path(local) / ('leg-' + str(ordinal))
    state = {'ordinal': str(ordinal), 'mode': mode, 'status': 'RUNNING'}
    primary = None
    try:
        leg(binary, disk, mode, work, seconds, pool, observation=state, nonce=nonce)
        state['status'] = 'PASS'
    except BaseException as exc:
        primary = exc
        state.update(status='FAIL', exception=type(exc).__name__)
        if isinstance(exc, ProductExit): state['product_exit'] = exc.product_exit
    destination = export / (('failed-' if primary else 'completed-') + str(ordinal))
    try:
        destination.mkdir(mode=0o700)
        state['retained_capture'] = retain_capture(work, destination / 'capture')
        if primary is None and any(row['truncated'] for row in state['retained_capture'].values()):
            raise ValueError('verified capture export exceeds evidence bound')
        state['retained_verification'] = 'unverified-failure' if primary else 'verified-capture'
        write_observations(destination / 'observations.json', state)
    except BaseException as exc:
        state['export_error'] = type(exc).__name__
        state['status'] = 'FAIL'
        if primary is None: primary = exc
    try: write_observations(work / 'observations.json', state)
    except BaseException as exc:
        state['local_receipt_error'] = type(exc).__name__
        if primary is None: primary = exc
    mirror_warnings = []
    if work != forensics:
        mirror_warnings = copy_leg_forensics(work, forensics)
        for warning in mirror_warnings:
            print('candidate live campaign: ' + warning, file=sys.stderr)
    if primary is None and not mirror_warnings and work != forensics:
        _cleanup_overlay_work(work)
    if primary is not None:
        primary.observation = state
        raise primary
    return state


def guest_mac(token):
    return '52:54:00:' + ':'.join(token[i:i+2] for i in (10, 12, 14))


def validate_guest_identity(token, cmdline, guest_boot, host_boot, serial, sectors, mac, mounted):
    if (not re.fullmatch('[0-9a-f]{16}', token or '') or
            'memveil_candidate_guest=' + token not in cmdline or 'swiotlb=force' not in cmdline or
            not guest_boot or not host_boot or guest_boot == host_boot or serial != 'mv-' + token or
            sectors != 131072 or mac.lower() != guest_mac(token) or mounted):
        raise ValueError('owned isolated guest scratch/network identity unproved')


IDENTITY_SCAN_ATTEMPTS = 11
IDENTITY_SCAN_INTERVAL = 0.5
# Block-device name prefixes that can never be the owned
# scratch disk: the owned disk is nvme with the token serial
# by construction (host() attaches exactly one nvme device
# carrying serial mv-<token>), while sr* are SCSI optical
# drives. An sr drive with no medium raises persistent
# read-time ENXIO on device/serial, which no retry can fix.
OPTICAL_BLOCK_PREFIXES = ('sr',)


def _transient_sysfs(error):
    """Whether a sysfs read error is a rename flap worth one more scan.

    Only ENXIO (a stale dentry read mid-rename) and ENOENT
    (an entry vanished mid-scan) retry; anything else
    (permissions, I/O errors) raises immediately, as before.
    """
    if not isinstance(error, OSError):
        return False
    return error.errno in (errno.ENXIO, errno.ENOENT)


def scan_sysfs_matches(root, attribute, value, label, missing_ok=False,
                       skip_prefixes=()):
    """Entries under root whose attribute file reads value.

    One clean pass returns the exact match list; a pass
    interrupted by a concurrent rename (coldplug brings an
    interface up or renames it while the scan reads) sleeps
    and rescans from scratch, bounded by
    IDENTITY_SCAN_ATTEMPTS passes IDENTITY_SCAN_INTERVAL
    apart (udev settle is seconds-scale while the campaign
    timeout is hours, so a few seconds here cost nothing,
    and a stable tree never sleeps). Predicate mismatches
    never retry: absence and ambiguity return 0/2 matches
    for the caller's unchanged exactly-one check.
    missing_ok skips entries whose attribute is legitimately
    absent (serial-less disks) instead of treating ENOENT as
    a flap. skip_prefixes excludes entries that cannot be
    the owned node by type: their attribute is never read,
    so a persistently unreadable excluded entry (an sr
    optical drive with no medium raises read-time ENXIO on
    every pass, which no retry can fix) cannot abort the
    scan. Everything else stays strict: an unreadable
    non-excluded entry still fails the scan closed after
    retries, and exhaustion raises the last flap chained
    under the scan label, so the next abort names which
    access raised.
    """
    last = None
    for attempt in range(IDENTITY_SCAN_ATTEMPTS):
        try:
            matches = []
            for entry in root.iterdir():
                if entry.name.startswith(skip_prefixes):
                    continue
                try:
                    text = (entry / attribute).read_text()
                except OSError as error:
                    if missing_ok and isinstance(error, FileNotFoundError):
                        continue
                    raise
                if text.strip() == value:
                    matches.append(entry)
            return matches
        except OSError as error:
            if not _transient_sysfs(error):
                raise
            last = error
            if attempt + 1 < IDENTITY_SCAN_ATTEMPTS:
                time.sleep(IDENTITY_SCAN_INTERVAL)
    raise OSError('guest %s: sysfs still renaming after %d scans: %s: %s'
                  % (label, IDENTITY_SCAN_ATTEMPTS, root, last)) from last


def read_sysfs_text(path, label):
    """One sysfs attribute read, tolerant of concurrent renames.

    Same transient set and bound as scan_sysfs_matches,
    for re-reads of an already-selected node; exhaustion
    names the path and the label instead of aborting raw.
    """
    last = None
    for attempt in range(IDENTITY_SCAN_ATTEMPTS):
        try:
            return path.read_text()
        except OSError as error:
            if not _transient_sysfs(error):
                raise
            last = error
            if attempt + 1 < IDENTITY_SCAN_ATTEMPTS:
                time.sleep(IDENTITY_SCAN_INTERVAL)
    raise OSError('guest %s: sysfs read still failing after %d tries: %s: %s'
                  % (label, IDENTITY_SCAN_ATTEMPTS, path, last)) from last


def verify_installed(manifest, root=Path('/')):
    """Refuse unless the installed tree matches the candidate closure.

    Every manifest file must exist at its installed destination
    with the pinned bytes, reached without aliases; memveil
    prefixes must carry no extra runtime files. Unrelated
    system paths are ignored.
    """
    from support.candidate_input import candidate
    if root.is_symlink(): raise ValueError('installed root is an alias')
    expected = {}
    for name, pinned in manifest['files'].items():
        relative = candidate.installed_file_path(name)
        expected[relative] = pinned
        source = root / relative
        for parent in (source, *source.parents):
            if parent == root: break
            if parent.is_symlink(): raise ValueError('installed candidate contains an alias')
        if source.is_symlink(): raise ValueError('installed candidate contains an alias')
        if not source.is_file(): raise ValueError('installed candidate file absent')
        if candidate.digest(source) != pinned:
            raise ValueError('installed candidate file differs: ' + name)
    generated = {'usr/share/doc/memveil/copyright', 'usr/share/doc/memveil/changelog.Debian.gz'}
    for prefix in ('usr/lib/memveil', 'usr/share/memveil', 'usr/share/doc/memveil'):
        if (root / prefix).is_symlink(): raise ValueError('installed prefix is an alias')
        for source in (root / prefix).rglob('*'):
            if source.is_symlink(): raise ValueError('installed candidate contains an alias')
            if not source.is_file(): continue
            if source.relative_to(root).as_posix() not in expected \
                    and source.relative_to(root).as_posix() not in generated:
                raise ValueError('extra installed candidate runtime file')


INSTALLED_BINARY = Path('/usr/bin/memveil')


def verify_installed_binary(manifest, binary=INSTALLED_BINARY):
    """Refuse unless the installed binary is the sealed bytes that run.

    Hash first: sha256(installed binary) must equal the
    manifest bin/memveil pin, no exceptions, reached without
    aliases. Then execute `binary --version`: exit 0 with
    version output proves the measured bytes run as the
    engine, never mere existence. This is the post-install
    identity gate whatever installer placed the bytes; the
    per-leg verify_installed re-hashes the same binary
    between legs, so executability need only be proved at
    the campaign boundaries.
    """
    from support.candidate_input import candidate
    pinned = manifest['files'].get('bin/memveil')
    if pinned is None:
        raise ValueError('installed binary has no pinned digest')
    target = Path(binary)
    if target.is_symlink():
        raise ValueError('installed binary is an alias')
    if not target.is_file():
        raise ValueError('installed binary absent')
    if candidate.digest(target) != pinned:
        raise ValueError('installed binary differs from the sealed candidate')
    proc = subprocess.run([str(target), '--version'],
                          capture_output=True, timeout=60)
    if proc.returncode != 0 or not proc.stdout.strip():
        raise ValueError(
            'installed binary identity unproved: --version refused')


def journal_admission(binary, capability=JOURNAL_CAPABILITY):
    """Passive doctor verdict for one capability as (admitted, reason).

    Exit 0 admits; exit 3 (unavailable or unknown) declines with a
    recorded reason; any other exit raises instead of silently
    skipping a campaign row.
    """
    proc = subprocess.run([str(binary), 'doctor', '--capability', capability],
                          capture_output=True, timeout=120)
    if proc.returncode == 0: return True, ''
    if proc.returncode == 3:
        return False, capability + ' not admitted by this build (doctor exit 3)'
    raise ValueError('capability admission check failed for %s: exit %d'
                     % (capability, proc.returncode))


def run_overhead(one, result, admit):
    """Five paired runs per mode; unadmitted journal modes skip with reason.

    The admission probe runs once per journal mode up front: a
    declined mode contributes skip rows and no legs, while every
    other mode runs its full paired schedule.
    """
    skipped = {}
    for mode in MODES:
        if mode in JOURNAL_MODES:
            admitted, reason = admit(mode)
            if not admitted:
                skipped[mode] = reason
    pairs = {mode: ([], []) for mode in MODES if mode not in skipped}
    for mode, pair in schedule():
        if mode in skipped: continue
        order = ('off', mode) if pair % 2 == 0 else (mode, 'off')
        observations = {label: one(label, 60) for label in order}
        pairs[mode][0].append(observations['off'])
        pairs[mode][1].append(observations[mode])
    for mode, (baselines, observers) in pairs.items():
        for metric in ('block', 'network'):
            comparison = compare(mode + '/' + metric,
                [row['workload']['metrics'][metric] for row in baselines],
                [row['workload']['metrics'][metric] for row in observers])
            status, reason = assess(comparison)
            result['comparisons'].append({'mode': mode, 'metric': metric, 'status': status,
                'reason': reason, 'measurement': comparison,
                'target_required': True})
    for mode, reason in skipped.items():
        for metric in ('block', 'network'):
            result['comparisons'].append({'mode': mode, 'metric': metric, 'status': 'SKIP',
                'reason': reason, 'target_required': True})


def require_campaign_targets(comparisons):
    """Fail required rows that did not pass; skips need a journal reason.

    A skip row is an explicit not-run, never a pass: only journal
    modes may skip, and only with a recorded admission reason.
    """
    for row in comparisons:
        if row['status'] == 'SKIP':
            if row['mode'] not in JOURNAL_MODES:
                raise ValueError('non-journal comparison skipped: ' + row['mode'])
            if not row.get('reason'):
                raise ValueError('journal comparison skipped without reason: ' + row['mode'])
        elif row.get('target_required') and row['status'] != 'PASS':
            raise ValueError('summary overhead target failed')


CAMPAIGN_JSON_LIMIT = 256 * 1024**2


def campaign_totals(result):
    """Campaign-level scalar totals for gate measurements.

    Counts legs, non-passing legs, required rows that
    neither passed nor skipped, and cleanup mismatches
    (campaign plus per-leg BPF inventory). All values are
    canonical decimal strings; honest campaigns read
    legs=N with every other count zero.
    """
    legs = result.get('legs', [])
    failed = sum(1 for leg in legs if leg.get('status') != 'PASS')
    target_failures = sum(
        1 for row in result.get('comparisons', [])
        if row.get('target_required') and row.get('status') not in ('PASS', 'SKIP'))
    cleanup = result.get('cleanup', {})
    mismatches = sum(1 for leg in legs if leg.get('bpf_after') != leg.get('bpf_before'))
    if cleanup.get('before') != cleanup.get('after'):
        mismatches += 1
    return {'legs': str(len(legs)), 'failed_legs': str(failed),
            'target_failures': str(target_failures),
            'cleanup_mismatches': str(mismatches)}


def rederived_metric(window, metric):
    """Throughput/p99 re-derived from retained operation bytes.

    The cached throughput/p99 in a campaign export are guest
    claims; the retained evidence is completed_units,
    operation_seconds, and the window. Re-derivation repeats
    the collector's exact arithmetic (units over elapsed,
    nearest-rank p99 over the operation latencies), so
    honest bytes reproduce the cached values bit for bit
    while a tampered cache refuses. Value bounds (elapsed,
    counts) belong to the window check; this helper only
    refuses misshapen retention that would crash the
    arithmetic. Raises ValueError otherwise.
    """
    if not isinstance(metric, dict):
        raise ValueError('campaign workload metric differs')
    start, end = int(window['start_ns']), int(window['end_ns'])
    elapsed = (end - start) / 10**9
    if elapsed <= 0:
        raise ValueError('campaign workload window differs')
    seconds = metric.get('operation_seconds')
    if not isinstance(seconds, list) or not seconds:
        raise ValueError('campaign workload operations absent')
    for sample in seconds:
        if type(sample) not in (int, float) \
                or not math.isfinite(sample) or sample < 0:
            raise ValueError(
                'campaign workload operations differ')
    units = int(metric['completed_units'])
    ordered = sorted(seconds)
    return {'throughput': units / elapsed,
            'p99': ordered[math.ceil(.99 * len(ordered)) - 1]}


def _verify_workload_window(observation, required_seconds):
    from support.candidate_input import candidate
    candidate.exact(observation, {'elapsed_seconds', 'window', 'metrics', 'samples'},
                    'campaign workload')
    window = observation['window']
    candidate.exact(window, {'start_ns', 'end_ns'}, 'campaign window')
    metrics = observation['metrics']
    candidate.exact(metrics, {'block', 'network'}, 'campaign metrics')
    for kind in ('block', 'network'):
        candidate.exact(metrics[kind], {'valid', 'counts_ok', 'throughput', 'p99',
                                       'completed_units', 'operation_seconds'},
                        'campaign metric')
        if metrics[kind].get('valid') is not True \
                or metrics[kind].get('counts_ok') is not True:
            raise ValueError('campaign workload invalid: ' + kind)
    elapsed = (int(window['end_ns']) - int(window['start_ns'])) / 10**9
    validate_duration(required_seconds, elapsed,
                      int(metrics['block']['completed_units']),
                      int(metrics['network']['completed_units']))
    if not isinstance(observation['elapsed_seconds'], (int, float)) \
            or abs(observation['elapsed_seconds'] - elapsed) > 0.001:
        raise ValueError('campaign workload clock differs')
    if not isinstance(observation['samples'], list):
        raise ValueError('campaign workload samples differ')
    for sample in observation['samples']:
        candidate.exact(sample, {'elapsed_monotonic_ns', 'rss_kib', 'fd_count',
                                 'map_memlock_bytes'}, 'campaign sample')
        if int(sample['rss_kib']) > 256 * 1024:
            raise ValueError('campaign userspace RSS exceeded 256 MiB')
    for kind in ('block', 'network'):
        derived = rederived_metric(window, metrics[kind])
        for field in ('throughput', 'p99'):
            if metrics[kind][field] != derived[field]:
                raise ValueError(
                    'campaign workload %s differs from '
                    'retained operations: %s' % (field, kind))


def _verify_leg_events(data):
    kinds = {}
    pool_samples = []
    for raw in data.splitlines(keepends=True):
        if len(raw) > 65536:
            raise ValueError('campaign event exceeds line bound')
        if not raw.strip():
            continue
        event = json.loads(raw)
        if not isinstance(event, dict) or 'kind' not in event:
            raise ValueError('campaign event shape differs')
        kind = event['kind']
        kinds[kind] = kinds.get(kind, 0) + 1
        if kind == 'pool_sample':
            if len(pool_samples) >= 4096 + 64 + 2:
                raise ValueError('campaign pool inventory exceeds source bound')
            if 'ts_ns' not in event:
                raise ValueError('campaign pool sample shape differs')
            pool_samples.append(event['ts_ns'])
    return {key: str(value) for key, value in kinds.items()}, pool_samples


def _verify_leg_files(base, ordinal, leg):
    from support.candidate_input import candidate
    slot = base / ('completed-' + str(ordinal))
    if not slot.is_dir() or slot.is_symlink():
        raise ValueError('campaign leg inventory differs: ' + str(ordinal))
    names = set()
    for name in os.listdir(slot):
        if (slot / name).is_symlink():
            raise ValueError('campaign leg refuses aliases')
        names.add(name)
    if names != {'observations.json', 'capture'}:
        raise ValueError('campaign leg inventory differs: ' + str(ordinal))
    if not (slot / 'capture').is_dir() \
            or not (slot / 'observations.json').is_file():
        raise ValueError('campaign leg inventory differs: ' + str(ordinal))
    try:
        recorded = json.loads(candidate.read_regular(slot / 'observations.json'),
                              object_pairs_hook=candidate.unique)
    except OSError:
        raise ValueError('campaign leg observations unreadable: ' + str(ordinal))
    if recorded != leg:
        raise ValueError('campaign leg differs from retained observations: '
                         + str(ordinal))
    retained = leg.get('retained_capture', {})
    if not isinstance(retained, dict):
        raise ValueError('campaign leg retained inventory differs: ' + str(ordinal))
    capture = slot / 'capture'
    found = set()
    for name in os.listdir(capture):
        if (capture / name).is_symlink():
            raise ValueError('campaign capture refuses aliases')
        found.add(name)
    if found != set(retained):
        raise ValueError('campaign capture inventory differs: ' + str(ordinal))
    files = {}
    for name, record in retained.items():
        if name not in CAPTURE_LIMITS:
            raise ValueError('campaign capture refuses unknown file: ' + name)
        candidate.exact(record, {'bytes', 'sha256', 'truncated'}, 'retained capture')
        candidate.hexid(record['sha256'])
        if not isinstance(record.get('truncated'), bool):
            raise ValueError('campaign capture truncation differs: ' + name)
        path = capture / name
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('campaign capture is not an owned regular file: ' + name)
        if info.st_size > CAPTURE_LIMITS[name]:
            raise ValueError('campaign capture exceeds evidence bound: ' + name)
        data = path.read_bytes()
        if len(data) != candidate.parse_size(record['bytes']) \
                or hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError('campaign capture file changed: ' + name)
        files[name] = data
    return files


def _verify_leg_content(ordinal, leg, files):
    from support.candidate_input import candidate
    if leg.get('status') != 'PASS':
        raise ValueError('campaign leg did not pass: ' + str(ordinal))
    if leg.get('mode') != 'off' and leg.get('product_exit') != 0:
        raise ValueError('campaign leg exit differs: ' + str(ordinal))
    if leg.get('retained_verification') != 'verified-capture':
        raise ValueError('campaign leg capture unverified: ' + str(ordinal))
    if leg.get('cleanup_errors'):
        raise ValueError('campaign leg cleanup failed: ' + str(ordinal))
    if leg.get('bpf_after') != leg.get('bpf_before'):
        raise ValueError('campaign leg BPF inventory differs: ' + str(ordinal))
    mode = leg.get('mode')
    pooled = 'pool_oracle' in leg
    keys = {'ordinal', 'mode', 'status', 'bpf_before', 'bpf_after', 'product_exit',
            'cleanup_errors', 'warmup', 'workload', 'capture',
            'retained_capture', 'retained_verification'}
    if mode != 'off':
        keys |= {'output', 'stop_signal_ns'}
    if pooled:
        keys |= {'pool_oracle'}
    candidate.exact(leg, keys, 'campaign leg')
    _verify_workload_window(leg['warmup'], 10)
    _verify_workload_window(leg['workload'], POOL_SECONDS if pooled else 60)
    if mode == 'off':
        if leg['capture'] is not None or leg['product_exit'] is not None:
            raise ValueError('campaign off leg captured: ' + str(ordinal))
        if pooled:
            raise ValueError('campaign off leg carries a pool oracle: ' + str(ordinal))
        return
    output = leg['output']
    candidate.exact(output, {'ready', 'refresh_ns', 'error'}, 'campaign leg output')
    if output.get('error'):
        raise ValueError('campaign leg output incomplete: ' + str(ordinal))
    if output.get('ready') is not True:
        raise ValueError('campaign leg readiness unproved: ' + str(ordinal))
    if not isinstance(output.get('refresh_ns'), list):
        raise ValueError('campaign leg refresh inventory differs: ' + str(ordinal))
    if mode == 'live-top-1s':
        validate_top_refreshes(output['refresh_ns'], leg['workload']['window'])
    capture = leg['capture']
    candidate.exact(capture, {'quality', 'stop', 'kinds', 'session_sha256',
                              'events_sha256'}, 'campaign leg capture')
    if 'session.json' not in files or 'events.ndjson' not in files:
        raise ValueError('campaign leg capture files absent: ' + str(ordinal))
    if set(capture.get('quality', {})) != {'detail', 'aggregate', 'correlation',
                                           'baseline', 'terminal'}:
        raise ValueError('campaign leg quality inventory differs: ' + str(ordinal))
    session = json.loads(files['session.json'], object_pairs_hook=candidate.unique)
    if session.get('quality') != capture.get('quality') \
            or session.get('stop') != capture.get('stop'):
        raise ValueError('campaign leg capture differs from retained session: '
                         + str(ordinal))
    for channel in ('detail', 'aggregate', 'correlation', 'baseline', 'terminal'):
        value = capture['quality'][channel]
        if value.get('loss_count') not in ('0', None):
            raise ValueError('campaign leg channel loss: ' + channel)
        if value.get('status') not in ('complete_for_scope', 'not_applicable',
                                       'unavailable'):
            raise ValueError('campaign leg channel incomplete: ' + channel)
    if capture.get('session_sha256') != hashlib.sha256(files['session.json']).hexdigest():
        raise ValueError('campaign leg session digest differs: ' + str(ordinal))
    kinds, pool_samples = _verify_leg_events(files['events.ndjson'])
    if kinds != capture.get('kinds'):
        raise ValueError('campaign leg event inventory differs: ' + str(ordinal))
    if capture.get('events_sha256') != hashlib.sha256(files['events.ndjson']).hexdigest():
        raise ValueError('campaign leg events digest differs: ' + str(ordinal))
    if kinds.get('bounce_attempt', '0') == '0' \
            and kinds.get('transition_result', '0') == '0':
        raise ValueError('campaign leg has no workload observations: ' + str(ordinal))
    if pooled:
        validate_pool(pool_samples, leg['workload']['window'],
                      leg['pool_oracle'], leg['stop_signal_ns'])


def _verify_overhead_targets(legs, comparisons):
    from support.candidate_input import candidate
    for row in comparisons:
        keys = {'mode', 'metric', 'status', 'reason', 'target_required'}
        if row.get('status') != 'SKIP':
            keys |= {'measurement'}
        candidate.exact(row, keys, 'campaign comparison')
    cells = {(row.get('mode'), row.get('metric')) for row in comparisons}
    expected = {(mode, metric) for mode in MODES for metric in ('block', 'network')}
    if cells != expected:
        raise ValueError('campaign comparison inventory differs')
    require_campaign_targets(comparisons)
    skipped = {row['mode'] for row in comparisons if row['status'] == 'SKIP'}
    want = []
    for mode, pair in schedule():
        if mode in skipped:
            continue
        order = ('off', mode) if pair % 2 == 0 else (mode, 'off')
        want.extend(order)
    if [leg.get('mode') for leg in legs] != want:
        raise ValueError('campaign leg schedule differs')
    pairs = {mode: ([], []) for mode in MODES if mode not in skipped}
    index = 0
    for mode, pair in schedule():
        if mode in skipped:
            continue
        first, second = legs[index], legs[index + 1]
        index += 2
        observations = {first['mode']: first, second['mode']: second}
        pairs[mode][0].append(observations['off'])
        pairs[mode][1].append(observations[mode])
    for row in comparisons:
        if row['status'] == 'SKIP':
            continue
        if row.get('target_required') is not True:
            raise ValueError('campaign comparison target flag differs')
        baselines, observers = pairs[row['mode']]
        # The verdict replays from re-derived metrics, never
        # the cached values: every leg's cache already proved
        # equal to its retained operations above, and the
        # comparison consumes the re-derivation so a cache
        # that ever disagreed with its bytes could not move
        # the verdict.
        def derived(entry):
            workload = entry['workload']
            runs = dict(rederived_metric(
                workload['window'],
                workload['metrics'][row['metric']]))
            runs['valid'] = True
            runs['counts_ok'] = True
            return runs
        measurement = compare(row['mode'] + '/' + row['metric'],
            [derived(entry) for entry in baselines],
            [derived(entry) for entry in observers])
        status, reason = assess(measurement)
        if (status, reason) != (row['status'], row['reason']) \
                or measurement != row['measurement']:
            raise ValueError('campaign comparison differs from retained workloads')


def verify_live_campaign(evidence_dir, manifest, requested_mode,
                         campaign_data):
    """Re-verify one exported campaign from retained bytes; return totals.

    Checks the campaign schema and candidate binding, the exact
    export inventory (leg inventory present, no extras, no
    aliases), per-leg observations against the campaign copy,
    per-file hashes against the retained digests, and the
    predicate replay from retained bytes: capture quality and
    event inventory per leg, top cadence and pool coverage
    where measured, workload windows and RSS bounds,
    per-leg and campaign cleanup, the overhead comparison
    schedule with re-derived measurements, and soak/pool
    shapes. Guest-claimed totals must equal the recomputed
    ones. Raises ValueError on anything else; returns the
    verified totals dict (canonical decimal strings) for the
    host exit.json oracle.

    campaign_data carries the campaign.json bytes resolved
    through the caller's trust anchor (the signed source
    digests at qualification time, the fresh export at
    campaign time): the verifier opens no campaign file by
    bare path. Every other compared byte chains to those
    bytes: leg observations must equal the campaign copy,
    capture files must match the retained digests, event
    inventories must match the retained counts, and the
    progress chain fields must match the campaign header.
    The export mode must equal the requested mode: the
    export is attacker-influenced, so the caller binds what
    it asked for and a mismatch refuses. The campaign's
    source, toolchain, build receipt, and runtime files must
    equal the manifest under qualification, so a campaign
    run against another candidate refuses. Soak mixed time
    covers mixed legs only (off legs are excluded, never
    counted), every mixed leg must run the soak schedule
    (attempt-record-summary), and overlapping workload
    windows refuse (overlap would double-count time).
    """
    from support.candidate_input import candidate
    base = Path(evidence_dir)
    if base.is_symlink() or not base.is_dir():
        raise ValueError('campaign evidence root differs')
    if not isinstance(campaign_data, (bytes, bytearray)) \
            or not campaign_data \
            or len(campaign_data) > CAMPAIGN_JSON_LIMIT:
        raise ValueError('campaign evidence incomplete: campaign.json')
    result = json.loads(bytes(campaign_data),
                        object_pairs_hook=candidate.unique)
    if not isinstance(result, dict):
        raise ValueError('campaign evidence incomplete: campaign.json')
    mode = result.get('mode')
    if mode not in CAMPAIGN_MODES:
        raise ValueError('unknown live campaign mode: ' + str(mode))
    if requested_mode not in CAMPAIGN_MODES:
        raise ValueError(
            'unknown requested campaign mode: ' + str(requested_mode))
    if mode != requested_mode:
        raise ValueError(
            'campaign mode %s differs from requested %s'
            % (mode, requested_mode))
    expected_top = {'schema', 'candidate', 'mode', 'environment', 'kernel',
                    'btf_sha256', 'config_sha256', 'source', 'toolchain',
                    'build_receipt_sha256', 'runtime_files', 'helpers',
                    'legs', 'comparisons', 'cleanup', 'totals'}
    if mode == 'soak':
        expected_top |= {'mixed_seconds', 'campaign_seconds_before_pool'}
    elif mode == 'pool':
        expected_top |= {'pool'}
    candidate.exact(result, expected_top, 'campaign')
    if result['schema'] != 'memveil-installed-campaign/1':
        raise ValueError('campaign schema differs')
    if result['environment'] != 'ordinary-linux':
        raise ValueError('campaign environment differs')
    candidate_id = candidate.digest_bytes(candidate.canonical(manifest))
    if result['candidate'] != candidate_id:
        raise ValueError('campaign candidate differs')
    if result['source'] != manifest.get('source'):
        raise ValueError(
            'campaign source differs from the candidate manifest')
    if result['toolchain'] != manifest.get('toolchain'):
        raise ValueError(
            'campaign toolchain differs from the candidate manifest')
    if result['build_receipt_sha256'] != manifest.get('build_receipt_sha256'):
        raise ValueError(
            'campaign build receipt differs from the candidate manifest')
    if result['runtime_files'] != manifest.get('files'):
        raise ValueError(
            'campaign runtime files differ from the candidate manifest')
    candidate.hexid(result['btf_sha256'])
    candidate.hexid(result['config_sha256'])
    candidate.hexid(result['build_receipt_sha256'])
    candidate.exact(result['totals'], {'legs', 'failed_legs', 'target_failures',
                                      'cleanup_mismatches'}, 'campaign totals')
    for key in result['totals']:
        candidate.parse_size(result['totals'][key])
    legs = result['legs']
    if not isinstance(legs, list) or not legs \
            or any(not isinstance(leg, dict) for leg in legs):
        raise ValueError('campaign legs absent')
    if not isinstance(result['comparisons'], list):
        raise ValueError('campaign comparisons differ')
    found = set()
    for name in os.listdir(base):
        if (base / name).is_symlink():
            raise ValueError('campaign evidence refuses aliases: ' + name)
        found.add(name)
    expected_names = {'campaign.json'}
    for ordinal in range(len(legs)):
        expected_names.add('completed-' + str(ordinal))
        expected_names.add('progress-' + str(ordinal) + '.json')
    if found != expected_names:
        raise ValueError('campaign export inventory differs')
    for ordinal, leg in enumerate(legs):
        if leg.get('ordinal') != str(ordinal):
            raise ValueError('campaign leg ordinal differs')
        if not (base / ('completed-' + str(ordinal))).is_dir():
            raise ValueError('campaign leg inventory differs: ' + str(ordinal))
        files = _verify_leg_files(base, ordinal, leg)
        _verify_leg_content(ordinal, leg, files)
        progress = json.loads(candidate.read_regular(
            base / ('progress-' + str(ordinal) + '.json')),
            object_pairs_hook=candidate.unique)
        if progress.get('schema') != result['schema'] \
                or progress.get('candidate') != result['candidate'] \
                or progress.get('mode') != mode \
                or len(progress.get('legs', [])) != ordinal + 1:
            raise ValueError('campaign progress chain differs')
    cleanup = result['cleanup']
    candidate.exact(cleanup, {'before', 'after'}, 'campaign cleanup')
    if cleanup['before'] != cleanup['after']:
        raise ValueError('campaign cleanup differs')
    if mode == 'overhead':
        _verify_overhead_targets(legs, result['comparisons'])
    else:
        if result['comparisons'] != []:
            raise ValueError('campaign comparisons differ')
        pooled = [leg for leg in legs if 'pool_oracle' in leg]
        if mode == 'pool':
            if len(legs) != 1 or len(pooled) != 1:
                raise ValueError('campaign pool shape differs')
            candidate.exact(result['pool'], {'legs', 'observation'}, 'campaign pool')
            if result['pool'].get('legs') != 1 \
                    or result['pool'].get('observation') != legs[0]:
                raise ValueError('campaign pool shape differs')
        else:
            mixed = [leg for leg in legs
                     if 'pool_oracle' not in leg
                     and leg.get('mode') != 'off']
            if len(mixed) < 2 or len(pooled) != 1 \
                    or 'pool_oracle' not in legs[-1]:
                raise ValueError('campaign soak shape differs')
            for leg in mixed:
                if leg.get('mode') != 'attempt-record-summary':
                    raise ValueError(
                        'campaign soak schedule differs: '
                        + str(leg.get('mode')))
            spans = sorted(
                (int(leg['workload']['window']['start_ns']),
                 int(leg['workload']['window']['end_ns']))
                for leg in legs)
            for first, second in zip(spans, spans[1:]):
                if second[0] < first[1]:
                    raise ValueError('campaign soak windows overlap')
            measured = sum(int(leg['workload']['window']['end_ns'])
                           - int(leg['workload']['window']['start_ns'])
                           for leg in mixed) / 10**9
            claimed = result['mixed_seconds']
            if measured < SOAK_SECONDS \
                    or not isinstance(claimed, (int, float)) \
                    or abs(claimed - measured) > 0.001:
                raise ValueError('campaign soak measurement differs')
            before_pool = result['campaign_seconds_before_pool']
            if not isinstance(before_pool, (int, float)) or before_pool < measured:
                raise ValueError('campaign soak clock differs')
    recomputed = campaign_totals(result)
    if result['totals'] != recomputed:
        raise ValueError('campaign totals differ from retained legs')
    return recomputed


def guest(kind, manifest, bundle, deb, token, export, host_boot, digest, local_evidence):
    cmdline = Path('/proc/cmdline').read_text().split()
    if os.geteuid() != 0 or 'memveil_candidate_guest=' + token not in cmdline or 'swiotlb=force' not in cmdline:
        raise ValueError('owned isolated guest identity missing')
    selected = CandidateInput(dict(os.environ, MV_CANDIDATE_MANIFEST=manifest,
                                   MV_BUNDLE_TARBALL=bundle, MV_CANDIDATE_DIGEST=digest))
    from support.candidate_input import candidate
    try: entry = candidate.artifact(selected.manifest, 'deb')
    except StopIteration: raise ValueError('candidate has no deb artifact')
    candidate.verify_file(deb, entry)
    from guest_lifecycle import configure_net
    interfaces = scan_sysfs_matches(
        Path('/sys/class/net'), 'address', guest_mac(token),
        'NIC identity scan')
    if len(interfaces) != 1: raise ValueError('owned guest network identity missing or ambiguous')
    iface = interfaces[0]
    if not str((iface / 'device/driver').resolve()).endswith('/pcnet32'):
        raise ValueError('owned guest NIC driver differs')
    disks = scan_sysfs_matches(
        Path('/sys/block'), 'device/serial', 'mv-' + token,
        'scratch disk identity scan', missing_ok=True,
        skip_prefixes=OPTICAL_BLOCK_PREFIXES)
    if len(disks) != 1: raise ValueError('owned scratch disk identity missing or ambiguous')
    node = disks[0]
    disk = Path('/dev') / node.name
    if not stat.S_ISBLK(disk.stat().st_mode): raise ValueError('scratch is not a block device')
    devices = {read_sysfs_text(node / 'dev', 'identity re-read').strip()}
    devices.update(read_sysfs_text(p, 'identity re-read').strip()
                   for p in node.glob('*/dev'))
    mounted = any(line.split()[2] in devices for line in Path('/proc/self/mountinfo').read_text().splitlines())
    serial = read_sysfs_text(
        node / 'device/serial', 'identity re-read').strip()
    sectors = int(read_sysfs_text(node / 'size', 'identity re-read'))
    mac = read_sysfs_text(iface / 'address', 'identity re-read').strip()
    validate_guest_identity(token, cmdline, Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        host_boot, serial, sectors, mac, mounted)
    install_guest_deb(deb, local_evidence)
    verify_installed(selected.manifest)
    verify_installed_binary(selected.manifest)
    binary = INSTALLED_BINARY
    configure_net(iface.name)
    before = inventory()
    config = Path('/proc/config.gz')
    if not config.is_file(): config = Path('/boot') / ('config-' + os.uname().release)
    if not config.is_file(): raise ValueError('guest kernel config identity unavailable')
    result = {'schema': 'memveil-installed-campaign/1', 'candidate': selected.digest,
              'mode': kind, 'environment': 'ordinary-linux', 'kernel': os.uname().release,
              'btf_sha256': candidate.digest('/sys/kernel/btf/vmlinux'),
              'config_sha256': candidate.digest(config),
              'source': selected.manifest['source'], 'toolchain': selected.manifest['toolchain'],
              'build_receipt_sha256': selected.manifest['build_receipt_sha256'],
              'runtime_files': selected.manifest['files'],
              'helpers': {name: candidate.digest(path) for name, path in {
                  'campaign_source': Path(__file__),
                  'inventory_source': ROOT / 'tests/confidential/spikes/journal_spike.py',
                  'dd': Path(shutil.which('dd')), 'ping': Path(shutil.which('ping'))}.items()},
              'legs': [], 'comparisons': []}
    if local_evidence != '/tmp/memveil-local-evidence' or export != '/tmp/export':
        raise ValueError('owned evidence mount identity differs')
    local = Path(tempfile.mkdtemp(prefix='campaign-', dir=local_evidence))
    # Leg work stages on the guest-local overlay: creations on
    # the mount-backed dirs map to another uid, which the
    # product's capture-dir ownership guard refuses. The fixed
    # /tmp parent keeps this independent of any caller TMPDIR.
    scratch = Path(tempfile.mkdtemp(prefix='campaign-work-', dir='/tmp'))
    def one(mode, seconds, pool=False):
        verify_installed(selected.manifest)
        observation = record_leg(binary, disk, mode, seconds, pool, local, Path(export), len(result['legs']), token, scratch=scratch)
        result['legs'].append(observation)
        write_observations(Path(export) / ('progress-' + observation['ordinal'] + '.json'), result)
        return observation
    if kind == 'soak':
        run_soak(one, result)
    elif kind == 'pool':
        run_pool(one, result)
    else:
        run_overhead(one, result, admit=lambda mode: journal_admission(binary))
    result['cleanup'] = {'before': before, 'after': settled(before)}
    result['totals'] = campaign_totals(result)
    verify_installed(selected.manifest)
    verify_installed_binary(selected.manifest)
    with (Path(export) / 'campaign.json').open('x') as stream: json.dump(result, stream, sort_keys=True)
    require_campaign_targets(result['comparisons'])
    selected.close()


def _write_guest_console(out, stdout, stderr):
    """Persist a failed guest's console capture beside the receipt.

    The owned runner already holds both streams in memory,
    so the full text is cheap; a runner shape carrying none
    leaves empty files instead of failing the failure path.
    Fixed shell-inert names, siblings of export/, so the
    export inventory gate never sees them.
    """
    streams = (('guest-stdout.log', stdout), ('guest-stderr.log', stderr))
    for name, stream in streams:
        (out / name).write_text(stream if isinstance(stream, str) else '')


def host(mode, candidate=None, opts=None):
    """Run one installed-candidate campaign; return its receipt.

    The verified candidate inputs load first: without them the
    campaign refuses instead of running development bytes. A
    caller-held selection may pin the run but never replaces
    the environment inputs. The campaign runs only when armed
    for its mode (overhead needs MEMVEIL_VM_PERF=1, soak and
    pool need MEMVEIL_VM_LIVE_SOAK=1); unarmed exits 77.
    Acceptance re-verifies the export from retained bytes
    and records the verified totals in exit.json. A failed
    guest run keeps its console capture beside exit.json.
    Recognized options: out, the evidence parent (a fresh
    temporary directory by default).
    """
    selected = load(required=True)
    if candidate is not None and getattr(candidate, 'digest', None) != selected.digest:
        raise ValueError('candidate selection mismatch')
    if mode not in CAMPAIGN_MODES:
        raise ValueError('unknown live campaign mode: ' + str(mode))
    options = dict(opts) if opts else {}
    unknown = set(options) - {'out'}
    if unknown:
        raise ValueError('unknown live campaign option: ' + ', '.join(sorted(unknown)))
    armed_var = ARMED_VARS[mode]
    if os.environ.get(armed_var) != '1':
        print('SKIP: needs ' + armed_var + '=1')
        raise SystemExit(77)
    try: deb = selected.artifact('deb')
    except StopIteration: raise ValueError('candidate has no deb artifact')
    from test_attempt_capture import gate_prefix
    from vm_process import run_owned_guest
    from capture_durability import check_shell_inert_path
    prefix, _ = gate_prefix()
    lock = ROOT / 'build/vm/suite.lock'
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open('a+') as lease:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('VM suite lease already owned')
        parent = Path(options['out']) if options.get('out') else None
        if parent is not None:
            # Refused before anything is created: the run dir and
            # its fixed-name children reach the launcher command
            # raw, so the parent spelling must be shell-inert.
            check_shell_inert_path(parent, 'evidence path')
            parent.mkdir(parents=True, exist_ok=True)
        out = Path(tempfile.mkdtemp(prefix='memveil-candidate-live-', dir=str(parent) if parent else None))
        # Without --out the run dir inherits TMPDIR, which the
        # caller check above never saw; one gate covers both.
        check_shell_inert_path(out, 'evidence path')
        export = out / 'export'
        export.mkdir()
        local_evidence = out / 'local-evidence'
        local_evidence.mkdir()
        disk = out / 'scratch.raw'
        with disk.open('xb') as stream: stream.truncate(64 * 1024 * 1024)
        token = os.urandom(8).hex()
        guest_command = shlex.join([sys.executable, str(Path(__file__).resolve()), mode, '--guest',
            '--manifest', str(selected.manifest_path), '--bundle', str(selected.bundle), '--deb', str(deb),
            '--token', token, '--export', '/tmp/export', '--digest', selected.digest,
            '--local-evidence', '/tmp/memveil-local-evidence',
            '--host-boot', Path('/proc/sys/kernel/random/boot_id').read_text().strip()])
        # Microvm boots carry no pcnet NIC, so this network
        # guest needs the full machine (same flag as the
        # attempt lane's argv in test_attempt_capture and the
        # network branch of vm_boot).
        args = ['--run', '-m', '6G', '--disable-microvm',
                '--append', 'swiotlb=force memveil_candidate_guest=' + token,
                '--overlay-rwdir=/usr', '--overlay-rwdir=/etc', '--overlay-rwdir=/var',
                '--rwdir=/tmp/export=' + str(export),
                '--rwdir=/tmp/memveil-local-evidence=' + str(local_evidence), '--network', 'user',
                '--qemu-opts=-cpu host -device pcnet,netdev=pcnet0,mac=' + guest_mac(token) + ' -netdev user,id=pcnet0,net=10.0.3.0/24 '
                '-drive file=' + str(disk) + ',format=raw,if=none,id=mvowned '
                '-device nvme,drive=mvowned,serial=mv-' + token,
                '--exec', guest_command]
        try:
            print('candidate campaign evidence: ' + str(out), flush=True)
            try:
                proc = run_owned_guest(prefix + args, timeout=TIMEOUTS[mode])
            except subprocess.TimeoutExpired as exc:
                _write_guest_console(out, exc.output, exc.stderr)
                raise
            if proc.returncode:
                _write_guest_console(out, getattr(proc, 'stdout', ''),
                                     getattr(proc, 'stderr', ''))
            (out / 'exit.json').write_text(json.dumps({'guest_exit': proc.returncode, 'candidate': selected.digest}) + '\n')
            if proc.returncode: raise ValueError('guest campaign failed; receipt at ' + str(out))
            result = json.loads((export / 'campaign.json').read_bytes())
            if result['candidate'] != selected.digest or result['cleanup']['before'] != result['cleanup']['after']:
                raise ValueError('candidate receipt identity or cleanup mismatch')
            # The host anchors to its fresh export: these bytes
            # were just written by this run in this process, so
            # reading them here crosses no trust boundary. The
            # qualification path instead resolves the same bytes
            # through the signed source digests.
            totals = verify_live_campaign(
                export, selected.manifest, mode,
                (export / 'campaign.json').read_bytes())
            (out / 'exit.json').write_text(json.dumps(
                {'guest_exit': proc.returncode, 'candidate': selected.digest,
                 'totals': totals}) + '\n')
            print('candidate campaign receipt: ' + str(out))
            return {'mode': mode, 'candidate': selected.digest, 'evidence': str(out), 'campaign': result}
        finally:
            disk.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=CAMPAIGN_MODES)
    parser.add_argument('--guest', action='store_true')
    parser.add_argument('--out', default=None)
    for key in ('manifest', 'bundle', 'deb', 'token', 'export', 'host-boot', 'digest', 'local-evidence'): parser.add_argument('--' + key)
    args = parser.parse_args()
    try:
        if args.guest:
            guest(args.kind, args.manifest, args.bundle, args.deb, args.token, args.export, args.host_boot, args.digest, args.local_evidence)
            return 0
        host(args.kind, None, {'out': args.out} if args.out else None)
        return 0
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as exc:
        print('FAIL candidate live campaign: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
