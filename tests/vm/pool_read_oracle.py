# SPDX-License-Identifier: GPL-3.0-or-later
"""Intrusive pool-only read cadence oracle; raw trace bytes never reach storage."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time

PATHS = {'/sys/kernel/debug/swiotlb/io_tlb_used': 'used',
         '/sys/kernel/debug/swiotlb/io_tlb_nslabs': 'capacity'}
GAP_NS = 3 * 10**9
DELIVERY_NS = 250000000
MAX_RECORDS = 20000
MAX_TRACE_BYTES = 8 * 1024**2
MAX_DETACH_CONTROL_SKIPS = 4
MAX_CONTROL_PER_THREAD = 2


class PoolReadError(ValueError):
    """A classified pool-trace projection failure; shapes only, never bytes."""
    def __init__(self, check, shape, message, extra=None):
        super().__init__(message)
        self.check = check
        self.shape = shape
        self.extra = extra if extra is not None else {}


def _match_control(line):
    """Match strace detach-edge control output for read; None when absent.

    Returns (kind, pid, path) with kind 'unfinished' or 'resumed', pid an
    int or None, path the raw field bytes or None (a resumed line repeats
    no path). Matching is transient; callers store shapes, never the line.
    """
    unfinished = (rb'(?:(?:\[pid\s+(\d+)\]|(\d+))\s+)?(\d+)\.(\d{6,9})\s+'
                  rb'read\(\d+<([^>]+)>, .* <unfinished \.\.\.>\s*\n?')
    match = re.fullmatch(unfinished, line)
    if match is not None:
        pid = int(match[1] or match[2]) if match[1] or match[2] else None
        return ('unfinished', pid, match[5])
    resumed = (rb'(?:(?:\[pid\s+(\d+)\]|(\d+))\s+)?(\d+)\.(\d{6,9})\s+'
               rb'<\.\.\. read resumed>\s*.*?\)\s+=\s+(\?|-?\d+).*\n?')
    match = re.fullmatch(resumed, line)
    if match is None: return None
    pid = int(match[1] or match[2]) if match[1] or match[2] else None
    return ('resumed', pid, None)


def project_read(line, received_ns, wall_ns, owned_thread, default_tid=None):
    if len(line) > 65536:
        raise PoolReadError('line_too_long', 'exceeds_65536', 'pool trace line exceeds bound')
    pattern = (rb'(?:(?:\[pid\s+(\d+)\]|(\d+))\s+)?(\d+)\.(\d{6,9})\s+'
               rb'read\(\d+<([^>]+)>, .*\)\s+=\s+(\d+)\s*\n?')
    match = re.fullmatch(pattern, line)
    if match is None:
        control = _match_control(line)
        shape = 'control_' + control[0] if control is not None else 'unrecognized'
        raise PoolReadError('grammar', shape, 'unrecognized or failed pool read')
    pid = int(match[1] or match[2]) if match[1] or match[2] else default_tid
    if pid is None or not owned_thread(pid):
        raise PoolReadError('ownership', 'unowned_or_exited_tid', 'pool read target is not an owned thread')
    source_ns = int(match[3]) * 10**9 + int(match[4].ljust(9, b'0'))
    skew_ns = wall_ns - source_ns
    if not -1000000 <= skew_ns <= DELIVERY_NS:
        shape = 'late' if skew_ns > DELIVERY_NS else 'future'
        raise PoolReadError('delivery', shape, 'pool trace delivery is late or clock mapping is unstable',
                            {'skew_ns': str(skew_ns)})
    try:
        path = match[5].decode('ascii')
    except UnicodeError:
        raise PoolReadError('decode', 'non_ascii_path', 'pool read path is not ascii')
    if path not in PATHS:
        raise PoolReadError('path', 'foreign_path', 'pool read path is not allowlisted',
                            {'path_len': str(len(path))})
    count = int(match[6])
    if count > 65:
        raise PoolReadError('count_bound', 'over_65', 'pool read exceeds source counter bound',
                            {'count': str(count)})
    if count == 0: return None
    return {'field': PATHS[path], 'returned_bytes': str(count), 'received_ns': str(received_ns)}


def validate_pool(samples, window, oracle, stop_ns):
    ticks = [int(value) for value in samples]
    start, end, stop = int(window['start_ns']), int(window['end_ns']), int(stop_ns)
    if len(ticks) < 4098 or ticks[-1] - ticks[0] <= 4200 * 10**9:
        raise ValueError('pool routine sampling or long-duration coverage absent')
    routine = ticks[:4097]
    if any(not 500000000 <= b - a <= GAP_NS for a, b in zip(routine, routine[1:])):
        raise ValueError('pool routine periodic cadence invalid')
    if routine[-1] - routine[0] < 4096 * 10**9 - GAP_NS:
        raise ValueError('pool routine cap reached without its timed ticks')
    if oracle is None or oracle.get('errors') or oracle.get('cleanup') != 'detached':
        raise ValueError('pool read oracle unavailable or cleanup unproved')
    records = oracle['records']
    if len(records) > MAX_RECORDS: raise ValueError('pool oracle exceeds record bound')
    for row in records:
        if row['field'] not in PATHS.values() or not 0 < int(row['returned_bytes']) <= 65:
            raise ValueError('pool oracle has a failed or foreign read')
    post_start = routine[-1] + GAP_NS
    if min(end, stop) - post_start < 30 * 10**9:
        raise ValueError('pool post-cap measured interval too short')
    for field in PATHS.values():
        all_reads = [int(row['received_ns']) for row in records if row['field'] == field]
        active = [tick for tick in all_reads if start <= tick < min(end, stop)]
        if len(active) < 4096 or not active or active[0] - start > GAP_NS or end - active[-1] > GAP_NS:
            raise ValueError('pool read count or measured coverage incomplete: ' + field)
        if any(not 500000000 <= b - a <= GAP_NS for a, b in zip(active, active[1:])):
            raise ValueError('pool read burst or gap: ' + field)
        post = [tick for tick in active if tick > post_start]
        if not post or post[0] - post_start > GAP_NS or end - post[-1] > GAP_NS:
            raise ValueError('pool reads stop at routine cap: ' + field)


def digest(path):
    value = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''): value.update(chunk)
    return value.hexdigest()


def process_identity(pid):
    root = Path('/proc') / str(pid)
    start = (root / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    info = (root / 'exe').stat()
    return start, info.st_dev, info.st_ino


class PoolReadOracle:
    def __init__(self, product, binary, nonce):
        if product.poll() is not None: raise ValueError('pool oracle target exited')
        if not re.fullmatch('[0-9a-f]{16}', nonce or ''):
            raise ValueError('pool oracle nonce absent')
        if 'memveil_candidate_guest=' + nonce not in Path('/proc/cmdline').read_text().split():
            raise ValueError('pool oracle guest nonce differs')
        self.product = product
        self.identity = process_identity(product.pid)
        if not os.path.samefile(Path('/proc') / str(product.pid) / 'exe', binary):
            raise ValueError('pool oracle target executable differs')
        tracer = shutil.which('strace')
        if tracer is None: raise ValueError('pool read oracle needs strace')
        self.observation = {'kind': 'intrusive-read-cadence-only', 'pid': str(product.pid),
            'start_ticks': self.identity[0], 'nonce': nonce, 'executable_sha256': digest(binary),
            'tracer_sha256': digest(tracer), 'parser_sha256': digest(__file__),
            'records': [], 'errors': [], 'cleanup': 'pending',
            'delivery_bound_ns': str(DELIVERY_NS), 'cadence_gap_bound_ns': str(GAP_NS)}
        self.stopping = False
        args = [tracer, '-f', '-qq', '-ttt', '-yy', '-s', '0', '-e', 'trace=read', '-e', 'signal=none']
        for path in PATHS: args += ['-P', path]
        args += ['-p', str(product.pid)]
        self.tracer = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _owned_thread(self, tid):
        try:
            status = (Path('/proc') / str(tid) / 'status').read_text().splitlines()
            return any(line.split() == ['Tgid:', str(self.product.pid)] for line in status)
        except OSError:
            return False

    def _failure_record(self, check, shape, line_len, received_ns, wall_ns, extra=None):
        """Build a byte-free failure record: check, shape, sequence, timing.

        Takes only lengths, clocks, and counts — never the line — so trace
        bytes cannot flow into the record by construction; extras are
        restricted to the same shapes, counts, and offsets at each raise.
        """
        count = len(self.observation['records'])
        last = self.observation['records'][-1]['received_ns'] if count else None
        row = {'class': check, 'shape': shape, 'seq': str(count),
               'last_good_seq': str(count - 1) if count else 'none',
               'last_good_received_ns': last if last is not None else 'none',
               'failed_received_ns': str(received_ns), 'failed_wall_ns': str(wall_ns),
               'gap_ns': str(received_ns - int(last)) if last is not None else 'none',
               'line_len': str(line_len), 'stopping': 'true' if self.stopping else 'false'}
        if extra: row.update(extra)
        return row

    def _read(self):
        total = 0
        try:
            while True:
                line = self.tracer.stderr.readline(65537)
                if not line: break
                received_ns = time.monotonic_ns()
                wall_ns = time.time_ns()
                total += len(line)
                try:
                    if total > MAX_TRACE_BYTES:
                        raise PoolReadError('trace_bytes_bound', 'over_bound', 'trace_bytes_bound',
                                            {'bound_bytes': str(MAX_TRACE_BYTES), 'total_bytes': str(total)})
                    row = project_read(line, received_ns, wall_ns, self._owned_thread, self.product.pid)
                    if row is not None:
                        if len(self.observation['records']) >= MAX_RECORDS:
                            raise PoolReadError('trace_records_bound', 'over_bound', 'trace_records_bound',
                                                {'bound_records': str(MAX_RECORDS)})
                        self.observation['records'].append(row)
                except PoolReadError as exc:
                    self.observation['errors'].append(self._failure_record(
                        exc.check, exc.shape, len(line), received_ns, wall_ns, exc.extra))
                    return
        except OSError as exc:
            self.observation['errors'].append(self._failure_record(
                'read_os_error', 'readline_failed', 0, time.monotonic_ns(), time.time_ns(),
                {'errno': str(exc.errno or 0)}))
        except ValueError as exc:
            self.observation['errors'].append(self._failure_record(
                'unexpected_value', type(exc).__name__, 0, time.monotonic_ns(), time.time_ns()))

    def check(self):
        if self.observation['errors'] or self.tracer.poll() is not None:
            raise ValueError('pool read oracle failed before stop')
        if process_identity(self.product.pid) != self.identity:
            raise ValueError('pool read target identity changed')

    def close(self):
        if self.stopping: return
        self.stopping = True
        try:
            if self.tracer.poll() is None:
                self.tracer.terminate()
                try: self.tracer.wait(timeout=10)
                except subprocess.TimeoutExpired: self.tracer.kill(); self.tracer.wait(timeout=10)
            self.reader.join(timeout=5)
            if self.reader.is_alive(): raise ValueError('pool oracle reader did not stop')
            self.tracer.stderr.close()
            if self.product.poll() is None:
                if process_identity(self.product.pid) != self.identity: raise ValueError('pool target changed during detach')
                for task in (Path('/proc') / str(self.product.pid) / 'task').iterdir():
                    try: status = (task / 'status').read_text().splitlines()
                    except FileNotFoundError: continue
                    if not any(line.split() == ['TracerPid:', '0'] for line in status):
                        raise ValueError('pool oracle detach unproved')
            self.observation['cleanup'] = 'detached'
        except BaseException:
            self.observation['cleanup'] = 'unproved'
            raise
