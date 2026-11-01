#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reached-boundary process failures on the real writer; no storage admission."""
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from test_checkpoint_writer import independent, ROOT, PROBE, BIN
sys.path.insert(0, str(ROOT / 'tests'))
from preload_env import preload_env

FIXTURE = ROOT / 'tests/fixtures/reader/sealed-partial'
sys.path.insert(0, str(ROOT / 'tests/fuzz'))
from report_oracle import accepted_report

SHIM = ROOT / 'build/shim/capture_faults.so'


def environment(root, mode):
    return dict(preload_env(PROBE, SHIM), MEMVEIL_TEST_NO_BPF='1',
                MV_CAPTURE_FAULT=mode, MV_FAULT_MARKER=str(Path(root) / 'reached'))


def wait_for(predicate, child, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        if child.poll() is not None:
            raise AssertionError('process exited before required boundary: ' + str(child.returncode))
        time.sleep(0.01)
    raise AssertionError('required boundary was not reached')


class CaptureFailureTests(unittest.TestCase):
    def test_guard_denies_bpf_before_native_kernel_work(self):
        code = 'import ctypes,errno; c=ctypes.CDLL(None,use_errno=True); assert c.syscall(321,0,0,0)==-1; assert ctypes.get_errno()==errno.ENOSYS'
        proc = subprocess.run([sys.executable, '-c', code], env=dict(preload_env(PROBE, SHIM), MEMVEIL_TEST_NO_BPF='1'), capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_kill_after_observed_readiness_preserves_empty_checkpoint(self):
        with tempfile.TemporaryDirectory() as root:
            capture = Path(root) / 'capture'
            child = subprocess.Popen([str(PROBE), 'hold', str(capture), str(FIXTURE)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment(root, 'none'))
            try:
                self.assertTrue(select.select([child.stdout], [], [], 5)[0], 'readiness was not reached')
                self.assertEqual(child.stdout.readline(), b'ready\n')
                self.assertEqual(independent(capture)['capture']['integrity']['line_count'], '0')
                child.kill()
                child.communicate(timeout=5)
                self.assertEqual(child.returncode, -signal.SIGKILL)
                proc = subprocess.run([str(BIN), 'report', '--allow-partial', '--format', 'json', str(capture)], capture_output=True)
                self.assertEqual(proc.returncode, 4, proc.stderr)
                report = accepted_report(capture, proc.stdout, proc.returncode, allow_partial=True)
                self.assertEqual(report['integrity']['verified_events'], '0')
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=5)

    def test_kill_at_durable_readiness_checkpoint_and_finalization(self):
        for mode, events in [('checkpoint-1', '0'), ('checkpoint-3', '2'), ('final-stop', '2')]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                capture = Path(root) / 'capture'
                child = subprocess.Popen([str(PROBE), 'final', str(capture), str(FIXTURE)],
                    env=environment(root, mode), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    def stopped():
                        marker = Path(root) / 'reached'
                        state = Path('/proc') / str(child.pid) / 'status'
                        return marker.exists() and state.exists() and '\nState:\tT' in state.read_text()
                    wait_for(stopped, child)
                    self.assertEqual((Path(root) / 'reached').read_text(), mode)
                    promised = independent(capture)
                    self.assertEqual(promised['capture']['integrity']['line_count'], events)
                    child.kill()
                    child.communicate(timeout=5)
                    self.assertEqual(child.returncode, -signal.SIGKILL)
                    self.assertFalse((capture / 'session.json').exists())
                    refused = subprocess.run([str(BIN), 'report', str(capture)], capture_output=True)
                    self.assertEqual(refused.returncode, 2)
                    for flags in [('--allow-partial',), ('--allow-partial', '--strict')]:
                        result = subprocess.run([str(BIN), 'report', '--format', 'json', *flags, str(capture)], capture_output=True)
                        self.assertEqual(result.returncode, 4, result.stderr)
                        report = accepted_report(capture, result.stdout, result.returncode,
                                                 strict='--strict' in flags, allow_partial=True)
                        self.assertEqual(report['integrity']['verified_events'], events)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate(timeout=5)

    def test_missing_fault_boundary_cannot_count_as_success(self):
        with tempfile.TemporaryDirectory() as root:
            capture = Path(root) / 'capture'
            child = subprocess.Popen([str(PROBE), 'final', str(capture), str(FIXTURE)],
                env=environment(root, 'none'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with self.assertRaisesRegex(AssertionError, 'before required boundary'):
                    wait_for(lambda: (Path(root) / 'reached').exists(), child)
                child.communicate(timeout=5)
                self.assertEqual(child.returncode, 0)
                self.assertTrue(independent(capture)['capture']['finalized'])
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=5)

    def test_short_write_and_storage_errors_reach_writer(self):
        for mode in ('event-short', 'event-eio', 'event-full', 'final-sync', 'final-rename'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                capture = Path(root) / 'capture'
                proc = subprocess.run([str(PROBE), 'final', str(capture), str(FIXTURE)],
                    env=environment(root, mode), capture_output=True, timeout=5)
                self.assertEqual((Path(root) / 'reached').read_text(), mode)
                self.assertIn(b'ready\n', proc.stdout, 'startup refusal cannot pass a post-readiness fault')
                doc = independent(capture)
                self.assertIsNotNone(doc)
                if mode == 'event-short':
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertTrue(doc['capture']['finalized'])
                    self.assertEqual((capture / 'events.ndjson').read_bytes(), (FIXTURE / 'events.ndjson').read_bytes())
                else:
                    self.assertEqual(proc.returncode, 1, proc.stderr)
                    self.assertFalse((capture / 'session.json').exists())
                    self.assertFalse(doc['capture']['finalized'])

    def test_blocked_report_pipe_reaches_write_then_reports_epipe(self):
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK)
        child = None
        try:
            while True:
                try:
                    os.write(write_fd, b'x' * 4096)
                except BlockingIOError:
                    break
            fcntl.fcntl(write_fd, fcntl.F_SETFL, 0)
            child = subprocess.Popen([str(BIN), 'report', '--format', 'json', str(FIXTURE)],
                                     stdout=write_fd, stderr=subprocess.PIPE)
            wait_for(lambda: (Path('/proc') / str(child.pid) / 'wchan').read_text().strip() in ('pipe_write', 'anon_pipe_write'), child)
            os.close(read_fd)
            read_fd = -1
            _, err = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 1)
            self.assertIn(b'cannot write stdout', err)
        finally:
            if read_fd >= 0:
                os.close(read_fd)
            os.close(write_fd)
            if child is not None and child.poll() is None:
                child.kill()
                child.communicate(timeout=5)

    def test_symlink_and_fifo_swaps_after_readiness_preserve_foreign_entries(self):
        for name in ('events.ndjson', 'session.finalizing', '.finalization-reserve'):
            for kind in ('symlink', 'fifo'):
                with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as root:
                    capture = Path(root) / 'capture'
                    child = subprocess.Popen([str(PROBE), 'hold', str(capture), str(FIXTURE)],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        env=environment(root, 'none'))
                    try:
                        self.assertTrue(select.select([child.stdout], [], [], 5)[0], 'readiness was not reached')
                        self.assertEqual(child.stdout.readline(), b'ready\n')
                        self.assertEqual(independent(capture)['capture']['integrity']['line_count'], '0')
                        target = capture / name
                        target.rename(capture / (name + '.saved'))
                        foreign = Path(root) / 'foreign'
                        foreign.write_bytes(b'foreign evidence remains')
                        if kind == 'symlink':
                            target.symlink_to(foreign)
                        else:
                            os.mkfifo(target)
                        out, err = child.communicate(b'continue\n', timeout=5)
                        self.assertEqual(child.returncode, 1, out + err)
                        self.assertEqual(foreign.read_bytes(), b'foreign evidence remains')
                        self.assertTrue(target.is_symlink() if kind == 'symlink' else target.is_fifo())
                        self.assertFalse((capture / 'session.json').exists())
                    finally:
                        if child.poll() is None:
                            child.kill()
                            child.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main()
