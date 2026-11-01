#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent literal-prefix and syscall-order oracle for durable capture I/O."""
import hashlib
import json
import os
import stat
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / 'build/probe/checkpoint_probe'
SHIM = ROOT / 'build/shim/checkpoint_faults.so'
FIXTURE = ROOT / 'tests/fixtures/reader/sealed-complete'
BIN = ROOT / 'build/memveil'


def independent(path):
    final = path / 'session.json'
    source = final if final.exists() else path / 'checkpoint.json'
    if not source.exists():
        return None
    doc = json.loads(source.read_bytes())
    declared = doc['capture']['integrity']
    raw = (path / 'events.ndjson').read_bytes()
    extent = int(declared['events_bytes'])
    prefix = raw if final.exists() else raw[:extent]
    assert len(prefix) == extent
    assert hashlib.sha256(prefix).hexdigest() == declared['events_sha256']
    lines = prefix.splitlines(keepends=True)
    assert all(line.endswith(b'\n') for line in lines)
    assert len(lines) == int(declared['line_count'])
    counts = dict.fromkeys(declared['kinds'], 0)
    for seq, line in enumerate(lines):
        event = json.loads(line)
        assert event['session_id'] == doc['session_id']
        assert event['seq'] == str(seq)
        counts[event['kind']] += 1
    assert {key: str(value) for key, value in counts.items()} == declared['kinds']
    if not final.exists():
        assert doc['capture']['finalized'] is False
        assert doc['capture']['end_reason'] == 'checkpoint'
        assert int(doc['capture']['checkpoint_generation']) > 0
    return doc


class CheckpointWriterTests(unittest.TestCase):
    def invoke(self, root, mode='final', point=0, after=False, repeat=False, allocation='normal'):
        root = Path(root)
        capture = root / 'capture'
        trace = root / 'trace'
        env = dict(os.environ, LD_PRELOAD=str(SHIM), MV_IO_TRACE=str(trace), MV_IO_ALLOCATION=allocation)
        if point:
            env['MV_IO_FAIL'] = str(point)
        if after:
            env['MV_IO_AFTER'] = '1'
        if repeat:
            env['MV_IO_REPEAT'] = '1'
        proc = subprocess.run([str(PROBE), mode, str(capture), str(FIXTURE)],
                              capture_output=True, text=True, env=env)
        rows = [line.split() for line in trace.read_text().splitlines()] if trace.exists() else []
        return proc, capture, rows

    def test_order_and_cleanup(self):
        with tempfile.TemporaryDirectory() as root:
            proc, capture, rows = self.invoke(root)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            doc = independent(capture)
            self.assertTrue(doc['capture']['finalized'])
            self.assertEqual(sorted(p.name for p in capture.iterdir()), ['events.ndjson', 'session.json'])
            steps = [(row[1], row[2] if len(row) > 2 else '') for row in rows]
            self.assertEqual(steps[:3], [('sync', '.finalization-reserve'), ('sync', 'session.finalizing'), ('sync', 'events.ndjson')])
            publishes = [i for i, step in enumerate(steps) if step == ('rename', 'checkpoint.json')]
            self.assertEqual(len(publishes), 3)
            for i in publishes:
                self.assertEqual(steps[i-2:i], [('write', 'checkpoint.json.tmp'), ('sync', 'checkpoint.json.tmp')])
                self.assertEqual(steps[i+1][0], 'sync')
                self.assertEqual(steps[i+2][0], 'sync')
            final = steps.index(('rename', 'session.json'))
            release = steps.index(('truncate', '.finalization-reserve'))
            last_events_sync = max(i for i, step in enumerate(steps[:final]) if step == ('sync', 'events.ndjson'))
            self.assertLess(release, last_events_sync, 'reserve must be released before final event sync')
            self.assertEqual(steps[final-2:final], [('write', 'session.finalizing'), ('sync', 'session.finalizing')])
            self.assertTrue(all(step[0] == 'sync' for step in steps[final+1:]))

    def test_unfinalized_prefix_and_reserve(self):
        with tempfile.TemporaryDirectory() as root:
            proc, capture, _ = self.invoke(root, 'partial')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            doc = independent(capture)
            self.assertEqual(doc['capture']['checkpoint_generation'], '3')
            self.assertEqual(doc['capture']['integrity']['line_count'], '2')
            stat = (capture / '.finalization-reserve').stat()
            self.assertEqual(stat.st_size, 17 * 1024 * 1024)
            self.assertGreaterEqual(stat.st_blocks * 512, stat.st_size)
            self.assertEqual((capture / 'session.finalizing').stat().st_size, 0)
            result = subprocess.run([str(BIN), 'report', '--allow-partial', '--format', 'json', str(capture)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 4, result.stderr)
            output = json.loads(result.stdout)
            self.assertEqual(output['integrity']['verified_events'], '2')
            self.assertGreater(int(output['integrity']['unverified_bytes']), 0)

    def test_real_write_allocation_fallback_and_false_sparse_success(self):
        for mode, wanted in (('unsupported', 0), ('full', 1), ('sparse', 1)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                proc, capture, rows = self.invoke(root, 'partial', allocation=mode)
                self.assertEqual(proc.returncode, wanted, proc.stdout + proc.stderr)
                if wanted:
                    self.assertIn('prepare failed', proc.stdout)
                    self.assertIn('reserve', proc.stdout)
                    self.assertNotIn('ready\n', proc.stdout)
                    self.assertFalse(capture.exists())
                else:
                    self.assertEqual(sum(row[1:] == ['write', '.finalization-reserve'] for row in rows), 272)
                    stat = (capture / '.finalization-reserve').stat()
                    self.assertGreaterEqual(stat.st_blocks * 512, 17 * 1024 * 1024)
                    self.assertIsNotNone(independent(capture))

    def test_checkpoint_entry_swap_is_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            capture = Path(root) / 'capture'
            proc = subprocess.run([str(PROBE), 'final', str(capture), str(FIXTURE)],
                                  env=dict(os.environ, LD_PRELOAD=str(SHIM), MV_IO_SWAP_CHECKPOINT='1'),
                                  capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual((capture / 'checkpoint.json').read_bytes(), b'foreign checkpoint: preserve exactly')
            self.assertFalse((capture / 'session.json').exists())

    def test_group_threshold_then_failed_append_keeps_prior_prefix(self):
        with tempfile.TemporaryDirectory() as root:
            capture = Path(root) / 'capture'
            proc = subprocess.run([str(ROOT / 'build/probe/group_checkpoint_probe'), str(capture), str(FIXTURE)],
                                  env=dict(os.environ, LD_PRELOAD=str(SHIM)), capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn('checkpoint_refused=True', proc.stdout)
            self.assertIn('time_checkpoint_refused=True', proc.stdout)
            self.assertIn('append_failed=True', proc.stdout)
            doc = independent(capture)
            self.assertEqual(doc['capture']['integrity']['line_count'], '999')
            self.assertEqual(doc['capture']['checkpoint_generation'], '1')
            self.assertEqual(len((capture / 'events.ndjson').read_bytes()), int(doc['capture']['integrity']['events_bytes']))

    def test_final_summary_loss_and_requested_output_failure(self):
        for mode, code in (('stdout', 4), ('stdout0', 0), ('pipe', 4), ('pipe0', 0), ('stdout1', 1), ('pipe1', 1)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                proc, capture, _ = self.invoke(root, mode)
                self.assertEqual(proc.returncode, code, proc.stderr)
                self.assertTrue(independent(capture)['capture']['finalized'])
                self.assertIn(str(capture), proc.stderr)
                self.assertIn('cannot write stdout', proc.stderr)
                with open('/dev/full', 'wb') as destination:
                    report = subprocess.run([str(BIN), 'report', '--format', 'json', str(capture)],
                                            stdout=destination, stderr=subprocess.PIPE)
                self.assertEqual(report.returncode, 1)
                self.assertIn(b'cannot write stdout', report.stderr)
                self.assertTrue(independent(capture)['capture']['finalized'])
        with tempfile.TemporaryDirectory() as root:
            controlled = Path(root) / 'path-with-\n-and-\x1b'
            controlled.mkdir()
            proc, capture, _ = self.invoke(controlled, 'stdout')
            self.assertEqual(proc.returncode, 4)
            self.assertTrue(independent(capture)['capture']['finalized'])
            self.assertIn('path-with-\\n-and-', proc.stderr)
            self.assertNotIn('\x1b', proc.stderr)
            self.assertEqual(proc.stderr.count('\n'), 1)

    def test_readiness_lock_and_path_replacement(self):
        for swapped in ('none', 'directory', 'events.ndjson', 'session.finalizing',
                        '.finalization-reserve', 'checkpoint.json.tmp'):
            with self.subTest(swapped=swapped), tempfile.TemporaryDirectory() as root:
                capture = Path(root) / 'capture'
                child = subprocess.Popen([str(PROBE), 'hold', str(capture), str(FIXTURE)],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         text=True)
                try:
                    self.assertEqual(child.stdout.readline(), 'ready\n')
                    ready = independent(capture)
                    self.assertEqual(ready['capture']['integrity']['line_count'], '0')
                    self.assertEqual(ready['capture']['checkpoint_generation'], '1')
                    result = subprocess.run([str(BIN), 'report', '--allow-partial', str(capture)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn('active writer', result.stderr)
                    reserve = (capture / '.finalization-reserve').stat()
                    self.assertGreaterEqual(reserve.st_blocks * 512, 17 * 1024 * 1024)
                    foreign = None
                    if swapped == 'directory':
                        capture.rename(Path(root) / 'displaced')
                        capture.mkdir()
                        foreign = capture / 'unrelated'
                    elif swapped != 'none':
                        foreign = capture / swapped
                        if foreign.exists():
                            foreign.rename(capture / (swapped + '.displaced'))
                    if foreign is not None:
                        foreign.write_bytes(b'foreign evidence: preserve exactly')
                    out, err = child.communicate('continue\n', timeout=30)
                    if swapped in ('none', 'checkpoint.json.tmp'):
                        self.assertEqual(child.returncode, 0, out + err)
                    else:
                        self.assertNotEqual(child.returncode, 0, out + err)
                    if foreign is not None:
                        self.assertEqual(foreign.read_bytes(), b'foreign evidence: preserve exactly')
                    if swapped == 'checkpoint.json.tmp':
                        doc = independent(capture)
                        self.assertEqual(doc['stop']['checkpoint_failures'], '2')
                finally:
                    if child.poll() is None:
                        child.terminate()
                        child.wait(timeout=10)

    def test_final_pin_rejects_fifo_swap_without_blocking(self):
        for prepared in (True, False):
            with self.subTest(prepared=prepared), tempfile.TemporaryDirectory() as root:
                capture = Path(root) / 'capture'
                command = ([str(PROBE), 'final', str(capture), str(FIXTURE)] if prepared else
                           [str(ROOT / 'build/probe/shim_probe'), 'pincheck', str(capture)])
                proc = subprocess.run(command, capture_output=True, text=True, timeout=3,
                                      env=dict(os.environ, LD_PRELOAD=str(SHIM), MV_IO_SWAP_FINAL_FIFO='1'))
                self.assertTrue(stat.S_ISFIFO((capture / 'session.json').lstat().st_mode))
                self.assertTrue((capture / 'session.displaced').is_file(), 'swap boundary not reached')
                self.assertNotIn('status=finalized', proc.stdout)
                if prepared:
                    self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                    self.assertIn('final=unfinalized', proc.stdout)
                    doc = json.loads((capture / 'checkpoint.json').read_bytes())
                    extent = int(doc['capture']['integrity']['events_bytes'])
                    raw = (capture / 'events.ndjson').read_bytes()[:extent]
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), doc['capture']['integrity']['events_sha256'])
                else:
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    self.assertIn('status=unfinalized note=session replaced after rename pin=0', proc.stdout)
                report = subprocess.run([str(BIN), 'report', '--allow-partial', str(capture)],
                                        capture_output=True, text=True, timeout=3)
                self.assertEqual(report.returncode, 2, report.stderr)

    def test_persistent_sync_failure_cannot_finalize(self):
        with tempfile.TemporaryDirectory() as root:
            proc, _, rows = self.invoke(root)
            self.assertEqual(proc.returncode, 0)
        checkpoints = [int(row[0]) for row in rows if row[1:] == ['rename', 'checkpoint.json']]
        with tempfile.TemporaryDirectory() as root:
            proc, capture, _ = self.invoke(root, point=checkpoints[1] + 1, repeat=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotIn('final=finalized', proc.stdout)
            self.assertFalse((capture / 'session.json').exists())
            self.assertIsNotNone(independent(capture))
            self.assertTrue((capture / 'checkpoint.json.tmp').exists())

    def test_every_write_sync_rename_boundary(self):
        for allocation in ('normal', 'unsupported'):
            with tempfile.TemporaryDirectory() as root:
                proc, _, rows = self.invoke(root, allocation=allocation)
                self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertGreater(len(rows), 20)
            print(f'{allocation}: {len(rows)} syscall boundaries, before/after each', flush=True)
            for row in rows:
                point = int(row[0])
                for after in (False, True):
                    with self.subTest(allocation=allocation, point=point, op=row[1], after=after), tempfile.TemporaryDirectory() as root:
                        proc, capture, actual = self.invoke(root, point=point, after=after, allocation=allocation)
                        self.assertTrue(any(int(item[0]) == point for item in actual), 'fault boundary not reached')
                        if after:
                            self.assertEqual(proc.returncode, 91)
                        else:
                            self.assertIn(proc.returncode, (0, 1))
                        doc = independent(capture)
                        if 'ready\n' in proc.stdout and not (capture / 'session.json').exists():
                            self.assertIsNotNone(doc, 'readiness must retain a verified checkpoint')
                        if proc.returncode == 0:
                            self.assertTrue(doc['capture']['finalized'])
                            self.assertGreater(int(doc['stop']['checkpoint_failures']), 0)
                        if 'final=finalized' in proc.stdout:
                            self.assertEqual(proc.returncode, 0)


if __name__ == '__main__':
    unittest.main()
