#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real replay must reach the bounded pacing adapter and retain exact arithmetic."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PacedReadsTests(unittest.TestCase):
    def test_receipt_oracle_rejects_missing_unpaced_short_and_unbounded_reads(self):
        from replay import paced_errors
        source = ROOT / 'tests/fixtures/reader/sealed-complete/events.ndjson'
        st = source.stat()
        good = dict(calls=2, bytes=st.st_size, lines=3, max_request_bytes=65536,
                    elapsed_ns=60000000, device=st.st_dev, inode=st.st_ino, eof=True, error=0)
        self.assertEqual(paced_errors(good, st, 3, st.st_size, 60000000, .06), [])
        self.assertTrue(paced_errors({}, st, 3, st.st_size, 60000000, .06))
        for key, value in [('calls', 0), ('bytes', 0), ('lines', 0), ('max_request_bytes', 1048576),
                           ('elapsed_ns', 0), ('inode', -1), ('eof', False), ('error', 5)]:
            with self.subTest(key=key):
                bad = dict(good, **{key: value})
                self.assertTrue(paced_errors(bad, st, 3, st.st_size, 60000000, .06))
        self.assertTrue(paced_errors(good, st, 3, st.st_size, 60000000, 0))

    def test_adapter_paces_actual_regular_file_reads(self):
        source = ROOT / 'tests/fixtures/reader/sealed-complete'
        shim = ROOT / 'build/perf/paced_reads.so'
        with tempfile.TemporaryDirectory() as tmp:
            receipt = Path(tmp) / 'reads.json'
            env = dict(os.environ, MEMVEIL_PACED_FILE=str(source / 'events.ndjson'),
                       MEMVEIL_PACED_RECEIPT=str(receipt), MEMVEIL_PACED_LINES='3',
                       MEMVEIL_PACED_NS='60000000')
            if shim.exists():
                env['LD_PRELOAD'] = str(shim) + (':' + env['LD_PRELOAD'] if env.get('LD_PRELOAD') else '')
            start = time.monotonic()
            proc = subprocess.run([str(ROOT / 'build/memveil'), 'report', '--format', 'json', str(source)],
                                  env=env, capture_output=True, timeout=5)
            elapsed = time.monotonic() - start
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(receipt.exists(), 'actual product read boundary was not instrumented')
            measured = json.loads(receipt.read_text())
            self.assertEqual(measured['lines'], 3)
            self.assertEqual(measured['bytes'], (source / 'events.ndjson').stat().st_size)
            self.assertTrue(measured['eof'])
            self.assertEqual(measured['error'], 0)
            self.assertGreaterEqual(measured['calls'], 2)
            self.assertLessEqual(measured['max_request_bytes'], 65536)
            self.assertGreaterEqual(measured['elapsed_ns'], 60000000)
            self.assertGreaterEqual(elapsed, .06)
            doc = json.loads(proc.stdout)
            self.assertEqual(doc['integrity']['verified_events'], '3')
            metrics = {m['name']: m['value'] for m in doc['metrics'] if m['dimensions']['device_id'] is None}
            self.assertEqual(metrics['bounce_attempts'], '3')
            raw = (source / 'events.ndjson').read_bytes()
            expected = sum(int(json.loads(line)['data']['requested_bytes']) for line in raw.splitlines())
            self.assertEqual(metrics['requested_bounce_bytes'], str(expected))


if __name__ == '__main__':
    unittest.main()
