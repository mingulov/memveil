#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Negative controls for accepted-report validation; every input uses real replay."""
import copy
import json
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest
import run

ROOT = Path(__file__).resolve().parents[2]


class OracleTests(unittest.TestCase):
    def test_source_quality_cannot_erase_loss_or_invent_coverage(self):
        cases = [
            ('quality-detail-counters', 'detail', {'loss_count': '0'}),
            ('quality-detail-counters', 'aggregate', {'loss_count': '0'}),
            ('sealed-complete', 'aggregate', {'status': 'complete_for_scope', 'loss_count': '0'}),
            ('sealed-complete', 'aggregate', {'status': 'complete_for_scope'}),
        ]
        for fixture, channel, change in cases:
            with self.subTest(fixture=fixture, channel=channel):
                path = ROOT / 'tests/fixtures/reader' / fixture
                for flags, code in [((), 0), (('--strict',), 4 if fixture == 'quality-detail-counters' else 0)]:
                    proc = subprocess.run([str(ROOT / 'build/memveil'), 'report', '--format', 'json',
                                           *flags, str(path)], capture_output=True)
                    self.assertEqual(proc.returncode, code, proc.stderr)
                    self.assertIsNone(run.check(path, code, proc.stdout, b'', strict=bool(flags)))
                    doc = json.loads(proc.stdout)
                    doc['quality'][channel].update(change)
                    self.assertIsNotNone(run.check(path, code, json.dumps(doc).encode(), b'', strict=bool(flags)))

    def test_rejects_parseable_but_false_reports(self):
        path = ROOT / 'tests/fixtures/reader/sealed-complete'
        proc = subprocess.run([str(ROOT / 'build/memveil'), 'report', '--format', 'json', str(path)], capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout)
        self.assertIsNone(run.check(path, 0, proc.stdout, b''))
        mutations = [('empty', {})]
        for name, change in (
            ('arithmetic', lambda d: d['metrics'][0].update(value='999')),
            ('integrity', lambda d: d['integrity'].update(verified_bytes='0')),
            ('schema', lambda d: d.update(unrecognized=True)),
            ('quality', lambda d: d['quality']['detail'].update(loss_count='8')),
            ('identity', lambda d: d.update(session_id='other')),
            ('provenance', lambda d: d.update(synthetic=False)),
        ):
            bad = copy.deepcopy(doc)
            change(bad)
            mutations.append((name, bad))
        for name, bad in mutations:
            with self.subTest(mutation=name):
                self.assertIsNotNone(run.check(path, 0, json.dumps(bad).encode(), b''), name)

    def test_checkpoint_suffix_extent_and_quality_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            for name in ('session.json', 'events.ndjson'):
                shutil.copy(ROOT / 'tests/fixtures/reader/sealed-complete' / name, path)
            run.checkpoint(path)
            with (path / 'events.ndjson').open('ab') as stream:
                stream.write(b'unverified suffix')
            proc = subprocess.run([str(ROOT / 'build/memveil'), 'report', '--format', 'json',
                                   '--allow-partial', str(path)], capture_output=True)
            self.assertEqual(proc.returncode, 4, proc.stderr)
            self.assertIsNone(run.check(path, 4, proc.stdout, b'', allow_partial=True))
            doc = json.loads(proc.stdout)
            for field, value in [('status', 'verified'), ('unverified_bytes', '0'),
                                 ('verified_events', '99')]:
                bad = copy.deepcopy(doc)
                bad['integrity'][field] = value
                self.assertIsNotNone(run.check(path, 4, json.dumps(bad).encode(), b'', allow_partial=True))
            bad = copy.deepcopy(doc)
            bad['quality']['terminal']['status'] = 'complete_for_scope'
            self.assertIsNotNone(run.check(path, 4, json.dumps(bad).encode(), b'', allow_partial=True))
            self.assertIsNotNone(run.check(path, 0, proc.stdout, b'', allow_partial=True))
            self.assertIsNotNone(run.check(path, 4, proc.stdout, b''))

    def test_legacy_complete_claim_is_rejected(self):
        path = ROOT / 'tests/fixtures/reader/complete-stop'
        proc = subprocess.run([str(ROOT / 'build/memveil'), 'report', '--format', 'json', str(path)], capture_output=True)
        self.assertEqual(proc.returncode, 0)
        doc = json.loads(proc.stdout)
        doc['verdict']['name'] = 'complete'
        self.assertIsNotNone(run.check(path, 0, json.dumps(doc).encode(), b''))


if __name__ == '__main__':
    unittest.main()
