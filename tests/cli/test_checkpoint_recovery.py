#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent prefix-only recovery oracle, including final precedence."""
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
from preload_env import preload_env

BIN = ROOT / 'build/memveil'
FIXTURE = ROOT / 'tests/fixtures/reader/sealed-complete'


def run(path, *flags):
    return subprocess.run([str(BIN), 'report', '--format', 'json', *flags,
                           str(path)], capture_output=True, text=True)


class RecoveryTests(unittest.TestCase):
    def capture(self, root, suffix=b''):
        path = Path(root) / 'capture'
        path.mkdir(mode=0o700)
        doc = json.loads((FIXTURE / 'session.json').read_text())
        doc['capture'].update(finalized=False, end_reason='checkpoint',
                              checkpoint_generation='1')
        doc['stop']['checkpoint_failures'] = '0'
        doc['stop']['outcome'] = 'partial'
        doc['stop']['reason'] = 'checkpoint: measurement window remains open'
        for key in ('admission_closed', 'quiescence_observed', 'drain_completed',
                    'counters_valid'):
            doc['stop'][key] = False
        for channel in doc['quality'].values():
            if isinstance(channel, dict) and channel.get('status') == 'complete_for_scope':
                channel['status'] = 'partial'
                channel['reason'] = 'checkpoint: measurement window remains open'
        raw = (FIXTURE / 'events.ndjson').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), doc['capture']['integrity']['events_sha256'])
        (path / 'checkpoint.json').write_text(json.dumps(doc))
        (path / 'events.ndjson').write_bytes(raw + suffix)
        return path, doc, raw

    def test_verified_prefix_ignores_arbitrary_suffix(self):
        for suffix in (b'', b'not JSON\x00\xff', (FIXTURE / 'events.ndjson').read_bytes()):
            with self.subTest(suffix=len(suffix)), tempfile.TemporaryDirectory() as root:
                path, doc, raw = self.capture(root, suffix)
                denied = run(path)
                self.assertEqual(denied.returncode, 2)
                self.assertIn('--allow-partial', denied.stderr)
                for flags in (('--allow-partial',), ('--allow-partial', '--strict')):
                    result = run(path, *flags)
                    self.assertEqual(result.returncode, 4, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual(report['integrity'], {
                        'status': 'checkpoint_prefix', 'verified_bytes': str(len(raw)),
                        'verified_events': doc['capture']['integrity']['line_count'],
                        'unverified_bytes': str(len(suffix))})
                    self.assertNotEqual(report['verdict']['name'], 'complete')
                    attempts = [json.loads(line) for line in raw.splitlines()]
                    metrics = {(m['name'], m['dimensions']['device_id'], m['dimensions']['pool_id']): m['value'] for m in report['metrics']}
                    self.assertEqual(metrics[('bounce_attempts', None, None)], str(len(attempts)))
                    self.assertEqual(metrics[('requested_bounce_bytes', None, None)], str(sum(int(e['data']['requested_bytes']) for e in attempts)))

    def test_syscalls_do_not_read_the_unverified_suffix(self):
        with tempfile.TemporaryDirectory() as root:
            path, _, raw = self.capture(root, b"unverified suffix" * 4096)
            trace = Path(root) / 'reads.trace'
            result = subprocess.run(['strace', '-qq', '-yy', '-e', 'trace=read,pread64', '-o', str(trace),
                                     str(BIN), 'report', '--allow-partial', str(path)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 4, result.stderr)
            rows = [line for line in trace.read_text().splitlines() if '/events.ndjson>' in line]
            self.assertTrue(rows, 'event read boundary not reached')
            lengths = [int(re.search(r'= ([0-9]+)$', line).group(1)) for line in rows]
            self.assertEqual(sum(lengths), len(raw), 'only the verified prefix may be read')

    def test_final_precedence_and_active_writer(self):
        with tempfile.TemporaryDirectory() as root:
            path, _, _ = self.capture(root)
            directory = os.open(path, os.O_RDONLY)
            try:
                fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = run(path, '--allow-partial')
                self.assertEqual(result.returncode, 2)
                self.assertIn('active writer', result.stderr)
            finally:
                os.close(directory)
            (path / 'session.json').write_bytes(b'{broken')
            self.assertEqual(run(path, '--allow-partial').returncode, 2)
            (path / 'session.json').write_bytes((FIXTURE / 'session.json').read_bytes())
            self.assertEqual(run(path, '--allow-partial').returncode, 0)

    def test_symlinks_special_files_and_stale_temporary(self):
        for name in ('checkpoint.json', 'events.ndjson'):
            for kind in ('symlink', 'fifo', 'directory'):
                with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as root:
                    path, _, _ = self.capture(root)
                    target = path / name
                    target.rename(path / 'owned-backup')
                    if kind == 'symlink':
                        target.symlink_to('owned-backup')
                    elif kind == 'fifo':
                        os.mkfifo(target)
                    else:
                        target.mkdir()
                    result = run(path, '--allow-partial')
                    self.assertEqual(result.returncode, 2)
        with tempfile.TemporaryDirectory() as root:
            path, _, _ = self.capture(root)
            stale = path / 'checkpoint.json.tmp'
            stale.write_bytes(b'foreign stale checkpoint')
            self.assertEqual(run(path, '--allow-partial').returncode, 4)
            self.assertEqual(stale.read_bytes(), b'foreign stale checkpoint')
            os.mkfifo(path / 'session.json')
            self.assertEqual(run(path, '--allow-partial').returncode, 2)
        with tempfile.TemporaryDirectory() as root:
            path, _, _ = self.capture(root)
            alias = Path(root) / 'alias'
            alias.symlink_to(path, target_is_directory=True)
            self.assertEqual(run(alias, '--allow-partial').returncode, 2)

    def test_shared_readers_and_swapped_entries(self):
        with tempfile.TemporaryDirectory() as root:
            path, _, _ = self.capture(root)
            directory = os.open(path, os.O_RDONLY)
            try:
                fcntl.flock(directory, fcntl.LOCK_SH | fcntl.LOCK_NB)
                self.assertEqual(run(path, '--allow-partial').returncode, 4)
            finally:
                os.close(directory)
        for name in ('directory', 'checkpoint.json', 'events.ndjson'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                path, _, _ = self.capture(root)
                target = path if name == 'directory' else path / name
                env = dict(preload_env(BIN, ROOT / 'build/shim/checkpoint_faults.so'),
                           MV_IO_SWAP_READ=str(target))
                if name == 'directory':
                    env['MV_IO_SWAP_DIRECTORY'] = '1'
                result = subprocess.run([str(BIN), 'report', '--allow-partial', str(path)],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertTrue(Path(str(target) + '.displaced').exists(), 'swap boundary not reached')
                if name != 'directory':
                    self.assertEqual(target.read_bytes(), b'foreign evidence')

    def test_corrupt_prefix_never_salvages(self):
        for mutation in ('digest', 'literal', 'identity', 'kinds', 'torn-prefix', 'unknown-version'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as root:
                path, doc, raw = self.capture(root, b'ignored suffix')
                integrity = doc['capture']['integrity']
                if mutation == 'digest':
                    integrity['events_sha256'] = 'f' * 64
                elif mutation == 'literal':
                    raw = raw.replace(b'4096', b'4097', 1)
                    (path / 'events.ndjson').write_bytes(raw + b'ignored suffix')
                elif mutation == 'identity':
                    doc['session_id'] = 'different-session'
                elif mutation == 'kinds':
                    integrity['kinds']['bounce_attempt'] = '2'
                    integrity['kinds']['copy'] = '1'
                elif mutation == 'torn-prefix':
                    integrity['events_bytes'] = str(len(raw)-1)
                    integrity['events_sha256'] = hashlib.sha256(raw[:-1]).hexdigest()
                else:
                    doc['schema_version'] = '0.1.5'
                (path / 'checkpoint.json').write_text(json.dumps(doc))
                for flags in ((), ('--allow-partial',), ('--allow-partial', '--strict')):
                    result = run(path, *flags)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, '')

    def test_invalid_prefix_and_generation(self):
        for field, value in (('checkpoint_generation', '0'), ('checkpoint_generation', '01')):
            with tempfile.TemporaryDirectory() as root:
                path, doc, _ = self.capture(root)
                doc['capture'][field] = value
                (path / 'checkpoint.json').write_text(json.dumps(doc))
                self.assertEqual(run(path, '--allow-partial').returncode, 2)
        with tempfile.TemporaryDirectory() as root:
            path, _, raw = self.capture(root)
            (path / 'events.ndjson').write_bytes(raw[:-1])
            self.assertEqual(run(path, '--allow-partial').returncode, 2)


if __name__ == '__main__':
    unittest.main()
