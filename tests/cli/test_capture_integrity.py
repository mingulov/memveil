#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Literal-byte mutation oracle, version compatibility, and renderer contracts."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/fixtures/reader'
BIN = ROOT / 'build/memveil'
VALIDATOR = runpy.run_path(str(ROOT / 'tools/validate-schemas'))


def report(path, *args):
    return subprocess.run([str(BIN), 'report', *args, str(path)],
                          text=True, capture_output=True)


class IntegrityTests(unittest.TestCase):
    def assert_unverified(self, doc):
        self.assertEqual(doc['integrity'], {'status': 'legacy_unverified',
                         'verified_bytes': '0', 'verified_events': '0'})
        self.assertNotEqual(doc['verdict']['name'], 'complete')
        def walk(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in ('status', 'coverage'):
                        self.assertNotEqual(item, 'complete_for_scope')
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
        walk(doc['quality'])
        walk(doc['metrics'])

    @classmethod
    def setUpClass(cls):
        (ROOT / 'build/shim').mkdir(parents=True, exist_ok=True)
        subprocess.run(['clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-shared', '-fPIC', str(ROOT / 'tests/cli/capture_faults.c'),
                        '-o', str(ROOT / 'build/shim/capture_faults.so')], check=True)

    def test_finalized_special_files_refuse_before_reading(self):
        for fixture in ('sealed-complete', 'sealed-empty', 'complete-stop'):
            for name in ('session.json', 'events.ndjson'):
                for kind in ('fifo', 'directory', 'device-link'):
                    with self.subTest(fixture=fixture, name=name, kind=kind), tempfile.TemporaryDirectory() as tmp:
                        path = Path(tmp)
                        for entry in ('session.json', 'events.ndjson'):
                            shutil.copy(FIXTURES / fixture / entry, path)
                        target = path / name
                        target.unlink()
                        if kind == 'fifo':
                            os.mkfifo(target)
                        elif kind == 'directory':
                            target.mkdir()
                        else:
                            target.symlink_to('/dev/null')
                        for verb in ('report', 'top'):
                            for flags in ((), ('--allow-partial',), ('--strict',), ('--allow-partial', '--strict')):
                                proc = subprocess.run([str(BIN), verb, *flags, str(path)],
                                                      capture_output=True, timeout=3)
                                self.assertEqual(proc.returncode, 2, proc.stderr)
                                self.assertEqual(proc.stdout, b'')
                                self.assertTrue(proc.stderr)

    def test_stream_creation_failure_is_reported_after_regular_open(self):
        for verb in ('report', 'top'):
            with self.subTest(verb=verb), tempfile.TemporaryDirectory() as tmp:
                marker = Path(tmp) / 'reached'
                env = dict(os.environ, LD_PRELOAD=str(ROOT / 'build/shim/capture_faults.so'),
                           MEMVEIL_TEST_NO_BPF='1', MV_FAIL_FDOPEN_EVENTS='1', MV_FAULT_MARKER=str(marker))
                proc = subprocess.run([str(BIN), verb, str(FIXTURES / 'sealed-complete')],
                                      env=env, capture_output=True, timeout=3)
                self.assertEqual(marker.read_text(), 'events-fdopen-failure')
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(proc.stdout, b'')
                self.assertIn(b'cannot open stream', proc.stderr)

    def test_open_time_fifo_swap_reads_the_pinned_regular_descriptor(self):
        for verb in ('report', 'top'):
            for flags in ((), ('--allow-partial',), ('--strict',), ('--allow-partial', '--strict')):
                with self.subTest(verb=verb, flags=flags), tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp)
                    for name in ('session.json', 'events.ndjson'):
                        shutil.copy(FIXTURES / 'sealed-complete' / name, path)
                    marker = path / 'reached'
                    env = dict(os.environ, LD_PRELOAD=str(ROOT / 'build/shim/capture_faults.so'),
                               MEMVEIL_TEST_NO_BPF='1', MV_FINAL_OPEN_SWAP=str(path / 'events.ndjson'),
                               MV_FAULT_MARKER=str(marker))
                    proc = subprocess.run([str(BIN), verb, *flags, str(path)], env=env,
                                          capture_output=True, timeout=3)
                    self.assertEqual(marker.read_text(), 'events-open-swap')
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertTrue(proc.stdout)
                    self.assertTrue((path / 'events.ndjson').is_fifo())
                    self.assertEqual((path / 'events.ndjson.saved').read_bytes(),
                                     (FIXTURES / 'sealed-complete/events.ndjson').read_bytes())

    def test_finalized_regular_symlinks_and_hardlinks_remain_compatible(self):
        for kind in ('symlink', 'hardlink'):
            for fixture in ('sealed-complete', 'complete-stop'):
                with self.subTest(kind=kind, fixture=fixture), tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp)
                    for name in ('session.json', 'events.ndjson'):
                        if kind == 'symlink':
                            (path / name).symlink_to(FIXTURES / fixture / name)
                        else:
                            shutil.copy(FIXTURES / fixture / name, path / (name + '.real'))
                            os.link(path / (name + '.real'), path / name)
                    for verb in ('report', 'top'):
                        proc = subprocess.run([str(BIN), verb, str(path)], capture_output=True, timeout=3)
                        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_pristine_and_partial_all_renderers(self):
        for name, strict_exit in [('sealed-complete', 0), ('sealed-partial', 4),
                                  ('sealed-empty', 4)]:
            path = FIXTURES / name
            session, summary = VALIDATOR['validate_capture'](path)
            raw = (path / 'events.ndjson').read_bytes()
            sealed = json.loads((path / 'session.json').read_text())['capture']['integrity']
            self.assertEqual(sealed['events_sha256'], hashlib.sha256(raw).hexdigest())
            for fmt in ('json', 'text', 'markdown'):
                for flags, wanted in [((), 0), (('--strict',), strict_exit)]:
                    with self.subTest(name=name, fmt=fmt, flags=flags):
                        proc = report(path, '--format', fmt, *flags)
                        self.assertEqual(proc.returncode, wanted, proc.stderr)
                        if fmt == 'json':
                            doc = json.loads(proc.stdout)
                            self.assertEqual(doc['schema_version'], '0.1.4')
                            self.assertEqual(doc['integrity'], {
                                'status': 'verified', 'verified_bytes': str(len(raw)),
                                'verified_events': sealed['line_count']})
                            VALIDATOR['compare_report_obj'](doc, session, summary)
                        else:
                            self.assertIn('integrity: verified', proc.stdout)
                            self.assertIn('no authenticity claim', proc.stdout)

    def test_legacy_generations_all_renderers(self):
        for name in ('counters-single', 'f2-dangling-split-copy-ok', 'complete-stop', 'ev012'):
            path = FIXTURES / name
            session, summary = VALIDATOR['validate_capture'](path)
            for fmt in ('json', 'text', 'markdown'):
                for flags, wanted in [((), 0), (('--strict',), 4)]:
                    with self.subTest(name=name, fmt=fmt, flags=flags):
                        proc = report(path, '--format', fmt, *flags)
                        self.assertEqual(proc.returncode, wanted, proc.stderr)
                        if fmt == 'json':
                            doc = json.loads(proc.stdout)
                            self.assert_unverified(doc)
                            VALIDATOR['compare_report_obj'](doc, session, summary)
                        else:
                            self.assertIn('integrity: legacy_unverified', proc.stdout)
                            self.assertIn('arithmetic is unverified', proc.stdout)

    def test_mutations_refuse_in_every_mode(self):
        source = FIXTURES / 'sealed-complete'
        original = (source / 'session.json').read_bytes()
        raw = (source / 'events.ndjson').read_bytes()
        lines = raw.splitlines(keepends=True)
        self.assertGreaterEqual(len(lines), 3)
        edits = {
            'delete-first': b''.join(lines[1:]),
            'delete-middle': b''.join(lines[:1] + lines[2:]),
            'delete-last': b''.join(lines[:-1]),
            'same-length': raw.replace(b'4096', b'4097', 1),
            'append': raw + lines[-1],
            'swap': b''.join([lines[1], lines[0]] + lines[2:]),
            'duplicate': b''.join(lines[:1] + lines),
            'missing-newline': raw[:-1],
            'truncated-tail': raw[:-10],
            'whitespace': raw.replace(b'{', b'{ ', 1),
            'carriage-return': raw.replace(b'\n', b'\r\n', 1),
        }
        self.assertEqual(len(edits['same-length']), len(raw))
        for name, changed in edits.items():
            self.assertNotEqual(changed, raw, name)
        session_edits = {}
        base = json.loads(original)
        for field in ('events_bytes', 'line_count', 'kinds', 'events_sha256'):
            changed = copy.deepcopy(base)
            integrity = changed['capture']['integrity']
            if field == 'events_bytes':
                integrity[field] = str(len(raw) + 1)
            elif field == 'line_count':
                integrity[field] = str(len(lines) + 1)
                integrity['last_seq'] = str(len(lines))
                integrity['kinds']['marker'] = '1'
            elif field == 'kinds':
                integrity['kinds']['bounce_attempt'] = str(int(integrity['kinds']['bounce_attempt']) - 1)
                integrity['kinds']['marker'] = '1'
            else:
                integrity[field] = '0' * 64
            session_edits[field] = json.dumps(changed).encode()
        with tempfile.TemporaryDirectory(prefix='memveil-integrity-') as tmp:
            path = Path(tmp)
            cases = [(name, original, data) for name, data in edits.items()]
            cases += [(name, data, raw) for name, data in session_edits.items()]
            for name, session_bytes, events_bytes in cases:
                (path / 'session.json').write_bytes(session_bytes)
                (path / 'events.ndjson').write_bytes(events_bytes)
                if name in edits:
                    self.assertEqual((path / 'session.json').read_bytes(), original)
                with self.assertRaises(VALIDATOR['Error'], msg=name):
                    VALIDATOR['validate_capture'](path)
                for fmt in ('json', 'text', 'markdown'):
                    for flags in ((), ('--strict',), ('--allow-partial',),
                                  ('--strict', '--allow-partial')):
                        with self.subTest(mutation=name, fmt=fmt, flags=flags):
                            proc = report(path, '--format', fmt, *flags)
                            self.assertEqual(proc.returncode, 2, proc.stderr)
                            self.assertEqual(proc.stdout, '')
                            self.assertTrue(proc.stderr)
                            if name in session_edits:
                                self.assertIn('integrity', proc.stderr)
                                self.assertIn('mismatch', proc.stderr)

    def test_literal_chunk_boundaries_and_line_limit(self):
        source = FIXTURES / 'sealed-complete'
        original = json.loads((source / 'session.json').read_text())
        lines = (source / 'events.ndjson').read_bytes().splitlines(keepends=True)
        with tempfile.TemporaryDirectory(prefix='memveil-chunks-') as tmp:
            path = Path(tmp)
            for length, expected in [(65535, 0), (65536, 0), (65537, 2)]:
                raw = b' ' * (length - len(lines[0])) + b''.join(lines)
                session = copy.deepcopy(original)
                session['capture']['integrity']['events_bytes'] = str(len(raw))
                session['capture']['integrity']['events_sha256'] = hashlib.sha256(raw).hexdigest()
                (path / 'session.json').write_text(json.dumps(session))
                (path / 'events.ndjson').write_bytes(raw)
                proc = report(path, '--format', 'json')
                self.assertEqual(proc.returncode, expected, proc.stderr)
                if expected == 0:
                    doc = json.loads(proc.stdout)
                    self.assertEqual(doc['integrity']['verified_bytes'], str(len(raw)))
                    self.assertEqual(doc['integrity']['verified_events'], '3')
                else:
                    self.assertIn('line too large', proc.stderr)
                    self.assertEqual(proc.stdout, '')

    def test_verified_and_legacy_arithmetic_agree(self):
        legacy = json.loads(report(FIXTURES / 'complete-stop', '--format', 'json').stdout)
        sealed = json.loads(report(FIXTURES / 'sealed-complete', '--format', 'json').stdout)
        for old, new in zip(legacy['metrics'], sealed['metrics'], strict=True):
            old = dict(old)
            new = dict(new)
            old.pop('coverage')
            new.pop('coverage')
            self.assertEqual(old, new)
        self.assertEqual(sealed['verdict']['name'], 'complete')
        self.assertEqual(legacy['verdict']['name'], 'partial_unknown_loss')
        for channel in ('detail', 'aggregate', 'correlation', 'baseline', 'terminal'):
            self.assertEqual(legacy['quality'][channel]['loss_count'], sealed['quality'][channel]['loss_count'])
        self.assertEqual(sealed['quality']['aggregate']['status'], 'unavailable')
        self.assertEqual(sealed['quality']['baseline']['status'], 'not_applicable')

    def test_unknown_version_all_modes(self):
        with tempfile.TemporaryDirectory(prefix='memveil-version-') as tmp:
            path = Path(tmp)
            shutil.copy(FIXTURES / 'sealed-complete/events.ndjson', path)
            doc = json.loads((FIXTURES / 'sealed-complete/session.json').read_text())
            doc['schema_version'] = '0.1.5'
            (path / 'session.json').write_text(json.dumps(doc))
            for flags in ((), ('--strict',), ('--allow-partial',)):
                proc = report(path, *flags)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, '')

    def test_report_integrity_oracle_rejects_false_claims(self):
        path = FIXTURES / 'complete-stop'
        session, summary = VALIDATOR['validate_capture'](path)
        doc = json.loads(report(path, '--format', 'json').stdout)
        mutations = []
        for field, value in [('status', 'verified'), ('verified_bytes', '1'),
                             ('verified_events', '1')]:
            altered = copy.deepcopy(doc)
            altered['integrity'][field] = value
            mutations.append(altered)
        altered = copy.deepcopy(doc)
        del altered['integrity']
        mutations.append(altered)
        for channel in ('detail', 'aggregate', 'correlation', 'baseline', 'terminal'):
            altered = copy.deepcopy(doc)
            altered['quality'][channel]['status'] = 'complete_for_scope'
            mutations.append(altered)
        altered = copy.deepcopy(doc)
        altered['metrics'][0]['coverage'] = 'complete_for_scope'
        mutations.append(altered)
        for index, altered in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaises(VALIDATOR['Error']):
                    VALIDATOR['compare_report_obj'](altered, session, summary)

    def test_sealer_filesystem_refusals_and_concurrent_creation(self):
        with tempfile.TemporaryDirectory(prefix='memveil-sealer-states-') as tmp:
            root = Path(tmp)
            (root / 'tools').mkdir()
            tool = root / 'tools/seal-capture'
            shutil.copy(ROOT / 'tools/seal-capture', tool)
            fixtures = root / 'tests/fixtures/reader'
            fixtures.mkdir(parents=True)
            source = root / 'source'
            source.mkdir()
            for name in ('session.json', 'events.ndjson'):
                shutil.copy(FIXTURES / 'complete-stop' / name, source / name)
            def command(target):
                return [str(tool), str(source), str(target)]
            regular = fixtures / 'sealed-file'
            regular.write_bytes(b'preserve')
            fifo = fixtures / 'sealed-fifo'
            os.mkfifo(fifo)
            link = fixtures / 'sealed-link'
            link.symlink_to(source, target_is_directory=True)
            partial = fixtures / 'sealed-partial'
            partial.mkdir()
            (partial / 'events.ndjson').write_bytes(b'preserve')
            for target in (regular, fifo, link, partial):
                proc = subprocess.run(command(target), capture_output=True)
                self.assertEqual(proc.returncode, 2)
            self.assertEqual(regular.read_bytes(), b'preserve')
            self.assertEqual((partial / 'events.ndjson').read_bytes(), b'preserve')
            self.assertTrue(fifo.is_fifo())
            self.assertTrue(link.is_symlink())
            target = fixtures / 'sealed-concurrent'
            first = subprocess.Popen(command(target), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            second = subprocess.Popen(command(target), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            first.communicate()
            second.communicate()
            self.assertEqual(sorted([first.returncode, second.returncode]), [0, 2])
            VALIDATOR['validate_capture'](target)
            session_path = source / 'session.json'
            session_path.unlink()
            session_path.symlink_to(FIXTURES / 'complete-stop/session.json')
            refused = fixtures / 'sealed-source-link'
            proc = subprocess.run(command(refused), capture_output=True)
            self.assertEqual(proc.returncode, 2)
            self.assertFalse(refused.exists())
            session_path.unlink()
            os.mkfifo(session_path)
            refused = fixtures / 'sealed-source-fifo'
            proc = subprocess.run(command(refused), capture_output=True)
            self.assertEqual(proc.returncode, 2)
            self.assertFalse(refused.exists())

    def test_sealer_refuses_existing_and_unsafe_targets(self):
        sealer = ROOT / 'tools/seal-capture'
        source = FIXTURES / 'complete-stop'
        targets = [FIXTURES / 'sealed-complete', ROOT / 'examples/sealed-unsafe',
                   FIXTURES / 'complete-stop']
        before = (FIXTURES / 'sealed-complete/session.json').read_bytes()
        for target in targets:
            proc = subprocess.run([str(sealer), str(source), str(target)], capture_output=True)
            self.assertEqual(proc.returncode, 2)
        self.assertEqual((FIXTURES / 'sealed-complete/session.json').read_bytes(), before)
        with tempfile.TemporaryDirectory(prefix='memveil-sealer-') as tmp:
            link = Path(tmp) / 'link'
            link.symlink_to(FIXTURES, target_is_directory=True)
            proc = subprocess.run([str(sealer), str(source), str(link / 'sealed-refuse')], capture_output=True)
            self.assertEqual(proc.returncode, 2)
            self.assertFalse((FIXTURES / 'sealed-refuse').exists())


if __name__ == '__main__':
    unittest.main()
