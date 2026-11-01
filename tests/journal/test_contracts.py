#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent fixed values and negative controls for journal contracts."""
import copy
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import unittest
import tempfile
import shutil
import resource
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader('journal_contracts', str(ROOT / 'tools/validate-journal-contracts'))
spec = importlib.util.spec_from_loader(loader.name, loader)
contract = importlib.util.module_from_spec(spec)
loader.exec_module(contract)

class Contracts(unittest.TestCase):
    def test_fixtures(self):
        self.assertEqual(contract.validate_fixtures(ROOT / 'tests/fixtures/journal'), 13)
        expected = {'success': (1, 0), 'failure': (1, 1), 'orphan-encrypt': (1, 0), 'overlap': (2, 0),
                    'pre-attach': (0, 0), 'unresolved': (1, 0), 'disabled': (1, 0), 'persistent': (1, 0), 'invalid-pages': (1, 0),
                    'initial-checkpoint': (0, 0), 'open-checkpoint': (1, 0), 'censored': (1, 0)}
        for name, counts in expected.items():
            self.assertEqual(contract.validate_capture(ROOT / 'tests/fixtures/journal' / name), counts)
        for name in ('initial-checkpoint', 'open-checkpoint'):
            report = json.loads((ROOT / 'tests/fixtures/journal' / name / 'report.json').read_text())
            self.assertEqual(report['integrity']['status'], 'checkpoint_prefix')
            self.assertEqual(report['quality']['detail']['status'], 'partial')
            self.assertIsNone(report['journal']['censored'])
            self.assertEqual(report['journal']['censored_reason'], 'not_observable')
        report = json.loads((ROOT / 'tests/fixtures/journal/censored/report.json').read_text())
        self.assertEqual(report['journal']['censored'], '1')
        self.assertEqual(report['journal']['requests'], '1')
        with self.assertRaisesRegex(ValueError, 'duplicate operation token'):
            contract.validate_capture(ROOT / 'tests/fixtures/journal/duplicate')

    def test_event_refusals(self):
        event = json.loads((ROOT / 'tests/fixtures/journal/success/events.ndjson').read_text())
        contract.validate_event(event)
        mutations = [
            ('schema_version', '0.3.0'), ('seq', '18446744073709551616'),
            ('seq', '01'), ('seq', 1), ('raw_address', 'redacted'),
        ]
        for key, value in mutations:
            bad = copy.deepcopy(event)
            bad[key] = value
            with self.assertRaises(ValueError, msg=key):
                contract.validate_event(bad)
        for key, value in [('region', {}), ('effect', 'kernel_reported_state'),
                           ('requested_bytes', '8192'), ('requested_pages', '2'),
                           ('native_result', 4294967295), ('operation_token', '0')]:
            bad = copy.deepcopy(event)
            bad['data'][key] = value
            with self.assertRaises(ValueError, msg=key):
                contract.validate_event(bad)
        for key, value in [('label', 'arbitrary_symbol'), ('class', 'swiotlb'), ('status', 'resolved')]:
            bad = copy.deepcopy(event)
            bad['data']['caller'][key] = value
            with self.assertRaises(ValueError, msg=key):
                contract.validate_event(bad)

    def test_schema_family(self):
        event = json.loads((ROOT / 'schemas/event-v0.2.0.schema.json').read_text())
        session = json.loads((ROOT / 'schemas/session-v0.2.0.schema.json').read_text())
        kinds = event['properties']['kind']['enum']
        integrity = session['properties']['capture']['properties']['integrity']['properties']['kinds']
        self.assertEqual(set(kinds), set(integrity['required']))
        self.assertEqual(set(kinds), set(integrity['properties']))
        self.assertEqual(len(kinds), 10)
        for name in ('session', 'event', 'report'):
            schema = json.loads((ROOT / ('schemas/' + name + '-v0.2.0.schema.json')).read_text())
            self.assertEqual(schema['properties']['schema_version'], {'const': '0.2.0'})

    def test_window_and_state_negative_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / 'capture'
            shutil.copytree(ROOT / 'tests/fixtures/journal/success', folder)
            session = json.loads((folder / 'session.json').read_text())
            for section, key, value in [('journal', 'admission_end_ns', '1000000001'),
                                        ('journal', 'epoch', '2'),
                                        ('journal', 'region_identity', 'invented'),
                                        ('baseline', 'complete', True)]:
                bad = copy.deepcopy(session)
                bad[section][key] = value
                (folder / 'session.json').write_text(json.dumps(bad))
                with self.assertRaises(ValueError, msg=key):
                    contract.validate_capture(folder)
            unknown = copy.deepcopy(session)
            unknown['journal']['counters']['missed_callbacks'] = None
            (folder / 'session.json').write_text(json.dumps(unknown))
            with self.assertRaises(ValueError):
                contract.validate_capture(folder)
            unknown['journal']['counter_reasons']['missed_callbacks'] = 'not_observable'
            (folder / 'session.json').write_text(json.dumps(unknown))
            contract.validate_capture(folder)
            (folder / 'session.json').write_text(json.dumps(session))
            with (folder / 'events.ndjson').open('ab') as stream:
                stream.write(b' ')
            with self.assertRaises(ValueError):
                contract.validate_capture(folder)

    def test_checkpoint_window_states(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / 'capture'
            shutil.copytree(ROOT / 'tests/fixtures/journal/success', folder)
            session = json.loads((folder / 'session.json').read_text())
            session['capture'].update(finalized=False, end_reason='checkpoint', checkpoint_generation='1')
            session['journal'].update(admission_end_ns=None, admission_end_reason='admission_open', admission_start_reason=None)
            session['journal']['counters']['censored'] = None
            session['journal']['counter_reasons']['censored'] = 'not_observable'
            (folder / 'session.json').unlink()
            (folder / 'checkpoint.json').write_text(json.dumps(session))
            self.assertEqual(contract.validate_capture(folder), (1, 0))
            initial = copy.deepcopy(session)
            initial['journal'].update(admission_start_ns=None, admission_start_reason='not_opened', admission_end_reason='not_opened')
            for key in initial['journal']['counters']:
                if initial['journal']['counters'][key] is not None:
                    initial['journal']['counters'][key] = '0'
            (folder / 'events.ndjson').write_bytes(b'')
            integ = initial['capture']['integrity']
            integ.update(events_bytes='0', line_count='0', first_seq=None, last_seq=None, events_sha256=hashlib.sha256(b'').hexdigest())
            integ['kinds'] = {kind: '0' for kind in integ['kinds']}
            (folder / 'checkpoint.json').write_text(json.dumps(initial))
            self.assertEqual(contract.validate_capture(folder), (0, 0))
            invalid = copy.deepcopy(initial)
            invalid['journal']['epoch'] = '0'
            (folder / 'checkpoint.json').write_text(json.dumps(invalid))
            with self.assertRaises(ValueError):
                contract.validate_capture(folder)
            invalid = copy.deepcopy(initial)
            invalid['journal']['counters']['entries'] = '1'
            (folder / 'checkpoint.json').write_text(json.dumps(invalid))
            with self.assertRaises(ValueError):
                contract.validate_capture(folder)
            for key, value in [('admission_start_reason', None), ('admission_end_reason', 'admission_open')]:
                invalid = copy.deepcopy(initial)
                invalid['journal'][key] = value
                (folder / 'checkpoint.json').write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):
                    contract.validate_capture(folder)

    def test_native_extremes_and_orphan_membership(self):
        event = json.loads((ROOT / 'tests/fixtures/journal/success/events.ndjson').read_text())
        event['data'].update(requested_native_pages=2147483647, requested_pages='2147483647', requested_bytes='8796093018112', native_result=-2147483648)
        contract.validate_event(event)
        event['data'].update(requested_native_pages=-2147483648, requested_pages=None, requested_bytes=None, size_reason='invalid_native_pages')
        contract.validate_event(event)
        event['data'].update(operation_token=None, entry_ns=None, membership='unmatched_exit')
        event['source']['correlation'] = 'unpaired'
        contract.validate_event(event)
        event['data']['operation_token'] = '1'
        with self.assertRaises(ValueError):
            contract.validate_event(event)

    def test_oversized_event_stream_is_refused_with_bounded_memory(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / 'success'
            shutil.copytree(ROOT / 'tests/fixtures/journal/success', folder)
            with (folder / 'events.ndjson').open('wb') as stream:
                stream.write(b' ' * 65537)
                stream.seek(96 * 1024 * 1024 - 1)
                stream.write(b'\n')
            def memory_limit():
                resource.setrlimit(resource.RLIMIT_AS, (80 * 1024 * 1024, 80 * 1024 * 1024))
            result = subprocess.run([sys.executable, str(ROOT / 'tools/validate-journal-contracts'), temporary],
                                    capture_output=True, text=True, preexec_fn=memory_limit, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn('line limit/framing', result.stderr)
            self.assertNotIn('MemoryError', result.stderr)

    def test_generated_profile_unadmitted(self):
        profile = json.loads((ROOT / 'profiles/journal-candidates/linux-7.0.14-x86-journal-provisional.json').read_text())
        self.assertEqual(profile['status'], 'unadmitted')
        self.assertEqual(profile['effect'], 'request_only')
        self.assertEqual(profile['linux_commit'], '458c6079fc1d41d564c37679c8ace02cd83ee817')
        for key in ('config_sha256', 'btf_sha256', 'object_sha256'):
            self.assertIsNone(profile[key])

    def test_manifest_binding(self):
        for file, suite in [('range-manifest.json', 'confidential-ranges'), ('guest-manifest.json', 'confidential-real'), ('late-manifest.json', 'confidential-late-attach')]:
            item = json.loads((ROOT / 'tests/fixtures/journal' / file).read_text())
            contract.validate_manifest(item, suite, 'a' * 64, 'linux-7.0.14-x86-journal-provisional')
            item['required_cases'].append(item['required_cases'][0])
            with self.assertRaises(ValueError):
                contract.validate_manifest(item, suite, 'a' * 64, 'linux-7.0.14-x86-journal-provisional')
        manifest = json.loads((ROOT / 'tests/fixtures/journal/range-manifest.json').read_text())
        contract.validate_manifest(manifest, 'confidential-ranges', 'a' * 64, 'linux-7.0.14-x86-journal-provisional')
        with self.assertRaisesRegex(ValueError, 'synthetic'):
            contract.validate_manifest(manifest, 'confidential-ranges', 'a' * 64, 'linux-7.0.14-x86-journal-provisional', qualification=True)
        for key, value in [('candidate_manifest_sha256', 'b' * 64), ('profile_id', 'foreign'), ('required_cases', [])]:
            bad = copy.deepcopy(manifest)
            bad[key] = value
            with self.assertRaises(ValueError):
                contract.validate_manifest(bad, 'confidential-ranges', 'a' * 64, 'linux-7.0.14-x86-journal-provisional')

if __name__ == '__main__':
    unittest.main()
