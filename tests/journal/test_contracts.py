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

class ReportValidation(unittest.TestCase):
    def mutate_fixture(self, name, filename, path, value, reason):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / name
            shutil.copytree(ROOT / 'tests/fixtures/journal' / name, folder)
            document = json.loads((folder / filename).read_text())
            target = document
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = value
            (folder / filename).write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, reason):
                contract.validate_fixtures(Path(temporary))

    def test_report_arithmetic_and_privacy_controls(self):
        for filename, path, value, reason in [
            ('report.json', ['journal', 'requested_bytes'], '8192', 'report journal'),
            ('report.json', ['journal', 'successes'], '999', 'report journal'),
            ('report.json', ['raw_address'], 'redacted', 'schema'),
            ('session.json', ['journal', 'raw_address'], 'redacted', 'schema'),
            ('report.json', ['quality', 'terminal', 'status'], 'complete_for_scope', 'report quality'),
        ]:
            with self.subTest(path=path):
                self.mutate_fixture('success', filename, path, value, reason)

    def test_report_source_derived_fields(self):
        for path, value, reason in [
            (['journal', 'requests'], '2', 'report journal'),
            (['journal', 'failures'], '1', 'report journal'),
            (['journal', 'unmatched_exits'], '1', 'report journal'),
            (['journal', 'censored'], '1', 'report journal'),
            (['integrity', 'verified_bytes'], '0', 'report integrity'),
            (['integrity', 'verified_events'], '0', 'report integrity'),
            (['integrity', 'status'], 'legacy_unverified', 'schema.*quality.detail.status'),
            (['session_id'], 'foreign', 'report provenance'),
            (['synthetic'], False, 'report provenance'),
            (['environment', 'mode'], 'sev_snp', 'report provenance'),
            (['engine_version'], 'real-qualified-build', 'report provenance'),
            (['verdict', 'name'], 'complete', 'report verdict'),
            (['verdict', 'delivered'], '1', 'report verdict'),
            (['verdict', 'loss_ratio_bps'], '1', 'report verdict'),
        ]:
            with self.subTest(path=path):
                self.mutate_fixture('success', 'report.json', path, value, reason)
        for channel in ('detail', 'aggregate', 'correlation', 'baseline', 'terminal'):
            with self.subTest(channel=channel):
                self.mutate_fixture('success', 'report.json', ['quality', channel, 'reason'], 'invented evidence', 'report quality')
        for name, path, value, reason in [
            ('invalid-pages', ['journal', 'requested_bytes_reason'], 'incomplete_evidence', 'report journal'),
            ('open-checkpoint', ['journal', 'censored_reason'], 'read_failed', 'report journal'),
            ('open-checkpoint', ['integrity', 'unverified_bytes'], '1', 'report integrity'),
            ('initial-checkpoint', ['quality', 'detail', 'status'], 'complete_for_scope', 'schema.*quality.detail.status'),
            ('censored', ['journal', 'censored'], '0', 'report journal'),
            ('failure', ['findings', 0, 'evidence_refs'], ['event:99'], 'report findings'),
            ('failure', ['findings', 0, 'severity'], 'informational', 'report findings'),
        ]:
            with self.subTest(name=name, path=path):
                self.mutate_fixture(name, 'report.json', path, value, reason)

    def test_required_exclusions(self):
        required = (
            'Boot and pre-attach conversions are excluded.',
            'MMIO conversions are excluded.',
            'Kexec and accept paths are excluded.',
            'Unobserved conversion paths are excluded.',
        )
        for path in sorted((ROOT / 'tests/fixtures/journal').glob('*/report.json')):
            report = json.loads(path.read_text())
            for exclusion in required:
                with self.subTest(fixture=path.parent.name, exclusion=exclusion):
                    self.assertIn(exclusion, report['limitations'])
                    limitations = [x for x in report['limitations'] if x != exclusion]
                    self.mutate_fixture(path.parent.name, 'report.json', ['limitations'], limitations, 'report exclusions')

    def test_event_source_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / 'success'
            shutil.copytree(ROOT / 'tests/fixtures/journal/success', folder)
            event = json.loads((folder / 'events.ndjson').read_text())
            for field, value in [('profile_id', 'foreign'), ('backend', 'fentry_fexit')]:
                bad = copy.deepcopy(event)
                bad['source'][field] = value
                contract.validate_document(bad, 'event-v0.2.0')
                (folder / 'events.ndjson').write_text(json.dumps(bad) + '\n')
                with self.assertRaisesRegex(ValueError, 'event provenance'):
                    contract.validate_capture(folder)

    def test_unknown_measurements_are_not_zero(self):
        for name, field in [('open-checkpoint', 'censored'), ('invalid-pages', 'requested_bytes')]:
            journal = json.loads((ROOT / 'tests/fixtures/journal' / name / 'report.json').read_text())['journal']
            journal[field] = '0'
            journal[field + '_reason'] = None
            self.mutate_fixture(name, 'report.json', ['journal'], journal, 'report journal')

    def test_optional_provenance_and_invented_metrics(self):
        session = json.loads((ROOT / 'tests/fixtures/journal/success/session.json').read_text())
        capabilities = {k: dict(status=v['status'], grade=v.get('grade'), reason=v['reason']) for k, v in session['capabilities'].items()}
        report = json.loads((ROOT / 'tests/fixtures/journal/success/report.json').read_text())
        report['capabilities'] = copy.deepcopy(capabilities)
        contract.validate_document(report, 'report-v0.2.0')
        contract.validate_report(report, contract.capture_evidence(ROOT / 'tests/fixtures/journal/success'))
        capabilities['conversion_results']['grade'] = 'validated'
        self.mutate_fixture('success', 'report.json', ['capabilities'], capabilities, 'report provenance capabilities')
        self.mutate_fixture('success', 'report.json', ['device_catalog', 'devices'],
                            [{'device_id': 'foreign', 'name': 'foreign', 'identity_status': 'resolved'}], 'report provenance device_catalog')
        metric = dict(name='invented', value='1', unit='count', measurement='observed', coverage='complete_for_scope',
                      confidence='high', aggregation='counter', sample_count=None, dimensions=dict(device_id=None, pool_id=None),
                      scope='global', notes='')
        self.mutate_fixture('success', 'report.json', ['metrics'], [metric], 'report metrics')

    def test_independent_mixed_results_and_counter_alternatives(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / 'success'
            shutil.copytree(ROOT / 'tests/fixtures/journal/success', folder)
            session = json.loads((folder / 'session.json').read_text())
            row = json.loads((folder / 'events.ndjson').read_text())
            rows = [copy.deepcopy(row) for _ in range(3)]
            for i, event in enumerate(rows):
                event['seq'] = str(i)
                event['data'].update(operation_token=str(i + 1), requested_native_pages=i + 2,
                                     requested_pages=str(i + 2), requested_bytes=str((i + 2) * 4096))
            rows[1]['data'].update(direction='encrypt', requested_state='private', native_result=-5)
            rows[1]['source']['hook'] = 'set_memory_encrypted'
            rows[2]['data'].update(membership='unmatched_exit', operation_token=None, entry_ns=None, native_result=-5)
            rows[2]['source']['correlation'] = 'unpaired'
            raw = b''.join((json.dumps(event) + '\n').encode() for event in rows)
            (folder / 'events.ndjson').write_bytes(raw)
            session['capture']['integrity'].update(events_bytes=str(len(raw)), line_count='3', last_seq='2', events_sha256=hashlib.sha256(raw).hexdigest())
            session['capture']['integrity']['kinds']['transition_result'] = '3'
            session['journal']['counters'].update(entries='999', exits='888', matched_results='777', unmatched_exits='666', censored='5')
            (folder / 'session.json').write_text(json.dumps(session))
            evidence = contract.capture_evidence(folder)
            expected = dict(requests='2', successes='1', failures='1', unmatched_exits='1', censored='5', censored_reason=None,
                            requested_bytes='20480', requested_bytes_reason=None, shared_bytes=None, unreverted_ranges=None,
                            state_reason='request_only_source')
            self.assertEqual(evidence['journal'], expected)
            self.assertEqual(evidence['failed_refs'], ['event:1'])
            self.assertEqual(evidence['integrity'], dict(status='verified', verified_bytes=str(len(raw)), verified_events='3'))
            for reason in ('not_observable', 'read_failed', 'overflow'):
                session['journal']['counters']['censored'] = None
                session['journal']['counter_reasons']['censored'] = reason
                (folder / 'session.json').write_text(json.dumps(session))
                evidence = contract.capture_evidence(folder)
                self.assertIsNone(evidence['journal']['censored'])
                self.assertEqual(evidence['journal']['censored_reason'], reason)

    def test_schema_vocabulary_and_json_bounds(self):
        for document in contract.SCHEMA_NAMES:
            schema = contract.document_schema(document)
            for keyword in ('format', 'oneOf', 'unevaluatedProperties'):
                bad = copy.deepcopy(schema)
                bad['$defs'] = dict(bad.get('$defs', {}), unused={keyword: []})
                with self.assertRaisesRegex(ValueError, 'unsupported vocabulary'):
                    contract.audit_schema(bad, bad)
        schema = {'$ref': 'https://invalid.example/schema'}
        with self.assertRaisesRegex(ValueError, 'unsupported reference'):
            contract.audit_schema(schema, schema)
        self.assertFalse(contract.json_equal(True, 1))
        with self.assertRaisesRegex(ValueError, 'document limit'):
            contract.read_json(b' ' * 16777217)
        with self.assertRaisesRegex(ValueError, 'nesting limit'):
            contract.read_json(b'[' * 2000 + b'0' + b']' * 2000)
        for raw in (b'NaN', b'Infinity', b'-Infinity', b'1e999'):
            with self.assertRaisesRegex(ValueError, 'nonfinite'):
                contract.read_json(raw)
        for raw in (b'{"same":0,"same":1}', b'{"outer":{"same":0,"same":1}}'):
            with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
                contract.read_json(raw)
        schema = contract.document_schema('session-v0.2.0')
        for value in ('18446744073709551616', '0\n'):
            with self.assertRaisesRegex(ValueError, 'schema.*u64'):
                contract.check_schema(value, {'$ref': '#/$defs/u64'}, schema)
        contract.check_schema('18446744073709551615', {'$ref': '#/$defs/u64'}, schema)
        # Reference siblings are constraints too.
        with self.assertRaisesRegex(ValueError, 'schema.*const'):
            contract.check_schema('1', {'$ref': '#/$defs/u64', 'const': '0'}, schema)

    def test_complete_document_structure(self):
        documents = [
            ('success/session.json', 'session-v0.2.0'),
            ('initial-checkpoint/checkpoint.json', 'session-v0.2.0'),
            ('open-checkpoint/checkpoint.json', 'session-v0.2.0'),
            ('success/events.ndjson', 'event-v0.2.0'),
            ('failure/report.json', 'report-v0.2.0'),
            ('range-manifest.json', 'confidential-range-manifest-v1'),
            ('late-manifest.json', 'confidential-range-manifest-v1'),
            ('guest-manifest.json', 'confidential-guest-manifest-v1'),
        ]
        def object_paths(value, path=()):
            if type(value) is dict:
                yield path
                for key, item in value.items():
                    yield from object_paths(item, path + (key,))
            elif type(value) is list:
                for i, item in enumerate(value):
                    yield from object_paths(item, path + (i,))
        for filename, schema in documents:
            original = json.loads((ROOT / 'tests/fixtures/journal' / filename).read_text())
            contract.validate_document(original, schema)
            for path in object_paths(original):
                with self.subTest(document=filename, path=path):
                    bad = copy.deepcopy(original)
                    obj = bad
                    for part in path:
                        obj = obj[part]
                    obj['raw_address'] = 'redacted'
                    with self.assertRaisesRegex(ValueError, 'schema'):
                        contract.validate_document(bad, schema)

    def test_schema_constraints_reach_their_boundaries(self):
        cases = [
            ('success/session.json', 'session-v0.2.0', ['product', 'version'], '', 'minLength'),
            ('success/session.json', 'session-v0.2.0', ['environment', 'mode'], 'foreign', 'enum'),
            ('success/session.json', 'session-v0.2.0', ['capture', 'window', 'start_ns'], '01', 'pattern'),
            ('success/session.json', 'session-v0.2.0', ['journal', 'epoch'], '0', 'not'),
            ('success/session.json', 'session-v0.2.0', ['journal', 'callers'], 1, 'type'),
            ('success/session.json', 'session-v0.2.0', ['journal', 'ring_bytes'], '0', 'const'),
            ('success/session.json', 'session-v0.2.0', ['journal', 'counter_reasons', 'entries'], 'overflow', 'type'),
            ('success/events.ndjson', 'event-v0.2.0', ['data', 'native_result'], 2147483648, 'maximum'),
            ('success/events.ndjson', 'event-v0.2.0', ['data', 'native_result'], -2147483649, 'minimum'),
            ('success/events.ndjson', 'event-v0.2.0', ['data', 'requested_pages'], None, 'type'),
            ('success/events.ndjson', 'event-v0.2.0', ['observer_context'], {'relation': 'execution_context_only'}, 'false'),
            ('success/report.json', 'report-v0.2.0', ['engine_version'], 'x' * 65, 'maxLength'),
            ('success/report.json', 'report-v0.2.0', ['limitations'], ['x'] * 257, 'maxItems'),
            ('success/report.json', 'report-v0.2.0', ['journal', 'censored'], None, 'type'),
            ('range-manifest.json', 'confidential-range-manifest-v1', ['required_cases'], [], 'minItems'),
            ('range-manifest.json', 'confidential-range-manifest-v1', ['required_cases'], ['same', 'same'], 'uniqueItems'),
        ]
        for filename, schema, path, value, reason in cases:
            with self.subTest(document=filename, path=path):
                document = json.loads((ROOT / 'tests/fixtures/journal' / filename).read_text())
                contract.validate_document(document, schema)
                target = document
                for field in path[:-1]:
                    target = target[field]
                target[path[-1]] = value
                with self.assertRaisesRegex(ValueError, 'schema.*' + reason):
                    contract.validate_document(document, schema)
        for filename, schema in [('success/session.json', 'session-v0.2.0'), ('open-checkpoint/checkpoint.json', 'session-v0.2.0'), ('success/events.ndjson', 'event-v0.2.0'), ('success/report.json', 'report-v0.2.0'), ('guest-manifest.json', 'confidential-guest-manifest-v1')]:
            document = json.loads((ROOT / 'tests/fixtures/journal' / filename).read_text())
            for field in document:
                if schema == 'report-v0.2.0' and field == 'capabilities':
                    continue
                with self.subTest(document=filename, missing=field):
                    bad = copy.deepcopy(document)
                    del bad[field]
                    with self.assertRaisesRegex(ValueError, 'schema.*required'):
                        contract.validate_document(bad, schema)

if __name__ == '__main__':
    unittest.main()
