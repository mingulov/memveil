# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent offline uncertainty regressions; synthetic inputs remain synthetic."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Uncertainty(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cap = Path(self.tmp.name)

    def load(self, fixture):
        path = ROOT / 'tests/fixtures' / fixture
        self.session = json.loads((path / 'session.json').read_text())
        self.events = [json.loads(line) for line in (path / 'events.ndjson').read_text().splitlines()]

    def quality(self, channel, status='partial'):
        self.session['quality'][channel].update(status=status, loss_count='1', reason='Producer evidence lost')

    def gap(self, channel, template):
        ev = copy.deepcopy(template)
        ev.update(kind='gap', ts_ns='1300000000')
        ev['data'] = dict(channel=channel, lost_count='1', reason='Dropped correctness state',
                          window_start_ns='1300000000', window_end_ns='1300000001')
        return ev

    def write(self):
        (self.cap / 'session.json').write_text(json.dumps(self.session))
        for i, ev in enumerate(self.events, 1):
            ev['seq'] = str(i)
        (self.cap / 'events.ndjson').write_text(''.join(json.dumps(ev) + '\n' for ev in self.events))

    def report(self, want=4, fmt='json'):
        self.write()
        proc = subprocess.run([str(ROOT / 'build/memveil'), 'report', '--format', fmt, str(self.cap)],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, want, proc.stderr + proc.stdout[:400])
        if want != 2:
            self.assertEqual(proc.stderr, '')
        return json.loads(proc.stdout) if fmt == 'json' and want != 2 else proc.stdout

    def metric(self, report, name):
        return next(m for m in report['metrics'] if m['name'] == name and not m['dimensions']['device_id'] and not m['dimensions']['pool_id'])

    def incomplete(self, report):
        fs = [f for f in report['findings'] if f['code'] == 'CAPTURE_INCOMPLETE']
        self.assertEqual(len(fs), 1)
        self.assertTrue(fs[0]['evidence_refs'])

    def test_correlation_gap(self):
        self.load('lifecycle/quality-gap-open')
        self.events[-1]['data']['channel'] = 'correlation'
        r = self.report()
        self.assertIsNone(self.metric(r, 'live_observed_allocation_bytes')['value'])
        self.assertIsNone(self.metric(r, 'open_mappings')['value'])
        self.assertEqual(self.metric(r, 'successful_allocations')['value'], '1')
        self.assertEqual(self.metric(r, 'successful_allocations')['coverage'], 'partial')
        self.incomplete(r)
        self.assertFalse(any(f['code'] == 'UNPAIRED_LIFECYCLE' for f in r['findings']))

    def test_producer_correlation(self):
        for status in ('partial', 'unavailable'):
            with self.subTest(status=status):
                self.load('lifecycle/open-at-end')
                self.quality('correlation', status)
                r = self.report()
                self.assertIsNone(self.metric(r, 'live_observed_allocation_bytes')['value'])
                self.assertEqual(self.metric(r, 'bounce_attempts')['coverage'], 'complete_for_scope')
                self.incomplete(r)

    def test_pressure_gap_and_fresh_run(self):
        self.load('pools/pressure')
        third = self.events.pop()
        self.events.append(self.gap('detail', self.events[-1]))
        third['ts_ns'] = '1400000000'
        self.events.append(third)
        r = self.report()
        self.assertFalse(any(f['code'] == 'POOL_PRESSURE' for f in r['findings']))
        for ts in ('1500000000', '1600000000'):
            ev = copy.deepcopy(third)
            ev['ts_ns'] = ts
            self.events.append(ev)
        r = self.report()
        self.assertTrue(any(f['code'] == 'POOL_PRESSURE' for f in r['findings']))

    def test_pressure_unlocated_loss(self):
        self.load('pools/pressure')
        self.quality('detail')
        r = self.report()
        self.assertFalse(any(f['code'] == 'POOL_PRESSURE' for f in r['findings']))
        self.assertTrue(any(m['name'] == 'pool_used_bytes' and m['value'] == '900' for m in r['metrics']))
        self.incomplete(r)

    def test_pressure_aggregate_gap(self):
        self.load('pools/pressure')
        self.events.insert(2, self.gap('aggregate', self.events[1]))
        self.events[-1]['ts_ns'] = '1400000000'
        r = self.report(0)
        self.assertTrue(any(f['code'] == 'POOL_PRESSURE' for f in r['findings']))

    def test_region_loss(self):
        for state in ('shared', 'private'):
            with self.subTest(state=state):
                self.load('regions/region-union')
                self.events = self.events[:2]
                self.events[-1]['data']['requested_state'] = state
                self.events.append(self.gap('detail', self.events[-1]))
                r = self.report()
                for name in ('known_shared_region_bytes', 'known_private_region_bytes', 'unknown_region_bytes'):
                    self.assertIsNone(self.metric(r, name)['value'])
                self.assertEqual(self.metric(r, 'conversion_requests')['value'], '1')

    def test_region_producer_loss(self):
        self.load('regions/region-union')
        self.quality('detail')
        r = self.report()
        self.assertIsNone(self.metric(r, 'known_shared_region_bytes')['value'])

    def test_estimated_copy_rejected(self):
        for strength in ('estimated', 'derived'):
            for mixed in (False, True):
                with self.subTest(strength=strength, mixed=mixed):
                    self.load('lifecycle/lifecycle-nested')
                    copies = [ev for ev in self.events if ev['kind'] == 'copy']
                    for ev in copies[:1] if mixed else copies:
                        ev['source']['measurement'] = strength
                    self.report(2)
                    proc = subprocess.run([str(ROOT / 'tools/validate-schemas'), str(self.cap)], capture_output=True, text=True)
                    self.assertNotEqual(proc.returncode, 0)

    def test_observed_copy_and_occupancy(self):
        self.load('lifecycle/lifecycle-nested')
        r = self.report(0)
        self.assertEqual(self.metric(r, 'copy_original_to_bounce_bytes')['value'], '5120')
        self.assertEqual(self.metric(r, 'copy_original_to_bounce_bytes')['measurement'], 'observed')
        for name in ('peak_live_observed_allocation_bytes', 'allocation_byte_microseconds'):
            rows = [m for m in r['metrics'] if m['name'] == name]
            self.assertEqual(len(rows), 1)
            for m in rows:
                self.assertNotIn('exposure', m['notes'])
                self.assertIn('allocation', m['notes'].lower())

    def test_terminal_partial_and_unavailable(self):
        for status in ('partial', 'unavailable'):
            with self.subTest(status=status):
                self.load('attempts')
                self.quality('terminal', status)
                self.incomplete(self.report())
                for fmt in ('text', 'markdown'):
                    self.assertEqual(self.report(fmt=fmt).count('CAPTURE_INCOMPLETE'), 1)

    def test_complete_empty_and_optional_absence(self):
        self.load('attempts')
        self.events = []
        r = self.report(0)
        self.assertEqual(r['findings'], [])
        self.assertEqual(self.metric(r, 'bounce_attempts')['value'], '0')
        self.load('attempts')
        r = self.report(0)
        self.assertEqual(r['findings'], [])

    def test_incomplete_deduplicated(self):
        self.load('lifecycle/quality-gap-open')
        self.quality('terminal')
        self.incomplete(self.report())

    def test_release_preserves_shared_region(self):
        self.load('regions/region-union')
        self.events = self.events[:2]
        lifecycle = ROOT / 'tests/fixtures/lifecycle/lifecycle-nested/events.ndjson'
        for ev in map(json.loads, lifecycle.read_text().splitlines()):
            if ev['kind'] in ('map_result', 'unmap'):
                ev['session_id'] = self.session['session_id']
                self.events.append(ev)
        self.session['quality']['correlation'].update(status='complete_for_scope', loss_count='0')
        r = self.report(0)
        self.assertEqual(self.metric(r, 'live_observed_allocation_bytes')['value'], '0')
        self.assertEqual(self.metric(r, 'known_shared_region_bytes')['value'], '8192')
        self.assertFalse(any('exposure' in m['notes'] for m in r['metrics']))

    def test_region_aggregate_gap_preserves_state(self):
        self.load('regions/region-union')
        self.events = self.events[:2]
        self.events.append(self.gap('aggregate', self.events[-1]))
        r = self.report(0)
        self.assertEqual(self.metric(r, 'known_shared_region_bytes')['value'], '8192')
        self.assertEqual(self.metric(r, 'known_shared_region_bytes')['coverage'], 'complete_for_scope')

    def test_combined_quality_reasons_fit_report(self):
        self.load('lifecycle/open-at-end')
        for channel in ('detail', 'correlation', 'terminal'):
            self.quality(channel)
            self.session['quality'][channel]['reason'] = 'λ' * 512
        r = self.report()
        self.incomplete(r)
        for finding in r['findings']:
            self.assertLessEqual(len(finding['explanation']), 1024)

    def test_partial_copy_measurement_constraint(self):
        for strength in ('estimated', 'derived', 'observed'):
            for source_first in (False, True):
                with self.subTest(strength=strength, source_first=source_first):
                    self.load('lifecycle/lifecycle-nested')
                    record = self.events[1]
                    record['source']['measurement'] = strength
                    keys = ['schema_version', 'session_id', 'seq', 'ts_ns']
                    keys += ['source', 'kind'] if source_first else ['kind', 'source']
                    prefix = json.dumps({key: record[key] for key in keys})[:-1] + ','
                    self.events = self.events[:1]
                    self.write()
                    with (self.cap / 'events.ndjson').open('a') as stream:
                        stream.write(prefix)
                    for partial in (False, True):
                        cmd = [str(ROOT / 'build/memveil'), 'report', '--format', 'json']
                        if partial:
                            cmd.append('--allow-partial')
                        cmd.append(str(self.cap))
                        proc = subprocess.run(cmd, capture_output=True, text=True)
                        want = 4 if partial and strength == 'observed' else 2
                        self.assertEqual(proc.returncode, want, proc.stderr)
                        if want == 2:
                            self.assertEqual(proc.stdout, '')
                        else:
                            self.incomplete(json.loads(proc.stdout))

    def test_partial_copy_incomplete_source_constraint(self):
        for strength in ('estimated', 'derived', 'observed'):
            with self.subTest(strength=strength):
                self.load('lifecycle/lifecycle-nested')
                record = self.events[1]
                prefix = json.dumps({key: record[key] for key in
                                    ('schema_version', 'session_id', 'seq', 'ts_ns', 'kind')})[:-1]
                prefix += ', "source": {"measurement": ' + json.dumps(strength) + ','
                self.events = self.events[:1]
                self.write()
                with (self.cap / 'events.ndjson').open('a') as stream:
                    stream.write(prefix)
                proc = subprocess.run([str(ROOT / 'build/memveil'), 'report', '--format', 'json',
                                       '--allow-partial', str(self.cap)], capture_output=True, text=True)
                want = 4 if strength == 'observed' else 2
                self.assertEqual(proc.returncode, want, proc.stderr)
                if want == 2:
                    self.assertEqual(proc.stdout, '')
                else:
                    self.incomplete(json.loads(proc.stdout))

    def test_partial_non_copy_estimates_remain_recoverable(self):
        for strength in ('estimated', 'derived'):
            with self.subTest(strength=strength):
                self.load('attempts')
                record = self.events[0]
                record['source']['measurement'] = strength
                prefix = json.dumps({key: record[key] for key in
                                    ('schema_version', 'session_id', 'seq', 'ts_ns', 'kind', 'source')})[:-1] + ','
                self.events = []
                self.write()
                (self.cap / 'events.ndjson').write_text(prefix)
                proc = subprocess.run([str(ROOT / 'build/memveil'), 'report', '--format', 'json',
                                       '--allow-partial', str(self.cap)], capture_output=True, text=True)
                self.assertEqual(proc.returncode, 4, proc.stderr)
                self.incomplete(json.loads(proc.stdout))

    def test_partial_unknown_copy_constraint_is_inconclusive(self):
        self.load('lifecycle/lifecycle-nested')
        record = self.events[1]
        record['source']['measurement'] = 'estimated'
        base = json.dumps({key: record[key] for key in
                           ('schema_version', 'session_id', 'seq', 'ts_ns')})[:-1]
        prefixes = [
            base + ', "source": ' + json.dumps(record['source']) + ', "kind": "cop',
            base + ', "kind": "copy", "source": {"measurement": "estim',
            base + ', "source": ' + json.dumps(record['source']) + ',',
        ]
        self.events = self.events[:1]
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                self.write()
                with (self.cap / 'events.ndjson').open('a') as stream:
                    stream.write(prefix)
                proc = subprocess.run([str(ROOT / 'build/memveil'), 'report', '--format', 'json',
                                       '--allow-partial', str(self.cap)], capture_output=True, text=True)
                self.assertEqual(proc.returncode, 4, proc.stderr)
                self.incomplete(json.loads(proc.stdout))

    def test_real_example_terminal(self):
        path = ROOT / 'examples/real-capture'
        self.session = json.loads((path / 'session.json').read_text())
        self.events = [json.loads(x) for x in (path / 'events.ndjson').read_text().splitlines()]
        self.incomplete(self.report())


if __name__ == '__main__':
    unittest.main(verbosity=2)
