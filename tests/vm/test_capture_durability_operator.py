# SPDX-License-Identifier: GPL-3.0-or-later
"""Host-only contract for the durability operator phase (owned-I/O leg).

The checkpoint leg is not established by an idle guest: the operator
arranges a reproducible owned-I/O workload, the guest records window
markers in the oracle log, and the verdict judges same-UUID recovery
plus an independently re-verified prefix from raw bytes. A run that
repeats sampling alone, without operator evidence, leaves the leg
NOT RUN -- never PASS.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

VM = Path(__file__).resolve().parent
if str(VM) not in sys.path:
    sys.path.insert(0, str(VM))

NONCE = '0123456789abcdef0123'
RAW_SESSION = 'b01dface-0000-4000-8000-000000000001'


def make_raw_capture(root, session=RAW_SESSION, events=2):
    import hashlib
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps({'session_id': session, 'seq': str(seq),
                         'kind': 'attempt'}) + '\n'
             for seq in range(events)]
    raw = ''.join(lines).encode()
    doc = {'session_id': session,
           'capture': {'finalized': False, 'end_reason': 'checkpoint',
                       'checkpoint_generation': '2',
                       'integrity': {'events_bytes': str(len(raw)),
                                     'events_sha256': hashlib.sha256(raw).hexdigest(),
                                     'line_count': str(len(lines)),
                                     'kinds': {'attempt': str(len(lines))}}}}
    (root / 'events.ndjson').write_bytes(raw)
    (root / 'checkpoint.json').write_text(json.dumps(doc))
    return doc['capture']['integrity']


def make_promised(integrity, nonce=NONCE):
    return {'nonce': nonce, 'scenario': 'checkpoint', 'fs_uuid': 'uuid-kept',
            'integrity': integrity}


def make_oracle_log(plan, start_ns=100, end_ns=200):
    import capture_durability_operator as operator
    total = plan['workload']['total_bytes']
    lines = [
        {'marker': 'window-start', 'workload': plan['workload']['id'],
         'nonce': plan['nonce'], 'mono_ns': str(start_ns), 'seq': '0'},
        {'marker': 'window-end', 'workload': plan['workload']['id'],
         'nonce': plan['nonce'], 'mono_ns': str(end_ns), 'seq': '1',
         'bytes_written': str(total), 'bytes_read': str(total),
         'workload_sha256': operator.expected_workload_sha(plan['workload'])},
    ]
    return ''.join(json.dumps(row) + '\n' for row in lines)


class OperatorEntryTests(unittest.TestCase):
    """The campaign legs the operator phase must express."""

    def test_operator_module_importable(self):
        import capture_durability_operator as operator
        for name in ('write_plan', 'validate_window', 'judge_verdict',
                     'validate_verdict', 'leg_status', 'run_workload',
                     'expected_workload_sha', 'main'):
            self.assertTrue(callable(getattr(operator, name)), name)

    def test_runner_exposes_operator_hooks(self):
        import capture_durability as runner
        self.assertTrue(callable(runner.operator_checkpoint_capture))
        self.assertTrue(callable(runner.operator_checkpoint_recover))

    def test_guest_exposes_operator_workload(self):
        import capture_durability_guest as guest
        self.assertTrue(callable(guest.run_operator_workload))
        self.assertTrue(callable(guest.write_operator_verdict))

    def test_dry_run_entry_reports_usage(self):
        proc = subprocess.run(
            [sys.executable, str(VM / 'capture_durability_operator.py'),
             '--help'], capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(b'--fixture', proc.stdout)
        self.assertIn(b'--out', proc.stdout)


class WorkloadSpecTests(unittest.TestCase):
    def test_spec_is_bounded_and_nonzero(self):
        import capture_durability_operator as operator
        spec = operator.workload_spec()
        self.assertEqual(spec['id'], 'owned-io-sweep/1')
        self.assertEqual(spec['block_bytes'], 65536)
        self.assertEqual(spec['block_count'], 64)
        self.assertEqual(spec['total_bytes'], 65536 * 64)
        self.assertGreater(spec['total_bytes'], 0)

    def test_spec_reproduces_identical_bytes(self):
        import capture_durability_operator as operator
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / 'first'
            second = Path(tmp) / 'second'
            first.mkdir()
            second.mkdir()
            spec = operator.workload_spec()
            one = operator.run_workload(first, spec)
            two = operator.run_workload(second, spec)
            self.assertEqual(one, two)
            self.assertEqual(one['bytes_written'], spec['total_bytes'])
            self.assertEqual(one['bytes_read'], spec['total_bytes'])
            self.assertEqual(one['workload_sha256'],
                             operator.expected_workload_sha(spec))

    def test_workload_refuses_escape_target(self):
        import capture_durability_operator as operator
        with tempfile.TemporaryDirectory() as tmp:
            spec = dict(operator.workload_spec(), target='../escape')
            with self.assertRaisesRegex(ValueError, '^operator workload target escapes its mount$'):
                operator.run_workload(Path(tmp), spec)
            spec = dict(operator.workload_spec(), target='/absolute')
            with self.assertRaisesRegex(ValueError, '^operator workload target escapes its mount$'):
                operator.run_workload(Path(tmp), spec)


class WindowMarkerTests(unittest.TestCase):
    def plan(self):
        import capture_durability_operator as operator
        with tempfile.TemporaryDirectory() as tmp:
            plan = operator.write_plan(Path(tmp), NONCE)
        return plan

    def log(self, plan, start_ns=100, end_ns=200, scale=1):
        text = make_oracle_log(plan, start_ns, end_ns)
        if scale == 1:
            return text
        total = str(plan['workload']['total_bytes'] * scale)
        rows = [json.loads(line) for line in text.splitlines()]
        rows[1]['bytes_written'] = total
        rows[1]['bytes_read'] = total
        return ''.join(json.dumps(row) + '\n' for row in rows)

    def test_honest_markers_validate(self):
        import capture_durability_operator as operator
        plan = self.plan()
        window = operator.validate_window(plan, self.log(plan))
        self.assertEqual(window['start_ns'], '100')
        self.assertEqual(window['end_ns'], '200')
        self.assertEqual(window['bytes_written'], str(plan['workload']['total_bytes']))

    def test_missing_start_or_end_fails(self):
        import capture_durability_operator as operator
        plan = self.plan()
        lines = self.log(plan).splitlines(keepends=True)
        with self.assertRaisesRegex(ValueError, '^operator window is missing its start marker$'):
            operator.validate_window(plan, lines[1])
        with self.assertRaisesRegex(ValueError, '^operator window is missing its end marker$'):
            operator.validate_window(plan, lines[0])

    def test_unordered_markers_fail(self):
        import capture_durability_operator as operator
        plan = self.plan()
        lines = self.log(plan).splitlines(keepends=True)
        with self.assertRaisesRegex(ValueError, '^operator window markers out of order$'):
            operator.validate_window(plan, lines[1] + lines[0])

    def test_idle_zero_byte_window_fails(self):
        import capture_durability_operator as operator
        plan = self.plan()
        with self.assertRaisesRegex(ValueError, '^operator window recorded no owned I/O$'):
            operator.validate_window(plan, self.log(plan, scale=0))

    def test_foreign_marker_line_fails(self):
        import capture_durability_operator as operator
        plan = self.plan()
        with self.assertRaisesRegex(ValueError, '^operator oracle log has a foreign line$'):
            operator.validate_window(plan, self.log(plan) + '{"marker": "other"}\n')

    def test_plan_mismatch_fails(self):
        import capture_durability_operator as operator
        plan = self.plan()
        other = dict(plan, nonce='f' * 20)
        with self.assertRaisesRegex(ValueError, '^operator window breaks the arranged plan$'):
            operator.validate_window(other, self.log(plan))

    def test_sha_mismatch_fails(self):
        import capture_durability_operator as operator
        plan = self.plan()
        bad = self.log(plan).replace(operator.expected_workload_sha(plan['workload']), '0' * 64)
        with self.assertRaisesRegex(ValueError, '^operator workload bytes differ from the arranged sweep$'):
            operator.validate_window(plan, bad)


class VerdictTests(unittest.TestCase):
    def test_honest_recovery_passes_both_predicates(self):
        import capture_durability_operator as operator
        with tempfile.TemporaryDirectory() as tmp:
            integrity = make_raw_capture(Path(tmp) / 'raw')
            verdict = operator.judge_verdict(
                make_promised(integrity), 'uuid-kept', Path(tmp) / 'raw')
            self.assertEqual(verdict['status'], 'PASS')
            predicates = verdict['predicates']
            self.assertEqual(predicates['same_uuid_recovery']['status'], 'PASS')
            self.assertEqual(predicates['prefix_reverified_from_raw_bytes']['status'], 'PASS')
            self.assertEqual(operator.validate_verdict(verdict, make_promised(integrity)), 'PASS')

    def test_uuid_drift_fails(self):
        import capture_durability_operator as operator
        with tempfile.TemporaryDirectory() as tmp:
            integrity = make_raw_capture(Path(tmp) / 'raw')
            verdict = operator.judge_verdict(
                make_promised(integrity), 'uuid-changed', Path(tmp) / 'raw')
            self.assertEqual(verdict['status'], 'FAIL')
            self.assertEqual(verdict['predicates']['same_uuid_recovery']['status'], 'FAIL')

    def test_prefix_drift_fails(self):
        import capture_durability_operator as operator
        with tempfile.TemporaryDirectory() as tmp:
            integrity = make_raw_capture(Path(tmp) / 'raw')
            tampered = dict(integrity, line_count='99')
            verdict = operator.judge_verdict(
                make_promised(tampered), 'uuid-kept', Path(tmp) / 'raw')
            self.assertEqual(verdict['status'], 'FAIL')
            self.assertEqual(verdict['predicates']['prefix_reverified_from_raw_bytes']['status'], 'FAIL')

    def test_retained_pass_claim_is_rejudged(self):
        import capture_durability_operator as operator
        with tempfile.TemporaryDirectory() as tmp:
            integrity = make_raw_capture(Path(tmp) / 'raw')
            verdict = operator.judge_verdict(
                make_promised(integrity), 'uuid-kept', Path(tmp) / 'raw')
            verdict['predicates']['same_uuid_recovery']['recovered_fs_uuid'] = 'uuid-edited'
            with self.assertRaisesRegex(ValueError, '^operator verdict claim does not match its retained values$'):
                operator.validate_verdict(verdict, make_promised(integrity))

    def test_pool_sample_only_leaves_leg_not_run(self):
        import capture_durability_operator as operator
        with tempfile.TemporaryDirectory() as tmp:
            case = Path(tmp) / 'checkpoint'
            case.mkdir()
            (case / 'pool-samples.json').write_text('{"ticks": []}\n')
            self.assertEqual(operator.leg_status(case), 'NOT RUN')


class RunnerHookTests(unittest.TestCase):
    def stage(self, root):
        import capture_durability_operator as operator
        case = Path(root) / 'checkpoint'
        export = case / 'export'
        export.mkdir(parents=True)
        plan = operator.write_plan(case, NONCE)
        (export / 'oracle.log').write_text(make_oracle_log(plan))
        return case, export, plan

    def test_capture_hook_retains_window(self):
        import capture_durability as runner
        with tempfile.TemporaryDirectory() as tmp:
            case, export, plan = self.stage(tmp)
            window = runner.operator_checkpoint_capture(case, export, NONCE)
            self.assertEqual(window['start_ns'], '100')
            retained = json.loads((case / 'operator-window.json').read_text())
            self.assertEqual(retained, window)

    def test_capture_hook_refuses_absent_log(self):
        import capture_durability as runner
        with tempfile.TemporaryDirectory() as tmp:
            case, export, plan = self.stage(tmp)
            (export / 'oracle.log').unlink()
            with self.assertRaisesRegex(ValueError, '^operator oracle log absent$'):
                runner.operator_checkpoint_capture(case, export, NONCE)

    def test_capture_hook_refuses_plan_drift(self):
        import capture_durability as runner
        with tempfile.TemporaryDirectory() as tmp:
            case, export, plan = self.stage(tmp)
            with self.assertRaisesRegex(ValueError, '^operator plan ownership drift$'):
                runner.operator_checkpoint_capture(case, export, 'f' * 20)

    def test_recover_hook_retains_verdict(self):
        import capture_durability as runner
        import capture_durability_operator as operator
        with tempfile.TemporaryDirectory() as tmp:
            case, export, plan = self.stage(tmp)
            integrity = make_raw_capture(Path(tmp) / 'raw')
            promised = make_promised(integrity)
            (export / 'barrier.json').write_text(json.dumps(promised))
            verdict = operator.judge_verdict(promised, 'uuid-kept', Path(tmp) / 'raw')
            (export / 'operator-verdict.json').write_text(json.dumps(verdict))
            judged = runner.operator_checkpoint_recover(case, export, promised)
            self.assertEqual(judged['status'], 'PASS')
            retained = json.loads((case / 'operator-verdict.json').read_text())
            self.assertEqual(retained, verdict)

    def test_recover_hook_refuses_absent_verdict(self):
        import capture_durability as runner
        with tempfile.TemporaryDirectory() as tmp:
            case, export, plan = self.stage(tmp)
            integrity = make_raw_capture(Path(tmp) / 'raw')
            with self.assertRaisesRegex(ValueError, '^operator verdict absent$'):
                runner.operator_checkpoint_recover(case, export, make_promised(integrity))

    def test_recover_hook_refuses_fail_verdict(self):
        import capture_durability as runner
        import capture_durability_operator as operator
        with tempfile.TemporaryDirectory() as tmp:
            case, export, plan = self.stage(tmp)
            integrity = make_raw_capture(Path(tmp) / 'raw')
            promised = make_promised(integrity)
            verdict = operator.judge_verdict(promised, 'uuid-changed', Path(tmp) / 'raw')
            (export / 'operator-verdict.json').write_text(json.dumps(verdict))
            with self.assertRaisesRegex(ValueError, '^operator verdict is not PASS$'):
                runner.operator_checkpoint_recover(case, export, promised)


if __name__ == '__main__':
    unittest.main()
