# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic transport/privacy tests; these never attach a kernel probe."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name('journal_spike.py')
spec = importlib.util.spec_from_file_location('journal_spike', PATH)
kit = importlib.util.module_from_spec(spec) if PATH.exists() else None
if kit:
    spec.loader.exec_module(kit)


def record(data):
    return json.dumps({'type': 'printf', 'data': data}).encode() + b'\n'


ATTACHED = b'{"type":"attached_probes","count":6,"data":{"probes":6}}\n'


class SpikeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(kit, 'runnable spike implementation is missing')

    def stream(self, hook='fentry', callers=False):
        parser = kit.Trace(hook, callers, owned=True)
        parser.feed(ATTACHED)
        parser.feed(record('MVJ1|ready\n'))
        for direction in ('shared', 'private'):
            stack = '\n  mv_command_set+19 [memveil_region_oracle]\n' if callers else 'disabled'
            parser.feed(record(f'MVJ1|entry|{direction}|3|{stack}\n'))
            pages = '3' if hook == 'fentry' else '-'
            parser.feed(record(f'MVJ1|exit|{direction}|{pages}|0\n'))
        parser.feed(record('MVJ1|counts|1|1|1|1\n'))
        return parser

    def test_real_protocol_and_native_join_both_modes(self):
        for hook in ('fentry', 'kprobe'):
            for callers in (False, True):
                with self.subTest(hook=hook, callers=callers):
                    parser = self.stream(hook, callers)
                    result = parser.finish()
                    kit.compare_owned(parser, [['shared', '3', 0], ['private', '3', 0]])
                    self.assertEqual(result['counts'], dict.fromkeys(kit.COUNTERS, '1'))
                    self.assertEqual(result['caller_quality']['classified'], '2' if callers else '0')
                    self.assertEqual(result['caller_quality']['target_met'], True if callers else None)
                    self.assertNotIn('+19', json.dumps(result))

    def test_native_mismatch_and_unsettled_sequences(self):
        for rows in ([['shared', '4', 0], ['private', '3', 0]],
                     [['shared', '3', -5], ['private', '3', 0]], []):
            with self.assertRaisesRegex(ValueError, 'owned'):
                kit.compare_owned(self.stream(), rows)
        parser = kit.Trace('fentry', False, owned=True)
        parser.feed(ATTACHED)
        parser.feed(record('MVJ1|ready\n'))
        parser.feed(record('MVJ1|entry|shared|3|disabled\n'))
        parser.feed(record('MVJ1|counts|1|0|0|0\n'))
        with self.assertRaisesRegex(ValueError, 'owned'):
            kit.compare_owned(parser, [['shared', '3', 0], ['private', '3', 0]])

    def test_strict_protocol_negative_controls(self):
        bad = [b'{"type":"lost_events","data":1}\n',
               b'{"type":"printf","type":"map","data":"MVJ1|ready\\n"}\n',
               record('MVJ1|entry|shared|01|disabled\n'),
               record('MVJ1|exit|shared|3|2147483648\n'),
               record('MVJ1|entry|shared|3|raw_secret\n'),
               record('MVJ1|entry|foreign|3|disabled\n'),
               b'x' * 65537, record('untrusted diagnostic secret\n')]
        for raw in bad:
            with self.subTest(case=bad.index(raw)):
                parser = kit.Trace('fentry', False)
                parser.feed(ATTACHED)
                parser.feed(record('MVJ1|ready\n'))
                with self.assertRaises(ValueError) as error:
                    parser.feed(raw)
                self.assertNotIn('secret', str(error.exception))
        parser = self.stream()
        with self.assertRaises(ValueError):
            parser.feed(record('MVJ1|ready\n'))
        parser = kit.Trace('fentry', False)
        parser.feed(ATTACHED)
        parser.feed(record('MVJ1|ready\n'))
        parser.feed(record('MVJ1|counts|1|0|0|0\n'))
        with self.assertRaisesRegex(ValueError, 'count'):
            parser.finish()

    def test_callers_are_allowlisted_bounded_and_conservative(self):
        good = '\n  set_memory_decrypted+4\n  mv_command_set+0x30 [memveil_region_oracle]\n'
        label = kit.classify(good)
        self.assertEqual(label, ('owned', ['mv_command_set [memveil_region_oracle]']))
        for stack, expected in [('', 'unresolved'), ('\n  deadbeef\n', 'unresolved'),
                                ('\n  mv_command_set+1 [other]\n', 'unresolved'),
                                ('\n  mv_command_set+1 [memveil_region_oracle]\n  swiotlb_free_tlb+2\n', 'ambiguous'),
                                ('\n  swiotlb_free_tlb+2\n' * 16, 'truncated')]:
            self.assertEqual(kit.classify(stack)[0], expected)
        with self.assertRaises(ValueError):
            kit.classify('\n  swiotlb_free_tlb+2\n' * 17)
        self.assertEqual(kit.classify('\n  private_name+42 [private_module]\n')[1], [])

    def test_empty_natural_window_is_not_classification_pass(self):
        parser = kit.Trace('fentry', True)
        parser.feed(ATTACHED)
        parser.feed(record('MVJ1|ready\n'))
        parser.feed(record('MVJ1|counts|0|0|0|0\n'))
        result = parser.finish()
        self.assertIsNone(result['caller_quality']['target_met'])
        self.assertEqual(result['window_membership'], 'unproved_global_boundaries')

    def test_program_configuration_and_caller_opt_in(self):
        for hook in ('fentry', 'kprobe'):
            for callers in (False, True):
                source = kit.program(hook, callers, True)
                self.assertEqual('kstack(bpftrace, 16)' in source, callers)
                self.assertIn('pid == cpid', source)
                self.assertIn('count()', source)
                self.assertNotIn('arg0', source)
                self.assertNotIn('args.addr', source)
                self.assertIn('print_maps_on_exit=0', source)
                self.assertNotIn('system(', source)
        with self.assertRaises(ValueError):
            kit.program('tracepoint', False, False)

    def test_output_exclusive_and_symlink_preservation(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            target = root/'result.json'
            kit.save(target, {'status': 'synthetic'})
            original = target.read_bytes()
            with self.assertRaises(FileExistsError):
                kit.save(target, {'status': 'replacement'})
            link = root/'link.json'
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                kit.save(link, {})
            self.assertEqual(target.read_bytes(), original)

    def test_unarmed_cli_cannot_reach_tools_or_create_output(self):
        with tempfile.TemporaryDirectory() as name:
            target = Path(name)/'output'
            result = subprocess.run([sys.executable, str(PATH), '--output', str(target)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 77)
            self.assertIn('SKIPPED', result.stdout)
            self.assertFalse(target.exists())

    def test_bounded_pipe_transport_and_diagnostic_redaction(self):
        parser = kit.Trace('fentry', False)
        code = 'import sys; sys.stdout.write(' + repr(ATTACHED.decode() + record('MVJ1|ready\n').decode() + record('MVJ1|counts|0|0|0|0\n').decode()) + ')'
        rc, diagnostic = kit.pipe([sys.executable, '-c', code], parser, 3)
        self.assertEqual((rc, diagnostic), (0, 'none'))
        self.assertEqual(parser.finish()['counts'], dict.fromkeys(kit.COUNTERS, '0'))
        parser = kit.Trace('fentry', False)
        code = 'import sys; sys.stderr.write("failed to attach probe secret_address: Operation not permitted\\n"); sys.exit(1)'
        self.assertEqual(kit.pipe([sys.executable, '-c', code], parser, 3), (1, 'permission'))
        code = 'import sys; sys.stderr.write("exec child: Permission denied\\n"); sys.exit(1)'
        self.assertEqual(kit.pipe([sys.executable, '-c', code], parser, 3), (1, 'diagnostic'))
        with self.assertRaisesRegex(ValueError, 'bound'):
            kit.pipe([sys.executable, '-c', 'print("x"*70000)'], kit.Trace('fentry', False), 3)

    def test_symbol_module_resolution_never_infers_ambiguous_identity(self):
        symbols = io.StringIO('1000 t mv_command_set [memveil_region_oracle]\n'
                              '2000 t private_symbol [private_module]\n'
                              '3000 t dma_direct_alloc\n4000 t dma_direct_alloc [other]\n')
        names = kit.identities(symbols)
        self.assertEqual(names, {'mv_command_set': 'mv_command_set [memveil_region_oracle]', 'dma_direct_alloc': None})
        self.assertEqual(kit.classify('\n mv_command_set+3\n', names)[0], 'owned')
        self.assertEqual(kit.classify('\n dma_direct_alloc+3\n', names)[0], 'unresolved')

    def manifest(self):
        return {'schema': 'memveil-journal-spike-input/1', 'platform': 'ordinary',
                'kernel_release': '7.0.14-070014-generic', 'lockdown': 'none',
                **{key: 'a'*64 for key in kit.DIGESTS}, 'owned': None}

    def test_manifest_prerequisite_types_and_no_unobserved_cell(self):
        good = self.manifest()
        kit.validate_manifest(good, False)
        for key, value in [('kernel_release', 'unobserved image'), ('platform', 'auto'),
                           ('lockdown', None), ('btf_sha256', 'a'*63), ('owned', True)]:
            bad = dict(good, **{key: value})
            with self.assertRaises(ValueError):
                kit.validate_manifest(bad, False)
        with self.assertRaises(ValueError):
            kit.validate_manifest(good, True)
        owned = {key: 'b'*64 for key in kit.OWNED_DIGESTS}
        owned['restore_contract'] = 'whole_range_native_success'
        kit.validate_manifest(dict(good, owned=owned), True)
        for key in kit.OWNED_DIGESTS:
            with self.assertRaises(ValueError):
                kit.validate_manifest(dict(good, owned=dict(owned, **{key: False})), True)

    def test_refusal_verdict_requires_reached_tracer_and_cleanup(self):
        self.assertEqual(kit.verdict('refusal', 1, 'permission', False, True), 'REFUSAL_OBSERVED')
        for values in [('refusal', 0, 'none', False, True),
                       ('refusal', 1, 'diagnostic', False, True),
                       ('refusal', 1, 'permission', True, True),
                       ('refusal', 1, 'permission', False, False),
                       ('observe', 1, 'permission', False, True)]:
            with self.assertRaises(ValueError):
                kit.verdict(*values)
        self.assertEqual(kit.verdict('observe', 0, 'none', True, True), 'OBSERVED')

    def test_begin_is_not_attachment_readiness(self):
        parser = kit.Trace('fentry', False)
        with self.assertRaisesRegex(ValueError, 'attach'):
            parser.feed(record('MVJ1|ready\n'))
        parser = kit.Trace('fentry', False)
        with self.assertRaises(ValueError):
            parser.feed(b'{"type":"attached_probes","count":4,"data":{"probes":4}}\n')
        with self.assertRaises(ValueError):
            parser.feed(b'{"type":"attached_probes","count":6,"data":{"probes":6.0}}\n')

    def test_document_depth_bound(self):
        self.assertEqual(kit.decode(b'['*64 + b'0' + b']'*64), json.loads('['*64 + '0' + ']'*64))
        with self.assertRaisesRegex(ValueError, 'depth'):
            kit.decode(b'['*65 + b'0' + b']'*65)
        self.assertEqual(kit.decode(json.dumps('['*100).encode()), '['*100)

    def test_trace_deadline_reaps_process_group(self):
        parser = kit.Trace('fentry', False)
        with self.assertRaisesRegex(ValueError, 'deadline'):
            kit.pipe([sys.executable, '-c', 'import time; time.sleep(10)'], parser, 0.05)
        import os
        with self.assertRaises(ProcessLookupError):
            os.killpg(parser.child_pid, 0)

    def run_synthetic(self, root, mode, payload, snapshots=None):
        tool = root/'synthetic-tracer'
        tool.write_text('#!' + sys.executable + '\n' + payload)
        tool.chmod(0o700)
        manifest = root/'input.json'
        manifest.write_text(json.dumps(self.manifest()))
        args = SimpleNamespace(mode=mode, hook='fentry', callers=False, seconds=1,
                               pages=3, retain_seconds=1, output=root/'output',
                               manifest=manifest, module=root/'synthetic-module')
        empty = dict.fromkeys(('prog', 'map', 'link'), set())
        with patch.object(kit, 'preflight', return_value=(self.manifest(), str(tool), 'synthetic-bpftool')):
            with patch.object(kit, 'resources', side_effect=snapshots or [empty, empty, empty]):
                result = kit.run(args)
        return result, json.loads((args.output/'receipt.json').read_text())

    def test_synthetic_full_owned_protocol_and_independent_cleanup_failure(self):
        text = ATTACHED.decode() + record('MVJ1|ready\n').decode()
        for direction in ('shared', 'private'):
            text += record(f'MVJ1|entry|{direction}|3|disabled\n').decode()
            text += record(f'MVJ1|exit|{direction}|3|0\n').decode()
        text += record('MVJ1|counts|1|1|1|1\n').decode()
        payload = '''import json, pathlib, shlex, sys
args = shlex.split(sys.argv[sys.argv.index('-c')+1])
native = {'status':'PASS', 'cleanup':'unloaded', 'epoch':args[args.index('--epoch')+1],
          'pages':'3', 'rows':[['shared','3',0],['private','3',0]], 'retained_seconds':'1'}
pathlib.Path(args[args.index('--output')+1]).write_text(json.dumps(native))
sys.stdout.write(''' + repr(text) + ')\n'
        with tempfile.TemporaryDirectory() as name:
            rc, receipt = self.run_synthetic(Path(name), 'owned', payload)
            self.assertEqual(rc, 0)
            self.assertEqual(receipt['status'], 'OBSERVED')
            self.assertEqual(receipt['cleanup'], 'verified')
            self.assertEqual(receipt['admission'], 'not_granted')
            self.assertIn('native_sha256', receipt)
        empty = dict.fromkeys(('prog', 'map', 'link'), set())
        occupied = dict(empty, map={42})
        with tempfile.TemporaryDirectory() as name:
            rc, receipt = self.run_synthetic(Path(name), 'owned', payload, [empty, occupied, occupied])
            self.assertEqual(rc, 1)
            self.assertEqual(receipt['status'], 'FAIL')
            self.assertEqual(receipt['cleanup'], 'unproved_reboot_required')

    def test_synthetic_full_refusal_and_positive_failure_do_not_leak_diagnostics(self):
        payload = 'import sys; sys.stderr.write("failed to attach probe private_name+999: Operation not permitted\\n"); sys.exit(1)\n'
        for mode, status, rc in [('refusal', 'REFUSAL_OBSERVED', 0), ('observe', 'FAIL', 1)]:
            with tempfile.TemporaryDirectory() as name:
                result, receipt = self.run_synthetic(Path(name), mode, payload)
                self.assertEqual(result, rc)
                self.assertEqual(receipt['status'], status)
                self.assertEqual(receipt['tracer_exit'], 1)
                self.assertNotIn('private_name', json.dumps(receipt))

    def test_armed_missing_prerequisites_refuses_without_output(self):
        with tempfile.TemporaryDirectory() as name:
            target = Path(name)/'output'
            result = subprocess.run([sys.executable, str(PATH), '--arm', '--output', str(target)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('prerequisites unmet', result.stderr)
            self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
