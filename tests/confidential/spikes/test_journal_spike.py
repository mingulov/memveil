# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic transport/privacy tests; these never attach a kernel probe."""
import importlib.util
import ctypes
import errno
import itertools
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import signal
import tempfile
import threading
import time
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

    def stream(self, hook='fentry', callers=False, caller_stacks=None, owned=True):
        parser = kit.Trace(hook, callers, owned=owned)
        parser.feed(ATTACHED)
        parser.feed(record('MVJ1|ready\n'))
        for direction in ('shared', 'private'):
            stack = '\n  mv_command_set+19 [memveil_region_oracle]\n' if callers else 'disabled'
            if caller_stacks is not None:
                stack = caller_stacks.get(direction, stack)
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

    def test_owned_join_requires_each_enabled_caller_identity(self):
        samples = {
            'unresolved': '\n unknown_caller+1\n',
            'foreign_class': '\n dma_direct_alloc+1\n',
            'foreign_module': '\n mv_command_set+1 [other]\n',
            'ambiguous': '\n mv_command_set+1 [memveil_region_oracle]\n swiotlb_free_tlb+1\n',
            'truncated': '\n mv_command_set+1 [memveil_region_oracle]\n' * 16,
        }
        rows = [['shared', '3', 0], ['private', '3', 0]]
        for hook in ('fentry', 'kprobe'):
            for direction in ('shared', 'private'):
                for condition, stack in samples.items():
                    with self.subTest(hook=hook, direction=direction, condition=condition):
                        trace = self.stream(hook, True, {direction: stack})
                        self.assertEqual(trace.finish()['counts'], dict.fromkeys(kit.COUNTERS, '1'))
                        with self.assertRaisesRegex(ValueError, 'owned caller'):
                            kit.compare_owned(trace, rows)
            good = self.stream(hook, True, {'private': '\n mv_restore+7 [memveil_region_oracle]\n'})
            kit.compare_owned(good, rows)
            kit.compare_owned(self.stream(hook, False), rows)
            global_trace = self.stream(hook, True, dict.fromkeys(('shared', 'private'), samples['unresolved']), owned=False)
            quality = global_trace.finish()['caller_quality']
            self.assertEqual(quality['classes']['unresolved'], '2')
            self.assertFalse(quality['target_met'])

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

    def descendant_case(self, leader_exits_first, close_pipes=False):
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        trace = kit.Trace('fentry', False)
        stopped, reaped = threading.Event(), threading.Event()
        try:
            with tempfile.TemporaryDirectory() as name:
                marker = Path(name)/'descendant'
                code = '''import os, pathlib, signal, sys, time
marker = pathlib.Path(sys.argv[1])
worker = os.fork()
if worker == 0:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    marker.write_text(str(os.getpid()))
    if sys.argv[3] == 'close':
        os.close(1)
        os.close(2)
    time.sleep(30)
    os._exit(0)
signal.signal(signal.SIGINT, lambda *_: os._exit(0))
while not marker.exists():
    time.sleep(0.005)
if sys.argv[2] == 'first':
    os._exit(0)
time.sleep(30)
'''

                def reap_descendant():
                    while not stopped.wait(0.005):
                        if not marker.exists():
                            continue
                        try:
                            pid = int(marker.read_text())
                            waited, _ = os.waitpid(pid, os.WNOHANG)
                        except (ChildProcessError, ValueError):
                            continue
                        if waited == pid:
                            reaped.set()
                            return

                reaper = threading.Thread(target=reap_descendant)
                reaper.start()
                try:
                    with patch.object(kit, 'GROUP_GRACE_SECONDS', 0.1, create=True), patch.object(kit, 'GROUP_KILL_SECONDS', 1, create=True):
                        argv = [sys.executable, '-c', code, str(marker),
                                'first' if leader_exits_first else 'interrupt', 'close' if close_pipes else 'keep']
                        if close_pipes:
                            self.assertEqual(kit.pipe(argv, trace, 0.3), (0, 'none'))
                        else:
                            with self.assertRaisesRegex(ValueError, 'trace deadline exceeded'):
                                kit.pipe(argv, trace, 0.3)
                    self.assertTrue(marker.exists(), 'descendant must reach its installed signal handler')
                    with self.assertRaises(ProcessLookupError):
                        os.killpg(trace.child_pid, 0)
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(trace.child_pid, os.WNOHANG)
                    self.assertEqual(trace.process_cleanup, 'verified')
                    self.assertTrue(reaped.wait(1), 'synthetic adopted descendant must be reaped')
                finally:
                    if hasattr(trace, 'child_pid'):
                        try:
                            os.killpg(trace.child_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    reaped.wait(2)
                    stopped.set()
                    reaper.join(timeout=2)
        finally:
            self.assertEqual(libc.prctl(36, previous.value, 0, 0, 0), 0)

    def test_group_cleanup_when_leader_exits_first(self):
        self.descendant_case(True)

    def test_group_cleanup_when_leader_exits_on_interrupt(self):
        self.descendant_case(False)

    def test_group_cleanup_after_successful_leader_and_pipe_eof(self):
        self.descendant_case(True, close_pipes=True)

    def test_primary_failure_survives_cleanup_interruption(self):
        trace = kit.Trace('fentry', False)
        real_killpg = os.killpg

        def interrupt_cleanup(pgid, signum):
            if signum == signal.SIGINT:
                raise KeyboardInterrupt
            return real_killpg(pgid, signum)

        with patch.object(kit, 'GROUP_GRACE_SECONDS', 0.1), patch.object(kit.os, 'killpg', side_effect=interrupt_cleanup):
            with self.assertRaisesRegex(ValueError, 'trace deadline exceeded') as error:
                kit.pipe([sys.executable, '-c', 'import time; time.sleep(30)'], trace, 0.05)
        self.assertEqual(error.exception.__notes__, ['owned process-group cleanup unproved'])
        self.assertEqual(trace.process_cleanup, 'unproved')
        with self.assertRaises(ProcessLookupError):
            real_killpg(trace.child_pid, 0)
        with self.assertRaises(ChildProcessError):
            os.waitpid(trace.child_pid, os.WNOHANG)

    def test_selector_setup_failure_still_reaps_owned_group(self):
        trace = kit.Trace('fentry', False)
        with patch.object(kit.selectors, 'DefaultSelector', side_effect=OSError('synthetic selector failure')):
            with self.assertRaisesRegex(OSError, 'synthetic selector failure'):
                kit.pipe([sys.executable, '-c', 'import time; time.sleep(30)'], trace, 3)
        self.assertEqual(trace.process_cleanup, 'verified')
        with self.assertRaises(ProcessLookupError):
            os.killpg(trace.child_pid, 0)

    def test_cleanup_signal_is_latched_until_group_is_gone(self):
        trace = kit.Trace('fentry', False)
        original = kit._cleanup_group
        prior_handler = signal.getsignal(signal.SIGINT)

        def signal_during_cleanup(child):
            os.kill(os.getpid(), signal.SIGINT)
            return original(child)

        with patch.object(kit, '_cleanup_group', side_effect=signal_during_cleanup):
            with self.assertRaisesRegex(ValueError, 'trace deadline exceeded') as error:
                kit.pipe([sys.executable, '-c', 'import time; time.sleep(30)'], trace, 0.05)
        self.assertEqual(signal.getsignal(signal.SIGINT), prior_handler)
        self.assertEqual(error.exception.__notes__, ['owned process-group cleanup unproved'])
        self.assertEqual(trace.process_cleanup, 'unproved')
        with self.assertRaises(ProcessLookupError):
            os.killpg(trace.child_pid, 0)

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
            states = snapshots or [empty, empty, empty]
            with patch.object(kit, 'resources', side_effect=itertools.chain(states, itertools.repeat(states[-1]))), \
                    patch.object(kit, 'RESOURCE_SETTLE_ATTEMPTS', 3):
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

    def test_resource_absence_cannot_hide_unproved_process_cleanup(self):
        real_cleanup = kit.cleanup_group

        def unproved(child):
            self.assertTrue(real_cleanup(child))
            return False

        payload = 'import sys; sys.stderr.write("failed to attach probe: Operation not permitted\\n"); sys.exit(1)\n'
        with tempfile.TemporaryDirectory() as name, patch.object(kit, 'cleanup_group', side_effect=unproved):
            rc, receipt = self.run_synthetic(Path(name), 'refusal', payload)
        self.assertEqual(rc, 1)
        self.assertEqual(receipt['status'], 'FAIL')
        self.assertEqual(receipt['process_cleanup'], 'unproved')
        self.assertEqual(receipt['cleanup'], 'unproved_reboot_required')
        self.assertEqual(receipt['tracer_exit'], 1)
        self.assertIn('failure', receipt)

    def test_synthetic_settlement_preserves_errors_and_expired_deadlines(self):
        payload = 'import sys; sys.stderr.write("failed to attach probe: Operation not permitted\\n"); sys.exit(1)\n'
        empty = {'prog': set(), 'map': set(), 'link': set()}
        occupied = dict(empty, link={42})
        cases = [([empty, occupied, empty], 0, 'verified', 'verified'),
                 ([empty, ValueError('resource inventory unavailable'), empty], 1, 'unproved', 'verified_resources_only'),
                 ([empty, occupied, occupied, occupied, empty], 1, 'timeout', 'verified_resources_only')]
        for snapshots, expected_exit, settlement, cleanup in cases:
            with self.subTest(settlement=settlement), tempfile.TemporaryDirectory() as name:
                rc, receipt = self.run_synthetic(Path(name), 'refusal', payload, snapshots)
                self.assertEqual(rc, expected_exit)
                self.assertEqual(receipt['resource_settlement'], settlement)
                self.assertEqual(receipt['cleanup'], cleanup)
                self.assertEqual(receipt['tracer_exit'], 1)
                self.assertEqual(receipt['status'], 'FAIL' if expected_exit else 'REFUSAL_OBSERVED')

    def test_transport_failure_still_settles_resources_without_erasing_failure(self):
        empty = {'prog': set(), 'map': set(), 'link': set()}
        occupied = dict(empty, prog={42})
        payload = 'print("invalid synthetic protocol")\n'
        with tempfile.TemporaryDirectory() as name:
            rc, receipt = self.run_synthetic(Path(name), 'observe', payload, [empty, occupied, empty])
        self.assertEqual(rc, 1)
        self.assertEqual(receipt['status'], 'FAIL')
        self.assertIn('failure', receipt)
        self.assertEqual(receipt['resource_settlement'], 'verified')
        self.assertEqual(receipt['cleanup'], 'verified_resources_only')

    def test_armed_missing_prerequisites_refuses_without_output(self):
        with tempfile.TemporaryDirectory() as name:
            target = Path(name)/'output'
            result = subprocess.run([sys.executable, str(PATH), '--arm', '--output', str(target)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('prerequisites unmet', result.stderr)
            self.assertFalse(target.exists())


class InventoryTests(unittest.TestCase):
    def inventory(self, responses, machine='x86_64', system='Linux'):
        cursors = {11: 0, 12: 0, 31: 0}
        streams = {cmd: iter(rows) for cmd, rows in responses.items()}

        def syscall(number, command, pointer, size):
            self.assertEqual(number, 321)
            self.assertIn(command, (11, 12, 31))
            self.assertEqual(size, 12)
            attr = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32 * 3)).contents
            self.assertEqual(list(attr), [cursors[command], 0, 0])
            value = next(streams[command], OSError(errno.ENOENT, 'end'))
            if isinstance(value, OSError):
                ctypes.set_errno(value.errno)
                return -1
            if isinstance(value, tuple):
                result, value = value
            else:
                result = 0
            attr[1] = value
            cursors[command] = value
            return result

        library = SimpleNamespace(syscall=unittest.mock.Mock(side_effect=syscall))
        identity = SimpleNamespace(machine=machine, sysname=system)
        with patch.object(ctypes, 'CDLL', return_value=library), patch.object(kit.os, 'uname', return_value=identity):
            with patch.object(kit, 'metadata', side_effect=AssertionError('inventory launched an observer')):
                try:
                    return kit.resources()
                except TypeError as error:
                    self.fail('read-only inventory entry point missing: ' + str(error))

    def test_direct_inventory_keeps_every_id_without_observer(self):
        self.assertEqual(self.inventory({11: [2, 19], 12: [1, 4294967295], 31: [8]}),
                         {'prog': {2, 19}, 'map': {1, 4294967295}, 'link': {8}})
        self.assertEqual(self.inventory({11: [], 12: [], 31: []}),
                         {'prog': set(), 'map': set(), 'link': set()})

    def test_inventory_errors_never_become_empty(self):
        for command in (11, 12, 31):
            for error in (errno.EPERM, errno.EACCES, errno.EINVAL, errno.ENOSYS, errno.EIO, errno.EINTR):
                with self.subTest(command=command, error=error):
                    rows = {11: [], 12: [], 31: []}
                    rows[command] = [7, OSError(error, 'private diagnostic')]
                    with self.assertRaisesRegex(ValueError, '^resource inventory unavailable$'):
                        self.inventory(rows)

    def test_inventory_rejects_zero_repeated_decreasing_and_malformed_success(self):
        for command in (11, 12, 31):
            for rows in ([0], [5, 5], [5, 4], [(1, 7)], [(-2, 7)]):
                with self.subTest(command=command, rows=rows):
                    responses = {11: [], 12: [], 31: []}
                    responses[command] = rows
                    with self.assertRaisesRegex(ValueError, 'invalid resource'):
                        self.inventory(responses)

    def test_inventory_accepts_bound_and_refuses_overflow(self):
        for command in (11, 12, 31):
            with self.subTest(command=command):
                rows = {11: [], 12: [], 31: []}
                rows[command] = range(1, 4097)
                snapshot = self.inventory(rows)
                self.assertEqual(sum(map(len, snapshot.values())), 4096)
                rows[command] = range(1, 4098)
                with self.assertRaisesRegex(ValueError, 'resource inventory outside bound'):
                    self.inventory(rows)

    def test_inventory_refuses_other_syscall_abis(self):
        for system, machine in [('FreeBSD', 'x86_64'), ('Linux', 'aarch64'), ('Linux', 'i686')]:
            with self.subTest(system=system, machine=machine):
                with self.assertRaisesRegex(ValueError, 'Linux x86-64'):
                    self.inventory({}, machine, system)
        original_sizeof = ctypes.sizeof
        for narrow in (ctypes.c_void_p, ctypes.c_long):
            with self.subTest(narrow=narrow), patch.object(ctypes, 'sizeof',
                    side_effect=lambda kind: 4 if kind is narrow else original_sizeof(kind)):
                with self.assertRaisesRegex(ValueError, 'Linux x86-64'):
                    self.inventory({})


class SettlementTests(unittest.TestCase):
    def settle(self, snapshots, groups=None, module=False, process='verified', clock=None):
        baseline = {'prog': {7}, 'map': {8}, 'link': {9}}
        trace = SimpleNamespace(process_cleanup=process, child_pid=17)
        states = itertools.chain(snapshots, itertools.repeat(snapshots[-1]))
        group_states = groups or [True]
        absent = itertools.chain(group_states, itertools.repeat(group_states[-1]))
        with patch.object(kit, 'resources', side_effect=states), patch.object(kit, 'group_absent', side_effect=absent):
            with patch.object(Path, 'exists', return_value=module), patch.object(kit.time, 'sleep') as sleep:
                with patch.object(kit.time, 'monotonic', side_effect=clock or itertools.repeat(0)):
                    self.assertTrue(hasattr(kit, 'settle_resources'), 'bounded resource settlement missing')
                    result = kit.settle_resources(baseline, trace)
                self.assertLessEqual(sleep.call_count, 20)
                return result

    def test_settlement_waits_for_all_resources_and_group(self):
        baseline = {'prog': {7}, 'map': {8}, 'link': {9}}
        for kind in baseline:
            with self.subTest(kind=kind):
                pending = dict(baseline, **{kind: baseline[kind] | {42}})
                self.assertEqual(self.settle([pending, baseline]), 'verified')
        self.assertEqual(self.settle([baseline], groups=[False, True]), 'verified')

    def test_settlement_refuses_extra_missing_and_replaced_ids(self):
        baseline = {'prog': {7}, 'map': {8}, 'link': {9}}
        for kind in baseline:
            for ids in (set(), {42}, baseline[kind] | {42}):
                with self.subTest(kind=kind, ids=ids):
                    pending = dict(baseline, **{kind: ids})
                    self.assertEqual(self.settle([pending]), 'timeout')

    def test_settlement_requires_module_and_process_absence(self):
        baseline = {'prog': {7}, 'map': {8}, 'link': {9}}
        self.assertEqual(self.settle([baseline], module=True), 'timeout')
        self.assertEqual(self.settle([baseline], groups=[False]), 'timeout')
        self.assertEqual(self.settle([baseline], process='unproved'), 'process_unproved')

    def test_settlement_stops_at_deadline_and_preserves_inventory_error(self):
        baseline = {'prog': {7}, 'map': {8}, 'link': {9}}
        pending = dict(baseline, map={42})
        self.assertEqual(self.settle([pending, baseline], clock=[0, 1]), 'timeout')
        with self.assertRaisesRegex(ValueError, 'resource inventory unavailable'):
            self.settle([ValueError('resource inventory unavailable'), baseline])

    def test_settlement_cannot_succeed_after_deadline(self):
        baseline = {'prog': {7}, 'map': {8}, 'link': {9}}
        self.assertEqual(self.settle([baseline], clock=[0, 2]), 'timeout')


if __name__ == '__main__':
    unittest.main()
