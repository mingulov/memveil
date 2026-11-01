#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
import json
from pathlib import Path
import sys
import unittest
import tempfile
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))


class LedgerTests(unittest.TestCase):
    def test_native_ledger_is_strict_and_ordered(self):
        from owned_region import parse_ledger
        text = ('epoch=7 ordinal=1 direction=shared pages=3 result=0\n'
                'epoch=7 ordinal=2 direction=private pages=3 result=0\n')
        want = [('shared', '3', 0), ('private', '3', 0)]
        self.assertEqual(parse_ledger(text, 7, 3), want)
        for bad in (text.replace('epoch=7', 'epoch=8', 1), text + text,
                    text.replace('ordinal=2', 'ordinal=1'),
                    text.replace('pages=3', 'pages=03'),
                    text + 'pointer=0x1234\n', text.replace('result=0', 'result=1'),
                    text.replace('pages=3', 'pages=4', 1), text.splitlines()[0] + '\n'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_ledger(bad, 7, 3)

    def test_independent_counts_require_exact_positive_calls(self):
        from owned_region import parse_counts
        good = '\n'.join(json.dumps({'type': 'map', 'data': {name: 1}})
                         for name in ('@shared_entry', '@private_entry', '@shared_exit', '@private_exit'))
        self.assertEqual(parse_counts(good), {'shared_entry': '1', 'private_entry': '1',
                                             'shared_exit': '1', 'private_exit': '1'})
        for bad in ('', good.replace(': 1', ': 0', 1), good + '\n' + good,
                    good + '\n' + json.dumps({'type': 'lost_events', 'data': 1}),
                    good + '\n' + json.dumps({'type': 'map', 'data': {'@foreign': 1}})):
            with self.assertRaises(ValueError):
                parse_counts(bad)

    def test_join_refuses_foreign_missing_duplicate_and_ambiguous_observations(self):
        from owned_region import compare_observations
        native = [('shared', '3', 0), ('private', '3', 0)]
        rows = [{'direction': d, 'pages': p, 'result': r,
                 'caller': 'mv_command_set [memveil_region_oracle]'} for d, p, r in native]
        compare_observations(native, rows, 'mv_command_set [memveil_region_oracle]')
        for bad in (rows[:1], rows + rows, list(reversed(rows)),
                    [dict(rows[0], caller='unknown'), rows[1]],
                    [dict(rows[0], pages='4'), rows[1]],
                    [dict(rows[0], result=False), rows[1]],
                    [dict(rows[0], address='redacted'), rows[1]]):
            with self.assertRaises(ValueError):
                compare_observations(native, bad, 'mv_command_set [memveil_region_oracle]')


class WorkerTests(unittest.TestCase):
    def test_cleanup_restores_or_quarantines_every_native_failure_path(self):
        import owned_region as runner
        for decrypt, encrypt, interrupted in [(0,0,False), (-5,0,False), (-5,-5,False),
                                               (0,-5,False), (0,0,True), (0,0,'keyboard')]:
            with self.subTest(decrypt=decrypt, encrypt=encrypt, interrupted=interrupted), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                params = root / 'module' / 'parameters'
                args = SimpleNamespace(module=root/'oracle.ko', output=root/'result.json',
                                       pages=3, epoch=42, retain_seconds=1)
                actions = []
                def ledger(second=False):
                    text = f'epoch=42 ordinal=1 direction=shared pages=3 result={decrypt}\n'
                    if second:
                        text += f'epoch=42 ordinal=2 direction=private pages=3 result={encrypt}\n'
                    (params/'ledger').write_text(text)
                def run(command, **kwargs):
                    actions.append(command[0])
                    if command[0] == 'insmod':
                        params.mkdir(parents=True)
                        (params/'ledger').write_text('')
                        (params.parent/'refcnt').write_text('1')
                    elif command[0] == 'rmmod':
                        self.assertEqual(encrypt, 0)
                        shutil.rmtree(params.parent)
                    else:
                        self.fail('unexpected subprocess')
                def native(command):
                    actions.append(command)
                    ledger(command == 'restore' or decrypt != 0)
                    if (command == 'share' and decrypt) or (command == 'restore' and encrypt):
                        raise OSError('injected native error')
                def sleep(seconds):
                    if interrupted == 'keyboard':
                        raise KeyboardInterrupt
                    if interrupted:
                        raise OSError('injected retained-window interruption')
                with patch.object(runner, 'guest_guard'), patch.object(runner, 'PARAMS', params), \
                     patch.object(runner.subprocess, 'run', side_effect=run), \
                     patch.object(runner, 'command', side_effect=native), \
                     patch.object(runner.time, 'sleep', side_effect=sleep):
                    try:
                        rc = runner.worker(args)
                    except KeyboardInterrupt:
                        self.fail('interruption must produce an explicit failed worker receipt')
                self.assertEqual(rc, int(bool(decrypt or encrypt or interrupted)))
                result = json.loads(args.output.read_text())
                self.assertEqual(result['status'], 'FAIL' if decrypt or encrypt or interrupted else 'PASS')
                self.assertEqual(result['cleanup'], 'unloaded' if encrypt == 0 else 'quarantined_reboot_required')
                self.assertEqual(actions.count('rmmod'), int(encrypt == 0))
                self.assertEqual(actions.count('restore'), int(decrypt == 0))
                self.assertEqual(result['rows'], [['shared', '3', decrypt], ['private', '3', encrypt]])

    def test_indeterminate_load_never_claims_absent_module(self):
        import owned_region as runner
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            params = root/'module'/'parameters'
            args = SimpleNamespace(module=root/'oracle.ko', output=root/'result.json',
                                   pages=3, epoch=42, retain_seconds=1)
            def interrupted_load(command, **kwargs):
                params.mkdir(parents=True)
                raise subprocess.TimeoutExpired('insmod', 30)
            with patch.object(runner, 'guest_guard'), patch.object(runner, 'PARAMS', params), \
                 patch.object(runner.subprocess, 'run', side_effect=interrupted_load):
                self.assertEqual(runner.worker(args), 1)
            result = json.loads(args.output.read_text())
            self.assertEqual(result['cleanup'], 'unproved_reboot_required')
            self.assertEqual(result['status'], 'FAIL')
            self.assertTrue(params.exists())

    def test_evidence_never_overwrites_existing_or_symlink_targets(self):
        from owned_region import save_new
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)/'evidence'
            target.write_text('preserved')
            link = Path(tmp)/'link'
            link.symlink_to(target)
            for path in (target, link):
                with self.assertRaises(OSError):
                    save_new(path, {'x': 1})
            self.assertEqual(target.read_text(), 'preserved')


if __name__ == '__main__':
    unittest.main()
