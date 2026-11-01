# SPDX-License-Identifier: GPL-3.0-or-later
"""Host-only negative controls for the power-cut evidence barrier."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from capture_durability import validate_barrier


class BarrierTests(unittest.TestCase):
    def test_missing_or_false_reached_boundary_fails(self):
        inputs = {'binary': 'a' * 64}
        good = dict(nonce='b' * 32, scenario='readiness', stopped=True,
                    marker='readiness-announced', ready_observed=True, reserve_allocated=17 * 1048576,
                    fs_uuid='owned', identity=dict(inputs=inputs, boot_id='before'),
                    integrity=dict(events_bytes='0', line_count='0', events_sha256=hashlib.sha256(b'').hexdigest()))
        validate_barrier(good, 'b' * 32, 'readiness', inputs)
        for key, value in [('nonce', 'other'), ('ready_observed', False), ('stopped', False), ('marker', 'attach-refused'),
                           ('reserve_allocated', 0), ('identity', {}), ('fs_uuid', '')]:
            bad = copy.deepcopy(good)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_barrier(bad, 'b' * 32, 'readiness', inputs)
        with self.assertRaises(ValueError):
            validate_barrier({}, 'b' * 32, 'readiness', inputs)

    def test_preflight_failure_never_overwrites_existing_evidence(self):
        import capture_durability
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            sentinel = path / 'failure.json'
            sentinel.write_bytes(b'preserve unrelated evidence')
            argv = ['capture-durability', '--out', str(path), '--binary-sha256', 'a' * 64]
            for name in ('binary', 'object', 'bridge', 'profile', 'kernel', 'kernel-config'):
                argv += ['--' + name, '/missing']
            with patch.dict(os.environ, MEMVEIL_VM_CAPTURE_FAILURES='1'), patch.object(sys, 'argv', argv), \
                 patch.object(capture_durability, 'execute', side_effect=ValueError('preflight refusal')):
                self.assertEqual(capture_durability.main(), 1)
            self.assertEqual(sentinel.read_bytes(), b'preserve unrelated evidence')

    def test_failure_receipt_preserves_swaps_and_existing_entries(self):
        from capture_durability import retain_owned_failure
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owned = root / 'owned'
            owned.mkdir()
            identity = (owned.stat().st_dev, owned.stat().st_ino)
            foreign = root / 'foreign'
            foreign.write_bytes(b'foreign')
            (owned / 'failure.json').symlink_to(foreign)
            retain_owned_failure(owned, identity, 'failed')
            self.assertEqual(foreign.read_bytes(), b'foreign')
            self.assertTrue((owned / 'failure.json').is_symlink())
            owned.rename(root / 'displaced')
            owned.mkdir()
            retain_owned_failure(owned, identity, 'failed')
            self.assertEqual(list(owned.iterdir()), [])
            retain_owned_failure(root / 'displaced', identity, 'failed')
            self.assertEqual(foreign.read_bytes(), b'foreign')
            clean = root / 'clean'
            clean.mkdir()
            retain_owned_failure(clean, (clean.stat().st_dev, clean.stat().st_ino), 'expected')
            self.assertEqual(json.loads((clean / 'failure.json').read_text())['reason'], 'expected')

    def test_unarmed_runner_skips_before_inputs_or_resources(self):
        env = dict(os.environ)
        env.pop('MEMVEIL_VM_CAPTURE_FAILURES', None)
        runner = Path(__file__).with_name('capture_durability.py')
        proc = subprocess.run([sys.executable, str(runner)], env=env, capture_output=True)
        self.assertEqual(proc.returncode, 77)
        self.assertIn(b'SKIP', proc.stdout)

    def test_guest_refuses_host_before_device_lookup(self):
        from capture_durability_guest import owned_device
        with self.assertRaises(ValueError):
            owned_device('invalid')
        with self.assertRaises(ValueError):
            owned_device('0' * 32)


if __name__ == '__main__':
    unittest.main()
