# SPDX-License-Identifier: GPL-3.0-or-later
"""Host-only negative controls for the power-cut evidence barrier."""
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import signal
import select
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from capture_durability import validate_barrier

PROBE = Path(__file__).resolve().parents[2] / "build/probe/checkpoint_probe"
PROBE_GONE = not PROBE.is_file()
PROBE_CAUSE = ("checkpoint_probe retired with the Mojo tree (cutover); "
               "durability oracle needs a Rust probe binary")


class BarrierTests(unittest.TestCase):
    def test_earlier_success_cannot_pass_the_fullness_boundary(self):
        from capture_durability_guest import finalize_after_fullness, ROOT
        child = subprocess.Popen([sys.executable, '-c', 'print("ready session=already-finalized",flush=True)'],
                                 stdout=subprocess.PIPE)
        child.wait(timeout=5)
        try:
            with self.assertRaisesRegex(ValueError, 'exited before exhaustion'):
                finalize_after_fullness(child, ROOT / 'tests/fixtures/reader/sealed-complete',
                                        lambda: self.fail('early success reached filler'))
        finally:
            child.stdout.close()

    @unittest.skipIf(PROBE_GONE, PROBE_CAUSE)
    def test_real_writer_publishes_only_after_the_mock_exhaustion_barrier(self):
        from capture_durability_guest import finalize_after_fullness, require_stopped_unfinalized, ROOT
        from test_capture_failures import environment
        from report_oracle import accepted_report
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            capture = path / 'capture'
            filler = path / 'filler'
            # The real EventWriter probe releases on stdin. Ignore SIGHUP only
            # in this child so the guest's stop protocol can release the probe.
            child = subprocess.Popen([str(ROOT / 'build/probe/checkpoint_probe'), 'hold', str(capture),
                                      str(ROOT / 'tests/fixtures/reader/sealed-partial')],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment(path, 'none'),
                preexec_fn=lambda: signal.signal(signal.SIGHUP, signal.SIG_IGN))
            try:
                self.assertTrue(select.select([child.stdout], [], [], 5)[0])
                self.assertEqual(child.stdout.readline(), b'ready\n')
                def reached():
                    self.assertFalse(require_stopped_unfinalized(child, capture)['capture']['finalized'])
                    filler.mkdir()
                    (filler / 'sentinel').write_bytes(b'retained mock exhaustion evidence')
                    child.stdin.write(b'continue\n')
                    child.stdin.flush()
                    return dict(reached_errno='ENOSPC'), filler
                before, final, evidence = finalize_after_fullness(child, capture, reached)
                self.assertFalse(before['capture']['finalized'])
                self.assertTrue(final['capture']['finalized'])
                self.assertEqual(evidence['reached_errno'], 'ENOSPC')
                self.assertEqual((filler / 'sentinel').read_bytes(), b'retained mock exhaustion evidence')
                proc = subprocess.run([str(ROOT / 'build/memveil'), 'report', '--format', 'json', str(capture)],
                                      capture_output=True)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                accepted_report(capture, proc.stdout, proc.returncode)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=5)

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
            argv = ['capture-durability', '--out', str(path), '--binary-sha256', 'a' * 64,
                   '--expected-release', '7.0.14-070014-generic', '--expected-kernel-sha256', 'b' * 64,
                   '--expected-modules-sha256', 'c' * 64, '--expected-btf-sha256', 'd' * 64]
            for name in ('binary', 'object', 'bridge', 'profile', 'kernel', 'kernel-config', 'modules'):
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


class IdentityTests(unittest.TestCase):
    APPROVED = '7.0.14-070014-generic'
    OTHER = '7.1.13-070113-generic'
    BTF = 'b' * 64
    MODS = 'm' * 64
    INPUT_KEYS = ('binary', 'object', 'bridge', 'profile', 'shim')
    INPUT_SHAS = {'/staged/' + key: hashlib.sha256(key.encode()).hexdigest()
                  for key in INPUT_KEYS}

    def identify(self, release, expected, config_gz, staged_sha='s' * 64,
                 mods_sha=None, btf_sha=None, readlink='/resolved/mods',
                 isdir=True, lexists=False, read_staged=True):
        import capture_durability_guest as guest
        mods_sha = self.MODS if mods_sha is None else mods_sha
        btf_sha = self.BTF if btf_sha is None else btf_sha
        config = {key: '/staged/' + key for key in self.INPUT_KEYS}
        config.update(kernel_config='/staged/config', expected_release=expected,
                      expected_modules_sha256=self.MODS, expected_btf_sha256=self.BTF)

        def fake_digest(path):
            name = str(path)
            if name == '/sys/kernel/btf/vmlinux':
                if isinstance(btf_sha, Exception):
                    raise btf_sha
                return btf_sha
            if name == '/staged/config':
                if not read_staged:
                    raise AssertionError('staged config read on the absent path')
                return staged_sha
            if name in self.INPUT_SHAS:
                return self.INPUT_SHAS[name]
            raise AssertionError('unexpected guest digest: ' + name)

        def fake_read_bytes(node):
            if str(node) != '/proc/config.gz':
                raise AssertionError('unexpected guest read: ' + str(node))
            if isinstance(config_gz, Exception):
                raise config_gz
            return config_gz

        def fake_read_text(node, *args, **kwargs):
            if str(node).endswith('boot_id'):
                return 'test-boot-id\n'
            raise AssertionError('unexpected guest read: ' + str(node))

        def fake_readlink(path):
            if isinstance(readlink, Exception):
                raise readlink
            return readlink

        with patch.object(os, 'uname', return_value=SimpleNamespace(release=release)), \
             patch.object(os, 'readlink', side_effect=fake_readlink), \
             patch.object(os.path, 'isdir', return_value=isdir), \
             patch.object(os.path, 'lexists', return_value=lexists), \
             patch.object(guest, 'modules_manifest_sha', return_value=(mods_sha, 7)), \
             patch.object(guest, 'digest', side_effect=fake_digest), \
             patch.object(Path, 'read_bytes', autospec=True, side_effect=fake_read_bytes), \
             patch.object(Path, 'read_text', autospec=True, side_effect=fake_read_text):
            return guest.identity(config)

    def test_absent_accepted_only_on_approved_row(self):
        ident = self.identify(self.APPROVED, self.APPROVED, FileNotFoundError(), read_staged=False)
        self.assertEqual(ident['config_status'], 'absent')
        self.assertIsNone(ident['kernel_config_sha256'])
        self.assertEqual(ident['kernel'], self.APPROVED)
        self.assertEqual(ident['boot_id'], 'test-boot-id')
        self.assertEqual(ident['btf_sha256'], self.BTF)
        self.assertEqual(ident['modules_manifest_sha256'], self.MODS)
        self.assertEqual(ident['inputs'], {key: self.INPUT_SHAS['/staged/' + key]
                                           for key in self.INPUT_KEYS})

    def test_absent_refused_on_other_rows(self):
        rows = [self.OTHER, '6.18.0-061800-generic', self.APPROVED + ' ',
                ' ' + self.APPROVED, self.APPROVED.upper(), '7.0.14', '',
                self.APPROVED + '\n']
        for row in rows:
            with self.subTest(row=row):
                with self.assertRaisesRegex(ValueError, '^kernel config absent on an unapproved row$'):
                    self.identify(row, row, FileNotFoundError())

    def test_release_drift_refused(self):
        with self.assertRaisesRegex(ValueError, '^booted kernel release differs from expected release$'):
            self.identify(self.OTHER, self.APPROVED, FileNotFoundError())
        with self.assertRaisesRegex(ValueError, '^booted kernel release differs from expected release$'):
            self.identify(self.APPROVED, self.OTHER, FileNotFoundError())
        with self.assertRaisesRegex(ValueError, '^booted kernel release differs from expected release$'):
            self.identify(self.OTHER, self.APPROVED, gzip.compress(b'CONFIG_X=y\n'))

    def test_measured_config_match_accepted_on_any_row(self):
        raw = b'CONFIG_IKCONFIG_PROC=y\n'
        ident = self.identify(self.OTHER, self.OTHER, gzip.compress(raw),
                              staged_sha=hashlib.sha256(raw).hexdigest())
        self.assertEqual(ident['config_status'], 'measured')
        self.assertEqual(ident['kernel_config_sha256'], hashlib.sha256(raw).hexdigest())

    def test_measured_config_mismatch_refused(self):
        with self.assertRaisesRegex(ValueError, '^booted kernel config differs from supplied config$'):
            self.identify(self.OTHER, self.OTHER, gzip.compress(b'CONFIG_X=y\n'),
                          staged_sha='0' * 64)

    def test_config_unreadable_refused(self):
        cases = [b'not gzip at all', PermissionError(), IsADirectoryError()]
        for case in cases:
            with self.subTest(case=repr(case)[:20]):
                with self.assertRaisesRegex(ValueError, '^booted kernel config unreadable$'):
                    self.identify(self.APPROVED, self.APPROVED, case)
        with self.assertRaisesRegex(ValueError, '^booted kernel config unreadable$'):
            self.identify(self.APPROVED, self.APPROVED, FileNotFoundError(), lexists=True)

    def test_empty_config_counts_as_present(self):
        with self.assertRaisesRegex(ValueError, '^booted kernel config differs from supplied config$'):
            self.identify(self.APPROVED, self.APPROVED, b'', staged_sha='0' * 64)

    def test_modules_manifest_drift_refused(self):
        with self.assertRaisesRegex(ValueError, '^guest modules manifest differs from bound modules$'):
            self.identify(self.APPROVED, self.APPROVED, FileNotFoundError(), mods_sha='0' * 64)

    def test_modules_dir_missing_refused(self):
        with self.assertRaisesRegex(ValueError, '^guest modules dir missing for booted release$'):
            self.identify(self.APPROVED, self.APPROVED, FileNotFoundError(), isdir=False)

    def test_modules_symlink_forms_resolve(self):
        for link in ('../../usr/lib/modules/tied', OSError()):
            with self.subTest(link=repr(link)[:30]):
                ident = self.identify(self.APPROVED, self.APPROVED, FileNotFoundError(), readlink=link)
                self.assertEqual(ident['config_status'], 'absent')

    def test_btf_drift_refused(self):
        with self.assertRaisesRegex(ValueError, '^live BTF differs from pinned BTF$'):
            self.identify(self.APPROVED, self.APPROVED, FileNotFoundError(), btf_sha='0' * 64)

    def test_btf_unreadable_refused(self):
        for exc in (FileNotFoundError(), PermissionError()):
            with self.subTest(exc=type(exc).__name__):
                with self.assertRaisesRegex(ValueError, '^live BTF unreadable$'):
                    self.identify(self.APPROVED, self.APPROVED, FileNotFoundError(), btf_sha=exc)

    def test_host_bound_config_check(self):
        from capture_durability import check_bound_config
        messages = ('Mismatch', 'AbsentUnapproved', 'AbsentWithHash', 'Unknown')
        base = dict(kernel=self.APPROVED, kernel_config_sha256='c' * 64, config_status='measured')
        check_bound_config(base, 'c' * 64, self.APPROVED, messages)
        check_bound_config(dict(base, kernel_config_sha256='d' * 64), 'd' * 64, self.OTHER, messages)
        with self.assertRaisesRegex(ValueError, '^Mismatch$'):
            check_bound_config(base, 'd' * 64, self.APPROVED, messages)
        with self.assertRaisesRegex(ValueError, '^Mismatch$'):
            check_bound_config(dict(kernel=self.APPROVED, config_status='measured'), 'c' * 64,
                               self.APPROVED, messages)
        check_bound_config(dict(kernel=self.APPROVED, kernel_config_sha256=None, config_status='absent'),
                           'c' * 64, self.APPROVED, messages)
        with self.assertRaisesRegex(ValueError, '^AbsentUnapproved$'):
            check_bound_config(dict(kernel=self.OTHER, kernel_config_sha256=None, config_status='absent'),
                               'c' * 64, self.OTHER, messages)
        with self.assertRaisesRegex(ValueError, '^AbsentUnapproved$'):
            check_bound_config(dict(kernel=self.APPROVED, kernel_config_sha256=None, config_status='absent'),
                               'c' * 64, self.OTHER, messages)
        with self.assertRaisesRegex(ValueError, '^AbsentWithHash$'):
            check_bound_config(dict(kernel=self.APPROVED, kernel_config_sha256='c' * 64,
                                    config_status='absent'), 'c' * 64, self.APPROVED, messages)
        for bad in ({}, dict(kernel=self.APPROVED), dict(kernel=self.APPROVED, config_status='weird')):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, '^Unknown$'):
                    check_bound_config(bad, 'c' * 64, self.APPROVED, messages)

    def test_host_kernel_binding(self):
        from capture_durability import check_kernel_binding
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'vmlinuz-test'
            image.write_bytes(b'test kernel image')
            want = hashlib.sha256(b'test kernel image').hexdigest()
            self.assertEqual(check_kernel_binding(image, want), want)
            with self.assertRaisesRegex(ValueError, '^kernel image differs from bound image$'):
                check_kernel_binding(image, '0' * 64)

    def test_host_modules_binding(self):
        from capture_durability import check_modules_binding
        from kernel_matrix import modules_manifest_sha
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'modules'
            (root / 'kernel').mkdir(parents=True)
            (root / 'kernel' / 'mod.ko').write_bytes(b'module bytes')
            (root / 'modules.order').write_bytes(b'order\n')
            want, files = modules_manifest_sha(str(root))
            self.assertGreater(files, 0)
            self.assertEqual(check_modules_binding(root, want), (want, files))
            (root / 'kernel' / 'mod.ko').write_bytes(b'tampered bytes')
            with self.assertRaisesRegex(ValueError, '^modules manifest differs from bound modules$'):
                check_modules_binding(root, want)


if __name__ == '__main__':
    unittest.main()
