# SPDX-License-Identifier: GPL-3.0-or-later
"""Host-only negative controls for the power-cut evidence barrier."""
import contextlib
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
from unittest.mock import Mock, patch

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
        good = dict(nonce='b' * 20, scenario='readiness', stopped=True,
                    marker='readiness-announced', ready_observed=True, reserve_allocated=17 * 1048576,
                    fs_uuid='owned', identity=dict(inputs=inputs, boot_id='before'),
                    integrity=dict(events_bytes='0', line_count='0', events_sha256=hashlib.sha256(b'').hexdigest()))
        validate_barrier(good, 'b' * 20, 'readiness', inputs)
        for key, value in [('nonce', 'other'), ('ready_observed', False), ('stopped', False), ('marker', 'attach-refused'),
                           ('reserve_allocated', 0), ('identity', {}), ('fs_uuid', '')]:
            bad = copy.deepcopy(good)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_barrier(bad, 'b' * 20, 'readiness', inputs)
        with self.assertRaises(ValueError):
            validate_barrier({}, 'b' * 20, 'readiness', inputs)

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
        with self.assertRaisesRegex(ValueError, '^invalid ownership nonce$'):
            owned_device('invalid')
        with self.assertRaisesRegex(ValueError, '^invalid ownership nonce$'):
            owned_device('0' * 32)


class OwnershipNonceTests(unittest.TestCase):
    """The 20-char ownership serial fits the virtio-blk ID truncation."""

    NONCE = '0123456789abcdef0123'

    @contextlib.contextmanager
    def guest(self, nonce, serials, mounts='sysfs /sys sysfs rw 0 0\n'):
        """Mocked guest: root, cmdline gate for nonce, vd serials, mounts."""
        cmdline = 'swiotlb=force memveil_fs_gate=' + nonce + '\n'
        entries = [Path('/sys/block/vd' + chr(ord('a') + index))
                   for index in range(len(serials))]
        contents = {str(entry / 'serial'): text
                    for entry, text in zip(entries, serials)}

        def fake_glob(node, pattern):
            if str(node) == '/sys/block' and pattern == 'vd*':
                return list(entries)
            raise AssertionError('unexpected guest glob: ' + str(node))

        def fake_exists(node):
            if str(node) in contents:
                return True
            raise AssertionError('unexpected guest exists: ' + str(node))

        def fake_read_text(node, *args, **kwargs):
            name = str(node)
            if name == '/proc/cmdline':
                return cmdline
            if name == '/proc/mounts':
                return mounts
            if name in contents:
                return contents[name]
            raise AssertionError('unexpected guest read: ' + name)

        with patch.object(os, 'geteuid', return_value=0), \
             patch.object(Path, 'glob', autospec=True, side_effect=fake_glob), \
             patch.object(Path, 'exists', autospec=True, side_effect=fake_exists), \
             patch.object(Path, 'read_text', autospec=True, side_effect=fake_read_text):
            yield

    def test_round_trip_accepts_exact_20_bytes(self):
        from capture_durability_guest import owned_device
        with self.guest(self.NONCE, [self.NONCE]):
            self.assertEqual(owned_device(self.NONCE), '/dev/vda')
        with self.guest(self.NONCE, [self.NONCE + '\n']):
            self.assertEqual(owned_device(self.NONCE), '/dev/vda')

    def test_old_32_char_shape_refused(self):
        from capture_durability_guest import owned_device
        with self.assertRaisesRegex(ValueError, '^invalid ownership nonce$'):
            owned_device('0' * 32)

    def test_off_by_one_lengths_refused(self):
        from capture_durability_guest import owned_device
        for text in ('0' * 19, '0' * 21):
            with self.subTest(length=len(text)):
                with self.assertRaisesRegex(ValueError, '^invalid ownership nonce$'):
                    owned_device(text)

    def test_non_hex_at_exact_length_refused(self):
        from capture_durability_guest import owned_device
        for text in ('g' * 20, 'B' * 20, '0' * 19 + ' '):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ValueError, '^invalid ownership nonce$'):
                    owned_device(text)

    def test_truncated_32_char_presentation_refused(self):
        from capture_durability_guest import owned_device
        long = '0123456789abcdef0123456789abcdef'
        # The kernel exposes only the first 20 bytes of the serial, so a
        # 32-char nonce arrives truncated; the shape gate must refuse it
        # rather than match the visible prefix.
        with self.guest(long, [long[:20]]):
            with self.assertRaisesRegex(ValueError, '^invalid ownership nonce$'):
                owned_device(long)

    def test_serial_mismatch_refused(self):
        from capture_durability_guest import owned_device
        with self.guest(self.NONCE, ['f' * 20]):
            with self.assertRaisesRegex(ValueError, '^expected exactly one owned virtio disk$'):
                owned_device(self.NONCE)
        with self.guest(self.NONCE, []):
            with self.assertRaisesRegex(ValueError, '^expected exactly one owned virtio disk$'):
                owned_device(self.NONCE)


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


class FakeLaunchedChild:
    """Minimal stand-in for the QEMU child behind a mocked boot."""
    pid = 1 << 30
    returncode = 0

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 0


class HostBindingTests(unittest.TestCase):
    APPROVED = '7.0.14-070014-generic'
    BTF = 'b' * 64

    def make_stage(self, root):
        from kernel_matrix import modules_manifest_sha
        root = Path(root)
        (root / 'tests' / 'vm').mkdir(parents=True)
        (root / 'build' / 'shim').mkdir(parents=True)
        (root / 'build' / 'shim' / 'capture_faults.so').write_bytes(b'shim')
        mods = root / 'cache' / 'lib' / 'modules' / self.APPROVED
        (mods / 'kernel').mkdir(parents=True)
        (mods / 'kernel' / 'mod.ko').write_bytes(b'module bytes')
        (mods / 'modules.order').write_bytes(b'order\n')
        kernel = root / 'cache' / 'boot' / ('vmlinuz-' + self.APPROVED)
        kernel.parent.mkdir(parents=True)
        kernel.write_bytes(b'genuine kernel image')
        other = root / 'other' / 'lib' / 'modules' / self.APPROVED
        (other / 'kernel').mkdir(parents=True)
        (other / 'kernel' / 'mod.ko').write_bytes(b'module bytes')
        (other / 'modules.order').write_bytes(b'order\n')
        kernel_sha = hashlib.sha256(b'genuine kernel image').hexdigest()
        mods_sha, mods_files = modules_manifest_sha(str(mods))
        lock = {'schema': 'memveil-kernel-matrix/2',
                'kernels': [{'id': '7.0', 'release': self.APPROVED,
                             'source': {'kind': 'archive', 'vng_version': 'v7.0.14',
                                        'archive_date': '2026-06-27 15:46',
                                        'vmlinuz_sha256': kernel_sha,
                                        'modules_manifest_sha256': mods_sha}}]}
        (root / 'tests' / 'vm' / 'kernels.lock.json').write_text(json.dumps(lock))
        pin = {}
        for name, data in (('binary', b'candidate'), ('object', b'object'),
                           ('bridge', b'bridge'), ('profile', b'profile'),
                           ('kernel-config', b'CONFIG_X=y\n')):
            path = root / 'inputs' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            pin[name] = hashlib.sha256(data).hexdigest()
        (root / 'out').mkdir()
        return SimpleNamespace(root=root, mods=mods, other=other, kernel=kernel,
                               kernel_sha=kernel_sha, mods_sha=mods_sha,
                               mods_files=mods_files, pin=pin)

    def make_args(self, stage, **override):
        params = dict(binary=stage.root / 'inputs' / 'binary',
                      object=stage.root / 'inputs' / 'object',
                      bridge=stage.root / 'inputs' / 'bridge',
                      profile=stage.root / 'inputs' / 'profile',
                      kernel=stage.kernel,
                      kernel_config=stage.root / 'inputs' / 'kernel-config',
                      modules=stage.mods, out=stage.root / 'out' / 'ev',
                      binary_sha256=stage.pin['binary'],
                      expected_release=self.APPROVED,
                      expected_kernel_sha256=stage.kernel_sha,
                      expected_modules_sha256=stage.mods_sha,
                      expected_btf_sha256=self.BTF, owned_out_ids=None)
        params.update(override)
        return SimpleNamespace(**params)

    @contextlib.contextmanager
    def harness(self, stage, boot_mock):
        import capture_durability
        real_access = os.access

        def fake_access(path, mode):
            if str(path) == '/dev/kvm':
                return True
            return real_access(path, mode)

        with patch.object(capture_durability, 'ROOT', stage.root), \
             patch('shutil.which', return_value='/fake/vng'), \
             patch('os.access', side_effect=fake_access), \
             patch('harness_env.check_harness_versions', return_value={'vng': 'fake'}), \
             patch('subprocess.check_output', return_value='f' * 40), \
             patch.object(capture_durability, 'boot', boot_mock), \
             patch.object(capture_durability, 'qmp_disk', return_value=None), \
             patch.object(capture_durability, 'stop_owned', return_value=None):
            yield

    def fake_boots(self, stage, statuses, tamper=None, tamper_at=1, operator=True):
        import capture_durability_operator as operator_mod
        calls = []
        inputs = {key: stage.pin[key] for key in ('binary', 'object', 'bridge', 'profile')}
        inputs['shim'] = hashlib.sha256(b'shim').hexdigest()

        def one(vng, config_path, kernel, scenario, nonce, disk, export, qmp, phase, logs):
            calls.append((scenario, phase))
            (logs / (phase + '-command.json')).write_text('[]\n')
            status = statuses[scenario]
            claim = {'kernel': self.APPROVED, 'config_status': status,
                     'kernel_config_sha256': stage.pin['kernel-config'] if status == 'measured' else None,
                     'boot_id': 'boot-' + phase, 'btf_sha256': self.BTF,
                     'modules_manifest_sha256': stage.mods_sha, 'inputs': dict(inputs)}
            if phase == 'capture' and scenario in ('readiness', 'checkpoint'):
                if scenario == 'readiness':
                    integrity = {'events_bytes': '0', 'line_count': '0',
                                 'events_sha256': hashlib.sha256(b'').hexdigest()}
                    marker, ready = 'readiness-announced', True
                else:
                    integrity = {'events_bytes': '8', 'line_count': '1',
                                 'events_sha256': hashlib.sha256(b'x').hexdigest()}
                    marker, ready = 'checkpoint-2', False
                (export / 'barrier.json').write_text(json.dumps(dict(
                    nonce=nonce, scenario=scenario, stopped=True, marker=marker,
                    ready_observed=ready, reserve_allocated=17 * 1048576,
                    fs_uuid='owned', identity=claim, integrity=integrity)))
                if operator and scenario == 'checkpoint':
                    plan = json.loads((export.parent / 'operator-plan.json').read_text())
                    spec = plan['workload']
                    total = str(spec['total_bytes'])
                    sha = operator_mod.expected_workload_sha(spec)
                    (export / 'oracle.log').write_text(
                        json.dumps({'marker': 'window-start', 'workload': spec['id'],
                                    'nonce': nonce, 'mono_ns': '100', 'seq': '0'}) + '\n'
                        + json.dumps({'marker': 'window-end', 'workload': spec['id'],
                                      'nonce': nonce, 'mono_ns': '200', 'seq': '1',
                                      'bytes_written': total, 'bytes_read': total,
                                      'workload_sha256': sha}) + '\n')
            else:
                (export / 'result.json').write_text(json.dumps(dict(
                    status='PASS', scenario=scenario, nonce=nonce,
                    fs_uuid='owned', identity=claim)))
                if operator and scenario == 'checkpoint' and phase == 'recover':
                    promised = json.loads((export / 'barrier.json').read_text())
                    kept = promised['integrity']
                    (export / 'operator-verdict.json').write_text(json.dumps(dict(
                        schema=operator_mod.SCHEMA, nonce=nonce, scenario=scenario,
                        status='PASS', predicates={
                            'same_uuid_recovery': dict(
                                status='PASS', promised_fs_uuid='owned',
                                recovered_fs_uuid='owned'),
                            'prefix_reverified_from_raw_bytes': dict(
                                status='PASS',
                                promised_events_sha256=kept['events_sha256'],
                                promised_line_count=kept['line_count'],
                                recovered_events_sha256=kept['events_sha256'],
                                recovered_line_count=kept['line_count'],
                                detail='re-verified from raw bytes')})))
            if tamper is not None and len(calls) == tamper_at:
                tamper()
            return FakeLaunchedChild()

        one.calls = calls
        return one

    def test_substitute_pins_refused_before_boot(self):
        import capture_durability
        from kernel_matrix import modules_manifest_sha
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            sub_kernel = stage.root / 'sub' / 'vmlinuz'
            sub_kernel.parent.mkdir()
            sub_kernel.write_bytes(b'substitute image')
            sub_mods = stage.root / 'sub' / 'mods'
            (sub_mods / 'kernel').mkdir(parents=True)
            (sub_mods / 'kernel' / 'm.ko').write_bytes(b'substitute module')
            (sub_mods / 'modules.order').write_bytes(b'sub\n')
            sub_kernel_sha = hashlib.sha256(b'substitute image').hexdigest()
            sub_mods_sha, _ = modules_manifest_sha(str(sub_mods))
            cases = [
                (dict(kernel=sub_kernel, expected_kernel_sha256=sub_kernel_sha),
                 '^supplied kernel pin differs from the locked row$'),
                (dict(modules=sub_mods, expected_modules_sha256=sub_mods_sha),
                 '^supplied modules pin differs from the locked row$'),
            ]
            for override, message in cases:
                with self.subTest(message=message):
                    args = self.make_args(stage, **override)
                    launches = Mock(side_effect=AssertionError('unexpected boot'))
                    with self.harness(stage, launches):
                        with self.assertRaisesRegex(ValueError, message):
                            capture_durability.execute(args)
                    self.assertEqual(launches.call_count, 0)

    def test_unlisted_release_refused_before_boot(self):
        import capture_durability
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            for release in ('9.9.9-fake', '7.0.14-070014-GENERIC',
                            ' ' + self.APPROVED, self.APPROVED + '\n'):
                with self.subTest(release=release):
                    args = self.make_args(stage, expected_release=release)
                    launches = Mock(side_effect=AssertionError('unexpected boot'))
                    with self.harness(stage, launches):
                        with self.assertRaisesRegex(ValueError, '^expected release has no locked kernel row$'):
                            capture_durability.execute(args)
                    self.assertEqual(launches.call_count, 0)

    def test_file_or_empty_modules_refused(self):
        import capture_durability
        from capture_durability import check_modules_binding
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            blob = stage.root / 'blob'
            blob.write_bytes(b'not a modules tree')
            empty_hash = hashlib.sha256(b'\n').hexdigest()
            with self.assertRaisesRegex(ValueError, '^modules path is not a modules directory$'):
                check_modules_binding(blob, empty_hash)
            with self.assertRaisesRegex(ValueError, '^modules path is not a modules directory$'):
                check_modules_binding(blob, stage.mods_sha)
            bare = stage.root / 'bare'
            bare.mkdir()
            with self.assertRaisesRegex(ValueError, '^modules manifest is empty$'):
                check_modules_binding(bare, empty_hash)
            for mods, message in ((blob, '^modules path is not a modules directory$'),
                                  (bare, '^modules manifest is empty$')):
                with self.subTest(mods=mods.name):
                    args = self.make_args(stage, modules=mods)
                    launches = Mock(side_effect=AssertionError('unexpected boot'))
                    with self.harness(stage, launches):
                        with self.assertRaisesRegex(ValueError, message):
                            capture_durability.execute(args)
                    self.assertEqual(launches.call_count, 0)

    def test_modules_from_other_tree_refused(self):
        import capture_durability
        from kernel_matrix import modules_manifest_sha
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            self.assertEqual(modules_manifest_sha(str(stage.other))[0], stage.mods_sha)
            args = self.make_args(stage, modules=stage.other)
            launches = Mock(side_effect=AssertionError('unexpected boot'))
            with self.harness(stage, launches):
                with self.assertRaisesRegex(ValueError, '^supplied modules are not the image-resolved module tree$'):
                    capture_durability.execute(args)
            self.assertEqual(launches.call_count, 0)

    def test_usr_staged_layout_with_symlinked_lib_refused(self):
        import capture_durability
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            # Staged /usr layout: the locked image and modules live under
            # stage/usr, while stage/lib is a symlink to a foreign lib
            # tree carrying modules/$release. The launcher resolver steps
            # back from .../usr to stage when ../lib is a symlink, so it
            # selects the foreign tree; the harness must refuse instead of
            # verifying the staged tree and launching into the foreign one.
            usr = stage.root / 'stage' / 'usr'
            (usr / 'boot').mkdir(parents=True)
            (usr / 'lib' / 'modules' / self.APPROVED / 'kernel').mkdir(parents=True)
            (usr / 'boot' / ('vmlinuz-' + self.APPROVED)).write_bytes(b'genuine kernel image')
            (usr / 'lib' / 'modules' / self.APPROVED / 'kernel' / 'mod.ko').write_bytes(b'module bytes')
            (usr / 'lib' / 'modules' / self.APPROVED / 'modules.order').write_bytes(b'order\n')
            foreign = stage.root / 'foreignlib'
            (foreign / 'modules' / self.APPROVED / 'kernel').mkdir(parents=True)
            (foreign / 'modules' / self.APPROVED / 'kernel' / 'mod.ko').write_bytes(b'foreign module bytes')
            (foreign / 'modules' / self.APPROVED / 'modules.order').write_bytes(b'foreign\n')
            (stage.root / 'stage' / 'lib').symlink_to(foreign)
            args = self.make_args(stage,
                                  kernel=usr / 'boot' / ('vmlinuz-' + self.APPROVED),
                                  modules=usr / 'lib' / 'modules' / self.APPROVED)
            launches = Mock(side_effect=AssertionError('unexpected boot'))
            with self.harness(stage, launches):
                with self.assertRaisesRegex(ValueError, '^supplied modules are not the image-resolved module tree$'):
                    capture_durability.execute(args)
            self.assertEqual(launches.call_count, 0)

    def test_shell_rewritten_kernel_spelling_refused_before_boot(self):
        import capture_durability
        from kernel_matrix import modules_manifest_sha
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            # Exact launcher-handoff repro: the locked image and module
            # tree live under a directory literally named staged"copy",
            # while sibling stagedcopy carries the same image with a
            # DIFFERENT module tree. The wrapper strips the quotes, so
            # without the pre-boot refusal it would boot the sibling.
            quoted = stage.root / 'staged"copy"'
            (quoted / 'boot').mkdir(parents=True)
            kernel = quoted / 'boot' / ('vmlinuz-' + self.APPROVED)
            kernel.write_bytes(b'genuine kernel image')
            mods = quoted / 'lib' / 'modules' / self.APPROVED
            (mods / 'kernel').mkdir(parents=True)
            (mods / 'kernel' / 'mod.ko').write_bytes(b'module bytes')
            (mods / 'modules.order').write_bytes(b'order\n')
            sibling = stage.root / 'stagedcopy'
            (sibling / 'boot').mkdir(parents=True)
            (sibling / 'boot' / ('vmlinuz-' + self.APPROVED)).write_bytes(b'genuine kernel image')
            other = sibling / 'lib' / 'modules' / self.APPROVED
            (other / 'kernel').mkdir(parents=True)
            (other / 'kernel' / 'mod.ko').write_bytes(b'sibling module bytes')
            (other / 'modules.order').write_bytes(b'sibling\n')
            self.assertNotEqual(modules_manifest_sha(str(other))[0], stage.mods_sha)
            args = self.make_args(stage, kernel=kernel, modules=mods)
            launches = Mock(side_effect=AssertionError('unexpected boot'))
            with self.harness(stage, launches):
                with self.assertRaises(ValueError) as refused:
                    capture_durability.execute(args)
            self.assertEqual(str(refused.exception),
                             'kernel path contains characters the launcher shell rewrites: '
                             + str(kernel.resolve()))
            self.assertEqual(launches.call_count, 0)
            # The spelling refusal precedes hash verification: tampered
            # bytes under the quoted dir still refuse on the spelling.
            kernel.write_bytes(b'tampered image')
            with self.harness(stage, launches):
                with self.assertRaises(ValueError) as refused:
                    capture_durability.execute(args)
            self.assertEqual(str(refused.exception),
                             'kernel path contains characters the launcher shell rewrites: '
                             + str(kernel.resolve()))
            self.assertEqual(launches.call_count, 0)

    def test_shell_metacharacters_refused_and_real_cache_paths_accepted(self):
        from capture_durability import check_shell_inert_path
        rejected = ['"', "'", '`', '$', ';', '&', '|', '<', '>', '(', ')',
                    '{', '}', '[', ']', '*', '?', '#', '~', ' ', '\t', '\n',
                    '\\', '!', '^']
        for char in rejected:
            with self.subTest(char=repr(char)):
                probe = '/tmp/stage/part-' + char + '-x/boot/vmlinuz-test'
                with self.assertRaises(ValueError) as refused:
                    check_shell_inert_path(probe, 'kernel path')
                self.assertEqual(str(refused.exception),
                                 'kernel path contains characters the launcher shell rewrites: ' + probe)
        home = str(Path.home())
        for accepted in (
                home + '/.cache/virtme-ng/v7.0.14/amd64/boot/vmlinuz-7.0.14-070014-generic',
                home + '/.cache/virtme-ng/v7.0.14/amd64/usr/lib/modules/7.0.14-070014-generic',
                '/tmp/mv12-evidence_2026-11-21+run,1/out:v2/ev'):
            with self.subTest(path=accepted):
                check_shell_inert_path(accepted, 'kernel path')
                check_shell_inert_path(accepted, 'modules path')
                check_shell_inert_path(accepted, 'evidence path')

    def test_shell_rewritten_evidence_and_socket_paths_refused(self):
        import capture_durability
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            quoted_out = stage.root / 'o"ut'
            quoted_out.mkdir()
            args = self.make_args(stage, out=quoted_out / 'ev')
            launches = Mock(side_effect=AssertionError('unexpected boot'))
            with self.harness(stage, launches):
                with self.assertRaises(ValueError) as refused:
                    capture_durability.execute(args)
            self.assertEqual(str(refused.exception),
                             'evidence path contains characters the launcher shell rewrites: '
                             + str(quoted_out.resolve() / 'ev'))
            self.assertEqual(launches.call_count, 0)
            quoted_tmp = stage.root / 't"mp'
            quoted_tmp.mkdir()
            args = self.make_args(stage)
            statuses = {name: 'absent' for name in capture_durability.SCENARIOS}
            boots = self.fake_boots(stage, statuses)
            with self.harness(stage, boots), patch.dict(os.environ, TMPDIR=str(quoted_tmp)), \
                 patch.object(tempfile, 'tempdir', None):
                with self.assertRaises(ValueError) as refused:
                    capture_durability.execute(args)
            self.assertTrue(str(refused.exception).startswith(
                'QMP socket path contains characters the launcher shell rewrites: '))
            self.assertIn(str(quoted_tmp.resolve()), str(refused.exception))
            self.assertEqual(boots.calls, [])

    def test_kernel_drift_after_first_capture_refused(self):
        import capture_durability
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            args = self.make_args(stage)
            statuses = {name: 'absent' for name in capture_durability.SCENARIOS}
            boots = self.fake_boots(stage, statuses,
                                     tamper=lambda: stage.kernel.write_bytes(b'drifted image'))
            with self.harness(stage, boots):
                with self.assertRaisesRegex(ValueError, '^kernel image differs from bound image$'):
                    capture_durability.execute(args)
            self.assertEqual(boots.calls, [('readiness', 'capture')])

    def test_modules_drift_after_first_capture_refused(self):
        import capture_durability
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            args = self.make_args(stage)
            statuses = {name: 'absent' for name in capture_durability.SCENARIOS}
            target = stage.mods / 'kernel' / 'mod.ko'
            boots = self.fake_boots(stage, statuses,
                                     tamper=lambda: target.write_bytes(b'tampered'))
            with self.harness(stage, boots):
                with self.assertRaisesRegex(ValueError, '^modules manifest differs from bound modules$'):
                    capture_durability.execute(args)
            self.assertEqual(boots.calls, [('readiness', 'capture')])

    def test_drift_after_recovery_refused_before_next_capture(self):
        import capture_durability
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            args = self.make_args(stage)
            statuses = {name: 'absent' for name in capture_durability.SCENARIOS}
            boots = self.fake_boots(stage, statuses,
                                     tamper=lambda: stage.kernel.write_bytes(b'drifted image'),
                                     tamper_at=2)
            with self.harness(stage, boots):
                with self.assertRaisesRegex(ValueError, '^kernel image differs from bound image$'):
                    capture_durability.execute(args)
            self.assertEqual(boots.calls, [('readiness', 'capture'), ('readiness', 'recover')])

    def test_aggregate_records_verified_status_per_scenario(self):
        import capture_durability
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            args = self.make_args(stage)
            # Mixed mock statuses prove per-scenario capture, not one copied flag.
            statuses = {'readiness': 'absent', 'checkpoint': 'absent',
                        'bytes-full': 'measured', 'inodes-full': 'measured'}
            boots = self.fake_boots(stage, statuses)
            with self.harness(stage, boots):
                capture_durability.execute(args)
            evidence = stage.root / 'out' / 'ev'
            aggregate = json.loads((evidence / 'result.json').read_text())
            self.assertEqual(aggregate['status'], 'PASS')
            self.assertEqual(aggregate['scenarios'], list(capture_durability.SCENARIOS))
            self.assertEqual(aggregate['identity']['config_status_by_scenario'], statuses)
            self.assertTrue(aggregate['identity']['config_absent_approved'])
            preboot = json.loads((evidence / 'identity.json').read_text())
            self.assertNotIn('config_status_by_scenario', preboot)

    def test_genuine_mocked_run_reaches_aggregate_pass(self):
        import capture_durability
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            args = self.make_args(stage)
            statuses = {name: 'absent' for name in capture_durability.SCENARIOS}
            boots = self.fake_boots(stage, statuses)
            with self.harness(stage, boots):
                capture_durability.execute(args)
            self.assertEqual(boots.calls, [('readiness', 'capture'), ('readiness', 'recover'),
                                           ('checkpoint', 'capture'), ('checkpoint', 'recover'),
                                           ('bytes-full', 'capture'), ('inodes-full', 'capture')])
            aggregate = json.loads((stage.root / 'out' / 'ev' / 'result.json').read_text())
            self.assertEqual(aggregate['status'], 'PASS')
            self.assertEqual(aggregate['identity']['config_status_by_scenario'], statuses)
            self.assertEqual(aggregate['identity']['modules_files'], stage.mods_files)

    def test_checkpoint_without_operator_records_refused(self):
        import capture_durability
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            args = self.make_args(stage)
            statuses = {name: 'absent' for name in capture_durability.SCENARIOS}
            boots = self.fake_boots(stage, statuses, operator=False)
            with self.harness(stage, boots):
                with self.assertRaisesRegex(ValueError, '^operator oracle log absent$'):
                    capture_durability.execute(args)
            self.assertEqual(boots.calls, [('readiness', 'capture'), ('readiness', 'recover'),
                                           ('checkpoint', 'capture')])

    def test_checkpoint_retains_operator_plan_window_and_verdict(self):
        import capture_durability
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            args = self.make_args(stage)
            statuses = {name: 'absent' for name in capture_durability.SCENARIOS}
            boots = self.fake_boots(stage, statuses)
            with self.harness(stage, boots):
                capture_durability.execute(args)
            case = stage.root / 'out' / 'ev' / 'checkpoint'
            plan = json.loads((case / 'operator-plan.json').read_text())
            self.assertEqual(plan['scenario'], 'checkpoint')
            window = json.loads((case / 'operator-window.json').read_text())
            self.assertEqual(window['bytes_written'], str(plan['workload']['total_bytes']))
            verdict = json.loads((case / 'operator-verdict.json').read_text())
            self.assertEqual(verdict['status'], 'PASS')
            self.assertEqual(verdict['nonce'], plan['nonce'])

    def test_generated_nonce_fits_20_byte_serial(self):
        import capture_durability
        with tempfile.TemporaryDirectory() as tmp:
            stage = self.make_stage(tmp)
            args = self.make_args(stage)
            statuses = {name: 'absent' for name in capture_durability.SCENARIOS}
            boots = self.fake_boots(stage, statuses)
            with self.harness(stage, boots):
                capture_durability.execute(args)
            nonces = []
            for scenario in capture_durability.SCENARIOS:
                export = stage.root / 'out' / 'ev' / scenario / 'export'
                if scenario in ('readiness', 'checkpoint'):
                    nonces.append(json.loads((export / 'barrier.json').read_text())['nonce'])
                nonces.append(json.loads((export / 'result.json').read_text())['nonce'])
            self.assertEqual(len(nonces), 6)
            for nonce in nonces:
                self.assertEqual(len(nonce), capture_durability.OWNERSHIP_NONCE_LENGTH)
                self.assertTrue(all(c in '0123456789abcdef' for c in nonce))
            self.assertEqual(len(set(nonces)), 4)

    def test_boot_binds_serial_to_cmdline_gate(self):
        import capture_durability
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / 'logs'
            logs.mkdir()
            nonce = '0123456789abcdef0123'
            self.assertEqual(len(nonce), capture_durability.OWNERSHIP_NONCE_LENGTH)
            with patch('subprocess.Popen', return_value=Mock()) as launched:
                capture_durability.boot('/fake/vng', Path(tmp) / 'config.json',
                                        Path(tmp) / 'vmlinuz', 'readiness', nonce,
                                        Path(tmp) / 'disk.img', Path(tmp) / 'export',
                                        Path(tmp) / 'qmp', 'capture', logs)
            self.assertEqual(launched.call_count, 1)
            command = json.loads((logs / 'capture-command.json').read_text())
            append = command[command.index('--append') + 1]
            self.assertIn('memveil_fs_gate=' + nonce, append.split())
            opts = next(part for part in command if part.startswith('--qemu-opts='))
            self.assertIn('serial=' + nonce, opts)


if __name__ == '__main__':
    unittest.main()
