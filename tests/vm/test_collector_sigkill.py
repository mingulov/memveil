#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Collector-SIGKILL recovery gate: armed live run plus offline self-test.

Armed (MEMVEIL_VM_SIGKILL=1): boots one pinned guest per kill boundary
(readiness, durable checkpoint, finalization), SIGKILLs the live
collector exactly at the boundary, then verifies the recovered prefix
with independent hashes/counts and the owned cleanup.

Unarmed (default): runs the offline self-test, which drives the exact
guest flow against a mock collector and mock report, plus negative
controls proving each verdict can fail. No VM, product binary, or
privilege needed.
"""
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / 'tests' / 'cli'))
sys.path.insert(0, str(ROOT / 'tests' / 'fuzz'))
from sigkill_verify import (SCENARIOS, validate_barrier, validate_result,
                            validate_export_inventory, recompute_prefix,
                            load_json)
import sigkill_guest
import sigkill_mock

ARMED_VAR = 'MEMVEIL_VM_SIGKILL'
GUEST_TIMEOUT = 600


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def boot(vng, config_path, kernel, scenario, nonce, export, logs):
    if '/' in kernel or kernel[:1] == '-' or not kernel:
        raise ValueError('kernel is not a plain vng release token')
    command = [vng, '--run', kernel, '-m', '2G', '--append',
               'swiotlb=force memveil_sigkill_gate=' + nonce,
               '--disable-microvm', '--network', 'user',
               '--qemu-opts=-device pcnet,netdev=pcnet0'
               ' -netdev user,id=pcnet0,net=10.0.3.0/24',
               '--rwdir=/tmp/export=' + str(export), '--exec',
               shlex.join([sys.executable, str(HERE / 'sigkill_guest.py'),
                           str(config_path), scenario, nonce])]
    (logs / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    stdout = (logs / 'guest.stdout').open('wb')
    stderr = (logs / 'guest.stderr').open('wb')
    try:
        return subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                start_new_session=True)
    finally:
        stdout.close()
        stderr.close()


def stop_owned(child):
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait(timeout=60)


def host_verify(case, export, nonce, scenario, inputs):
    names = sorted(p.name for p in export.iterdir())
    validate_export_inventory(names, scenario)
    barrier = load_json(export / 'barrier.json')
    validate_barrier(barrier, nonce, scenario, inputs)
    result = load_json(export / 'result.json')
    validate_result(result, barrier, inputs)
    checkpoint_doc = load_json(export / 'checkpoint.json')
    if hashlib.sha256((export / 'checkpoint.json').read_bytes()).hexdigest() \
            != barrier['checkpoint_sha256']:
        raise ValueError('exported checkpoint disagrees with barrier digest')
    prefix_bytes = (export / 'prefix-events.ndjson').read_bytes()
    recomputed = recompute_prefix(prefix_bytes, checkpoint_doc)
    if recomputed != barrier['integrity']:
        raise ValueError('host recomputation disagrees with barrier')
    if recomputed != result['integrity']:
        raise ValueError('host recomputation disagrees with result')
    receipt = dict(status='PASS', scenario=scenario, nonce=nonce,
                   integrity=recomputed,
                   checkpoint_sha256=barrier['checkpoint_sha256'])
    (case / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def execute(args):
    from harness_env import check_harness_versions
    vng = shutil.which('vng')
    if not vng or not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise ValueError('owned unprivileged QEMU needs vng and writable /dev/kvm')
    harness = check_harness_versions(vng)
    config = {key: str(getattr(args, key).resolve(strict=True))
              for key in ('binary', 'object', 'profile')}
    if args.bridge:
        # Omitted for statically linked loaders, which ship no bridge.
        config['bridge'] = str(args.bridge.resolve(strict=True))
    shim = args.shim.resolve(strict=True) if args.shim else \
        (ROOT / 'build/shim/capture_faults.so').resolve(strict=True)
    config['shim'] = str(shim)
    config['expect_release'] = args.expect_release
    if digest(config['binary']) != args.binary_sha256:
        raise ValueError('candidate executable hash mismatch')
    inputs = {key: digest(path) for key, path in config.items()
              if key != 'expect_release'}
    args.out = args.out.parent.resolve(strict=True) / args.out.name
    if any(c.isspace() or c == ',' for c in str(args.out)):
        raise ValueError('evidence path contains ambiguous QEMU separators')
    if shutil.disk_usage(args.out.parent).free < 2 * 1024**3:
        raise ValueError('insufficient host space for bounded owned images')
    args.out.mkdir(mode=0o700)
    owned = args.out.stat()
    args.owned_out_ids = (owned.st_dev, owned.st_ino)
    config_path = args.out / 'config.json'
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    identity = dict(inputs=inputs, harness=harness,
                    kernel=args.kernel, expect_release=args.expect_release,
                    source=subprocess.check_output(
                        ['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                        text=True).strip())
    (args.out / 'identity.json').write_text(json.dumps(identity, indent=2)
                                            + '\n')
    lock_path = ROOT / 'build/vm/suite.lock'
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    receipts = []
    with lock_path.open('a+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for scenario in SCENARIOS:
            case = args.out / scenario
            case.mkdir(mode=0o700)
            export = case / 'export'
            export.mkdir(mode=0o700)
            nonce = uuid.uuid4().hex
            child = boot(vng, config_path, args.kernel, scenario, nonce,
                         export, case)
            try:
                child.wait(timeout=GUEST_TIMEOUT)
                if child.returncode != 0:
                    raise ValueError('guest failure, exit %s'
                                     % child.returncode)
                receipts.append(host_verify(case, export, nonce, scenario,
                                            inputs))
            finally:
                stop_owned(child)
    (args.out / 'result.json').write_text(json.dumps(
        dict(status='PASS', scenarios=list(SCENARIOS), identity=identity,
             receipts=receipts), indent=2) + '\n')


def retain_owned_failure(path, identity, reason):
    if identity is None:
        return
    directory = -1
    try:
        directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        actual = os.fstat(directory)
        if (actual.st_dev, actual.st_ino) != identity:
            raise ValueError('evidence directory was replaced')
        fd = os.open('failure.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(dict(status='FAIL', reason=reason)) + '\n')
    except (OSError, ValueError) as exc:
        print('collector-sigkill: failure evidence not replaced: ' + str(exc),
              file=sys.stderr)
    finally:
        if directory >= 0:
            os.close(directory)


# --- Offline self-test: the exact guest flow against mock binaries. ---

MOCK_FAULT = {'readiness': 'readiness', 'checkpoint': 'checkpoint-2',
              'finalization': 'final-stop'}


def mock_identity(inputs):
    return dict(kernel_config_sha256=None, kernel='mock-release',
                release='mock-release', banner='mock banner',
                boot_id='mock-boot-id', btf_sha256='mock-btf',
                inputs=dict(inputs))


def mock_spawn(work, mode_flags=None):
    mode_flags = mode_flags or []

    def spawn(capture, marker):
        err = open(Path(work) / 'record.stderr', 'wb')
        proc = subprocess.Popen(
            [sys.executable, str(HERE / 'sigkill_mock.py'), 'collector',
             str(capture), str(marker), MOCK_FAULT[current[0]]] + mode_flags,
            stdout=subprocess.PIPE, stderr=err)
        err.close()
        return proc
    current = [None]
    return spawn, current


def mock_report(report_flags=None):
    report_flags = report_flags or []

    def run(capture, flags):
        return subprocess.run(
            [sys.executable, str(HERE / 'sigkill_mock.py'), 'report']
            + report_flags + flags + [str(capture)], capture_output=True)
    return run


def run_mock_scenario(scenario, tmp, collect_flags=None, report_flags=None,
                      stimulus=False):
    tmp = Path(tmp)
    work = tmp / 'work'
    work.mkdir(mode=0o700)
    export = tmp / 'export'
    export.mkdir(mode=0o700)
    inputs = {'binary': 'a' * 64, 'object': 'b' * 64, 'bridge': 'c' * 64,
              'profile': 'd' * 64, 'shim': 'e' * 64}
    nonce = 'f' * 32
    spawn, current = mock_spawn(work, collect_flags)
    current[0] = scenario
    barrier, result = sigkill_guest.run_scenario(
        scenario, nonce, work, export, inputs, mock_identity(inputs), spawn,
        mock_report(report_flags), 'sigkill_mock.py', stimulus=stimulus)
    return barrier, result, export, inputs, nonce


ARMED_READINESS_EXPORT = HERE / 'fixtures' / 'sigkill-armed-readiness'
SEVEN_KEYS = frozenset(('algorithm', 'events_bytes', 'events_sha256',
                        'first_seq', 'kinds', 'last_seq', 'line_count'))


def armed_export_copy(tmp):
    """Fresh writable copy of the byte-identical armed export."""
    tmp = Path(tmp)
    export = tmp / 'export'
    export.mkdir(mode=0o700)
    for name in ('barrier.json', 'result.json', 'checkpoint.json',
                 'prefix-events.ndjson', 'record.stderr'):
        shutil.copyfile(ARMED_READINESS_EXPORT / name, export / name)
    return export


def tampered_declared(declared):
    """One wrong value per integrity key, derived from a good dict."""
    count = int(declared['line_count'])
    variants = {}
    variants['algorithm'] = 'sha512'
    variants['events_bytes'] = str(int(declared['events_bytes']) + 1)
    variants['line_count'] = str(count + 1)
    first = declared['events_sha256'][0]
    variants['events_sha256'] = ('0' if first != '0' else '1') \
        + declared['events_sha256'][1:]
    if declared['first_seq'] is None:
        variants['first_seq'] = '0'
        variants['last_seq'] = '0'
    else:
        variants['first_seq'] = str(int(declared['first_seq']) + 1)
        variants['last_seq'] = str(int(declared['last_seq']) - 1)
    kinds = dict(declared['kinds'])
    bump = sorted(kinds)[0]
    kinds[bump] = str(int(kinds[bump]) + 1)
    variants['kinds'] = kinds
    return variants


class SigkillSelfTests(unittest.TestCase):
    def test_all_three_boundaries_pass_offline(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario), \
                    tempfile.TemporaryDirectory() as tmp:
                barrier, result, export, inputs, nonce = run_mock_scenario(
                    scenario, tmp)
                validate_barrier(barrier, nonce, scenario, inputs)
                validate_result(result, barrier, inputs)
                names = sorted(p.name for p in Path(export).iterdir())
                validate_export_inventory(names, scenario)
                checkpoint_doc = load_json(Path(export) / 'checkpoint.json')
                prefix_bytes = (Path(export)
                                / 'prefix-events.ndjson').read_bytes()
                recomputed = recompute_prefix(prefix_bytes, checkpoint_doc)
                self.assertEqual(recomputed, barrier['integrity'])
                self.assertEqual(result['collector_returncode'], -9)
                if scenario == 'readiness':
                    self.assertEqual(barrier['integrity']['line_count'], '0')
                    self.assertEqual(prefix_bytes, b'')
                else:
                    self.assertGreater(
                        int(barrier['integrity']['line_count']), 0)

    def test_host_verify_accepts_mock_evidence(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario), \
                    tempfile.TemporaryDirectory() as tmp:
                _, _, export, inputs, nonce = run_mock_scenario(scenario, tmp)
                receipt = host_verify(Path(tmp), Path(export), nonce,
                                      scenario, inputs)
                self.assertEqual(receipt['status'], 'PASS')

    def test_recompute_agrees_with_independent_oracle(self):
        from test_checkpoint_writer import independent
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario), \
                    tempfile.TemporaryDirectory() as tmp:
                _, _, export, _, _ = run_mock_scenario(scenario, tmp)
                checkpoint_doc = load_json(Path(export) / 'checkpoint.json')
                prefix_bytes = (Path(export)
                                / 'prefix-events.ndjson').read_bytes()
                with tempfile.TemporaryDirectory() as other:
                    capture = Path(other) / 'capture'
                    capture.mkdir()
                    (capture / 'events.ndjson').write_bytes(prefix_bytes)
                    (capture / 'checkpoint.json').write_text(
                        json.dumps(checkpoint_doc))
                    doc = independent(capture)
                self.assertEqual(doc['capture']['integrity'],
                                 recompute_prefix(prefix_bytes,
                                                  checkpoint_doc))

    def test_host_verify_accepts_armed_seven_key_export(self):
        # Replays the byte-identical armed readiness export through
        # the host judge offline. The barrier carries the product's
        # 7-key integrity shape; the host recomputation must agree
        # exactly, not merely on a 4-key subset.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            export = armed_export_copy(tmp)
            barrier = load_json(export / 'barrier.json')
            self.assertEqual(set(barrier['integrity']), set(SEVEN_KEYS))
            receipt = host_verify(tmp, export, barrier['nonce'],
                                  barrier['scenario'],
                                  barrier['identity']['inputs'])
            self.assertEqual(receipt['status'], 'PASS')
            self.assertEqual(receipt['integrity'], barrier['integrity'])

    def test_mock_emits_armed_seven_key_shape(self):
        # The mock must seal the exact product shape, or the offline
        # suite cannot guard the host judge: the empty mock prefix
        # must equal the armed empty prefix key for key, and the
        # non-empty prefix must carry the 0..N-1 span over ten kinds.
        armed = load_json(ARMED_READINESS_EXPORT / 'barrier.json')
        with tempfile.TemporaryDirectory() as tmp:
            barrier, _, _, _, _ = run_mock_scenario('readiness', tmp)
            self.assertEqual(barrier['integrity'], armed['integrity'])
        with tempfile.TemporaryDirectory() as tmp:
            barrier, _, _, _, _ = run_mock_scenario('checkpoint', tmp)
            integrity = barrier['integrity']
            self.assertEqual(set(integrity), set(SEVEN_KEYS))
            self.assertEqual(integrity['algorithm'], 'sha256')
            self.assertEqual(integrity['first_seq'], '0')
            self.assertEqual(integrity['last_seq'],
                             str(int(integrity['line_count']) - 1))
            self.assertEqual(len(integrity['kinds']), 10)

    def test_recompute_derives_all_seven_keys_from_bytes(self):
        # Every returned key is re-derived from the raw prefix bytes
        # and cross-checked against the declared value: tampering any
        # single declared key must raise instead of flowing into the
        # result. Proves the host recomputation verifies rather than
        # copies the checkpoint books. Covers the armed empty prefix
        # and a non-empty span.
        with tempfile.TemporaryDirectory() as tmp:
            export = armed_export_copy(tmp)
            armed_prefix = (export / 'prefix-events.ndjson').read_bytes()
            armed_doc = load_json(export / 'checkpoint.json')
            armed_barrier = load_json(export / 'barrier.json')
        with tempfile.TemporaryDirectory() as tmp:
            _, _, mock_export, _, _ = run_mock_scenario('checkpoint', tmp)
            mock_export = Path(mock_export)
            mock_prefix = (mock_export
                           / 'prefix-events.ndjson').read_bytes()
            mock_doc = load_json(mock_export / 'checkpoint.json')
            mock_barrier = load_json(mock_export / 'barrier.json')
        for label, prefix, doc, barrier in (
                ('armed-empty', armed_prefix, armed_doc, armed_barrier),
                ('mock-nonempty', mock_prefix, mock_doc, mock_barrier)):
            with self.subTest(shape=label):
                recomputed = recompute_prefix(prefix, doc)
                self.assertEqual(set(recomputed), set(SEVEN_KEYS))
                self.assertEqual(recomputed, barrier['integrity'])
                for key, wrong in tampered_declared(
                        doc['capture']['integrity']).items():
                    bad = copy.deepcopy(doc)
                    bad['capture']['integrity'][key] = wrong
                    with self.subTest(key=key), \
                            self.assertRaises(ValueError):
                        recompute_prefix(prefix, bad)

    def test_host_verify_refuses_each_tampered_key(self):
        # Tamper one barrier/result integrity key at a time, leaving
        # the checkpoint and prefix pristine with barrier == result,
        # so only the host's independent checks can refuse. Keys the
        # barrier shape gate does not cover must fail at the
        # recomputation comparison itself.
        recompute_refusals = {'algorithm', 'first_seq', 'last_seq',
                              'kinds'}
        barrier = load_json(ARMED_READINESS_EXPORT / 'barrier.json')
        for key, wrong in tampered_declared(
                barrier['integrity']).items():
            with self.subTest(key=key), \
                    tempfile.TemporaryDirectory() as tmp:
                tmp = Path(tmp)
                export = armed_export_copy(tmp)
                for name in ('barrier.json', 'result.json'):
                    doc = load_json(export / name)
                    doc['integrity'][key] = wrong
                    (export / name).write_text(json.dumps(doc) + '\n')
                if key in recompute_refusals:
                    with self.assertRaisesRegex(ValueError, 'recomput'):
                        host_verify(tmp, export, barrier['nonce'],
                                    barrier['scenario'],
                                    barrier['identity']['inputs'])
                else:
                    with self.assertRaises(ValueError):
                        host_verify(tmp, export, barrier['nonce'],
                                    barrier['scenario'],
                                    barrier['identity']['inputs'])

    def test_lying_books_fail_the_barrier(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, 'prefix'):
                run_mock_scenario('checkpoint', tmp, collect_flags=['--lie'])

    def test_missing_boundary_never_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            work = tmp / 'work'
            work.mkdir(mode=0o700)
            export = tmp / 'export'
            export.mkdir(mode=0o700)
            inputs = {'binary': 'a' * 64}
            nonce = 'f' * 32

            def spawn(capture, marker):
                del marker
                err = open(work / 'record.stderr', 'wb')
                proc = subprocess.Popen(
                    [sys.executable, str(HERE / 'sigkill_mock.py'),
                     'collector', str(capture), str(tmp / 'unused'), 'none'],
                    stdout=subprocess.PIPE, stderr=err)
                err.close()
                return proc

            with self.assertRaisesRegex(ValueError, 'boundary'):
                sigkill_guest.run_scenario(
                    'checkpoint', nonce, work, export, inputs,
                    mock_identity(inputs), spawn, mock_report(),
                    'sigkill_mock.py', stimulus=False)

    def test_tampered_prefix_fails_stability(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            work = tmp / 'work'
            work.mkdir(mode=0o700)
            export = tmp / 'export'
            export.mkdir(mode=0o700)
            inputs = {'binary': 'a' * 64}
            nonce = 'f' * 32
            real_kill = sigkill_guest.kill_and_prove

            def tampering_kill(child):
                code = real_kill(child)
                events = work / 'capture' / 'events.ndjson'
                raw = bytearray(events.read_bytes())
                raw[5] ^= 0xff
                events.write_bytes(bytes(raw))
                return code

            spawn, current = mock_spawn(work)
            current[0] = 'checkpoint'
            sigkill_guest.kill_and_prove = tampering_kill
            try:
                with self.assertRaisesRegex(ValueError, 'across the kill'):
                    sigkill_guest.run_scenario(
                        'checkpoint', nonce, work, export, inputs,
                        mock_identity(inputs), spawn, mock_report(),
                        'sigkill_mock.py', stimulus=False)
            finally:
                sigkill_guest.kill_and_prove = real_kill

    def test_wrong_report_exit_fails_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, 'report'):
                run_mock_scenario('readiness', tmp,
                                  report_flags=['--wrong-exit'])

    def test_wrong_recovered_count_fails_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, 'count'):
                run_mock_scenario('checkpoint', tmp,
                                  report_flags=['--wrong-count'])

    def test_stray_capture_file_fails_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            work = tmp / 'work'
            work.mkdir(mode=0o700)
            export = tmp / 'export'
            export.mkdir(mode=0o700)
            inputs = {'binary': 'a' * 64}
            nonce = 'f' * 32
            spawn, current = mock_spawn(work)
            current[0] = 'readiness'
            real_cleanup = sigkill_guest.check_cleanup

            def littering_cleanup(scenario, capture, binary_name):
                (Path(capture) / 'stray.tmp').write_bytes(b'litter')
                return real_cleanup(scenario, capture, binary_name)

            sigkill_guest.check_cleanup = littering_cleanup
            try:
                with self.assertRaisesRegex(ValueError, 'inventory'):
                    sigkill_guest.run_scenario(
                        'readiness', nonce, work, export, inputs,
                        mock_identity(inputs), spawn, mock_report(),
                        'sigkill_mock.py', stimulus=False)
            finally:
                sigkill_guest.check_cleanup = real_cleanup

    def test_capture_inventory_matches_armed_product_shape(self):
        # Pins the armed capture-dir shape WITHOUT the mock collector: the
        # exact file set the real `record` leaves at each kill boundary
        # (derivation in the CAPTURE_INVENTORY comment). The mock and the
        # gate must agree with this shape independently, so a
        # stand-in/harness co-drift cannot hide a mismatch again.
        from sigkill_verify import CAPTURE_INVENTORY
        for scenario in ('readiness', 'checkpoint'):
            with self.subTest(scenario=scenario), \
                    tempfile.TemporaryDirectory() as tmp:
                capture = Path(tmp) / 'capture'
                capture.mkdir(mode=0o700)
                sigkill_mock.write_reserve(capture / '.finalization-reserve')
                (capture / 'session.finalizing').write_bytes(b'')
                events, kinds = sigkill_mock.make_events(0)
                first = sigkill_mock.checkpoint_doc(1, events, kinds)
                if scenario == 'checkpoint':
                    (capture / 'checkpoint.json.tmp').write_text(
                        json.dumps(first) + '\n')
                    events, _ = sigkill_mock.make_events(
                        sigkill_mock.EVENT_COUNT)
                    sigkill_mock.publish(capture, 2, events, kinds)
                else:
                    sigkill_mock.publish(capture, 1, events, kinds)
                cleanup = sigkill_guest.check_cleanup(
                    scenario, capture, 'memveil-test-no-such-process')
                self.assertEqual(set(cleanup['capture_inventory']),
                                 set(CAPTURE_INVENTORY[scenario]))

    def test_held_lock_fails_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = Path(tmp) / 'capture'
            capture.mkdir()
            fd = os.open(capture, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertFalse(sigkill_guest.dir_lock_released(str(capture)))
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            self.assertTrue(sigkill_guest.dir_lock_released(str(capture)))

    def test_non_sigkill_death_fails_kill_proof(self):
        child = subprocess.Popen([sys.executable, '-c',
                                  'import time; time.sleep(30)'])
        try:
            child.terminate()
            with self.assertRaisesRegex(ValueError, 'SIGKILL'):
                sigkill_guest.kill_and_prove(child)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)

    def test_barrier_negatives(self):
        inputs = {'binary': 'a' * 64}
        good = dict(nonce='b' * 32, scenario='readiness', stopped=True,
                    marker='readiness-announced', ready_observed=True,
                    reserve_allocated=17 * 1048576, reserve_released=False,
                    integrity={'algorithm': 'sha256',
                               'events_bytes': '0', 'line_count': '0',
                               'first_seq': None, 'last_seq': None,
                               'events_sha256': hashlib.sha256(b'').hexdigest(),
                               'kinds': {}},
                    checkpoint_sha256='c' * 64,
                    identity=dict(inputs=inputs, boot_id='boot',
                                  release='7.0.14', banner='banner',
                                  btf_sha256='btf'))
        validate_barrier(good, 'b' * 32, 'readiness', inputs)
        for key, value in [('nonce', 'other'), ('scenario', 'checkpoint'),
                           ('stopped', False), ('marker', 'attach-refused'),
                           ('ready_observed', False), ('reserve_allocated', 0),
                           ('reserve_released', True),
                           ('integrity', {}), ('identity', {}),
                           ('checkpoint_sha256', None)]:
            bad = copy.deepcopy(good)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_barrier(bad, 'b' * 32, 'readiness', inputs)
        with self.assertRaises(ValueError):
            validate_barrier({}, 'b' * 32, 'readiness', inputs)

    def test_finalization_barrier_requires_release_proof(self):
        inputs = {'binary': 'a' * 64}
        integrity = {'algorithm': 'sha256', 'events_bytes': '10',
                     'line_count': '1', 'first_seq': '0', 'last_seq': '0',
                     'events_sha256': 'd' * 64,
                     'kinds': {'bounce_attempt': '1'}}
        good = dict(nonce='b' * 32, scenario='finalization', stopped=True,
                    marker='final-stop', ready_observed=True,
                    reserve_allocated=None, reserve_released=True,
                    integrity=dict(integrity), session_json_absent=True,
                    finalizing_present=True, checkpoint_sha256='c' * 64,
                    identity=dict(inputs=inputs, boot_id='boot',
                                  release='7.0.14', banner='banner',
                                  btf_sha256='btf'))
        validate_barrier(good, 'b' * 32, 'finalization', inputs)
        for key, value in [('reserve_released', False),
                           ('reserve_released', None),
                           ('reserve_allocated', 17 * 1048576),
                           ('session_json_absent', False),
                           ('finalizing_present', False)]:
            bad = copy.deepcopy(good)
            bad[key] = value
            with self.subTest(key=key, value=value), \
                    self.assertRaises(ValueError):
                validate_barrier(bad, 'b' * 32, 'finalization', inputs)

    def test_finalization_barrier_proves_armed_release_shape(self):
        # The armed final-stop capture holds NO .finalization-reserve:
        # finalize() unlinks it before the stopped session.json rename
        # (derivation in the CAPTURE_INVENTORY comment). The barrier and
        # the inventory gate must accept that true shape and refuse the
        # NOT-released one, or the release proof is vacuous. Built
        # WITHOUT the mock collector so a stand-in/harness co-drift
        # cannot hide a mismatch.
        from sigkill_verify import CAPTURE_INVENTORY
        inputs = {'binary': 'a' * 64}
        nonce = 'f' * 32
        with tempfile.TemporaryDirectory() as tmp:
            capture = Path(tmp) / 'capture'
            capture.mkdir(mode=0o700)
            events, kinds = sigkill_mock.make_events(
                sigkill_mock.EVENT_COUNT)
            sigkill_mock.publish(capture, 2, events, kinds)
            doc = sigkill_mock.checkpoint_doc(2, events, kinds)
            doc['capture']['finalized'] = True
            (capture / 'session.finalizing').write_text(json.dumps(doc)
                                                       + '\n')
            marker = Path(tmp) / 'reached'
            marker.write_text('final-stop')
            barrier = sigkill_guest.snapshot_barrier(
                'finalization', nonce, marker, capture,
                mock_identity(inputs))
            self.assertTrue(barrier['reserve_released'])
            self.assertIsNone(barrier['reserve_allocated'])
            validate_barrier(barrier, nonce, 'finalization', inputs)
            cleanup = sigkill_guest.check_cleanup(
                'finalization', capture, 'memveil-test-no-such-process')
            self.assertEqual(set(cleanup['capture_inventory']),
                             set(CAPTURE_INVENTORY['finalization']))
            self.assertNotIn('.finalization-reserve',
                             cleanup['capture_inventory'])
            # The old (wrong) shape — reserve still present at the
            # finalization barrier — must fail closed.
            sigkill_mock.write_reserve(capture / '.finalization-reserve')
            with self.assertRaisesRegex(ValueError, 'release'):
                sigkill_guest.snapshot_barrier(
                    'finalization', nonce, marker, capture,
                    mock_identity(inputs))

    def test_result_negatives(self):
        inputs = {'binary': 'a' * 64}
        integrity = {'algorithm': 'sha256', 'events_bytes': '0',
                     'line_count': '0', 'first_seq': None, 'last_seq': None,
                     'events_sha256': hashlib.sha256(b'').hexdigest(),
                     'kinds': {}}
        barrier = dict(nonce='b' * 32, scenario='readiness',
                       integrity=integrity, checkpoint_sha256='c' * 64)
        good = dict(nonce='b' * 32, scenario='readiness',
                    killed_by_sigkill=True, collector_returncode=-9,
                    integrity=dict(integrity), checkpoint_sha256='c' * 64,
                    report=dict(plain_exit=2, partial_exit=4,
                                partial_strict_exit=4, verified_events='0'),
                    cleanup=dict(session_json_absent=True, stray_processes=[],
                                 dir_lock_released=True,
                                 capture_inventory=['.finalization-reserve',
                                                    'checkpoint.json',
                                                    'events.ndjson',
                                                    'session.finalizing']),
                    identity=dict(inputs=inputs))
        validate_result(good, barrier, inputs)
        bads = [dict(good, nonce='other'),
                dict(good, killed_by_sigkill=False),
                dict(good, collector_returncode=-15),
                dict(good, integrity=dict(integrity, line_count='1')),
                dict(good, report=dict(plain_exit=0, partial_exit=4,
                                       partial_strict_exit=4,
                                       verified_events='0')),
                dict(good, report=dict(plain_exit=2, partial_exit=0,
                                       partial_strict_exit=4,
                                       verified_events='0')),
                dict(good, cleanup=dict(session_json_absent=False,
                                         stray_processes=[],
                                         dir_lock_released=True,
                                         capture_inventory=[]))]
        for bad in bads:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_result(bad, barrier, inputs)

    def test_export_tamper_fails_host_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, export, inputs, nonce = run_mock_scenario('checkpoint', tmp)
            prefix = Path(export) / 'prefix-events.ndjson'
            raw = bytearray(prefix.read_bytes())
            # Flip a byte inside the declared extent; the host
            # recomputation must catch the digest mismatch.
            raw[5] ^= 0xff
            prefix.write_bytes(bytes(raw))
            with self.assertRaises(ValueError):
                host_verify(Path(tmp), Path(export), nonce, 'checkpoint',
                            inputs)

    def test_collector_argv_omits_missing_bridge(self):
        base = dict(binary='/b/memveil', object='/b/attempt.bpf.o',
                    profile='/b/7.0.json')
        argv = sigkill_guest.collector_argv(dict(base), '/cap', 'checkpoint')
        self.assertNotIn('--bridge', argv)
        self.assertIn('--object', argv)
        argv = sigkill_guest.collector_argv(dict(base, bridge='/b/bridge.so'),
                                           '/cap', 'checkpoint')
        self.assertIn('--bridge', argv)

    def test_boot_rejects_kernel_paths(self):
        with self.assertRaises(ValueError):
            boot('vng', Path('/tmp/config'), '../evil', 'readiness',
                 'f' * 32, Path('/tmp/export'), Path('/tmp/logs'))


def main():
    if os.environ.get(ARMED_VAR) != '1':
        unittest.main(argv=[sys.argv[0]] + sys.argv[1:], verbosity=2)
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'object', 'profile', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--bridge', type=Path, required=False,
                        help='native bridge (omit for static loaders)')
    parser.add_argument('--kernel', required=True,
                        help='vng release token for the pinned guest')
    parser.add_argument('--expect-release', required=True,
                        help='uname -r the guest must boot')
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--shim', type=Path, required=False,
                        help='capture fault shim (default: build tree)')
    args = parser.parse_args()
    args.owned_out_ids = None
    try:
        execute(args)
    except Exception as exc:
        print('collector-sigkill: FAIL: ' + str(exc), file=sys.stderr)
        retain_owned_failure(args.out, args.owned_out_ids, str(exc))
        return 1
    print('collector-sigkill: PASS: live kills at readiness, durable '
          'checkpoint and finalization')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
