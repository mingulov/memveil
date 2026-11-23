#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Armed ext4 full-filesystem and hard-QEMU-power-cut qualification runner.

Requires an exact candidate and an admitted profile for the selected kernel.
Creates only bounded, exclusive scratch images; never mounts or formats host
storage. Unarmed exit 77 is a skip. Any armed prerequisite or boundary failure
is fatal, with evidence retained. SIGKILL of the collector is a different test.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ('readiness', 'checkpoint', 'bytes-full', 'inodes-full')

# Config-absent admission: this exact release's kernel is built without
# IKCONFIG_PROC, so its guests expose no /proc/config.gz. Absence is accepted
# ONLY on that release; any other row fails closed. The compensating binding
# (image and modules pins compared with the locked row, then the image and
# the image-resolved module tree re-verified before every boot; expected
# release plus module manifest plus pinned live BTF before guest disk
# mutation) is explicitly weaker than a direct config match: an image digest
# proves image identity, not the exact build config. Receipts from this
# revision carry a new evidence identity (this harness commit plus the
# config-absent row) and require explicit downstream approval before any gate
# use.
APPROVED_CONFIG_ABSENT_RELEASE = '7.0.14-070014-generic'

# Ownership-nonce shape. The guest reads the nonce back through the
# virtio-blk serial, which the kernel exposes truncated to
# VIRTIO_BLK_ID_BYTES (20 bytes) at /sys/block/vdX/serial, so a nonce
# longer than 20 chars can never round-trip. The generated value is
# exactly 20 lowercase hex chars. 20 hex chars carry 80 bits of fresh
# uuid4 randomness per scenario run, which suffices for a per-run
# ownership binding: each value is used once, matched exactly against
# one attached disk, and never reused, so passing the gate requires
# predicting the fresh 80-bit value outright.
OWNERSHIP_NONCE_LENGTH = 20

# Shell-inert path characters. The launcher interpolates the verified
# kernel path, the export dir, and the disk/QMP socket paths into one
# shell command without quoting (virtme_ng/run.py: kimg at :1058, rwdir
# at :1015, qemu-opts at :1356, executed via shell=True at :1470), so
# any spelling the shell rewrites would boot something other than the
# verified inputs. Quoting for the wrapper is too fragile, so paths
# reaching that command are restricted to characters the shell leaves
# alone: letters, digits, and _@%+=:,./- (the real cache trees need
# only letters, digits, /, ., -, _). Each shell rewrite class stays
# inert: quote removal has no ' or " to strip; word splitting has no
# whitespace; globbing has no *, ?, or [ (nor ] to close one); tilde,
# brace, command, parameter, and arithmetic expansion have no ~, {, },
# `, $, (, or ); chaining, redirection, pipelines, and comments have
# no ;, &, |, <, >, or #; escaping has no backslash; and ! and ^ are
# refused although a non-interactive shell would leave them alone.
# Resolved paths start with /, so = can never begin an assignment and
# - can never begin an option; the remaining signs (: , % @ + .) are
# ordinary shell word characters.
SHELL_INERT_CHARS = frozenset(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@%+=:,./-')


def check_shell_inert_path(path, label):
    """Refuse a path the launcher shell would rewrite before it is used."""
    text = str(path)
    if any(char not in SHELL_INERT_CHARS for char in text):
        raise ValueError(label + ' contains characters the launcher shell rewrites: ' + text)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_kernel_binding(kernel, expected_sha256):
    observed = digest(kernel)
    if observed != expected_sha256:
        raise ValueError('kernel image differs from bound image')
    return observed


def check_modules_binding(modules, expected_sha256):
    from kernel_matrix import modules_manifest_sha
    if not os.path.isdir(modules):
        raise ValueError('modules path is not a modules directory')
    observed, files = modules_manifest_sha(str(modules))
    if files == 0:
        raise ValueError('modules manifest is empty')
    if observed != expected_sha256:
        raise ValueError('modules manifest differs from bound modules')
    return observed, files


def check_bound_config(ident, config_sha, expected_release, messages):
    """Fail-closed config claim check for one guest receipt identity.

    messages is (mismatch, absent_unapproved, absent_with_hash, unknown)
    with the caller's exact refusal texts.
    """
    mismatch, absent_unapproved, absent_with_hash, unknown = messages
    status = ident.get('config_status')
    if status == 'measured':
        if ident.get('kernel_config_sha256') != config_sha:
            raise ValueError(mismatch)
        return
    if status == 'absent':
        if ident.get('kernel') != expected_release or expected_release != APPROVED_CONFIG_ABSENT_RELEASE:
            raise ValueError(absent_unapproved)
        if ident.get('kernel_config_sha256') is not None:
            raise ValueError(absent_with_hash)
        return
    raise ValueError(unknown)


def locked_row_pins(expected_release):
    """Pinned image and modules shas for one exact locked release."""
    try:
        doc = json.loads((ROOT / 'tests/vm/kernels.lock.json').read_text())
    except (OSError, ValueError):
        raise ValueError('locked kernel rows unreadable')
    rows = doc.get('kernels') if isinstance(doc, dict) else None
    if not isinstance(rows, list):
        raise ValueError('locked kernel rows unreadable')
    pairs = set()
    for row in rows:
        if not isinstance(row, dict) or row.get('release') != expected_release:
            continue
        source = row.get('source') or {}
        image = source.get('vmlinuz_sha256') or source.get('bzimage_sha256')
        mods = source.get('modules_manifest_sha256')
        if image and mods:
            pairs.add((image, mods))
    if not pairs:
        raise ValueError('expected release has no locked kernel row')
    if len(pairs) > 1:
        raise ValueError('expected release matches ambiguous locked rows')
    return pairs.pop()


def image_modules_dir(kernel, expected_release):
    """Module tree the launcher derives from a kernel image path.

    Mirrors the virtme-ng rootfs walk: the closest ancestor holding
    lib/modules (or usr/lib/modules) becomes the root, and the guest
    takes <root>/lib/modules/<release> from it. The launch argv carries
    only the image path, so the supplied modules must be this tree.
    """
    path = os.path.dirname(os.path.abspath(str(kernel)))
    while path and path != '/' and not os.path.exists(path + '/lib/modules'):
        if os.path.exists(path + '/usr/lib/modules'):
            path += '/usr'
            break
        path, _ = os.path.split(path)
    # Trailing-/usr correction from the launcher resolver: when the walk
    # stops at .../usr but the sibling ../lib is a symlink, the launcher
    # steps back to the parent root before deriving lib/modules/<release>.
    if path.endswith('/usr') and os.path.islink(path + '/../lib'):
        path, _ = os.path.split(path)
    return os.path.abspath(path) + '/lib/modules/' + expected_release


def verify_boot_inputs(raw_kernel, raw_modules, expected_release,
                       expected_kernel_sha256, expected_modules_sha256):
    """Resolve and verify exactly what the next boot will use."""
    kernel = Path(raw_kernel).resolve(strict=True)
    modules = Path(raw_modules).resolve(strict=True)
    check_shell_inert_path(kernel, 'kernel path')
    check_shell_inert_path(modules, 'modules path')
    kernel_sha = check_kernel_binding(kernel, expected_kernel_sha256)
    modules_sha, modules_files = check_modules_binding(modules, expected_modules_sha256)
    resolved = image_modules_dir(kernel, expected_release)
    if not os.path.isdir(resolved):
        raise ValueError('kernel image resolves to no module tree')
    if os.path.realpath(resolved) != os.path.realpath(str(modules)):
        raise ValueError('supplied modules are not the image-resolved module tree')
    return kernel, kernel_sha, modules_sha, modules_files


def validate_barrier(doc, nonce, scenario, inputs):
    if doc.get('nonce') != nonce or doc.get('scenario') != scenario or doc.get('stopped') is not True:
        raise ValueError('missing owned stopped-writer barrier')
    if doc.get('identity', {}).get('inputs') != inputs:
        raise ValueError('candidate identity changed at barrier')
    wanted = 'readiness-announced' if scenario == 'readiness' else 'checkpoint-2'
    if doc.get('marker') != wanted or doc.get('reserve_allocated', 0) < 17 * 1048576:
        raise ValueError('durability boundary or allocated reserve missing')
    integrity = doc['integrity']
    if scenario == 'readiness':
        if doc.get('ready_observed') is not True:
            raise ValueError('readiness announcement not observed')
        if integrity['events_bytes'] != '0' or integrity['line_count'] != '0' or integrity['events_sha256'] != hashlib.sha256(b'').hexdigest():
            raise ValueError('readiness is not an empty durable prefix')
    elif int(integrity['line_count']) <= 0 or int(integrity['events_bytes']) <= 0:
        raise ValueError('checkpoint prefix is empty')
    if not doc.get('fs_uuid') or not doc.get('identity', {}).get('boot_id'):
        raise ValueError('filesystem or boot identity absent')


def qmp_disk(socket_path, disk):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(socket_path))
        stream = client.makefile('rwb', buffering=0)
        if 'QMP' not in json.loads(stream.readline()):
            raise ValueError('QMP greeting absent')
        for command in ('qmp_capabilities', 'query-block'):
            stream.write((json.dumps({'execute': command}) + '\n').encode())
            while True:
                reply = json.loads(stream.readline())
                if 'event' not in reply:
                    break
            if 'return' not in reply:
                raise ValueError('QMP command failed')
        images = [row.get('inserted', {}).get('file') for row in reply['return']]
        if str(disk) not in images:
            raise ValueError('owned image absent from running QEMU')


def operator_checkpoint_capture(case, export, nonce):
    """Judge the operator I/O window recorded during the capture boot."""
    from capture_durability_operator import OPERATOR_WINDOW_NAME, validate_window
    plan = json.loads((Path(case) / 'operator-plan.json').read_text())
    if plan.get('nonce') != nonce:
        raise ValueError('operator plan ownership drift')
    log_path = Path(export) / 'oracle.log'
    if not log_path.is_file():
        raise ValueError('operator oracle log absent')
    window = validate_window(plan, log_path.read_text())
    (Path(case) / OPERATOR_WINDOW_NAME).write_text(
        json.dumps(window, indent=2, sort_keys=True) + '\n')
    return window


def operator_checkpoint_recover(case, export, promised):
    """Re-judge the retained operator verdict after the recovery boot."""
    from capture_durability_operator import OPERATOR_VERDICT_NAME, validate_verdict
    verdict_path = Path(export) / OPERATOR_VERDICT_NAME
    if not verdict_path.is_file():
        raise ValueError('operator verdict absent')
    verdict = json.loads(verdict_path.read_text())
    status = validate_verdict(verdict, promised)
    (Path(case) / OPERATOR_VERDICT_NAME).write_text(
        json.dumps(verdict, indent=2, sort_keys=True) + '\n')
    if status != 'PASS':
        raise ValueError('operator verdict is not PASS')
    return verdict


def stop_owned(child):
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait(timeout=15)


def boot(vng, config_path, kernel, scenario, nonce, disk, export, qmp, phase, logs):
    command = [vng, '--run', str(kernel), '-m', '2G', '--append',
        'swiotlb=force memveil_fs_gate=' + nonce,
        '--rwdir=/tmp/export=' + str(export), '--exec',
        shlex.join([sys.executable, str(ROOT / 'tests/vm/capture_durability_guest.py'),
                    str(config_path), phase, scenario, nonce]),
        '--qemu-opts=-drive file=' + str(disk) + ',if=none,id=memveilfs,format=raw,cache=writeback'
        + ' -device virtio-blk-pci,drive=memveilfs,serial=' + nonce
        + ' -qmp unix:' + str(qmp) + ',server=on,wait=off']
    (logs / (phase + '-command.json')).write_text(json.dumps(command, indent=2) + '\n')
    stdout = (logs / (phase + '.stdout')).open('wb')
    stderr = (logs / (phase + '.stderr')).open('wb')
    try:
        return subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
    finally:
        stdout.close()
        stderr.close()


def execute(args):
    from harness_env import check_harness_versions
    vng = shutil.which('vng')
    if not vng or not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise ValueError('owned unprivileged QEMU needs vng and writable /dev/kvm')
    harness = check_harness_versions(vng)
    config = {key: str(getattr(args, key).resolve(strict=True)) for key in ('binary', 'object', 'bridge', 'profile')}
    config['shim'] = str((ROOT / 'build/shim/capture_faults.so').resolve(strict=True))
    if digest(config['binary']) != args.binary_sha256:
        raise ValueError('candidate executable hash mismatch')
    locked_kernel_sha, locked_modules_sha = locked_row_pins(args.expected_release)
    if args.expected_kernel_sha256 != locked_kernel_sha:
        raise ValueError('supplied kernel pin differs from the locked row')
    if args.expected_modules_sha256 != locked_modules_sha:
        raise ValueError('supplied modules pin differs from the locked row')
    kernel, kernel_sha, modules_sha, modules_files = verify_boot_inputs(
        args.kernel, args.modules, args.expected_release,
        args.expected_kernel_sha256, args.expected_modules_sha256)
    inputs = {key: digest(path) for key, path in config.items()}
    config['kernel_config'] = str(args.kernel_config.resolve(strict=True))
    config_sha = digest(config['kernel_config'])
    config['expected_release'] = args.expected_release
    config['expected_modules_sha256'] = args.expected_modules_sha256
    config['expected_btf_sha256'] = args.expected_btf_sha256
    args.out = args.out.parent.resolve(strict=True) / args.out.name
    if any(c.isspace() or c == ',' for c in str(args.out)):
        raise ValueError('evidence path contains ambiguous QEMU separators')
    check_shell_inert_path(args.out, 'evidence path')
    if shutil.disk_usage(args.out.parent).free < 2 * 1024**3:
        raise ValueError('insufficient host space for bounded owned images')
    args.out.mkdir(mode=0o700)
    owned = args.out.stat()
    args.owned_out_ids = (owned.st_dev, owned.st_ino)
    config_path = args.out / 'config.json'
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    identity = dict(inputs=inputs, harness=harness, kernel_sha256=kernel_sha, expected_release=args.expected_release,
                    modules_manifest_sha256=modules_sha, modules_files=modules_files,
                    expected_btf_sha256=args.expected_btf_sha256,
                    config_absent_approved=args.expected_release == APPROVED_CONFIG_ABSENT_RELEASE,
                    publisher_config=dict(sha256=config_sha, provenance='publisher-supplied kernel build config; '
                                           'matched against the guest only when the guest exposes /proc/config.gz, '
                                           'otherwise recorded here and never merged into a config-absent claim'),
                    source=subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip())
    (args.out / 'identity.json').write_text(json.dumps(identity, indent=2) + '\n')
    lock_path = ROOT / 'build/vm/suite.lock'
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open('a+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        verified_config = {}
        for scenario in SCENARIOS:
            case = args.out / scenario
            case.mkdir(mode=0o700)
            export = case / 'export'
            export.mkdir(mode=0o700)
            disk = case / 'owned-ext4.img'
            with disk.open('xb') as image:
                image.truncate(128 * 1048576)
            nonce = uuid.uuid4().hex[:OWNERSHIP_NONCE_LENGTH]
            if scenario == 'checkpoint':
                from capture_durability_operator import write_plan
                write_plan(case, nonce)
            with tempfile.TemporaryDirectory(prefix='mvfs-qmp-') as sockets:
                qmp = Path(sockets) / 'monitor'
                check_shell_inert_path(qmp, 'QMP socket path')
                kernel, _, _, _ = verify_boot_inputs(
                    args.kernel, args.modules, args.expected_release,
                    args.expected_kernel_sha256, args.expected_modules_sha256)
                child = boot(vng, config_path, kernel, scenario, nonce, disk, export, qmp, 'capture', case)
                try:
                    if scenario in ('readiness', 'checkpoint'):
                        barrier = export / 'barrier.json'
                        deadline = time.monotonic() + 120
                        while not barrier.exists():
                            if child.poll() is not None:
                                raise ValueError('guest exited before durable barrier')
                            if time.monotonic() >= deadline:
                                raise ValueError('guest durable barrier timeout')
                            time.sleep(.05)
                        promised = json.loads(barrier.read_text())
                        validate_barrier(promised, nonce, scenario, inputs)
                        if promised['identity'].get('kernel') != args.expected_release:
                            raise ValueError('guest kernel release differs from expected release')
                        check_bound_config(promised['identity'], config_sha, args.expected_release,
                                           ('guest kernel config differs from supplied config',
                                            'guest kernel config absent on an unapproved row',
                                            'guest absent config claim carries a config hash',
                                            'guest kernel config status unknown'))
                        if promised['identity'].get('btf_sha256') != args.expected_btf_sha256:
                            raise ValueError('guest live BTF differs from pinned BTF')
                        if promised['identity'].get('modules_manifest_sha256') != args.expected_modules_sha256:
                            raise ValueError('guest modules manifest differs from bound modules')
                        if scenario == 'checkpoint':
                            operator_checkpoint_capture(case, export, nonce)
                        qmp_disk(qmp, disk)
                        stop_owned(child)
                        (case / 'power-cut.json').write_text(json.dumps(dict(
                            method='SIGKILL owned QEMU process group', nonce=nonce,
                            qmp_verified_disk=str(disk), process_exit=child.returncode,
                            barrier_sha256=digest(barrier))) + '\n')
                        if qmp.exists():
                            qmp.unlink()
                        kernel, _, _, _ = verify_boot_inputs(
                            args.kernel, args.modules, args.expected_release,
                            args.expected_kernel_sha256, args.expected_modules_sha256)
                        child = boot(vng, config_path, kernel, scenario, nonce, disk, export, qmp, 'recover', case)
                    child.wait(timeout=150)
                    if child.returncode != 0:
                        raise ValueError('guest failure, exit ' + str(child.returncode))
                    result = json.loads((export / 'result.json').read_text())
                    if result.get('status') != 'PASS' or result.get('nonce') != nonce or result.get('scenario') != scenario:
                        raise ValueError('guest result is missing or has wrong ownership')
                    if result['identity'].get('kernel') != args.expected_release:
                        raise ValueError('result kernel release identity drift')
                    check_bound_config(result['identity'], config_sha, args.expected_release,
                                       ('result kernel config identity drift',
                                        'result kernel config absent on an unapproved row',
                                        'result absent config claim carries a config hash',
                                        'result kernel config status unknown'))
                    if result['identity'].get('btf_sha256') != args.expected_btf_sha256:
                        raise ValueError('result live BTF identity drift')
                    if result['identity'].get('modules_manifest_sha256') != args.expected_modules_sha256:
                        raise ValueError('result modules identity drift')
                    if result['identity']['inputs'] != inputs:
                        raise ValueError('result candidate identity drift')
                    if scenario == 'checkpoint':
                        promised = json.loads((export / 'barrier.json').read_text())
                        operator_checkpoint_recover(case, export, promised)
                    verified_config[scenario] = result['identity']['config_status']
                    (case / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                finally:
                    stop_owned(child)
    aggregate = dict(identity, config_status_by_scenario=verified_config)
    (args.out / 'result.json').write_text(json.dumps(dict(status='PASS', scenarios=list(SCENARIOS), identity=aggregate), indent=2) + '\n')


def retain_owned_failure(path, identity, reason):
    if identity is None:
        return
    directory = -1
    try:
        directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        actual = os.fstat(directory)
        if (actual.st_dev, actual.st_ino) != identity:
            raise ValueError('evidence directory was replaced')
        fd = os.open('failure.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(dict(status='FAIL', reason=reason)) + '\n')
    except (OSError, ValueError) as exc:
        print('capture-durability: failure evidence not replaced: ' + str(exc), file=sys.stderr)
    finally:
        if directory >= 0:
            os.close(directory)


def main():
    if os.environ.get('MEMVEIL_VM_CAPTURE_FAILURES') != '1':
        print('capture-durability: SKIP: needs MEMVEIL_VM_CAPTURE_FAILURES=1 and owned guest inputs')
        return 77
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'object', 'bridge', 'profile', 'kernel', 'kernel-config', 'modules', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--expected-release', required=True)
    parser.add_argument('--expected-kernel-sha256', required=True)
    parser.add_argument('--expected-modules-sha256', required=True)
    parser.add_argument('--expected-btf-sha256', required=True)
    args = parser.parse_args()
    args.owned_out_ids = None
    try:
        execute(args)
    except Exception as exc:
        print('capture-durability: FAIL: ' + str(exc), file=sys.stderr)
        retain_owned_failure(args.out, args.owned_out_ids, str(exc))
        return 1
    print('capture-durability: PASS: ext4 physical fullness and hard-power-cut/remount')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
