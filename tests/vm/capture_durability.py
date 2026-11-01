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


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


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
    kernel = args.kernel.resolve(strict=True)
    inputs = {key: digest(path) for key, path in config.items()}
    config['kernel_config'] = str(args.kernel_config.resolve(strict=True))
    config_sha = digest(config['kernel_config'])
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
    identity = dict(inputs=inputs, harness=harness, kernel_sha256=digest(kernel), kernel_config_sha256=config_sha,
                    source=subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip())
    (args.out / 'identity.json').write_text(json.dumps(identity, indent=2) + '\n')
    lock_path = ROOT / 'build/vm/suite.lock'
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open('a+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for scenario in SCENARIOS:
            case = args.out / scenario
            case.mkdir(mode=0o700)
            export = case / 'export'
            export.mkdir(mode=0o700)
            disk = case / 'owned-ext4.img'
            with disk.open('xb') as image:
                image.truncate(128 * 1048576)
            nonce = uuid.uuid4().hex
            with tempfile.TemporaryDirectory(prefix='mvfs-qmp-') as sockets:
                qmp = Path(sockets) / 'monitor'
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
                        if promised['identity'].get('kernel_config_sha256') != config_sha:
                            raise ValueError('guest kernel config differs from supplied config')
                        qmp_disk(qmp, disk)
                        stop_owned(child)
                        (case / 'power-cut.json').write_text(json.dumps(dict(
                            method='SIGKILL owned QEMU process group', nonce=nonce,
                            qmp_verified_disk=str(disk), process_exit=child.returncode,
                            barrier_sha256=digest(barrier))) + '\n')
                        if qmp.exists():
                            qmp.unlink()
                        child = boot(vng, config_path, kernel, scenario, nonce, disk, export, qmp, 'recover', case)
                    child.wait(timeout=150)
                    if child.returncode != 0:
                        raise ValueError('guest failure, exit ' + str(child.returncode))
                    result = json.loads((export / 'result.json').read_text())
                    if result.get('status') != 'PASS' or result.get('nonce') != nonce or result.get('scenario') != scenario:
                        raise ValueError('guest result is missing or has wrong ownership')
                    if result['identity'].get('kernel_config_sha256') != config_sha:
                        raise ValueError('result kernel config identity drift')
                    if result['identity']['inputs'] != inputs:
                        raise ValueError('result candidate identity drift')
                    (case / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                finally:
                    stop_owned(child)
    (args.out / 'result.json').write_text(json.dumps(dict(status='PASS', scenarios=list(SCENARIOS), identity=identity), indent=2) + '\n')


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
    for name in ('binary', 'object', 'bridge', 'profile', 'kernel', 'kernel-config', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
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
