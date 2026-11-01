#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned ext4 guest flow. Refuses host execution before any disk mutation."""
import errno
import gzip
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/cli'))
sys.path.insert(0, str(ROOT / 'tests/fuzz'))
from test_checkpoint_writer import independent
from report_oracle import accepted_report


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


def owned_device(nonce):
    if len(nonce) != 32 or any(c not in '0123456789abcdef' for c in nonce):
        raise ValueError('invalid ownership nonce')
    if os.geteuid() != 0 or 'memveil_fs_gate=' + nonce not in Path('/proc/cmdline').read_text().split():
        raise ValueError('owned guest command-line barrier absent')
    matches = []
    for entry in Path('/sys/block').glob('vd*'):
        serial = entry / 'serial'
        if serial.exists() and serial.read_text().strip() == nonce:
            matches.append('/dev/' + entry.name)
    if len(matches) != 1:
        raise ValueError('expected exactly one owned virtio disk')
    device = matches[0]
    if any(line.split()[0] == device for line in Path('/proc/mounts').read_text().splitlines()):
        raise ValueError('owned disk was already mounted')
    return device


def emit(path, doc):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(doc, sort_keys=True) + '\n')
    temp.replace(path)


def identity(config):
    observed = hashlib.sha256(gzip.decompress(Path('/proc/config.gz').read_bytes())).hexdigest()
    if observed != digest(config['kernel_config']):
        raise ValueError('booted kernel config differs from supplied config')
    return dict(kernel_config_sha256=observed, kernel=os.uname().release,
                boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                btf_sha256=digest('/sys/kernel/btf/vmlinux'),
                inputs={key: digest(config[key]) for key in ('binary', 'object', 'bridge', 'profile', 'shim')})


def wait_marker(child, marker, deadline):
    while time.monotonic() < deadline:
        if marker.exists():
            state = Path('/proc') / str(child.pid) / 'status'
            if state.exists() and '\nState:\tT' in state.read_text():
                return
        if child.poll() is not None:
            raise ValueError('collector exited before durable boundary: ' + str(child.returncode))
        time.sleep(.02)
    raise ValueError('durable checkpoint boundary not reached')


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    phase, scenario, nonce = sys.argv[2:5]
    device = owned_device(nonce)
    export = Path('/tmp/export')
    mount = Path('/tmp/memveil-owned-ext4')
    mount.mkdir(mode=0o700)
    if phase == 'capture':
        run(['mkfs.ext4', '-F', '-q', '-m', '0', '-N', '2048', '-L', 'memveil-owned', device])
    elif phase != 'recover':
        raise ValueError('unknown phase')
    uuid = run(['blkid', '-s', 'UUID', '-o', 'value', device]).stdout.strip()
    run(['mount', '-t', 'ext4', '-o', 'data=ordered', device, str(mount)])
    capture = mount / 'capture'
    ident = identity(config)
    child = None
    try:
        mounts = [line.split() for line in Path('/proc/mounts').read_text().splitlines()]
        if not any(row[0] == device and row[1] == str(mount) and row[2] == 'ext4' for row in mounts):
            raise ValueError('ext4 mount identity not established')
        if phase == 'recover':
            promised = json.loads((export / 'barrier.json').read_text())
            if promised['nonce'] != nonce or promised['fs_uuid'] != uuid:
                raise ValueError('recovery disk identity changed')
            if promised['identity']['boot_id'] == ident['boot_id']:
                raise ValueError('power loss requires a fresh kernel boot')
            if promised['identity']['inputs'] != ident['inputs'] or promised['identity']['btf_sha256'] != ident['btf_sha256'] or promised['identity']['kernel_config_sha256'] != ident['kernel_config_sha256']:
                raise ValueError('candidate or guest identity changed across power cut')
            doc = independent(capture)
            if doc['capture']['integrity'] != promised['integrity']:
                raise ValueError('durable prefix changed across remount')
            proc = subprocess.run([config['binary'], 'report', '--format', 'json', '--allow-partial', str(capture)], capture_output=True)
            accepted_report(capture, proc.stdout, proc.returncode, allow_partial=True)
            if proc.returncode != 4 or (capture / 'session.json').exists():
                raise ValueError('power-cut recovery was not an unfinalized prefix')
            emit(export / 'result.json', dict(status='PASS', scenario=scenario, nonce=nonce,
                 fs_uuid=uuid, identity=ident, product_exit=proc.returncode,
                 integrity=doc['capture']['integrity'], report_sha256=hashlib.sha256(proc.stdout).hexdigest()))
            return
        mode = 'checkpoint-2' if scenario == 'checkpoint' else 'none'
        marker = export / 'reached'
        env = dict(os.environ, LD_PRELOAD=config['shim'], MV_CAPTURE_FAULT=mode, MV_FAULT_MARKER=str(marker))
        env.pop('MEMVEIL_TEST_NO_BPF', None)
        argv = [config['binary'], 'record', '--output', str(capture), '--duration', '60',
                '--object', config['object'], '--bridge', config['bridge'], '--profile', config['profile']]
        with (export / 'record.stderr').open('wb') as err:
            child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=err, env=env)
            if scenario in ('readiness', 'checkpoint'):
                if scenario == 'readiness':
                    if not select.select([child.stdout], [], [], 30)[0]:
                        raise ValueError('collector readiness absent')
                    if not child.stdout.readline().startswith(b'ready session='):
                        raise ValueError('collector refused before readiness')
                    child.send_signal(signal.SIGSTOP)
                    marker.write_text('readiness-announced')
                wait_marker(child, marker, time.monotonic() + 30)
                doc = independent(capture)
                extent = int(doc['capture']['integrity']['line_count'])
                if scenario == 'readiness' and extent != 0 or scenario == 'checkpoint' and extent == 0:
                    raise ValueError('wrong durable-prefix boundary')
                reserve = (capture / '.finalization-reserve').stat()
                if reserve.st_blocks * 512 < 17 * 1048576:
                    raise ValueError('readiness reserve is not physically allocated')
                emit(export / 'barrier.json', dict(nonce=nonce, scenario=scenario,
                    fs_uuid=uuid, identity=ident, stopped=True, ready_observed=scenario == 'readiness', marker=marker.read_text(),
                    integrity=doc['capture']['integrity'], reserve_allocated=reserve.st_blocks * 512))
                while True:
                    time.sleep(1)
            if scenario not in ('bytes-full', 'inodes-full'):
                raise ValueError('unknown failure scenario')
            if not select.select([child.stdout], [], [], 30)[0]:
                raise ValueError('collector readiness absent')
            ready = child.stdout.readline()
            if not ready.startswith(b'ready session='):
                raise ValueError('collector refused before readiness')
            before = independent(capture)
            filler = mount / 'filler'
            filler.mkdir()
            files, filled = 0, 0
            try:
                if scenario == 'bytes-full':
                    with (filler / 'bytes').open('wb', buffering=0) as stream:
                        while filled <= 128 * 1048576:
                            filled += stream.write(b'\0' * 65536)
                    raise ValueError('bounded disk did not fill')
                while files <= 4096:
                    (filler / str(files)).touch(exist_ok=False)
                    files += 1
                raise ValueError('bounded inode table did not fill')
            except OSError as exc:
                if exc.errno != errno.ENOSPC:
                    raise
            state = os.statvfs(mount)
            if scenario == 'inodes-full' and state.f_favail != 0:
                raise ValueError('inode exhaustion boundary absent')
            child.send_signal(signal.SIGHUP)
            child.communicate(timeout=30)
            if child.returncode != 0:
                raise ValueError('full-filesystem finalization failed: ' + str(child.returncode))
            final = independent(capture)
            if not final['capture']['finalized'] or (capture / 'checkpoint.json').exists():
                raise ValueError('full-filesystem capture did not finalize durably')
            proc = subprocess.run([config['binary'], 'report', '--format', 'json', str(capture)], capture_output=True)
            accepted_report(capture, proc.stdout, proc.returncode)
            emit(export / 'result.json', dict(status='PASS', scenario=scenario, nonce=nonce,
                 fs_uuid=uuid, identity=ident, product_exit=child.returncode, replay_exit=proc.returncode,
                 reached_errno='ENOSPC', filler_bytes=filled, filler_files=files,
                 free_blocks=state.f_bavail, free_inodes=state.f_favail,
                 readiness_integrity=before['capture']['integrity'], integrity=final['capture']['integrity']))
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
        run(['umount', str(mount)])


if __name__ == '__main__':
    main()
