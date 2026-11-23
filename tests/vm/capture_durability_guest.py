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
from capture_durability import APPROVED_CONFIG_ABSENT_RELEASE, OWNERSHIP_NONCE_LENGTH
from capture_durability_operator import (
    OPERATOR_VERDICT_NAME, ORACLE_LOG_NAME, judge_verdict, run_workload)
from kernel_matrix import modules_manifest_sha


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


def owned_device(nonce):
    # Exact 20-char shape: the virtio-blk serial survives the guest
    # kernel only up to VIRTIO_BLK_ID_BYTES (20 bytes), so a longer
    # value can never round-trip and a shorter one is not ours.
    if len(nonce) != OWNERSHIP_NONCE_LENGTH or any(c not in '0123456789abcdef' for c in nonce):
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


def load_operator_plan(config_path, scenario, nonce):
    plan = json.loads((Path(config_path).parent / scenario / 'operator-plan.json').read_text())
    if plan.get('nonce') != nonce or plan.get('scenario') != scenario:
        raise ValueError('operator plan ownership drift')
    return plan


def run_operator_workload(mount, export, plan):
    """Run the arranged sweep on the owned disk; record window markers."""
    spec = plan['workload']
    start_ns = time.monotonic_ns()
    observed = run_workload(mount, spec)
    end_ns = time.monotonic_ns()
    rows = [dict(marker='window-start', workload=spec['id'], nonce=plan['nonce'],
                 mono_ns=str(start_ns), seq='0'),
            dict(marker='window-end', workload=spec['id'], nonce=plan['nonce'],
                 mono_ns=str(end_ns), seq='1', bytes_written=str(observed['bytes_written']),
                 bytes_read=str(observed['bytes_read']),
                 workload_sha256=observed['workload_sha256'])]
    Path(export, ORACLE_LOG_NAME).write_text(
        ''.join(json.dumps(row) + '\n' for row in rows))
    return observed


def write_operator_verdict(export, promised, fs_uuid, capture):
    verdict = judge_verdict(promised, fs_uuid, capture)
    Path(export, OPERATOR_VERDICT_NAME).write_text(
        json.dumps(verdict, indent=2, sort_keys=True) + '\n')
    return verdict


def identity(config):
    release = os.uname().release
    if release != config['expected_release']:
        raise ValueError('booted kernel release differs from expected release')
    try:
        link = os.readlink('/lib/modules/' + release)
        mods = link if os.path.isabs(link) else os.path.join('/lib/modules', release, link)
    except OSError:
        mods = '/lib/modules/' + release
    if not os.path.isdir(mods):
        raise ValueError('guest modules dir missing for booted release')
    observed_mods, _ = modules_manifest_sha(mods)
    if observed_mods != config['expected_modules_sha256']:
        raise ValueError('guest modules manifest differs from bound modules')
    try:
        btf = digest('/sys/kernel/btf/vmlinux')
    except OSError:
        raise ValueError('live BTF unreadable')
    if btf != config['expected_btf_sha256']:
        raise ValueError('live BTF differs from pinned BTF')
    try:
        raw = Path('/proc/config.gz').read_bytes()
    except FileNotFoundError:
        if os.path.lexists('/proc/config.gz'):
            raise ValueError('booted kernel config unreadable')
        raw = None
    except OSError:
        raise ValueError('booted kernel config unreadable')
    if raw is None:
        if release != APPROVED_CONFIG_ABSENT_RELEASE:
            raise ValueError('kernel config absent on an unapproved row')
        status, observed = 'absent', None
    else:
        try:
            observed = hashlib.sha256(gzip.decompress(raw)).hexdigest()
        except Exception:
            raise ValueError('booted kernel config unreadable')
        if observed != digest(config['kernel_config']):
            raise ValueError('booted kernel config differs from supplied config')
        status = 'measured'
    return dict(kernel_config_sha256=observed, config_status=status, kernel=release,
                boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                btf_sha256=btf, modules_manifest_sha256=observed_mods,
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


def require_stopped_unfinalized(child, capture):
    state = Path('/proc') / str(child.pid) / 'status'
    if child.poll() is not None or not state.exists() or '\nState:\tT' not in state.read_text():
        raise ValueError('writer is not held at the exhaustion boundary')
    if (capture / 'session.json').exists():
        raise ValueError('writer finalized before exhaustion')
    doc = independent(capture)
    if doc['capture']['finalized'] or not (capture / 'checkpoint.json').is_file():
        raise ValueError('active unfinalized checkpoint absent')
    return doc


def finalize_after_fullness(child, capture, fill):
    """Hold the writer across exhaustion; queue shutdown before releasing it."""
    child.send_signal(signal.SIGSTOP)
    deadline = time.monotonic() + 5
    while True:
        if child.poll() is not None:
            raise ValueError('writer exited before exhaustion')
        state = Path('/proc') / str(child.pid) / 'status'
        if state.exists() and '\nState:\tT' in state.read_text():
            break
        if time.monotonic() >= deadline:
            raise ValueError('writer did not stop before exhaustion')
        time.sleep(.01)
    before = require_stopped_unfinalized(child, capture)
    fullness, filler = fill()
    if fullness.get('reached_errno') != 'ENOSPC' or not filler.is_dir():
        raise ValueError('exhaustion evidence or retained filler absent')
    identity = (filler.stat().st_dev, filler.stat().st_ino)
    if require_stopped_unfinalized(child, capture) != before:
        raise ValueError('checkpoint changed while writer was held')
    # A pending SIGHUP is handled only after the stopped writer resumes.
    # It cannot complete naturally between a liveness check and this signal.
    child.send_signal(signal.SIGHUP)
    child.send_signal(signal.SIGCONT)
    child.communicate(timeout=30)
    if child.returncode != 0:
        raise ValueError('full-filesystem finalization failed: ' + str(child.returncode))
    if not filler.is_dir() or (filler.stat().st_dev, filler.stat().st_ino) != identity:
        raise ValueError('filler disappeared before final publication')
    final = independent(capture)
    if not final['capture']['finalized'] or (capture / 'checkpoint.json').exists():
        raise ValueError('full-filesystem capture did not finalize durably')
    return before, final, fullness


def fill_owned_image(mount, scenario):
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
    return (dict(reached_errno='ENOSPC', filler_bytes=filled, filler_files=files,
                 free_blocks=state.f_bavail, free_inodes=state.f_favail), filler)


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    phase, scenario, nonce = sys.argv[2:5]
    device = owned_device(nonce)
    export = Path('/tmp/export')
    mount = Path('/tmp/memveil-owned-ext4')
    mount.mkdir(mode=0o700)
    ident = identity(config)
    if phase == 'capture':
        run(['mkfs.ext4', '-F', '-q', '-m', '0', '-N', '2048', '-L', 'memveil-owned', device])
    elif phase != 'recover':
        raise ValueError('unknown phase')
    uuid = run(['blkid', '-s', 'UUID', '-o', 'value', device]).stdout.strip()
    run(['mount', '-t', 'ext4', '-o', 'data=ordered', device, str(mount)])
    capture = mount / 'capture'
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
            if promised['identity']['inputs'] != ident['inputs'] or promised['identity']['btf_sha256'] != ident['btf_sha256'] or promised['identity']['kernel_config_sha256'] != ident['kernel_config_sha256'] or promised['identity']['config_status'] != ident['config_status'] or promised['identity']['modules_manifest_sha256'] != ident['modules_manifest_sha256']:
                raise ValueError('candidate or guest identity changed across power cut')
            doc = independent(capture)
            if doc['capture']['integrity'] != promised['integrity']:
                raise ValueError('durable prefix changed across remount')
            proc = subprocess.run([config['binary'], 'report', '--format', 'json', '--allow-partial', str(capture)], capture_output=True)
            accepted_report(capture, proc.stdout, proc.returncode, allow_partial=True)
            if proc.returncode != 4 or (capture / 'session.json').exists():
                raise ValueError('power-cut recovery was not an unfinalized prefix')
            result = dict(status='PASS', scenario=scenario, nonce=nonce,
                 fs_uuid=uuid, identity=ident, product_exit=proc.returncode,
                 integrity=doc['capture']['integrity'], report_sha256=hashlib.sha256(proc.stdout).hexdigest())
            if scenario == 'checkpoint':
                verdict = write_operator_verdict(export, promised, uuid, capture)
                if verdict['status'] != 'PASS':
                    raise ValueError('operator verdict is not PASS')
                result['operator_verdict'] = verdict['status']
            emit(export / 'result.json', result)
            return
        mode = 'checkpoint-2' if scenario == 'checkpoint' else 'none'
        marker = export / 'reached'
        env = dict(os.environ, LD_PRELOAD=config['shim'], MV_CAPTURE_FAULT=mode, MV_FAULT_MARKER=str(marker))
        env.pop('MEMVEIL_TEST_NO_BPF', None)
        argv = [config['binary'], 'record', '--output', str(capture), '--duration', '60',
                '--object', config['object'], '--bridge', config['bridge'], '--profile', config['profile']]
        with (export / 'record.stderr').open('wb') as err:
            child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=err, env=env)
            operator_observed = None
            if scenario == 'checkpoint':
                plan = load_operator_plan(sys.argv[1], scenario, nonce)
                operator_observed = run_operator_workload(mount, export, plan)
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
                barrier = dict(nonce=nonce, scenario=scenario,
                    fs_uuid=uuid, identity=ident, stopped=True, ready_observed=scenario == 'readiness', marker=marker.read_text(),
                    integrity=doc['capture']['integrity'], reserve_allocated=reserve.st_blocks * 512)
                if scenario == 'checkpoint':
                    barrier['operator'] = dict(window=operator_observed,
                        oracle_log_sha256=digest(export / 'oracle.log'))
                emit(export / 'barrier.json', barrier)
                while True:
                    time.sleep(1)
            if scenario not in ('bytes-full', 'inodes-full'):
                raise ValueError('unknown failure scenario')
            if not select.select([child.stdout], [], [], 30)[0]:
                raise ValueError('collector readiness absent')
            ready = child.stdout.readline()
            if not ready.startswith(b'ready session='):
                raise ValueError('collector refused before readiness')
            before, final, fullness = finalize_after_fullness(
                child, capture, lambda: fill_owned_image(mount, scenario))
            proc = subprocess.run([config['binary'], 'report', '--format', 'json', str(capture)], capture_output=True)
            accepted_report(capture, proc.stdout, proc.returncode)
            emit(export / 'result.json', dict(status='PASS', scenario=scenario, nonce=nonce,
                 fs_uuid=uuid, identity=ident, product_exit=child.returncode, replay_exit=proc.returncode,
                 **fullness,
                 readiness_integrity=before['capture']['integrity'], integrity=final['capture']['integrity']))
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
        run(['umount', str(mount)])


if __name__ == '__main__':
    main()
