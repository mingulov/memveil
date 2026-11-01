#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Test-only native ledger validation and armed disposable-guest transport runner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import shlex
import subprocess
import sys
import time

PARAMS = Path('/sys/module/memveil_region_oracle/parameters')
ROW = re.compile(r'epoch=([1-9][0-9]*) ordinal=([12]) direction=(shared|private) pages=([1-9][0-9]*) result=(0|-[1-9][0-9]*|[1-9][0-9]*)')
COUNTERS = {'shared_entry', 'private_entry', 'shared_exit', 'private_exit'}


def native_rows(text, epoch, pages):
    if len(text) > 1024 or not text.endswith('\n'):
        raise ValueError('invalid native ledger framing')
    rows = []
    for i, line in enumerate(text.splitlines(), 1):
        match = ROW.fullmatch(line)
        if not match:
            raise ValueError('invalid native ledger metadata')
        token, ordinal, direction, count, result = match.groups()
        if (int(token) != epoch or int(token) >= 2**64 or int(ordinal) != i
                or direction != ('shared' if i == 1 else 'private')
                or int(count) != pages or not 1 <= pages <= 256
                or not -(2**31) <= int(result) < 2**31):
            raise ValueError('native ledger identity/order mismatch')
        rows.append((direction, count, int(result)))
    return rows


def parse_ledger(text, epoch, pages):
    rows = native_rows(text, epoch, pages)
    if len(rows) != 2 or any(row[2] != 0 for row in rows):
        raise ValueError('native sequence incomplete or failed; no successful gate')
    return rows


def parse_counts(text):
    if len(text) > 65536:
        raise ValueError('counter output exceeded bound')
    counts = {}
    for line in text.splitlines():
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError('invalid tracer document')
        if item.get('type') == 'attached_probes' and item.get('data', {}).get('probes') == 4:
            continue
        if item.get('type') != 'map' or not isinstance(item.get('data'), dict):
            raise ValueError('unexpected tracer output or loss')
        for name, value in item['data'].items():
            key = name.removeprefix('@')
            if name != '@' + key or key not in COUNTERS or key in counts or type(value) is not int or value != 1:
                raise ValueError('missing, duplicate or foreign native count')
            counts[key] = str(value)
    if set(counts) != COUNTERS:
        raise ValueError('incomplete independent counters')
    return counts


def compare_observations(native, observations, caller):
    if not isinstance(observations, list) or len(native) != len(observations):
        raise ValueError('observation count mismatch')
    for wanted, row in zip(native, observations):
        if (not isinstance(row, dict) or set(row) != {'direction', 'pages', 'result', 'caller'}
                or row['caller'] != caller or type(row['result']) is not int
                or (row['direction'], row['pages'], row['result']) != wanted):
            raise ValueError('foreign, ambiguous or mismatched observation')


def digest(path):
    value = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def save_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def guest_guard():
    if os.environ.get('MEMVEIL_OWNED_REGION_GUEST') != '1':
        raise ValueError('requires MEMVEIL_OWNED_REGION_GUEST=1 inside an owned disposable guest')
    if os.geteuid() != 0 or not Path('/sys/kernel/btf/vmlinux').is_file():
        raise ValueError('guest root and readable kernel BTF required')


def command(value):
    with open(PARAMS / 'command', 'w') as stream:
        stream.write(value + '\n')


def worker(args):
    guest_guard()
    if PARAMS.parent.exists():
        raise ValueError('existing module is not owned by this run')
    loaded = False
    cleanup = 'not_loaded'
    ledger = ''
    failure = False
    try:
        subprocess.run(['insmod', str(args.module), 'mv_region_oracle_arm=1',
                        f'mv_region_oracle_pages={args.pages}', f'mv_region_oracle_epoch={args.epoch}'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        loaded = True
        command('share')
        ledger = (PARAMS / 'ledger').read_text()
        if native_rows(ledger, args.epoch, args.pages) != [('shared', str(args.pages), 0)]:
            raise ValueError('retained phase did not reach exactly one successful native request')
        if int((PARAMS.parent / 'refcnt').read_text()) < 1:
            raise ValueError('retained allocation lacks module ownership')
        time.sleep(args.retain_seconds)
        command('restore')
        ledger = (PARAMS / 'ledger').read_text()
        parse_ledger(ledger, args.epoch, args.pages)
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt):
        failure = True
    finally:
        if not loaded and PARAMS.parent.exists():
            cleanup = 'unproved_reboot_required'
            failure = True
        if loaded:
            # Restore only a never-restored retained range; failed restores are terminal.
            try:
                ledger = (PARAMS / 'ledger').read_text()
                rows = native_rows(ledger, args.epoch, args.pages) if ledger else []
                if len(rows) == 1:
                    try:
                        command('restore')
                    except OSError:
                        failure = True
                    ledger = (PARAMS / 'ledger').read_text()
                    rows = native_rows(ledger, args.epoch, args.pages)
                if not rows or (len(rows) == 2 and rows[-1][2] == 0):
                    subprocess.run(['rmmod', 'memveil_region_oracle'], check=True,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                    if PARAMS.parent.exists():
                        raise ValueError('module survived normal removal')
                    cleanup = 'unloaded'
                else:
                    cleanup = 'quarantined_reboot_required'
                    failure = True
            except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt):
                cleanup = 'unproved_reboot_required'
                failure = True
        # Only validated allowlisted rows cross the evidence boundary.
        try:
            rows = native_rows(ledger, args.epoch, args.pages) if ledger else []
        except ValueError:
            rows = []
            failure = True
        save_new(args.output, {'epoch': str(args.epoch), 'pages': str(args.pages),
                              'rows': rows, 'cleanup': cleanup,
                              'retained_seconds': str(args.retain_seconds),
                              'status': 'FAIL' if failure else 'PASS'})
    return 1 if failure else 0


def bpf_program(pages):
    return f'''
kprobe:set_memory_decrypted /pid == cpid && arg1 == {pages}/ {{ @shared_entry = count(); }}
kprobe:set_memory_encrypted /pid == cpid && arg1 == {pages}/ {{ @private_entry = count(); }}
kretprobe:set_memory_decrypted /pid == cpid && retval == 0/ {{ @shared_exit = count(); }}
kretprobe:set_memory_encrypted /pid == cpid && retval == 0/ {{ @private_exit = count(); }}
'''


def transport(args):
    guest_guard()
    if not args.module.is_file() or PARAMS.parent.exists():
        raise ValueError('module missing or an existing module is not owned by this run')
    if not 1 <= args.pages <= 256 or not 3 <= args.cycles <= 10 or not 1 <= args.retain_seconds <= 3:
        raise ValueError('pages/cycles/retention outside bounded test limits')
    # This runner accepts only an ordinary guest; real platform admission is separate.
    flags = Path('/proc/cpuinfo').read_text()
    if any(flag in flags.split() for flag in ('sev', 'sev_snp', 'tdx_guest')):
        raise ValueError('ordinary transport runner refuses confidential CPU capabilities')
    tracer = shutil.which('bpftrace')
    if not tracer:
        raise ValueError('bpftrace missing')
    version = subprocess.run([tracer, '--version'], capture_output=True, text=True, check=True).stdout.strip()
    lock = json.loads((Path(__file__).resolve().parent.parent / 'vm' / 'kernels.lock.json').read_text())
    if version != lock['tools']['bpftrace']:
        raise ValueError('tracer version differs from the repository lock')
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    results = []
    for cycle in range(args.cycles):
        for retained in (0, args.retain_seconds):
            epoch = secrets.randbelow(2**64 - 1) + 1
            target = args.output / f'cycle-{cycle}-{retained}.json'
            child = [sys.executable, str(Path(__file__).resolve()), '--worker', '--module', str(args.module.resolve()),
                     '--output', str(target.resolve()), '--epoch', str(epoch), '--pages', str(args.pages),
                     '--retain-seconds', str(retained)]
            proc = subprocess.run(['bpftrace', '-f', 'json', '-e', bpf_program(args.pages), '-c', shlex.join(child)],
                                  capture_output=True, text=True, timeout=120)
            if proc.returncode or proc.stderr.strip():
                raise ValueError('tracer or worker failed; inspect sanitized worker receipt, reboot if cleanup unproved')
            counts = parse_counts(proc.stdout)
            receipt = json.loads(target.read_text())
            if receipt['status'] != 'PASS' or receipt['cleanup'] != 'unloaded':
                raise ValueError('worker or cleanup did not pass')
            results.append({'epoch': str(epoch), 'retained_seconds': str(retained), 'counts': counts,
                            'receipt_sha256': digest(target), 'receipt': target.name})
    save_new(args.output / 'transport.json', {
        'schema': 'memveil-owned-transport/1', 'status': 'PASS',
        'semantics': 'ordinary_noop_transport_only', 'kernel_release': os.uname().release,
        'btf_sha256': digest('/sys/kernel/btf/vmlinux'), 'module_sha256': digest(args.module),
        'runner_sha256': digest(__file__),
        'oracle_source_sha256': digest(Path(__file__).resolve().parent.parent / 'kernel' / 'memveil_region_oracle.c'), 'pages': str(args.pages), 'cycles': results,
        'bpftrace_version': version, 'bpftrace_sha256': digest(tracer),
        'shared_hook_blind_spot': True, 'state_claim': 'unavailable'})
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--pages', type=int, default=3)
    parser.add_argument('--cycles', type=int, default=3)
    parser.add_argument('--retain-seconds', type=int, default=1)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--epoch', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        return worker(args) if args.worker else transport(args)
    except (OSError, ValueError, subprocess.SubprocessError):
        print('FAIL owned-region: prerequisites, transport or cleanup unproved; preserve sanitized receipts; never force unload', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
