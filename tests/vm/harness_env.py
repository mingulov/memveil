# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared exact VM and oracle tool identities; no installation or boot."""
import json
import subprocess
from pathlib import Path


def check_harness_versions(vng):
    here = Path(__file__).parent
    lock = json.loads((here / 'harness.lock.json').read_text())
    lock.update(json.loads((here / 'kernels.lock.json').read_text())['tools'])
    observed = {}
    commands = (('vng', [vng, '--version']),
                ('qemu', ['qemu-system-x86_64', '--version']),
                ('bpftrace', ['bpftrace', '--version']),
                ('bpftool', ['bpftool', '--version']))
    for name, cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError('VM harness identity unreadable: ' + name) from exc
        line = proc.stdout.splitlines()[0] if proc.stdout else ''
        # QEMU may append its packaging attribution after the exact generation.
        if proc.returncode or not (line == lock[name] or
                name == 'qemu' and line.startswith(lock[name] + ' (')):
            raise ValueError('VM harness identity drift: ' + name + ' ' + repr(line))
        observed[name] = line
    return observed
