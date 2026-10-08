# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared exact VM tool identities; no installation or runner provisioning."""
import json
import subprocess
from pathlib import Path


def check_harness_versions(vng):
    lock=json.loads((Path(__file__).parent/'harness.lock.json').read_text())
    observed={}
    for name, cmd in (('vng',[vng,'--version']),('qemu',['qemu-system-x86_64','--version'])):
        proc=subprocess.run(cmd,capture_output=True,text=True,timeout=10)
        line=proc.stdout.splitlines()[0] if proc.stdout else ''
        # QEMU may append its packaging attribution after the exact generation.
        if proc.returncode or not (line == lock[name] or
                name == 'qemu' and line.startswith(lock[name]+' (')):
            raise ValueError('VM harness identity drift: '+name+' '+repr(line))
        observed[name]=line
    return observed
