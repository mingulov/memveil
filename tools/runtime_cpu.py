#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify the engine's required CPU declaration before staging or execution."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

CONTRACT = {'code_generation': 'x86-64-v2', 'runtime_required': 'x86-64-v3',
            'enforcement': 'gnu-property-x86-isa-needed'}


def verify_engine(path):
    try:
        result = subprocess.run(['readelf', '--program-headers', '--notes', str(path)],
                                capture_output=True, text=True, env=dict(os.environ, LC_ALL='C'))
    except OSError as error:
        raise ValueError('CPU ISA inspection requires readelf: ' + str(error)) from error
    levels = re.findall(r'^\s*(?:Properties:\s*)?x86 ISA needed:\s*(.+)$', result.stdout, re.M)
    if (result.returncode != 0 or
            re.search(r'^\s*GNU_PROPERTY\s', result.stdout, re.M) is None or
            len(levels) != 1):
        raise ValueError('engine lacks a loadable CPU ISA requirement')
    needed = set(levels[0].split(', '))
    if ('x86-64-v3' not in needed or
            not needed <= {'x86-64-baseline', 'x86-64-v2', 'x86-64-v3'}):
        raise ValueError('engine CPU ISA requirement must be x86-64-v3')


def verifier_identity():
    path = shutil.which('readelf')
    if path is None:
        raise ValueError('CPU ISA inspection requires readelf')
    version = subprocess.check_output([path, '--version'], text=True).splitlines()[0]
    return {'version': version, 'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest()}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: runtime_cpu.py ENGINE')
    try:
        verify_engine(sys.argv[1])
    except ValueError as error:
        sys.exit('runtime-cpu: ' + str(error))
    print('runtime-cpu: loadable x86-64-v3 requirement verified')
