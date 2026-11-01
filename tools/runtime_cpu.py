#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify the engine's required CPU declaration before staging or execution."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

CONTRACT = {'code_generation': 'x86-64-v2', 'runtime_required': 'x86-64-v3',
            'enforcement': 'gnu-property-x86-isa-needed'}


def mapped_isa(path):
    """Read the property reached through the ELF loader's program headers."""
    def invalid():
        raise ValueError('engine CPU ISA property is not validly mapped')
    with open(path, 'rb') as stream:
        length = os.fstat(stream.fileno()).st_size
        def read_at(offset, size):
            if offset < 0 or size < 0 or offset + size > length:
                invalid()
            stream.seek(offset)
            data = stream.read(size)
            if len(data) != size:
                invalid()
            return data
        header = read_at(0, 64)
        if (header[:7] != b'\x7fELF\x02\x01\x01' or
                struct.unpack_from('<H', header, 16)[0] not in (2, 3) or
                struct.unpack_from('<H', header, 18)[0] != 62):
            invalid()
        offset = struct.unpack_from('<Q', header, 32)[0]
        width, count = struct.unpack_from('<HH', header, 54)
        if width != 56 or not 0 < count <= 128:
            invalid()
        headers = [struct.unpack('<IIQQQQQQ', read_at(offset + i * width, width))
                   for i in range(count)]
        properties = [entry for entry in headers if entry[0] == 0x6474e553]
        if len(properties) != 1:
            invalid()
        prop = properties[0]
        # Main-executable loaders visit note headers backwards. Require the
        # canonical property to be visited first, and validate its full memory
        # extent rather than leaving a trailing note outside the checked bytes.
        if any(entry[0] == 4 for entry in headers[headers.index(prop) + 1:]):
            invalid()
        if (not 16 <= prop[5] <= 65536 or prop[6] != prop[5] or prop[7] != 8 or
                not any(load[0] == 1 and load[1] & 4 and
                        load[2] <= prop[2] and prop[2] + prop[5] <= load[2] + load[5] and
                        prop[3] == load[3] + prop[2] - load[2] and
                        prop[3] + prop[6] <= load[3] + load[6] for load in headers)):
            invalid()
        note = read_at(prop[2], prop[5])
    namesize, descsize, kind = struct.unpack_from('<III', note)
    if (namesize != 4 or kind != 5 or note[12:16] != b'GNU\0' or
            descsize % 8 or len(note) != 16 + descsize):
        invalid()
    cursor = 16
    needed = []
    previous = -1
    while cursor < len(note):
        if cursor + 8 > len(note):
            invalid()
        kind, size = struct.unpack_from('<II', note, cursor)
        # The loader stops scanning on out-of-order types and abandons an
        # ill-formed recognized property, even if readelf displays a later ISA.
        if kind <= previous or (kind in (0xb0008000, 0xc0000002, 0xc0008002)
                                and size != 4):
            invalid()
        previous = kind
        start = cursor + 8
        cursor = (start + size + 7) & ~7
        if cursor > len(note):
            invalid()
        if kind == 0xc0008002:
            if size != 4:
                invalid()
            needed.append(struct.unpack_from('<I', note, start)[0])
    if len(needed) != 1 or not needed[0] & 4 or needed[0] & ~7:
        invalid()


def verify_engine(path):
    try:
        mapped_isa(path)
    except OSError as error:
        raise ValueError('CPU ISA inspection failed: ' + str(error)) from error
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
