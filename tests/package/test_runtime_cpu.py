# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject engines whose loadable ISA declaration cannot protect startup."""
from pathlib import Path
import struct
import subprocess
import sys
import json
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


def engine(tmp_path, level):
    source = tmp_path / 'probe.c'
    source.write_text('int main(void) { return 0; }\n')
    output = tmp_path / 'probe'
    flags = [] if level == 'baseline' else ['-Wl,-z,x86-64-' + level]
    subprocess.run(['cc', '-march=x86-64', *flags, str(source), '-o', str(output)],
                   check=True, capture_output=True)
    return output


@pytest.mark.parametrize('level', ['baseline', 'v2', 'v3', 'v4'])
def test_actual_linked_isa_requirement(tmp_path, level):
    import runtime_cpu
    path = engine(tmp_path, level)
    if level == 'v3':
        runtime_cpu.verify_engine(path)
    else:
        with pytest.raises(ValueError, match='ISA'):
            runtime_cpu.verify_engine(path)


def test_nonloadable_note_refuses(tmp_path):
    import runtime_cpu
    path = engine(tmp_path, 'v3')
    data = bytearray(path.read_bytes())
    offset = struct.unpack_from('<Q', data, 32)[0]
    width, count = struct.unpack_from('<HH', data, 54)
    changed = False
    for i in range(count):
        at = offset + i * width
        if struct.unpack_from('<I', data, at)[0] == 0x6474e553:
            struct.pack_into('<I', data, at, 0)
            changed = True
    assert changed, 'setup: compiler did not emit the property program header'
    path.write_bytes(data)
    with pytest.raises(ValueError, match='ISA'):
        runtime_cpu.verify_engine(path)


@pytest.mark.parametrize('damage', ['redirected', 'unmapped', 'empty'])
def test_property_header_must_map_the_actual_isa_note(tmp_path, damage):
    import runtime_cpu
    path = engine(tmp_path, 'v3')
    data = bytearray(path.read_bytes())
    offset = struct.unpack_from('<Q', data, 32)[0]
    width, count = struct.unpack_from('<HH', data, 54)
    for i in range(count):
        at = offset + i * width
        if struct.unpack_from('<I', data, at)[0] != 0x6474e553:
            continue
        if damage == 'redirected':
            for field in (8, 16):
                value = struct.unpack_from('<Q', data, at + field)[0]
                struct.pack_into('<Q', data, at + field, value + 8)
        elif damage == 'unmapped':
            struct.pack_into('<Q', data, at + 16, 0)
        else:
            struct.pack_into('<Q', data, at + 32, 0)
        break
    else:
        pytest.fail('setup: missing property header')
    path.write_bytes(data)
    with pytest.raises(ValueError, match='ISA'):
        runtime_cpu.verify_engine(path)


def test_missing_inspection_tool_refuses(tmp_path, monkeypatch):
    import runtime_cpu
    path = engine(tmp_path, 'v3')
    monkeypatch.setenv('PATH', str(tmp_path))
    with pytest.raises(ValueError, match='readelf'):
        runtime_cpu.verify_engine(path)


def test_non_elf_engine_refuses(tmp_path):
    import runtime_cpu
    path = tmp_path / 'invalid'
    path.write_text('not an ELF executable')
    with pytest.raises(ValueError, match='ISA'):
        runtime_cpu.verify_engine(path)


@pytest.mark.parametrize('level,claimed', [('baseline', 'x86-64-v3'),
    ('v3', 'x86-64-v2'), ('v3', 'x86-64-v3')])
def test_bundle_requires_matching_cpu_metadata_and_actual_note(tmp_path, level, claimed):
    import canonical_runtime
    import runtime_cpu
    root = tmp_path / 'bundle'
    for name in ('bin', 'lib/memveil', 'bpf', 'profiles'):
        (root / name).mkdir(parents=True)
    shutil.copy2(engine(tmp_path, level), root / 'bin/memveil')
    entries = canonical_runtime.inventory(root)
    manifest = {'canonical_runtime': {'format': canonical_runtime.FORMAT,
                'cpu': dict(runtime_cpu.CONTRACT, runtime_required=claimed),
                'entries': entries},
                'files': {entry['path']: entry['sha256'] for entry in entries}}
    (root / 'MANIFEST.json').write_text(json.dumps(manifest))
    if level == 'v3' and claimed == 'x86-64-v3':
        canonical_runtime.verify_bundle(root)
    else:
        with pytest.raises(ValueError):
            canonical_runtime.verify_bundle(root)


@pytest.mark.parametrize('damage', ['order', 'feature_size', 'needed_size', 'duplicate'])
def test_preceding_property_cannot_disable_loader_isa_check(tmp_path, damage):
    import runtime_cpu
    source = tmp_path / 'property.c'
    source.write_text('int main(void) { return 0; }\n')
    path = tmp_path / 'property'
    subprocess.run(['cc', '-march=x86-64', '-Wl,-z,x86-64-v3', '-Wl,-z,ibt',
                    str(source), '-o', str(path)], check=True, capture_output=True)
    runtime_cpu.verify_engine(path)
    data = bytearray(path.read_bytes())
    offset = struct.unpack_from('<Q', data, 32)[0]
    width, count = struct.unpack_from('<HH', data, 54)
    for i in range(count):
        at = offset + i * width
        if struct.unpack_from('<I', data, at)[0] == 0x6474e553:
            note = struct.unpack_from('<Q', data, at + 8)[0]
            break
    else:
        pytest.fail('setup: missing property header')
    assert struct.unpack_from('<II', data, note + 16) == (0xc0000002, 4)
    assert struct.unpack_from('<I', data, note + 32)[0] == 0xc0008002
    if damage == 'order':
        struct.pack_into('<I', data, note + 16, 0xc0010000)
    elif damage == 'feature_size':
        struct.pack_into('<I', data, note + 20, 8)
    elif damage == 'needed_size':
        struct.pack_into('<II', data, note + 16, 0xb0008000, 8)
    else:
        struct.pack_into('<I', data, note + 16, 0xc0008002)
    path.write_bytes(data)
    with pytest.raises(ValueError, match='ISA'):
        runtime_cpu.verify_engine(path)


@pytest.mark.parametrize('damage', ['memory_extent', 'note_precedence'])
def test_loader_reads_only_the_verified_property_segment(tmp_path, damage):
    import runtime_cpu
    path = engine(tmp_path, 'v3')
    data = bytearray(path.read_bytes())
    offset = struct.unpack_from('<Q', data, 32)[0]
    width, count = struct.unpack_from('<HH', data, 54)
    property_at = next(offset + i * width for i in range(count)
                       if struct.unpack_from('<I', data, offset + i * width)[0] == 0x6474e553)
    if damage == 'memory_extent':
        size = struct.unpack_from('<Q', data, property_at + 40)[0]
        struct.pack_into('<Q', data, property_at + 40, size + 8)
    else:
        note_at = next(offset + i * width for i in range(count)
                       if struct.unpack_from('<I', data, offset + i * width)[0] == 4)
        prop = bytes(data[property_at:property_at + width])
        data[property_at:property_at + width] = data[note_at:note_at + width]
        data[note_at:note_at + width] = prop
    path.write_bytes(data)
    with pytest.raises(ValueError, match='ISA'):
        runtime_cpu.verify_engine(path)
