# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic artifact selection does not qualify a runtime."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))


def api():
    assert importlib.util.find_spec('support.candidate_input'), 'candidate input loader missing'
    from support import candidate_input
    return candidate_input


def test_development_binary_stays_explicit(tmp_path):
    assert api().binary(tmp_path / 'development', env={}) == str(tmp_path / 'development')


@pytest.mark.parametrize('env', [{'MV_BUNDLE_TARBALL': 'a'}, {'MV_CANDIDATE_MANIFEST': 'b'},
                                 {'MV_BUNDLE_TARBALL': '', 'MV_CANDIDATE_MANIFEST': ''}])
def test_partial_or_empty_inputs_refuse_before_execution(env):
    with pytest.raises(ValueError, match='both'):
        api().load(env=env)


@pytest.mark.parametrize('key', ['MEMVEIL_BIN', 'MV_DEB', 'MV_RPM', 'MV_KERNELS_BUNDLE',
                                'LMB_NATIVE_LIB', 'LD_PRELOAD', 'LD_LIBRARY_PATH',
                                'MEMVEIL_TEST_NO_BPF', 'LMB_SANITIZE', 'MV_CANDIDATE_ROOT'])
def test_overrides_refused_before_reading_inputs(key):
    with pytest.raises(ValueError, match='override'):
        api().load(env={'MV_BUNDLE_TARBALL': 'absent', 'MV_CANDIDATE_MANIFEST': 'absent', key: 'foreign'})


@pytest.fixture
def sealed(tmp_path):
    import json
    import tarfile
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate
    root = tmp_path / 'synthetic'
    (root / 'bin').mkdir(parents=True)
    source = tmp_path / 'probe.c'
    source.write_text('#include <stdio.h>\nint main(void){puts("packaged-synthetic");return 0;}\n')
    subprocess.run(['cc', '-Wl,-z,x86-64-v3', str(source), '-o', str(root / 'bin/memveil')], check=True)
    for name in ('lib/memveil/libx.so.1', 'bpf/probe.bpf.o', 'profiles/test.json', 'LICENSE'):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('synthetic\n')
    rt = {'format': 'memveil-runtime/1', 'cpu': candidate.runtime.runtime_cpu.CONTRACT,
          'entries': candidate.runtime.inventory(root)}
    files = {p.relative_to(root).as_posix(): candidate.runtime.digest(p) for p in root.rglob('*') if p.is_file()}
    bm = {'canonical_runtime': rt, 'files': files, 'memveil_revision': 'a' * 40,
          'source_inventory_digest': 'b' * 64, 'build_receipt_sha256': 'c' * 64}
    (root / 'MANIFEST.json').write_bytes(candidate.canonical(bm))
    archive = tmp_path / 'bundle.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        tar.add(root, arcname=root.name)
    artifacts = []
    for role in candidate.ROLES:
        path = archive if role == 'bundle' else tmp_path / (role + '.fixture')
        if role != 'bundle': path.write_text('synthetic artifact\n')
        artifacts.append({'role': role, 'name': path.name, 'size': str(path.stat().st_size),
                          'sha256': candidate.runtime.digest(path)})
    doc = {'schema': candidate.SCHEMA, 'origin': 'local-build',
           'source': {'commit': 'a' * 40, 'tree': 'd' * 40, 'inventory_sha256': 'b' * 64},
           'toolchain': {'lock_sha256': 'e' * 64, 'pixi_lock_sha256': 'f' * 64},
           'build_receipt_sha256': 'c' * 64, 'bundle_manifest_sha256': candidate.runtime.digest(root / 'MANIFEST.json'),
           'policy_sha256': '1' * 64, 'canonical_runtime': rt, 'files': files,
           'artifacts': sorted(artifacts, key=lambda item: item['role'])}
    manifest = tmp_path / 'candidate.json'
    candidate.seal_manifest(doc, manifest)
    return {'MV_BUNDLE_TARBALL': str(archive), 'MV_CANDIDATE_MANIFEST': str(manifest)}


def test_real_loader_selects_packaged_binary_and_cleans_owned_root(sealed, tmp_path):
    selected = api().load(env=sealed)
    owned = selected.root
    wrong = tmp_path / 'development'
    wrong.write_text('#!/bin/sh\necho WRONG\n')
    wrong.chmod(0o755)
    assert selected.bin != wrong
    assert subprocess.check_output([selected.bin], text=True) == 'packaged-synthetic\n'
    assert selected.artifact('deb').name == 'deb.fixture'
    selected.close()
    assert not owned.exists()
    assert wrong.exists()


@pytest.mark.parametrize('damage', ['archive', 'manifest', 'alias', 'extra-elf', 'override'])
def test_real_loader_rejects_damaged_inputs(sealed, tmp_path, damage):
    import json
    import tarfile
    import io
    import candidate
    archive = Path(sealed['MV_BUNDLE_TARBALL'])
    manifest = Path(sealed['MV_CANDIDATE_MANIFEST'])
    if damage == 'archive': archive.write_bytes(archive.read_bytes() + b'tampered')
    if damage == 'manifest': manifest.write_bytes(manifest.read_bytes() + b' ')
    if damage == 'override': sealed['MEMVEIL_BIN'] = str(tmp_path / 'development')
    if damage in ('alias', 'extra-elf'):
        old = tmp_path / 'old.tar.gz'
        archive.rename(old)
        with tarfile.open(old) as src, tarfile.open(archive, 'w:gz') as dst:
            for member in src.getmembers(): dst.addfile(member, src.extractfile(member) if member.isfile() else None)
            entry = tarfile.TarInfo('synthetic/foreign')
            if damage == 'alias': entry.type, entry.linkname = tarfile.SYMTYPE, '/etc/passwd'
            else: entry.size = 4
            dst.addfile(entry, io.BytesIO(b'\x7fELF') if damage == 'extra-elf' else None)
        doc = json.loads(manifest.read_bytes())
        record = candidate.artifact(doc, 'bundle')
        record.update(size=str(archive.stat().st_size), sha256=candidate.runtime.digest(archive))
        manifest.write_bytes(candidate.canonical(doc))
    with pytest.raises((ValueError, OSError)):
        api().load(env=sealed)


def test_conflicting_binary_argument_is_rejected(sealed, monkeypatch):
    for key in api().OVERRIDES:
        monkeypatch.delenv(key, raising=False)
    for key, value in sealed.items(): monkeypatch.setenv(key, value)
    with pytest.raises(ValueError, match='--binary'):
        api().binary('development', explicit='development')
    api()._cached.close()
    api()._cached = None
