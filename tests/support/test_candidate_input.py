# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic artifact selection does not qualify a runtime."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))


def api():
    assert importlib.util.find_spec(
        'support.candidate_input'), \
        'candidate input loader missing'
    from support import candidate_input
    return candidate_input


def test_development_binary_stays_explicit(tmp_path):
    assert api().binary(
        tmp_path / 'development', env={}) == str(
            tmp_path / 'development')


@pytest.mark.parametrize('env', [{'MV_BUNDLE_TARBALL': 'a'},
                                 {'MV_CANDIDATE_MANIFEST': 'b'},
                                 {'MV_BUNDLE_TARBALL': '',
                                  'MV_CANDIDATE_MANIFEST': ''}])
def test_partial_or_empty_inputs_refuse_before_execution(env):
    with pytest.raises(ValueError, match='both'):
        api().load(env=env)


@pytest.mark.parametrize('key', ['MEMVEIL_BIN', 'MV_DEB', 'MV_RPM',
                                'MV_KERNELS_BUNDLE',
                                'LMB_NATIVE_LIB', 'LD_PRELOAD',
                                'LD_LIBRARY_PATH',
                                'MEMVEIL_TEST_NO_BPF',
                                'LMB_SANITIZE',
                                'MV_CANDIDATE_ROOT'])
def test_overrides_refused_before_reading_inputs(key):
    with pytest.raises(ValueError, match='override'):
        api().load(env={'MV_BUNDLE_TARBALL': 'absent',
                        'MV_CANDIDATE_MANIFEST': 'absent',
                        key: 'foreign'})


@pytest.fixture
def sealed(tmp_path):
    import tarfile
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate
    root = tmp_path / 'synthetic'
    (root / 'bin').mkdir(parents=True)
    engine = root / 'bin/memveil'
    engine.write_text('#!/bin/sh\necho packaged-synthetic\n')
    engine.chmod(0o755)
    for name in ('lib/memveil/libx.so.1', 'bpf/swiotlb_attempt.bpf.o',
                 'bpf/swiotlb_lifecycle.bpf.o', 'bpf/swiotlb_copy.bpf.o',
                 'profiles/test.json', 'LICENSE'):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('synthetic\n')
    files = {p.relative_to(root).as_posix(): candidate.digest(p)
             for p in sorted(root.rglob('*')) if p.is_file()}
    bpf = {name: files['bpf/' + name]
           for name in candidate.BPF_OBJECTS}
    receipt = {'source_commit': 'a' * 40,
               'inventory_sha256': 'd' * 64,
               'tools': {'cargo': '1.100.0', 'rustc': '1.100.0',
                         'bpf_linker': '0.10.4'},
               'outputs': {'engine_sha256': files['bin/memveil'],
                           'bpf': bpf}}
    bm = {'files': files, 'embedded_bpf': bpf,
          'memveil_revision': 'a' * 40,
          'cargo': {'lock_sha256': 'e' * 64,
                    'ebpf_lock_sha256': 'f' * 64},
          'toolchain': {'cargo': {'version': '1.100.0'},
                        'rustc': {'version': '1.100.0'}},
          'build_receipt': receipt}
    (root / 'MANIFEST.json').write_bytes(candidate.canonical(bm))
    archive = tmp_path / 'bundle.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        tar.add(root, arcname=root.name)
    artifacts = []
    for role in sorted(candidate.ROLES):
        path = archive if role == 'bundle' else tmp_path / (role + '.fixture')
        if role != 'bundle':
            path.write_text('synthetic artifact\n')
        artifacts.append({'role': role, 'name': path.name,
                          'size': str(path.stat().st_size),
                          'sha256': candidate.digest(path)})
    doc = {'schema': candidate.SCHEMA, 'origin': 'local-build',
           'source': {'commit': 'a' * 40, 'tree': 'b' * 40,
                      'inventory_sha256': 'd' * 64},
           'toolchain': {'cargo_lock_sha256': 'e' * 64,
                         'ebpf_lock_sha256': 'f' * 64,
                         'tools': {'cargo': '1.100.0',
                                   'rustc': '1.100.0',
                                   'bpf_linker': '0.10.4'}},
           'build_receipt_sha256':
           candidate.digest_canonical(receipt),
           'bundle_manifest_sha256':
           candidate.digest(root / 'MANIFEST.json'),
           'policy_sha256': '1' * 64, 'files': files,
           'artifacts': sorted(artifacts,
                               key=lambda item: item['role'])}
    manifest = tmp_path / 'candidate.json'
    candidate.seal_manifest(doc, manifest)
    return {'MV_BUNDLE_TARBALL': str(archive),
            'MV_CANDIDATE_MANIFEST': str(manifest)}


def test_candidate_input_loader(sealed):
    selected = api().load(env=sealed)
    try:
        deb = selected.artifact('deb')
        assert deb.name == 'deb.fixture' and deb.is_file()
        engine = selected.path('bin/memveil')
        assert engine == selected.bin and engine.is_file()
        engine.write_text('tampered\n')
        with pytest.raises(ValueError, match='changed'):
            selected.path('bin/memveil')
    finally:
        selected.close()
    with pytest.raises(ValueError, match='override'):
        api().load(env=dict(sealed, MEMVEIL_TEST_X='1'))
    with pytest.raises(ValueError, match='both'):
        api().load(env={}, required=True)


def test_artifact_path_resolves_all_manifest_roles(sealed):
    import candidate
    selected = api().load(env=sealed)
    try:
        assert set(candidate.ROLES) == {
            'bundle', 'deb', 'rpm', 'source', 'sbom',
            'provenance'}
        for role in sorted(candidate.ROLES):
            entry = candidate.artifact(selected.manifest,
                                       role)
            path = selected.artifact_path(role)
            assert path.is_file()
            assert path.name == entry['name']
            if role == 'bundle':
                assert path == selected.bundle
            else:
                assert path.parent == selected.manifest_path \
                    .parent
    finally:
        selected.close()


@pytest.mark.parametrize('role', ['kernel', '', 'deb ',
                                  None, 0, ['deb']])
def test_artifact_path_rejects_unknown_role(sealed, role):
    selected = api().load(env=sealed)
    try:
        with pytest.raises(ValueError, match='role'):
            selected.artifact_path(role)
    finally:
        selected.close()


def test_artifact_path_rejects_tampered_artifact(sealed):
    selected = api().load(env=sealed)
    try:
        deb = selected.artifact_path('deb')
        assert deb.is_file()
        with deb.open('ab') as handle:
            handle.write(b'tampered')
        with pytest.raises(ValueError, match='mismatch'):
            selected.artifact_path('deb')
    finally:
        selected.close()


def test_real_loader_selects_packaged_binary_and_cleans_owned_root(
        sealed, tmp_path):
    selected = api().load(env=sealed)
    owned = selected.root
    wrong = tmp_path / 'development'
    wrong.write_text('#!/bin/sh\necho WRONG\n')
    wrong.chmod(0o755)
    assert selected.bin != wrong
    assert subprocess.check_output(
        [selected.bin], text=True) == 'packaged-synthetic\n'
    assert selected.artifact('deb').name == 'deb.fixture'
    selected.close()
    assert not owned.exists()
    assert wrong.exists()


@pytest.mark.parametrize('damage', ['archive', 'manifest', 'alias',
                                    'extra-elf', 'override'])
def test_real_loader_rejects_damaged_inputs(sealed, tmp_path, damage):
    import json
    import tarfile
    import io
    import candidate
    archive = Path(sealed['MV_BUNDLE_TARBALL'])
    manifest = Path(sealed['MV_CANDIDATE_MANIFEST'])
    if damage == 'archive':
        archive.write_bytes(archive.read_bytes() + b'tampered')
    if damage == 'manifest':
        manifest.write_bytes(manifest.read_bytes() + b' ')
    if damage == 'override':
        sealed['MEMVEIL_BIN'] = str(tmp_path / 'development')
    if damage in ('alias', 'extra-elf'):
        old = tmp_path / 'old.tar.gz'
        archive.rename(old)
        with tarfile.open(old) as src, tarfile.open(
                archive, 'w:gz') as dst:
            for member in src.getmembers():
                payload = src.extractfile(member) \
                    if member.isfile() else None
                dst.addfile(member, payload)
            entry = tarfile.TarInfo('synthetic/foreign')
            if damage == 'alias':
                entry.type = tarfile.SYMTYPE
                entry.linkname = '/etc/passwd'
            else:
                entry.size = 4
            blob = io.BytesIO(b'\x7fELF') \
                if damage == 'extra-elf' else None
            dst.addfile(entry, blob)
        doc = json.loads(manifest.read_bytes())
        record = candidate.artifact(doc, 'bundle')
        record.update(size=str(archive.stat().st_size),
                      sha256=candidate.digest(archive))
        manifest.write_bytes(candidate.canonical(doc))
    with pytest.raises((ValueError, OSError)):
        api().load(env=sealed)


def test_conflicting_binary_argument_is_rejected(sealed, monkeypatch):
    for key in api().OVERRIDES:
        monkeypatch.delenv(key, raising=False)
    for key, value in sealed.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ValueError, match='--binary'):
        api().binary('development', explicit='development')
    api()._cached.close()
    api()._cached = None


def test_cleanup_preserves_replacement_directory(sealed):
    import shutil
    selected = api().load(env=sealed)
    owned = selected.root.parent.parent
    moved = owned.with_name(owned.name + '-moved')
    owned.rename(moved)
    owned.mkdir()
    sentinel = owned / 'foreign'
    sentinel.write_bytes(b'preserve')
    try:
        with pytest.raises(ValueError, match='ownership'):
            selected.close()
        assert sentinel.read_bytes() == b'preserve'
    finally:
        shutil.rmtree(moved)
        if owned.exists():
            shutil.rmtree(owned)
