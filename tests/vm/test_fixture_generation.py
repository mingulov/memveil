# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline provisional fixtures retain exact build custody and semantics."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / 'tools/emit-test-fixtures'


def run(*args):
    return subprocess.run([sys.executable, str(TOOL), *map(str, args)],
                          capture_output=True, text=True)


@pytest.fixture(scope='module')
def generated(tmp_path_factory):
    out = tmp_path_factory.mktemp('provisional')
    proc = run('--out', out)
    assert proc.returncode == 0, proc.stderr
    return out


def test_fresh_fixture_exact_recompile_and_provisional_status(generated):
    proc = run('--out', generated, '--check')
    assert proc.returncode == 0, proc.stderr
    doc = json.loads((generated / 'profile.json').read_text())
    assert doc['status'] == 'reference-unvalidated'
    assert doc['profile_id'] == 'test-narrow-provisional'
    manifest = json.loads((generated / 'manifest.json').read_text())
    assert manifest['qualification'] == 'synthetic-only'
    assert manifest['inputs']['compiler']['version']
    assert manifest['inputs']['compiler']['sha256']
    assert manifest['inputs']['sources']['tests/fixtures/core/relo_kinds.bpf.c']
    assert manifest['inputs']['headers']['build/deps/include/bpf/bpf_core_read.h']
    assert manifest['inputs']['resource_headers']
    assert manifest['inputs']['flags']


@pytest.mark.parametrize('part', ['sources', 'headers', 'compiler', 'flags'])
def test_recorded_input_drift_is_refused(generated, part):
    path = generated / 'manifest.json'
    original = path.read_bytes()
    manifest = json.loads(original)
    manifest['inputs'][part] = {'changed': 'unexpected input'}
    try:
        path.write_text(json.dumps(manifest))
        proc = run('--out', generated, '--check')
        assert proc.returncode == 1
        assert 'input identity drift' in proc.stderr
    finally:
        path.write_bytes(original)


def test_changed_object_is_refused_even_if_manifest_rehashed(generated):
    import hashlib
    path = generated / 'swiotlb_attempt.bpf.o'
    mp = generated / 'manifest.json'
    original, manifest_bytes = path.read_bytes(), mp.read_bytes()
    try:
        path.write_bytes(original + b'changed object')
        manifest = json.loads(manifest_bytes)
        manifest['outputs'][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        mp.write_text(json.dumps(manifest))
        proc = run('--out', generated, '--check')
        assert proc.returncode == 1
        assert 'fresh compile differs' in proc.stderr
    finally:
        path.write_bytes(original)
        mp.write_bytes(manifest_bytes)


@pytest.mark.parametrize('path', ['bpf/programs/swiotlb_attempt.bpf.c',
                                  'build/deps/include/bpf/bpf_core_read.h'])
def test_actual_source_or_header_drift_is_refused(generated, tmp_path, path):
    import shutil
    manifest = json.loads((generated / 'manifest.json').read_text())
    root = tmp_path / 'source'
    for name in set(manifest['inputs']['sources']) | set(manifest['inputs']['headers']):
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, target)
    out = root / 'build/fixtures/provisional'
    shutil.copytree(generated, out)
    changed = root / path
    changed.write_bytes(changed.read_bytes() + b'\n/* changed input */\n')
    proc = subprocess.run([sys.executable, str(root / 'tools/emit-test-fixtures'),
                           '--out', str(out), '--check'], capture_output=True, text=True)
    assert proc.returncode == 1
    assert 'input identity drift' in proc.stderr


def test_actual_compiler_invoker_drift_is_refused(tmp_path):
    import shutil
    clang = shutil.which('clang')
    wrapper = tmp_path / 'compiler'
    wrapper.write_text('#!/bin/sh\nexec "' + clang + '" "$@"\n')
    wrapper.chmod(0o755)
    out = tmp_path / 'objects'
    proc = run('--out', out, '--clang', wrapper)
    assert proc.returncode == 0, proc.stderr
    wrapper.write_text(wrapper.read_text() + '# compiler installation changed\n')
    proc = run('--out', out, '--clang', wrapper, '--check')
    assert proc.returncode == 1
    assert 'input identity drift' in proc.stderr


def test_codegen_library_drift_changes_identity(monkeypatch, tmp_path):
    import hashlib
    import importlib.util
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader('fixture_identity_test', str(TOOL))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    lib = tmp_path / 'libcompiler.so'
    lib.write_bytes(b'first code generator')
    real_run = module.subprocess.run

    def run_with_library(args, **kwargs):
        if args[0] == 'ldd':
            return subprocess.CompletedProcess(args, 0,
                'libcompiler.so => %s (0x0)\n' % lib, '')
        return real_run(args, **kwargs)

    # Substitute the external loader's listing, then exercise real file
    # hashing: a library upgrade must invalidate the recorded compiler.
    monkeypatch.setattr(module.subprocess, 'run', run_with_library)
    before = module.input_identity('clang')
    lib.write_bytes(b'replacement code generator')
    after = module.input_identity('clang')
    assert before['compiler'] != after['compiler']
    assert after['compiler']['shared_libraries'][str(lib)] == hashlib.sha256(
        b'replacement code generator').hexdigest()


@pytest.mark.parametrize('kind', ['symlink', 'directory', 'fifo'])
def test_special_output_is_refused_without_touching_target(tmp_path, kind):
    import os
    out = tmp_path / 'out'
    out.mkdir()
    target = tmp_path / 'historical'
    target.write_bytes(b'preserve historical bytes')
    path = out / 'swiotlb_attempt.bpf.o'
    if kind == 'symlink':
        path.symlink_to(target)
    elif kind == 'directory':
        path.mkdir()
    else:
        os.mkfifo(path)
    proc = run('--out', out)
    assert proc.returncode == 1
    assert 'non-regular fixture output' in proc.stderr
    assert target.read_bytes() == b'preserve historical bytes'


def test_concurrent_fixture_writer_is_refused(tmp_path):
    import fcntl
    import os
    out = tmp_path / 'out'
    out.mkdir()
    fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        proc = run('--out', out)
        assert proc.returncode == 1
        assert 'fixture directory is busy' in proc.stderr
        assert list(out.iterdir()) == []
    finally:
        os.close(fd)


def test_partial_regular_output_can_be_regenerated(tmp_path):
    out = tmp_path / 'out'
    out.mkdir()
    (out / 'swiotlb_copy.bpf.o').write_bytes(b'partial')
    proc = run('--out', out)
    assert proc.returncode == 0, proc.stderr
    proc = run('--out', out, '--check')
    assert proc.returncode == 0, proc.stderr


def test_compiler_identity_uses_executing_driver_not_program_lookup(tmp_path):
    import hashlib
    import importlib.util
    import shutil
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader('fixture_driver_test', str(TOOL))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    real = shutil.which('clang')
    wrong = tmp_path / 'different-clang'
    wrong.write_text('#!/bin/sh\nexit 0\n')
    wrapper = tmp_path / 'clang-alternate-name'
    wrapper.write_text('#!/bin/sh\nif [ "$1" = -print-prog-name=clang ]; then\n'
                       '  echo "' + str(wrong) + '"; exit 0\nfi\n'
                       'exec "' + real + '" "$@"\n')
    wrapper.chmod(0o755)
    identity = module.input_identity(str(wrapper))
    baseline = module.input_identity('clang')
    assert identity['compiler']['sha256'] == baseline['compiler']['sha256']
    assert identity['compiler']['shared_libraries'] == baseline['compiler']['shared_libraries']
