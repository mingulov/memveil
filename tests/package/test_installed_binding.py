# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind all copied package bytes before execution and final assembly."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import shutil
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import canonical_runtime as api


def deb_tool():
    loader = importlib.machinery.SourceFileLoader('binding_deb', str(ROOT / 'tools/package-deb'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def retained_bundle(tmp_path):
    source = os.environ.get('MV_CANONICAL_BUNDLE_DIR')
    if not source:
        pytest.skip('requires a retained canonical bundle')
    bundle = tmp_path / 'bundle'
    shutil.copytree(source, bundle)
    return bundle


@pytest.mark.parametrize('name', ['LICENSE', 'THIRD-PARTY-NOTICES.md',
    'docs/build.md', 'examples/real-capture/session.json', 'bin/memveil'])
@pytest.mark.parametrize('boundary', ['source', 'destination'])
def test_deb_refuses_changed_copied_bytes_before_execution(tmp_path, monkeypatch, name, boundary):
    bundle = retained_bundle(tmp_path)
    tool = deb_tool()
    out = tmp_path / 'out'
    out.mkdir()
    sentinel = out / 'existing.deb'
    sentinel.write_bytes(b'unrelated output')
    executed = []
    real_run = tool.run
    def observe_run(argv, *args, **kwargs):
        if Path(argv[0]).name == 'memveil' or '--binary' in argv:
            executed.append(argv)
        return real_run(argv, *args, **kwargs)
    monkeypatch.setattr(tool, 'run', observe_run)
    def change(path):
        if name == 'bin/memveil':
            path.write_text('#!/bin/sh\nprintf "memveil-0.1.0\\n"\n')
        else:
            path.write_bytes(b'changed after complete verification\n')
    if boundary == 'source':
        real_verify = api.verify_bundle
        def mutate(root):
            manifest = real_verify(root)
            change(Path(root) / name)
            return manifest
        monkeypatch.setattr(api, 'verify_bundle', mutate)
    else:
        real_copy = shutil.copy2
        def mutate(src, dst, *args, **kwargs):
            result = real_copy(src, dst, *args, **kwargs)
            if Path(src) == bundle / name:
                change(Path(dst))
            return result
        monkeypatch.setattr(shutil, 'copy2', mutate)
        real_tree = shutil.copytree
        def copy_tree(src, dst, *args, **kwargs):
            if len(args) < 3:
                kwargs.setdefault('copy_function', mutate)
            return real_tree(src, dst, *args, **kwargs)
        monkeypatch.setattr(shutil, 'copytree', copy_tree)
    with pytest.raises((ValueError, SystemExit)):
        tool.main(['--bundle', str(bundle), '--out', str(out), '--tag', 'existing'])
    assert not executed, 'unverified staged engine was executed'
    assert sentinel.read_bytes() == b'unrelated output'
    assert list(out.iterdir()) == [sentinel]


@pytest.mark.parametrize('damage', ['symlink', 'extra'])
def test_deb_refuses_postverify_substitution_and_extra_copy(tmp_path, monkeypatch, damage):
    bundle = retained_bundle(tmp_path)
    tool = deb_tool()
    outside = tmp_path / 'unrelated'
    outside.write_bytes(b'unrelated input')
    real_verify = api.verify_bundle
    def mutate(root):
        manifest = real_verify(root)
        if damage == 'symlink':
            (bundle / 'LICENSE').unlink()
            (bundle / 'LICENSE').symlink_to(outside)
        else:
            (bundle / 'docs/extra.txt').write_bytes(b'not sealed')
        return manifest
    monkeypatch.setattr(api, 'verify_bundle', mutate)
    with pytest.raises((ValueError, SystemExit)):
        tool.main(['--bundle', str(bundle), '--out', str(tmp_path / 'out')])
    assert not (tmp_path / 'out').exists()
    assert outside.read_bytes() == b'unrelated input'


def test_every_retained_installed_file_is_bound(tmp_path):
    bundle = retained_bundle(tmp_path)
    manifest = api.verify_bundle(bundle)
    installed = tmp_path / 'installed'
    for name in manifest['files']:
        dest = installed / api.installed_file_path(name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bundle / name, dest)
    api.verify_installed(installed, manifest)
    for name in manifest['files']:
        dest = installed / api.installed_file_path(name)
        original = dest.read_bytes()
        dest.write_bytes(original + b'changed')
        with pytest.raises(ValueError):
            api.verify_installed(installed, manifest)
        dest.write_bytes(original)
    api.verify_installed(installed, manifest)


def test_deb_rechecks_copied_files_after_generators(tmp_path, monkeypatch):
    bundle = retained_bundle(tmp_path)
    tool = deb_tool()
    real_run = tool.run
    changed = []
    def mutate_after_man(argv, *args, **kwargs):
        result = real_run(argv, *args, **kwargs)
        if '--binary' in argv:
            root = Path(argv[argv.index('--binary') + 1]).parents[2]
            target = root / 'usr/share/doc/memveil/LICENSE'
            target.write_bytes(b'changed after the pre-execution check')
            changed.append(target)
        return result
    monkeypatch.setattr(tool, 'run', mutate_after_man)
    out = tmp_path / 'out'
    with pytest.raises(ValueError, match='installed file differs'):
        tool.main(['--bundle', str(bundle), '--out', str(out)])
    assert len(changed) == 1
    assert not out.exists()


@pytest.mark.parametrize('name', ['/LICENSE', '../LICENSE', 'docs/../LICENSE',
                                   'docs//build.md', './LICENSE', 'unknown/file'])
def test_installed_file_mapping_refuses_escapes_and_unknown_paths(name):
    with pytest.raises(ValueError):
        api.installed_file_path(name)


def test_installed_mapping_cannot_alias_two_sealed_files(tmp_path):
    bundle = retained_bundle(tmp_path)
    manifest = api.verify_bundle(bundle)
    installed = tmp_path / 'installed'
    for name in manifest['files']:
        dest = installed / api.installed_file_path(name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bundle / name, dest)
    manifest['files']['docs/examples/real-capture/session.json'] = manifest['files']['examples/real-capture/session.json']
    with pytest.raises(ValueError, match='duplicate'):
        api.verify_installed(installed, manifest)
