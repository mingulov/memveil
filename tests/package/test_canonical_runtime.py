# SPDX-License-Identifier: GPL-3.0-or-later
"""The same complete runtime inventory must survive every package format."""
import importlib.util
from pathlib import Path
import shutil
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


def helper():
    spec = importlib.util.find_spec('canonical_runtime')
    assert spec is not None, 'canonical runtime verifier is missing'
    import canonical_runtime
    return canonical_runtime


def payload(root):
    files = {'bin/memveil': b'engine', 'lib/memveil/liba.so.1': b'library',
             'bpf/attempt.bpf.o': b'bpf', 'profiles/manifest.txt': b'profile list',
             'profiles/semantic.json': b'{"meaning":"request"}'}
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return files


def test_all_runtime_entries_equal_across_layouts(tmp_path):
    api = helper()
    bundle = tmp_path / 'bundle'
    files = payload(bundle)
    expected = api.inventory(bundle)
    assert {entry['path'] for entry in expected} == set(files)
    for kind in ('deb', 'rpm'):
        installed = tmp_path / kind
        for name, data in files.items():
            path = installed / api.installed_path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        assert api.inventory(installed, installed=True) == expected
        for name in files:
            path = installed / api.installed_path(name)
            original = path.read_bytes()
            path.write_bytes(original + b'changed')
            with pytest.raises(ValueError, match='differs'):
                api.verify(installed, expected, installed=True)
            path.write_bytes(original)


@pytest.mark.parametrize('change', ['extra', 'missing', 'escape', 'directory_escape'])
def test_inventory_refuses_incomplete_or_escaped_payload(tmp_path, change):
    api = helper()
    payload(tmp_path)
    expected = api.inventory(tmp_path)
    target = tmp_path / 'lib/memveil/liba.so.1'
    if change == 'extra':
        (target.parent / 'extra.so').write_bytes(b'extra')
    elif change == 'missing':
        target.unlink()
    elif change == 'escape':
        target.unlink()
        target.symlink_to('/etc/passwd')
    else:
        shutil.rmtree(target.parent)
        target.parent.symlink_to('/tmp', target_is_directory=True)
    with pytest.raises(ValueError):
        api.verify(tmp_path, expected)


def test_retained_packages_match_canonical_payload():
    import os
    bundle = os.environ.get('MV_CANONICAL_BUNDLE_DIR')
    deb = os.environ.get('MV_DEB_ROOT')
    rpm = os.environ.get('MV_RPM_ROOT')
    if not all((bundle, deb, rpm)):
        pytest.skip('requires extracted canonical bundle, Debian and RPM roots')
    api = helper()
    manifest = api.verify_bundle(bundle)
    expected = manifest['canonical_runtime']['entries']
    assert any(entry['path'].endswith('.so.1') for entry in expected)
    assert any(entry['path'].endswith('.bpf.o') for entry in expected)
    assert any(entry['path'].startswith('profiles/') for entry in expected)
    for root in (deb, rpm):
        assert api.verify(root, expected, installed=True) == expected


def test_transformed_dependencies_preserve_runtime_sections():
    import os
    import struct
    import subprocess
    bundle = os.environ.get('MV_CANONICAL_BUNDLE_DIR')
    if not bundle:
        pytest.skip('requires a canonical bundle and its original build inputs')
    api = helper()
    manifest = api.verify_bundle(bundle)

    def allocated_sections(path):
        data = Path(path).read_bytes()
        assert data[:6] == b'\x7fELF\x02\x01'
        offset = struct.unpack_from('<Q', data, 40)[0]
        width, count, strings_index = struct.unpack_from('<HHH', data, 58)
        headers = [struct.unpack_from('<IIQQQQIIQQ', data, offset + n * width) for n in range(count)]
        strings = headers[strings_index]
        names = data[strings[4]:strings[4] + strings[5]]
        return {names[h[0]:].split(b'\0', 1)[0]: data[h[4]:h[4] + h[5]]
                for h in headers if h[2] & 2 and h[1] != 8}

    changed = {'libbpf_mojo.so.1', 'libgcc_s.so.1', 'libstdc++.so.6'}
    for entry in manifest['canonical_runtime']['entries']:
        relative = entry['path']
        if not relative.startswith('lib/memveil/'):
            continue
        name = Path(relative).name
        source = ROOT / ('build/deps/lmb/lib' if name == 'libbpf_mojo.so.1' else '.pixi/envs/default/lib') / name
        target = Path(bundle) / relative
        if name not in changed:
            assert source.read_bytes() == target.read_bytes()
            continue
        record = manifest['normalization'][relative]
        assert record['source_root'] == 'source-tree'
        assert record['source_path'] == source.relative_to(ROOT).as_posix()
        assert record['source_sha256'] == api.digest(source)
        assert record['output_sha256'] == api.digest(target)
        assert record['operations'] == [['strip', '--strip-unneeded', relative]]
        assert allocated_sections(source) == allocated_sections(target)
        for option in ('--dynamic', '--dyn-syms', '--version-info'):
            before = subprocess.check_output(['readelf', '-W', option, str(source)])
            after = subprocess.check_output(['readelf', '-W', option, str(target)])
            assert before == after, (name, option)


def test_explicit_bundle_input_never_rebuilds(tmp_path):
    import os
    import subprocess
    tools = tmp_path / 'tools'
    tools.mkdir()
    shutil.copy2(ROOT / 'tools/test', tools / 'test')
    package = tools / 'package'
    package.write_text('#!/usr/bin/env python3\nfrom pathlib import Path\nPath(__file__).with_name("rebuilt").write_text("unexpected build")\nraise SystemExit(1)\n')
    package.chmod(0o755)
    result = subprocess.run([str(tools / 'test'), 'package'], cwd=tmp_path,
                            env=dict(os.environ, MV_BUNDLE_TARBALL=str(tmp_path / 'absent.tar.gz'), LMB_PACKAGE='unused'),
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert not (tools / 'rebuilt').exists(), 'explicit bundle caused a product rebuild'
