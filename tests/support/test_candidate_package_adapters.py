# SPDX-License-Identifier: GPL-3.0-or-later
"""Package adapter boundaries with synthetic bytes; no installs or execution."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/package'))


def module(name):
    spec = importlib.util.spec_from_file_location('adapter_' + name, ROOT / 'tests/package' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


@pytest.mark.parametrize('development', [False, True])
def test_deb_uses_verified_candidate_bpf_without_build_tree(tmp_path, monkeypatch, development):
    m = module('test_deb')
    packaged = tmp_path / 'candidate'
    installed = tmp_path / 'installed'
    checkout = tmp_path / 'checkout'
    for name in m.BPF_OBJECTS:
        original = packaged / 'bpf' / name
        original.parent.mkdir(parents=True, exist_ok=True)
        original.write_bytes(b'packaged:' + name.encode())
        target = installed / 'usr/lib/memveil' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(original.read_bytes())
        if development:
            other = checkout / 'build/bpf' / name
            other.parent.mkdir(parents=True, exist_ok=True)
            other.write_bytes(b'different development bytes')
    monkeypatch.setattr(m, 'REPO', str(checkout))
    monkeypatch.setattr(m, '_selected', SimpleNamespace(path=lambda rel: packaged / rel))
    m.test_bpf_objects_match_build(installed)
    (installed / 'usr/lib/memveil' / m.BPF_OBJECTS[0]).write_bytes(b'wrong installed bytes')
    with pytest.raises(AssertionError): m.test_bpf_objects_match_build(installed)


def test_candidate_cleanroom_accepts_already_absent_pixi(tmp_path, monkeypatch):
    m = module('test_clean_runtime')
    monkeypatch.setattr(m, 'REPO', str(tmp_path / 'compiler-free'))
    monkeypatch.setattr(m, 'load', lambda: object())
    fixture = m.TestCleanRoom.hidden_pixi.__wrapped__(m.TestCleanRoom(), tmp_path)
    assert next(fixture)['initial_state'] == 'absent'
    with pytest.raises(StopIteration): next(fixture)
    assert not (tmp_path / 'compiler-free/.pixi').exists()


def test_development_cleanroom_still_requires_the_expected_libraries(tmp_path, monkeypatch):
    m = module('test_clean_runtime')
    monkeypatch.setattr(m, 'REPO', str(tmp_path / 'development'))
    monkeypatch.setattr(m, 'load', lambda: None)
    with pytest.raises(AssertionError, match='pixi libs missing'):
        next(m.TestCleanRoom.hidden_pixi.__wrapped__(m.TestCleanRoom(), tmp_path))


@pytest.mark.parametrize('access', ['clean', 'pixi-attempt', 'checkout-attempt'])
def test_candidate_cleanroom_still_audits_runtime_resolution_and_paths(tmp_path, monkeypatch, access):
    import json
    m = module('test_clean_runtime')
    root = tmp_path / 'candidate'
    checkout = tmp_path / 'checkout'
    monkeypatch.setattr(m, 'REPO', str(checkout))
    monkeypatch.setattr(m, 'load', lambda: object())
    monkeypatch.setattr(m.shutil, 'which', lambda name: '/usr/bin/strace')
    calls = []
    def run(*args, **kwargs):
        calls.append(args[0])
        if args[0] == 'ldd':
            return SimpleNamespace(returncode=0, stderr='', stdout='\n'.join(
                name + ' => ' + str(root / 'bin/../lib/memveil' / name) for name in m.HIDE_LIBS))
        assert args[0] == 'strace'
        trace = '1 execve("' + str(root / 'bin/memveil') + '", [], []) = 0\n'
        if access == 'pixi-attempt': trace += '1 openat(AT_FDCWD, "/absent/.pixi/lib.so", O_RDONLY) = -1 ENOENT\n'
        if access == 'checkout-attempt': trace += '1 openat(AT_FDCWD, "' + str(checkout / 'build/memveil') + '", O_RDONLY) = -1 ENOENT\n'
        Path(args[args.index('-o') + 1]).write_text(trace)
        return SimpleNamespace(returncode=0, stderr='', stdout=json.dumps({'metrics': [{'name': 'bounce_attempts', 'value': '30'}]}))
    monkeypatch.setattr(m, 'run', run)
    call = lambda: m.TestCleanRoom().test_replay_without_pixi_env_cwd((root, {}), {'initial_state': 'absent'}, tmp_path)
    if access == 'clean': call()
    else:
        with pytest.raises(AssertionError, match='attempted'): call()
    assert calls == ['ldd', 'strace']
