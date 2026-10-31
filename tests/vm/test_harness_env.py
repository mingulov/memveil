# SPDX-License-Identifier: GPL-3.0-or-later
"""Every locked runner and oracle version must pass before boot."""
import json
import os
from pathlib import Path

import pytest
import harness_env

HERE = Path(__file__).resolve().parent


@pytest.fixture
def commands(tmp_path, monkeypatch):
    expected = json.loads((HERE / 'harness.lock.json').read_text())
    expected = {k: expected[k] for k in ('vng', 'qemu')}
    expected.update(json.loads((HERE / 'kernels.lock.json').read_text())['tools'])
    names = {'vng': 'vng', 'qemu': 'qemu-system-x86_64',
             'bpftrace': 'bpftrace', 'bpftool': 'bpftool'}
    paths = {}
    for name, version in expected.items():
        p = tmp_path / names[name]
        p.write_text('#!/bin/sh\nprintf "%s\\n" "' + version + '"\n')
        p.chmod(0o755)
        paths[name] = p
    monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ['PATH'])
    return paths, expected


def test_preboot_checks_all_four_locks(commands):
    paths, expected = commands
    assert harness_env.check_harness_versions(str(paths['vng'])) == expected


@pytest.mark.parametrize('name', ['vng', 'qemu', 'bpftrace', 'bpftool'])
def test_any_tool_drift_refuses_preboot(commands, name):
    paths, _ = commands
    paths[name].write_text('#!/bin/sh\nprintf "unlocked generation\\n"\n')
    with pytest.raises(ValueError, match='identity drift: ' + name):
        harness_env.check_harness_versions(str(paths['vng']))


def test_qemu_packaging_suffix_preserves_exact_generation(commands):
    paths, expected = commands
    line = expected['qemu'] + ' (packager build)'
    paths['qemu'].write_text('#!/bin/sh\nprintf "%s\\n" "' + line + '"\n')
    assert harness_env.check_harness_versions(str(paths['vng']))['qemu'] == line


def test_sudo_keeps_preflight_tool_selection_with_separate_vng_prefix(
        commands, tmp_path, monkeypatch):
    import shutil
    import subprocess
    import test_attempt_capture as gate
    paths, expected = commands
    vng_dir = tmp_path / 'vng-only'
    vng_dir.mkdir()
    vng = vng_dir / 'vng'
    vng.write_bytes(paths['vng'].read_bytes())
    vng.chmod(0o755)
    # A vng installation must neither hide the caller's isolated tools nor
    # shadow them with unrelated executables beside vng.
    for name in ('qemu', 'bpftrace', 'bpftool'):
        shadow = vng_dir / paths[name].name
        shadow.write_text('#!/bin/sh\nprintf "unlocked generation\\n"\n')
        shadow.chmod(0o755)
    monkeypatch.setenv('VNG', str(vng))
    real_exists, real_access, real_run = os.path.exists, os.access, subprocess.run
    monkeypatch.setattr(os.path, 'exists', lambda p:
                        True if p == '/dev/kvm' else real_exists(p))
    monkeypatch.setattr(os, 'access', lambda p, mode:
                        False if str(p).startswith(('/boot/', '/dev/kvm'))
                        else real_access(p, mode))

    def allow_sudo_probe(args, **kwargs):
        if args == ['sudo', '-n', 'true']:
            return subprocess.CompletedProcess(args, 0, b'', b'')
        return real_run(args, **kwargs)

    monkeypatch.setattr(subprocess, 'run', allow_sudo_probe)
    prefix, env = gate.gate_prefix()
    assert prefix[:3] == ['sudo', '-n', 'env']
    assert prefix[3] == 'PATH=' + env['PATH']
    assert prefix[-1] == str(vng)
    for name in ('qemu', 'bpftrace', 'bpftool'):
        selected = shutil.which(paths[name].name, path=env['PATH'])
        assert selected == str(paths[name])
        proc = real_run([selected, '--version'], env=env,
                        capture_output=True, text=True)
        assert proc.returncode == 0
        assert proc.stdout.splitlines()[0] == expected[name]
