# SPDX-License-Identifier: GPL-3.0-or-later
"""Qualification dispatch refuses partial inputs, selects packaged bytes.

Candidate mode is selected before any build-tree access:
partial inputs fail closed with exit 2, unarmed live soak
skips with 77, packaged-binary selection resolves the
verified executable, candidate package runs never pass on
skips, and source inventories exclude versioned evidence
names. Runner wiring belongs to a later task; the
selection test here pins the shared selector the runners
consume.
"""
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
from test_candidate_input import sealed, api
import pytest
ROOT = Path(__file__).resolve().parents[2]

PARTIAL_SUITES = ['perf-replay', 'perf-region', 'soak',
                  'fuzz-smoke', 'privacy',
                  'extracted-robustness', 'package',
                  'release-runtime', 'perf-overhead',
                  'perf-workload', 'vm-live-soak']
assert len(PARTIAL_SUITES) == 11


def candidate_clean_env():
    return {key: value for key, value in os.environ.items()
            if key not in api().OVERRIDES
            and not key.startswith('MEMVEIL_TEST_')}


@pytest.mark.parametrize('suite', PARTIAL_SUITES)
def test_partial_input_refuses_pre_build(suite, tmp_path):
    env = dict(os.environ,
               MV_BUNDLE_TARBALL=str(tmp_path / 'missing'))
    env.pop('MV_CANDIDATE_MANIFEST', None)
    env['MV_KERNELS_OUT'] = str(
        tmp_path / 'kernels-must-not-exist')
    env['MV_SCENARIOS_OUT'] = str(
        tmp_path / 'scenarios-must-not-exist')
    build = ROOT / 'build'
    before = sorted(entry.name for entry in build.iterdir()) \
        if build.is_dir() else None
    result = subprocess.run(
        [str(ROOT / 'tools/test'), suite],
        env=env, capture_output=True, text=True)
    assert result.returncode == 2
    assert 'both' in result.stderr
    assert not (tmp_path / 'kernels-must-not-exist').exists()
    assert not (tmp_path / 'scenarios-must-not-exist').exists()
    after = sorted(entry.name for entry in build.iterdir()) \
        if build.is_dir() else None
    assert before == after


def test_unarmed_soak_skips_77():
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('MV_CANDIDATE', 'MV_BUNDLE',
                                   'MEMVEIL_VM_'))}
    result = subprocess.run(
        [str(ROOT / 'tools/test'), 'vm-live-soak'],
        env=env, capture_output=True, text=True)
    assert result.returncode == 77
    assert 'SKIP' in result.stdout + result.stderr


@pytest.mark.parametrize('runner', ['perf/replay.py',
                                    'perf/region_replay.py',
                                    'perf/soak.py',
                                    'privacy/test_canaries.py'])
def test_packaged_binary_selected(sealed, runner, tmp_path):
    environment = candidate_clean_env()
    environment.update(sealed)
    fake = tmp_path / 'build' / 'memveil'
    fake.parent.mkdir(parents=True)
    fake.write_text('#!/bin/sh\necho fake-build-tree\n')
    fake.chmod(0o755)
    development = runpy.run_path(
        str(ROOT / 'tests' / runner))['BIN']
    for candidate in (development, str(fake)):
        resolved = api().binary(candidate, env=environment)
        assert resolved != str(fake)
        result = subprocess.run(
            [resolved], env=environment,
            capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        assert result.stdout == 'packaged-synthetic\n'


def test_conftest_fails_candidate_skips(sealed, tmp_path):
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['PYTHONPATH'] = str(ROOT / 'tests') + (
        os.pathsep + environment['PYTHONPATH']
        if environment.get('PYTHONPATH') else '')
    shutil.copy(str(ROOT / 'tests/package/conftest.py'),
                tmp_path / 'conftest.py')
    (tmp_path / 'test_synthetic_skip.py').write_text(
        'import pytest\n'
        'pytestmark = pytest.mark.skip'
        '(reason="synthetic")\n'
        'def test_skip():\n'
        '    pass\n')
    result = subprocess.run(
        [sys.executable, '-m', 'pytest',
         'test_synthetic_skip.py', '-q', '-p',
         'no:cacheprovider'],
        env=environment, capture_output=True, text=True,
        cwd=tmp_path)
    assert 'skipped' in result.stdout
    assert result.returncode == 1


def test_inventory_excludes_only_named_evidence_files(tmp_path):
    sys.path.insert(0, str(ROOT / 'tools'))
    import source_inventory
    folder = tmp_path / 'packaging/qualifications'
    folder.mkdir(parents=True)
    (folder / 'qualification.json').write_text('{}\n')
    (folder / 'engine.so').write_bytes(b'\x7fELFsynthetic')
    (tmp_path / 'packaging/candidate-policy.json').write_text(
        '{}\n')
    (tmp_path / 'packaging/tested-payload.sha256').write_text(
        'synthetic\n')
    names = {entry['path'] for entry in source_inventory
             .take_inventory(tmp_path, dirs=('packaging',))
             ['files']}
    assert 'packaging/qualifications/qualification.json' \
        not in names
    assert 'packaging/tested-payload.sha256' not in names
    assert 'packaging/qualifications/engine.so' in names
    assert 'packaging/candidate-policy.json' in names
    tree = {entry['path'] for entry in source_inventory
            .take_inventory(tmp_path)['files']}
    assert 'packaging/qualifications/qualification.json' \
        in tree
