# SPDX-License-Identifier: GPL-3.0-or-later
"""Qualification dispatch refuses partial inputs, selects packaged bytes.

Candidate mode is selected before any build-tree access:
partial inputs fail closed with exit 2, unarmed live soak
skips with 77, packaged-binary selection resolves the
verified executable, candidate package runs never pass on
skips, and source inventories exclude versioned evidence
names. Runner wiring is pinned here: every runner family
resolves the packaged binary in candidate mode, truncated
replay/soak workloads refuse, a conflicting --binary fails
closed pre-exec, and a missing packaged binary never falls
back to the build tree.
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
def test_verified_binary_selected_over_dev_default(
        sealed, runner, tmp_path):
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


IMPORT_RUNNERS = ['perf/replay.py', 'perf/region_replay.py',
                  'perf/soak.py', 'perf/overhead.py',
                  'privacy/test_canaries.py',
                  'fuzz/test_oracle.py']


@pytest.mark.parametrize('runner',
                         IMPORT_RUNNERS + ['fuzz/run.py',
                                           'perf/workloads.py'])
def test_runners_select_packaged_binary(sealed, runner, tmp_path):
    environment = candidate_clean_env()
    environment.update(sealed)
    fake = tmp_path / 'build' / 'memveil'
    fake.parent.mkdir(parents=True)
    fake.write_text('#!/bin/sh\necho fake-build-tree\n')
    fake.chmod(0o755)
    development = str(ROOT / 'build' / 'memveil')
    if runner == 'fuzz/run.py':
        regress = tmp_path / 'regress'
        result = subprocess.run(
            [sys.executable, str(ROOT / 'tests/fuzz/run.py'),
             '--seeds', '1', '--regress', str(regress)],
            env=environment, capture_output=True, text=True,
            timeout=120)
        lines = [line for line in
                 result.stdout.splitlines()
                 if line.startswith('fuzz: binary ')]
        assert len(lines) == 1, result.stdout + result.stderr
        resolved = lines[0].split(' sha256 ')[0][len(
            'fuzz: binary '):]
        assert resolved != str(fake)
        assert resolved != development
        assert resolved.endswith('bin/memveil')
        # The runner subprocess owns its extraction: it
        # cleans up on exit, so execution is proved by the
        # failure signature below, not by re-running the
        # printed path here. The synthetic packaged script
        # echoes instead of reporting, so executing it fails
        # the pristine positive; executing the build tree
        # would pass and exit 0.
        assert result.returncode == 1, \
            result.stdout + result.stderr
        assert 'FAIL pristine positive' in result.stdout
        return
    if runner == 'perf/workloads.py':
        script = ('import os, runpy; value = runpy.run_path('
                  + repr(str(ROOT / 'tests' / runner))
                  + '); assert os.path.isfile('
                    'value["LC_PROBE"]); assert os.path.isfile('
                    'value["CP_PROBE"]); '
                    'print(value["LC_PROBE"]); '
                    'print(value["CP_PROBE"])')
        result = subprocess.run(
            [sys.executable, '-c', script],
            env=environment, capture_output=True, text=True,
            timeout=120)
        assert result.returncode == 0, result.stderr
        probes = result.stdout.splitlines()
        assert len(probes) == 2, result.stdout
        for probe in probes:
            assert probe != str(fake)
            assert probe != os.path.join(
                str(ROOT), 'build', 'bpf',
                os.path.basename(probe))
        return
    if runner == 'fuzz/test_oracle.py':
        environment['PYTHONPATH'] = str(
            ROOT / 'tests' / 'fuzz') + (
                os.pathsep + environment['PYTHONPATH']
                if environment.get('PYTHONPATH') else '')
    script = ('import runpy, subprocess; resolved = '
              'runpy.run_path('
              + repr(str(ROOT / 'tests' / runner))
              + ')["BIN"]; print(resolved); proc = '
                'subprocess.run([resolved], capture_output=True, '
                'text=True); print(proc.stdout, end="")')
    result = subprocess.run(
        [sys.executable, '-c', script],
        env=environment, capture_output=True, text=True,
        timeout=120)
    assert result.returncode == 0, result.stderr
    assert str(fake) not in result.stdout.splitlines()
    assert development not in result.stdout.splitlines()
    assert 'packaged-synthetic' in result.stdout


def test_replay_requires_pacing(sealed):
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MEMVEIL_PACED_SECONDS'] = '5'
    result = subprocess.run(
        [sys.executable, str(ROOT / 'tests/perf/replay.py')],
        env=environment, capture_output=True, text=True,
        timeout=600)
    assert result.returncode != 0
    assert 'pacing' in result.stderr


def test_soak_requires_30min(sealed):
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MEMVEIL_SOAK_MINUTES'] = '1'
    result = subprocess.run(
        [sys.executable, str(ROOT / 'tests/perf/soak.py')],
        env=environment, capture_output=True, text=True,
        timeout=600)
    assert result.returncode != 0
    assert '30 minutes' in result.stderr


def test_fuzz_binary_conflict_refuses(sealed, tmp_path):
    environment = candidate_clean_env()
    environment.update(sealed)
    result = subprocess.run(
        [sys.executable, str(ROOT / 'tests/fuzz/run.py'),
         '--seeds', '1', '--binary',
         str(tmp_path / 'foreign')],
        env=environment, capture_output=True, text=True,
        timeout=120)
    assert result.returncode != 0
    assert '--binary override' in result.stderr
    assert 'packaged-synthetic' not in result.stdout


def test_no_build_fallback(sealed, tmp_path):
    decoy = tmp_path / 'memveil'
    decoy.write_text('#!/bin/sh\necho fake-build-tree\n')
    decoy.chmod(0o755)
    broken = candidate_clean_env()
    broken.update(sealed)
    broken['MV_BUNDLE_TARBALL'] = str(
        tmp_path / 'missing.tar.gz')
    overridden = dict(broken, MEMVEIL_BIN=str(decoy))
    script = ('import runpy, subprocess; resolved = '
              'runpy.run_path('
              + repr(str(ROOT / 'tests/privacy'
                         / 'test_canaries.py'))
              + ')["BIN"]; print(resolved); proc = '
                'subprocess.run([resolved], capture_output=True, '
                'text=True); print(proc.stdout, end="")')
    result = subprocess.run(
        [sys.executable, '-c', script],
        env=overridden, capture_output=True, text=True,
        timeout=120)
    assert result.returncode != 0
    assert 'fake-build-tree' not in result.stdout
    probe = ('import runpy; print(runpy.run_path('
             + repr(str(ROOT / 'tests/perf/replay.py'))
             + ')["BIN"])')
    refused = subprocess.run(
        [sys.executable, '-c', probe],
        env=broken, capture_output=True, text=True,
        timeout=120)
    assert refused.returncode != 0
    assert 'build' not in refused.stdout
