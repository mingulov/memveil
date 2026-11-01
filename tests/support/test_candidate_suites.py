# SPDX-License-Identifier: GPL-3.0-or-later
"""Candidate dispatch rejects incomplete inputs before any workload."""
import os
from pathlib import Path
import subprocess
import sys
from test_candidate_input import sealed, api
import pytest
ROOT = Path(__file__).resolve().parents[2]

@pytest.mark.parametrize('suite', ['perf-replay', 'perf-region', 'soak', 'fuzz-smoke', 'privacy',
                                  'extracted-robustness', 'package', 'release-runtime',
                                  'perf-overhead', 'perf-workload', 'vm-live-soak'])
def test_wrapper_refuses_partial_input_before_build_or_vm(suite, tmp_path):
    env = dict(os.environ, MV_BUNDLE_TARBALL=str(tmp_path / 'missing'))
    env.pop('MV_CANDIDATE_MANIFEST', None)
    result = subprocess.run([str(ROOT / 'tools/test'), suite], env=env, capture_output=True, text=True)
    assert result.returncode == 2
    assert 'both' in result.stderr


def test_unarmed_live_soak_skips():
    env = {k: v for k, v in os.environ.items() if not k.startswith(('MV_CANDIDATE', 'MV_BUNDLE', 'MEMVEIL_VM_'))}
    result = subprocess.run([str(ROOT / 'tools/test'), 'vm-live-soak'], env=env, capture_output=True, text=True)
    assert result.returncode == 77


@pytest.mark.parametrize('runner', ['perf/replay.py', 'perf/region_replay.py', 'perf/soak.py',
                                   'privacy/test_canaries.py'])
def test_runner_import_selects_packaged_binary(sealed, runner):
    import json
    environment = {key: value for key, value in os.environ.items() if key not in api().OVERRIDES}
    environment.update(sealed)
    script = ('import runpy,subprocess; value=runpy.run_path(' + repr(str(ROOT / 'tests' / runner)) + '); '
              'print(subprocess.check_output([value["BIN"]], text=True), end="")')
    result = subprocess.run([sys.executable, '-c', script], env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'packaged-synthetic\n'


def test_fuzz_conflict_refuses_before_executable(sealed, tmp_path):
    environment = {key: value for key, value in os.environ.items() if key not in api().OVERRIDES}
    environment.update(sealed)
    result = subprocess.run([sys.executable, str(ROOT / 'tests/fuzz/run.py'), '--seeds', '1',
                             '--binary', str(tmp_path / 'foreign')], env=environment, capture_output=True, text=True)
    assert result.returncode != 0
    assert '--binary override' in result.stderr
    assert 'packaged-synthetic' not in result.stdout
