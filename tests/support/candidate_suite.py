#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Dispatch exact-candidate suites without product build or packaging fallbacks."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
from support.candidate_input import load


def run(suite):
    selected = load(required=True)
    if suite in ('fuzz-campaign', 'extracted-robustness') and int(os.environ.get('MEMVEIL_FUZZ_SEEDS', '10000')) < 10000:
        raise ValueError('qualification fuzz campaign requires at least 10000 seeds')
    print('qualification input: ' + selected.digest, flush=True)
    commands = {
        'perf-replay': ['tests/perf/replay.py'],
        'perf-region': ['tests/perf/region_replay.py'],
        'soak': ['tests/perf/soak.py'],
        'privacy': ['tests/privacy/test_canaries.py'],
        'fuzz-smoke': ['tests/fuzz/run.py', '--seeds', '200'],
        'fuzz-campaign': ['tests/fuzz/run.py', '--seeds', os.environ.get('MEMVEIL_FUZZ_SEEDS', '10000')],
        'perf-overhead': ['tests/vm/candidate_live.py', 'overhead'],
        'perf-workload': ['tests/perf/workloads.py'],
        'vm-live-soak': ['tests/vm/candidate_live.py', 'soak'],
        'release-runtime': ['-m', 'pytest', 'tests/package/test_release_runtime.py', '-q'],
        'package': ['-m', 'pytest', 'tests/package/test_release_runtime.py',
                    'tests/package/test_clean_runtime.py', '-q'],
        'deb': ['-m', 'pytest', 'tests/package/test_deb.py', '-q'],
        'rpm-journey': ['-m', 'pytest', 'tests/package/test_rpm_journey.py', '-q'],
    }
    if suite in ('vm-kernels', 'vm-scenarios'):
        scenarios = suite == 'vm-scenarios'
        armed = 'MEMVEIL_VM_SCENARIOS' if scenarios else 'MEMVEIL_VM_KERNELS'
        if os.environ.get(armed) != '1':
            print('SKIP: needs ' + armed + '=1')
            return 77
        args = [str(ROOT / 'tools/kernel-matrix')]
        if scenarios:
            args += ['--scenarios', '--kernels', '7.0', '--out',
                     os.environ.get('MV_SCENARIOS_OUT', str(ROOT / 'build/vm/scenarios'))]
        else:
            ids = os.environ.get('MV_KERNELS_IDS')
            args += ['--kernels', ids] if ids else ['--all']
            args += ['--out', os.environ.get('MV_KERNELS_OUT', str(ROOT / 'build/vm/kernels'))]
            if os.environ.get('MV_KERNELS_DISK'): args += ['--disk-img', os.environ['MV_KERNELS_DISK']]
        return subprocess.run([sys.executable, *args], cwd=ROOT).returncode
    if suite == 'extracted-robustness':
        for name in ('fuzz-campaign', 'privacy'):
            result = run(name)
            if result:
                return result
        return 0
    if suite not in commands:
        raise ValueError('suite has no candidate qualification adapter: ' + suite)
    env = dict(os.environ)
    env['MV_VALID_EMPTY'] = str(ROOT / 'tests/package/valid-empty')
    return subprocess.run([sys.executable, *commands[suite]], cwd=ROOT, env=env).returncode


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('one suite is required')
        sys.exit(run(sys.argv[1]))
    except (ValueError, OSError) as exc:
        print('candidate inputs: ' + str(exc), file=sys.stderr)
        sys.exit(2)
