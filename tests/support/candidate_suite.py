#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Dispatch exact-candidate suites without product build fallbacks."""
import atexit
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
from support.candidate_input import load
from support.deferred_skips import lookup

# Arming variable per dispatched suite that needs one: an
# unarmed 77 passes through, an armed 77 fails as an
# unexpected skip. Variables mirror the runners (live
# campaigns arm per mode in tests/vm/candidate_live.py;
# the matrix lanes arm in the vm branch below). A suite
# without an entry runs unarmed and any 77 from it fails.
SUITE_ARMING = {
    'perf-overhead': 'MEMVEIL_VM_PERF',
    'vm-live-soak': 'MEMVEIL_VM_LIVE_SOAK',
    'vm-kernels': 'MEMVEIL_VM_KERNELS',
    'vm-scenarios': 'MEMVEIL_VM_SCENARIOS',
}


def _checked(suite, code, live):
    """Keep an unarmed 77; fail a skip once armed.

    A deferred suite always passes its skip through. A
    suite with an arming variable passes 77 through only
    while unarmed; after arming, or for a suite with no
    arming variable, 77 is an unexpected skip and fails.
    """
    if code != 77:
        return code
    if lookup(suite) is not None:
        return code
    var = SUITE_ARMING.get(suite)
    if var is not None and live.get(var) != '1':
        return code
    if var is None:
        print('FAIL: suite %s skipped without a deferral '
              'entry' % suite, file=sys.stderr, flush=True)
    else:
        print('FAIL: suite %s skipped after arming '
              '(%s=1)' % (suite, var),
              file=sys.stderr, flush=True)
    return 1


def _run(suite, argv, live, selected):
    entry = lookup(suite)
    if entry is not None:
        print('SKIP: %s [deferred]'
              % entry['reason'], flush=True)
        return 77
    if suite in ('fuzz-campaign', 'extracted-robustness') \
            and int(live.get('MEMVEIL_FUZZ_SEEDS', '10000')) \
            < 10000:
        raise ValueError('qualification fuzz campaign requires '
                         'at least 10000 seeds')
    print('qualification input: ' + selected.digest, flush=True)
    commands = {
        'perf-replay': ['tests/perf/replay.py'],
        'perf-region': ['tests/perf/region_replay.py'],
        'soak': ['tests/perf/soak.py'],
        'privacy': ['tests/privacy/test_canaries.py'],
        'fuzz-smoke': ['tests/fuzz/run.py', '--seeds', '200'],
        'fuzz-campaign': ['tests/fuzz/run.py', '--seeds',
                          live.get('MEMVEIL_FUZZ_SEEDS', '10000')],
        'perf-overhead': ['tests/vm/candidate_live.py',
                          'overhead'],
        'vm-live-soak': ['tests/vm/candidate_live.py', 'soak'],
        'release-runtime': ['-m', 'pytest',
                            'tests/package/test_release_runtime.py',
                            '-q'],
        'package': ['-m', 'pytest',
                    'tests/package/test_release_runtime.py',
                    'tests/package/test_clean_runtime.py', '-q'],
        'deb': ['cargo', 'test', '--locked', '--test',
                'package_deb'],
        'rpm-journey': ['cargo', 'test', '--locked', '--test',
                        'package_rpm'],
    }
    if suite in ('vm-kernels', 'vm-scenarios'):
        scenarios = suite == 'vm-scenarios'
        armed = 'MEMVEIL_VM_SCENARIOS' if scenarios \
            else 'MEMVEIL_VM_KERNELS'
        if live.get(armed) != '1':
            print('SKIP: needs ' + armed + '=1')
            return _checked(suite, 77, live)
        args = [str(ROOT / 'tools/kernel-matrix')]
        if scenarios:
            args += ['--scenarios', '--kernels', '7.0',
                     '--out', live.get(
                         'MV_SCENARIOS_OUT',
                         str(ROOT / 'build/vm/scenarios'))]
        else:
            ids = live.get('MV_KERNELS_IDS')
            args += ['--kernels', ids] if ids else ['--all']
            args += ['--out', live.get(
                'MV_KERNELS_OUT',
                str(ROOT / 'build/vm/kernels'))]
            if live.get('MV_KERNELS_DISK'):
                args += ['--disk-img', live['MV_KERNELS_DISK']]
        args += list(argv)
        return subprocess.run(
            [sys.executable, *args], cwd=ROOT,
            env=dict(live)).returncode
    if suite == 'extracted-robustness':
        for name in ('fuzz-campaign', 'privacy'):
            result = _run(name, argv, live, selected)
            if result:
                return result
        return 0
    if suite not in commands:
        raise ValueError('suite has no candidate qualification '
                         'adapter: ' + suite)
    command = commands[suite] + list(argv)
    env = dict(live)
    env['MV_VALID_EMPTY'] = str(
        ROOT / 'tests/package/valid-empty')
    if command[0] == 'cargo':
        env.pop('RUSTUP_TOOLCHAIN', None)
    else:
        command = [sys.executable, *command]
    return _checked(suite, subprocess.run(
        command, cwd=ROOT, env=env).returncode, live)


def dispatch(suite, argv, env):
    """Run one qualification suite against verified inputs.

    Returns the suite exit code. Partial or otherwise
    invalid candidate inputs print a diagnostic and raise
    SystemExit(2); dispatch never falls back to the build
    tree. An unarmed suite passes 77 through; a deferred
    suite passes its recorded skip; any other 77 fails as
    an unexpected skip. Extra argv entries are appended
    to the suite command.
    """
    try:
        selected = load(env=env, required=True)
    except ValueError as exc:
        print('candidate inputs: ' + str(exc), file=sys.stderr)
        raise SystemExit(2)
    atexit.register(selected.close)
    live = os.environ if env is None else env
    return _checked(suite, _run(suite, argv, live, selected),
                    live)


if __name__ == '__main__':
    try:
        if len(sys.argv) < 2:
            raise ValueError('one suite is required')
        sys.exit(dispatch(sys.argv[1], sys.argv[2:],
                          os.environ))
    except (ValueError, OSError) as exc:
        print('candidate inputs: ' + str(exc), file=sys.stderr)
        sys.exit(2)
