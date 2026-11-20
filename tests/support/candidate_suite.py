#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Dispatch exact-candidate suites without product build fallbacks.

Journey suites launch prebuilt executables recorded by
tests/support/journey_prep.py (MV_JOURNEY_PREP names the
record); the qualification path itself never invokes a
build.
"""
import atexit
import hashlib
import json
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

# Journey suites launch prebuilt executables, never cargo:
# tests/support/journey_prep.py builds them once and
# records their paths, MV_JOURNEY_PREP names the record,
# and the launcher below re-hashes before exec.
JOURNEY_SUITES = ('deb', 'rpm-journey')

JOURNEY_PREP_SCHEMA = 'memveil-journey-prep/1'

# pytest files per dispatched pytest suite. Development
# fixture tests live in the same files but carry a
# deselecting marker (see tests/conftest.py), so the
# dispatched path runs zero builds; the selection tests
# consume these same lists, so selection and tests cannot
# drift.
PYTEST_SELECTIONS = {
    'package': ('tests/package/test_release_runtime.py',
                'tests/package/test_clean_runtime.py'),
    'release-runtime':
    ('tests/package/test_release_runtime.py',),
}


def pytest_dispatch_argv(*files):
    """pytest argv for one dispatched qualification selection."""
    return ['-m', 'pytest', *files, '-q', '-m',
            'qualification']


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


def _journey_record(live):
    """Validated prep record for the journey launcher.

    Refuses a missing, unreadable, or misshapen record
    instead of falling back to a build.
    """
    name = live.get('MV_JOURNEY_PREP', '')
    if not name:
        raise ValueError(
            'qualification needs prebuilt journey '
            'executables: run tests/support/journey_prep.py '
            'first (MV_JOURNEY_PREP unset)')
    try:
        with open(name, encoding='utf-8') as stream:
            record = json.load(stream)
    except (OSError, ValueError) as exc:
        raise ValueError(
            'journey prep record unreadable: %s' % exc)
    if not isinstance(record, dict) \
            or record.get('schema') != JOURNEY_PREP_SCHEMA \
            or not isinstance(record.get('suites'), dict):
        raise ValueError('journey prep record shape differs')
    return record['suites']


def _run_journey(suite, argv, live):
    """Launch one recorded journey executable directly.

    The recorded bytes are re-hashed before exec; a stale
    record, a missing or aliased executable, or digest
    drift refuses. No build invocation on this path.
    """
    entry = _journey_record(live).get(suite)
    if not isinstance(entry, dict) \
            or set(entry) != {'path', 'sha256'} \
            or not isinstance(entry['path'], str) \
            or not isinstance(entry['sha256'], str):
        raise ValueError(
            'journey prep record lacks suite: ' + suite)
    path = Path(entry['path'])
    if not path.is_absolute() or path.is_symlink() \
            or not path.is_file():
        raise ValueError(
            'recorded journey executable is not a plain '
            'file: ' + entry['path'])
    if not os.access(path, os.X_OK):
        raise ValueError(
            'recorded journey executable is not '
            'executable: ' + entry['path'])
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != entry['sha256']:
        raise ValueError(
            'recorded journey executable changed; re-run '
            'tests/support/journey_prep.py: ' + suite)
    env = dict(live)
    env['MV_VALID_EMPTY'] = str(
        ROOT / 'tests/package/valid-empty')
    env.pop('RUSTUP_TOOLCHAIN', None)
    return subprocess.run(
        [str(path), *argv], cwd=ROOT, env=env).returncode


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
    if suite in JOURNEY_SUITES:
        return _checked(
            suite, _run_journey(suite, argv, live), live)
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
        'release-runtime': pytest_dispatch_argv(
            *PYTEST_SELECTIONS['release-runtime']),
        'package': pytest_dispatch_argv(
            *PYTEST_SELECTIONS['package']),
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
    command = [sys.executable, *(commands[suite] + list(argv))]
    env = dict(live)
    env['MV_VALID_EMPTY'] = str(
        ROOT / 'tests/package/valid-empty')
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
