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
# tests/support/journey_prep.py builds them once, stages
# the verified bytes into an owned directory, and records
# the staged paths, MV_JOURNEY_PREP names the record, and
# the launcher below verifies checkout, suite, and staged
# bytes before exec plus executed-test evidence after.
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


def _git_lines(*argv):
    """Stdout lines of a read-only git query in this checkout.

    Refuses when git is absent or the query fails: checkout
    identity is load-bearing, never optional.
    """
    try:
        proc = subprocess.run(
            ['git', '-C', str(ROOT), *argv],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors='replace')
    except OSError as exc:
        raise ValueError(
            'checkout identity unavailable: %s' % exc)
    if proc.returncode != 0:
        raise ValueError(
            'checkout identity unavailable: git %s refused'
            % argv[0])
    return proc.stdout.split('\0')


def checkout_identity(exclude=()):
    """(commit, tree digest) binding this checkout's exact state.

    commit is HEAD; the tree digest is SHA-256 over the
    sorted worktree bytes (relpath plus file content) of
    every tracked and every untracked non-ignored file,
    so it binds the sources the recorded executables were
    built from, clean or dirty. Ignored build outputs never
    enter the digest. exclude holds absolute paths (the
    prep record itself) skipped by identity. Refuses when
    any listed file is unreadable. Shared with the prep
    tool, which imports it from here.
    """
    head = _git_lines('rev-parse', 'HEAD')[0].strip()
    if len(head) != 40 \
            or any(char not in '0123456789abcdef'
                   for char in head):
        raise ValueError('checkout identity unavailable')
    skip = {str(Path(name).resolve()) for name in exclude}
    names = []
    for args in (['ls-files', '-z'],
                 ['ls-files', '--others', '--exclude-standard',
                  '-z']):
        for entry in _git_lines(*args):
            if entry:
                names.append(entry)
    material = hashlib.sha256()
    for name in sorted(set(names)):
        if '/' in name and name.split('/')[0] in ('', '.', '..'):
            raise ValueError('checkout identity unavailable')
        full = ROOT / name
        if str(full.resolve()) in skip:
            continue
        try:
            with open(full, 'rb') as stream:
                content = stream.read()
        except OSError as exc:
            raise ValueError(
                'checkout identity unavailable: %s' % exc)
        material.update(name.encode('utf-8') + b'\0')
        material.update(content + b'\0')
    return head, material.hexdigest()


def _journey_record(live):
    """Validated prep record for the journey launcher.

    Refuses a missing, unreadable, or misshapen record
    instead of falling back to a build. Returns the
    (record, record path) pair: the launcher needs the
    path to exclude the record itself from checkout
    identity.
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
    commit = record.get('commit')
    if not isinstance(commit, str) or len(commit) != 40 \
            or any(char not in '0123456789abcdef'
                   for char in commit):
        raise ValueError('journey prep record shape differs')
    tree = record.get('tree')
    if not isinstance(tree, str) or len(tree) != 64 \
            or any(char not in '0123456789abcdef'
                   for char in tree):
        raise ValueError('journey prep record shape differs')
    if set(record) != {'schema', 'commit', 'tree', 'suites'}:
        raise ValueError('journey prep record shape differs')
    return record, name


def _require_harness_evidence(suite, stdout):
    """Refuse output without executed-test evidence.

    A genuine test-suite run prints the harness envelope
    (`running N tests` plus a `test result: ok.` summary)
    with one `... ok` line per executed check; a stub
    reporting bare success prints none of it. Requires at
    least one executed check, a passing summary with zero
    failures, and summary counts consistent with the
    executed lines. Raises ValueError otherwise.
    """
    import re
    running = [line for line in stdout.splitlines()
               if re.fullmatch(r'running (\d+) tests?', line)]
    if not running or int(running[0].split()[1]) < 1:
        raise ValueError(
            'journey suite produced no executed-test '
            'evidence: ' + suite)
    passed = [line for line in stdout.splitlines()
              if re.fullmatch(r'test \S+ \.\.\. ok', line)]
    summary = [line for line in stdout.splitlines()
               if re.match(r'test result: ok\. (\d+) passed; '
                           r'0 failed', line)]
    if not summary or int(summary[0].split()[3]) < 1 \
            or int(summary[0].split()[3]) != len(passed):
        raise ValueError(
            'journey suite produced no executed-test '
            'evidence: ' + suite)


def _run_journey(suite, argv, live):
    """Launch one recorded journey executable directly.

    The record must bind this checkout (commit plus tree
    digest recomputed live), the requested suite (the
    recorded build target must equal the dispatched
    suite's), and the staged executable bytes (re-hashed
    before exec); a stale record, a rebuilt-from-dirty
    checkout, a suite mixup, a missing or aliased staged
    executable, or digest drift refuses. The staged copy
    is the only executed path: the original build output
    is provenance only and is never resolved here. The
    run's own output must carry executed-test evidence
    (the load-bearing control: a stub reporting bare
    success has none). No build invocation on this path.

    Chain of custody: the prep tool builds each suite
    executable, stages the verified bytes into its owned
    directory, hashes the staged copy, binds the checkout
    state it built from, and writes the one record file
    this launcher reads back. A hand-written record never
    passes through the prep tool, so it can only name
    bytes the writer already holds; any substitution
    (another binary, a rebuilt checkout, a bare-success
    stub) breaks at least one verified binding. Residual:
    a local writer who hand-builds a binary, forges
    harness output inside it, and hand-writes a fully
    consistent record defeats file checks; that fraud is
    active (not a stale artifact) and re-running the prep
    tool exposes it (the honest record names different
    bytes).
    """
    from support.journey_prep import TARGETS
    record, name = _journey_record(live)
    entry = record['suites'].get(suite)
    if not isinstance(entry, dict) \
            or set(entry) \
            != {'path', 'staged', 'sha256', 'target'} \
            or not isinstance(entry['path'], str) \
            or not isinstance(entry['staged'], str) \
            or not isinstance(entry['sha256'], str) \
            or not isinstance(entry['target'], str):
        raise ValueError(
            'journey prep record lacks suite: ' + suite)
    if TARGETS.get(suite) != entry['target']:
        raise ValueError(
            'journey prep record names another suite\'s '
            'executable: ' + suite)
    staged = Path(entry['staged'])
    if not staged.is_absolute() or staged.is_symlink() \
            or not staged.is_file():
        raise ValueError(
            'recorded journey staged executable is not a '
            'plain file: ' + entry['staged'])
    if not os.access(staged, os.X_OK):
        raise ValueError(
            'recorded journey staged executable is not '
            'executable: ' + entry['staged'])
    digest = hashlib.sha256(staged.read_bytes()).hexdigest()
    if digest != entry['sha256']:
        raise ValueError(
            'recorded journey staged executable changed; '
            're-run tests/support/journey_prep.py: '
            + suite)
    commit, tree = checkout_identity(exclude=[name])
    if commit != record['commit'] or tree != record['tree']:
        raise ValueError(
            'checkout changed since fixture prep; re-run '
            'tests/support/journey_prep.py: ' + suite)
    env = dict(live)
    env['MV_VALID_EMPTY'] = str(
        ROOT / 'tests/package/valid-empty')
    env.pop('RUSTUP_TOOLCHAIN', None)
    proc = subprocess.run(
        [str(staged), *argv], cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, errors='replace')
    if proc.stdout:
        print(proc.stdout, end='', flush=True)
    if proc.stderr:
        print(proc.stderr, end='', file=sys.stderr, flush=True)
    if proc.returncode != 0:
        return proc.returncode
    _require_harness_evidence(suite, proc.stdout)
    return 0


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
