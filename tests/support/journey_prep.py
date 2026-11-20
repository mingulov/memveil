#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fixture-prep phase for journey qualification.

Builds the journey test executables once, stages their
verified bytes into an owned directory beside the record,
and records the staged paths plus SHA-256 digests, so
qualification can launch them directly without invoking
cargo. Usage:

    tests/support/journey_prep.py RECORD

RECORD is the JSON record file to write; dispatch reads it
through MV_JOURNEY_PREP. The record binds the checkout the
executables were built from (HEAD commit plus worktree
digest), the dispatched suite's build target, and the
hashed staged bytes, so the launcher can verify all four
live. The checkout must stay stable across the builds:
identity is recorded before the first build and re-verified
after the last, and any change refuses. Re-run after any
rebuild or checkout change: the launcher re-hashes the
staged bytes before exec and refuses stale records instead
of rebuilding. This is the only step that compiles: the
qualification path itself contains no cargo invocation.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
from support.candidate_suite import JOURNEY_SUITES, \
    checkout_identity

SCHEMA = 'memveil-journey-prep/1'

# Dispatch suite name to cargo test target.
TARGETS = {'deb': 'package_deb', 'rpm-journey': 'package_rpm'}


def build_executable(target):
    """Compile one test target without running it; return its path.

    Parses the executable cargo names (the same marker the
    installed-mapping legs use); refuses when cargo fails,
    names nothing, or names a missing file.
    """
    env = {key: value for key, value in os.environ.items()
           if key != 'RUSTUP_TOOLCHAIN'}
    proc = subprocess.run(
        ['cargo', 'test', '--locked', '--no-run',
         '--test', target],
        cwd=str(ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env)
    if proc.returncode != 0:
        raise ValueError(
            'fixture prep failed for %s: %s'
            % (target, proc.stderr[-2000:]))
    marker = 'Executable tests/%s.rs (' % target
    for line in proc.stdout.splitlines() \
            + proc.stderr.splitlines():
        line = line.strip()
        if line.startswith(marker) and line.endswith(')'):
            found = Path(line[len(marker):-1])
            if not found.is_absolute():
                found = ROOT / found
            if not found.is_file():
                raise ValueError(
                    'cargo named a missing test binary: %s'
                    % found)
            return found
    raise ValueError(
        'cargo named no test binary for %s' % target)


def prepare(record_path):
    """Build every journey suite; write the record file.

    Checkout identity is recorded before the first build
    and re-verified after the last: the two must agree, so
    an edit during prep refuses instead of mislabelling an
    older executable. The record file itself and the staged
    copies are excluded from the digest.
    """
    if set(JOURNEY_SUITES) != set(TARGETS):
        raise ValueError(
            'prep targets differ from dispatched journey '
            'suites')
    record_abs = Path(record_path).resolve()
    commit_before, tree_before = checkout_identity(
        exclude=[str(record_abs)])
    staged_dir = record_abs.parent \
        / (record_abs.stem + '.staged')
    staged_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(staged_dir, 0o700)
    suites = {}
    for suite in JOURNEY_SUITES:
        executable = build_executable(TARGETS[suite])
        data = executable.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        staged = staged_dir / TARGETS[suite]
        staged.write_bytes(data)
        os.chmod(staged, 0o700)
        if hashlib.sha256(staged.read_bytes()).hexdigest() \
                != digest:
            raise ValueError(
                'fixture prep staged copy differs: %s'
                % suite)
        suites[suite] = {'path': str(executable),
                         'staged': str(staged),
                         'sha256': digest,
                         'target': TARGETS[suite]}
        print('prep: %s -> %s sha256:%s'
              % (suite, staged, digest[:16]))
    staged_paths = [entry['staged']
                    for entry in suites.values()]
    commit_after, tree_after = checkout_identity(
        exclude=[str(record_abs)] + staged_paths)
    if commit_after != commit_before \
            or tree_after != tree_before:
        raise ValueError(
            'checkout changed during fixture prep; re-run '
            'tests/support/journey_prep.py')
    record = {'schema': SCHEMA, 'commit': commit_before,
              'tree': tree_before, 'suites': suites}
    Path(record_path).write_text(
        json.dumps(record, indent=2, sort_keys=True) + '\n')
    return record


def main(argv):
    if len(argv) != 2:
        print('usage: journey_prep.py RECORD',
              file=sys.stderr)
        return 2
    try:
        prepare(argv[1])
    except (ValueError, OSError) as exc:
        print('fixture prep: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
