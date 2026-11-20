#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fixture-prep phase for journey qualification.

Builds the journey test executables once, stages their
verified bytes into a fresh private directory beside the
record, and records the staged paths plus SHA-256 digests,
so qualification can launch them directly without invoking
cargo. Each prep creates its own staging directory: a
previous stage is never reused or overwritten, and
symlinks anywhere in the staging path refuse. Usage:

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
import stat
import tempfile
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
from support.candidate_suite import JOURNEY_SUITES, \
    checkout_identity, journey_identity_excludes

SCHEMA = 'memveil-journey-prep/1'

# Dispatch suite name to cargo test target.
TARGETS = {'deb': 'package_deb', 'rpm-journey': 'package_rpm'}


def _refuse_symlinked_path(path):
    """Refuse when any existing component of path is a symlink.

    Walks the unresolved absolute path from the leaf to the
    root with lstat, never following: a planted link
    anywhere along the staging path would redirect staged
    bytes outside the operator's directory. Missing
    components are skipped: the stage setup creates them as
    real directories and re-checks afterwards.
    """
    for candidate in (path, *path.parents):
        try:
            mode = os.lstat(candidate).st_mode
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ValueError(
                'staging path unavailable: %s' % exc)
        if stat.S_ISLNK(mode):
            raise ValueError(
                'staging path refuses symlink: %s' % candidate)


def _private_stage_dir(record_abs):
    """Create a fresh private staging directory beside the record.

    Each prep gets its own unique directory (exclusive
    creation: the call fails rather than reusing an
    existing path), so a concurrent prep can never replace
    staged bytes between hashing and launch. Symlinks
    anywhere in the staging path refuse, both before and
    after the parent setup; the created directory is
    re-verified as a real directory whose resolved path
    equals its spelled path. Previous stages are never
    reused or overwritten: they stay beside the record for
    operator cleanup.
    """
    parent = record_abs.parent
    _refuse_symlinked_path(parent)
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError(
            'staging directory unavailable: %s' % exc)
    _refuse_symlinked_path(parent)
    try:
        staged_dir = Path(tempfile.mkdtemp(
            prefix=record_abs.stem + '-', suffix='.staged',
            dir=str(parent)))
    except OSError as exc:
        raise ValueError(
            'staging directory unavailable: %s' % exc)
    try:
        mode = os.lstat(staged_dir).st_mode
    except OSError as exc:
        raise ValueError(
            'staging directory unavailable: %s' % exc)
    if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
        raise ValueError(
            'staging path refuses symlink: %s' % staged_dir)
    if os.path.realpath(staged_dir) != str(staged_dir):
        raise ValueError(
            'staging path changed during prep: %s'
            % staged_dir)
    os.chmod(staged_dir, 0o700)
    return staged_dir


def _stage_bytes(staged, data, suite):
    """Write staged bytes exactly once; refuse overwrite or alias.

    Exclusive creation fails when the path already exists,
    so a previous stage is never overwritten; no-follow
    refuses a planted symlink instead of writing through
    it.
    """
    try:
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT
                     | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    except FileExistsError:
        raise ValueError(
            'fixture prep refuses to overwrite staged '
            'executable: %s' % suite)
    except OSError as exc:
        raise ValueError(
            'fixture prep cannot stage executable %s: %s'
            % (suite, exc))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    except OSError as exc:
        raise ValueError(
            'fixture prep cannot stage executable %s: %s'
            % (suite, exc))
    os.chmod(staged, 0o700)


def _publish_record_atomically(raw_abs, record_abs, payload):
    """Publish the record through a same-directory temp file.

    The payload is fully written and fsynced to an
    exclusively created temp file in the record's own
    directory, then moved over the record path with
    os.replace: a concurrent launch reads the old record
    or the new one, never partial JSON. The unresolved
    path is replaced, so a planted leaf symlink is
    swapped, never followed. A failed publish removes
    the temp file and refuses.
    """
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=record_abs.name + '.', suffix='.tmp',
            dir=str(record_abs.parent))
    except OSError as exc:
        raise ValueError(
            'fixture prep cannot publish record: %s' % exc)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, raw_abs)
    except (OSError, ValueError) as exc:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise ValueError(
            'fixture prep cannot publish record: %s' % exc)


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
    copies are derived outputs excluded from the digest
    through the exclusion list shared with the launcher, so
    both sides hash the identical source set.
    """
    if set(JOURNEY_SUITES) != set(TARGETS):
        raise ValueError(
            'prep targets differ from dispatched journey '
            'suites')
    raw_abs = Path(os.path.abspath(record_path))
    _refuse_symlinked_path(raw_abs.parent)
    record_abs = raw_abs.resolve()
    staged_dir = _private_stage_dir(record_abs)
    planned = [str(staged_dir / TARGETS[suite])
               for suite in JOURNEY_SUITES]
    excludes = journey_identity_excludes(
        str(record_abs), planned)
    commit_before, tree_before = checkout_identity(
        exclude=excludes)
    suites = {}
    for suite in JOURNEY_SUITES:
        executable = build_executable(TARGETS[suite])
        data = executable.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        staged = staged_dir / TARGETS[suite]
        _stage_bytes(staged, data, suite)
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
    commit_after, tree_after = checkout_identity(
        exclude=excludes)
    if commit_after != commit_before \
            or tree_after != tree_before:
        raise ValueError(
            'checkout changed during fixture prep; re-run '
            'tests/support/journey_prep.py')
    record = {'schema': SCHEMA, 'commit': commit_before,
              'tree': tree_before, 'suites': suites}
    _publish_record_atomically(
        raw_abs, record_abs,
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
