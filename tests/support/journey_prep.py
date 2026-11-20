#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fixture-prep phase for journey qualification.

Builds the journey test executables once, stages their
verified bytes into a fresh private directory under the
tool-owned staging root, and records the staged paths
plus SHA-256 digests,
so qualification can launch them directly without invoking
cargo. Each prep creates its own staging directory: a
previous stage is never reused or overwritten, and
symlinks anywhere in the staging path refuse. Usage:

    tests/support/journey_prep.py RECORD

RECORD is the JSON record file to write, under the
records subdir of the tool-owned prep directory
(MV_JOURNEY_PREP_DIR relocates it from the checkout
default); dispatch reads it through MV_JOURNEY_PREP.
The record
binds the checkout the executables were built from
(HEAD commit plus worktree digest), the dispatched
suite's build target, and the hashed staged bytes, so
the launcher can verify all four live. The checkout
must stay stable across the builds: identity is
recorded before the first build and re-verified after
the last, and any change refuses. Re-run after any
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
    checkout_identity, journey_identity_excludes, \
    journey_prep_dir, journey_records_dir, \
    journey_staging_root, refuse_symlinked_path, \
    refuse_unowned_prep_contents, resolve_journey_record

SCHEMA = 'memveil-journey-prep/1'

# Dispatch suite name to cargo test target.
TARGETS = {'deb': 'package_deb', 'rpm-journey': 'package_rpm'}


def _ensure_owned_dir(path):
    """Create a tool-owned directory; refuse links and aliases.

    The path and its parents must hold no symlink, both
    before and after creation; the result is re-verified
    as a real directory whose resolved path equals its
    spelled path, so a planted link can neither redirect
    tool outputs nor widen the identity exclusion onto
    source.
    """
    refuse_symlinked_path(path)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError(
            'staging directory unavailable: %s' % exc)
    refuse_symlinked_path(path)
    try:
        mode = os.lstat(path).st_mode
    except OSError as exc:
        raise ValueError(
            'staging directory unavailable: %s' % exc)
    if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
        raise ValueError(
            'staging path refuses symlink: %s' % path)
    if os.path.realpath(path) != str(path):
        raise ValueError(
            'staging path changed during prep: %s' % path)
    os.chmod(path, 0o700)


def _private_stage_dir(record_abs):
    """Create a fresh private stage under the owned root.

    The staging root (inside the tool-owned prep
    directory, derived through the shared helper) holds
    every stage for every record; each prep gets its own
    unique directory inside it (exclusive creation: the
    call fails rather than reusing an existing path), so
    a concurrent prep can never replace staged bytes
    between hashing and launch. The owned directories
    are verified as real directories, never links.
    Previous stages are never reused or overwritten:
    they stay under the root for operator cleanup.
    """
    _ensure_owned_dir(Path(journey_prep_dir()))
    root = Path(journey_staging_root())
    _ensure_owned_dir(root)
    try:
        staged_dir = Path(tempfile.mkdtemp(
            prefix=record_abs.stem + '-', suffix='.staged',
            dir=str(root)))
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
    it. The destination must stay under the stages root:
    a stage write aimed at the records subdir (or
    anywhere else) refuses instead of replacing tool
    outputs.
    """
    root = Path(journey_staging_root())
    if root not in Path(os.path.abspath(staged)).parents:
        raise ValueError(
            'fixture prep stages outside the stages '
            'directory: %s' % staged)
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
    swapped, never followed. Publication stays inside
    the records subdir of the tool-owned prep directory:
    a record path outside it refuses instead of
    scattering scratch beside user paths. A failed
    publish removes the temp file and refuses.
    """
    records = Path(journey_records_dir())
    parent = record_abs.parent
    if parent != records and records not in parent.parents:
        raise ValueError(
            'fixture prep publishes outside the records '
            'directory: %s' % record_abs)
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

    The record lives under the records subdir of the
    tool-owned prep directory (refused elsewhere);
    staged executables live under the sibling stages
    subdir. The tracked-content and tool-owned-content
    boundary checks run before any directory creation,
    mode change, or write: only a prep directory empty
    of tracked content and holding nothing outside
    tool-owned records, stages, and publication scratch
    proceeds to creation. Checkout identity is
    recorded before the first build and re-verified
    after the last: the two must agree, so an edit
    during prep refuses instead of mislabelling an older
    executable.
    The prep directory holding every record, stage, and
    publication scratch file is excluded wholesale from
    the digest through the exclusion list shared with
    the launcher, so both sides hash the identical
    source set.
    """
    if set(JOURNEY_SUITES) != set(TARGETS):
        raise ValueError(
            'prep targets differ from dispatched journey '
            'suites')
    record_abs = Path(resolve_journey_record(record_path))
    raw_abs = Path(os.path.abspath(record_path))
    excludes = journey_identity_excludes()
    refuse_unowned_prep_contents()
    _ensure_owned_dir(record_abs.parent)
    staged_dir = _private_stage_dir(record_abs)
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
