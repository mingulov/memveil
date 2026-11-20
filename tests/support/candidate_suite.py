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
import stat
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
    sorted worktree bytes of every tracked and every
    untracked non-ignored file, so it binds the sources
    the recorded executables were built from, clean or
    dirty: each entry hashes its relpath, its kind tag,
    and its bytes (file content, or the link target text
    for a symlink, so a link hashes as the link it is
    and never vanishes through its target). Ignored
    build outputs never enter the digest. exclude holds
    absolute paths skipped by identity, compared against
    the unresolved spelling of each listed path: an
    excluded directory skips its whole subtree lexically,
    so present and future files under it never enter the
    digest, while a link outside the set stays hashed
    wherever its target points. Refuses when any listed
    file is unreadable or is neither a plain file nor a
    link. Shared with the prep tool, which imports it
    from here.
    """
    head = _git_lines('rev-parse', 'HEAD')[0].strip()
    if len(head) != 40 \
            or any(char not in '0123456789abcdef'
                   for char in head):
        raise ValueError('checkout identity unavailable')
    skip = {os.path.abspath(entry) for entry in exclude}
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
        text = os.path.abspath(str(full))
        if any(text == entry
               or text.startswith(entry + os.sep)
               for entry in skip):
            continue
        try:
            mode = os.lstat(full).st_mode
        except OSError as exc:
            raise ValueError(
                'checkout identity unavailable: %s' % exc)
        if stat.S_ISLNK(mode):
            try:
                target = os.readlink(os.fsencode(full))
            except OSError as exc:
                raise ValueError(
                    'checkout identity unavailable: %s'
                    % exc)
            material.update(name.encode('utf-8') + b'\0')
            material.update(b'link\0' + target + b'\0')
            continue
        if not stat.S_ISREG(mode):
            raise ValueError(
                'checkout identity unavailable: %s' % name)
        try:
            with open(full, 'rb') as stream:
                content = stream.read()
        except OSError as exc:
            raise ValueError(
                'checkout identity unavailable: %s' % exc)
        material.update(name.encode('utf-8') + b'\0')
        material.update(b'file\0' + content + b'\0')
    return head, material.hexdigest()


# Tool-owned output directory holding every
# fixture-prep record, stage, and publication scratch
# file. Prep writes only here, launch reads only here,
# and checkout identity excludes the directory
# wholesale, so any number of records coexist without
# invalidating each other, and scratch never reads as
# source. The default lives under the checkout root;
# MV_JOURNEY_PREP_DIR relocates it.
JOURNEY_PREP_DIRNAME = '.candidate-prep'
JOURNEY_RECORDS_DIRNAME = 'records'
JOURNEY_STAGES_DIRNAME = 'stages'


def journey_prep_dir():
    """Absolute path of the tool-owned prep directory.

    The single location for fixture-prep outputs; both
    the prep tool and the launcher derive it through
    this one function, never by recomputing the name.
    MV_JOURNEY_PREP_DIR overrides the checkout default
    with an absolute path (checked link-free on its
    unresolved spelling, then resolved before use);
    empty or unset keeps the default. Refuses a relative
    override, any symlink along the override, or an
    override covering the checkout itself: tool outputs
    must never scatter beside user paths or swallow
    versioned source from identity. The cover check
    compares resolved paths component-wise, so every
    ancestor of the checkout refuses, including the
    filesystem root.
    """
    override = os.environ.get('MV_JOURNEY_PREP_DIR')
    if not override:
        return str(ROOT / JOURNEY_PREP_DIRNAME)
    if not os.path.isabs(override):
        raise ValueError(
            'journey prep directory must be absolute: %s'
            % override)
    refuse_symlinked_path(Path(override))
    candidate = Path(override).resolve()
    root = ROOT.resolve()
    if candidate == root \
            or candidate in root.parents:
        raise ValueError(
            'journey prep directory must not cover the '
            'checkout: %s' % override)
    return str(candidate)


def journey_records_dir():
    """Records subdir inside the tool-owned prep directory.

    Every prep record lives under this one directory;
    staged executables live under the sibling stages
    root instead. Prep and launch derive the same path
    through this one function, never by recomputing the
    name; a record destination anywhere else refuses.
    """
    return str(Path(journey_prep_dir())
               / JOURNEY_RECORDS_DIRNAME)


def journey_staging_root():
    """Staging root inside the tool-owned prep directory.

    Every prep stage for every record lives under this
    one directory, so excluding the prep directory keeps
    all present and future stages out of checkout
    identity. The prep tool creates its fresh stage
    inside it; prep and launch derive the same path
    through this one function, never by recomputing the
    name.
    """
    return str(Path(journey_prep_dir())
               / JOURNEY_STAGES_DIRNAME)


def refuse_symlinked_path(path):
    """Refuse when any existing component of path is a symlink.

    Walks the raw path from the leaf to the root with
    lstat, never following: a planted link anywhere
    along the path would redirect tool outputs outside
    the operator's directory. The path is walked exactly
    as spelled, since callers must never normalize it
    first: collapsing dot-dot textually can hide a
    traversed link. Relative paths resolve against the
    current directory for the walk. Missing components
    are skipped: the setup creates them as real
    directories and re-checks afterwards. Shared with
    the prep tool, which imports it from here.
    """
    if not path.is_absolute():
        path = Path.cwd() / path
    for candidate in (path, *path.parents):
        try:
            mode = os.lstat(candidate).st_mode
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ValueError(
                'path unavailable: %s' % exc)
        if stat.S_ISLNK(mode):
            raise ValueError(
                'refuses symlink: %s' % candidate)


def resolve_journey_record(name):
    """Validate a prep record path; return its absolute form.

    The record must live under the records subdir of the
    tool-owned prep directory (staged executables live
    under the sibling stages subdir instead), so records,
    stages, and publication scratch share the one
    excluded location while staying disjoint. The
    destination must end in .json, matching the records
    the checks accept, so the publish path can never
    emit a record the next check rejects. Refuses an
    empty name, a non-JSON name, a symlink at the record
    path itself or any parent component, and any
    destination outside the records subdir. Both the
    prep tool and the launcher validate through this
    one function, before any staging, exclusion, or
    publication step derives paths from the record.
    """
    if not name:
        raise ValueError(
            'journey prep record must live under %s'
            % JOURNEY_RECORDS_DIRNAME)
    if not name.endswith('.json'):
        raise ValueError(
            'journey prep record must be a JSON record '
            'under %s: %s'
            % (JOURNEY_RECORDS_DIRNAME, name))
    raw = Path(name)
    refuse_symlinked_path(raw)
    resolved = raw.resolve()
    if Path(journey_records_dir()) not in resolved.parents:
        raise ValueError(
            'journey prep record must live under %s: %s'
            % (JOURNEY_RECORDS_DIRNAME, name))
    return str(resolved)


def journey_identity_excludes():
    """Checkout-identity exclusion set shared by prep and launch.

    The tool-owned prep directory holds every record,
    stage, and publication scratch file, so excluding it
    wholesale keeps all present and future prep outputs
    out of the checkout digest: a freshly prepared
    record verifies instead of self-invalidating, a
    repeat prep sees no earlier output, and deleting a
    retired stage keeps the current record valid. Both
    sides call this one function; no duplicated lists
    to drift. Refuses when the effective directory holds
    tracked files: the exclusion must never mask
    versioned source, even force-added.
    """
    top = journey_prep_dir()
    rel = os.path.relpath(top, str(ROOT))
    if rel != '.' and rel != '..' \
            and not rel.startswith('..' + os.sep):
        tracked = [entry for entry in _git_lines(
            'ls-files', '-z', '--', rel)
            if entry]
        if tracked:
            raise ValueError(
                'journey prep directory holds tracked '
                'files; refusing: %s' % tracked[0])
    return [top]


def refuse_unowned_prep_contents():
    """Refuse prep content outside valid tool-owned shape.

    The one prep shape validator shared by the publish
    path and every check path: the prep tool runs it
    before any write, and the launcher runs the
    identical function before exec, so a record the
    publisher emits can never be one the checks reject.
    The prep directory holds only the records and
    stages subdirs. Under records, every JSON file must
    parse as a valid prep record through the shape
    predicate shared with the launcher; anything not a
    record or publication scratch refuses (notably
    untracked source inside an in-checkout override,
    which would vanish from checkout identity through
    the wholesale exclusion). Publication scratch
    (<record>.<random>.tmp) is judged by its name
    pattern alone: it is partial JSON by nature (a temp
    file may hold a torn write), so content checks
    cannot apply, and safety comes from nonconforming
    siblings refusing plus the launcher re-validating
    its own record before exec. Under stages, every
    stage directory holds only staged executables, and
    a staged file whose path some valid record
    references must hash to a digest some valid record
    references; anything else refuses. Files no record
    binds (a stage mid-publish, a retired stage awaiting
    operator cleanup) are inert, since launch reads only
    referenced paths and re-hashes them, so they refuse
    nowhere here. The prep directory's own components
    are verified link-free before the scan. A missing
    directory is fine: the prep tool creates it. Entries
    are judged without following links, and link safety
    stays with the checks consuming each path.
    """
    from support.journey_prep import TARGETS
    top = Path(journey_prep_dir())
    refuse_symlinked_path(top)
    try:
        mode = os.lstat(top).st_mode
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ValueError(
            'journey prep directory unavailable: %s' % exc)
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise ValueError(
            'journey prep directory is not a directory: '
            '%s' % top)
    staged_names = set(TARGETS.values())
    referenced_paths = set()
    referenced_digests = set()

    def refuse(entry):
        raise ValueError(
            'journey prep directory holds content outside '
            'tool-owned records and stages; refusing: %s'
            % entry)

    def children(directory):
        try:
            with os.scandir(directory) as scanner:
                return list(scanner)
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise ValueError(
                'journey prep directory unreadable: %s'
                % exc)

    def kind(entry):
        try:
            mode = os.lstat(entry.path).st_mode
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ValueError(
                'journey prep directory unreadable: %s'
                % exc)
        if stat.S_ISLNK(mode):
            return 'link'
        if stat.S_ISDIR(mode):
            return 'dir'
        if stat.S_ISREG(mode):
            return 'file'
        return 'other'

    def real_dir(path):
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise ValueError(
                'journey prep directory unreadable: %s'
                % exc)
        return stat.S_ISDIR(mode)

    def check_record_file(path):
        try:
            with open(path, encoding='utf-8') as stream:
                record = json.load(stream)
        except (OSError, ValueError) as exc:
            raise ValueError(
                'journey prep directory holds a prep '
                'record that fails to parse: %s (%s)'
                % (path, exc))
        reason = _prep_record_shape_error(record)
        if reason is not None:
            raise ValueError(
                'journey prep directory holds a prep '
                'record with an invalid shape: %s (%s)'
                % (path, reason))
        for entry in record['suites'].values():
            if not isinstance(entry, dict):
                continue
            staged = entry.get('staged')
            if isinstance(staged, str):
                referenced_paths.add(os.path.abspath(staged))
            digest = entry.get('sha256')
            if isinstance(digest, str):
                referenced_digests.add(digest)

    def staged_digest(path):
        try:
            with open(path, 'rb') as stream:
                return hashlib.sha256(
                    stream.read()).hexdigest()
        except OSError as exc:
            raise ValueError(
                'journey prep directory holds unreadable '
                'staged bytes: %s (%s)' % (path, exc))

    def check_records(directory):
        for child in children(directory):
            entry_kind = kind(child)
            if entry_kind is None:
                continue
            if entry_kind == 'dir':
                check_records(child.path)
            elif entry_kind == 'link' \
                    and (child.name.endswith('.json')
                         or child.name.endswith('.tmp')):
                continue
            elif entry_kind == 'file' \
                    and child.name.endswith('.tmp'):
                continue
            elif entry_kind == 'file' \
                    and child.name.endswith('.json'):
                check_record_file(child.path)
            else:
                refuse(child.path)

    def check_stage(directory):
        for child in children(directory):
            entry_kind = kind(child)
            if entry_kind is None:
                continue
            if entry_kind not in ('file', 'link') \
                    or child.name not in staged_names:
                refuse(child.path)
            if entry_kind == 'link':
                continue
            if os.path.abspath(child.path) \
                    not in referenced_paths:
                continue
            if staged_digest(child.path) \
                    not in referenced_digests:
                raise ValueError(
                    'journey prep directory holds staged '
                    'bytes matching no digest referenced '
                    'by any valid prep record: %s'
                    % child.path)

    def check_stages(directory):
        for child in children(directory):
            entry_kind = kind(child)
            if entry_kind is None:
                continue
            if not child.name.endswith('.staged'):
                refuse(child.path)
            if entry_kind == 'dir':
                check_stage(child.path)
            elif entry_kind != 'link':
                refuse(child.path)

    for child in children(top):
        if child.name not in (JOURNEY_RECORDS_DIRNAME,
                              JOURNEY_STAGES_DIRNAME):
            refuse(child.path)
        if kind(child) not in ('dir', 'link'):
            refuse(child.path)
    if real_dir(top / JOURNEY_RECORDS_DIRNAME):
        check_records(str(top / JOURNEY_RECORDS_DIRNAME))
    if real_dir(top / JOURNEY_STAGES_DIRNAME):
        check_stages(str(top / JOURNEY_STAGES_DIRNAME))


def _prep_record_shape_error(record):
    """Prep-record shape reason; None when valid.

    The one prep-record shape predicate shared by the
    publish path and every check path: the launcher
    validates its own record through it, and the
    prep-directory validator applies it to every record
    file present, so no forked copy can drift. Mirrors
    the prep record writer exactly: the schema tag, the
    40-hex HEAD commit and 64-hex tree digest bindings,
    and the per-suite table. Suite entry shapes stay
    with the launcher: a record whose entries are
    misshapen still parses here and refuses at dispatch
    with the suite error, never silently.
    """
    if not isinstance(record, dict) \
            or record.get('schema') != JOURNEY_PREP_SCHEMA \
            or not isinstance(record.get('suites'), dict):
        return 'schema or suite table differs'
    commit = record.get('commit')
    if not isinstance(commit, str) or len(commit) != 40 \
            or any(char not in '0123456789abcdef'
                   for char in commit):
        return 'commit binding differs'
    tree = record.get('tree')
    if not isinstance(tree, str) or len(tree) != 64 \
            or any(char not in '0123456789abcdef'
                   for char in tree):
        return 'tree binding differs'
    if set(record) != {'schema', 'commit', 'tree', 'suites'}:
        return 'record keys differ'
    return None


def _journey_record(live):
    """Validated prep record for the journey launcher.

    Refuses a missing, misplaced, unreadable, or
    misshapen record instead of falling back to a build.
    Returns the record.
    """
    name = live.get('MV_JOURNEY_PREP', '')
    if not name:
        raise ValueError(
            'qualification needs prebuilt journey '
            'executables: run tests/support/journey_prep.py '
            'first (MV_JOURNEY_PREP unset)')
    resolved = resolve_journey_record(name)
    try:
        with open(resolved, encoding='utf-8') as stream:
            record = json.load(stream)
    except (OSError, ValueError) as exc:
        raise ValueError(
            'journey prep record unreadable: %s' % exc)
    if _prep_record_shape_error(record) is not None:
        raise ValueError('journey prep record shape differs')
    return record


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
    executable, an executable outside the stages
    directory, or digest drift refuses. The staged path
    must be a regular file with every path component
    link-free (links refuse outright, never followed),
    normalizing strictly inside the configured stages
    tree (itself link-free at every component): a digest
    match alone never authorizes an outside path. The
    tool-owned
    prep directory holding every record, stage, and
    publication scratch file is excluded wholesale from
    the digest through the exclusion list shared with
    the prep tool, so both sides hash the identical
    source set. The staged copy is the only
    executed path: the original build output is
    provenance only and is never resolved here. The run's
    own output must carry executed-test evidence
    (the load-bearing control: a stub reporting bare
    success has none). No build invocation on this path.

    Chain of custody: the prep tool builds each suite
    executable, stages the verified bytes into its owned
    directory, hashes the staged copy, binds the checkout
    state it built from, and writes one record file under
    the owned directory; this launcher reads it back. A
    hand-written record never
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
    record = _journey_record(live)
    refuse_unowned_prep_contents()
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
    if not staged.is_absolute():
        raise ValueError(
            'recorded journey staged executable is not a '
            'plain file: ' + entry['staged'])
    try:
        mode = os.lstat(staged).st_mode
    except OSError:
        raise ValueError(
            'recorded journey staged executable is not a '
            'plain file: ' + entry['staged'])
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise ValueError(
            'recorded journey staged executable is not a '
            'plain file: ' + entry['staged'])
    refuse_symlinked_path(staged)
    stages_root = Path(journey_staging_root())
    refuse_symlinked_path(stages_root)
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
    if stages_root not in Path(
            os.path.abspath(entry['staged'])).parents:
        raise ValueError(
            'recorded journey staged executable is outside '
            'the stages directory; re-run '
            'tests/support/journey_prep.py: ' + suite)
    commit, tree = checkout_identity(
        exclude=journey_identity_excludes())
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
