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
back to the build tree. Guests receive the candidate env,
resolve BPF under the verified root, and refuse a digest
mismatch before any guest work.
"""
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import uuid
from test_candidate_input import sealed, api
import pytest
ROOT = Path(__file__).resolve().parents[2]

PARTIAL_SUITES = ['perf-replay', 'perf-region', 'soak',
                  'fuzz-smoke', 'fuzz-campaign', 'privacy',
                  'extracted-robustness', 'package', 'deb',
                  'rpm-journey', 'release-runtime', 'perf-overhead',
                  'perf-workload', 'vm-live-soak', 'vm-kernels',
                  'vm-scenarios']
# NOTE: keep in sync with the candidate-mode suite list in tools/test;
# a newly routed suite must be added here or its partial-input refusal
# goes unpinned.
assert len(PARTIAL_SUITES) == 16


def candidate_clean_env():
    return {key: value for key, value in os.environ.items()
            if key not in api().OVERRIDES
            and not key.startswith('MEMVEIL_TEST_')}


def _prep_record_path(tag):
    """Unique record path in the prep dir's records subdir."""
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_records_dir
    return Path(journey_records_dir()) / (
        '%s-%d-%s.json'
        % (tag, os.getpid(), uuid.uuid4().hex[:8]))


def _staged_state():
    """Byte-stable staged-change summary of the live index.

    Captured before a test body that must leave the index
    alone and compared after: the index must be unchanged,
    whatever it held before, so pre-existing staged work
    never reads as test contamination. Honors
    GIT_INDEX_FILE like every git query, so index-copy
    checks read the copy.
    """
    result = subprocess.run(
        ['git', '-C', str(ROOT), 'diff', '--cached',
         '--name-status', '-z'],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.fixture(autouse=True)
def _private_journey_prep_root(tmp_path, monkeypatch):
    """Point the prep root at a private tmp dir for one test.

    No test in this file may create, delete, or move
    anything under the operator's real prep directory:
    every prep-root-touching path derives from the
    override below, which resolves under this test's own
    tmp_path. Tests needing tracked content relocate the
    override to a fresh in-checkout path instead (never
    the real directory).
    """
    root = tmp_path / 'prep-root'
    monkeypatch.setenv('MV_JOURNEY_PREP_DIR', str(root))
    yield root
    shutil.rmtree(root, ignore_errors=True)
    if root.is_symlink():
        root.unlink(missing_ok=True)


@pytest.mark.parametrize('suite', PARTIAL_SUITES)
@pytest.mark.parametrize('present,missing', [
    ('MV_BUNDLE_TARBALL', 'MV_CANDIDATE_MANIFEST'),
    ('MV_CANDIDATE_MANIFEST', 'MV_BUNDLE_TARBALL'),
])
def test_partial_input_refuses_pre_build(suite, present, missing,
                                         tmp_path):
    env = dict(os.environ, **{present: str(tmp_path / 'missing')})
    env.pop(missing, None)
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


def test_armed_soak_without_inputs_fails():
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('MV_CANDIDATE', 'MV_BUNDLE',
                                   'MEMVEIL_VM_'))}
    env['MEMVEIL_VM_LIVE_SOAK'] = '1'
    result = subprocess.run(
        [str(ROOT / 'tools/test'), 'vm-live-soak'],
        env=env, capture_output=True, text=True)
    assert result.returncode == 1
    assert 'FAIL' in result.stdout + result.stderr
    assert '77' not in result.stdout + result.stderr


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


def test_perf_workload_derouted_skips_with_reason(sealed):
    environment = candidate_clean_env()
    environment.update(sealed)
    result = subprocess.run(
        [sys.executable,
         str(ROOT / 'tests/support/candidate_suite.py'),
         'perf-workload'],
        env=environment, capture_output=True, text=True,
        timeout=120)
    combined = result.stdout + result.stderr
    assert result.returncode == 77, combined
    assert 'mv_consume' in combined and 'bridge' in combined \
        and 'oracle ko' in combined, combined
    assert '[deferred]' in combined, combined
    assert re.search(r'MV\d+-\d+', combined) is None, combined
    assert 'perf-workload:' not in combined, \
        'de-routed suite executed its runner'


def test_unarmed_dispatch_skip_preserved(sealed):
    environment = {key: value
                   for key, value in candidate_clean_env().items()
                   if not key.startswith('MEMVEIL_VM_')}
    environment.update(sealed)
    result = subprocess.run(
        [sys.executable,
         str(ROOT / 'tests/support/candidate_suite.py'),
         'vm-kernels'],
        env=environment, capture_output=True, text=True,
        timeout=120)
    combined = result.stdout + result.stderr
    assert result.returncode == 77, combined
    assert 'SKIP' in combined, combined
    assert 'FAIL' not in combined, combined


def test_unarmed_runner_skip_preserved_end_to_end(sealed):
    environment = {key: value
                   for key, value in candidate_clean_env().items()
                   if not key.startswith('MEMVEIL_VM_')}
    environment.update(sealed)
    result = subprocess.run(
        [sys.executable,
         str(ROOT / 'tests/support/candidate_suite.py'),
         'vm-live-soak'],
        env=environment, capture_output=True, text=True,
        timeout=120)
    combined = result.stdout + result.stderr
    assert result.returncode == 77, combined
    assert 'SKIP' in combined, combined
    assert 'FAIL' not in combined, combined


def test_armed_unexpected_skip_fails(sealed, monkeypatch,
                                     capsys):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support import candidate_suite as dispatch_mod
    from support import candidate_input
    for key in list(os.environ):
        if key in candidate_input.OVERRIDES \
                or key.startswith(
                    ('MEMVEIL_VM_', 'MEMVEIL_TEST_')):
            monkeypatch.delenv(key, raising=False)
    for key, value in sealed.items():
        monkeypatch.setenv(key, value)
    from types import SimpleNamespace
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=77)
    monkeypatch.setattr(dispatch_mod.subprocess, 'run',
                        fake_run)
    # Unarmed: the matrix lane never executes and 77 passes.
    assert dispatch_mod.dispatch(
        'vm-kernels', [], dict(os.environ)) == 77
    assert calls == []
    # Armed: the lane executes, and its 77 fails.
    monkeypatch.setenv('MEMVEIL_VM_KERNELS', '1')
    assert dispatch_mod.dispatch(
        'vm-kernels', [], dict(os.environ)) == 1
    assert len(calls) == 1
    assert 'kernel-matrix' in calls[0][1]
    assert 'after arming' in capsys.readouterr().err
    # A suite with no arming variable fails any 77.
    assert dispatch_mod.dispatch(
        'perf-replay', [], dict(os.environ)) == 1
    assert 'deferral' in capsys.readouterr().err


def test_deferred_allowlist_shape_validated():
    sys.path.insert(0, str(ROOT / 'tests'))
    from support import deferred_skips as ds
    from types import SimpleNamespace
    ds.validate()
    entry = ds.lookup('perf-workload')
    assert set(entry) == {'suite', 'reason', 'nodes'}
    assert entry['nodes'] == []
    assert ds.lookup('vm-kernels') is None
    good = [{'suite': 'x', 'reason': 'r',
             'nodes': ['n1', 'n2']}]
    ds.validate(good)
    bad_lists = [
        [{'suite': 'x', 'reason': 'r'}],
        [{'suite': 'x', 'reason': 'r', 'nodes': [],
          'owning-card': 'y'}],
        [{'suite': '', 'reason': 'r', 'nodes': []}],
        [{'suite': 'x', 'reason': '  ', 'nodes': []}],
        [{'suite': 'x', 'reason': 'r',
          'nodes': 'n1'}],
        [{'suite': 'x', 'reason': 'r', 'nodes': ['']}],
        [{'suite': 'x', 'reason': 'r',
          'nodes': ['n1', 'n1']}],
        [{'suite': 'x', 'reason': 'r', 'nodes': [1]}],
        [dict(entry), dict(entry)],
        'not-a-list',
    ]
    for bad in bad_lists:
        with pytest.raises(ValueError):
            ds.validate(bad)
    assert ds.skip_reason(SimpleNamespace(
        longrepr=('f', 1, 'Skipped: ' + entry['reason']))) \
        == entry['reason']
    assert ds.skip_reason(SimpleNamespace(
        longrepr=('f', 1, 'Skipped'))) is None
    assert ds.skip_reason(
        SimpleNamespace(longrepr='weird')) is None

    def report(nodeid, reason):
        return SimpleNamespace(
            nodeid=nodeid,
            longrepr=('f', 1, 'Skipped: ' + reason))
    # Exemption needs the exact node plus the exact
    # reason; either half failing keeps the skip unlisted.
    assert ds.unlisted_skips(
        [report('n1', 'r')], good) == []
    assert ds.unlisted_skips(
        [report('n3', 'r')], good) != []
    assert ds.unlisted_skips(
        [report('n1', 'other')], good) != []
    assert ds.unlisted_skips(
        [report('n1', 'r')]) != []
    assert ds.unlisted_skips(
        [report('a', 'nope')]) != []


def test_conftest_refuses_same_reason_unlisted_node(
        sealed, tmp_path):
    import json
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.deferred_skips import lookup
    reason = lookup('perf-workload')['reason']
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['PYTHONPATH'] = str(ROOT / 'tests') + (
        os.pathsep + environment['PYTHONPATH']
        if environment.get('PYTHONPATH') else '')
    shutil.copy(str(ROOT / 'tests/package/conftest.py'),
                tmp_path / 'conftest.py')
    (tmp_path / 'test_same_reason_skip.py').write_text(
        'import pytest\n'
        'pytestmark = pytest.mark.skip(reason='
        + json.dumps(reason) + ')\n'
        'def test_skip():\n'
        '    pass\n')
    result = subprocess.run(
        [sys.executable, '-m', 'pytest',
         'test_same_reason_skip.py', '-q', '-p',
         'no:cacheprovider'],
        env=environment, capture_output=True, text=True,
        cwd=tmp_path)
    combined = result.stdout + result.stderr
    assert 'skipped' in result.stdout, combined
    assert result.returncode == 1, combined
    assert 'unlisted' in combined, combined


def test_perf_workload_docs_deferred():
    text = (ROOT / 'docs' / 'performance.md').read_text()
    flat = ' '.join(text.split())
    assert '`perf-workload` is DEFERRED ' \
        'under qualification inputs' in flat
    assert 'never executes against candidate bytes' in flat
    at = flat.index('consume the selected bytes')
    sentence = flat[flat.rfind('.', 0, at) + 1:
                   flat.index('.', at)]
    assert 'perf-workload' not in sentence, \
        'docs advertise candidate execution for a ' \
        'deferred suite'


def _shadow_cargo_bin(tmp_path):
    """PATH dir whose cargo stub fails loudly, leaving a sentinel."""
    bindir = tmp_path / 'shadowbin'
    bindir.mkdir()
    sentinel = tmp_path / 'cargo-invoked'
    stub = bindir / 'cargo'
    stub.write_text(
        '#!/bin/sh\necho CARGO-SHADOWED-STUB >&2\n'
        'touch "%s"\nexit 99\n' % sentinel)
    stub.chmod(0o755)
    return str(bindir), str(sentinel)


def test_journey_prep_records_executables(tmp_path):
    import hashlib
    import json
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import JOURNEY_SUITES, \
        checkout_identity, journey_identity_excludes, \
        journey_prep_dir
    from support.journey_prep import TARGETS
    record = _prep_record_path('prep')
    result = subprocess.run(
        [sys.executable,
         str(ROOT / 'tests/support/journey_prep.py'),
         str(record)],
        capture_output=True, text=True, timeout=900,
        cwd=str(ROOT))
    assert result.returncode == 0, result.stderr[-2000:]
    doc = json.loads(record.read_text())
    assert doc['schema'] == 'memveil-journey-prep/1'
    assert set(doc) == {'schema', 'commit', 'tree', 'suites'}
    assert set(doc['suites']) == set(JOURNEY_SUITES)
    commit, tree = checkout_identity(
        exclude=journey_identity_excludes())
    assert doc['commit'] == commit
    assert doc['tree'] == tree
    top = Path(journey_prep_dir())
    assert top in record.resolve().parents
    for entry in doc['suites'].values():
        assert top in Path(entry['staged']).resolve().parents
    for suite, entry in doc['suites'].items():
        assert set(entry) == {
            'path', 'staged', 'sha256', 'target'}, suite
        assert entry['target'] == TARGETS[suite], suite
        exe = Path(entry['path'])
        assert exe.is_absolute(), suite
        assert exe.is_file() and not exe.is_symlink(), suite
        staged = Path(entry['staged'])
        assert staged.is_absolute(), suite
        assert staged.is_file() \
            and not staged.is_symlink(), suite
        assert os.access(staged, os.X_OK), suite
        assert hashlib.sha256(staged.read_bytes()).hexdigest() \
            == entry['sha256'], suite
        assert hashlib.sha256(exe.read_bytes()).hexdigest() \
            == entry['sha256'], suite


def test_journey_dispatch_never_invokes_cargo():
    text = (ROOT / 'tests/support/candidate_suite.py') \
        .read_text()
    assert 'JOURNEY_SUITES' in text
    assert '_run_journey' in text
    assert '"cargo"' not in text, \
        'qualification dispatch must not name cargo'
    assert "'cargo'" not in text, \
        'qualification dispatch must not name cargo'


def _journey_stub_record(tmp_path, script, suite='deb'):
    """Hand-written prep-shaped record for one stub script."""
    import hashlib
    import json
    import shutil
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import checkout_identity, \
        journey_identity_excludes, journey_staging_root
    from support.journey_prep import TARGETS
    stub = tmp_path / ('stub-' + suite)
    stub.write_text(script)
    stub.chmod(0o755)
    staged_dir = Path(journey_staging_root()) / (
        'stub-%s-%d-%s.staged'
        % (suite, os.getpid(), uuid.uuid4().hex[:8]))
    staged_dir.mkdir(parents=True)
    staged = staged_dir / TARGETS[suite]
    shutil.copyfile(stub, staged)
    staged.chmod(0o755)
    record_path = _prep_record_path('stub-' + suite)
    record_path.parent.mkdir(parents=True, exist_ok=True)
    commit, tree = checkout_identity(
        exclude=journey_identity_excludes())
    record_path.write_text(json.dumps(
        {'schema': 'memveil-journey-prep/1',
         'commit': commit, 'tree': tree,
         'suites': {suite: {
             'path': str(stub),
             'staged': str(staged),
             'sha256': hashlib.sha256(
                 staged.read_bytes()).hexdigest(),
             'target': TARGETS[suite]}}}))
    return stub, staged, record_path


def _launch_journey(suite, environment, *argv):
    return subprocess.run(
        [sys.executable,
         str(ROOT / 'tests/support/candidate_suite.py'),
         suite, *argv],
        env=environment, capture_output=True,
        text=True, timeout=120)


def test_journey_launcher_runs_recorded_binary(sealed,
                                               tmp_path):
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    stub, staged, record_path = _journey_stub_record(
        tmp_path, harness)
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record_path)

    def launched(suite):
        return _launch_journey(suite, environment)

    result = launched('deb')
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert 'journey-marker' in result.stdout, combined
    assert '1 passed' in combined, combined
    result = launched('rpm-journey')
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'lacks suite' in combined, combined
    with staged.open('ab') as stream:
        stream.write(b'# tampered\n')
    result = launched('deb')
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    # Tampered bytes match no digest any valid record
    # references, so the shared prep-directory validator
    # refuses before launch; the launch-time digest
    # refusal stays pinned by the lying-record test.
    assert 'matching no digest referenced' in combined, \
        combined
    bare = {key: value for key, value in environment.items()
            if key != 'MV_JOURNEY_PREP'}
    result = subprocess.run(
        [sys.executable,
         str(ROOT / 'tests/support/candidate_suite.py'),
         'deb'],
        env=bare, capture_output=True, text=True,
        timeout=120)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'journey_prep.py' in combined, combined


def test_journey_launcher_refuses_bare_success_stub(sealed,
                                                   tmp_path):
    # A stub that exits 0 with bare output (no harness
    # envelope, no executed checks) refuses even though
    # its record fields are fully consistent.
    stub, staged, record_path = _journey_stub_record(
        tmp_path, '#!/bin/sh\necho journey-marker\n')
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record_path)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'executed-test evidence' in combined, combined
    # A forged envelope with zero executed checks refuses
    # too: the summary must claim a positive count that
    # matches the executed lines.
    forged = ('#!/bin/sh\necho "running 0 tests"\n'
              'echo "test result: ok. 0 passed; 0 failed; '
              '0 ignored; 0 measured; 0 filtered out"\n')
    staged.write_text(forged)
    import hashlib
    import json
    record = json.loads(record_path.read_text())
    record['suites']['deb']['sha256'] = hashlib.sha256(
        staged.read_bytes()).hexdigest()
    record_path.write_text(json.dumps(record))
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'executed-test evidence' in combined, combined


def test_journey_honest_prep_and_launch_accepts(sealed,
                                                tmp_path):
    # The prep tool's own record launches green: checkout,
    # suite, and bytes verify, and the real run carries
    # executed-test evidence. A unit filter keeps the leg
    # fast and sudo-free.
    record = _prep_record_path('prep')
    result = subprocess.run(
        [sys.executable,
         str(ROOT / 'tests/support/journey_prep.py'),
         str(record)],
        capture_output=True, text=True, timeout=900,
        cwd=str(ROOT))
    assert result.returncode == 0, result.stderr[-2000:]
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record)
    result = _launch_journey('deb', environment,
                             'journey_gate_matrix')
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert '1 passed' in combined, combined
    assert '0 failed' in combined, combined


def test_journey_identity_excludes_prep_dir_wholesale():
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import checkout_identity, \
        journey_identity_excludes, journey_prep_dir
    import hashlib
    import json
    top = Path(journey_prep_dir())
    top.mkdir(parents=True, exist_ok=True)
    tag = 'wholesale-%d' % os.getpid()
    staged = top / 'stages' / 'stage' / 'staged-exe'
    staged.parent.mkdir(parents=True, exist_ok=True)
    staged.write_bytes(b'staged-bytes\n')
    record = top / 'records' / (tag + '.json')
    record.parent.mkdir(parents=True, exist_ok=True)
    commit, tree = checkout_identity(
        exclude=journey_identity_excludes())
    record.write_text(json.dumps(
        {'schema': 'memveil-journey-prep/1',
         'commit': commit, 'tree': tree,
         'suites': {'deb': {
             'path': str(top / 'provenance-exe'),
             'staged': str(staged),
             'sha256': hashlib.sha256(
                 staged.read_bytes()).hexdigest(),
             'target': 'package_deb'}}}))
    scratch = top / 'records' / (tag + '.json.stale000.tmp')
    scratch.write_bytes(b'{"partial": ')
    source = ROOT / (tag + '-source.py')
    source.write_text('print("source")\n')
    try:
        excludes = journey_identity_excludes()
        assert excludes == [str(top)]
        _, first = checkout_identity(exclude=excludes)
        with staged.open('ab') as stream:
            stream.write(b'more-staged-bytes\n')
        with record.open('ab') as stream:
            stream.write(b'more-record-bytes\n')
        with scratch.open('ab') as stream:
            stream.write(b'more-scratch\n')
        assert checkout_identity(
            exclude=excludes)[1] == first
        # A later file under the dir (absent when the
        # list was built) stays excluded; removing the
        # whole dir is invisible too.
        future = top / 'stages' / 'future-stage' / 'exe'
        future.parent.mkdir(parents=True)
        future.write_bytes(b'future-staged-bytes\n')
        assert checkout_identity(
            exclude=excludes)[1] == first
        shutil.rmtree(top, ignore_errors=True)
        assert checkout_identity(
            exclude=excludes)[1] == first
        with source.open('ab') as stream:
            stream.write(b'more-source-bytes\n')
        assert checkout_identity(
            exclude=excludes)[1] != first
    finally:
        source.unlink(missing_ok=True)
    prep_text = (ROOT / 'tests/support/journey_prep.py') \
        .read_text()
    dispatch_text = (
        ROOT / 'tests/support/candidate_suite.py').read_text()
    assert prep_text.count(
        'def journey_identity_excludes') \
        + dispatch_text.count(
            'def journey_identity_excludes') == 1
    assert prep_text.count(
        'def journey_prep_dir') \
        + dispatch_text.count(
            'def journey_prep_dir') == 1
    assert prep_text.count(
        'def journey_records_dir') \
        + dispatch_text.count(
            'def journey_records_dir') == 1
    assert 'journey_identity_excludes(' in prep_text
    assert prep_text.count(
        'def refuse_unowned_prep_contents') \
        + dispatch_text.count(
            'def refuse_unowned_prep_contents') == 1
    assert prep_text.count(
        'def _prep_record_shape_error') \
        + dispatch_text.count(
            'def _prep_record_shape_error') == 1
    assert prep_text.count(
        'def resolve_journey_record') \
        + dispatch_text.count(
            'def resolve_journey_record') == 1
    assert 'refuse_unowned_prep_contents(' in prep_text
    assert 'resolve_journey_record(' in prep_text
    assert dispatch_text.count(
        'journey_identity_excludes(') >= 2
    assert dispatch_text.count(
        'refuse_unowned_prep_contents(') >= 2
    assert 'journey_staging_root(' in prep_text
    assert 'journey_records_dir(' in prep_text
    assert 'journey_prep_dir(' in prep_text
    assert '.candidate-prep' not in prep_text
    assert "'stages'" not in prep_text
    assert '.stages' not in prep_text
    assert "'records'" not in prep_text
    assert '.records' not in prep_text


def test_journey_identity_hashes_outside_link_as_link(
        tmp_path):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import checkout_identity, \
        journey_identity_excludes, journey_staging_root
    root = Path(journey_staging_root())
    root.mkdir(parents=True, exist_ok=True)
    target = root / ('stage-target-%d' % os.getpid())
    target.write_bytes(b'staged-bytes\n')
    link = ROOT / ('outside-link-%d' % os.getpid())
    git_dir = subprocess.run(
        ['git', '-C', str(ROOT), 'rev-parse', '--git-dir'],
        capture_output=True, text=True)
    assert git_dir.returncode == 0, git_dir.stderr
    resolved = Path(git_dir.stdout.strip())
    if not resolved.is_absolute():
        resolved = ROOT / resolved
    index_copy = tmp_path / 'index-copy'
    shutil.copyfile(resolved / 'index', index_copy)
    baseline = _staged_state()
    try:
        saved = os.environ.get('GIT_INDEX_FILE')
        os.environ['GIT_INDEX_FILE'] = str(index_copy)
        try:
            link.symlink_to(target)
            added = subprocess.run(
                ['git', '-C', str(ROOT), 'add', '-f',
                 str(link)],
                capture_output=True, text=True)
            assert added.returncode == 0, added.stderr
            excludes = journey_identity_excludes()
            _, with_link = checkout_identity(
                exclude=excludes)
            # The link hashes as the link it is: target
            # bytes never leak into the digest.
            target.write_bytes(b'rewritten-staged-bytes\n')
            assert checkout_identity(
                exclude=excludes)[1] == with_link
        finally:
            if saved is None:
                os.environ.pop('GIT_INDEX_FILE', None)
            else:
                os.environ['GIT_INDEX_FILE'] = saved
        # Removing the link changes the digest: it never
        # vanished through its excluded target.
        link.unlink()
        _, without = checkout_identity(
            exclude=journey_identity_excludes())
        assert without != with_link
        # Repointing (even dangling) changes it too: the
        # hashed bytes are the link text.
        link.symlink_to(tmp_path / 'elsewhere')
        _, repointed = checkout_identity(
            exclude=journey_identity_excludes())
        assert repointed != with_link
        assert _staged_state() == baseline, \
            'real index gained staged changes'
    finally:
        link.unlink(missing_ok=True)
        target.unlink(missing_ok=True)


def test_journey_in_checkout_prep_and_launch_accepts(
        sealed, tmp_path, monkeypatch):
    # The record and its stage live inside the checkout, so
    # the digest would see them: the wholesale prep-dir
    # exclusion on both sides accepts instead of
    # self-invalidating.
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    fake = tmp_path / 'fake-exe'
    fake.write_text(harness)
    fake.chmod(0o755)
    sys.path.insert(0, str(ROOT / 'tests'))
    import support.journey_prep as prep
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    record = _prep_record_path('prep')
    prep.prepare(str(record))
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert 'journey-marker' in result.stdout, combined
    assert '1 passed' in combined, combined


def test_journey_records_coexist_in_prep_dir(
        sealed, tmp_path, monkeypatch):
    # Two records share the tool-owned directory: prep A,
    # prep B, launch both accept, and both bind the
    # identical checkout identity (neither record, stage,
    # nor scratch invalidates the other).
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    fake = tmp_path / 'fake-exe'
    fake.write_text(harness)
    fake.chmod(0o755)
    sys.path.insert(0, str(ROOT / 'tests'))
    import support.journey_prep as prep
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    record_a = _prep_record_path('prep-a')
    record_b = _prep_record_path('prep-b')
    first = prep.prepare(str(record_a))
    second = prep.prepare(str(record_b))
    assert first['commit'] == second['commit']
    assert first['tree'] == second['tree']
    assert Path(first['suites']['deb']['staged']).parent \
        != Path(second['suites']['deb']['staged']).parent
    environment = candidate_clean_env()
    environment.update(sealed)
    for record in (record_a, record_b):
        environment['MV_JOURNEY_PREP'] = str(record)
        result = _launch_journey('deb', environment)
        combined = result.stdout + result.stderr
        assert result.returncode == 0, combined
        assert 'journey-marker' in result.stdout, combined
        assert '1 passed' in combined, combined


def test_journey_prep_dir_ignored_narrowly_by_git():
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import JOURNEY_PREP_DIRNAME
    lines = (ROOT / '.gitignore').read_text().splitlines()
    assert [line for line in lines
            if 'candidate-prep' in line] \
        == ['/' + JOURNEY_PREP_DIRNAME + '/']
    inside = subprocess.run(
        ['git', '-C', str(ROOT), 'check-ignore', '-q',
         JOURNEY_PREP_DIRNAME + '/probe.json'])
    assert inside.returncode == 0
    outside = subprocess.run(
        ['git', '-C', str(ROOT), 'check-ignore', '-q',
         JOURNEY_PREP_DIRNAME + '-evil/probe.json'])
    assert outside.returncode == 1


def test_journey_prep_root_resolves_under_tmp(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import JOURNEY_PREP_DIRNAME, \
        journey_prep_dir
    # The test run's prep root lives under this test's
    # tmp_path, so no test can touch the operator dir.
    private = Path(journey_prep_dir()).resolve()
    assert tmp_path.resolve() in private.parents, private
    assert private != ROOT / JOURNEY_PREP_DIRNAME
    assert ROOT / JOURNEY_PREP_DIRNAME \
        not in private.parents
    # The default is unchanged once the override lifts.
    monkeypatch.delenv('MV_JOURNEY_PREP_DIR')
    assert journey_prep_dir() == str(
        ROOT / JOURNEY_PREP_DIRNAME)
    # A relative override, or one covering the checkout
    # itself, refuses instead of scattering outputs or
    # swallowing source from identity.
    monkeypatch.setenv('MV_JOURNEY_PREP_DIR',
                       'relative/prep')
    with pytest.raises(ValueError, match='absolute'):
        journey_prep_dir()
    monkeypatch.setenv('MV_JOURNEY_PREP_DIR', str(ROOT))
    with pytest.raises(ValueError, match='must not cover'):
        journey_prep_dir()


def test_journey_prep_dir_refuses_tracked_content(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import \
        journey_identity_excludes, journey_prep_dir
    import support.journey_prep as prep
    # Tracked content needs an in-checkout prep root: a
    # fresh probe directory, never the operator's dir.
    fresh = ROOT / ('probe-prep-%d-%s'
                    % (os.getpid(), uuid.uuid4().hex[:8]))
    monkeypatch.setenv('MV_JOURNEY_PREP_DIR', str(fresh))
    top = Path(journey_prep_dir())
    assert top == fresh
    top.mkdir(parents=True, exist_ok=True)
    plant = top / ('tracked-%d.txt' % os.getpid())
    plant.write_text('force-added\n')
    # Stage into a COPY of the index, never the real one: a
    # kill between add and cleanup must not leave the
    # operator's checkout dirty.
    git_dir = subprocess.run(
        ['git', '-C', str(ROOT), 'rev-parse', '--git-dir'],
        capture_output=True, text=True)
    assert git_dir.returncode == 0, git_dir.stderr
    resolved = Path(git_dir.stdout.strip())
    if not resolved.is_absolute():
        resolved = ROOT / resolved
    index_copy = tmp_path / 'index-copy'
    shutil.copyfile(resolved / 'index', index_copy)
    baseline = _staged_state()
    saved = os.environ.get('GIT_INDEX_FILE')
    os.environ['GIT_INDEX_FILE'] = str(index_copy)
    try:
        added = subprocess.run(
            ['git', '-C', str(ROOT), 'add', '-f',
             str(plant)],
            capture_output=True, text=True)
        assert added.returncode == 0, added.stderr
        with pytest.raises(ValueError, match='tracked'):
            journey_identity_excludes()
        with pytest.raises(ValueError, match='tracked'):
            prep.prepare(str(top / 'records' / 'prep.json'))
    finally:
        if saved is None:
            os.environ.pop('GIT_INDEX_FILE', None)
        else:
            os.environ['GIT_INDEX_FILE'] = saved
        plant.unlink(missing_ok=True)
        shutil.rmtree(top, ignore_errors=True)
        assert _staged_state() == baseline, \
            'real index gained staged changes'


def test_journey_prep_refuses_tracked_before_any_write(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_prep_dir
    import support.journey_prep as prep
    # Tracked content needs an in-checkout prep root: a
    # fresh probe directory, never the operator's dir.
    fresh = ROOT / ('probe-prep-%d-%s'
                    % (os.getpid(), uuid.uuid4().hex[:8]))
    monkeypatch.setenv('MV_JOURNEY_PREP_DIR', str(fresh))
    top = Path(journey_prep_dir())
    assert top == fresh
    try:
        # Plant the tracked file, stage it into an index
        # copy, then remove the directory from disk: the
        # future prep path holds tracked content while
        # existing nowhere on disk.
        top.mkdir(parents=True)
        plant = top / ('tracked-%d.txt' % os.getpid())
        plant.write_text('force-added\n')
        git_dir = subprocess.run(
            ['git', '-C', str(ROOT), 'rev-parse', '--git-dir'],
            capture_output=True, text=True)
        assert git_dir.returncode == 0, git_dir.stderr
        resolved = Path(git_dir.stdout.strip())
        if not resolved.is_absolute():
            resolved = ROOT / resolved
        index_copy = tmp_path / 'index-copy'
        shutil.copyfile(resolved / 'index', index_copy)
        baseline = _staged_state()
        saved = os.environ.get('GIT_INDEX_FILE')
        os.environ['GIT_INDEX_FILE'] = str(index_copy)
        try:
            added = subprocess.run(
                ['git', '-C', str(ROOT), 'add', '-f',
                 str(plant)],
                capture_output=True, text=True)
            assert added.returncode == 0, added.stderr
            shutil.rmtree(top, ignore_errors=True)
            assert not os.path.lexists(top)
            with pytest.raises(ValueError, match='tracked'):
                prep.prepare(
                    str(top / 'records' / 'prep.json'))
            assert not os.path.lexists(top), \
                'refused prep created its directory'
        finally:
            if saved is None:
                os.environ.pop('GIT_INDEX_FILE', None)
            else:
                os.environ['GIT_INDEX_FILE'] = saved
        assert _staged_state() == baseline, \
            'real index gained staged changes'
    finally:
        if top.is_symlink():
            top.unlink(missing_ok=True)
        else:
            shutil.rmtree(top, ignore_errors=True)


def test_journey_prep_dir_refuses_filesystem_root(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_prep_dir
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    # The filesystem root and every ancestor of the
    # checkout refuse; a parent directory is not the
    # checkout itself, yet covers it all the same.
    monkeypatch.setenv('MV_JOURNEY_PREP_DIR', '/')
    with pytest.raises(ValueError, match='must not cover'):
        journey_prep_dir()
    monkeypatch.setenv('MV_JOURNEY_PREP_DIR',
                       str(ROOT.parent))
    with pytest.raises(ValueError, match='must not cover'):
        journey_prep_dir()
    # A refused root override attempts no mode change:
    # the refusal lands before any write or chmod, and
    # the root mode is untouched.
    monkeypatch.setenv('MV_JOURNEY_PREP_DIR', '/')
    calls = []
    real_chmod = os.chmod

    def recording(path, mode):
        calls.append((str(path), mode))
        return real_chmod(path, mode)

    monkeypatch.setattr(os, 'chmod', recording)
    before = os.stat('/').st_mode
    with pytest.raises(ValueError, match='must not cover'):
        prep.prepare('/records/prep.json')
    assert calls == [], 'refused prep attempted chmod'
    assert os.stat('/').st_mode == before
    assert not os.path.lexists('/records')


def test_journey_prep_refuses_untracked_source_in_override(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_prep_dir
    import support.journey_prep as prep
    # Untracked source needs an in-checkout prep root: a
    # fresh probe directory, never the operator's dir.
    fresh = ROOT / ('probe-prep-%d-%s'
                    % (os.getpid(), uuid.uuid4().hex[:8]))
    monkeypatch.setenv('MV_JOURNEY_PREP_DIR', str(fresh))
    assert Path(journey_prep_dir()) == fresh
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    calls = []
    real_chmod = os.chmod

    def recording(path, mode):
        calls.append((str(path), mode))
        return real_chmod(path, mode)

    monkeypatch.setattr(os, 'chmod', recording)
    try:
        fresh.mkdir(parents=True)
        plant = fresh / 'untracked-source.py'
        plant.write_text('print("untracked")\n')
        rel = fresh.relative_to(ROOT)
        listed = subprocess.run(
            ['git', '-C', str(ROOT), 'ls-files', '--others',
             '--exclude-standard', '-z', '--', str(rel)],
            capture_output=True, text=True)
        assert listed.returncode == 0, listed.stderr
        assert (rel / plant.name).as_posix() in \
            listed.stdout.split('\0'), \
            'plant is not untracked-but-visible'
        with pytest.raises(ValueError,
                           match='tool-owned'):
            prep.prepare(str(fresh / 'records' / 'prep.json'))
        assert calls == [], 'refused prep attempted chmod'
        assert not (fresh / 'records').exists(), \
            'refused prep created its records dir'
        assert plant.read_text() == 'print("untracked")\n'
    finally:
        shutil.rmtree(fresh, ignore_errors=True)


def test_journey_prep_accepts_tool_owned_override(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_prep_dir
    import support.journey_prep as prep
    # An in-checkout override holding only tool-owned
    # entries (records, stages, a prior record from an
    # earlier prep, and a lingering publication scratch
    # file) proceeds.
    fresh = ROOT / ('probe-prep-%d-%s'
                    % (os.getpid(), uuid.uuid4().hex[:8]))
    monkeypatch.setenv('MV_JOURNEY_PREP_DIR', str(fresh))
    assert Path(journey_prep_dir()) == fresh
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    fake.chmod(0o755)
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    try:
        (fresh / 'records').mkdir(parents=True)
        (fresh / 'stages').mkdir(parents=True)
        prior = prep.prepare(
            str(fresh / 'records' / 'prior.json'))
        assert (fresh / 'records' / 'prior.json').is_file()
        for suite, entry in prior['suites'].items():
            assert Path(entry['staged']).is_file(), suite
        (fresh / 'records' / 'prior.json.stale000.tmp') \
            .write_bytes(b'{"schema": "partial-')
        record = prep.prepare(
            str(fresh / 'records' / 'prep.json'))
        assert (fresh / 'records' / 'prep.json').is_file()
        for suite, entry in record['suites'].items():
            staged = Path(entry['staged'])
            assert (fresh / 'stages') in staged.parents, \
                suite
            assert staged.is_file(), suite
    finally:
        shutil.rmtree(fresh, ignore_errors=True)


def test_journey_prep_dir_refuses_symlinked_override_ancestor(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_prep_dir
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    # An override reached through a symlinked ancestor
    # refuses on the unresolved spelling instead of
    # resolving onto the honest-looking directory.
    real = tmp_path / 'real-ancestor'
    real.mkdir()
    link = tmp_path / 'link-ancestor'
    link.symlink_to(real, target_is_directory=True)
    override = link / 'prep-ancestor'
    monkeypatch.setenv('MV_JOURNEY_PREP_DIR', str(override))
    with pytest.raises(ValueError, match='symlink'):
        journey_prep_dir()
    with pytest.raises(ValueError, match='symlink'):
        prep.prepare(
            str(override / 'records' / 'prep.json'))
    assert sorted(entry.name for entry in real.iterdir()) \
        == []


def test_journey_prep_refuses_dotdot_hidden_symlink(
        sealed, tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_prep_dir
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    top = Path(journey_prep_dir())
    real = tmp_path / 'real-dotdot'
    real.mkdir()
    link = tmp_path / 'link-dotdot'
    link.symlink_to(real, target_is_directory=True)
    # The spelling collapses into the records subdir,
    # hiding the traversed link from a normalizing walk;
    # the raw-component walk still refuses it.
    spelled = link / 'x' / '..' / '..' / top.name \
        / 'records' / 'prep.json'
    collapsed = top / 'records' / 'prep.json'
    assert os.path.abspath(spelled) == str(collapsed)
    with pytest.raises(ValueError, match='symlink'):
        prep.prepare(str(spelled))
    assert not os.path.lexists(collapsed)
    assert sorted(entry.name for entry in real.iterdir()) \
        == []
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(spelled)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'symlink' in combined, combined


def test_journey_prep_accepts_fresh_override(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    import support.journey_prep as prep
    # A fresh override path, existing nowhere on disk,
    # is created and proceeds.
    fresh = tmp_path / 'fresh-prep-root'
    monkeypatch.setenv('MV_JOURNEY_PREP_DIR', str(fresh))
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    fake.chmod(0o755)
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    assert not os.path.lexists(fresh)
    record = prep.prepare(
        str(fresh / 'records' / 'prep.json'))
    assert (fresh / 'records' / 'prep.json').is_file()
    for suite, entry in record['suites'].items():
        staged = Path(entry['staged'])
        assert (fresh / 'stages') in staged.parents, suite
        assert staged.is_file(), suite


def test_staged_state_baseline_tolerates_preset_changes(
        tmp_path):
    # The clean-index assertion compares against a
    # baseline instead of demanding emptiness: a
    # pre-existing staged change passes, a new one fails.
    # Staged into an index copy, never the real index.
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import \
        journey_identity_excludes
    before = _staged_state()
    probe = ROOT / ('baseline-probe-%d.txt' % os.getpid())
    probe.write_text('baseline\n')
    extra = ROOT / ('baseline-extra-%d.txt' % os.getpid())
    git_dir = subprocess.run(
        ['git', '-C', str(ROOT), 'rev-parse', '--git-dir'],
        capture_output=True, text=True)
    assert git_dir.returncode == 0, git_dir.stderr
    resolved = Path(git_dir.stdout.strip())
    if not resolved.is_absolute():
        resolved = ROOT / resolved
    index_copy = tmp_path / 'index-copy'
    shutil.copyfile(resolved / 'index', index_copy)
    saved = os.environ.get('GIT_INDEX_FILE')
    os.environ['GIT_INDEX_FILE'] = str(index_copy)
    try:
        added = subprocess.run(
            ['git', '-C', str(ROOT), 'add', '-f',
             str(probe)],
            capture_output=True, text=True)
        assert added.returncode == 0, added.stderr
        baseline = _staged_state()
        assert baseline != '', 'preset staged nothing'
        # An emptiness check would false-positive here.
        dirty = subprocess.run(
            ['git', '-C', str(ROOT), 'diff', '--cached',
             '--quiet'],
            capture_output=True, text=True)
        assert dirty.returncode != 0, \
            'preset baseline left the copy clean'
        # The checked operation stages nothing: the
        # summary still equals the preset baseline.
        journey_identity_excludes()
        assert _staged_state() == baseline
        # ...but a further staged change is detected.
        extra.write_text('extra\n')
        added = subprocess.run(
            ['git', '-C', str(ROOT), 'add', '-f',
             str(extra)],
            capture_output=True, text=True)
        assert added.returncode == 0, added.stderr
        assert _staged_state() != baseline
    finally:
        if saved is None:
            os.environ.pop('GIT_INDEX_FILE', None)
        else:
            os.environ['GIT_INDEX_FILE'] = saved
        probe.unlink(missing_ok=True)
        extra.unlink(missing_ok=True)
    assert _staged_state() == before, \
        'real index gained staged changes'


def test_journey_record_outside_prep_dir_refuses(
        sealed, tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    outside = tmp_path / 'prep.json'
    with pytest.raises(ValueError, match='must live under'):
        prep.prepare(str(outside))
    assert not outside.exists()
    stray = ROOT / ('journey-stray-probe-%d.json'
                    % os.getpid())
    try:
        with pytest.raises(ValueError, match='must live under'):
            prep.prepare(str(stray))
        assert not stray.exists()
        environment = candidate_clean_env()
        environment.update(sealed)
        environment['MV_JOURNEY_PREP'] = str(outside)
        result = _launch_journey('deb', environment)
        combined = result.stdout + result.stderr
        assert result.returncode == 2, combined
        assert 'must live under' in combined, combined
    finally:
        stray.unlink(missing_ok=True)


def test_journey_record_into_stages_refuses(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_prep_dir, \
        journey_staging_root
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    staged_record = Path(
        journey_staging_root()) / 'prep.json'
    with pytest.raises(ValueError, match='must live under'):
        prep.prepare(str(staged_record))
    assert not os.path.lexists(staged_record)
    # The old top-level layout refuses too: records live
    # only under the records subdir now.
    legacy = Path(journey_prep_dir()) / 'prep.json'
    with pytest.raises(ValueError, match='must live under'):
        prep.prepare(str(legacy))
    assert not os.path.lexists(legacy)


def test_journey_prep_refuses_txt_record_destination(
        sealed, tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_prep_dir, \
        journey_staging_root
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    # A record destination outside the JSON record shape
    # refuses before anything is written: the publish path
    # and the checks share the one destination rule, so a
    # published record is always one the checks accept.
    target = Path(journey_prep_dir()) / 'records' \
        / 'prep.txt'
    root = Path(journey_staging_root())
    before = sorted(root.iterdir()) if root.exists() \
        else []
    with pytest.raises(ValueError, match='must be a JSON'):
        prep.prepare(str(target))
    assert not os.path.lexists(target)
    after = sorted(root.iterdir()) if root.exists() \
        else []
    assert after == before, 'refused prep staged bytes'
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(target)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'must be a JSON' in combined, combined


def test_journey_stage_into_records_refuses(tmp_path):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_records_dir
    import support.journey_prep as prep
    records = Path(journey_records_dir())
    records.mkdir(parents=True, exist_ok=True)
    aimed = records / 'smuggled-exe'
    with pytest.raises(ValueError,
                       match='outside the stages'):
        prep._stage_bytes(aimed, b'#!/bin/sh\necho x\n',
                          'deb')
    assert not os.path.lexists(aimed)


def test_journey_honest_layout_accepts(tmp_path,
                                       monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_records_dir, \
        journey_staging_root
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    record_path = _prep_record_path('prep')
    record = prep.prepare(str(record_path))
    assert record_path.parent == Path(journey_records_dir())
    root = Path(journey_staging_root())
    for suite, entry in record['suites'].items():
        assert root in Path(entry['staged']).parents, suite


def test_journey_honest_record_and_stage_accepts(
        sealed, tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import \
        refuse_unowned_prep_contents
    import support.journey_prep as prep
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    fake = tmp_path / 'fake-exe'
    fake.write_text(harness)
    fake.chmod(0o755)
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    record_path = _prep_record_path('prep')
    prep.prepare(str(record_path))
    # An honest record with its referenced stages passes
    # the shared validator directly, across a repeat prep,
    # and at launch.
    refuse_unowned_prep_contents()
    prep.prepare(str(_prep_record_path('prep-next')))
    refuse_unowned_prep_contents()
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record_path)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert '1 passed' in combined, combined


def test_journey_retired_stage_cleanup_keeps_record_valid(
        sealed, tmp_path, monkeypatch):
    # Repeat prep, delete the retired first stage, launch
    # the second record: the retired stage never entered
    # the digest, so cleanup cannot self-invalidate.
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    fake = tmp_path / 'fake-exe'
    fake.write_text(harness)
    fake.chmod(0o755)
    sys.path.insert(0, str(ROOT / 'tests'))
    import support.journey_prep as prep
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    record = _prep_record_path('prep')
    first = prep.prepare(str(record))
    stage_one = Path(
        first['suites']['deb']['staged']).parent
    prep.prepare(str(record))
    shutil.rmtree(stage_one)
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert 'journey-marker' in result.stdout, combined
    assert '1 passed' in combined, combined


def test_journey_repeat_prep_keeps_identity_pure(
        sealed, tmp_path, monkeypatch):
    # Prep, launch, prep again, launch: both launches
    # accept, and the second record binds the identical
    # checkout identity (no earlier stage pollutes it).
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    fake = tmp_path / 'fake-exe'
    fake.write_text(harness)
    fake.chmod(0o755)
    sys.path.insert(0, str(ROOT / 'tests'))
    import support.journey_prep as prep
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    record = _prep_record_path('prep')
    first = prep.prepare(str(record))
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert '1 passed' in combined, combined
    second = prep.prepare(str(record))
    assert second['commit'] == first['commit']
    assert second['tree'] == first['tree']
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert '1 passed' in combined, combined


def test_journey_tampered_executable_post_prep_refuses(
        sealed, tmp_path):
    import hashlib
    import json
    import shutil
    record = _prep_record_path('prep')
    result = subprocess.run(
        [sys.executable,
         str(ROOT / 'tests/support/journey_prep.py'),
         str(record)],
        capture_output=True, text=True, timeout=900,
        cwd=str(ROOT))
    assert result.returncode == 0, result.stderr[-2000:]
    doc = json.loads(record.read_text())
    original = Path(doc['suites']['deb']['path'])
    original_digest = hashlib.sha256(
        original.read_bytes()).hexdigest()
    assert original_digest == doc['suites']['deb']['sha256']
    # Mutate a private copy, never the shared build output:
    # the copy lives in this test's directory, carries the
    # honest staged name (so this leg exercises containment
    # rather than the staged-filename binding), the record
    # is repointed at it, and no restoration is needed.
    private = tmp_path / doc['suites']['deb']['target']
    shutil.copyfile(original, private)
    private.chmod(0o755)
    doc['suites']['deb']['staged'] = str(private)
    record.write_text(json.dumps(doc))
    with private.open('ab') as stream:
        stream.write(b'# tampered-post-prep\n')
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record)
    result = _launch_journey('deb', environment,
                             'journey_gate_matrix')
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    # The tampered copy sits outside the stages tree, so
    # containment refuses before any byte is read; the
    # launch-time digest refusal stays pinned by the
    # lying-record test.
    assert 'outside the stages' in combined, combined
    assert hashlib.sha256(
        original.read_bytes()).hexdigest() \
        == original_digest


def test_journey_prep_refuses_unreferenced_staged_bytes(
        sealed, tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    import support.journey_prep as prep
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    fake = tmp_path / 'fake-exe'
    fake.write_text(harness)
    fake.chmod(0o755)
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    record_path = _prep_record_path('prep')
    record = prep.prepare(str(record_path))
    staged = Path(record['suites']['deb']['staged'])
    with staged.open('ab') as stream:
        stream.write(b'# unreferenced-bytes\n')
    # Staged bytes matching no digest any valid record
    # references refuse on the publish path (before any
    # new write) and on the check path through the
    # identical validator.
    with pytest.raises(
            ValueError,
            match='matching no digest referenced'):
        prep.prepare(str(_prep_record_path('prep-next')))
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record_path)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'matching no digest referenced' in combined, \
        combined
    assert 'journey-marker' not in result.stdout, combined


def test_journey_launcher_refuses_lying_record_digest(
        sealed, tmp_path):
    import hashlib
    import json
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import checkout_identity, \
        journey_identity_excludes, journey_staging_root
    from support.journey_prep import TARGETS
    # Two records bind the same staged path: the honest
    # record names the true digest (so the shared
    # validator accepts the bytes), the lying record
    # names another digest for the same path, and the
    # launch-time re-hash refuses it.
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    tag = '%d-%s' % (os.getpid(), uuid.uuid4().hex[:8])
    stage_dir = Path(journey_staging_root()) / (
        'stub-lying-%s.staged' % tag)
    stage_dir.mkdir(parents=True)
    staged = stage_dir / TARGETS['deb']
    staged.write_text(harness)
    staged.chmod(0o755)
    digest = hashlib.sha256(
        staged.read_bytes()).hexdigest()
    assert digest != '0' * 64
    commit, tree = checkout_identity(
        exclude=journey_identity_excludes())
    honest = _prep_record_path('stub-honest')
    honest.parent.mkdir(parents=True, exist_ok=True)
    honest.write_text(json.dumps(
        {'schema': 'memveil-journey-prep/1',
         'commit': commit, 'tree': tree,
         'suites': {'deb': {
             'path': str(staged),
             'staged': str(staged),
             'sha256': digest,
             'target': TARGETS['deb']}}}))
    lying = _prep_record_path('stub-lying')
    lying.write_text(json.dumps(
        {'schema': 'memveil-journey-prep/1',
         'commit': commit, 'tree': tree,
         'suites': {'deb': {
             'path': str(staged),
             'staged': str(staged),
             'sha256': '0' * 64,
             'target': TARGETS['deb']}}}))
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(lying)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'changed' in combined, combined
    assert 'journey-marker' not in result.stdout, combined


def test_journey_record_non_string_path_refuses(sealed,
                                               tmp_path):
    import json
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import checkout_identity, \
        journey_identity_excludes
    record_path = _prep_record_path('prep')
    record_path.parent.mkdir(parents=True, exist_ok=True)
    commit, tree = checkout_identity(
        exclude=journey_identity_excludes())
    record_path.write_text(json.dumps(
        {'schema': 'memveil-journey-prep/1',
         'commit': commit, 'tree': tree,
         'suites': {'deb': {'path': 12345,
                            'staged': str(
                                tmp_path / 'unstaged'),
                            'sha256': '0' * 64,
                            'target': 'package_deb'}}}))
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record_path)
    result = subprocess.run(
        [sys.executable,
         str(ROOT / 'tests/support/candidate_suite.py'),
         'deb'],
        env=environment, capture_output=True, text=True,
        timeout=120)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'Traceback' not in combined, combined
    # The misshapen entry refuses at the shared scan
    # before dispatch: the scan validates suite entries
    # through the same predicate as the launcher.
    assert 'invalid shape' in combined, combined
    # Control: the same complete record with a valid path
    # type passes the entry check and fails later, proving
    # the refusal above fires on the type check. The bad
    # record is removed first, since the scan covers every
    # record in the directory. The unstaged path carries
    # the honest staged name, so the control exercises the
    # missing-file check rather than the staged-filename
    # binding.
    record_path.unlink()
    control_path = _prep_record_path('prep-control')
    commit, tree = checkout_identity(
        exclude=journey_identity_excludes())
    control_path.write_text(json.dumps(
        {'schema': 'memveil-journey-prep/1',
         'commit': commit, 'tree': tree,
         'suites': {'deb': {'path': str(tmp_path / 'orig'),
                            'staged': str(
                                tmp_path / 'package_deb'),
                            'sha256': '0' * 64,
                            'target': 'package_deb'}}}))
    environment['MV_JOURNEY_PREP'] = str(control_path)
    result = subprocess.run(
        [sys.executable,
         str(ROOT / 'tests/support/candidate_suite.py'),
         'deb'],
        env=environment, capture_output=True, text=True,
        timeout=120)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'lacks suite' not in combined, combined
    assert 'not a plain file' in combined, combined


def test_journey_prep_refuses_mid_prep_edit(tmp_path,
                                           monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    calls = []

    def flipping(exclude=()):
        calls.append(1)
        if len(calls) == 1:
            return ('a' * 40, 'a' * 64)
        return ('a' * 40, 'b' * 64)

    monkeypatch.setattr(prep, 'checkout_identity', flipping)
    with pytest.raises(ValueError, match='changed during'):
        prep.prepare(str(_prep_record_path('prep')))


def test_journey_prep_uses_fresh_private_stage(tmp_path,
                                              monkeypatch):
    import hashlib
    sys.path.insert(0, str(ROOT / 'tests'))
    import support.journey_prep as prep
    first = tmp_path / 'first-exe'
    first.write_bytes(
        b'#!/bin/sh\necho first-stage\n' + b'A' * 4096)
    second = tmp_path / 'second-exe'
    second.write_bytes(
        b'#!/bin/sh\necho second-stage\n' + b'B' * 4096)
    current = [first]
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: current[0])
    record_path = _prep_record_path('prep')
    record_one = prep.prepare(str(record_path))
    stage_one = Path(
        record_one['suites']['deb']['staged']).parent
    current[0] = second
    record_two = prep.prepare(str(record_path))
    stage_two = Path(
        record_two['suites']['deb']['staged']).parent
    assert stage_one != stage_two
    # The second prep left the first stage's hashed bytes
    # intact instead of overwriting them.
    for suite, entry in record_one['suites'].items():
        assert hashlib.sha256(
            Path(entry['staged']).read_bytes()).hexdigest() \
            == entry['sha256'], suite
    for suite, entry in record_two['suites'].items():
        assert hashlib.sha256(
            Path(entry['staged']).read_bytes()).hexdigest() \
            == entry['sha256'], suite


def test_journey_concurrent_preps_keep_private_stages(
        tmp_path, monkeypatch):
    import hashlib
    import threading
    sys.path.insert(0, str(ROOT / 'tests'))
    import support.journey_prep as prep
    fakes = {}
    for tag in ('alpha', 'beta'):
        fake = tmp_path / ('fake-' + tag)
        fake.write_bytes(
            b'#!/bin/sh\necho ' + tag.encode() + b'\n'
            + tag.encode() * 65536)
        fakes[tag] = fake
    barrier = threading.Barrier(2)

    def build(target):
        tag = threading.current_thread().name
        barrier.wait(timeout=120)
        return fakes[tag]

    monkeypatch.setattr(prep, 'build_executable', build)
    record_path = _prep_record_path('prep')
    outcomes = {}

    def run(tag):
        try:
            outcomes[tag] = (
                'ok', prep.prepare(str(record_path)))
        except Exception as exc:
            outcomes[tag] = ('error', repr(exc))

    threads = [threading.Thread(target=run, args=(tag,),
                               name=tag)
               for tag in ('alpha', 'beta')]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=300)
    assert not any(thread.is_alive() for thread in threads)
    for tag in ('alpha', 'beta'):
        status, record = outcomes[tag]
        assert status == 'ok', (tag, record)
    stages = [Path(outcomes[tag][1]['suites']['deb']
                   ['staged']).parent
              for tag in ('alpha', 'beta')]
    assert stages[0] != stages[1]
    for tag in ('alpha', 'beta'):
        for suite, entry in \
                outcomes[tag][1]['suites'].items():
            assert hashlib.sha256(
                Path(entry['staged'])
                .read_bytes()).hexdigest() \
                == entry['sha256'], (tag, suite)


def test_journey_record_publishes_via_temp_replace(
        tmp_path, monkeypatch):
    import json
    sys.path.insert(0, str(ROOT / 'tests'))
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    calls = []
    real_replace = os.replace

    def recording(src, dst):
        calls.append((src, dst))
        return real_replace(src, dst)

    monkeypatch.setattr(os, 'replace', recording)
    record_path = _prep_record_path('prep')
    before = prep.prepare(str(record_path))
    assert json.loads(record_path.read_text()) == before
    first_inode = record_path.stat().st_ino
    assert calls, 'record publish bypassed os.replace'
    want = record_path.resolve()
    for src, dst in calls:
        assert Path(src).parent == want.parent
        assert Path(dst).resolve() == want
    prep.prepare(str(record_path))
    assert record_path.stat().st_ino != first_inode


def test_journey_record_reads_valid_under_concurrent_prep(
        tmp_path, monkeypatch):
    import json
    import threading
    sys.path.insert(0, str(ROOT / 'tests'))
    import support.journey_prep as prep
    payloads = []
    for index in range(4):
        fake = tmp_path / ('fake-%d' % index)
        fake.write_bytes(
            b'#!/bin/sh\necho payload-%d\n' % index
            + bytes((index,)) * 65536)
        payloads.append(fake)

    def build(target):
        return payloads[int(threading.current_thread().name)]

    monkeypatch.setattr(prep, 'build_executable', build)
    record_path = _prep_record_path('prep')
    barrier = threading.Barrier(4)
    stop = threading.Event()
    errors = []
    counts = []

    def run_preps(tag):
        try:
            barrier.wait(timeout=120)
            for _ in range(5):
                prep.prepare(str(record_path))
        except Exception as exc:
            errors.append(repr(exc))

    def run_reads():
        import time
        try:
            parsed = 0
            while not stop.is_set():
                time.sleep(0.001)
                try:
                    text = record_path.read_text(
                        encoding='utf-8')
                except FileNotFoundError:
                    continue
                doc = json.loads(text)
                assert doc['schema'] == \
                    'memveil-journey-prep/1'
                assert set(doc) == {
                    'schema', 'commit', 'tree', 'suites'}
                parsed += 1
            counts.append(parsed)
        except Exception as exc:
            errors.append(repr(exc))

    threads = [threading.Thread(
        target=run_preps, args=(tag,), name=str(tag))
        for tag in range(4)]
    threads += [threading.Thread(target=run_reads)
                for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads[:4]:
        thread.join(timeout=300)
    stop.set()
    for thread in threads[4:]:
        thread.join(timeout=300)
    assert not any(thread.is_alive() for thread in threads)
    assert errors == []
    assert sum(counts) >= 50


def test_journey_publication_scratch_stays_invisible(
        sealed, tmp_path, monkeypatch):
    # A lingering publication temp file inside the
    # tool-owned directory never enters checkout
    # identity: overlapping prep and launch accept with
    # it present, and the digest matches the
    # scratch-free digest. The real publish temp is
    # recorded too, proving it lands inside the excluded
    # directory.
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    fake = tmp_path / 'fake-exe'
    fake.write_text(harness)
    fake.chmod(0o755)
    import json
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import checkout_identity, \
        journey_identity_excludes, journey_prep_dir
    import support.journey_prep as prep
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    temps = []
    real_replace = os.replace

    def recording(src, dst):
        temps.append(src)
        return real_replace(src, dst)

    monkeypatch.setattr(os, 'replace', recording)
    top = Path(journey_prep_dir())
    record_path = _prep_record_path('prep')
    record = prep.prepare(str(record_path))
    assert temps, 'record publish bypassed os.replace'
    for temp in temps:
        assert Path(temp).name.startswith(
            record_path.name + '.')
        assert Path(temp).name.endswith('.tmp')
        assert top in Path(temp).resolve().parents, temp
    excludes = journey_identity_excludes()
    assert excludes == [str(top)]
    scratch = record_path.parent / (
        record_path.name + '.stale000.tmp')
    scratch.write_bytes(b'{"schema": "partial-')
    try:
        _, with_scratch = checkout_identity(
            exclude=excludes)
        scratch.unlink()
        _, without = checkout_identity(exclude=excludes)
        assert with_scratch == without
        assert record['tree'] == without
        scratch.write_bytes(b'{"schema": "partial-')
        again = prep.prepare(str(_prep_record_path('prep2')))
        assert again['tree'] == record['tree']
        environment = candidate_clean_env()
        environment.update(sealed)
        environment['MV_JOURNEY_PREP'] = str(record_path)
        result = _launch_journey('deb', environment)
        combined = result.stdout + result.stderr
        assert result.returncode == 0, combined
        assert '1 passed' in combined, combined
        with pytest.raises(ValueError, match='outside'):
            prep._publish_record_atomically(
                tmp_path / 'x.json', tmp_path / 'x.json',
                json.dumps(record))
        assert not (tmp_path / 'x.json').exists()
    finally:
        scratch.unlink(missing_ok=True)


def test_journey_prep_refuses_symlinked_staging_path(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_prep_dir
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    top = Path(journey_prep_dir())
    top.mkdir(parents=True, exist_ok=True)
    real = tmp_path / 'real'
    real.mkdir()
    linked = top / ('linked-%d' % os.getpid())
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match='symlink'):
        prep.prepare(str(linked / 'prep.json'))
    assert sorted(entry.name for entry in real.iterdir()) \
        == []


def test_journey_prep_leaves_planted_stage_name_untouched(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_staging_root
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    victim = tmp_path / 'victim'
    victim.mkdir()
    sentinel = victim / 'sentinel'
    sentinel.write_text('untouched\n')
    record_path = _prep_record_path('prep')
    root = Path(journey_staging_root())
    root.mkdir(parents=True, exist_ok=True)
    plant = root / (record_path.stem + '.staged')
    plant.symlink_to(victim, target_is_directory=True)
    record = prep.prepare(str(record_path))
    assert plant.is_symlink()
    assert sentinel.read_text() == 'untouched\n'
    assert sorted(entry.name for entry in victim.iterdir()) \
        == ['sentinel']
    for suite, entry in record['suites'].items():
        assert Path(entry['staged']).parent != plant, suite


def test_journey_prep_refuses_symlinked_staging_root(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_staging_root
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    real = tmp_path / 'real'
    real.mkdir()
    root = Path(journey_staging_root())
    root.parent.mkdir(parents=True, exist_ok=True)
    aside = tmp_path / 'staging-root-aside'
    if root.exists() or root.is_symlink():
        shutil.move(str(root), str(aside))
    try:
        root.symlink_to(real, target_is_directory=True)
        with pytest.raises(ValueError, match='symlink'):
            prep.prepare(str(_prep_record_path('prep')))
        assert sorted(
            entry.name for entry in real.iterdir()) == []
    finally:
        if root.is_symlink():
            root.unlink()
        if aside.exists():
            shutil.move(str(aside), str(root))


def test_journey_prep_refuses_symlinked_record(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_prep_dir
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    top = Path(journey_prep_dir())
    top.mkdir(parents=True, exist_ok=True)
    target = top / ('target-%d.json' % os.getpid())
    target.write_text('{"existing": true}\n')
    link = top / ('link-%d.json' % os.getpid())
    link.symlink_to(target)
    with pytest.raises(ValueError, match='symlink'):
        prep.prepare(str(link))
    assert link.is_symlink()
    assert target.read_text() == '{"existing": true}\n'


def test_journey_launcher_refuses_symlinked_record(
        sealed, tmp_path):
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    _, _, record_path = _journey_stub_record(
        tmp_path, harness)
    link = record_path.parent / (
        'link-%s.json' % uuid.uuid4().hex[:8])
    link.symlink_to(record_path)
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(link)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'symlink' in combined, combined
    assert 'Traceback' not in combined, combined
    assert 'journey-marker' not in result.stdout, combined


def test_journey_prep_refuses_symlinked_prep_dir(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_prep_dir
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    top = Path(journey_prep_dir())
    aside = tmp_path / 'prep-dir-aside'
    if top.exists() or top.is_symlink():
        shutil.move(str(top), str(aside))
    try:
        real = tmp_path / 'real'
        real.mkdir()
        top.symlink_to(real, target_is_directory=True)
        with pytest.raises(ValueError, match='symlink'):
            prep.prepare(str(top / 'prep.json'))
        assert sorted(
            entry.name for entry in real.iterdir()) == []
    finally:
        if top.is_symlink():
            top.unlink()
        if aside.exists():
            shutil.move(str(aside), str(top))


def test_journey_launcher_ignores_original_post_stage(
        sealed, tmp_path):
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    stub, staged, record_path = _journey_stub_record(
        tmp_path, harness)
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record_path)
    with stub.open('ab') as stream:
        stream.write(b'# original-swapped\n')
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert '1 passed' in combined, combined


def test_journey_launcher_refuses_exe_outside_stages(
        sealed, tmp_path):
    import hashlib
    import json
    import shutil
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import checkout_identity, \
        journey_identity_excludes, journey_staging_root
    from support.journey_prep import TARGETS
    # A digest-matching executable outside the configured
    # stages tree refuses: copying a valid record between
    # two prep roots must not execute the original root's
    # bytes.
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    stub = tmp_path / 'stub-outside'
    stub.write_text(harness)
    stub.chmod(0o755)
    # The outside file carries the honest staged name, so
    # this leg exercises containment rather than the
    # staged-filename binding.
    outside = tmp_path / TARGETS['deb']
    shutil.copyfile(stub, outside)
    outside.chmod(0o755)
    assert Path(journey_staging_root()).resolve() \
        not in outside.resolve().parents
    record_path = _prep_record_path('stub-outside')
    record_path.parent.mkdir(parents=True, exist_ok=True)
    commit, tree = checkout_identity(
        exclude=journey_identity_excludes())
    record_path.write_text(json.dumps(
        {'schema': 'memveil-journey-prep/1',
         'commit': commit, 'tree': tree,
         'suites': {'deb': {
             'path': str(stub),
             'staged': str(outside),
             'sha256': hashlib.sha256(
                 outside.read_bytes()).hexdigest(),
             'target': TARGETS['deb']}}}))
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record_path)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'outside the stages' in combined, combined
    assert 'journey-marker' not in result.stdout, combined


def test_journey_launcher_refuses_outside_exe_without_reading(
        sealed, tmp_path):
    import hashlib
    import json
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import checkout_identity, \
        journey_identity_excludes, journey_staging_root
    from support.journey_prep import TARGETS
    # Containment precedes any byte read: the outside
    # executable is unreadable, yet the refusal is still
    # the containment error rather than an IO error, so
    # the launch never opens unauthorized bytes.
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    # The outside file carries the honest staged name, so
    # this leg exercises containment rather than the
    # staged-filename binding.
    outside = tmp_path / TARGETS['deb']
    outside.write_text(harness)
    digest = hashlib.sha256(
        outside.read_bytes()).hexdigest()
    record_path = _prep_record_path('stub-outside-unread')
    record_path.parent.mkdir(parents=True, exist_ok=True)
    commit, tree = checkout_identity(
        exclude=journey_identity_excludes())
    assert Path(journey_staging_root()).resolve() \
        not in outside.resolve().parents
    record_path.write_text(json.dumps(
        {'schema': 'memveil-journey-prep/1',
         'commit': commit, 'tree': tree,
         'suites': {'deb': {
             'path': str(outside),
             'staged': str(outside),
             'sha256': digest,
             'target': TARGETS['deb']}}}))
    outside.chmod(0o000)
    try:
        environment = candidate_clean_env()
        environment.update(sealed)
        environment['MV_JOURNEY_PREP'] = str(record_path)
        result = _launch_journey('deb', environment)
    finally:
        outside.chmod(0o755)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'outside the stages' in combined, combined
    assert 'not executable' not in combined, combined
    assert 'unreadable' not in combined, combined
    assert 'Traceback' not in combined, combined
    assert 'journey-marker' not in result.stdout, combined


def test_journey_launcher_refuses_symlinked_stages_root(
        sealed, tmp_path):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_staging_root
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    _, staged, record_path = _journey_stub_record(
        tmp_path, harness)
    # The stages root itself is a link to bytes matching
    # the record: containment must refuse the link, never
    # follow it onto the honest-looking bytes.
    root = Path(journey_staging_root())
    real = tmp_path / 'stages-real'
    real.mkdir()
    shutil.copytree(staged.parent,
                    real / staged.parent.name)
    aside = tmp_path / 'stages-root-aside'
    shutil.move(str(root), str(aside))
    try:
        root.symlink_to(real, target_is_directory=True)
        environment = candidate_clean_env()
        environment.update(sealed)
        environment['MV_JOURNEY_PREP'] = str(record_path)
        result = _launch_journey('deb', environment)
        combined = result.stdout + result.stderr
        assert result.returncode == 2, combined
        assert 'symlink' in combined, combined
        assert 'Traceback' not in combined, combined
        assert 'journey-marker' not in result.stdout, \
            combined
    finally:
        if root.is_symlink():
            root.unlink()
        if aside.exists():
            shutil.move(str(aside), str(root))
    # The honest tree underneath still launches: the
    # refusal above fires on the link, not the setup.
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record_path)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert '1 passed' in combined, combined


def test_journey_launcher_refuses_symlinked_exe(
        sealed, tmp_path):
    import hashlib
    import json
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import checkout_identity, \
        journey_identity_excludes, journey_staging_root
    from support.journey_prep import TARGETS
    # A staged path that is a link refuses outright, even
    # when it points at digest-matching bytes inside the
    # stages tree: links are never followed on launch.
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    tag = '%d-%s' % (os.getpid(), uuid.uuid4().hex[:8])
    target_dir = Path(journey_staging_root()) / (
        'stub-target-%s.staged' % tag)
    target_dir.mkdir(parents=True)
    target = target_dir / TARGETS['deb']
    target.write_text(harness)
    target.chmod(0o755)
    link_dir = Path(journey_staging_root()) / (
        'stub-link-%s.staged' % tag)
    link_dir.mkdir(parents=True)
    link = link_dir / TARGETS['deb']
    link.symlink_to(target)
    record_path = _prep_record_path('stub-link')
    record_path.parent.mkdir(parents=True, exist_ok=True)
    commit, tree = checkout_identity(
        exclude=journey_identity_excludes())
    record_path.write_text(json.dumps(
        {'schema': 'memveil-journey-prep/1',
         'commit': commit, 'tree': tree,
         'suites': {'deb': {
             'path': str(target),
             'staged': str(link),
             'sha256': hashlib.sha256(
                 target.read_bytes()).hexdigest(),
             'target': TARGETS['deb']}}}))
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record_path)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'not a plain file' in combined, combined
    assert 'journey-marker' not in result.stdout, combined


def test_journey_launcher_accepts_honest_staged_exe(
        sealed, tmp_path):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_staging_root
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    _, staged, record_path = _journey_stub_record(
        tmp_path, harness)
    assert Path(journey_staging_root()) in \
        staged.resolve().parents
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record_path)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert 'journey-marker' in result.stdout, combined
    assert '1 passed' in combined, combined


def test_journey_shadowed_cargo_stays_green(sealed, tmp_path):
    record = _prep_record_path('prep')
    result = subprocess.run(
        [sys.executable,
         str(ROOT / 'tests/support/journey_prep.py'),
         str(record)],
        capture_output=True, text=True, timeout=900,
        cwd=str(ROOT))
    assert result.returncode == 0, result.stderr[-2000:]
    bindir, sentinel = _shadow_cargo_bin(tmp_path)
    env = {'PATH': bindir + ':/usr/bin:/bin',
           'MV_JOURNEY_PREP': str(record),
           'MV_JOURNEY_PREP_DIR': os.environ[
               'MV_JOURNEY_PREP_DIR']}
    env.update(sealed)
    result = subprocess.run(
        [sys.executable,
         str(ROOT / 'tests/support/candidate_suite.py'),
         'deb', 'journey_gate_matrix'],
        env=env, capture_output=True, text=True,
        timeout=300)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert '1 passed' in combined, combined
    assert 'CARGO-SHADOWED-STUB' not in combined, combined
    assert not Path(sentinel).exists(), \
        'qualification invoked cargo'


def test_journey_shadowed_rehomed_legs_green(tmp_path):
    sys.path.insert(0, str(ROOT / 'tests/package'))
    from sealed_fixture import (candidate_env,
                                seal_candidate)
    import test_release_runtime as legs
    sealed = seal_candidate(tmp_path, 'shadowed', shaped=True)
    record = _prep_record_path('prep')
    result = subprocess.run(
        [sys.executable,
         str(ROOT / 'tests/support/journey_prep.py'),
         str(record)],
        capture_output=True, text=True, timeout=900,
        cwd=str(ROOT))
    assert result.returncode == 0, result.stderr[-2000:]
    bindir, sentinel = _shadow_cargo_bin(tmp_path)
    env = {'PATH': bindir + ':/usr/bin:/bin',
           'MV_JOURNEY_PREP': str(record),
           'MV_JOURNEY_PREP_DIR': os.environ[
               'MV_JOURNEY_PREP_DIR']}
    env.update(candidate_env(sealed))
    targets = {'package_deb': 'deb',
               'package_rpm': 'rpm-journey'}
    assert set(target for target, _ in legs.CANDIDATE_SUITES) \
        == set(targets)
    for target, names in legs.CANDIDATE_SUITES:
        suite = targets[target]
        for name in names:
            result = subprocess.run(
                [sys.executable,
                 str(ROOT
                     / 'tests/support/candidate_suite.py'),
                 suite, name],
                env=env, capture_output=True, text=True,
                timeout=300)
            combined = result.stdout + result.stderr
            assert result.returncode == 0, \
                '%s %s: %s' % (
                    suite, name, combined[-2000:])
            assert '1 passed' in combined, \
                '%s ran no %s' % (suite, name)
    assert not Path(sentinel).exists(), \
        'qualification invoked cargo'


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


def test_guest_env_propagated(sealed):
    environment = candidate_clean_env()
    environment.update(sealed)
    script = ('import sys; sys.path.insert(0, '
              + repr(str(ROOT / 'tests')) + '); '
                'sys.path.insert(0, '
              + repr(str(ROOT / 'tests/vm')) + '); '
                'from support.candidate_input import load; '
                'import vm_boot; '
                'selected = load(); '
                'print(vm_boot.guest_exec_command('
                "'matrix', '/tmp/vmgate-work', '/repo', "
                'selected)); '
                'print(vm_boot.guest_exec_command('
                "'matrix', '/tmp/vmgate-work', '/repo', None))")
    result = subprocess.run(
        [sys.executable, '-c', script],
        env=environment, capture_output=True, text=True,
        timeout=120)
    assert result.returncode == 0, result.stderr
    propagated, dev = result.stdout.splitlines()
    assert 'MV_CANDIDATE_MANIFEST=' + sealed[
        'MV_CANDIDATE_MANIFEST'] in propagated
    assert 'MV_BUNDLE_TARBALL=' + sealed[
        'MV_BUNDLE_TARBALL'] in propagated
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate
    digest = candidate.digest_bytes(
        Path(sealed['MV_CANDIDATE_MANIFEST']).read_bytes())
    assert re.fullmatch(r'[0-9a-f]{64}', digest)
    assert 'MV_CANDIDATE_DIGEST=' + digest in propagated
    assert 'guest_lifecycle.py' in propagated
    assert 'matrix' in propagated
    assert dev.startswith('python3 ')
    assert dev.endswith(
        ' matrix /tmp/vmgate-work /tmp/export /repo')
    assert 'MV_CANDIDATE' not in dev
    assert 'MV_BUNDLE' not in dev


def test_guest_uses_candidate_bpf(sealed):
    environment = candidate_clean_env()
    environment.update(sealed)
    script = ('import os, sys; sys.path.insert(0, '
              + repr(str(ROOT / 'tests')) + '); '
                'sys.path.insert(0, '
              + repr(str(ROOT / 'tests/vm')) + '); '
                'from types import SimpleNamespace; '
                'from support.candidate_input import load; '
                'import guest_lifecycle, overhead_guest, '
                'vm_boot; '
                'selected = load(); '
                'print("root=" + str(selected.root)); '
                'resolved = guest_lifecycle.guest_bpf_objects('
                '"/repo", selected); '
                'assert os.path.isfile(resolved["lc_obj"]); '
                'assert os.path.isfile(resolved["cp_obj"]); '
                'print("lc=" + resolved["lc_obj"]); '
                'print("cp=" + resolved["cp_obj"]); '
                'dev = guest_lifecycle.guest_bpf_objects('
                '"/repo", None); '
                'print("dev-lc=" + dev["lc_obj"]); '
                'print("dev-cp=" + dev["cp_obj"]); '
                'stub = SimpleNamespace(repo="/repo", '
                'candidate=selected, lc_obj=resolved['
                '"lc_obj"], cp_obj=resolved["cp_obj"], '
                'lc_test_obj="/repo/build/bpf/'
                'swiotlb_lifecycle-test.bpf.o", '
                'cp_test_obj="/repo/build/bpf/'
                'swiotlb_copy-test.bpf.o", bridge="/repo/'
                'build/deps/lmb/lib/libbpf_mojo.so.1"); '
                'ctx = overhead_guest.build_ctx('
                'stub, "ethX", "/dev/X"); '
                'assert os.path.isfile(ctx["memveil"]); '
                'assert os.path.isfile(ctx["attempt_obj"]); '
                'print("ctx-memveil=" + ctx["memveil"]); '
                'print("ctx-attempt=" + ctx["attempt_obj"]); '
                'print("ctx-lc=" + ctx["lc_obj"]); '
                'print("ctx-cp=" + ctx["cp_obj"]); '
                'plain = SimpleNamespace(repo="/repo", '
                'candidate=None, lc_obj=dev["lc_obj"], '
                'cp_obj=dev["cp_obj"], lc_test_obj="/repo/'
                'build/bpf/swiotlb_lifecycle-test.bpf.o", '
                'cp_test_obj="/repo/build/bpf/'
                'swiotlb_copy-test.bpf.o", bridge="/repo/'
                'build/deps/lmb/lib/libbpf_mojo.so.1"); '
                'dctx = overhead_guest.build_ctx('
                'plain, "ethX", "/dev/X"); '
                'print("devctx-memveil=" + dctx["memveil"]); '
                'table = vm_boot.guest_artifact_paths('
                '"matrix", "/repo", selected); '
                'print("art-lc=" + table["lc_sha"]); '
                'print("art-cp=" + table["cp_sha"]); '
                'dtable = vm_boot.guest_artifact_paths('
                '"matrix", "/repo", None); '
                'print("devart-lc=" + dtable["lc_sha"]); '
                'stable = vm_boot.guest_artifact_paths('
                '"saturation", "/repo", None); '
                'print("devsat-lc=" + stable["lc_sha"])')
    result = subprocess.run(
        [sys.executable, '-c', script],
        env=environment, capture_output=True, text=True,
        timeout=120)
    assert result.returncode == 0, result.stderr
    assert 'libbpf_mojo.so' not in result.stdout
    facts = dict(
        line.split('=', 1)
        for line in result.stdout.splitlines())
    root = facts['root']
    for key in ('lc', 'cp', 'ctx-memveil', 'ctx-attempt',
                'ctx-lc', 'ctx-cp', 'art-lc', 'art-cp'):
        assert facts[key].startswith(root + '/'), key
    assert facts['lc'].endswith(
        'bpf/swiotlb_lifecycle.bpf.o')
    assert facts['cp'].endswith('bpf/swiotlb_copy.bpf.o')
    assert facts['ctx-attempt'].endswith(
        'bpf/swiotlb_attempt.bpf.o')
    assert facts['ctx-memveil'].endswith('bin/memveil')
    assert facts['ctx-lc'] == facts['lc']
    assert facts['ctx-cp'] == facts['cp']
    assert facts['art-lc'] == facts['lc']
    assert facts['art-cp'] == facts['cp']
    assert facts['dev-lc'] == (
        '/repo/build/bpf/swiotlb_lifecycle.bpf.o')
    assert facts['dev-cp'] == (
        '/repo/build/bpf/swiotlb_copy.bpf.o')
    assert facts['devctx-memveil'] == '/repo/build/memveil'
    assert facts['devart-lc'] == (
        '/repo/build/bpf/swiotlb_lifecycle.bpf.o')
    assert facts['devsat-lc'] == (
        '/repo/build/bpf/swiotlb_lifecycle-test.bpf.o')


def test_guest_identity_mismatch_refuses(sealed):
    environment = candidate_clean_env()
    environment.update(sealed)
    script = ('import sys; sys.path.insert(0, '
              + repr(str(ROOT / 'tests')) + '); '
                'sys.path.insert(0, '
              + repr(str(ROOT / 'tests/vm')) + '); '
                'from guest_lifecycle import '
                'load_guest_candidate; '
                'selected = load_guest_candidate("/repo"); '
                'print("digest=" + selected.digest)')
    control = subprocess.run(
        [sys.executable, '-c', script],
        env=environment, capture_output=True, text=True,
        timeout=120)
    assert control.returncode == 0, control.stderr
    assert re.fullmatch(r'digest=[0-9a-f]{64}\n',
                        control.stdout)
    tampered = dict(environment, MV_CANDIDATE_DIGEST='0' * 64)
    refused = subprocess.run(
        [sys.executable, '-c', script],
        env=tampered, capture_output=True, text=True,
        timeout=120)
    assert refused.returncode != 0
    assert 'digest' in refused.stderr
    assert 'digest=' not in refused.stdout


def test_topwalk_product_paths_resolve_packaged(sealed):
    sys.path.insert(0, str(ROOT / 'tests/vm'))
    import guest_lifecycle
    from support.candidate_input import load
    selected = load(env=sealed)
    try:
        memveil, attempt = \
            guest_lifecycle.topwalk_product_paths(
                '/repo', selected)
        assert memveil == str(selected.root / 'bin/memveil')
        assert attempt == str(
            selected.root / 'bpf/swiotlb_attempt.bpf.o')
        executed = subprocess.run(
            [memveil], capture_output=True, text=True,
            timeout=60)
        assert executed.stdout == 'packaged-synthetic\n'
        dev = guest_lifecycle.topwalk_product_paths(
            '/repo', None)
        assert dev == ('/repo/build/memveil',
                       '/repo/build/bpf/swiotlb_attempt.bpf.o')
    finally:
        selected.close()


def test_topwalk_guest_uses_packaged_paths(
        sealed, tmp_path, capsys):
    sys.path.insert(0, str(ROOT / 'tests/vm'))
    import guest_lifecycle
    from types import SimpleNamespace
    from support.candidate_input import load
    gate = SimpleNamespace(repo=str(tmp_path), candidate=None)
    with pytest.raises(SystemExit):
        guest_lifecycle.run_topwalk(gate)
    assert ('missing ' + str(tmp_path / 'build/memveil')) \
        in capsys.readouterr().err
    selected = load(env=sealed)
    try:
        gate = SimpleNamespace(
            repo=str(tmp_path), candidate=selected)
        with pytest.raises(SystemExit):
            guest_lifecycle.run_topwalk(gate)
        err = capsys.readouterr().err
        assert 'gate-profile.json' in err
        assert 'build/memveil' not in err
    finally:
        selected.close()


def test_topwalk_replay_selects_packaged_binary(
        sealed, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests/vm'))
    import guest_lifecycle
    from support import candidate_input
    for key in list(os.environ):
        if key in candidate_input.OVERRIDES \
                or key.startswith('MEMVEIL_TEST_'):
            monkeypatch.delenv(key, raising=False)
    for key, value in sealed.items():
        monkeypatch.setenv(key, value)
    previous, candidate_input._cached = \
        candidate_input._cached, None
    try:
        memveil, selected = \
            guest_lifecycle.topwalk_replay_binary('/repo')
        assert selected is not None
        assert memveil == str(selected.root / 'bin/memveil')
        executed = subprocess.run(
            [memveil], capture_output=True, text=True,
            timeout=60)
        assert executed.stdout == 'packaged-synthetic\n'
    finally:
        if candidate_input._cached is not None:
            candidate_input._cached.close()
        candidate_input._cached = previous
    monkeypatch.delenv('MV_BUNDLE_TARBALL')
    monkeypatch.delenv('MV_CANDIDATE_MANIFEST')
    memveil, selected = \
        guest_lifecycle.topwalk_replay_binary('/repo')
    assert selected is None
    assert memveil == '/repo/build/memveil'


def test_topwalk_memveil_binding_refuses_mismatch(sealed):
    sys.path.insert(0, str(ROOT / 'tests/vm'))
    import guest_lifecycle
    from support.candidate_input import load
    selected = load(env=sealed)
    try:
        pinned = selected.manifest['files']['bin/memveil']
        guest_lifecycle.assert_topwalk_memveil_binding(
            {'memveil_sha': pinned}, selected)
        guest_lifecycle.assert_topwalk_memveil_binding(
            {'memveil_sha': '0' * 64}, None)
        with pytest.raises(ValueError, match='memveil_sha'):
            guest_lifecycle.assert_topwalk_memveil_binding(
                {'memveil_sha': '0' * 64}, selected)
        with pytest.raises(ValueError, match='memveil_sha'):
            guest_lifecycle.assert_topwalk_memveil_binding(
                {}, selected)
    finally:
        selected.close()


def test_journey_scan_binds_digests_per_path(
        sealed, tmp_path):
    import hashlib
    import json
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import checkout_identity, \
        journey_identity_excludes, journey_staging_root, \
        refuse_unowned_prep_contents
    from support.journey_prep import TARGETS

    def harness(marker):
        return ('#!/bin/sh\necho %s\n'
                'echo "running 1 tests"\n'
                'echo "test journey_probe ... ok"\n'
                'echo "test result: ok. 1 passed; 0 failed; '
                '0 ignored; 0 measured; 0 filtered out"\n'
                % marker)

    # One stage holding both genuine harnesses; the
    # record binds each staged path to its own digest.
    tag = '%d-%s' % (os.getpid(), uuid.uuid4().hex[:8])
    stage_dir = Path(journey_staging_root()) / (
        'stub-bound-%s.staged' % tag)
    stage_dir.mkdir(parents=True)
    deb_file = stage_dir / TARGETS['deb']
    rpm_file = stage_dir / TARGETS['rpm-journey']
    deb_file.write_text(harness('journey-marker-deb'))
    rpm_file.write_text(harness('journey-marker-rpm'))
    deb_file.chmod(0o755)
    rpm_file.chmod(0o755)
    commit, tree = checkout_identity(
        exclude=journey_identity_excludes())
    record_path = _prep_record_path('stub-bound')
    record_path.parent.mkdir(parents=True, exist_ok=True)
    record_path.write_text(json.dumps(
        {'schema': 'memveil-journey-prep/1',
         'commit': commit, 'tree': tree,
         'suites': {
             'deb': {
                 'path': str(deb_file),
                 'staged': str(deb_file),
                 'sha256': hashlib.sha256(
                     deb_file.read_bytes()).hexdigest(),
                 'target': TARGETS['deb']},
             'rpm-journey': {
                 'path': str(rpm_file),
                 'staged': str(rpm_file),
                 'sha256': hashlib.sha256(
                     rpm_file.read_bytes()).hexdigest(),
                 'target': TARGETS['rpm-journey']}}}))
    # Honest bytes pass the scan and launch green.
    refuse_unowned_prep_contents()
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record_path)
    for suite, marker in (('deb', 'journey-marker-deb'),
                          ('rpm-journey',
                           'journey-marker-rpm')):
        result = _launch_journey(suite, environment)
        combined = result.stdout + result.stderr
        assert result.returncode == 0, combined
        assert marker in result.stdout, combined
    # Swap the deb staged bytes for the rpm bytes: the
    # resulting digest is genuine (claimed for the rpm
    # path) but claimed for no deb path, so the scan
    # refuses instead of crediting cross-path bytes.
    deb_file.write_bytes(rpm_file.read_bytes())
    with pytest.raises(
            ValueError,
            match='matching no digest referenced'):
        refuse_unowned_prep_contents()
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'matching no digest referenced' in combined, \
        combined
    assert 'journey-marker-rpm' not in result.stdout, \
        combined


def test_journey_launcher_refuses_cross_suite_staged_exe(
        sealed, tmp_path):
    import hashlib
    import json
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import checkout_identity, \
        journey_identity_excludes, journey_staging_root, \
        refuse_unowned_prep_contents
    from support.journey_prep import TARGETS

    def harness(marker):
        return ('#!/bin/sh\necho %s\n'
                'echo "running 1 tests"\n'
                'echo "test journey_probe ... ok"\n'
                'echo "test result: ok. 1 passed; 0 failed; '
                '0 ignored; 0 measured; 0 filtered out"\n'
                % marker)

    # Both genuine staged harnesses under one stage.
    tag = '%d-%s' % (os.getpid(), uuid.uuid4().hex[:8])
    stage_dir = Path(journey_staging_root()) / (
        'stub-mixed-%s.staged' % tag)
    stage_dir.mkdir(parents=True)
    deb_file = stage_dir / TARGETS['deb']
    rpm_file = stage_dir / TARGETS['rpm-journey']
    deb_file.write_text(harness('journey-marker-deb'))
    rpm_file.write_text(harness('journey-marker-rpm'))
    deb_file.chmod(0o755)
    rpm_file.chmod(0o755)
    deb_digest = hashlib.sha256(
        deb_file.read_bytes()).hexdigest()
    rpm_digest = hashlib.sha256(
        rpm_file.read_bytes()).hexdigest()
    commit, tree = checkout_identity(
        exclude=journey_identity_excludes())
    record_path = _prep_record_path('stub-mixed')
    record_path.parent.mkdir(parents=True, exist_ok=True)

    def write_record(deb_staged, deb_digest):
        record_path.write_text(json.dumps(
            {'schema': 'memveil-journey-prep/1',
             'commit': commit, 'tree': tree,
             'suites': {
                 'deb': {
                     'path': str(deb_staged),
                     'staged': str(deb_staged),
                     'sha256': deb_digest,
                     'target': TARGETS['deb']},
                 'rpm-journey': {
                     'path': str(rpm_file),
                     'staged': str(rpm_file),
                     'sha256': rpm_digest,
                     'target': TARGETS['rpm-journey']}}}))

    # The deb entry aims at the rpm staged bytes with the
    # rpm digest: every byte binding is genuine, and the
    # swapped binary's output would satisfy the generic
    # executed-test check, so only the pre-exec filename
    # binding can refuse the misattribution.
    write_record(rpm_file, rpm_digest)
    refuse_unowned_prep_contents()
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record_path)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert "stages another suite's" in combined, combined
    assert 'journey-marker-rpm' not in result.stdout, \
        combined
    # The honestly-aimed suite in the same record still
    # launches: only the mixed-up entry refuses.
    result = _launch_journey('rpm-journey', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert 'journey-marker-rpm' in result.stdout, combined
    # Honest control: each entry aimed at its own staged
    # file launches green for both suites.
    write_record(deb_file, deb_digest)
    for suite, marker in (('deb', 'journey-marker-deb'),
                          ('rpm-journey',
                           'journey-marker-rpm')):
        result = _launch_journey(suite, environment)
        combined = result.stdout + result.stderr
        assert result.returncode == 0, combined
        assert marker in result.stdout, combined


def test_journey_scan_judges_scratch_by_producer_name(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import PUBLISH_SCRATCH_RE, \
        journey_records_dir, refuse_unowned_prep_contents
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    fake.chmod(0o755)
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    records = Path(journey_records_dir())
    records.mkdir(parents=True, exist_ok=True)
    # Genuine publisher output matches the pinned
    # pattern: the rule under test accepts exactly what
    # the publisher emits.
    temps = []
    real_replace = os.replace

    def recording(src, dst):
        temps.append(src)
        return real_replace(src, dst)

    monkeypatch.setattr(os, 'replace', recording)
    prep.prepare(str(records / 'prep.json'))
    assert temps, 'record publish bypassed os.replace'
    for temp in temps:
        assert PUBLISH_SCRATCH_RE.fullmatch(
            Path(temp).name) is not None, temp
    # A lingering scratch file in the exact producer
    # shape passes the scan...
    honest = records / 'prep.json.deadbeef.tmp'
    honest.write_bytes(b'{"schema": "partial-')
    refuse_unowned_prep_contents()
    # ...while any other .tmp name refuses.
    honest.unlink()
    for impostor in ('notes.tmp', 'prep.json.tmp',
                     'prep.json.stale.tmp',
                     'prep.json.DEADBEEF.tmp',
                     'prep.txt.deadbeef.tmp',
                     '.json.deadbeef.tmp'):
        plant = records / impostor
        plant.write_bytes(b'{"schema": "partial-')
        with pytest.raises(ValueError, match='tool-owned'):
            refuse_unowned_prep_contents()
        plant.unlink()
    refuse_unowned_prep_contents()


def test_journey_scan_refuses_symlinked_record(
        sealed, tmp_path):
    harness = ('#!/bin/sh\necho journey-marker\n'
               'echo "running 1 tests"\n'
               'echo "test journey_probe ... ok"\n'
               'echo "test result: ok. 1 passed; 0 failed; '
               '0 ignored; 0 measured; 0 filtered out"\n')
    _, _, record_path = _journey_stub_record(
        tmp_path, harness)
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import \
        refuse_unowned_prep_contents
    link = record_path.parent / (
        'alias-%s.json' % uuid.uuid4().hex[:8])
    link.symlink_to(record_path)
    with pytest.raises(ValueError, match='symlink'):
        refuse_unowned_prep_contents()
    environment = candidate_clean_env()
    environment.update(sealed)
    environment['MV_JOURNEY_PREP'] = str(record_path)
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert 'symlink' in combined, combined
    assert 'journey-marker' not in result.stdout, combined
    # Honest control: without the link the same record
    # launches.
    link.unlink()
    result = _launch_journey('deb', environment)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert 'journey-marker' in result.stdout, combined


def test_journey_scan_validates_suite_entries(tmp_path):
    import json
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import \
        _prep_suite_entry_error, checkout_identity, \
        journey_identity_excludes, \
        refuse_unowned_prep_contents
    # The shared predicate pins the writer's entry shape:
    # one definition, used by both the scan and dispatch.
    good = {'path': 'p', 'staged': 's', 'sha256': 'd',
            'target': 't'}
    assert _prep_suite_entry_error(good) is None
    assert _prep_suite_entry_error(None) is not None
    assert _prep_suite_entry_error(['p']) is not None
    assert _prep_suite_entry_error(
        {'path': 'p', 'staged': 's',
         'sha256': 'd'}) is not None
    assert _prep_suite_entry_error(
        dict(good, sha256=12345)) is not None
    assert _prep_suite_entry_error(
        dict(good, extra=1)) is not None
    dispatch_text = (
        ROOT / 'tests/support/candidate_suite.py').read_text()
    prep_text = (
        ROOT / 'tests/support/journey_prep.py').read_text()
    assert prep_text.count(
        'def _prep_suite_entry_error') \
        + dispatch_text.count(
            'def _prep_suite_entry_error') == 1
    # The scan applies it to every entry of every record.
    commit, tree = checkout_identity(
        exclude=journey_identity_excludes())
    record_path = _prep_record_path('stub-entries')
    record_path.parent.mkdir(parents=True, exist_ok=True)

    def write_record(entry):
        record_path.write_text(json.dumps(
            {'schema': 'memveil-journey-prep/1',
             'commit': commit, 'tree': tree,
             'suites': {'deb': entry}}))

    write_record({'path': str(tmp_path / 'orig'),
                  'staged': str(tmp_path / 'package_deb'),
                  'sha256': '0' * 64,
                  'target': 'package_deb'})
    refuse_unowned_prep_contents()
    for bad in ('not-an-entry',
                {'path': str(tmp_path / 'orig'),
                 'staged': str(tmp_path / 'package_deb'),
                 'sha256': '0' * 64},
                {'path': str(tmp_path / 'orig'),
                 'staged': str(tmp_path / 'package_deb'),
                 'sha256': 12345,
                 'target': 'package_deb'}):
        write_record(bad)
        with pytest.raises(ValueError, match='invalid shape'):
            refuse_unowned_prep_contents()


def test_journey_prep_verifies_roots_before_any_write(
        tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.candidate_suite import journey_records_dir, \
        journey_staging_root
    import support.journey_prep as prep
    fake = tmp_path / 'fake-exe'
    fake.write_bytes(b'#!/bin/sh\necho fake\n')
    fake.chmod(0o755)
    monkeypatch.setattr(
        prep, 'build_executable', lambda target: fake)
    records = Path(journey_records_dir())
    root = Path(journey_staging_root())
    root.parent.mkdir(parents=True, exist_ok=True)
    real = tmp_path / 'real'
    real.mkdir()
    root.symlink_to(real, target_is_directory=True)
    calls = []
    real_chmod = os.chmod

    def recording(path, mode):
        calls.append((str(path), mode))
        return real_chmod(path, mode)

    monkeypatch.setattr(os, 'chmod', recording)
    # The linked stages root refuses before any write: the
    # records directory is never created and no mode
    # changes.
    assert not os.path.lexists(records)
    with pytest.raises(ValueError, match='symlink'):
        prep.prepare(str(records / 'prep.json'))
    assert calls == [], 'refused prep attempted chmod'
    assert not os.path.lexists(records), \
        'refused prep created its records dir'
    assert sorted(entry.name for entry in real.iterdir()) \
        == []
    # Honest control: without the link the same prep
    # proceeds and verifies.
    root.unlink()
    record = prep.prepare(str(records / 'prep.json'))
    assert (records / 'prep.json').is_file()
    for suite, entry in record['suites'].items():
        assert Path(entry['staged']).is_file(), suite
