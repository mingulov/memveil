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
    assert 'MV31-12' in combined, combined
    assert 'perf-workload:' not in combined, \
        'de-routed suite executed its runner'


def test_unlisted_dispatch_skip_fails(sealed):
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
    assert result.returncode == 1, combined
    assert 'FAIL' in combined and 'deferral' in combined, \
        combined


def test_deferred_allowlist_shape_validated():
    sys.path.insert(0, str(ROOT / 'tests'))
    from support import deferred_skips as ds
    from types import SimpleNamespace
    ds.validate()
    entry = ds.lookup('perf-workload')
    assert entry['owning-card'] == 'MV31-12'
    assert ds.listed_reason(entry['reason'])
    assert not ds.listed_reason('unlisted reason')
    assert ds.lookup('vm-kernels') is None
    bad_lists = [
        [{'suite': 'x', 'reason': 'r'}],
        [{'suite': 'x', 'reason': 'r',
          'owning-card': 'MV31-12', 'extra': 1}],
        [{'suite': '', 'reason': 'r',
          'owning-card': 'MV31-12'}],
        [{'suite': 'x', 'reason': '  ',
          'owning-card': 'MV31-12'}],
        [{'suite': 'x', 'reason': 'r',
          'owning-card': 'MV31'}],
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
    assert ds.unlisted_skips([SimpleNamespace(
        nodeid='a',
        longrepr=('f', 1, 'Skipped: nope'))]) != []
    assert ds.unlisted_skips([SimpleNamespace(
        nodeid='a', longrepr=(
            'f', 1, 'Skipped: ' + entry['reason']))]) == []


def test_conftest_passes_listed_skip_reason(sealed, tmp_path):
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
    (tmp_path / 'test_listed_skip.py').write_text(
        'import pytest\n'
        'pytestmark = pytest.mark.skip(reason='
        + json.dumps(reason) + ')\n'
        'def test_skip():\n'
        '    pass\n')
    result = subprocess.run(
        [sys.executable, '-m', 'pytest',
         'test_listed_skip.py', '-q', '-p',
         'no:cacheprovider'],
        env=environment, capture_output=True, text=True,
        cwd=tmp_path)
    assert 'skipped' in result.stdout, \
        result.stdout + result.stderr
    assert result.returncode == 0, \
        result.stdout + result.stderr


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
