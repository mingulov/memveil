# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline protocol tests; never boot a guest or attach a probe."""
import importlib.util
import os
from pathlib import Path
import sys
import pytest
sys.path.insert(0, str(Path(__file__).parent))
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'tests/support'))
from test_candidate_input import sealed  # noqa: E402,F401


def api():
    assert importlib.util.find_spec('candidate_live'), 'installed live campaign runner missing'
    import candidate_live
    return candidate_live


def measured(seconds=60, start=0):
    return {'workload': {'elapsed_seconds': seconds,
            'window': {'start_ns': str(start * 10**9), 'end_ns': str((start + seconds) * 10**9)},
            'metrics': {kind: {'completed_units': '1'} for kind in ('block', 'network')}}}


def test_soak_durations_do_not_shrink():
    m = api()
    assert m.SOAK_SECONDS >= 1800
    assert m.POOL_SECONDS > 4200


def test_top_and_record_are_separate_and_paired():
    m = api()
    schedule = m.schedule()
    for mode in ('attempt-record-summary', 'live-top-1s', 'journal-summary', 'journal-callers-detail'):
        pairs = [pair for pair in schedule if pair[0] == mode]
        assert len(pairs) >= 5
    top = m.product_command('/candidate/bin/memveil', 'live-top-1s', '/tmp/owned', 60)
    assert top[1] == 'top' and top[top.index('--interval') + 1] == '1s'
    plain = m.product_command('/candidate/bin/memveil', 'journal-summary', '/tmp/owned', 60)
    detail = m.product_command('/candidate/bin/memveil', 'journal-callers-detail', '/tmp/owned', 60)
    assert '--journal-callers' not in plain and '--journal-callers' in detail


@pytest.mark.parametrize('mode', ['overhead', 'soak', 'pool'])
def test_host_without_candidate_env_refuses(monkeypatch, mode):
    m = api()
    monkeypatch.setenv('MEMVEIL_VM_LIVE_SOAK', '1')
    monkeypatch.delenv('MV_BUNDLE_TARBALL', raising=False)
    monkeypatch.delenv('MV_CANDIDATE_MANIFEST', raising=False)
    monkeypatch.delenv('MV_CANDIDATE_DIGEST', raising=False)
    def no_spawn(*args, **kwargs): raise AssertionError('host refused before spawning')
    monkeypatch.setattr(m.subprocess, 'run', no_spawn)
    monkeypatch.setattr(m.subprocess, 'Popen', no_spawn)
    with pytest.raises(ValueError, match='both'):
        m.host(mode)
    from types import SimpleNamespace
    with pytest.raises(ValueError, match='both'):
        m.host(mode, candidate=SimpleNamespace(digest='f' * 64), opts={})


def test_host_rejects_unknown_mode(sealed, monkeypatch):
    from support import candidate_input
    m = api()
    for key in list(os.environ):
        if key in candidate_input.OVERRIDES or key.startswith('MEMVEIL_TEST_'):
            monkeypatch.delenv(key, raising=False)
    for key, value in sealed.items():
        monkeypatch.setenv(key, value)
    previous, candidate_input._cached = candidate_input._cached, None
    try:
        with pytest.raises(ValueError, match='unknown'):
            m.host('nope')
    finally:
        if candidate_input._cached is not None:
            candidate_input._cached.close()
        candidate_input._cached = previous


def test_unarmed_soak_77(sealed, monkeypatch):
    from support import candidate_input
    m = api()
    for key in list(os.environ):
        if key in candidate_input.OVERRIDES or key.startswith('MEMVEIL_TEST_'):
            monkeypatch.delenv(key, raising=False)
    for key, value in sealed.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('MEMVEIL_VM_LIVE_SOAK', raising=False)
    previous, candidate_input._cached = candidate_input._cached, None
    try:
        with pytest.raises(SystemExit) as caught:
            m.host('soak')
        assert caught.value.code == 77
    finally:
        if candidate_input._cached is not None:
            candidate_input._cached.close()
        candidate_input._cached = previous


@pytest.mark.parametrize('returncode', [1, 2, 3, 4, -9])
def test_attach_or_capture_refusal_is_failure(returncode):
    with pytest.raises(ValueError, match='exit'):
        api().require_product_exit(returncode)


def test_no_workload_or_short_duration_cannot_pass():
    m = api()
    with pytest.raises(ValueError): m.validate_duration(1800, 1799, 10, 10)
    with pytest.raises(ValueError): m.validate_duration(1800, 1800, 0, 10)
    with pytest.raises(ValueError): m.validate_duration(1800, 1800, 10, 0)


def test_soak_clock_excludes_nonworkload(monkeypatch):
    m = api()
    monkeypatch.setattr(m, 'SOAK_SECONDS', 900)
    clock = [0]
    result = {'legs': []}
    def one(mode, seconds, pool=False):
        before = clock[0]
        clock[0] += seconds + 60
        observation = measured(seconds, before)
        result['legs'].append(observation)
        return observation
    monkeypatch.setattr(m.time, 'monotonic', lambda: clock[0])
    m.run_soak(one, result)
    assert len(result['legs']) == 16
    assert result['measured_mixed_seconds'] == 900
    assert result['campaign_seconds_before_pool'] == 1800
    with pytest.raises(ValueError):
        m.validate_duration(1800, result['measured_mixed_seconds'], 1, 1)


def test_pool_requires_periodic_proof(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace
    m = api()
    quality = {key: {'status': 'complete_for_scope', 'loss_count': '0'}
               for key in ('detail', 'aggregate', 'correlation', 'baseline', 'terminal')}
    (tmp_path / 'session.json').write_text(json.dumps({'quality': quality, 'stop': {}}))
    events = [{'kind': 'pool_sample', 'ts_ns': '0'}, {'kind': 'bounce_attempt', 'ts_ns': '1'},
              {'kind': 'pool_sample', 'ts_ns': str(4260 * 10**9)}]
    (tmp_path / 'events.ndjson').write_text(''.join(json.dumps(event) + '\n' for event in events))
    monkeypatch.setattr(m.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0, stdout=b'{"integrity":{"status":"verified"}}'))
    with pytest.raises(ValueError, match='pool'):
        m.capture_facts('/unused', tmp_path, True, {'records': [], 'errors': [], 'cleanup': 'detached'},
                        measured(4260)['workload']['window'], str(4261 * 10**9))


def test_live_top_requires_cadence():
    m = api()
    window = measured()['workload']['window']
    with pytest.raises(ValueError, match='refresh'):
        m.validate_top_refreshes([str(int(v * 10**9)) for v in (1, 1.000001)], window)
    m.validate_top_refreshes([str(int((i + (.1 if i % 2 else -.1)) * 10**9))
                              for i in range(1, 60)], window)


@pytest.mark.parametrize('ticks', [list(range(-60, 0)),
                                  list(range(1, 20)) + list(range(40, 60)),
                                  [i / 1000 for i in range(60)]])
def test_live_top_rejects_bursts_gaps_and_outside_window(ticks):
    with pytest.raises(ValueError, match='refresh'):
        api().validate_top_refreshes([str(int(v * 10**9)) for v in ticks], measured()['workload']['window'])


def test_collector_output_retains_only_readiness_and_refresh_times():
    import io
    observed = {'ready': False, 'refresh_ns': [], 'error': None}
    api().observe_output(io.BytesIO(b'native raw secret diagnostic\nready session=allowlisted\n--- refresh 1\n--- refresh 2\n'), observed)
    assert observed['ready'] and len(observed['refresh_ns']) == 2
    assert 'secret' not in str(observed)


def paired_run():
    return {'valid': True, 'counts_ok': True, 'throughput': 100.0, 'p99': 5.0}


def test_journal_rows_need_capability():
    m = api()
    calls = []
    def one(mode, seconds):
        calls.append(mode)
        return {'workload': {'elapsed_seconds': seconds,
                'window': {'start_ns': '0', 'end_ns': str(seconds * 10**9)},
                'metrics': {kind: dict(paired_run()) for kind in ('block', 'network')}}}
    result = {'comparisons': []}
    m.run_overhead(one, result, admit=lambda mode: (False, 'conversion-journal not admitted'))
    skips = [row for row in result['comparisons'] if row['status'] == 'SKIP']
    assert len(skips) == 4
    assert all(row['reason'] for row in skips)
    assert {row['mode'] for row in skips} == {'journal-summary', 'journal-callers-detail'}
    assert 'journal-summary' not in calls and 'journal-callers-detail' not in calls
    assert len(calls) == 20
    m.require_campaign_targets(result['comparisons'])
    admitted, calls2 = {'comparisons': []}, []
    def run(mode, seconds):
        calls2.append(mode)
        return one(mode, seconds)
    m.run_overhead(run, admitted, admit=lambda mode: (True, ''))
    assert len(admitted['comparisons']) == 8
    assert all(row['status'] == 'PASS' for row in admitted['comparisons'])
    assert len(calls2) == 40
    with pytest.raises(ValueError):
        m.require_campaign_targets([{'mode': 'journal-summary', 'metric': 'block',
                                     'status': 'SKIP', 'reason': ''}])
    with pytest.raises(ValueError):
        m.require_campaign_targets([{'mode': 'attempt-record-summary', 'metric': 'block',
                                     'status': 'SKIP', 'reason': 'unsupported'}])


def test_journal_admission_maps_doctor_verdicts(tmp_path):
    m = api()
    for code in (0, 3, 1):
        script = tmp_path / ('doctor%d' % code)
        script.write_text('#!/bin/sh\nexit %d\n' % code)
        script.chmod(0o755)
    assert m.journal_admission(tmp_path / 'doctor0') == (True, '')
    admitted, reason = m.journal_admission(tmp_path / 'doctor3')
    assert admitted is False and 'conversion-journal' in reason
    with pytest.raises(ValueError):
        m.journal_admission(tmp_path / 'doctor1')


@pytest.mark.parametrize('failure', ['product', 'report', 'cleanup'])
def test_failure_retains_capture(tmp_path, monkeypatch, failure):
    import json
    m = api()
    local, export = tmp_path / 'local', tmp_path / 'export'
    local.mkdir(); export.mkdir()
    error = m.ProductExit(3) if failure == 'product' else ValueError(failure + ' failed')
    def fail(binary, disk, mode, work, seconds, pool=False, observation=None, **kwargs):
        capture = work / 'capture'
        capture.mkdir()
        (capture / 'checkpoint.json').write_text('{"synthetic":true}')
        (capture / 'events.ndjson').write_text('')
        observation['product_exit'] = 3 if failure == 'product' else 0
        observation['output'] = {'ready': True}
        raise error
    monkeypatch.setattr(m, 'leg', fail)
    with pytest.raises(type(error)) as caught:
        m.record_leg('/unused', '/unused', 'attempt-record-summary', 60, False, local, export, 0)
    assert caught.value is error
    assert (local / 'leg-0/capture/checkpoint.json').exists()
    assert (export / 'failed-0/capture/checkpoint.json').exists()
    receipt = json.loads((local / 'leg-0/observations.json').read_text())
    assert receipt['status'] == 'FAIL' and receipt['output']['ready']
    assert receipt['product_exit'] == (3 if failure == 'product' else 0)


def test_export_failure_keeps_original_product_exit_and_local_capture(tmp_path, monkeypatch):
    import json
    m = api()
    local, export = tmp_path / 'local', tmp_path / 'export'
    local.mkdir(); export.mkdir()
    def fail(binary, disk, mode, work, seconds, pool=False, observation=None, **kwargs):
        (work / 'capture').mkdir()
        (work / 'capture/checkpoint.json').write_text('{"synthetic":true}')
        observation['product_exit'] = 3
        raise m.ProductExit(3)
    monkeypatch.setattr(m, 'leg', fail)
    monkeypatch.setattr(m, 'retain_capture', lambda *a: (_ for _ in ()).throw(OSError('export failed')))
    with pytest.raises(m.ProductExit) as caught:
        m.record_leg('/unused', '/unused', 'attempt-record-summary', 60, False, local, export, 0)
    assert caught.value.product_exit == 3
    assert (local / 'leg-0/capture/checkpoint.json').exists()
    receipt = json.loads((local / 'leg-0/observations.json').read_text())
    assert receipt['product_exit'] == 3 and receipt['export_error']


def test_cleanup_failure_does_not_replace_primary_product_failure(tmp_path, monkeypatch):
    m = api()
    monkeypatch.setattr(m, 'inventory', lambda: {})
    monkeypatch.setattr(m, 'workload', lambda *a, **k: (_ for _ in ()).throw(m.ProductExit(3)))
    monkeypatch.setattr(m, 'settled', lambda *a: (_ for _ in ()).throw(ValueError('cleanup failed')))
    observation = {}
    with pytest.raises(m.ProductExit) as caught:
        m.leg('/unused', '/unused', 'off', tmp_path, 60, observation=observation)
    assert caught.value.product_exit == 3
    assert observation['cleanup_errors']


def test_failure_export_refuses_alias_without_deleting_foreign_file(tmp_path):
    m = api()
    work = tmp_path / 'work'; work.mkdir()
    (work / 'capture').mkdir()
    foreign = tmp_path / 'foreign'; foreign.write_text('preserve')
    (work / 'capture/checkpoint.json').symlink_to(foreign)
    with pytest.raises((ValueError, OSError)):
        m.retain_capture(work, tmp_path / 'export')
    assert foreign.read_text() == 'preserve'


@pytest.mark.parametrize('refreshes,accept', [([1, 1.000001], False), (list(range(1, 60)), True)])
def test_real_leg_applies_measured_top_cadence_guard(tmp_path, monkeypatch, refreshes, accept):
    import io
    m = api()
    class Process:
        pid = 123
        stdout = io.BytesIO()
        returncode = None
        def poll(self): return self.returncode
        def send_signal(self, signal): self.returncode = 0
        def wait(self, timeout): return self.returncode
    process = Process()
    def output(stream, observed):
        observed.update(ready=True, refresh_ns=[str(int(tick * 10**9)) for tick in refreshes])
    monkeypatch.setattr(m, 'inventory', lambda: {})
    monkeypatch.setattr(m, 'settled', lambda before: {})
    monkeypatch.setattr(m, 'observe_output', output)
    monkeypatch.setattr(m, 'workload', lambda *args, **kwargs: measured()['workload'])
    monkeypatch.setattr(m, 'capture_facts', lambda *args: {})
    monkeypatch.setattr(m.subprocess, 'Popen', lambda *args, **kwargs: process)
    if accept:
        assert m.leg('/unused', '/unused', 'live-top-1s', tmp_path, 60)['product_exit'] == 0
    else:
        with pytest.raises(ValueError, match='refresh'):
            m.leg('/unused', '/unused', 'live-top-1s', tmp_path, 60)


def test_workload_oracle_rejects_short_io_and_packet_loss():
    m = api()
    assert m.completed_units('block', b'', b'16777216 bytes (17 MB) copied, 1 s', False) == 16777216
    assert m.completed_units('network', b'32 packets transmitted, 32 received, 0% packet loss', b'', False) == 32
    for kind, out, err in [('block', b'', b'1024 bytes (1 KB) copied, 1 s'),
                            ('network', b'32 packets transmitted, 1 received, 97% packet loss', b'')]:
        with pytest.raises(ValueError): m.completed_units(kind, out, err, False)


@pytest.mark.parametrize('field,value', [('token', '../foreign'), ('guest_boot', 'host'),
    ('serial', 'foreign'), ('sectors', 1), ('mac', '52:54:00:00:00:00'), ('mounted', True),
    ('cmdline', [])])
def test_guest_ownership_is_required_before_mutation(field, value):
    values = dict(token='0123456789abcdef', cmdline=['swiotlb=force', 'memveil_candidate_guest=0123456789abcdef'],
                  guest_boot='guest', host_boot='host', serial='mv-0123456789abcdef', sectors=131072,
                  mac='52:54:00:ab:cd:ef', mounted=False)
    api().validate_guest_identity(**values)
    values[field] = value
    with pytest.raises(ValueError): api().validate_guest_identity(**values)


def test_installed_verification_ignores_unrelated_system_binaries(tmp_path):
    import hashlib
    root = tmp_path / 'system'
    files = {'bin/memveil': b'candidate', 'lib/memveil/libx.so.1': b'library',
             'bpf/probe.bpf.o': b'probe', 'profiles/test.json': b'profile'}
    mapping = {'bin/memveil': 'usr/bin/memveil', 'lib/memveil/libx.so.1': 'usr/lib/memveil/libx.so.1',
               'bpf/probe.bpf.o': 'usr/lib/memveil/probe.bpf.o', 'profiles/test.json': 'usr/share/memveil/profiles/test.json'}
    entries = {}
    for name, value in files.items():
        path = root / mapping[name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        entries[name] = hashlib.sha256(value).hexdigest()
    (root / 'usr/bin/unrelated').write_bytes(b'unrelated system binary')
    api().verify_installed({'files': entries}, root)
    (root / 'usr/lib/memveil/foreign.so').write_bytes(b'wrong')
    with pytest.raises(ValueError): api().verify_installed({'files': entries}, root)


@pytest.mark.parametrize('prefix', ['usr/lib/memveil', 'usr/share/memveil', 'usr/share/doc/memveil'])
def test_private_extra_files_never_hide_in_installed_snapshot(tmp_path, prefix):
    root = tmp_path / 'system'
    path = root / prefix / 'foreign.so'
    path.parent.mkdir(parents=True)
    path.write_bytes(b'extra')
    with pytest.raises(ValueError, match='extra'):
        api().verify_installed({'files': {}}, root)


@pytest.mark.parametrize('parent', [False, True])
def test_installed_leaf_and_parent_aliases_refuse_without_touching_foreign_files(tmp_path, parent):
    import hashlib
    root = tmp_path / 'system'
    foreign = tmp_path / 'foreign'
    foreign.mkdir()
    (foreign / 'memveil').write_bytes(b'unchanged')
    if parent:
        (root / 'usr').mkdir(parents=True)
        (root / 'usr/bin').symlink_to(foreign, target_is_directory=True)
    else:
        (root / 'usr/bin').mkdir(parents=True)
        (root / 'usr/bin/memveil').symlink_to(foreign / 'memveil')
    doc = {'files': {'bin/memveil': hashlib.sha256(b'unchanged').hexdigest()}}
    with pytest.raises(ValueError, match='alias'):
        api().verify_installed(doc, root)
    assert (foreign / 'memveil').read_bytes() == b'unchanged'
