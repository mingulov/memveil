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


def _sealed_arming_env(monkeypatch, sealed):
    from support import candidate_input
    for key in list(os.environ):
        if key in candidate_input.OVERRIDES or key.startswith('MEMVEIL_TEST_'):
            monkeypatch.delenv(key, raising=False)
    for key, value in sealed.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('MEMVEIL_VM_LIVE_SOAK', raising=False)
    monkeypatch.delenv('MEMVEIL_VM_PERF', raising=False)
    previous, candidate_input._cached = candidate_input._cached, None
    return previous


def _restore_sealed(previous):
    from support import candidate_input
    if candidate_input._cached is not None:
        candidate_input._cached.close()
    candidate_input._cached = previous


def test_host_arming_is_per_mode(sealed, monkeypatch):
    m = api()
    assert m.ARMED_VARS == {'overhead': 'MEMVEIL_VM_PERF',
                            'soak': 'MEMVEIL_VM_LIVE_SOAK',
                            'pool': 'MEMVEIL_VM_LIVE_SOAK'}
    previous = _sealed_arming_env(monkeypatch, sealed)
    try:
        monkeypatch.setenv('MEMVEIL_VM_LIVE_SOAK', '1')
        with pytest.raises(SystemExit) as caught:
            m.host('overhead')
        assert caught.value.code == 77
        monkeypatch.delenv('MEMVEIL_VM_LIVE_SOAK')
        monkeypatch.setenv('MEMVEIL_VM_PERF', '1')
        with pytest.raises(SystemExit) as caught:
            m.host('soak')
        assert caught.value.code == 77
        with pytest.raises(SystemExit) as caught:
            m.host('pool')
        assert caught.value.code == 77
    finally:
        _restore_sealed(previous)


def test_host_overhead_armed_via_perf_flag(sealed, monkeypatch, tmp_path):
    from types import SimpleNamespace
    m = api()
    previous = _sealed_arming_env(monkeypatch, sealed)
    monkeypatch.setenv('MEMVEIL_VM_PERF', '1')
    monkeypatch.setattr(m, 'ROOT', tmp_path)
    calls = []
    def fake_guest(cmd, timeout):
        calls.append((list(cmd), timeout))
        return SimpleNamespace(returncode=1, stdout='stub stdout\n',
                                 stderr='stub stderr\n')
    monkeypatch.setitem(sys.modules, 'test_attempt_capture',
                        SimpleNamespace(gate_prefix=lambda: (['true'], None)))
    monkeypatch.setitem(sys.modules, 'vm_process',
                        SimpleNamespace(run_owned_guest=fake_guest))
    try:
        with pytest.raises(ValueError, match='guest campaign failed'):
            m.host('overhead')
    finally:
        _restore_sealed(previous)
    assert len(calls) == 1
    assert calls[0][1] == m.TIMEOUTS['overhead']
    assert 'overhead' in calls[0][0][-1]


def test_host_boots_full_machine_for_pcnet(sealed, monkeypatch, tmp_path):
    from types import SimpleNamespace
    m = api()
    previous = _sealed_arming_env(monkeypatch, sealed)
    monkeypatch.setenv('MEMVEIL_VM_PERF', '1')
    monkeypatch.setattr(m, 'ROOT', tmp_path)
    calls = []
    def fake_guest(cmd, timeout):
        calls.append((list(cmd), timeout))
        return SimpleNamespace(returncode=1, stdout='stub stdout\n',
                                 stderr='stub stderr\n')
    monkeypatch.setitem(sys.modules, 'test_attempt_capture',
                        SimpleNamespace(gate_prefix=lambda: (['true'], None)))
    monkeypatch.setitem(sys.modules, 'vm_process',
                        SimpleNamespace(run_owned_guest=fake_guest))
    try:
        with pytest.raises(ValueError, match='guest campaign failed'):
            m.host('overhead')
    finally:
        _restore_sealed(previous)
    assert len(calls) == 1
    argv = calls[0][0]
    assert '--disable-microvm' in argv
    assert argv.index('--disable-microvm') < argv.index('--exec')
    assert any(part.startswith('--qemu-opts=') and 'pcnet' in part
               for part in argv)


@pytest.mark.parametrize('evil', ['x"y', 'o$(touch_x)', 'x;y',
                                 'x y'])
def test_host_rewritten_out_refused_before_boot(sealed, monkeypatch,
                                                tmp_path, evil):
    from types import SimpleNamespace
    m = api()
    previous = _sealed_arming_env(monkeypatch, sealed)
    monkeypatch.setenv('MEMVEIL_VM_PERF', '1')
    monkeypatch.setattr(m, 'ROOT', tmp_path)
    calls = []
    def fake_guest(cmd, timeout):
        calls.append((list(cmd), timeout))
        return SimpleNamespace(returncode=0)
    monkeypatch.setitem(sys.modules, 'test_attempt_capture',
                        SimpleNamespace(gate_prefix=lambda: (['true'], None)))
    monkeypatch.setitem(sys.modules, 'vm_process',
                        SimpleNamespace(run_owned_guest=fake_guest))
    try:
        with pytest.raises(ValueError, match='launcher shell'):
            m.host('overhead', opts={'out': str(tmp_path / evil)})
    finally:
        _restore_sealed(previous)
    assert calls == []
    assert not (tmp_path / evil).exists()


def test_host_honest_out_reaches_boot(sealed, monkeypatch, tmp_path):
    from types import SimpleNamespace
    m = api()
    previous = _sealed_arming_env(monkeypatch, sealed)
    monkeypatch.setenv('MEMVEIL_VM_PERF', '1')
    monkeypatch.setattr(m, 'ROOT', tmp_path)
    calls = []
    def fake_guest(cmd, timeout):
        calls.append((list(cmd), timeout))
        return SimpleNamespace(returncode=1, stdout='stub stdout\n',
                                 stderr='stub stderr\n')
    monkeypatch.setitem(sys.modules, 'test_attempt_capture',
                        SimpleNamespace(gate_prefix=lambda: (['true'], None)))
    monkeypatch.setitem(sys.modules, 'vm_process',
                        SimpleNamespace(run_owned_guest=fake_guest))
    try:
        with pytest.raises(ValueError, match='guest campaign failed'):
            m.host('overhead', opts={'out': str(tmp_path / 'ev')})
    finally:
        _restore_sealed(previous)
    assert len(calls) == 1


def test_host_rewritten_tmpdir_refused_before_boot(sealed, monkeypatch,
                                                   tmp_path):
    import tempfile
    from types import SimpleNamespace
    m = api()
    previous = _sealed_arming_env(monkeypatch, sealed)
    monkeypatch.setenv('MEMVEIL_VM_PERF', '1')
    monkeypatch.setattr(m, 'ROOT', tmp_path)
    calls = []
    def fake_guest(cmd, timeout):
        calls.append((list(cmd), timeout))
        return SimpleNamespace(returncode=0)
    monkeypatch.setitem(sys.modules, 'test_attempt_capture',
                        SimpleNamespace(gate_prefix=lambda: (['true'], None)))
    monkeypatch.setitem(sys.modules, 'vm_process',
                        SimpleNamespace(run_owned_guest=fake_guest))
    hostile = tmp_path / 't"mp'
    hostile.mkdir()
    monkeypatch.setenv('TMPDIR', str(hostile))
    monkeypatch.setattr(tempfile, 'tempdir', None)
    try:
        with pytest.raises(ValueError, match='launcher shell'):
            m.host('overhead')
    finally:
        _restore_sealed(previous)
    assert calls == []


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
    assert result['mixed_seconds'] == 900
    assert result['campaign_seconds_before_pool'] == 1800
    with pytest.raises(ValueError):
        m.validate_duration(1800, result['mixed_seconds'], 1, 1)


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


def test_admitted_journal_detail_fail_refuses_campaign():
    m = api()
    def one(mode, seconds):
        return {'workload': {'elapsed_seconds': seconds,
                'window': {'start_ns': '0', 'end_ns': str(seconds * 10**9)},
                'metrics': {kind: dict(paired_run()) for kind in ('block', 'network')}}}
    result = {'comparisons': []}
    m.run_overhead(one, result, admit=lambda mode: (True, ''))
    assert len(result['comparisons']) == 8
    assert all(row['target_required'] for row in result['comparisons'])
    detail = [row for row in result['comparisons'] if row['mode'] == 'journal-callers-detail']
    assert len(detail) == 2
    detail[0]['status'] = 'FAIL'
    with pytest.raises(ValueError, match='target failed'):
        m.require_campaign_targets(result['comparisons'])


def test_journal_admission_maps_doctor_verdicts(tmp_path):
    m = api()
    for code in (0, 3, 1, 2):
        script = tmp_path / ('doctor%d' % code)
        script.write_text('#!/bin/sh\nexit %d\n' % code)
        script.chmod(0o755)
    assert m.journal_admission(tmp_path / 'doctor0') == (True, '')
    admitted, reason = m.journal_admission(tmp_path / 'doctor3')
    assert admitted is False and 'conversion-journal' in reason
    with pytest.raises(ValueError):
        m.journal_admission(tmp_path / 'doctor1')
    # An unknown capability (doctor exit 2) is a failure,
    # never an admission decline.
    with pytest.raises(ValueError):
        m.journal_admission(tmp_path / 'doctor2')


@pytest.mark.parametrize('failure', ['product', 'report', 'cleanup'])
def test_failure_retains_capture(tmp_path, monkeypatch, failure):
    import json
    m = api()
    local, export = tmp_path / 'local', tmp_path / 'export'
    local.mkdir(); export.mkdir()
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
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
        m.record_leg('/unused', '/unused', 'attempt-record-summary', 60, False, local, export, 0, scratch=scratch)
    assert caught.value is error
    assert (scratch / 'leg-0/capture/checkpoint.json').exists()
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
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    def fail(binary, disk, mode, work, seconds, pool=False, observation=None, **kwargs):
        (work / 'capture').mkdir()
        (work / 'capture/checkpoint.json').write_text('{"synthetic":true}')
        observation['product_exit'] = 3
        raise m.ProductExit(3)
    monkeypatch.setattr(m, 'leg', fail)
    monkeypatch.setattr(m, 'retain_capture', lambda *a: (_ for _ in ()).throw(OSError('export failed')))
    with pytest.raises(m.ProductExit) as caught:
        m.record_leg('/unused', '/unused', 'attempt-record-summary', 60, False, local, export, 0, scratch=scratch)
    assert caught.value.product_exit == 3
    assert (scratch / 'leg-0/capture/checkpoint.json').exists()
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
        stderr = io.BytesIO()
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


def _campaign_metric(units, seconds):
    # Honest cached values derive from the retained bytes
    # through the verifier's own re-derivation, so the
    # fixture can never drift from the re-derivation rule.
    derived = api().rederived_metric(
        {'start_ns': '0', 'end_ns': str(seconds * 10**9)},
        {'completed_units': units, 'operation_seconds': [0.5]})
    return {'valid': True, 'counts_ok': True,
            'throughput': derived['throughput'], 'p99': derived['p99'],
            'completed_units': units, 'operation_seconds': [0.5]}


def _campaign_window(start_ns, seconds):
    return {'elapsed_seconds': float(seconds),
            'window': {'start_ns': str(start_ns),
                       'end_ns': str(start_ns + seconds * 10**9)},
            'metrics': {'block': _campaign_metric('16777216', seconds),
                        'network': _campaign_metric('32', seconds)},
            'samples': [{'elapsed_monotonic_ns': str(start_ns), 'rss_kib': '1024',
                         'fd_count': '8', 'map_memlock_bytes': {}}]}


def _campaign_quality():
    return {key: {'status': 'complete_for_scope', 'loss_count': '0'}
            for key in ('detail', 'aggregate', 'correlation', 'baseline', 'terminal')}


def _campaign_capture(session_bytes, events_bytes, kinds):
    import hashlib
    return {'quality': _campaign_quality(), 'stop': {}, 'kinds': kinds,
            'session_sha256': hashlib.sha256(session_bytes).hexdigest(),
            'events_sha256': hashlib.sha256(events_bytes).hexdigest()}


def _campaign_retained(session_bytes, events_bytes):
    import hashlib
    return {'session.json': {'bytes': str(len(session_bytes)),
                             'sha256': hashlib.sha256(session_bytes).hexdigest(),
                             'truncated': False},
            'events.ndjson': {'bytes': str(len(events_bytes)),
                              'sha256': hashlib.sha256(events_bytes).hexdigest(),
                              'truncated': False}}


def _pool_leg():
    import json
    session_bytes = json.dumps({'quality': _campaign_quality(), 'stop': {}}).encode()
    samples = [str(tick * 1025000000) for tick in range(4150)]
    events = ''.join(json.dumps({'kind': 'pool_sample', 'ts_ns': tick}) + '\n'
                     for tick in samples)
    events += json.dumps({'kind': 'bounce_attempt', 'ts_ns': '1'}) + '\n'
    events_bytes = events.encode()
    records = []
    for field in ('used', 'capacity'):
        for tick in range(4261):
            records.append({'field': field, 'returned_bytes': '3',
                            'received_ns': str(tick * 10**9)})
    leg = {'ordinal': '0', 'mode': 'attempt-record-summary', 'status': 'PASS',
           'bpf_before': {}, 'bpf_after': {}, 'product_exit': 0, 'cleanup_errors': [],
           'output': {'ready': True, 'refresh_ns': [], 'error': None},
           'warmup': _campaign_window(0, 10),
           'workload': _campaign_window(0, 4261),
           'stop_signal_ns': str(4262 * 10**9),
           'pool_oracle': {'records': records, 'errors': [], 'cleanup': 'detached'},
           'capture': _campaign_capture(
               session_bytes, events_bytes,
               {'pool_sample': '4150', 'bounce_attempt': '1'}),
           'retained_capture': _campaign_retained(session_bytes, events_bytes),
           'retained_verification': 'verified-capture'}
    return leg, {'session.json': session_bytes, 'events.ndjson': events_bytes}


def _write_export_leg(export, ordinal, leg, files):
    slot = export / ('completed-' + str(ordinal))
    (slot / 'capture').mkdir(parents=True)
    for name, data in files.items():
        (slot / 'capture' / name).write_bytes(data)
    api().write_observations(slot / 'observations.json', leg)


def _write_campaign(export, manifest, mode, legs, comparisons, extra=None):
    import json
    m = api()
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate as c
    result = {'schema': 'memveil-installed-campaign/1',
              'candidate': c.digest_bytes(c.canonical(manifest)),
              'mode': mode, 'environment': 'ordinary-linux', 'kernel': 'test-kernel',
              'btf_sha256': 'ab' * 32, 'config_sha256': 'cd' * 32,
              'source': manifest['source'], 'toolchain': manifest['toolchain'],
              'build_receipt_sha256': manifest['build_receipt_sha256'],
              'runtime_files': manifest['files'],
              'helpers': {}, 'legs': legs, 'comparisons': comparisons,
              'cleanup': {'before': {}, 'after': {}}}
    if extra:
        result.update(extra)
    result['totals'] = m.campaign_totals(result)
    with (export / 'campaign.json').open('x') as stream:
        json.dump(result, stream, sort_keys=True)
    for ordinal in range(len(legs)):
        m.write_observations(export / ('progress-' + str(ordinal) + '.json'),
                             {'schema': result['schema'], 'candidate': result['candidate'],
                              'mode': mode, 'legs': legs[:ordinal + 1]})
    return result


def _pool_export(export, manifest):
    leg, files = _pool_leg()
    _write_export_leg(export, 0, leg, files)
    return _write_campaign(export, manifest, 'pool', [leg], [],
                           {'pool': {'legs': 1, 'observation': leg}})


def _overhead_product_leg(ordinal, mode, start_ns):
    import json
    session_bytes = json.dumps({'quality': _campaign_quality(), 'stop': {}}).encode()
    events_bytes = ''.join(json.dumps({'kind': 'bounce_attempt', 'ts_ns': str(tick)})
                           + '\n' for tick in range(3)).encode()
    output = {'ready': True, 'refresh_ns': [], 'error': None}
    if mode == 'live-top-1s':
        output['refresh_ns'] = [str(start_ns + tick * 10**9) for tick in range(1, 60)]
    leg = {'ordinal': str(ordinal), 'mode': mode, 'status': 'PASS',
           'bpf_before': {}, 'bpf_after': {}, 'product_exit': 0, 'cleanup_errors': [],
           'output': output,
           'warmup': _campaign_window(start_ns, 10),
           'workload': _campaign_window(start_ns, 60),
           'stop_signal_ns': str(start_ns + 61 * 10**9),
           'capture': _campaign_capture(session_bytes, events_bytes,
                                        {'bounce_attempt': '3'}),
           'retained_capture': _campaign_retained(session_bytes, events_bytes),
           'retained_verification': 'verified-capture'}
    return leg, {'session.json': session_bytes, 'events.ndjson': events_bytes}


def _overhead_off_leg(ordinal, start_ns):
    return {'ordinal': str(ordinal), 'mode': 'off', 'status': 'PASS',
            'bpf_before': {}, 'bpf_after': {}, 'product_exit': None, 'cleanup_errors': [],
            'warmup': _campaign_window(start_ns, 10),
            'workload': _campaign_window(start_ns, 60),
            'capture': None, 'retained_capture': {},
            'retained_verification': 'verified-capture'}, {}


def _overhead_export(export, manifest):
    m = api()
    skipped = {'journal-summary', 'journal-callers-detail'}
    legs, files = [], []
    ordinal = 0
    for mode, pair in m.schedule():
        if mode in skipped:
            continue
        order = ('off', mode) if pair % 2 == 0 else (mode, 'off')
        for label in order:
            start_ns = ordinal * 100 * 10**9
            if label == 'off':
                leg, leg_files = _overhead_off_leg(ordinal, start_ns)
            else:
                leg, leg_files = _overhead_product_leg(ordinal, label, start_ns)
            legs.append(leg)
            files.append(leg_files)
            ordinal += 1
    pairs = {mode: ([], []) for mode in m.MODES if mode not in skipped}
    index = 0
    for mode, pair in m.schedule():
        if mode in skipped:
            continue
        first, second = legs[index], legs[index + 1]
        index += 2
        observations = {first['mode']: first, second['mode']: second}
        pairs[mode][0].append(observations['off'])
        pairs[mode][1].append(observations[mode])
    comparisons = []
    for mode, (baselines, observers) in pairs.items():
        for metric in ('block', 'network'):
            measurement = m.compare(
                mode + '/' + metric,
                [row['workload']['metrics'][metric] for row in baselines],
                [row['workload']['metrics'][metric] for row in observers])
            status, reason = m.assess(measurement)
            comparisons.append({'mode': mode, 'metric': metric, 'status': status,
                                'reason': reason, 'measurement': measurement,
                                'target_required': True})
    for mode in sorted(skipped):
        for metric in ('block', 'network'):
            comparisons.append({'mode': mode, 'metric': metric, 'status': 'SKIP',
                                'reason': 'conversion-journal not admitted (test)',
                                'target_required': True})
    for number, (leg, leg_files) in enumerate(zip(legs, files)):
        _write_export_leg(export, number, leg, leg_files)
    return _write_campaign(export, manifest, 'overhead', legs, comparisons)


def _soak_export(export, manifest, mixed_legs=30):
    # Honest soak schedule: mixed attempt legs, then one pool
    # leg last. The pool leg reuses the honest pool-leg
    # fixture verbatim (window 0..4261s); mixed windows start
    # past it at 100s spacing, so no two workload windows
    # overlap.
    legs, files = [], []
    for ordinal in range(mixed_legs):
        leg, leg_files = _overhead_product_leg(
            ordinal, 'attempt-record-summary',
            (4262 + ordinal * 100) * 10**9)
        legs.append(leg)
        files.append(leg_files)
    pool_leg, pool_files = _pool_leg()
    pool_leg['ordinal'] = str(mixed_legs)
    legs.append(pool_leg)
    files.append(pool_files)
    for number, (leg, leg_files) in enumerate(zip(legs, files)):
        _write_export_leg(export, number, leg, leg_files)
    measured = float(mixed_legs * 60)
    return _write_campaign(
        export, manifest, 'soak', legs, [],
        {'mixed_seconds': measured,
         'campaign_seconds_before_pool': measured + 100.0})


def _live_manifest():
    return {'schema': 'test-manifest/1',
            'source': {'commit': 'a' * 40, 'tree': 'b' * 40,
                       'inventory_sha256': 'c' * 64},
            'toolchain': {'cargo_lock_sha256': 'd' * 64,
                          'ebpf_lock_sha256': 'e' * 64},
            'build_receipt_sha256': 'ef' * 32,
            'files': {'bin/memveil': 'ab' * 32}}


def _verify(m, export, manifest, mode):
    """Verify one fixture export through resolved campaign bytes."""
    return m.verify_live_campaign(
        export, manifest, mode,
        (export / 'campaign.json').read_bytes())


def live_gate_evidence(tmp_path, manifest):
    """Evidence dir with both campaigns, exit oracles, and inputs doc.

    Returns (evidence, inputs doc): live/overhead and
    live/soak hold complete exports, live/<mode>-exit.json
    the host oracles, and live-inputs.json binds all eight
    per-campaign totals on both sides. Shared with the
    qualification-path tests, which seal their own manifest.
    """
    import json
    m = api()
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate as c
    evidence = tmp_path / 'evidence'
    live = evidence / 'live'
    builders = {'overhead': _overhead_export, 'soak': _soak_export}
    product, oracle, sources = {}, {}, {'product': {}, 'oracle': {}}
    for mode, build in builders.items():
        slot = live / mode
        slot.mkdir(parents=True)
        build(slot, manifest)
        campaign = json.loads((slot / 'campaign.json').read_bytes())
        totals = _verify(m, slot, manifest, mode)
        assert campaign['totals'] == totals
        exit_doc = {'guest_exit': 0, 'candidate': campaign['candidate'],
                    'totals': totals}
        exit_name = mode + '-exit.json'
        (live / exit_name).write_bytes(
            json.dumps(exit_doc, sort_keys=True).encode())
        for key, value in totals.items():
            prefixed = '%s_%s' % (mode, key)
            product[prefixed] = value
            oracle[prefixed] = value
            sources['product'][prefixed] = {
                'file': 'live/%s/campaign.json' % mode,
                'sha256': c.digest(slot / 'campaign.json'),
                'path': ['totals', key], 'encoding': 'u64'}
            sources['oracle'][prefixed] = {
                'file': 'live/' + exit_name,
                'sha256': c.digest(live / exit_name),
                'path': ['totals', key], 'encoding': 'u64'}
    doc = {'schema': 'memveil-gate-input/1', 'environment': 'ordinary-linux',
           'product': product, 'oracle': oracle, 'sources': sources}
    (evidence / 'live-inputs.json').write_bytes(c.canonical(doc))
    return evidence, doc


def test_live_gate_inputs_verify_through_qualify_path(tmp_path):
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate as c
    manifest = _live_manifest()
    evidence, doc = live_gate_evidence(tmp_path, manifest)
    assert c.validate_inputs_doc(doc) == 'gate'
    policy, _ = c.validate_policy(ROOT / 'packaging/candidate-policy.json')
    requirement = policy['required_gates']['live-campaign/1']
    retained = c.read_json(evidence / 'live-inputs.json', sealed=True)
    c.verify_measurement_sources(retained, evidence)
    assert c.rederive_measurements(retained, requirement) is True
    c.verify_live_campaigns(retained, evidence, manifest)


def test_live_gate_refuses_overhead_only(tmp_path):
    import shutil
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate as c
    manifest = _live_manifest()
    evidence, doc = live_gate_evidence(tmp_path, manifest)
    shutil.rmtree(evidence / 'live/soak')
    with pytest.raises(ValueError):
        c.verify_live_campaigns(doc, evidence, manifest)


def test_live_gate_refuses_soak_only(tmp_path):
    import shutil
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate as c
    manifest = _live_manifest()
    evidence, doc = live_gate_evidence(tmp_path, manifest)
    shutil.rmtree(evidence / 'live/overhead')
    with pytest.raises(ValueError):
        c.verify_live_campaigns(doc, evidence, manifest)


def test_live_gate_refuses_pool_in_campaign_slot(tmp_path):
    import shutil
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate as c
    manifest = _live_manifest()
    evidence, doc = live_gate_evidence(tmp_path, manifest)
    slot = evidence / 'live/soak'
    shutil.rmtree(slot)
    slot.mkdir()
    _pool_export(slot, manifest)
    # Re-bind the substituted file so the refusal comes
    # from the mode check, not the digest check.
    fresh = c.digest(slot / 'campaign.json')
    for key, binding in doc['sources']['product'].items():
        if key.startswith('soak_'):
            binding['sha256'] = fresh
    with pytest.raises(ValueError, match='differs from requested'):
        c.verify_live_campaigns(doc, evidence, manifest)


def test_live_gate_refuses_scalar_drift(tmp_path):
    import json
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate as c
    manifest = _live_manifest()
    evidence, doc = live_gate_evidence(tmp_path, manifest)
    doc['product']['soak_legs'] = '32'
    (evidence / 'live-inputs.json').write_bytes(c.canonical(doc))
    retained = c.read_json(evidence / 'live-inputs.json', sealed=True)
    with pytest.raises(ValueError, match='retained bytes'):
        c.verify_live_campaigns(retained, evidence, manifest)


def test_live_gate_refuses_wrong_file_replay(tmp_path):
    import json
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate as c
    manifest = _live_manifest()
    evidence, doc = live_gate_evidence(tmp_path, manifest)
    # Substitute unsigned bytes at the replay path: the
    # totals still match the bound scalars, but the file no
    # longer matches its signed digest.
    campaign_path = evidence / 'live/overhead/campaign.json'
    campaign = json.loads(campaign_path.read_bytes())
    campaign['kernel'] = 'wrong-file-replay'
    campaign_path.write_bytes(
        json.dumps(campaign, sort_keys=True).encode())
    with pytest.raises(ValueError, match='file changed'):
        c.verify_live_campaigns(doc, evidence, manifest)


def test_live_gate_refuses_identity_mismatch(tmp_path):
    import json
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate as c
    manifest = _live_manifest()
    evidence, doc = live_gate_evidence(tmp_path, manifest)
    # A campaign run against another candidate: re-bind the
    # signed digests to the substituted bytes (as a confused
    # signer would), keeping every scalar intact. The
    # manifest identity check must still refuse.
    campaign_path = evidence / 'live/soak/campaign.json'
    campaign = json.loads(campaign_path.read_bytes())
    campaign['source'] = {'commit': 'f' * 40, 'tree': 'e' * 40,
                          'inventory_sha256': 'd' * 64}
    campaign_path.write_bytes(
        json.dumps(campaign, sort_keys=True).encode())
    fresh = c.digest(campaign_path)
    for key, binding in doc['sources']['product'].items():
        if key.startswith('soak_'):
            binding['sha256'] = fresh
    (evidence / 'live-inputs.json').write_bytes(c.canonical(doc))
    retained = c.read_json(evidence / 'live-inputs.json', sealed=True)
    with pytest.raises(ValueError, match='candidate manifest'):
        c.verify_live_campaigns(retained, evidence, manifest)


def _rebind_exit_oracle(c, evidence, doc, mode):
    fresh = c.digest(evidence / ('live/%s-exit.json' % mode))
    for key, binding in doc['sources']['oracle'].items():
        if key.startswith(mode + '_'):
            binding['sha256'] = fresh
    (evidence / 'live-inputs.json').write_bytes(c.canonical(doc))
    return c.read_json(evidence / 'live-inputs.json', sealed=True)


def test_live_gate_refuses_nonzero_guest_exit(tmp_path):
    import json
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate as c
    manifest = _live_manifest()
    evidence, doc = live_gate_evidence(tmp_path, manifest)
    exit_path = evidence / 'live/soak-exit.json'
    exit_doc = json.loads(exit_path.read_bytes())
    exit_doc['guest_exit'] = 1
    exit_path.write_bytes(
        json.dumps(exit_doc, sort_keys=True).encode())
    retained = _rebind_exit_oracle(c, evidence, doc, 'soak')
    with pytest.raises(ValueError, match='guest exit'):
        c.verify_live_campaigns(retained, evidence, manifest)


@pytest.mark.parametrize('bad_exit', ['0', True, 0.0, None])
def test_live_gate_refuses_non_integer_guest_exit(
        tmp_path, bad_exit):
    import json
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate as c
    manifest = _live_manifest()
    evidence, doc = live_gate_evidence(tmp_path, manifest)
    exit_path = evidence / 'live/overhead-exit.json'
    exit_doc = json.loads(exit_path.read_bytes())
    exit_doc['guest_exit'] = bad_exit
    exit_path.write_bytes(
        json.dumps(exit_doc, sort_keys=True).encode())
    retained = _rebind_exit_oracle(c, evidence, doc, 'overhead')
    with pytest.raises(ValueError, match='guest exit'):
        c.verify_live_campaigns(retained, evidence, manifest)


def test_live_gate_refuses_huge_guest_exit(tmp_path):
    import json
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate as c
    manifest = _live_manifest()
    evidence, doc = live_gate_evidence(tmp_path, manifest)
    exit_path = evidence / 'live/soak-exit.json'
    exit_doc = json.loads(exit_path.read_bytes())
    # int() of infinity raises OverflowError, not
    # TypeError/ValueError: the gate must still refuse
    # cleanly instead of propagating a traceback.
    exit_doc['guest_exit'] = float('inf')
    exit_path.write_bytes(
        json.dumps(exit_doc, sort_keys=True).encode())
    retained = _rebind_exit_oracle(c, evidence, doc, 'soak')
    with pytest.raises(ValueError, match='guest exit'):
        c.verify_live_campaigns(retained, evidence, manifest)


def test_live_gate_refuses_host_totals_mismatch(tmp_path):
    import json
    sys.path.insert(0, str(ROOT / 'tools'))
    import candidate as c
    manifest = _live_manifest()
    evidence, doc = live_gate_evidence(tmp_path, manifest)
    exit_path = evidence / 'live/soak-exit.json'
    exit_doc = json.loads(exit_path.read_bytes())
    exit_doc['totals'] = dict(exit_doc['totals'])
    exit_doc['totals']['legs'] = '999'
    exit_path.write_bytes(
        json.dumps(exit_doc, sort_keys=True).encode())
    retained = _rebind_exit_oracle(c, evidence, doc, 'soak')
    with pytest.raises(ValueError, match='host totals'):
        c.verify_live_campaigns(retained, evidence, manifest)


def test_verify_live_campaign_accepts_honest_pool(tmp_path):
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _pool_export(export, manifest)
    assert _verify(m, export, manifest, 'pool') == {
        'legs': '1', 'failed_legs': '0', 'target_failures': '0',
        'cleanup_mismatches': '0'}


def test_verify_live_campaign_refuses_tampered_leg(tmp_path):
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _pool_export(export, manifest)
    target = export / 'completed-0/capture/events.ndjson'
    target.write_bytes(b'x' + target.read_bytes()[1:])
    with pytest.raises(ValueError, match='changed'):
        _verify(m, export, manifest, 'pool')


def test_verify_live_campaign_refuses_missing_leg(tmp_path):
    import shutil
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _pool_export(export, manifest)
    shutil.rmtree(export / 'completed-0')
    with pytest.raises(ValueError, match='inventory'):
        _verify(m, export, manifest, 'pool')


def test_verify_live_campaign_refuses_predicate_mismatch(tmp_path):
    import hashlib
    import json
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _pool_export(export, manifest)
    session_path = export / 'completed-0/capture/session.json'
    session = json.loads(session_path.read_bytes())
    session['quality']['detail']['loss_count'] = '5'
    fresh = json.dumps(session, sort_keys=True).encode()
    session_path.write_bytes(fresh)
    digest = hashlib.sha256(fresh).hexdigest()
    for path, nested in ((export / 'campaign.json', True),
                         (export / 'completed-0/observations.json', False)):
        doc = json.loads(path.read_bytes())
        leg = doc['legs'][0] if nested else doc
        leg['capture']['quality']['detail']['loss_count'] = '5'
        leg['capture']['session_sha256'] = digest
        leg['retained_capture']['session.json']['sha256'] = digest
        leg['retained_capture']['session.json']['bytes'] = str(len(fresh))
        if nested:
            path.write_bytes(json.dumps(doc, sort_keys=True).encode())
        else:
            path.write_bytes((json.dumps(doc, sort_keys=True) + '\n').encode())
    with pytest.raises(ValueError, match='loss'):
        _verify(m, export, manifest, 'pool')


def test_verify_live_campaign_accepts_honest_overhead(tmp_path):
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _overhead_export(export, manifest)
    assert _verify(m, export, manifest, 'overhead') == {
        'legs': '20', 'failed_legs': '0', 'target_failures': '0',
        'cleanup_mismatches': '0'}


def test_verify_live_campaign_refuses_workload_tamper(tmp_path):
    import json
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _overhead_export(export, manifest)
    for path, nested in ((export / 'campaign.json', True),
                         (export / 'completed-1/observations.json', False)):
        doc = json.loads(path.read_bytes())
        leg = doc['legs'][1] if nested else doc
        assert leg['mode'] == 'attempt-record-summary'
        leg['workload']['metrics']['block']['throughput'] = 50.0
        if nested:
            path.write_bytes(json.dumps(doc, sort_keys=True).encode())
        else:
            path.write_bytes((json.dumps(doc, sort_keys=True) + '\n').encode())
    # A bare cached-value tamper refuses at re-derivation,
    # before the comparison replay runs.
    with pytest.raises(ValueError, match='retained operations'):
        _verify(m, export, manifest, 'overhead')
    # A derivation-consistent tamper (latencies and cache
    # moved together) still refuses at the comparison
    # replay: the re-derived verdict differs from the
    # claimed measurement.
    export = tmp_path / 'consistent'
    export.mkdir()
    _overhead_export(export, manifest)
    for path, nested in ((export / 'campaign.json', True),
                         (export / 'completed-1/observations.json', False)):
        doc = json.loads(path.read_bytes())
        leg = doc['legs'][1] if nested else doc
        metric = leg['workload']['metrics']['block']
        metric['operation_seconds'] = [50.0]
        metric['p99'] = 50.0
        if nested:
            path.write_bytes(json.dumps(doc, sort_keys=True).encode())
        else:
            path.write_bytes((json.dumps(doc, sort_keys=True) + '\n').encode())
    with pytest.raises(ValueError, match='retained workloads'):
        _verify(m, export, manifest, 'overhead')


def test_verify_live_campaign_refuses_lying_comparison(tmp_path):
    import json
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _overhead_export(export, manifest)
    # Lie only in the recorded comparison outcome: the legs
    # (and every cached value) stay honest, so the refusal
    # must come from the re-derived comparison replay, not
    # from an upstream gate.
    campaign_path = export / 'campaign.json'
    doc = json.loads(campaign_path.read_bytes())
    row = next(item for item in doc['comparisons']
               if item['status'] != 'SKIP')
    assert row['status'] == 'PASS'
    row['measurement']['fields']['throughput']['median'] *= 2.0
    doc['totals'] = m.campaign_totals(doc)
    campaign_path.write_bytes(
        json.dumps(doc, sort_keys=True).encode())
    # The lie is well-formed upstream: the target gate still
    # passes and the totals still match the retained legs.
    assert doc['totals'] == {'legs': '20', 'failed_legs': '0',
                             'target_failures': '0',
                             'cleanup_mismatches': '0'}
    m.require_campaign_targets(doc['comparisons'])
    with pytest.raises(ValueError, match='retained workloads'):
        _verify(m, export, manifest, 'overhead')


def test_verify_live_campaign_refuses_nonzero_leg(tmp_path):
    import json
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _pool_export(export, manifest)
    for path, nested in ((export / 'campaign.json', True),
                         (export / 'completed-0/observations.json', False)):
        doc = json.loads(path.read_bytes())
        leg = doc['legs'][0] if nested else doc
        leg['product_exit'] = 1
        if nested:
            doc['pool']['observation']['product_exit'] = 1
            path.write_bytes(json.dumps(doc, sort_keys=True).encode())
        else:
            path.write_bytes((json.dumps(doc, sort_keys=True) + '\n').encode())
    with pytest.raises(ValueError, match='exit differs'):
        _verify(m, export, manifest, 'pool')


def test_verify_live_campaign_refuses_tampered_cached_metric(
        tmp_path):
    import json
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _overhead_export(export, manifest)
    # Scale every cached throughput together: the pairwise
    # ratios (and the claimed measurements) are unchanged,
    # so a cached-value compare would still accept while the
    # retained operation bytes disagree with every cache.
    campaign_path = export / 'campaign.json'
    doc = json.loads(campaign_path.read_bytes())
    for ordinal, leg in enumerate(doc['legs']):
        for section in ('warmup', 'workload'):
            for metric in leg[section]['metrics'].values():
                metric['throughput'] /= 2.0
        obs_path = export / ('completed-%d/observations.json'
                             % ordinal)
        obs = json.loads(obs_path.read_bytes())
        for section in ('warmup', 'workload'):
            for metric in obs[section]['metrics'].values():
                metric['throughput'] /= 2.0
        obs_path.write_bytes(
            (json.dumps(obs, sort_keys=True) + '\n').encode())
    campaign_path.write_bytes(
        json.dumps(doc, sort_keys=True).encode())
    with pytest.raises(ValueError, match='retained operations'):
        _verify(m, export, manifest, 'overhead')


def test_verify_live_campaign_refuses_overlapping_soak_windows(
        tmp_path):
    import json
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _soak_export(export, manifest, mixed_legs=30)
    # Slide leg 1's workload window back over leg 0,
    # keeping its duration (and every derived metric)
    # intact: overlap alone must refuse.
    for path, nested in ((export / 'campaign.json', True),
                         (export / 'completed-1/observations.json', False)):
        doc = json.loads(path.read_bytes())
        leg = doc['legs'][1] if nested else doc
        window = leg['workload']['window']
        window['start_ns'] = str(int(window['start_ns'])
                                 - 50 * 10**9)
        window['end_ns'] = str(int(window['end_ns'])
                               - 50 * 10**9)
        if nested:
            path.write_bytes(json.dumps(doc, sort_keys=True).encode())
        else:
            path.write_bytes((json.dumps(doc, sort_keys=True) + '\n').encode())
    with pytest.raises(ValueError, match='windows overlap'):
        _verify(m, export, manifest, 'soak')


def test_verify_live_campaign_refuses_mode_mismatch(tmp_path):
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _pool_export(export, manifest)
    with pytest.raises(ValueError, match='differs from requested'):
        _verify(m, export, manifest, 'soak')
    with pytest.raises(ValueError, match='requested'):
        _verify(m, export, manifest, 'nope')
    other = tmp_path / 'other'
    other.mkdir()
    _overhead_export(other, manifest)
    with pytest.raises(ValueError, match='differs from requested'):
        _verify(m, other, manifest, 'pool')
    assert _verify(
        m, other, manifest, 'overhead')['legs'] == '20'


def test_verify_live_campaign_accepts_honest_soak(tmp_path):
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _soak_export(export, manifest)
    assert _verify(m, export, manifest, 'soak') == {
        'legs': '31', 'failed_legs': '0', 'target_failures': '0',
        'cleanup_mismatches': '0'}


def test_verify_live_campaign_excludes_off_legs_from_soak_time(
        tmp_path):
    import json
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _soak_export(export, manifest, mixed_legs=30)
    doc = json.loads((export / 'campaign.json').read_bytes())
    assert doc['mixed_seconds'] == 1800.0
    # Slip an off leg before the pool leg, keeping ordinals
    # and files consistent; its window must not count. Its
    # window sits past the last mixed leg, overlapping none.
    off, _ = _overhead_off_leg(30, (4262 + 30 * 100) * 10**9)
    legs = doc['legs']
    legs.insert(-1, off)
    for ordinal, leg in enumerate(legs):
        leg['ordinal'] = str(ordinal)
    doc['totals'] = m.campaign_totals(doc)
    shifted = tmp_path / 'shifted'
    shifted.mkdir()
    for ordinal, leg in enumerate(legs):
        files = {}
        if leg.get('mode') != 'off':
            source = export / ('completed-%d/capture' % ordinal
                               if ordinal < 30 else 'completed-30/capture')
            files = {name: (source / name).read_bytes()
                     for name in os.listdir(source)}
        _write_export_leg(shifted, ordinal, leg, files)
    _write_campaign(shifted, manifest, 'soak', legs, [],
                    {'mixed_seconds': 1800.0,
                     'campaign_seconds_before_pool': 1900.0})
    assert _verify(
        m, shifted, manifest, 'soak')['legs'] == '32'
    # The same export claiming the off window counted
    # refuses: mixed time excludes off legs.
    tampered = json.loads(
        (shifted / 'campaign.json').read_bytes())
    tampered['mixed_seconds'] = 1860.0
    (shifted / 'campaign.json').write_text(
        json.dumps(tampered, sort_keys=True))
    with pytest.raises(ValueError, match='soak measurement'):
        _verify(m, shifted, manifest, 'soak')


def test_verify_live_campaign_refuses_soak_schedule_drift(
        tmp_path):
    import json
    m = api()
    manifest = _live_manifest()
    export = tmp_path / 'export'
    export.mkdir()
    _soak_export(export, manifest, mixed_legs=30)
    for path, nested in ((export / 'campaign.json', True),
                         (export / 'completed-0/observations.json', False)):
        doc = json.loads(path.read_bytes())
        leg = doc['legs'][0] if nested else doc
        assert leg['mode'] == 'attempt-record-summary'
        leg['mode'] = 'journal-summary'
        if nested:
            path.write_bytes(json.dumps(doc, sort_keys=True).encode())
        else:
            path.write_bytes((json.dumps(doc, sort_keys=True) + '\n').encode())
    with pytest.raises(ValueError, match='schedule differs'):
        _verify(m, export, manifest, 'soak')


def _export_argv_export(cmd):
    for token in cmd:
        if token.startswith('--rwdir=/tmp/export='):
            return Path(token[len('--rwdir=/tmp/export='):])
    raise AssertionError('guest argv lacks the export mount')


def test_host_acceptance_reverifies_export(sealed, monkeypatch, tmp_path):
    import json
    from types import SimpleNamespace
    m = api()
    previous = _sealed_arming_env(monkeypatch, sealed)
    monkeypatch.setenv('MEMVEIL_VM_LIVE_SOAK', '1')
    monkeypatch.setattr(m, 'ROOT', tmp_path)
    from support.candidate_input import load
    probe = load(env=dict(sealed))
    manifest, digest = probe.manifest, probe.digest
    probe.close()
    honest = tmp_path / 'honest'
    honest.mkdir()
    _pool_export(honest, manifest)
    def fake_guest(cmd, timeout):
        import shutil
        export = _export_argv_export(cmd)
        shutil.copytree(honest, export, dirs_exist_ok=True)
        return SimpleNamespace(returncode=0)
    monkeypatch.setitem(sys.modules, 'test_attempt_capture',
                        SimpleNamespace(gate_prefix=lambda: (['true'], None)))
    monkeypatch.setitem(sys.modules, 'vm_process',
                        SimpleNamespace(run_owned_guest=fake_guest))
    try:
        receipt = m.host('pool', opts={'out': str(tmp_path)})
    finally:
        _restore_sealed(previous)
    assert receipt['mode'] == 'pool' and receipt['candidate'] == digest
    exit_doc = json.loads((Path(receipt['evidence']) / 'exit.json').read_text())
    assert exit_doc['totals'] == {'legs': '1', 'failed_legs': '0',
                                  'target_failures': '0', 'cleanup_mismatches': '0'}


def test_host_acceptance_refuses_tampered_export(sealed, monkeypatch, tmp_path):
    import shutil
    from types import SimpleNamespace
    m = api()
    previous = _sealed_arming_env(monkeypatch, sealed)
    monkeypatch.setenv('MEMVEIL_VM_LIVE_SOAK', '1')
    monkeypatch.setattr(m, 'ROOT', tmp_path)
    from support.candidate_input import load
    probe = load(env=dict(sealed))
    manifest = probe.manifest
    probe.close()
    tampered = tmp_path / 'tampered'
    tampered.mkdir()
    _pool_export(tampered, manifest)
    shutil.rmtree(tampered / 'completed-0')
    def fake_guest(cmd, timeout):
        export = _export_argv_export(cmd)
        shutil.copytree(tampered, export, dirs_exist_ok=True)
        return SimpleNamespace(returncode=0)
    monkeypatch.setitem(sys.modules, 'test_attempt_capture',
                        SimpleNamespace(gate_prefix=lambda: (['true'], None)))
    monkeypatch.setitem(sys.modules, 'vm_process',
                        SimpleNamespace(run_owned_guest=fake_guest))
    try:
        with pytest.raises(ValueError, match='inventory'):
            m.host('pool', opts={'out': str(tmp_path)})
    finally:
        _restore_sealed(previous)


def _flap_read_text(monkeypatch, m, name, faults):
    """Fail the next reads of leaf `name` with `faults`, then read through."""
    real_read_text = Path.read_text
    state = {'raised': []}
    def flapping(self, *args, **kwargs):
        if self.name == name and faults:
            error = faults.pop(0)
            state['raised'].append(error.errno)
            raise error
        return real_read_text(self, *args, **kwargs)
    monkeypatch.setattr(m.Path, 'read_text', flapping)
    return state


def _recorded_sleeps(monkeypatch, m):
    sleeps = []
    monkeypatch.setattr(m.time, 'sleep', sleeps.append)
    return sleeps


def _fake_nic_tree(tmp_path, addresses):
    net = tmp_path / 'net'
    for iface, address in addresses.items():
        node = net / iface
        node.mkdir(parents=True)
        (node / 'address').write_text(address + '\n')
    return net


def test_identity_scan_rides_through_nic_rename_flap(tmp_path, monkeypatch):
    import errno
    m = api()
    token = '0123456789abcdef'
    net = _fake_nic_tree(tmp_path, {'eth0': m.guest_mac(token),
                                    'lo': '00:00:00:00:00:00'})
    flap = OSError(errno.ENXIO, 'No such device or address')
    raised = _flap_read_text(monkeypatch, m, 'address', [flap, flap])
    sleeps = _recorded_sleeps(monkeypatch, m)
    matches = m.scan_sysfs_matches(net, 'address', m.guest_mac(token),
                                   'NIC identity scan')
    assert [p.name for p in matches] == ['eth0']
    assert raised['raised'] == [errno.ENXIO, errno.ENXIO]
    assert sleeps == [m.IDENTITY_SCAN_INTERVAL] * 2


def test_identity_scan_stable_pass_never_sleeps(tmp_path, monkeypatch):
    m = api()
    token = '0123456789abcdef'
    net = _fake_nic_tree(tmp_path, {'eth0': m.guest_mac(token)})
    sleeps = _recorded_sleeps(monkeypatch, m)
    assert [p.name for p in m.scan_sysfs_matches(
        net, 'address', m.guest_mac(token), 'NIC identity scan')] == ['eth0']
    assert sleeps == []


@pytest.mark.parametrize('addresses,flaps', [
    ({'eth0': '52:54:00:00:00:01'}, []),
    ({'eth0': '52:54:00:00:00:01'}, ['flap']),
    ({'eth0': '52:54:00:ab:cd:ef', 'eth1': '52:54:00:ab:cd:ef'}, []),
    ({'eth0': '52:54:00:ab:cd:ef', 'eth1': '52:54:00:ab:cd:ef'}, ['flap']),
])
def test_identity_scan_absence_and_ambiguity_still_fail(
        tmp_path, monkeypatch, addresses, flaps):
    import errno
    m = api()
    token = '0123456789abcdef'
    net = _fake_nic_tree(tmp_path, addresses)
    faults = [OSError(errno.ENXIO, 'No such device or address')
              for _ in flaps]
    _flap_read_text(monkeypatch, m, 'address', faults)
    sleeps = _recorded_sleeps(monkeypatch, m)
    matches = m.scan_sysfs_matches(net, 'address', m.guest_mac(token),
                                   'NIC identity scan')
    # Retries converge to the same strict exactly-one check:
    # absence (0) and ambiguity (2) both fail it, with or
    # without a transient flap on the way.
    assert len(sleeps) == len(flaps)
    assert len(matches) != 1
    with pytest.raises(ValueError, match='missing or ambiguous'):
        if len(matches) != 1:
            raise ValueError(
                'owned guest network identity missing or ambiguous')


def test_identity_scan_exhaustion_names_the_access(tmp_path, monkeypatch):
    import errno
    m = api()
    token = '0123456789abcdef'
    net = _fake_nic_tree(tmp_path, {'eth0': m.guest_mac(token)})
    real_read_text = Path.read_text
    def always_flapping(self, *args, **kwargs):
        if self.name == 'address':
            raise OSError(errno.ENXIO, 'No such device or address', str(self))
        return real_read_text(self, *args, **kwargs)
    monkeypatch.setattr(m.Path, 'read_text', always_flapping)
    sleeps = _recorded_sleeps(monkeypatch, m)
    with pytest.raises(OSError) as caught:
        m.scan_sysfs_matches(net, 'address', m.guest_mac(token),
                             'NIC identity scan')
    assert 'NIC identity scan' in str(caught.value)
    assert str(net / 'eth0/address') in str(caught.value)
    assert isinstance(caught.value.__cause__, OSError)
    assert caught.value.__cause__.errno == errno.ENXIO
    assert sleeps == [m.IDENTITY_SCAN_INTERVAL] * \
        (m.IDENTITY_SCAN_ATTEMPTS - 1)


def test_identity_scan_nvme_skips_serial_less_disks(tmp_path, monkeypatch):
    m = api()
    token = '0123456789abcdef'
    block = tmp_path / 'block'
    owned = block / 'nvme0n1/device'
    owned.mkdir(parents=True)
    (owned / 'serial').write_text('mv-' + token + '\n')
    (block / 'sda').mkdir()
    sleeps = _recorded_sleeps(monkeypatch, m)
    matches = m.scan_sysfs_matches(block, 'device/serial', 'mv-' + token,
                                   'scratch disk identity scan',
                                   missing_ok=True)
    assert [p.name for p in matches] == ['nvme0n1']
    assert sleeps == []


def test_identity_scan_nvme_rides_through_serial_flap(tmp_path, monkeypatch):
    import errno
    m = api()
    token = '0123456789abcdef'
    block = tmp_path / 'block'
    owned = block / 'nvme0n1/device'
    owned.mkdir(parents=True)
    (owned / 'serial').write_text('mv-' + token + '\n')
    _flap_read_text(monkeypatch, m, 'serial',
                    [OSError(errno.ENXIO, 'No such device or address')])
    sleeps = _recorded_sleeps(monkeypatch, m)
    matches = m.scan_sysfs_matches(block, 'device/serial', 'mv-' + token,
                                   'scratch disk identity scan',
                                   missing_ok=True)
    assert [p.name for p in matches] == ['nvme0n1']
    assert sleeps == [m.IDENTITY_SCAN_INTERVAL]


def test_identity_scan_nvme_exhaustion_names_the_access(tmp_path, monkeypatch):
    import errno
    m = api()
    token = '0123456789abcdef'
    block = tmp_path / 'block'
    owned = block / 'nvme0n1/device'
    owned.mkdir(parents=True)
    (owned / 'serial').write_text('mv-' + token + '\n')
    real_read_text = Path.read_text
    def always_flapping(self, *args, **kwargs):
        if self.name == 'serial':
            raise OSError(errno.ENXIO, 'No such device or address', str(self))
        return real_read_text(self, *args, **kwargs)
    monkeypatch.setattr(m.Path, 'read_text', always_flapping)
    _recorded_sleeps(monkeypatch, m)
    with pytest.raises(OSError) as caught:
        m.scan_sysfs_matches(block, 'device/serial', 'mv-' + token,
                             'scratch disk identity scan', missing_ok=True)
    assert 'scratch disk identity scan' in str(caught.value)
    assert str(block / 'nvme0n1/device/serial') in str(caught.value)
    assert isinstance(caught.value.__cause__, OSError)


def _fake_block_tree(tmp_path, serials, bare=()):
    block = tmp_path / 'block'
    for dev, serial in serials.items():
        node = block / dev / 'device'
        node.mkdir(parents=True)
        (node / 'serial').write_text(serial + '\n')
    for dev in bare:
        (block / dev).mkdir(parents=True)
    return block


def _fault_entry_serial(monkeypatch, m, faults):
    """Fail device/serial reads for the entries in `faults`.

    `faults` maps entry name to a read budget: None faults
    persistently (every read raises the sr0-shaped bare
    ENXIO with filename=None), an int faults that many reads
    then reads through. Returns per-entry raise counts.
    """
    import errno
    real_read_text = Path.read_text
    raised = {dev: 0 for dev in faults}
    def faulting(self, *args, **kwargs):
        dev = self.parent.parent.name
        if (self.name == 'serial' and self.parent.name == 'device'
                and dev in faults and (faults[dev] is None
                                       or raised[dev] < faults[dev])):
            raised[dev] += 1
            raise OSError(errno.ENXIO, 'No such device or address')
        return real_read_text(self, *args, **kwargs)
    monkeypatch.setattr(m.Path, 'read_text', faulting)
    return raised


def test_identity_scan_nvme_skips_unreadable_optical(tmp_path, monkeypatch):
    m = api()
    token = '0123456789abcdef'
    assert m.OPTICAL_BLOCK_PREFIXES == ('sr',)
    block = _fake_block_tree(tmp_path, {'nvme0n1': 'mv-' + token,
                                        'sr0': 'medium-serial'},
                             bare=('sda',))
    raised = _fault_entry_serial(monkeypatch, m, {'sr0': None})
    sleeps = _recorded_sleeps(monkeypatch, m)
    matches = m.scan_sysfs_matches(block, 'device/serial', 'mv-' + token,
                                   'scratch disk identity scan',
                                   missing_ok=True,
                                   skip_prefixes=m.OPTICAL_BLOCK_PREFIXES)
    assert [p.name for p in matches] == ['nvme0n1']
    assert raised == {'sr0': 0}
    assert sleeps == []


def test_identity_scan_optical_excluded_by_type_not_value(
        tmp_path, monkeypatch):
    m = api()
    token = '0123456789abcdef'
    block = _fake_block_tree(tmp_path, {'nvme0n1': 'mv-' + token,
                                        'sr0': 'mv-' + token})
    sleeps = _recorded_sleeps(monkeypatch, m)
    matches = m.scan_sysfs_matches(block, 'device/serial', 'mv-' + token,
                                   'scratch disk identity scan',
                                   missing_ok=True,
                                   skip_prefixes=m.OPTICAL_BLOCK_PREFIXES)
    assert [p.name for p in matches] == ['nvme0n1']
    assert sleeps == []


def test_identity_scan_unreadable_nvme_still_fails_closed(
        tmp_path, monkeypatch):
    import errno
    m = api()
    token = '0123456789abcdef'
    block = _fake_block_tree(tmp_path, {'nvme0n1': 'mv-' + token,
                                        'sr0': 'medium-serial'})
    raised = _fault_entry_serial(monkeypatch, m, {'sr0': None,
                                                  'nvme0n1': None})
    sleeps = _recorded_sleeps(monkeypatch, m)
    with pytest.raises(OSError) as caught:
        m.scan_sysfs_matches(block, 'device/serial', 'mv-' + token,
                             'scratch disk identity scan',
                             missing_ok=True,
                             skip_prefixes=m.OPTICAL_BLOCK_PREFIXES)
    assert 'scratch disk identity scan' in str(caught.value)
    assert isinstance(caught.value.__cause__, OSError)
    assert caught.value.__cause__.errno == errno.ENXIO
    assert caught.value.__cause__.filename is None
    assert raised['nvme0n1'] == m.IDENTITY_SCAN_ATTEMPTS
    assert raised['sr0'] == 0
    assert sleeps == [m.IDENTITY_SCAN_INTERVAL] * \
        (m.IDENTITY_SCAN_ATTEMPTS - 1)


def test_identity_scan_unreadable_nonoptical_still_fails(
        tmp_path, monkeypatch):
    import errno
    m = api()
    token = '0123456789abcdef'
    block = _fake_block_tree(tmp_path, {'nvme0n1': 'mv-' + token,
                                        'sda': 'other-serial'})
    raised = _fault_entry_serial(monkeypatch, m, {'sda': None})
    sleeps = _recorded_sleeps(monkeypatch, m)
    with pytest.raises(OSError) as caught:
        m.scan_sysfs_matches(block, 'device/serial', 'mv-' + token,
                             'scratch disk identity scan',
                             missing_ok=True,
                             skip_prefixes=m.OPTICAL_BLOCK_PREFIXES)
    # The exclusion is optical-only, not nvme-scoping: any
    # other unreadable entry still fails the scan closed.
    assert 'scratch disk identity scan' in str(caught.value)
    assert caught.value.__cause__.errno == errno.ENXIO
    assert raised == {'sda': m.IDENTITY_SCAN_ATTEMPTS}
    assert sleeps == [m.IDENTITY_SCAN_INTERVAL] * \
        (m.IDENTITY_SCAN_ATTEMPTS - 1)


def test_identity_scan_optical_exclusion_absent_is_noop(
        tmp_path, monkeypatch):
    m = api()
    token = '0123456789abcdef'
    block = _fake_block_tree(tmp_path, {'nvme0n1': 'mv-' + token},
                             bare=('sda',))
    sleeps = _recorded_sleeps(monkeypatch, m)
    matches = m.scan_sysfs_matches(block, 'device/serial', 'mv-' + token,
                                   'scratch disk identity scan',
                                   missing_ok=True,
                                   skip_prefixes=m.OPTICAL_BLOCK_PREFIXES)
    assert [p.name for p in matches] == ['nvme0n1']
    assert sleeps == []


@pytest.mark.parametrize('serials,want', [
    ({'nvme0n1': 'mv-ffffffffffffffff'}, 0),
    ({'nvme0n1': 'mv-0123456789abcdef',
      'nvme1n1': 'mv-0123456789abcdef'}, 2),
])
def test_identity_scan_absence_and_ambiguity_still_fail_with_sr0_present(
        tmp_path, monkeypatch, serials, want):
    m = api()
    token = '0123456789abcdef'
    block = _fake_block_tree(tmp_path, dict(serials, sr0='medium-serial'))
    raised = _fault_entry_serial(monkeypatch, m, {'sr0': None})
    sleeps = _recorded_sleeps(monkeypatch, m)
    matches = m.scan_sysfs_matches(block, 'device/serial', 'mv-' + token,
                                   'scratch disk identity scan',
                                   missing_ok=True,
                                   skip_prefixes=m.OPTICAL_BLOCK_PREFIXES)
    assert len(matches) == want
    assert raised == {'sr0': 0}
    assert sleeps == []
    with pytest.raises(ValueError, match='missing or ambiguous'):
        if len(matches) != 1:
            raise ValueError(
                'owned scratch disk identity missing or ambiguous')


def test_identity_scan_default_still_reads_sr_named(tmp_path, monkeypatch):
    m = api()
    token = '0123456789abcdef'
    net = _fake_nic_tree(tmp_path, {'sr0': m.guest_mac(token)})
    sleeps = _recorded_sleeps(monkeypatch, m)
    assert [p.name for p in m.scan_sysfs_matches(
        net, 'address', m.guest_mac(token), 'NIC identity scan')] == ['sr0']
    assert sleeps == []


def test_identity_scan_nvme_flap_still_retries_with_sr0_present(
        tmp_path, monkeypatch):
    m = api()
    token = '0123456789abcdef'
    block = _fake_block_tree(tmp_path, {'nvme0n1': 'mv-' + token,
                                        'sr0': 'medium-serial'})
    raised = _fault_entry_serial(monkeypatch, m, {'sr0': None,
                                                  'nvme0n1': 2})
    sleeps = _recorded_sleeps(monkeypatch, m)
    matches = m.scan_sysfs_matches(block, 'device/serial', 'mv-' + token,
                                   'scratch disk identity scan',
                                   missing_ok=True,
                                   skip_prefixes=m.OPTICAL_BLOCK_PREFIXES)
    assert [p.name for p in matches] == ['nvme0n1']
    assert raised == {'sr0': 0, 'nvme0n1': 2}
    assert sleeps == [m.IDENTITY_SCAN_INTERVAL] * 2


def test_identity_reread_rides_through_flap_then_names_access(
        tmp_path, monkeypatch):
    import errno
    m = api()
    node = tmp_path / 'nvme0n1/device'
    node.mkdir(parents=True)
    (node / 'serial').write_text('mv-0123456789abcdef\n')
    _flap_read_text(monkeypatch, m, 'serial',
                    [OSError(errno.ENXIO, 'No such device or address'),
                     FileNotFoundError(errno.ENOENT, 'No such file')])
    sleeps = _recorded_sleeps(monkeypatch, m)
    assert m.read_sysfs_text(node / 'serial', 'identity re-read') == \
        'mv-0123456789abcdef\n'
    assert sleeps == [m.IDENTITY_SCAN_INTERVAL] * 2
    real_read_text = Path.read_text
    def always_flapping(self, *args, **kwargs):
        if self.name == 'serial':
            raise OSError(errno.ENXIO, 'No such device or address')
        return real_read_text(self, *args, **kwargs)
    monkeypatch.setattr(m.Path, 'read_text', always_flapping)
    with pytest.raises(OSError) as caught:
        m.read_sysfs_text(node / 'serial', 'identity re-read')
    assert 'identity re-read' in str(caught.value)
    assert str(node / 'serial') in str(caught.value)


def _failed_host_out(sealed, monkeypatch, tmp_path, fake_guest, raised):
    from types import SimpleNamespace
    m = api()
    previous = _sealed_arming_env(monkeypatch, sealed)
    monkeypatch.setenv('MEMVEIL_VM_PERF', '1')
    monkeypatch.setattr(m, 'ROOT', tmp_path)
    monkeypatch.setitem(sys.modules, 'test_attempt_capture',
                        SimpleNamespace(gate_prefix=lambda: (['true'], None)))
    monkeypatch.setitem(sys.modules, 'vm_process',
                        SimpleNamespace(run_owned_guest=fake_guest))
    parent = tmp_path / 'ev'
    try:
        with pytest.raises(raised[0], match=raised[1]):
            m.host('overhead', opts={'out': str(parent)})
    finally:
        _restore_sealed(previous)
    runs = [p for p in parent.iterdir() if p.is_dir()]
    assert len(runs) == 1
    return runs[0]


def test_host_preserves_guest_console_on_failure(
        sealed, monkeypatch, tmp_path):
    import json
    from types import SimpleNamespace
    stdout = 'guest booted\nFAIL candidate live campaign: [Errno 6] stuck\n'
    stderr = 'traceback line one\ntraceback line two\n'
    def fake_guest(cmd, timeout):
        return SimpleNamespace(returncode=1, stdout=stdout, stderr=stderr)
    out = _failed_host_out(sealed, monkeypatch, tmp_path, fake_guest,
                           (ValueError, 'guest campaign failed'))
    assert (out / 'guest-stdout.log').read_text() == stdout
    assert (out / 'guest-stderr.log').read_text() == stderr
    exit_doc = json.loads((out / 'exit.json').read_text())
    assert exit_doc['guest_exit'] == 1
    assert (out / 'export').is_dir()


def test_host_failure_console_tolerates_bare_runner_shape(
        sealed, monkeypatch, tmp_path):
    import json
    from types import SimpleNamespace
    def fake_guest(cmd, timeout):
        return SimpleNamespace(returncode=1)
    out = _failed_host_out(sealed, monkeypatch, tmp_path, fake_guest,
                           (ValueError, 'guest campaign failed'))
    assert (out / 'guest-stdout.log').read_text() == ''
    assert (out / 'guest-stderr.log').read_text() == ''
    assert json.loads((out / 'exit.json').read_text())['guest_exit'] == 1


def test_host_preserves_partial_console_on_timeout(
        sealed, monkeypatch, tmp_path):
    import subprocess
    def fake_guest(cmd, timeout):
        raise subprocess.TimeoutExpired(cmd, timeout, output='partial-out',
                                        stderr='partial-err')
    out = _failed_host_out(sealed, monkeypatch, tmp_path, fake_guest,
                           (subprocess.TimeoutExpired, 'timed out'))
    assert (out / 'guest-stdout.log').read_text() == 'partial-out'
    assert (out / 'guest-stderr.log').read_text() == 'partial-err'


def test_host_success_writes_no_console_files(sealed, monkeypatch, tmp_path):
    import shutil
    from types import SimpleNamespace
    m = api()
    previous = _sealed_arming_env(monkeypatch, sealed)
    monkeypatch.setenv('MEMVEIL_VM_LIVE_SOAK', '1')
    monkeypatch.setattr(m, 'ROOT', tmp_path)
    from support.candidate_input import load
    probe = load(env=dict(sealed))
    manifest, digest = probe.manifest, probe.digest
    probe.close()
    honest = tmp_path / 'honest'
    honest.mkdir()
    _pool_export(honest, manifest)
    def fake_guest(cmd, timeout):
        export = _export_argv_export(cmd)
        shutil.copytree(honest, export, dirs_exist_ok=True)
        return SimpleNamespace(returncode=0, stdout='ok\n', stderr='')
    monkeypatch.setitem(sys.modules, 'test_attempt_capture',
                        SimpleNamespace(gate_prefix=lambda: (['true'], None)))
    monkeypatch.setitem(sys.modules, 'vm_process',
                        SimpleNamespace(run_owned_guest=fake_guest))
    try:
        receipt = m.host('pool', opts={'out': str(tmp_path)})
    finally:
        _restore_sealed(previous)
    assert receipt['candidate'] == digest
    evidence = Path(receipt['evidence'])
    assert not (evidence / 'guest-stdout.log').exists()
    assert not (evidence / 'guest-stderr.log').exists()


# Verbatim transcript shape of the pinned guest configure
# refusal: unpack succeeds, only configure is refused on the
# Depends entry the package database cannot see.
INSTALL_REFUSAL_STDOUT = (
    'Selecting previously unselected package memveil.\n'
    '(Reading database ... 0 files and directories currently installed.)\n'
    'Preparing to unpack .../memveil_0.2.0-1_amd64.deb ...\n'
    'Unpacking memveil (0.2.0-1) ...\n'
)
INSTALL_REFUSAL_STDERR = (
    'dpkg: dependency problems prevent configuration of memveil:\n'
    ' memveil depends on libc6 (>= 2.35); however:\n'
    '  Package libc6 is not installed.\n'
    'dpkg: error processing package memveil (--install):\n'
    ' dependency problems - leaving unconfigured\n'
)


def _stub_installer(path, body):
    path.write_text('#!/bin/sh\n' + body)
    path.chmod(0o755)
    return path


def _shadow_path(monkeypatch, bindir):
    monkeypatch.setenv('PATH', str(bindir) + os.pathsep + os.environ['PATH'])


def _sealed_deb(tmp_path):
    return tmp_path / 'memveil_0.2.0-1_amd64.deb'


def test_guest_install_force_depends_bypasses_empty_package_db(
        tmp_path, monkeypatch):
    m = api()
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    _stub_installer(bindir / 'dpkg',
        'test "$1" = --force-depends || exit 2\n'
        'test "$2" = -i || exit 2\n'
        'echo "Unpacking memveil (0.2.0-1) ..."\n'
        'echo "dpkg: warning: depends on libc6 (>= 2.35)" >&2\n'
        'echo "Setting up memveil (0.2.0-1) ..."\n')
    _shadow_path(monkeypatch, bindir)
    evidence = tmp_path / 'local-evidence'
    evidence.mkdir()
    out = m.install_guest_deb(_sealed_deb(tmp_path), str(evidence))
    assert b'Unpacking' in out
    log = (evidence / m.INSTALL_LOG_NAME).read_bytes()
    assert b'Setting up' in log and b'--force-depends' in log


def test_guest_install_refusal_carries_cause_and_forensics(
        tmp_path, monkeypatch):
    import shlex
    m = api()
    assert issubclass(m.InstallFailure, ValueError)
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    _stub_installer(bindir / 'dpkg',
        'printf %s %s\nprintf %s %s >&2\nexit 1\n'
        % (shlex.quote(INSTALL_REFUSAL_STDOUT), '',
           shlex.quote(INSTALL_REFUSAL_STDERR), ''))
    _shadow_path(monkeypatch, bindir)
    evidence = tmp_path / 'local-evidence'
    evidence.mkdir()
    with pytest.raises(m.InstallFailure, match='libc6') as caught:
        m.install_guest_deb(_sealed_deb(tmp_path), str(evidence))
    assert 'dependency problems' in str(caught.value)
    assert 'dpkg exit 1' in str(caught.value)
    assert caught.value.returncode == 1
    assert b'leaving unconfigured' in caught.value.stderr
    assert b'Unpacking' in caught.value.stdout
    assert caught.value.log == str(evidence / m.INSTALL_LOG_NAME)
    log = (evidence / m.INSTALL_LOG_NAME).read_bytes()
    assert INSTALL_REFUSAL_STDOUT.encode() in log
    assert INSTALL_REFUSAL_STDERR.encode() in log


def test_guest_install_missing_installer_refuses_by_name(
        tmp_path, monkeypatch):
    m = api()
    empty = tmp_path / 'empty'
    empty.mkdir()
    monkeypatch.setenv('PATH', str(empty))
    evidence = tmp_path / 'local-evidence'
    evidence.mkdir()
    with pytest.raises(ValueError, match='dpkg not found'):
        m.install_guest_deb(_sealed_deb(tmp_path), str(evidence))
    assert not (evidence / m.INSTALL_LOG_NAME).exists()


def test_guest_install_timeout_keeps_partial_forensics(
        tmp_path, monkeypatch):
    m = api()
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    _stub_installer(bindir / 'dpkg', 'echo partial-transcript\nsleep 30\n')
    _shadow_path(monkeypatch, bindir)
    evidence = tmp_path / 'local-evidence'
    evidence.mkdir()
    with pytest.raises(m.InstallFailure, match='timed out'):
        m.install_guest_deb(
            _sealed_deb(tmp_path), str(evidence), timeout=0.2)
    log = (evidence / m.INSTALL_LOG_NAME).read_bytes()
    assert b'partial-transcript' in log and b'timeout' in log


def test_guest_install_unwritable_forensics_is_loud(tmp_path, monkeypatch):
    m = api()
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    _stub_installer(bindir / 'dpkg', 'echo "Setting up memveil ..."\n')
    _shadow_path(monkeypatch, bindir)
    blocker = tmp_path / 'blocker'
    blocker.write_text('not a directory\n')
    with pytest.raises(ValueError, match='forensics unwritable'):
        m.install_guest_deb(_sealed_deb(tmp_path), str(blocker))


def test_guest_install_failure_keeps_cause_when_forensics_unwritable(
        tmp_path, monkeypatch):
    import shlex
    m = api()
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    _stub_installer(bindir / 'dpkg',
        'printf %s %s\nprintf %s %s >&2\nexit 1\n'
        % (shlex.quote(INSTALL_REFUSAL_STDOUT), '',
           shlex.quote(INSTALL_REFUSAL_STDERR), ''))
    _shadow_path(monkeypatch, bindir)
    blocker = tmp_path / 'blocker'
    blocker.write_text('not a directory\n')
    with pytest.raises(m.InstallFailure) as caught:
        m.install_guest_deb(_sealed_deb(tmp_path), str(blocker))
    message = str(caught.value)
    assert 'libc6' in message
    assert 'forensics unwritable' in message
    assert message.index('libc6') < message.index('forensics unwritable')
    assert 'dpkg exit 1' in message
    assert caught.value.returncode == 1
    assert b'leaving unconfigured' in caught.value.stderr


def test_checked_keeps_label_only_contract(tmp_path):
    m = api()
    helper = _stub_installer(
        tmp_path / 'helper', 'echo secret-cause >&2\nexit 3\n')
    with pytest.raises(ValueError,
                       match='required helper failed: helper') as caught:
        m.checked([str(helper)], 60)
    assert 'secret-cause' not in str(caught.value)


def _pinned_binary(tmp_path, body):
    import hashlib
    binary = tmp_path / 'memveil'
    binary.write_text(body)
    binary.chmod(0o755)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    return binary, {'files': {'bin/memveil': digest}}


_VERSION_BODY = '#!/bin/sh\necho memveil 0.2.0-test\n'


def test_installed_binary_hash_and_version_prove_identity(tmp_path):
    m = api()
    assert m.INSTALLED_BINARY == Path('/usr/bin/memveil')
    binary, manifest = _pinned_binary(tmp_path, _VERSION_BODY)
    assert m.verify_installed_binary(manifest, binary) is None


def test_installed_binary_hash_mismatch_refuses(tmp_path):
    m = api()
    binary, manifest = _pinned_binary(tmp_path, _VERSION_BODY)
    binary.write_bytes(b'#!/bin/sh\necho other-bytes\n')
    binary.chmod(0o755)
    with pytest.raises(ValueError, match='differs'):
        m.verify_installed_binary(manifest, binary)


@pytest.mark.parametrize('body', ['#!/bin/sh\nexit 1\n', '#!/bin/sh\nexit 0\n'])
def test_installed_binary_silent_or_failing_version_refuses(tmp_path, body):
    m = api()
    binary, manifest = _pinned_binary(tmp_path, body)
    with pytest.raises(ValueError, match='unproved'):
        m.verify_installed_binary(manifest, binary)


def test_installed_binary_alias_and_absence_refuse(tmp_path):
    m = api()
    binary, manifest = _pinned_binary(tmp_path, _VERSION_BODY)
    link = tmp_path / 'link'
    link.symlink_to(binary)
    with pytest.raises(ValueError, match='alias'):
        m.verify_installed_binary(manifest, link)
    with pytest.raises(ValueError, match='absent'):
        m.verify_installed_binary(manifest, tmp_path / 'missing')


def test_installed_binary_unpinned_closure_refuses(tmp_path):
    m = api()
    binary, _ = _pinned_binary(tmp_path, _VERSION_BODY)
    with pytest.raises(ValueError, match='no pinned digest'):
        m.verify_installed_binary({'files': {}}, binary)


def test_host_guest_argv_install_inputs_unchanged(
        sealed, monkeypatch, tmp_path):
    from types import SimpleNamespace
    m = api()
    previous = _sealed_arming_env(monkeypatch, sealed)
    monkeypatch.setenv('MEMVEIL_VM_PERF', '1')
    monkeypatch.setattr(m, 'ROOT', tmp_path)
    calls = []
    def fake_guest(cmd, timeout):
        calls.append((list(cmd), timeout))
        return SimpleNamespace(returncode=1, stdout='stub stdout\n',
                                 stderr='stub stderr\n')
    monkeypatch.setitem(sys.modules, 'test_attempt_capture',
                        SimpleNamespace(gate_prefix=lambda: (['true'], None)))
    monkeypatch.setitem(sys.modules, 'vm_process',
                        SimpleNamespace(run_owned_guest=fake_guest))
    try:
        with pytest.raises(ValueError, match='guest campaign failed'):
            m.host('overhead')
    finally:
        _restore_sealed(previous)
    argv = calls[0][0]
    payload = argv[argv.index('--exec') + 1]
    assert '--deb' in payload
    assert '--rpm' not in payload
    assert 'force-depends' not in payload


# Overlay capture staging: the collector records to a
# guest-local dir while the mount-backed dirs stay the
# host-visible forensics mirror. The stubs below emulate
# the product's capture-dir ownership guard (refuse with
# exit 3 when --output sits under the refused mount) and
# the record lifecycle (ready line, SIGTERM stop with
# marker bytes).


GUARD_REFUSAL_LINE = ('memveil record: output exists: '
                      'output dir owned by another user')


def _collector_output_probe():
    return ('out=""; prev=""; for arg in "$@"; do '
            'if [ "$prev" = "--output" ]; then out="$arg"; fi; '
            'prev="$arg"; done; ')


def _stub_guard_collector(path):
    """Fake collector honouring a mount-shaped ownership guard.

    Refuses with the product's exit code and diagnostic when
    --output sits under $REFUSE_UNDER; otherwise readies,
    logs its --output to $ARGV_LOG, and writes marker
    bytes on SIGTERM. Needs no product, no mount, no boot.
    """
    body = (_collector_output_probe() +
            'if [ -n "$REFUSE_UNDER" ]; then case "$out" in '
            '"$REFUSE_UNDER"/*) echo "%s" >&2; exit 3;; esac; fi; '
            'mkdir -p "$out"; '
            'if [ -n "$ARGV_LOG" ]; then printf "%%s\\n" "$out" '
            '>> "$ARGV_LOG"; fi; '
            'echo "ready session=cap-fake-1"; '
            'trap \'printf "{\\"marker\\":true}" '
            '> "$out/checkpoint.json"; exit 0\' TERM; '
            'while :; do sleep 1; done\n' % GUARD_REFUSAL_LINE)
    return _stub_installer(path, body)


def _stub_refusing_collector(path):
    return _stub_installer(
        path, 'echo "%s" >&2\nexit 3\n' % GUARD_REFUSAL_LINE)


def _stub_partial_refusing_collector(path):
    body = (_collector_output_probe() +
            'mkdir -p "$out"; '
            'printf "{\\"partial\\":true}" > "$out/checkpoint.json"; '
            'echo "%s" >&2; exit 3\n' % GUARD_REFUSAL_LINE)
    return _stub_installer(path, body)


def _stub_flapping_collector(path):
    body = (_collector_output_probe() +
            'mkdir -p "$out"; '
            'printf "{\\"partial\\":true}" > "$out/checkpoint.json"; '
            'echo "ready session=cap-fake-2"; sleep 1; '
            'echo "memveil record: backend lost mid-leg" >&2; '
            'exit 3\n')
    return _stub_installer(path, body)


def _stub_flooding_collector(path):
    body = ('i=0; while [ "$i" -lt 3000 ]; do '
            'echo "diagnostic filler line $i padding padding" >&2; '
            'i=$((i + 1)); done; '
            'echo "%s" >&2; exit 3\n' % GUARD_REFUSAL_LINE)
    return _stub_installer(path, body)


def _overlay_leg_env(tmp_path, monkeypatch):
    """Scratch/local/export dirs plus instant workload doubles."""
    m = api()
    local, export, scratch = (tmp_path / name for name in
                              ('local', 'export', 'scratch'))
    local.mkdir(); export.mkdir(); scratch.mkdir()
    monkeypatch.setattr(m, 'inventory', lambda: {})
    monkeypatch.setattr(m, 'settled', lambda before: {})
    monkeypatch.setattr(m, 'workload',
                        lambda *args, **kwargs: measured()['workload'])
    monkeypatch.setattr(m, 'capture_facts', lambda *args: {'ok': True})
    return m, local, export, scratch


def test_record_leg_requires_overlay_scratch(tmp_path):
    m = api()
    local, export = tmp_path / 'local', tmp_path / 'export'
    local.mkdir(); export.mkdir()
    with pytest.raises(TypeError):
        m.record_leg('/unused', '/unused', 'attempt-record-summary',
                     60, False, local, export, 0)


def test_guard_refusal_shape_is_reproducible_offline(
        tmp_path, monkeypatch):
    """Work staged under the refused mount refuses, exit 3."""
    m = api()
    monkeypatch.setattr(m, 'inventory', lambda: {})
    monkeypatch.setattr(m, 'settled', lambda before: {})
    work = tmp_path / 'rwdir-mount' / 'leg-0'
    work.mkdir(parents=True)
    binary = _stub_refusing_collector(tmp_path / 'memveil')
    with pytest.raises(m.ProductExit) as caught:
        m.leg(str(binary), '/unused', 'attempt-record-summary',
              work, 60)
    assert caught.value.product_exit == 3


def test_overlay_leg_records_local_and_mirrors_forensics(
        tmp_path, monkeypatch):
    import json
    m, local, export, scratch = _overlay_leg_env(tmp_path, monkeypatch)
    monkeypatch.setenv('REFUSE_UNDER', str(local))
    argv_log = tmp_path / 'argv.log'
    monkeypatch.setenv('ARGV_LOG', str(argv_log))
    binary = _stub_guard_collector(tmp_path / 'memveil')
    state = m.record_leg(str(binary), '/unused',
                         'attempt-record-summary', 60, False,
                         local, export, 0, scratch=scratch)
    assert state['status'] == 'PASS'
    recorded = Path(argv_log.read_text().splitlines()[0])
    assert scratch.resolve() in recorded.resolve().parents
    assert local.resolve() not in recorded.resolve().parents
    assert (export / 'completed-0/capture/checkpoint.json').exists()
    mirror = local / 'leg-0'
    assert (mirror / 'capture/checkpoint.json').exists()
    receipt = json.loads((mirror / 'observations.json').read_text())
    assert receipt['status'] == 'PASS'
    assert 'export_error' not in receipt
    assert 'local_receipt_error' not in receipt
    assert not (scratch / 'leg-0').exists()


def test_overlay_mirror_preserves_private_modes(tmp_path, monkeypatch):
    import stat
    m, local, export, scratch = _overlay_leg_env(tmp_path, monkeypatch)
    monkeypatch.setenv('REFUSE_UNDER', str(local))
    binary = _stub_guard_collector(tmp_path / 'memveil')
    old = os.umask(0o027)
    try:
        state = m.record_leg(str(binary), '/unused',
                             'attempt-record-summary', 60, False,
                             local, export, 0, scratch=scratch)
    finally:
        os.umask(old)
    assert state['status'] == 'PASS'
    assert stat.S_IMODE((local / 'leg-0').stat().st_mode) == 0o700
    assert stat.S_IMODE(
        (local / 'leg-0/capture').stat().st_mode) == 0o700
    for name in ('capture/checkpoint.json', 'observations.json'):
        assert stat.S_IMODE(
            (local / ('leg-0/' + name)).stat().st_mode) == 0o600
    assert stat.S_IMODE((export / 'completed-0/capture'
                         / 'checkpoint.json').stat().st_mode) == 0o600


def test_passing_leg_observation_schema_is_frozen(
        tmp_path, monkeypatch):
    import json
    m, local, export, scratch = _overlay_leg_env(tmp_path, monkeypatch)
    monkeypatch.setenv('REFUSE_UNDER', str(local))
    binary = _stub_guard_collector(tmp_path / 'memveil')
    state = m.record_leg(str(binary), '/unused',
                         'attempt-record-summary', 60, False,
                         local, export, 0, scratch=scratch)
    assert state['status'] == 'PASS'
    exported = json.loads(
        (export / 'completed-0/observations.json').read_text())
    assert set(exported) == {'ordinal', 'mode', 'status',
                             'bpf_before', 'bpf_after', 'product_exit',
                             'cleanup_errors', 'warmup', 'workload',
                             'capture', 'retained_capture',
                             'retained_verification', 'output',
                             'stop_signal_ns'}


def test_successful_leg_keeps_no_collector_stderr(
        tmp_path, monkeypatch):
    m, local, export, scratch = _overlay_leg_env(tmp_path, monkeypatch)
    monkeypatch.setenv('REFUSE_UNDER', str(local))
    binary = _stub_guard_collector(tmp_path / 'memveil')
    state = m.record_leg(str(binary), '/unused',
                         'attempt-record-summary', 60, False,
                         local, export, 0, scratch=scratch)
    assert state['status'] == 'PASS'
    assert 'collector_stderr_tail' not in state
    assert not (local / 'leg-0/collector-stderr.log').exists()
    assert (local / 'leg-0/observations.json').exists()


def test_refusal_persists_stderr_and_partial_capture(
        tmp_path, monkeypatch):
    import json
    m, local, export, scratch = _overlay_leg_env(tmp_path, monkeypatch)
    binary = _stub_partial_refusing_collector(tmp_path / 'memveil')
    with pytest.raises(m.ProductExit) as caught:
        m.record_leg(str(binary), '/unused',
                     'attempt-record-summary', 60, False,
                     local, export, 0, scratch=scratch)
    assert caught.value.product_exit == 3
    assert 'owned by another user' in str(caught.value)
    state = caught.value.observation
    assert state['status'] == 'FAIL'
    assert 'owned by another user' in state['collector_stderr_tail']
    assert (scratch / 'leg-0/collector-stderr.log').exists()
    log = (local / 'leg-0/collector-stderr.log').read_bytes()
    assert b'owned by another user' in log
    assert (local / 'leg-0/capture/checkpoint.json').exists()
    assert (export / 'failed-0/capture/checkpoint.json').exists()
    receipt = json.loads((local / 'leg-0/observations.json').read_text())
    assert receipt['status'] == 'FAIL'
    assert receipt['product_exit'] == 3
    assert 'owned by another user' in receipt['collector_stderr_tail']


def test_refusal_without_capture_dir_still_mirrors_receipts(
        tmp_path, monkeypatch):
    m, local, export, scratch = _overlay_leg_env(tmp_path, monkeypatch)
    binary = _stub_refusing_collector(tmp_path / 'memveil')
    with pytest.raises(m.ProductExit):
        m.record_leg(str(binary), '/unused',
                     'attempt-record-summary', 60, False,
                     local, export, 0, scratch=scratch)
    assert not (local / 'leg-0/capture').exists()
    assert (local / 'leg-0/observations.json').exists()
    assert (local / 'leg-0/collector-stderr.log').exists()
    assert (export / 'failed-0/observations.json').exists()


def test_mid_leg_exit_persists_stderr_and_partial_capture(
        tmp_path, monkeypatch):
    import time
    m, local, export, scratch = _overlay_leg_env(tmp_path, monkeypatch)
    binary = _stub_flapping_collector(tmp_path / 'memveil')

    def short_workload(disk, seconds, proc=None, pool_case=False,
                       oracle=None):
        deadline = time.monotonic() + 30
        while proc is not None and proc.poll() is None \
                and time.monotonic() < deadline:
            time.sleep(0.05)
        if proc is not None and proc.poll() is not None:
            raise m.ProductExit(
                proc.returncode, 'collector exited during workload: exit')
        return measured()['workload']

    monkeypatch.setattr(m, 'workload', short_workload)
    with pytest.raises(m.ProductExit) as caught:
        m.record_leg(str(binary), '/unused',
                     'attempt-record-summary', 60, False,
                     local, export, 0, scratch=scratch)
    assert caught.value.product_exit == 3
    assert 'backend lost mid-leg' in \
        caught.value.observation['collector_stderr_tail']
    assert (local / 'leg-0/collector-stderr.log').exists()
    assert (local / 'leg-0/capture/checkpoint.json').exists()


def test_collector_stderr_is_bounded_and_tailed(
        tmp_path, monkeypatch):
    m = api()
    monkeypatch.setattr(m, 'inventory', lambda: {})
    monkeypatch.setattr(m, 'settled', lambda before: {})
    binary = _stub_flooding_collector(tmp_path / 'memveil')
    work = tmp_path / 'work'
    work.mkdir()
    observation = {}
    with pytest.raises(m.ProductExit):
        m.leg(str(binary), '/unused', 'attempt-record-summary',
              work, 60, observation=observation)
    log = (work / 'collector-stderr.log').read_bytes()
    assert len(log) <= m.COLLECTOR_STDERR_LIMIT + 8192
    assert b'owned by another user' in log
    tail = observation['collector_stderr_tail']
    assert 'owned by another user' in tail
    assert 'filler line 0' not in tail


def test_blocked_forensics_mirror_degrades_to_warning(
        tmp_path, monkeypatch, capsys):
    m, local, export, scratch = _overlay_leg_env(tmp_path, monkeypatch)
    monkeypatch.setenv('REFUSE_UNDER', str(local))
    binary = _stub_guard_collector(tmp_path / 'memveil')
    (local / 'leg-0').write_text('blocker file on the mirror path\n')
    state = m.record_leg(str(binary), '/unused',
                         'attempt-record-summary', 60, False,
                         local, export, 0, scratch=scratch)
    assert state['status'] == 'PASS'
    assert 'export_error' not in state
    assert 'local_receipt_error' not in state
    assert (export / 'completed-0/capture/checkpoint.json').exists()
    assert 'forensics' in capsys.readouterr().err
    assert (scratch / 'leg-0').exists()


def test_forensics_copy_failure_never_masks_primary(
        tmp_path, monkeypatch, capsys):
    m, local, export, scratch = _overlay_leg_env(tmp_path, monkeypatch)
    binary = _stub_partial_refusing_collector(tmp_path / 'memveil')
    (local / 'leg-0').write_text('blocker file on the mirror path\n')
    with pytest.raises(m.ProductExit) as caught:
        m.record_leg(str(binary), '/unused',
                     'attempt-record-summary', 60, False,
                     local, export, 0, scratch=scratch)
    assert caught.value.product_exit == 3
    assert 'owned by another user' in str(caught.value)
    assert 'forensics' in capsys.readouterr().err


def test_copy_leg_forensics_copies_what_exists(tmp_path):
    m = api()
    work = tmp_path / 'work'
    (work / 'capture').mkdir(parents=True)
    (work / 'capture/checkpoint.json').write_text('{"a":1}')
    (work / 'capture/session.json').symlink_to(tmp_path / 'foreign')
    (tmp_path / 'foreign').write_text('foreign')
    (work / 'observations.json').write_text('{"status":"FAIL"}')
    warnings = m.copy_leg_forensics(work, tmp_path / 'mirror')
    assert any('session.json' in warning for warning in warnings)
    assert (tmp_path / 'mirror/capture/checkpoint.json').exists()
    assert (tmp_path / 'mirror/observations.json').exists()
    assert not (tmp_path / 'mirror/capture/session.json').exists()
    assert (tmp_path / 'foreign').read_text() == 'foreign'
    assert (tmp_path / 'mirror/forensics-copy-warnings.log').exists()


def test_copy_leg_forensics_tolerates_missing_work(tmp_path):
    m = api()
    warnings = m.copy_leg_forensics(tmp_path / 'absent',
                                    tmp_path / 'mirror')
    assert warnings


def test_evidence_copy_enforces_modes_under_hostile_umask(tmp_path):
    import stat
    m = api()
    work = tmp_path / 'work'
    (work / 'capture').mkdir(parents=True)
    (work / 'capture/checkpoint.json').write_text('{"a":1}')
    (work / 'observations.json').write_text('{}')
    old = os.umask(0o777)
    try:
        warnings = m.copy_leg_forensics(work, tmp_path / 'mirror')
    finally:
        os.umask(old)
    assert warnings == []
    assert stat.S_IMODE(
        (tmp_path / 'mirror').stat().st_mode) == 0o700
    assert stat.S_IMODE(
        (tmp_path / 'mirror/capture').stat().st_mode) == 0o700
    for name in ('capture/checkpoint.json', 'observations.json'):
        assert stat.S_IMODE(
            (tmp_path / ('mirror/' + name)).stat().st_mode) == 0o600
