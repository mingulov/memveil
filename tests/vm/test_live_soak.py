# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline protocol tests; never boot a guest or attach a probe."""
import importlib.util
from pathlib import Path
import sys
import pytest
sys.path.insert(0, str(Path(__file__).parent))


def api():
    assert importlib.util.find_spec('candidate_live'), 'installed live campaign runner missing'
    import candidate_live
    return candidate_live


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


def test_armed_missing_candidate_fails_before_vm(monkeypatch):
    m = api()
    monkeypatch.setenv('MEMVEIL_VM_LIVE_SOAK', '1')
    monkeypatch.delenv('MV_BUNDLE_TARBALL', raising=False)
    monkeypatch.delenv('MV_CANDIDATE_MANIFEST', raising=False)
    with pytest.raises(ValueError, match='both'):
        m.host('soak')


@pytest.mark.parametrize('returncode', [1, 2, 3, 4, -9])
def test_attach_or_capture_refusal_is_failure(returncode):
    with pytest.raises(ValueError, match='exit'):
        api().require_product_exit(returncode)


def test_no_workload_or_short_duration_cannot_pass():
    m = api()
    with pytest.raises(ValueError): m.validate_duration(1800, 1799, 10, 10)
    with pytest.raises(ValueError): m.validate_duration(1800, 1800, 0, 10)
    with pytest.raises(ValueError): m.validate_duration(1800, 1800, 10, 0)


def test_installed_verification_ignores_unrelated_system_binaries(tmp_path):
    import hashlib
    root = tmp_path / 'system'
    files = {'bin/memveil': b'candidate', 'lib/memveil/libx.so.1': b'library',
             'bpf/probe.bpf.o': b'probe', 'profiles/test.json': b'profile'}
    mapping = {'bin/memveil': 'usr/bin/memveil', 'lib/memveil/libx.so.1': 'usr/lib/memveil/libx.so.1',
               'bpf/probe.bpf.o': 'usr/lib/memveil/probe.bpf.o', 'profiles/test.json': 'usr/share/memveil/profiles/test.json'}
    entries = []
    for name, value in files.items():
        path = root / mapping[name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        entries.append({'path': name, 'type': 'file', 'size': str(len(value)), 'sha256': hashlib.sha256(value).hexdigest()})
    doc = {'canonical_runtime': {'entries': sorted(entries, key=lambda e: e['path'])},
           'files': {entry['path']: entry['sha256'] for entry in entries}}
    (root / 'usr/bin/unrelated').write_bytes(b'unrelated system binary')
    api().verify_installed(doc, root)
    (root / 'usr/lib/memveil/foreign.so').write_bytes(b'wrong')
    with pytest.raises(ValueError): api().verify_installed(doc, root)


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


def test_collector_output_retains_only_readiness_and_refresh_times():
    import io
    observed = {'ready': False, 'refresh_ns': [], 'error': None}
    api().observe_output(io.BytesIO(b'native raw secret diagnostic\nready session=allowlisted\n--- refresh 1\n--- refresh 2\n'), observed)
    assert observed['ready'] and len(observed['refresh_ns']) == 2
    assert 'secret' not in str(observed)


@pytest.mark.parametrize('prefix', ['usr/lib/memveil', 'usr/share/memveil', 'usr/share/doc/memveil'])
def test_private_extra_files_never_hide_in_installed_snapshot(tmp_path, prefix):
    root = tmp_path / 'system'
    path = root / prefix / 'foreign.so'
    path.parent.mkdir(parents=True)
    path.write_bytes(b'extra')
    with pytest.raises(ValueError, match='extra'):
        api().verify_installed({'canonical_runtime': {'entries': []}, 'files': {}}, root)


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
    doc = {'files': {'bin/memveil': hashlib.sha256(b'unchanged').hexdigest()},
           'canonical_runtime': {'entries': []}}
    with pytest.raises(ValueError, match='alias'):
        api().verify_installed(doc, root)
    assert (foreign / 'memveil').read_bytes() == b'unchanged'


def test_workload_oracle_rejects_short_io_and_packet_loss():
    m = api()
    assert m.completed_units('block', b'', b'16777216 bytes (17 MB) copied, 1 s', False) == 16777216
    assert m.completed_units('network', b'32 packets transmitted, 32 received, 0% packet loss', b'', False) == 32
    for kind, out, err in [('block', b'', b'1024 bytes (1 KB) copied, 1 s'),
                            ('network', b'32 packets transmitted, 1 received, 97% packet loss', b'')]:
        with pytest.raises(ValueError): m.completed_units(kind, out, err, False)
