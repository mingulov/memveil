# SPDX-License-Identifier: GPL-3.0-or-later
"""Export value grammar and selected loaded-object identity regressions."""
import builtins
import hashlib
import io
import os
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch
import pytest

REPO=Path(__file__).resolve().parents[2]
sys.dont_write_bytecode=True
sys.path.insert(0,str(REPO/'tests/vm'))
import export_validation
import guest_lifecycle
import lifecycle_env
import test_attempt_capture


def attempt_export(tmp_path,change=None):
    export=tmp_path/'export';export.mkdir()
    ledger=dict(mode='correctness',fs_type='tracefs',identity=dict(release='7.0.9',config_src='gz',config_sha='a'*64,btf_sha='b'*64,format_sha='c'*64,image_sha='d'*64,image_bid='e'*40),hiwater_before='1',iface='eth0',dma_mask_bits=32,link_ok=True,trace_clock='mono',ready='ready session=test start_ns=1',workload_start_ns=1,workload_end_ns=2,ping_transmitted=1,ping_received=1,record_exit=4,drained_bytes=0,percpu={},hiwater_after='2',pipe_bytes=0,pipe_lines=0,lost_markers=0)
    if change:change(ledger)
    contents={'ledger.json':json.dumps(ledger),'oracle.json':json.dumps(dict(schema='memveil-vm-oracle/1',lost_lines=0,pipe_bytes=0,pipe_lines=0,header_lines=0,blank_lines=0,events=[])),'session.json':(REPO/'tests/fixtures/baseline/session.json').read_text(),'events.ndjson':'','ping.txt':'','record.stdout':'ready session=test start_ns=1\nrecord: end=duration outcome=finalized exit=4\n','record.stderr':''}
    for name,text in contents.items():
        path=export/('correctness-'+name);path.write_text(text)
        Path(str(path)+'.sha256').write_text(hashlib.sha256(path.read_bytes()).hexdigest()+'\n')
    return tmp_path


def test_valid_attempt_metadata_control(tmp_path):
    assert test_attempt_capture.verify_exports(attempt_export(tmp_path),'correctness')


@pytest.mark.parametrize('field',['hiwater_before','ready'])
def test_hash_correct_address_in_unchecked_value_refused(tmp_path,field):
    export=attempt_export(tmp_path,lambda doc:doc.update({field:'0xffff888012345000'}))
    with pytest.raises((ValueError,AssertionError)):
        test_attempt_capture.verify_exports(export,'correctness')


def test_untyped_attempt_metadata_refused(tmp_path):
    export=attempt_export(tmp_path,lambda doc:doc.update(iface={'payload':'not-allowlisted'},link_ok='true'))
    with pytest.raises((ValueError,AssertionError)):
        test_attempt_capture.verify_exports(export,'correctness')


def test_saturation_identity_seals_selected_loaded_objects(tmp_path):
    paths={}
    for name in ['bridge','consume','lc_obj','cp_obj','lc_test_obj','cp_test_obj','ko']:
        p=tmp_path/name;p.write_text('independently distinct '+name);paths[name]=str(p)
    gate=SimpleNamespace(**paths,sub='saturation')
    real_open=builtins.open
    def open_owned(path,*args,**kw):
        if str(path)=='/proc/cmdline':return io.StringIO('swiotlb=force')
        return real_open(path,*args,**kw)
    with patch.object(builtins,'open',side_effect=open_owned),patch.object(lifecycle_env,'module_build_identity',return_value=dict(config_sha='a'*64,btf_sha='b'*64)):
        ident=guest_lifecycle.Gate.identity(gate)
    for field,selected in [('lc_sha','lc_test_obj'),('cp_sha','cp_test_obj')]:
        assert ident[field]==hashlib.sha256(Path(paths[selected]).read_bytes()).hexdigest(), 'saturation receipt must hash the object that run_saturation actually loads'


def test_ext_family_stat_label_healthy_control(tmp_path):
    # stat -f renders the ext-family magic as ext2/ext3, including ext4.
    export=attempt_export(tmp_path,lambda doc:doc.update(fs_type='ext2/ext3'))
    assert test_attempt_capture.verify_exports(export,'correctness')


@pytest.mark.parametrize('value',['ext2/ext3 payload','0xffff888012345000',{'type':'ext4'}])
def test_filesystem_type_rejects_free_text_or_nested_values(tmp_path,value):
    export=attempt_export(tmp_path,lambda doc:doc.update(fs_type=value))
    with pytest.raises((ValueError,AssertionError)):
        test_attempt_capture.verify_exports(export,'correctness')


def lifecycle_export(tmp_path,name,doc):
    export=tmp_path/'export';export.mkdir()
    target=export/('perf-'+name);target.write_text(json.dumps(doc))
    Path(str(target)+'.sha256').write_text(hashlib.sha256(target.read_bytes()).hexdigest()+'\n')
    from vm_boot import verify_exports
    return verify_exports(tmp_path,'perf',[name])


def perf_pairs():
    observed=dict(pair=0,mode='observed',end_ns=3,attach_ns=1,detach_ns=2,
                  ping=dict(tx=1,rx=1,seconds=1.0,p99_ms=1.0,sample_tx=1,sample_rx=1,sample_count=1),
                  dd=dict(bytes=512,seconds=1.0))
    off=dict(observed,mode='off');off.pop('attach_ns');off.pop('detach_ns')
    return [[off,observed]]


def test_perf_observed_integer_timestamps_and_off_absence_control(tmp_path):
    assert lifecycle_export(tmp_path,'pairs.json',perf_pairs())


@pytest.mark.parametrize('field',['attach_ns','detach_ns'])
@pytest.mark.parametrize('value',[{'payload':'0xffff888012345000'},'1',True,None,-1,1<<64])
def test_perf_optional_timestamp_values_refused(tmp_path,field,value):
    pairs=perf_pairs();pairs[0][1][field]=value
    with pytest.raises((ValueError,AssertionError)):
        lifecycle_export(tmp_path,'pairs.json',pairs)


def test_inventory_files_are_typed_list_not_arbitrary_object(tmp_path):
    from export_validation import inventory_snapshot
    snapshot=dict(bpf=dict(progs=1,maps=1),io_tlb_used=[1],files=['cycle-lc.txt'])
    inventory_snapshot(snapshot)
    snapshot['files']={'cycle-lc.txt':{'payload':'0xffff888012345000'}}
    with pytest.raises(ValueError):inventory_snapshot(snapshot)


@pytest.mark.parametrize('field',['io_tlb_used','files'])
def test_inventory_lists_cannot_be_empty_objects(field):
    from export_validation import inventory_snapshot
    snapshot=dict(bpf=dict(progs=0,maps=0),io_tlb_used=[],files=[])
    inventory_snapshot(snapshot)
    snapshot[field]={}
    with pytest.raises(ValueError):inventory_snapshot(snapshot)


def inventory_doc(settle=0.5):
    snap=dict(bpf=dict(progs=0,maps=0),io_tlb_used=[],files=[])
    return dict(baseline=snap,after=dict(snap),bpf_settle_s=settle,
                dmesg_marker_present=True,suspicious=0)


def test_inventory_settle_seconds_valid(tmp_path):
    path=tmp_path/'inventory.json'
    path.write_text(json.dumps(inventory_doc()))
    export_validation.validate_lifecycle_exports(
        {'inventory.json':path},'cleanup')


@pytest.mark.parametrize('settle',['fast',-1,31,None,True])
def test_inventory_settle_seconds_refused(tmp_path,settle):
    path=tmp_path/'inventory.json'
    path.write_text(json.dumps(inventory_doc(settle)))
    with pytest.raises(ValueError):
        export_validation.validate_lifecycle_exports(
            {'inventory.json':path},'cleanup')


def test_stop_optional_victim_values_cannot_cross_other_modes(tmp_path):
    from export_validation import validate_lifecycle_exports
    path=tmp_path/'ledger.json'
    row=dict(cycle=0,mode='quiet',lc_exit=0,cp_exit=0)
    path.write_text(json.dumps([row]));validate_lifecycle_exports({'ledger.json':path},'stop')
    row['victim_signal_ns']={'payload':'0xffff888012345000'}
    path.write_text(json.dumps([row]))
    with pytest.raises(ValueError):validate_lifecycle_exports({'ledger.json':path},'stop')


@pytest.mark.parametrize('field',['used_before','used_after'])
def test_workload_samples_require_integer_lists(tmp_path,field):
    from export_validation import validate_lifecycle_exports
    path=tmp_path/'workload.json'
    workload=dict(iface='eth0',used_before=[1],used_after=[1],start_ns=1,end_ns=2,detach_ns=3,
                  ping_tx=1,ping_rx=1,disk='/dev/sda',disk_bytes=512)
    path.write_text(json.dumps(workload));validate_lifecycle_exports({'workload.json':path},'realio')
    workload[field]={}
    path.write_text(json.dumps(workload))
    with pytest.raises(ValueError):validate_lifecycle_exports({'workload.json':path},'realio')


def rewrite_export(path,text):
    path.write_text(text)
    Path(str(path)+'.sha256').write_text(hashlib.sha256(path.read_bytes()).hexdigest()+'\n')


@pytest.mark.parametrize('name,key',[
    ('ledger.json','ready'),('session.json','product'),
    ('oracle.json','schema'),('events.ndjson','data'),
])
def test_duplicate_attempt_json_cannot_hide_nonallowlisted_data(tmp_path,name,key):
    export=attempt_export(tmp_path)
    target=export/('export/correctness-'+name)
    if name=='events.ndjson':
        rewrite_export(target,(REPO/'tests/fixtures/baseline/events.ndjson').read_text())
    assert test_attempt_capture.verify_exports(export,'correctness')
    text=target.read_text()
    rewrite_export(target,'{'+json.dumps(key)+':{"payload":"0xffff888012345000"},'+text[1:])
    with pytest.raises(ValueError) as error:
        test_attempt_capture.verify_exports(export,'correctness')
    assert '0xffff888012345000' not in str(error.value)


def test_escaped_equivalent_json_keys_are_duplicates(tmp_path):
    export=attempt_export(tmp_path)
    target=export/'export/correctness-ledger.json'
    rewrite_export(target,r'{"\u0072eady":{"payload":"0xffff888012345000"},'+target.read_text()[1:])
    with pytest.raises(ValueError):
        test_attempt_capture.verify_exports(export,'correctness')


@pytest.mark.parametrize('name,sub,doc,key',[
    ('identity.json','oracle',dict(release='7.0.9',swiotlb_force=True,
        **{key:'a'*64 for key in ('config_sha','btf_sha','bridge_sha','consume_sha','lc_sha','cp_sha','ko_sha')}),'release'),
    ('ledger.json','stop',[dict(cycle=0,mode='quiet',lc_exit=0,cp_exit=0)],'cycle'),
    ('inventory.json','cleanup',dict(
        baseline=dict(bpf=dict(progs=0,maps=0),io_tlb_used=[],files=[]),
        after=dict(bpf=dict(progs=0,maps=0),io_tlb_used=[],files=[]),
        bpf_settle_s=0.5,
        dmesg_marker_present=True,suspicious=0),'progs'),
    ('workload.json','realio',dict(iface='eth0',used_before=[1],used_after=[1],
        start_ns=1,end_ns=2,detach_ns=3,ping_tx=1,ping_rx=1,disk='/dev/sda',disk_bytes=512),'disk_bytes'),
    ('pairs.json','perf',perf_pairs(),'tx'),
])
def test_duplicate_lifecycle_json_values_refused_recursively(tmp_path,name,sub,doc,key):
    path=tmp_path/name
    text=json.dumps(doc)
    path.write_text(text)
    export_validation.validate_lifecycle_exports({name:path},sub)
    needle=json.dumps(key)+':'
    path.write_text(text.replace(needle,needle+'{"payload":"0xffff888012345000"}, '+needle,1))
    with pytest.raises(ValueError):
        export_validation.validate_lifecycle_exports({name:path},sub)


def test_duplicate_json_error_does_not_echo_raw_key_or_value(tmp_path):
    path=tmp_path/'pairs.json'
    text=json.dumps(perf_pairs())
    path.write_text(text.replace('"tx":',
        '"0xffff888012345000":"private-value", "0xffff888012345000":0, "tx":',1))
    with pytest.raises(ValueError) as error:
        export_validation.validate_lifecycle_exports({'pairs.json':path},'perf')
    assert '0xffff888012345000' not in str(error.value)
    assert 'private-value' not in str(error.value)


@pytest.mark.parametrize('case', ['duplicate', 'mismatch', 'unexpected', 'reordered', 'wrong-mode'])
def test_perf_pair_identity_and_interleaving_refused(tmp_path, case):
    pairs = perf_pairs() + perf_pairs()
    for leg in pairs[1]:
        leg['pair'] = 1
    if case == 'duplicate':
        for leg in pairs[1]: leg['pair'] = 0
    elif case == 'mismatch': pairs[1][0]['pair'] = 0
    elif case == 'unexpected':
        for leg in pairs[1]: leg['pair'] = 2
    elif case == 'reordered': pairs.reverse()
    else: pairs[0].reverse()
    with pytest.raises(ValueError):
        lifecycle_export(tmp_path, 'pairs.json', pairs)


def faults_export(tmp_path, files):
    export = tmp_path / 'export'
    export.mkdir()
    for name, text in files.items():
        target = export / ('faults-' + name)
        target.write_text(text)
        Path(str(target) + '.sha256').write_text(
            hashlib.sha256(target.read_bytes()).hexdigest() + '\n')
    from vm_boot import verify_exports
    return verify_exports(tmp_path, 'faults', list(files))


def faults_row(scenario='f1', exit=3, cap=False, **extra):
    row = dict(scenario=scenario, exit=exit, stderr='refused',
               progs_before=1, progs_after=1,
               maps_before=2, maps_after=2, settle_s=0,
               cap=cap)
    row.update(extra)
    return row


def test_faults_ledger_valid(tmp_path):
    rows = [faults_row(),
            faults_row('f5b', 4, True, window=[1, 2]),
            faults_row('f4', 1, False, events_kept=True,
                       ready='ready session=x')]
    faults_export(tmp_path, {'faults.json': json.dumps(rows)})


# --- Owned-directory evidence retention ---
#
# Gates verify exports in a temporary directory that success-path
# cleanup deletes. When MEMVEIL_EVIDENCE_DIR names the
# workflow-owned evidence directory, the verified exports must be
# copied and verified there before the temporary directory goes
# away, on every disposition.

IDENTITY_DOC = dict(
    release='7.0.0-34-generic', swiotlb_force=True,
    **{key: 'a' * 64 for key in (
        'config_sha', 'btf_sha', 'bridge_sha', 'consume_sha',
        'lc_sha', 'cp_sha', 'ko_sha')})


def retention_run(tmp_path, gate='bundle', files=None):
    run = tmp_path / 'run'
    export = run / 'export'
    export.mkdir(parents=True)
    files = files if files is not None else {
        'identity.json': json.dumps(IDENTITY_DOC),
        'record.json': json.dumps(
            {'exit': 4, 'ready': 'ready session=q'}),
    }
    for name, text in files.items():
        target = export / (gate + '-' + name)
        target.write_text(text)
        Path(str(target) + '.sha256').write_text(
            hashlib.sha256(target.read_bytes()).hexdigest() + '\n')
    return run


def owned_dir(tmp_path, monkeypatch):
    owned = tmp_path / 'owned'
    monkeypatch.setenv('MEMVEIL_EVIDENCE_DIR', str(owned))
    return owned


def test_retained_success_identity_survives_export_deletion(
        tmp_path, monkeypatch):
    import evidence_retention
    run = retention_run(tmp_path)
    owned = owned_dir(tmp_path, monkeypatch)
    receipt = evidence_retention.retain_gate_evidence(
        run, 'bundle', 'passed')
    assert receipt == owned / 'gates' / 'bundle' / 'receipt.json'
    import shutil
    shutil.rmtree(run)
    assert not run.exists()
    doc = evidence_retention.verify_retained('bundle')
    assert doc['complete'] is True
    assert doc['disposition'] == 'passed'
    kept = owned / 'gates' / 'bundle' / 'bundle-identity.json'
    assert json.loads(kept.read_text()) == IDENTITY_DOC
    listed = {entry['name']: entry for entry in doc['files']}
    assert listed['bundle-identity.json']['sha256'] == hashlib.sha256(
        kept.read_bytes()).hexdigest()


def test_success_cleanup_retains_before_deleting(
        tmp_path, monkeypatch):
    from test_attempt_capture import cleanup
    import evidence_retention
    run = retention_run(tmp_path)
    owned_dir(tmp_path, monkeypatch)
    cleanup(run, 'bundle')
    assert not run.exists(), 'temporary exports must still be removed'
    doc = evidence_retention.verify_retained('bundle')
    assert doc['complete'] is True
    assert {entry['name'] for entry in doc['files']} == {
        'bundle-identity.json', 'bundle-record.json'}


def test_retention_unconfigured_keeps_legacy_cleanup(
        tmp_path, monkeypatch):
    from test_attempt_capture import cleanup
    import evidence_retention
    run = retention_run(tmp_path)
    monkeypatch.delenv('MEMVEIL_EVIDENCE_DIR', raising=False)
    assert evidence_retention.retain_gate_evidence(
        run, 'bundle', 'passed') is None
    cleanup(run)
    assert not run.exists()


@pytest.mark.parametrize('disposition', [
    'failed', 'skipped', 'cleanup-uncertain'])
def test_non_passed_dispositions_cannot_claim_complete(
        tmp_path, monkeypatch, disposition):
    import evidence_retention
    run = retention_run(tmp_path)
    owned_dir(tmp_path, monkeypatch)
    evidence_retention.retain_gate_evidence(
        run, 'bundle', disposition)
    doc = evidence_retention.verify_retained('bundle')
    assert doc['complete'] is False
    assert doc['disposition'] == disposition


def test_missing_receipt_cannot_produce_complete_evidence(
        tmp_path, monkeypatch):
    import evidence_retention
    run = retention_run(tmp_path)
    (run / 'export' / 'bundle-record.json.sha256').unlink()
    owned_dir(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        evidence_retention.retain_gate_evidence(
            run, 'bundle', 'passed')
    evidence_retention.retain_gate_evidence(
        run, 'bundle', 'failed')
    doc = evidence_retention.verify_retained('bundle')
    assert doc['complete'] is False
    assert doc['file_errors'] == [
        {'name': 'bundle-record.json',
         'error': 'missing sidecar'}]


def test_mismatched_hash_cannot_produce_complete_evidence(
        tmp_path, monkeypatch):
    import evidence_retention
    run = retention_run(tmp_path)
    target = run / 'export' / 'bundle-identity.json'
    target.write_text(json.dumps(dict(IDENTITY_DOC,
                                      release='7.0.0-99-guest')))
    owned_dir(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        evidence_retention.retain_gate_evidence(
            run, 'bundle', 'passed')
    evidence_retention.retain_gate_evidence(
        run, 'bundle', 'failed')
    doc = evidence_retention.verify_retained('bundle')
    assert doc['complete'] is False
    assert {entry['name'] for entry in doc['files']} == {
        'bundle-record.json'}
    assert doc['file_errors'] == [
        {'name': 'bundle-identity.json',
         'error': 'hash mismatch'}]


def test_interrupted_copy_leaves_no_receipt(
        tmp_path, monkeypatch):
    import evidence_retention
    run = retention_run(tmp_path)
    owned = owned_dir(tmp_path, monkeypatch)
    real_replace = os.replace

    def failing_replace(src, dst):
        if str(dst).endswith('bundle-record.json'):
            raise OSError('simulated interrupted copy')
        return real_replace(src, dst)

    monkeypatch.setattr(os, 'replace', failing_replace)
    with pytest.raises(OSError):
        evidence_retention.retain_gate_evidence(
            run, 'bundle', 'passed')
    assert not (owned / 'gates' / 'bundle' /
                'receipt.json').exists()


def test_upload_inventory_matches_retained_manifests(
        tmp_path, monkeypatch):
    import shutil
    import evidence_retention
    run = retention_run(tmp_path)
    owned = owned_dir(tmp_path, monkeypatch)
    evidence_retention.retain_gate_evidence(
        run, 'bundle', 'passed')
    shutil.rmtree(run)
    inventory = evidence_retention.retained_inventory()
    assert inventory == [owned / 'gates' / 'bundle' /
                         'receipt.json']
    for path in inventory:
        assert str(run) not in str(path)
        assert path.is_relative_to(owned)


def test_failed_path_retention_never_masks_the_gate_error(
        tmp_path, monkeypatch):
    import evidence_retention
    run = tmp_path / 'run'
    owned_dir(tmp_path, monkeypatch)
    receipt = evidence_retention.retain_failure(run, 'bundle')
    doc = evidence_retention.verify_retained('bundle')
    assert receipt is not None
    assert doc['complete'] is False
    assert doc['file_errors'] == [
        {'name': 'bundle-exports',
         'error': 'no verified exports'}]
    monkeypatch.delenv('MEMVEIL_EVIDENCE_DIR', raising=False)
    assert evidence_retention.retain_failure(
        run, 'bundle') is None


def overhead_legs_doc(change=None):
    import overhead_guest
    schedule = overhead_guest.build_schedule()
    legs = []
    for seq, (rnd, mode, pair) in enumerate(schedule):
        legs.append({'seq': seq, 'round': rnd, 'mode': mode,
                     'pair': pair, 'tag': 'l%02d' % seq,
                     'files': [], 'error': 'unexpected'})
    doc = {
        'schema': 'memveil-overhead-legs/1',
        'seed': overhead_guest.SEED,
        'rounds': 5,
        'schedule': [[rnd, mode, pair]
                     for rnd, mode, pair in schedule],
        'artifacts': dict(
            **{key: 'b' * 64 for key in (
                'memveil_sha', 'attempt_sha', 'lc_sha',
                'cp_sha', 'lc_test_sha', 'cp_test_sha',
                'bridge_sha', 'profile_sha')},
            profile_id='linux-x86_64-7.0.0-34-generic'),
        'workload': {
            'gateway': '10.0.3.2',
            'flood_count': overhead_guest.FLOOD_COUNT,
            'sample_count': overhead_guest.SAMPLE_COUNT,
            'warmup_ping_count':
                overhead_guest.WARMUP_PING_COUNT,
            'dd_count': overhead_guest.DD_COUNT,
            'dd_bytes': overhead_guest.DD_BYTES,
            'warmup_dd_count':
                overhead_guest.WARMUP_DD_COUNT,
            'record_duration_s':
                overhead_guest.RECORD_DURATION,
            'lab_window_s': overhead_guest.LAB_WINDOW,
            'seed': overhead_guest.SEED,
            'rounds': overhead_guest.ROUNDS},
        'fixture': {'iface': 'enp0s1', 'disk': '/dev/sdb',
                    'nslabs': 1024,
                    'bpf_boot': {'progs': 0, 'maps': 0},
                    'io_tlb_boot': [1, 1, 1]},
        'legs': legs,
        'epilogue': {'bpf_end': {'progs': 0, 'maps': 0},
                     'settled_waited_s': 0.2,
                     'settled': True},
    }
    if change:
        change(doc)
    return doc


def overhead_retention_run(tmp_path, legs_doc):
    return retention_run(tmp_path, gate='overhead', files={
        'identity.json': json.dumps(IDENTITY_DOC),
        'legs.json': json.dumps(legs_doc),
    })


def test_retention_admits_sanitized_error_legs(
        tmp_path, monkeypatch):
    import evidence_retention
    run = overhead_retention_run(tmp_path, overhead_legs_doc())
    owned_dir(tmp_path, monkeypatch)
    evidence_retention.retain_gate_evidence(
        run, 'overhead', 'passed')
    doc = evidence_retention.verify_retained('overhead')
    assert doc['complete'] is True
    assert {entry['name'] for entry in doc['files']} == {
        'overhead-identity.json', 'overhead-legs.json'}


def test_retention_refuses_nested_payload_on_error_leg(
        tmp_path, monkeypatch):
    import evidence_retention
    def poison(doc):
        doc['legs'][0]['collector'] = {
            'kind': 'none', 'payload': {'nested': [1]}}
    run = overhead_retention_run(
        tmp_path, overhead_legs_doc(poison))
    owned_dir(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        evidence_retention.retain_gate_evidence(
            run, 'overhead', 'passed')
    evidence_retention.retain_gate_evidence(
        run, 'overhead', 'failed')
    doc = evidence_retention.verify_retained('overhead')
    assert doc['complete'] is False
    assert doc['files'] == []
    assert doc['file_errors'] == [
        {'name': 'overhead-exports',
         'error': 'no verified exports'}]


def test_retention_refuses_address_text_in_leg_error(
        tmp_path, monkeypatch):
    import evidence_retention
    def poison(doc):
        doc['legs'][0]['error'] = (
            "failed at 0xffff888012345000 "
            "cmd='dd if=/dev/sdb'")
    run = overhead_retention_run(
        tmp_path, overhead_legs_doc(poison))
    owned_dir(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        evidence_retention.retain_gate_evidence(
            run, 'overhead', 'passed')
    evidence_retention.retain_gate_evidence(
        run, 'overhead', 'failed')
    doc = evidence_retention.verify_retained('overhead')
    assert doc['complete'] is False
    assert doc['files'] == []
    assert doc['file_errors'] == [
        {'name': 'overhead-exports',
         'error': 'no verified exports'}]


def test_cleanup_uncertain_without_exports_stays_incomplete(
        tmp_path, monkeypatch):
    import evidence_retention
    owned_dir(tmp_path, monkeypatch)
    evidence_retention.record_lane_disposition(
        'vm-cleanup', 'cleanup-uncertain',
        dict(status='BLOCKED', remaining_owned=1))
    doc = evidence_retention.verify_retained('vm-cleanup')
    assert doc['complete'] is False
    assert doc['files'] == []
    assert doc['detail']['remaining_owned'] == 1


def receipt_doc(**override):
    doc = dict(
        schema='memveil-gate-evidence/1', gate='bundle',
        disposition='passed', complete=True,
        files=[dict(name='bundle-identity.json',
                    sha256='a' * 64, bytes=3)],
        file_errors=[],
        detail=dict(report_exit=4, files_verified=1))
    doc.update(override)
    return doc


def test_evidence_receipt_passed_control():
    export_validation.validate_evidence_receipt(receipt_doc())


@pytest.mark.parametrize('disposition', [
    'failed', 'skipped', 'cleanup-uncertain'])
def test_evidence_receipt_complete_requires_passed(disposition):
    with pytest.raises(ValueError):
        export_validation.validate_evidence_receipt(
            receipt_doc(disposition=disposition))
    export_validation.validate_evidence_receipt(receipt_doc(
        disposition=disposition, complete=False,
        files=[], file_errors=[dict(
            name='bundle-exports',
            error='no verified exports')]))


@pytest.mark.parametrize('change', [
    lambda doc: doc.update(schema='memveil-gate-evidence/2'),
    lambda doc: doc.update(gate='../escape'),
    lambda doc: doc.update(disposition='unknown'),
    lambda doc: doc.update(complete='yes'),
    lambda doc: doc.update(extra='payload'),
    lambda doc: doc['files'].append(dict(
        name='bundle-identity.json', sha256='z' * 64, bytes=3)),
    lambda doc: doc['files'].append(dict(
        name='other-identity.json', sha256='a' * 64, bytes=3)),
    lambda doc: doc.update(file_errors=[dict(
        name='bundle-identity.json', error='exploded loudly')]),
    lambda doc: doc.update(detail=dict(report_exit=4),
                           files=[]),
])
def test_evidence_receipt_grammar_refused(change):
    doc = receipt_doc()
    change(doc)
    with pytest.raises(ValueError):
        export_validation.validate_evidence_receipt(doc)


@pytest.mark.parametrize('detail', [
    dict(note='0xffff888012345000'),
    dict(note='0X7F01 leak'),
    dict(env='PATH=/usr/bin\nSECRET=hunter2'),
    dict(cmd='record --key material'),
    dict(deep=dict(nested='no')),
    dict(many=['no']),
    dict(count=1 << 64),
    dict(note='x' * 257),
    dict(note=' trailing space '),
    dict(note=''),
])
def test_evidence_receipt_detail_refuses_unsafe_values(detail):
    with pytest.raises(ValueError) as error:
        export_validation.validate_evidence_receipt(
            receipt_doc(detail=detail))
    for value in detail.values():
        if isinstance(value, str) and 1 <= len(value) < 64:
            assert value not in str(error.value)


def test_evidence_receipt_detail_tokens_control():
    export_validation.validate_evidence_receipt(receipt_doc(
        detail=dict(status='BLOCKED', native_exit=None,
                    timed_out=False, remaining_owned=1,
                    owned_processes=2, reaped_descendants=2,
                    signal_errors=0, report_exit=4,
                    files_verified=3, cycles=100,
                    suspicious=0)))


@pytest.mark.parametrize('change', [
    lambda rows: rows.append(faults_row('f9')),
    lambda rows: rows.append(faults_row()),
    lambda rows: rows[0].update(exit='3'),
    lambda rows: rows[0].update(cap='no'),
    lambda rows: rows[0].update(window=[2, 1]),
    lambda rows: rows[0].update(stderr='x' * 513),
    lambda rows: rows[0].update(events_kept='yes'),
    lambda rows: rows[0].update(settle_s='fast'),
    lambda rows: rows[0].update(settle_s=-1),
    lambda rows: rows[0].update(settle_s=31),
    lambda rows: rows[0].pop('settle_s'),
])
def test_faults_ledger_refused(tmp_path, change):
    rows = [faults_row()]
    change(rows)
    with pytest.raises(ValueError):
        faults_export(tmp_path, {'faults.json': json.dumps(rows)})


def test_suffixed_capture_names_valid(tmp_path):
    session = (REPO / 'tests/fixtures/baseline/session.json'
               ).read_text()
    files = {
        'q-session.json': session,
        'q-events.ndjson': '',
        'q-record.json': json.dumps(
            {'exit': 4, 'ready': 'ready session=q'}),
        'q-report.json': json.dumps(
            {'schema_version': '0.1.0',
             'session_id': 'baseline-session',
             'quality': {}, 'metrics': [{}]}),
    }
    faults_export(tmp_path, files)


def test_suffixed_report_session_mismatch_refused(tmp_path):
    session = (REPO / 'tests/fixtures/baseline/session.json'
               ).read_text()
    files = {
        'q-session.json': session,
        'q-report.json': json.dumps(
            {'schema_version': '0.1.0',
             'session_id': 'foreign-session',
             'quality': {}, 'metrics': [{}]}),
    }
    with pytest.raises(ValueError):
        faults_export(tmp_path, files)


@pytest.mark.parametrize('detail', [
    dict(cmd='record -o /tmp/cap'),
    dict(note='ffff888012345000'),
    dict(count=0xffff888012345000),
    dict(files_verified=0xffff888012345000),
    dict(status='record -o /tmp/cap'),
    dict(status='ffff888012345000'),
    dict(native_exit=0xffff888012345000),
    dict(report_exit=0xffff888012345000),
])
def test_evidence_receipt_detail_rejects_command_shapes_and_addresses(
        detail):
    with pytest.raises(ValueError) as error:
        export_validation.validate_evidence_receipt(
            receipt_doc(detail=detail))
    for value in detail.values():
        if isinstance(value, str) and 1 <= len(value) < 64:
            assert value not in str(error.value)


def test_missing_entire_export_pair_cannot_produce_complete(
        tmp_path, monkeypatch):
    import evidence_retention
    run = retention_run(tmp_path)
    owned_dir(tmp_path, monkeypatch)
    export = run / 'export'
    expected = {}
    for path in export.iterdir():
        if path.is_file() and not path.name.endswith('.sha256'):
            expected[path.name] = hashlib.sha256(
                path.read_bytes()).hexdigest()
    (export / 'bundle-identity.json').unlink()
    (export / 'bundle-identity.json.sha256').unlink()
    with pytest.raises(ValueError):
        evidence_retention.retain_gate_evidence(
            run, 'bundle', 'passed', expected=expected)
    evidence_retention.retain_gate_evidence(
        run, 'bundle', 'failed', expected=expected)
    doc = evidence_retention.verify_retained('bundle')
    assert doc['complete'] is False
    assert {'name': 'bundle-identity.json',
            'error': 'missing export'} in doc['file_errors']
    assert 'bundle-record.json' in {
        entry['name'] for entry in doc['files']}


def test_rejected_export_bytes_are_never_uploaded(
        tmp_path, monkeypatch):
    import evidence_retention
    bad = dict(IDENTITY_DOC, release='0xffff888012345000',
               extra='PATH=/usr/bin')
    run = retention_run(tmp_path, gate='cleanup', files={
        'identity.json': json.dumps(bad),
    })
    owned = owned_dir(tmp_path, monkeypatch)
    from export_validation import validate_lifecycle_exports
    with pytest.raises(ValueError):
        validate_lifecycle_exports(
            {'identity.json':
             run / 'export' / 'cleanup-identity.json'},
            'cleanup')
    evidence_retention.retain_failure(run, 'cleanup')
    doc = evidence_retention.verify_retained('cleanup')
    assert doc['complete'] is False
    assert doc['files'] == []
    assert not (owned / 'gates' / 'cleanup' /
                'cleanup-identity.json').exists()


def test_extra_retained_file_breaks_verification(
        tmp_path, monkeypatch):
    import evidence_retention
    run = retention_run(tmp_path)
    owned = owned_dir(tmp_path, monkeypatch)
    evidence_retention.retain_gate_evidence(
        run, 'bundle', 'passed')
    assert evidence_retention.verify_retained('bundle')[
        'complete'] is True
    (owned / 'gates' / 'bundle' /
     'bundle-stale.json').write_text('{}')
    with pytest.raises(ValueError):
        evidence_retention.verify_retained('bundle')


def test_distinct_retained_identities_share_export_prefix(
        tmp_path, monkeypatch):
    import evidence_retention
    first = retention_run(tmp_path / 'first')
    second = retention_run(tmp_path / 'second')
    owned = owned_dir(tmp_path, monkeypatch)
    evidence_retention.retain_gate_evidence(
        first, 'attempt-bundle', 'passed',
        export_prefix='bundle')
    evidence_retention.retain_gate_evidence(
        second, 'lifecycle-bundle', 'passed',
        export_prefix='bundle')
    first_doc = evidence_retention.verify_retained(
        'attempt-bundle')
    second_doc = evidence_retention.verify_retained(
        'lifecycle-bundle')
    assert first_doc['complete'] is True
    assert second_doc['complete'] is True
    assert (owned / 'gates' / 'attempt-bundle' /
            'receipt.json').is_file()
    assert (owned / 'gates' / 'lifecycle-bundle' /
            'receipt.json').is_file()


def test_retained_inventory_proves_file_bytes(
        tmp_path, monkeypatch):
    import evidence_retention
    run = retention_run(tmp_path)
    owned = owned_dir(tmp_path, monkeypatch)
    evidence_retention.retain_gate_evidence(
        run, 'bundle', 'passed')
    assert evidence_retention.retained_inventory() == [
        owned / 'gates' / 'bundle' / 'receipt.json']
    (owned / 'gates' / 'bundle' /
     'bundle-stale.json').write_text('{}')
    with pytest.raises(ValueError):
        evidence_retention.retained_inventory()


def test_failed_cleanup_leaves_uncertain_receipt(
        tmp_path, monkeypatch):
    import shutil
    import subprocess
    from test_attempt_capture import cleanup
    import evidence_retention
    run = retention_run(tmp_path)
    owned_dir(tmp_path, monkeypatch)
    monkeypatch.delenv('MEMVEIL_VM_KEEP_EXPORTS', raising=False)

    def failing_rmtree(path, ignore_errors=False):
        raise OSError('simulated removal failure')

    monkeypatch.setattr(shutil, 'rmtree', failing_rmtree)
    monkeypatch.setattr(
        subprocess, 'run',
        lambda *args, **kwargs: type(
            'Result', (), dict(returncode=1))())
    with pytest.raises(AssertionError):
        cleanup(run, 'bundle')
    assert run.exists()
    doc = evidence_retention.verify_retained('bundle')
    assert doc['disposition'] == 'cleanup-uncertain'
    assert doc['complete'] is False


def test_boot_failure_still_records_failed_evidence(
        tmp_path, monkeypatch, capsys):
    import evidence_retention
    import test_saturation
    owned = owned_dir(tmp_path, monkeypatch)

    def failing_boot(sub, timeout=900, network=False):
        raise RuntimeError('simulated boot failure')

    monkeypatch.setattr(test_saturation, 'run_guest',
                        failing_boot)
    assert test_saturation.run_flow() == 1
    receipts = list((owned / 'gates').glob('*/receipt.json'))
    assert len(receipts) == 1
    doc = evidence_retention.verify_retained(
        receipts[0].parent.name, owned)
    assert doc['disposition'] == 'failed'
    assert doc['complete'] is False


def test_every_exporting_gate_wires_failure_retention():
    missing = []
    for name in (
            'test_attempt_capture.py', 'test_oracle_live.py',
            'test_lifecycle.py', 'test_copy_semantics.py',
            'test_real_io.py', 'test_stop_races.py',
            'test_saturation.py', 'test_canonical.py',
            'test_witness.py', 'test_record3.py',
            'test_faults.py', 'test_topwalk.py',
            'test_bundle.py', 'test_cleanup_failures.py'):
        text = (REPO / 'tests/vm' / name).read_text()
        if 'retain_failure' not in text:
            missing.append(name)
    assert missing == []


def test_expected_hashes_survive_post_verification_replacement(
        tmp_path, monkeypatch):
    import vm_boot
    import evidence_retention
    fakerepo = tmp_path / 'fakerepo'
    artifacts = {
        'build/vm/mv_consume': b'fake-consume',
        'build/bpf/swiotlb_lifecycle.bpf.o': b'fake-lc',
        'build/bpf/swiotlb_copy.bpf.o': b'fake-cp',
        'build/deps/lmb/lib/libbpf_mojo.so.1': b'fake-bridge',
    }
    shas = {}
    for rel, blob in artifacts.items():
        target = fakerepo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        shas[rel] = hashlib.sha256(blob).hexdigest()
    ko = tmp_path / 'oracle.ko'
    ko.write_bytes(b'fake-ko')
    identity = dict(
        release='7.0.0-34-generic', swiotlb_force=True,
        config_sha='c' * 64, btf_sha='d' * 64,
        consume_sha=shas['build/vm/mv_consume'],
        lc_sha=shas['build/bpf/swiotlb_lifecycle.bpf.o'],
        cp_sha=shas['build/bpf/swiotlb_copy.bpf.o'],
        bridge_sha=shas['build/deps/lmb/lib/libbpf_mojo.so.1'],
        ko_sha=hashlib.sha256(b'fake-ko').hexdigest())
    monkeypatch.setattr(vm_boot, 'REPO', fakerepo)
    monkeypatch.setattr(lifecycle_env, 'ORACLE_KO', str(ko))
    monkeypatch.setattr(
        lifecycle_env, 'module_build_identity',
        lambda: dict(release='7.0.0-34-generic',
                     config_sha='c' * 64, btf_sha='d' * 64))
    run = tmp_path / 'run'
    export = run / 'export'
    export.mkdir(parents=True)
    target = export / 'copy-identity.json'
    target.write_text(json.dumps(identity))
    original = hashlib.sha256(target.read_bytes()).hexdigest()
    (export / 'copy-identity.json.sha256').write_text(
        original + '\n')
    got = vm_boot.verify_exports(run, 'copy', ['identity.json'])
    target.write_text(json.dumps(
        dict(identity, config_sha='e' * 64)))
    replaced = hashlib.sha256(target.read_bytes()).hexdigest()
    (export / 'copy-identity.json.sha256').write_text(
        replaced + '\n')
    assert replaced != original
    expected = evidence_retention.expected_from_verified(
        got, 'copy')
    assert expected == {'copy-identity.json': original}
    owned_dir(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        evidence_retention.retain_gate_evidence(
            run, 'copy', 'passed', expected=expected)
    with pytest.raises(AssertionError, match='identity drift'):
        vm_boot.verify_exports(run, 'copy', ['identity.json'])


def test_retained_inventory_rejects_unmanifested_entries(
        tmp_path, monkeypatch):
    import shutil
    import evidence_retention
    run = retention_run(tmp_path)
    owned = owned_dir(tmp_path, monkeypatch)
    evidence_retention.retain_gate_evidence(
        run, 'bundle', 'passed')
    other = owned / 'gates' / 'other'
    other.mkdir()
    body = json.dumps(IDENTITY_DOC)
    (other / 'other-identity.json').write_text(body)
    (other / 'other-identity.json.sha256').write_text(
        hashlib.sha256(body.encode()).hexdigest() + '\n')
    with pytest.raises(ValueError):
        evidence_retention.retained_inventory()
    shutil.rmtree(other)
    assert evidence_retention.retained_inventory() == [
        owned / 'gates' / 'bundle' / 'receipt.json']
    (owned / 'gates' / 'stray.json').write_text('{}')
    with pytest.raises(ValueError):
        evidence_retention.retained_inventory()


def test_retention_ignores_sidecar_swapped_after_validation(
        tmp_path, monkeypatch):
    import evidence_retention
    run = retention_run(tmp_path)
    owned = owned_dir(tmp_path, monkeypatch)
    export = run / 'export'
    good_sidecar = (
        export / 'bundle-identity.json.sha256').read_text()
    real_copy = evidence_retention._copy_verified

    def swapping_copy(source, dest):
        (export / 'bundle-identity.json.sha256').write_text(
            '0xffff888012345000 PATH=/usr/bin\n')
        return real_copy(source, dest)

    monkeypatch.setattr(
        evidence_retention, '_copy_verified', swapping_copy)
    evidence_retention.retain_gate_evidence(
        run, 'bundle', 'passed')
    kept = (owned / 'gates' / 'bundle' /
            'bundle-identity.json.sha256').read_text()
    assert kept == good_sidecar
    assert '0xffff888012345000' not in kept
    doc = evidence_retention.verify_retained('bundle')
    assert doc['complete'] is True


def test_swapped_payload_never_reaches_the_upload_directory(
        tmp_path, monkeypatch):
    import evidence_retention
    run = retention_run(tmp_path)
    owned = owned_dir(tmp_path, monkeypatch)
    export = run / 'export'
    rejected = json.dumps(dict(
        IDENTITY_DOC, release='7.0.0-99-guest'))
    real_copy = evidence_retention._copy_verified

    def swapping_copy(source, dest):
        if source.name == 'bundle-identity.json':
            (export / 'bundle-identity.json').write_text(
                rejected)
        return real_copy(source, dest)

    monkeypatch.setattr(
        evidence_retention, '_copy_verified', swapping_copy)
    with pytest.raises(ValueError):
        evidence_retention.retain_gate_evidence(
            run, 'bundle', 'passed')
    kept = owned / 'gates' / 'bundle' / 'bundle-identity.json'
    assert not kept.exists() or rejected not in kept.read_text()
    assert list(owned.glob('.staging-*')) == []


def test_verify_retained_rejects_swapped_sidecar(
        tmp_path, monkeypatch):
    import evidence_retention
    run = retention_run(tmp_path)
    owned = owned_dir(tmp_path, monkeypatch)
    evidence_retention.retain_gate_evidence(
        run, 'bundle', 'passed')
    (owned / 'gates' / 'bundle' /
     'bundle-identity.json.sha256').write_text(
        '0xffff888012345000 PATH=/usr/bin\n')
    with pytest.raises(ValueError):
        evidence_retention.verify_retained('bundle')
    with pytest.raises(ValueError):
        evidence_retention.retained_inventory()


def test_cleanup_fallback_execution_failure_marks_uncertain(
        tmp_path, monkeypatch):
    import shutil
    import subprocess
    from test_attempt_capture import cleanup
    import evidence_retention
    run = retention_run(tmp_path)
    owned_dir(tmp_path, monkeypatch)
    monkeypatch.delenv('MEMVEIL_VM_KEEP_EXPORTS', raising=False)

    def failing_rmtree(path, ignore_errors=False):
        raise OSError('simulated removal failure')

    monkeypatch.setattr(shutil, 'rmtree', failing_rmtree)

    def missing_sudo(*args, **kwargs):
        raise FileNotFoundError('simulated missing fallback')

    monkeypatch.setattr(subprocess, 'run', missing_sudo)
    with pytest.raises(FileNotFoundError):
        cleanup(run, 'bundle')
    assert run.exists()
    doc = evidence_retention.verify_retained('bundle')
    assert doc['disposition'] == 'cleanup-uncertain'
    assert doc['complete'] is False


def test_copy_gate_cleanup_failure_records_failed_receipt(
        tmp_path, monkeypatch):
    import evidence_retention
    import test_copy_semantics as gate
    run = retention_run(tmp_path, gate='copy', files={
        'identity.json': json.dumps(IDENTITY_DOC)})
    owned = owned_dir(tmp_path, monkeypatch)
    monkeypatch.delenv('MEMVEIL_VM_KEEP_EXPORTS', raising=False)
    monkeypatch.setattr(
        gate, 'require_lifecycle_env', lambda *args: None)
    monkeypatch.setattr(
        gate, 'ensure_oracle_module', lambda: None)
    monkeypatch.setattr(
        gate, 'run_guest',
        lambda *args, **kwargs: (run, SimpleNamespace(
            returncode=0, stderr='')))

    def fake_verify(tmp, sub, names):
        return {'identity.json':
                tmp / 'export' / 'copy-identity.json'}

    monkeypatch.setattr(gate, 'verify_exports', fake_verify)

    def deleting_check(got, tag, fail_op):
        (run / 'export' / 'copy-identity.json').unlink(
            missing_ok=True)
        (run / 'export' /
         'copy-identity.json.sha256').unlink(missing_ok=True)

    monkeypatch.setattr(gate, 'check_window', deleting_check)
    with pytest.raises(ValueError):
        gate.test_copy_semantics()
    assert run.exists()
    receipt = owned / 'gates' / 'copy' / 'receipt.json'
    assert receipt.is_file(), \
        'late retention failure left no gate receipt'
    doc = evidence_retention.verify_retained('copy')
    assert doc['disposition'] == 'failed'
    assert doc['complete'] is False
    assert {'name': 'copy-identity.json',
            'error': 'missing export'} in doc['file_errors']


def test_malformed_export_type_errors_become_failed_receipt(
        tmp_path, monkeypatch):
    import evidence_retention
    run = retention_run(tmp_path, gate='cleanup', files={
        'identity.json': json.dumps(
            dict(IDENTITY_DOC, release=7)),
    })
    owned = owned_dir(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        evidence_retention.retain_gate_evidence(
            run, 'cleanup', 'passed')
    receipt = evidence_retention.retain_failure(run, 'cleanup')
    assert receipt is not None
    doc = evidence_retention.verify_retained('cleanup')
    assert doc['disposition'] == 'failed'
    assert doc['complete'] is False
    assert doc['files'] == []
    assert doc['file_errors'] == [
        {'name': 'cleanup-exports',
         'error': 'no verified exports'}]
    assert not (owned / 'gates' / 'cleanup' /
                'cleanup-identity.json').exists()


def kernel_build_world(tmp_path, monkeypatch):
    """Fake packaged build roots so kernel-identity checks run locally."""
    import vm_boot
    fakerepo = tmp_path / 'fakerepo'
    artifacts = {
        'build/vm/mv_consume': b'fake-consume',
        'build/bpf/swiotlb_lifecycle.bpf.o': b'fake-lc',
        'build/bpf/swiotlb_copy.bpf.o': b'fake-cp',
        'build/deps/lmb/lib/libbpf_mojo.so.1': b'fake-bridge',
    }
    shas = {}
    for rel, blob in artifacts.items():
        target = fakerepo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        shas[rel] = hashlib.sha256(blob).hexdigest()
    ko = tmp_path / 'oracle.ko'
    ko.write_bytes(b'fake-ko')
    monkeypatch.setattr(vm_boot, 'REPO', fakerepo)
    monkeypatch.setattr(lifecycle_env, 'ORACLE_KO', str(ko))
    monkeypatch.setattr(
        lifecycle_env, 'module_build_identity',
        lambda: dict(release='7.0.0-34-generic',
                     config_sha='c' * 64, btf_sha='d' * 64))
    return dict(
        release='7.0.0-34-generic', swiotlb_force=True,
        config_sha='c' * 64, btf_sha='d' * 64,
        consume_sha=shas['build/vm/mv_consume'],
        lc_sha=shas['build/bpf/swiotlb_lifecycle.bpf.o'],
        cp_sha=shas['build/bpf/swiotlb_copy.bpf.o'],
        bridge_sha=shas['build/deps/lmb/lib/libbpf_mojo.so.1'],
        ko_sha=hashlib.sha256(b'fake-ko').hexdigest())


def write_export_pair(export, prefix, name, text):
    target = export / (prefix + '-' + name)
    target.write_text(text)
    (export / (target.name + '.sha256')).write_text(
        hashlib.sha256(target.read_bytes()).hexdigest() + '\n')
    return target


def test_verify_hashes_and_semantics_share_one_snapshot(
        tmp_path, monkeypatch):
    import vm_boot
    identity = kernel_build_world(tmp_path, monkeypatch)
    run = tmp_path / 'run'
    export = run / 'export'
    export.mkdir(parents=True)
    drifted = json.dumps(dict(identity, config_sha='e' * 64))
    write_export_pair(export, 'copy', 'identity.json', drifted)
    valid = json.dumps(identity)
    real_validate = export_validation.validate_lifecycle_exports

    def swapping_validate(got, sub):
        write_export_pair(export, 'copy', 'identity.json', valid)
        return real_validate(got, sub)

    monkeypatch.setattr(export_validation, 'validate_lifecycle_exports',
                        swapping_validate)
    try:
        with pytest.raises(AssertionError, match='identity drift'):
            vm_boot.verify_exports(run, 'copy', ['identity.json'])
    finally:
        write_export_pair(export, 'copy', 'identity.json', drifted)
    monkeypatch.setattr(export_validation, 'validate_lifecycle_exports',
                        real_validate)
    with pytest.raises(AssertionError, match='identity drift'):
        vm_boot.verify_exports(run, 'copy', ['identity.json'])


def test_attempt_verify_hashes_and_semantics_share_one_snapshot(
        tmp_path, monkeypatch):
    export = attempt_export(tmp_path)
    target = export / 'export/correctness-ledger.json'
    valid = target.read_text()
    tampered = json.loads(valid)
    tampered['mode'] = 'saturation'
    rewrite_export(target, json.dumps(tampered))
    real_validate = export_validation.validate_attempt_exports

    def swapping_validate(got, mode):
        rewrite_export(export / 'export/correctness-ledger.json',
                       valid)
        return real_validate(got, mode)

    monkeypatch.setattr(export_validation, 'validate_attempt_exports',
                        swapping_validate)
    try:
        with pytest.raises(ValueError):
            test_attempt_capture.verify_exports(
                export, 'correctness')
    finally:
        rewrite_export(export / 'export/correctness-ledger.json',
                       valid)


PERF_LC_WINDOW = (
    'lc kind=1 ok=1 skip=0 dir=1 seq=0 ktime=100 size=512 gen=0\n'
    'summary observed=1 badframe=0 badrec=0 cnt_obs=1 cnt_obsb=512 '
    'cnt_emit=1 cnt_emitb=512 cnt_fail=0 cnt_flags=0 '
    'rx=1 dlv=1 mal=0 drop=0\n')
PERF_CP_WINDOW = (
    'cp kind=2 todev=1 known=1 clamp=0 ezero=0 dir=1 reason=0 '
    'seq=0 ktime=100 req=512 eff=512\n'
    'summary observed=1 badframe=0 badrec=0 cnt_obs=1 cnt_obsb=512 '
    'cnt_emit=1 cnt_emitb=512 cnt_fail=0 cnt_flags=0 '
    'rx=1 dlv=1 mal=0 drop=0\n')


def perf_pair(i):
    ping = dict(tx=1000, rx=1000, seconds=60.0, p99_ms=1.0,
                sample_tx=500, sample_rx=500, sample_count=500)
    dd = dict(bytes=32 * 16 * 65536, seconds=60.0)
    off = dict(pair=i, mode='off', ping=dict(ping), dd=dict(dd),
               end_ns=50)
    obs = dict(pair=i, mode='observed', ping=dict(ping),
               dd=dict(dd), end_ns=50, attach_ns=1, detach_ns=100)
    return [off, obs]


def perf_run(tmp_path, monkeypatch):
    identity = kernel_build_world(tmp_path, monkeypatch)
    run = tmp_path / 'run'
    export = run / 'export'
    export.mkdir(parents=True)
    files = {'identity.json': json.dumps(identity),
             'pairs.json': json.dumps(
                 [perf_pair(i) for i in range(6)])}
    for pair in range(6):
        files['p%d-lc.txt' % pair] = PERF_LC_WINDOW
        files['p%d-cp.txt' % pair] = PERF_CP_WINDOW
    for name, text in files.items():
        write_export_pair(export, 'perf', name, text)
    return run


def import_workloads():
    sys.path.insert(0, str(REPO / 'tests/perf'))
    import workloads
    return workloads


def drive_perf_flow(monkeypatch, run, tamper=None):
    workloads = import_workloads()
    monkeypatch.setattr(
        workloads, 'run_guest',
        lambda *args, **kwargs: (run, SimpleNamespace(
            returncode=0, stderr='')))
    if tamper is not None:
        real_compare = workloads.compare

        def tampering_compare(*args, **kwargs):
            tamper()
            return real_compare(*args, **kwargs)

        monkeypatch.setattr(workloads, 'compare',
                            tampering_compare)
    return workloads.run_flow()


def test_perf_workload_success_retains_verified_identity(
        tmp_path, monkeypatch, capsys):
    import evidence_retention
    run = perf_run(tmp_path, monkeypatch)
    owned = owned_dir(tmp_path, monkeypatch)
    monkeypatch.delenv('MEMVEIL_VM_KEEP_EXPORTS', raising=False)
    assert drive_perf_flow(monkeypatch, run) == 0
    assert not run.exists()
    doc = evidence_retention.verify_retained('perf')
    assert doc['disposition'] == 'passed'
    assert doc['complete'] is True
    assert 'perf-identity.json' in {
        entry['name'] for entry in doc['files']}
    kept = owned / 'gates' / 'perf' / 'perf-identity.json'
    assert json.loads(kept.read_text())['config_sha'] == 'c' * 64


def test_perf_workload_deleted_identity_pair_fails_closed(
        tmp_path, monkeypatch, capsys):
    import evidence_retention
    run = perf_run(tmp_path, monkeypatch)
    owned_dir(tmp_path, monkeypatch)
    monkeypatch.delenv('MEMVEIL_VM_KEEP_EXPORTS', raising=False)

    def tamper():
        (run / 'export' / 'perf-identity.json').unlink(
            missing_ok=True)
        (run / 'export' / 'perf-identity.json.sha256').unlink(
            missing_ok=True)

    with pytest.raises(ValueError):
        drive_perf_flow(monkeypatch, run, tamper)
    assert run.exists()
    doc = evidence_retention.verify_retained('perf')
    assert doc['disposition'] == 'failed'
    assert doc['complete'] is False
    assert {'name': 'perf-identity.json',
            'error': 'missing export'} in doc['file_errors']


def test_perf_workload_replaced_config_pair_fails_closed(
        tmp_path, monkeypatch, capsys):
    import evidence_retention
    run = perf_run(tmp_path, monkeypatch)
    owned_dir(tmp_path, monkeypatch)
    monkeypatch.delenv('MEMVEIL_VM_KEEP_EXPORTS', raising=False)

    def tamper():
        target = run / 'export' / 'perf-identity.json'
        doc = json.loads(target.read_text())
        doc['config_sha'] = 'e' * 64
        target.write_text(json.dumps(doc))
        (run / 'export' /
         'perf-identity.json.sha256').write_text(
            hashlib.sha256(target.read_bytes()).hexdigest()
            + '\n')

    with pytest.raises(ValueError):
        drive_perf_flow(monkeypatch, run, tamper)
    assert run.exists()
    doc = evidence_retention.verify_retained('perf')
    assert doc['disposition'] == 'failed'
    assert doc['complete'] is False
    assert {'name': 'perf-identity.json',
            'error': 'hash mismatch'} in doc['file_errors']


def test_perf_workload_missing_all_exports_records_failed_receipt(
        tmp_path, monkeypatch, capsys):
    import evidence_retention
    run = perf_run(tmp_path, monkeypatch)
    owned = owned_dir(tmp_path, monkeypatch)
    monkeypatch.delenv('MEMVEIL_VM_KEEP_EXPORTS', raising=False)

    def tamper():
        for path in (run / 'export').iterdir():
            path.unlink()

    with pytest.raises(ValueError):
        drive_perf_flow(monkeypatch, run, tamper)
    receipt = owned / 'gates' / 'perf' / 'receipt.json'
    assert receipt.is_file(), \
        'late retention failure left no gate receipt'
    doc = evidence_retention.verify_retained('perf')
    assert doc['disposition'] == 'failed'
    assert doc['complete'] is False


def test_perf_workload_wires_gate_evidence():
    text = (REPO / 'tests/perf/workloads.py').read_text()
    assert 'retain_failure' in text
    assert 'expected_from_verified' in text


def test_perf_workload_symlinked_windows_fail_closed(
        tmp_path, monkeypatch, capsys):
    import evidence_retention
    run = perf_run(tmp_path, monkeypatch)
    owned = owned_dir(tmp_path, monkeypatch)
    monkeypatch.delenv('MEMVEIL_VM_KEEP_EXPORTS', raising=False)
    export = run / 'export'
    for pair in range(1, 6):
        for ring in ('lc', 'cp'):
            link = export / ('perf-p%d-%s.txt' % (pair, ring))
            link.unlink()
            link.symlink_to('perf-p0-%s.txt' % ring)
    assert drive_perf_flow(monkeypatch, run) == 1
    assert run.exists()
    assert 'reused' in capsys.readouterr().out
    receipt = owned / 'gates' / 'perf' / 'receipt.json'
    assert receipt.is_file(), \
        'aliased perf windows left no gate receipt'
    doc = evidence_retention.verify_retained('perf')
    assert doc['disposition'] == 'failed'
    assert doc['complete'] is False


def test_perf_workload_stat_read_race_fails_closed(
        tmp_path, monkeypatch, capsys):
    import evidence_retention
    run = perf_run(tmp_path, monkeypatch)
    owned = owned_dir(tmp_path, monkeypatch)
    monkeypatch.delenv('MEMVEIL_VM_KEEP_EXPORTS', raising=False)
    export = run / 'export'
    real_read_text = Path.read_text

    def racing_read_text(self, *args, **kwargs):
        if (self.parent == export
                and self.name.startswith('perf-p')
                and self.name.endswith('.txt.sha256')):
            payload = export / self.name[:-len('.sha256')]
            pair, ring = payload.name[len('perf-'):].split('-', 1)
            if pair != 'p0' and not payload.is_symlink():
                payload.unlink()
                payload.symlink_to('perf-p0-%s' % ring)
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', racing_read_text)
    assert drive_perf_flow(monkeypatch, run) == 1
    assert run.exists()
    assert 'reused' in capsys.readouterr().out
    receipt = owned / 'gates' / 'perf' / 'receipt.json'
    assert receipt.is_file(), \
        'stat/read race left no gate receipt'
    doc = evidence_retention.verify_retained('perf')
    assert doc['disposition'] == 'failed'
    assert doc['complete'] is False


def test_empty_live_output_failure_retention_writes_failed_receipt(
        tmp_path, monkeypatch):
    import evidence_retention
    run = retention_run(tmp_path, gate='topwalk',
                        files={'live.txt': ''})
    owned = owned_dir(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        evidence_retention.retain_gate_evidence(
            run, 'topwalk', 'passed')
    receipt = evidence_retention.retain_failure(run, 'topwalk')
    assert receipt is not None
    doc = evidence_retention.verify_retained('topwalk')
    assert doc['disposition'] == 'failed'
    assert doc['complete'] is False
    assert doc['files'] == []
    assert doc['file_errors'] == [
        {'name': 'topwalk-exports',
         'error': 'no verified exports'}]
    assert not (owned / 'gates' / 'topwalk' /
                'topwalk-live.txt').exists()
