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
