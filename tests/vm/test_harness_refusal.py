# SPDX-License-Identifier: GPL-3.0-or-later
"""Adversarial host checks; these tests earn no live-kernel qualification."""
import copy
import json
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).parent))
from consume import (check_conservation, parse_oracle_log, check_oracle_script,
                     replay_oracle_ledger, compare_live, translate_session)
from oracle_ledger import OracleLedger, compare
from semantics import admit
from test_real_io import check_consistency


def lc(seq=0, **kw):
    e = dict(ring='lc', kind=1, ok=1, skip=0, dir=1, seq=seq, ktime=20, size=512)
    return dict(e, **kw)


def cp(seq=0, **kw):
    e = dict(ring='cp', kind=2, todev=1, known=1, clamp=0, ezero=0,
             dir=1, reason=0, seq=seq, ktime=10, req=512, eff=512)
    return dict(e, **kw)


def summary(events, lost=0, **kw):
    n = len(events)
    size = 'size' if events and events[0]['ring'] == 'lc' else 'req'
    b = sum(e[size] for e in events)
    return dict(dict(observed=n, badframe=0, badrec=0, cnt_obs=n+lost,
                     cnt_obsb=b+lost*512, cnt_emit=n, cnt_emitb=b, cnt_fail=lost,
                     cnt_flags=0, rx=n, dlv=n, mal=0, drop=0), **kw)


def test_conservation_rejects_phantom_emission_and_delivery():
    events = [lc(0), lc(3)]
    assert check_conservation(events, summary(events, cnt_obs=4, cnt_emit=4,
                                             rx=0, dlv=0), 'phantom')


def test_conservation_keeps_disclosed_leading_and_trailing_submit_loss():
    events = [lc(1), lc(3)]
    assert check_conservation(events, summary(events, lost=3), 'saturation') == []


@pytest.mark.parametrize('event', [cp(kind=1, known=1, reason=0), cp(eff=513),
    cp(todev=0), cp(clamp=1), cp(ezero=1), cp(known=0, reason=1, eff=512),
    lc(kind=1, skip=1), lc(kind=2, ok=0)])
def test_full_window_rejects_semantic_record_corruption(event):
    assert check_conservation([event], summary([event]), 'record')


def test_full_window_healthy_sync_and_clamped_copy():
    for event in [cp(kind=1, known=0, reason=4, eff=0), cp(clamp=1, eff=256),
                  cp(ezero=1, eff=0), cp(known=0, reason=1, eff=0)]:
        assert check_conservation([event], summary([event]), 'record') == []


@pytest.mark.parametrize('body', ['op=0 attempt requested=512 forced=0',
    'op=0 outcome=success mapping=0 mapped=512', 'mapping=0 release lifetime_ns=100',
    'script complete ops=1'])
def test_oracle_duplicates_refused(tmp_path, body):
    path = tmp_path/'oracle.log'
    path.write_text('mv-oracle: '+body+'\nmv-oracle: '+body+'\n')
    with pytest.raises(ValueError, match='duplicate'):
        parse_oracle_log(path)


def test_oracle_sync_mapping_bound(tmp_path):
    path = tmp_path/'oracle.log'
    path.write_text('mv-oracle: op=0 attempt requested=512 forced=0\n'
                    'mv-oracle: op=0 outcome=success mapping=0 mapped=512\n'
                    'mv-oracle: op=0 mapping=999 sync dir=1 len=512\n'
                    'mv-oracle: mapping=0 release lifetime_ns=100\n'
                    'mv-oracle: script complete ops=1\n')
    args = parse_oracle_log(path)
    assert check_oracle_script(*args, 1, -1, 'mapping')


@pytest.mark.parametrize('field,value', [('hook','unrelated'), ('target','unrelated'),
    ('kind','tracepoint'), ('authority','btf'), ('adapter_len',True),
    ('available','false'), ('inlined',''), ('hook',''), ('target',42)])
def test_admission_identity_and_types(field, value):
    case = json.loads((Path(__file__).parent/'semantics/ok-copy-bounce.json').read_text())
    recorded = dict(case['recorded'], **{k:case['definition'][k] for k in
                    ('hook','kind','target','authority')})
    candidate = dict(case['definition'], **{field:value})
    assert not admit(candidate, recorded)[0]


def test_admission_healthy_control():
    case = json.loads((Path(__file__).parent/'semantics/ok-copy-bounce.json').read_text())
    recorded = dict(case['recorded'], **{k:case['definition'][k] for k in
                    ('hook','kind','target','authority')})
    assert admit(case['definition'], recorded)[0]


def metric(name, value, pool=None):
    return dict(name=name, value=None if value is None else str(value),
                dimensions=dict(device_id=None, pool_id=pool))


def report_for(ledger):
    entries = ledger.entries
    has_outcome = any(e['kind']=='outcome' for e in entries)
    vals = dict(bounce_attempts=sum(e['kind']=='attempt' for e in entries),
                requested_bounce_bytes=sum(e['requested'] for e in entries if e['kind']=='attempt'),
                successful_allocations=ledger.expected_allocations() if has_outcome else None,
                failed_allocations=ledger.expected_failures() if has_outcome else None,
                mapped_bytes_total=ledger.expected_mapped_bytes() if has_outcome else None,
                copy_original_to_bounce_bytes=None, copy_bounce_to_original_bytes=None,
                live_observed_allocation_bytes=ledger.expected_live_bytes()[0] if has_outcome else None,
                open_mappings=ledger.expected_live_bytes()[1] if has_outcome else None,
                completed_lifetime_count=None, lifetime_mean_ns=None,
                lifetime_min_ns=None,lifetime_max_ns=None,lifetime_p50_ns=None,lifetime_p95_ns=None,lifetime_p99_ns=None)
    return dict(metrics=[metric(k,v) for k,v in vals.items()], findings=[])


@pytest.mark.parametrize('name', ['bounce_attempts','requested_bounce_bytes','failed_allocations',
                                 'lifetime_mean_ns','lifetime_p50_ns','lifetime_p99_ns'])
def test_ledger_rejects_unsourced_or_wrong_metrics(name):
    ledger = OracleLedger(); ledger.record_attempt(0,'dev',512,False)
    ledger.record_outcome(0,False,return_code=-5); ledger.seal()
    report = report_for(ledger)
    next(m for m in report['metrics'] if m['name']==name)['value']='999'
    assert compare(report,ledger)


def test_ledger_healthy_failure_control():
    ledger=OracleLedger(); ledger.record_attempt(0,'dev',512,False)
    ledger.record_outcome(0,False,return_code=-5); ledger.seal()
    assert compare(report_for(ledger),ledger)==[]


def test_pressure_false_positive_and_subject_borrowing():
    ledger=OracleLedger()
    for _ in range(3): ledger.record_pool('pool-0',100,1000,'bytes')
    ledger.seal(); report=report_for(ledger)
    report['metrics'].append(metric('pool_pressure_samples',3,'pool-0'))
    report['findings']=[dict(code='POOL_PRESSURE',evidence_refs=['pool:pool-1'])]
    assert compare(report,ledger)


def test_inner_allocation_is_separate_from_outer_failure():
    ops={i:dict(requested=n,forced=0,success=i!=2,mapped=n,mapping=i,
                syncs=[] if i==2 else [dict(mapping=i,dir=2 if i%2 else 1,len=n)],rc=-5)
         for i,n in enumerate((512,1024,2048,4096))}
    ledger=replay_oracle_ledger(ops,{0:100,1:100,3:100})
    assert ledger.expected_allocations()==4
    assert ledger.expected_failures()==0
    assert ledger.expected_copies()['original_to_bounce']==8192
    assert sum(e['kind']=='outcome' and not e['success'] for e in ledger.entries)==1


def test_live_lifetimes_need_probe_intervals():
    ledger=OracleLedger(); ledger.record_release(0,100); ledger.seal()
    report=report_for(ledger)
    report['metrics'] += [metric('completed_lifetime_count',1)]
    assert compare_live(report,ledger)


@pytest.mark.parametrize('events', [[lc(kind=2,ktime=10),lc(1,ktime=20)],
                                   [lc(ok=0)]])
def test_realio_orphan_or_failed_map_cannot_be_live(events):
    workload=dict(start_ns=0,end_ns=100,used_before=[1],used_after=[1])
    bad,live=check_consistency(events,[cp(kind=1,known=0,reason=4,eff=0)],workload)
    assert bad
    if events[0]['ok']==0: assert live==0


def test_translator_is_synthetic_partial_reconstruction(tmp_path):
    translate_session([lc(ktime=100),lc(1,kind=2,skip=1,ktime=200)], [cp(ktime=90)],
                      {0:dict(requested=512,success=True)},tmp_path,'fixture','test-profile')
    session=json.loads((tmp_path/'session.json').read_text())
    events=[json.loads(s) for s in (tmp_path/'events.ndjson').read_text().splitlines()]
    assert session['synthetic'] is True
    assert session['quality']['terminal']['status']=='partial'
    attempt=next(e for e in events if e['kind']=='bounce_attempt')
    assert attempt['source']['measurement']=='derived'
    assert attempt['source']['correlation']=='unpaired'
    assert int(attempt['ts_ns']) < 90


def test_bpf_inventory_command_failure_is_not_empty(monkeypatch):
    import guest_lifecycle as guest
    from types import SimpleNamespace
    monkeypatch.setattr(guest,'sh',lambda *a,**kw: SimpleNamespace(returncode=1,stdout='',stderr='denied'))
    with pytest.raises((ValueError,SystemExit)):
        guest.Gate.bpf_inventory(object())


def test_bpf_inventory_counts_objects_not_pretty_lines(monkeypatch):
    import guest_lifecycle as guest
    from types import SimpleNamespace
    monkeypatch.setattr(guest,'sh',lambda *a,**kw: SimpleNamespace(returncode=0,stdout='[\n {"id":1},\n {"id":2}\n]\n',stderr=''))
    assert guest.Gate.bpf_inventory(object())==dict(progs=2,maps=2)


def test_lifecycle_export_rejects_extra_metadata_key(tmp_path):
    import hashlib
    from vm_boot import verify_exports
    export=tmp_path/'export'; export.mkdir()
    path=export/'oracle-identity.json'; path.write_text(json.dumps(dict(release='7.0',alternate_raw_address='0xabc')))
    Path(str(path)+'.sha256').write_text(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n')
    with pytest.raises((AssertionError,ValueError)):
        verify_exports(tmp_path,'oracle',['identity.json'])


def test_armed_missing_vng_fails_instead_of_skip(monkeypatch):
    import test_attempt_capture as gate
    monkeypatch.setenv('MEMVEIL_VM_ORACLE','1')
    monkeypatch.setattr(gate,'find_vng',lambda:None)
    with pytest.raises(pytest.fail.Exception): gate.gate_prefix()


@pytest.mark.parametrize('blob',[b'bad swiotlb_bounced: size=12 NORMAL\n',
    b'x [001] .... 1.000001: swiotlb_bounced: size=12 NORMAL',
    b'x [001] .... 1.000001: swiotlb_bounced: size=12 MAYBE\n'])
def test_ftrace_relevant_malformed_and_truncation_refused(blob):
    from guest_flow import parse_ftrace
    with pytest.raises(ValueError): parse_ftrace(blob)


def test_ftrace_cardinality_healthy_control():
    from guest_flow import parse_ftrace
    doc=parse_ftrace(b'# header\n\nx [001] .... 1.000001: swiotlb_bounced: size=12 NORMAL\nCPU:0 [LOST 2 EVENTS]\n')
    assert len(doc['events'])==1
    assert doc['pipe_lines']==4
    assert doc['header_lines']==1 and doc['blank_lines']==1 and doc['lost_lines']==1


@pytest.mark.parametrize('rc',[0,1,-9])
def test_victim_other_exit_is_not_sigterm(rc):
    from guest_lifecycle import validate_victim
    with pytest.raises(ValueError): validate_victim(True,rc)


def test_victim_must_be_alive_before_signal():
    from guest_lifecycle import validate_victim
    with pytest.raises(ValueError): validate_victim(False,-15)
    assert validate_victim(True,-15) is None


def test_dmesg_missing_or_duplicate_marker_refused():
    from guest_lifecycle import dmesg_after_marker
    for text in ('old\nnew\n','marker\nmarker\nnew\n'):
        with pytest.raises(ValueError): dmesg_after_marker(text,'marker')
    assert dmesg_after_marker('old\nmarker\nnew\n','marker')==['new']


def test_oracle_sha_reuse_is_not_file_presence(monkeypatch,tmp_path):
    import lifecycle_env as env
    source=tmp_path/'memveil_dma_oracle.c'; source.write_text('source')
    (tmp_path/'Makefile').write_text('make')
    module=tmp_path/'memveil_dma_oracle.ko'; module.write_text('stale')
    module.with_suffix('.build.json').write_text('{}')
    monkeypatch.setattr(env,'KERNEL_DIR',str(tmp_path))
    monkeypatch.setattr(env,'ORACLE_KO',str(module))
    calls=[]
    def run(args,**kw):
        calls.append(args)
        if args[0]=='make': raise RuntimeError('rebuild reached')
        return type('Result',(),dict(returncode=0,stdout='',stderr=''))()
    monkeypatch.setattr(env.subprocess,'run',run)
    monkeypatch.setattr(env,'module_build_identity',lambda:dict(release='test'))
    (tmp_path/'memveil_region_oracle.c').write_text('region')
    monkeypatch.setattr(env.os.path,'isfile',lambda p: True)
    with pytest.raises(RuntimeError,match='rebuild reached'): env.ensure_oracle_module()


def test_report_exact_probe_lifetime_rejects_lower_values():
    ledger=OracleLedger();ledger.record_attempt(0,'dev',512,False)
    ledger.record_outcome(0,True,mapping=0,mapped_bytes=512);ledger.record_release(0,100);ledger.seal()
    report=report_for(ledger)
    for m in report['metrics']:
        if m['name']=='completed_lifetime_count':m['value']='1'
        if m['name'] in ('lifetime_mean_ns','lifetime_min_ns','lifetime_max_ns'):m['value']='90'
        if m['name'] in ('lifetime_p50_ns','lifetime_p95_ns','lifetime_p99_ns'):m['value']='127'
    probes={0:dict(map=10,unmap=100)}
    assert compare_live(report,ledger,probes)==[]
    next(m for m in report['metrics'] if m['name']=='lifetime_mean_ns')['value']='0'
    assert compare_live(report,ledger,probes)


def test_translate_report_is_partial_exit4(tmp_path):
    import subprocess
    from test_oracle_live import MEMVEIL_BIN
    translate_session([lc(ktime=100),lc(1,kind=2,skip=1,ktime=200)], [cp(ktime=90)],
                      {0:dict(requested=512,success=True)},tmp_path,'fixture','test-profile')
    proc=subprocess.run([MEMVEIL_BIN,'report','--format','json',str(tmp_path)],capture_output=True,text=True)
    assert proc.returncode==4,proc.stderr
    report=json.loads(proc.stdout)
    assert report['quality']['terminal']['status']=='partial'


def test_export_healthy_lifecycle_identity(tmp_path,monkeypatch):
    import hashlib
    import vm_boot
    from export_validation import validate_lifecycle_exports
    doc=dict(release='7.0.0-34-generic',swiotlb_force=True)
    doc.update({k:'a'*64 for k in ('config_sha','btf_sha','bridge_sha','consume_sha','lc_sha','cp_sha','ko_sha')})
    path=tmp_path/'identity.json';path.write_text(json.dumps(doc))
    validate_lifecycle_exports({'identity.json':path},'oracle')


def test_retained_multiset_rejects_compensating_corruption():
    from consume import check_retained_script
    assert check_retained_script([lc(size=513)],[],4,-1,'loss')
    assert check_retained_script([lc(size=512)],[],4,-1,'loss')==[]


def test_readiness_cannot_pass_loaded_programs_without_ack(monkeypatch):
    import guest_lifecycle as guest
    from types import SimpleNamespace
    proc=SimpleNamespace(gate_ready=False,poll=lambda:0)
    gate=SimpleNamespace(consumers=[proc])
    with pytest.raises(SystemExit): guest.Gate.wait_ready(gate,('loaded',),timeout=0.1)


def test_owned_guest_timeout_stops_its_child(tmp_path):
    import os,subprocess,time
    from vm_process import run_owned_guest
    marker=tmp_path/'child.pid'
    script="import subprocess,time,pathlib; p=subprocess.Popen(['sleep','30']); pathlib.Path(%r).write_text(str(p.pid)); time.sleep(30)" % str(marker)
    with pytest.raises(subprocess.TimeoutExpired):
        run_owned_guest([sys.executable,'-c',script],timeout=0.3)
    pid=int(marker.read_text())
    # An exited zombie awaits init reaping; it is no longer a running resource.
    status=Path('/proc')/str(pid)/'stat'
    try:
        state=status.read_text().split()[2]
    except FileNotFoundError:
        state='exited'
    assert state in ('Z','exited')


def test_missing_oracle_outcome_cannot_pass_parser(tmp_path):
    p=tmp_path/'oracle.log';p.write_text('mv-oracle: op=0 outcome=success\n')
    with pytest.raises(ValueError): parse_oracle_log(p)


def test_admission_exact_recorded_fexit_shape():
    case=json.loads((Path(__file__).parent/'semantics/ok-lifecycle-map.json').read_text())
    d=copy.deepcopy(case['definition']);d['kind']='fexit';d['hook']='fexit:swiotlb_tbl_map_single'
    recorded=dict(case['recorded'],kind=d['kind'],hook=d['hook'])
    assert admit(d,recorded)[0]
    assert not admit(d,dict(case['recorded'],kind='fentry',hook='fentry:swiotlb_tbl_map_single'))[0]


@pytest.mark.parametrize('name',['mapped_bytes_total','lifetime_min_ns','lifetime_max_ns','lifetime_p95_ns'])
def test_ledger_supported_metric_tampering(name):
    from test_oracle_ledger import _nested_ledger,_report_for
    report=_report_for('lifecycle/lifecycle-nested')
    next(m for m in report['metrics'] if m['name']==name)['value']='999'
    assert compare(report,_nested_ledger())


@pytest.mark.parametrize('field,value',[('signature',{}),('signature',{'return':'','params':[]}),
    ('btf_anchor',{'release':'7.0.0-34-generic','id':True})])
def test_admission_malformed_equal_evidence_refuses(field,value):
    case=json.loads((Path(__file__).parent/'semantics/ok-copy-bounce.json').read_text())
    d=dict(case['definition'],**{field:value}); r=dict(case['recorded'],**{field:value})
    assert not admit(d,r)[0]


def test_authored_projection_has_exact_nonzero_metrics_and_preserves_unpaired_capture(tmp_path):
    import subprocess
    from consume import author_reducer_fixture
    from test_oracle_live import MEMVEIL_BIN
    original=tmp_path/'reconstruction';fixture=tmp_path/'authored'
    probes=translate_session([lc(ktime=100),lc(1,kind=2,skip=1,ktime=200)], [cp(ktime=90)],
                      {0:dict(requested=512,success=True,forced=0)},original,'fixture','test-profile')
    before=(original/'events.ndjson').read_bytes()
    author_reducer_fixture(original,fixture)
    original_doc=json.loads((original/'session.json').read_text())
    doc=json.loads((fixture/'session.json').read_text())
    events=[json.loads(s) for s in (fixture/'events.ndjson').read_text().splitlines()]
    assert (original/'events.ndjson').read_bytes()==before
    assert original_doc['quality']['correlation']['status']=='partial'
    assert doc['synthetic'] is True and doc['capture']['mode']=='synthetic'
    assert doc['quality']['terminal']['status']=='partial'
    assert 'Authored' in doc['quality']['correlation']['reason']
    assert all(e['source']['backend']=='synthetic-fixture' and e['source']['profile_id'].startswith('authored-') for e in events)
    assert all(e['source']['hook'].startswith('fixture:') for e in events)
    assert next(e for e in events if e['kind']=='bounce_attempt')['source']['measurement']=='derived'
    proc=subprocess.run([MEMVEIL_BIN,'report','--format','json',str(fixture)],capture_output=True,text=True)
    assert proc.returncode==4,proc.stderr
    report=json.loads(proc.stdout)
    ledger=OracleLedger();ledger.record_attempt(0,'dev-1',512,False)
    ledger.record_outcome(0,True,mapping=0,mapped_bytes=512)
    ledger.record_copy(0,'original_to_bounce',512,mapping=0)
    ledger.record_release(0,100);ledger.seal()
    assert compare_live(report,ledger,probes)==[]
    metrics={m['name']:m['value'] for m in report['metrics'] if m['dimensions']['device_id'] is None and m['dimensions']['pool_id'] is None}
    assert metrics['successful_allocations']=='1'
    assert metrics['copy_original_to_bounce_bytes']=='512'
    assert metrics['completed_lifetime_count']=='1' and metrics['lifetime_mean_ns']=='100'
