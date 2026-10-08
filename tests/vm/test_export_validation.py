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
