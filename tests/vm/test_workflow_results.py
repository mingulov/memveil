# SPDX-License-Identifier: GPL-3.0-or-later
"""Execute native status collection with local fake suite executables."""
import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path


def load():
    loader=SourceFileLoader('results',str(Path(__file__).resolve().parents[2]/'tools/qualification-results'))
    spec=importlib.util.spec_from_loader(loader.name,loader)
    module=importlib.util.module_from_spec(spec);loader.exec_module(module)
    return module


def run(tmp_path,exits):
    repo=tmp_path/'repo';(repo/'tools').mkdir(parents=True)
    script=repo/'tools/test'
    cases='\n'.join(f'{suite}) exit {rc};;' for suite,rc in exits.items())
    script.write_text('#!/bin/sh\ncase "$1" in\n'+cases+'\nesac\n')
    script.chmod(0o755)
    out=tmp_path/'out'
    rc=load().run_suites(repo,out,list(exits))
    return rc,json.loads((out/'results.json').read_text())


def test_required_all_skips_block(tmp_path):
    rc,doc=run(tmp_path,dict(a=77,b=77))
    assert rc==1 and doc['status']=='BLOCKED'
    assert [r['native_exit'] for r in doc['lanes']]==[77,77]
    assert all(r['status']=='SKIP' for r in doc['lanes'])


def test_failed_lane_does_not_erase_later_results(tmp_path):
    rc,doc=run(tmp_path,dict(a=1,b=0))
    assert rc==1 and [r['status'] for r in doc['lanes']]==['FAIL','PASS']


def test_all_positive_native_results_pass(tmp_path):
    rc,doc=run(tmp_path,dict(a=0,b=0))
    assert rc==0 and doc['status']=='PASS'


def test_skipped_required_lane_blocks_even_with_positive_sibling(tmp_path):
    rc,doc=run(tmp_path,dict(a=77,b=0))
    assert rc==1 and doc['status']=='BLOCKED'


def test_soak_budget_includes_completion_margin(monkeypatch):
    module=load();monkeypatch.setenv('MEMVEIL_SOAK_MINUTES','30')
    assert module.suite_timeout('soak')>1800


def test_timeout_reaps_descendants_in_separate_sessions(tmp_path):
    import os,shlex,sys
    module=load();repo=tmp_path/'repo';(repo/'tools').mkdir(parents=True)
    childfile=tmp_path/'child.pid'
    script="import os,time,pathlib; pathlib.Path(%r).write_text(str(os.getpid()));time.sleep(30)" % str(childfile)
    tool=repo/'tools/test'
    tool.write_text('#!/bin/sh\nsetsid '+shlex.quote(sys.executable)+' -c '+shlex.quote(script)+' &\nwait\n')
    tool.chmod(0o755)
    code=module.run_suites(repo,tmp_path/'out',['owned-timeout'],timeouts={'owned-timeout':0.3})
    pid=int(childfile.read_text())
    assert not (Path('/proc')/str(pid)).exists()
    receipt=json.loads((tmp_path/'out/results.json').read_text())
    assert code==1 and receipt['lanes'][0]['timed_out'] is True
    assert receipt['lanes'][0]['cleanup']['remaining_owned']==0
