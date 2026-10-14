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


def test_term_handler_child_is_retired_before_later_lane(tmp_path):
    import os, shlex, signal, subprocess, sys
    module = load()
    repo = tmp_path / 'repo'
    (repo / 'tools').mkdir(parents=True)
    childfile = tmp_path / 'term-child.pid'
    later = tmp_path / 'later.started'
    tool = repo / 'tools/test'
    tool.write_text('#!/bin/sh\n'
        'if [ "$1" = later ]; then test ! -e /proc/$(cat ' + shlex.quote(str(childfile)) + ') && touch ' + shlex.quote(str(later)) + '; exit $?; fi\n'
        "trap 'setsid sleep 30 </dev/null >/dev/null 2>&1 & echo $! > " + shlex.quote(str(childfile)) + "; exit 0' TERM\n"
        'while :; do sleep 5; done\n')
    tool.chmod(0o755)
    unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    try:
        code = module.run_suites(repo, tmp_path / 'out', ['finite', 'later'], {'finite': .2, 'later': 1})
        pid = int(childfile.read_text())
        receipt = json.loads((tmp_path / 'out/results.json').read_text())
        assert code == 1 and receipt['lanes'][0]['timed_out'] is True
        assert not (Path('/proc') / str(pid)).exists()
        assert receipt['lanes'][0]['cleanup']['remaining_owned'] == 0
        assert receipt['lanes'][1]['status'] == 'PASS' and later.exists()
        assert unrelated.poll() is None
    finally:
        if childfile.exists():
            pid = int(childfile.read_text())
            if pid in module._processes():
                os.kill(pid, signal.SIGKILL)
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        unrelated.kill()
        unrelated.wait()


def test_uncertain_cleanup_blocks_later_lane(tmp_path, monkeypatch):
    module = load()
    repo = tmp_path / 'repo'
    (repo / 'tools').mkdir(parents=True)
    later = tmp_path / 'later.started'
    tool = repo / 'tools/test'
    tool.write_text('#!/bin/sh\nif [ "$1" = later ]; then touch ' + str(later) + '; else sleep 30; fi\n')
    tool.chmod(0o755)
    terminate = module._terminate_owned
    def uncertain(proc, prior):
        result = terminate(proc, prior)
        result['signal_errors'] = 1
        return result
    monkeypatch.setattr(module, '_terminate_owned', uncertain)
    assert module.run_suites(repo, tmp_path / 'out', ['finite', 'later'], {'finite': .2}) == 1
    receipt = json.loads((tmp_path / 'out/results.json').read_text())
    assert receipt['lanes'][1]['status'] == 'BLOCKED' and not later.exists()


def _uncertain_final_lane(tmp_path, monkeypatch, suites):
    module = load()
    repo = tmp_path / 'repo'
    (repo / 'tools').mkdir(parents=True)
    tool = repo / 'tools/test'
    # An adopted zombie needs reaping despite a successful leader exit.
    import sys
    tool.write_text('#!' + sys.executable + '\nimport os,sys,time\n'
                    'if sys.argv[1] == "first": sys.exit(0)\n'
                    'if os.fork() == 0: os._exit(0)\n'
                    'time.sleep(.1)\n')
    tool.chmod(0o755)
    terminate = module._terminate_owned
    def uncertain(proc, prior):
        result = terminate(proc, prior)
        result['signal_errors'] = 1
        return result
    monkeypatch.setattr(module, '_terminate_owned', uncertain)
    assert module.run_suites(repo, tmp_path / 'out', suites) == 1
    receipt = json.loads((tmp_path / 'out/results.json').read_text())
    assert receipt['status'] == 'BLOCKED'
    assert receipt['lanes'][-1]['status'] == 'BLOCKED'
    assert receipt['lanes'][-1]['native_exit'] == 0
    assert receipt['lanes'][-1]['cleanup']['remaining_owned'] == 0



def test_only_lane_with_uncertain_cleanup_cannot_pass(tmp_path, monkeypatch):
    _uncertain_final_lane(tmp_path, monkeypatch, ['only'])


def test_last_lane_with_uncertain_cleanup_cannot_pass(tmp_path, monkeypatch):
    _uncertain_final_lane(tmp_path, monkeypatch, ['first', 'only'])


def fake_tool(repo, body):
    script = repo / 'tools/test'
    script.write_text(body)
    script.chmod(0o755)


def owned_repo(tmp_path):
    repo = tmp_path / 'repo'
    (repo / 'tools').mkdir(parents=True)
    return repo


def test_child_suites_inherit_the_owned_evidence_directory(tmp_path):
    module = load()
    repo = owned_repo(tmp_path)
    seen = tmp_path / 'seen.env'
    fake_tool(repo, '#!/bin/sh\necho \"$MEMVEIL_EVIDENCE_DIR\" > '
              + str(seen) + '\n')
    out = tmp_path / 'out'
    assert module.run_suites(repo, out, ['a']) == 0
    assert seen.read_text().strip() == str(out.resolve())


def test_skipped_lane_writes_a_skipped_receipt(tmp_path):
    module = load()
    repo = owned_repo(tmp_path)
    fake_tool(repo, '#!/bin/sh\nexit 77\n')
    out = tmp_path / 'out'
    assert module.run_suites(repo, out, ['a']) == 1
    receipt = json.loads((out / 'gates' / 'a' /
                          'receipt.json').read_text())
    assert receipt['schema'] == 'memveil-gate-evidence/1'
    assert receipt['disposition'] == 'skipped'
    assert receipt['complete'] is False
    assert receipt['files'] == []
    assert receipt['detail']['native_exit'] == 77


def test_uncertain_cleanup_lane_writes_cleanup_uncertain_receipt(
        tmp_path, monkeypatch):
    module = load()
    repo = owned_repo(tmp_path)
    tool = repo / 'tools/test'
    tool.write_text('#!/bin/sh\nsleep 30\n')
    tool.chmod(0o755)
    terminate = module._terminate_owned

    def uncertain(proc, prior):
        result = terminate(proc, prior)
        result['signal_errors'] = 1
        return result

    monkeypatch.setattr(module, '_terminate_owned', uncertain)
    assert module.run_suites(
        repo, tmp_path / 'out', ['finite'],
        {'finite': .2}) == 1
    receipt = json.loads((tmp_path / 'out/gates/finite/'
                          'receipt.json').read_text())
    assert receipt['disposition'] == 'cleanup-uncertain'
    assert receipt['complete'] is False
    assert receipt['detail']['signal_errors'] == 1


def test_blocked_lane_after_unresolved_cleanup_stays_uncertain(
        tmp_path, monkeypatch):
    module = load()
    repo = owned_repo(tmp_path)
    tool = repo / 'tools/test'
    tool.write_text('#!/bin/sh\nsleep 30\n')
    tool.chmod(0o755)
    terminate = module._terminate_owned

    def uncertain(proc, prior):
        result = terminate(proc, prior)
        result['signal_errors'] = 1
        return result

    monkeypatch.setattr(module, '_terminate_owned', uncertain)
    out = tmp_path / 'out'
    assert module.run_suites(
        repo, out, ['finite', 'later'],
        {'finite': .2}) == 1
    receipt = json.loads((out / 'gates/later/'
                          'receipt.json').read_text())
    assert receipt['disposition'] == 'cleanup-uncertain'
    assert receipt['complete'] is False
    assert receipt['detail']['status'] == 'BLOCKED'


def test_finished_lane_keeps_gate_authored_evidence(tmp_path):
    module = load()
    repo = owned_repo(tmp_path)
    fake_tool(repo, '#!/bin/sh\nexit 0\n')
    out = tmp_path / 'out'
    assert module.run_suites(repo, out, ['a']) == 0
    assert not (out / 'gates' / 'a' / 'receipt.json').exists()


def test_failed_lane_writes_a_failed_receipt(tmp_path):
    module = load()
    repo = owned_repo(tmp_path)
    fake_tool(repo, '#!/bin/sh\nexit 1\n')
    out = tmp_path / 'out'
    assert module.run_suites(repo, out, ['a']) == 1
    receipt = json.loads((out / 'gates' / 'a' /
                          'receipt.json').read_text())
    assert receipt['disposition'] == 'failed'
    assert receipt['complete'] is False
    assert receipt['detail']['status'] == 'FAIL'
    assert receipt['detail']['native_exit'] == 1
    assert receipt['detail']['timed_out'] is False


def test_clean_timeout_writes_a_failed_receipt(tmp_path):
    module = load()
    repo = owned_repo(tmp_path)
    tool = repo / 'tools/test'
    tool.write_text('#!/bin/sh\nsleep 30\n')
    tool.chmod(0o755)
    out = tmp_path / 'out'
    assert module.run_suites(
        repo, out, ['finite'], {'finite': .2}) == 1
    lane = json.loads(
        (out / 'results.json').read_text())['lanes'][0]
    assert lane['timed_out'] is True
    assert lane['cleanup']['remaining_owned'] == 0
    assert lane['cleanup']['signal_errors'] == 0
    receipt = json.loads((out / 'gates/finite/'
                          'receipt.json').read_text())
    assert receipt['disposition'] == 'failed'
    assert receipt['complete'] is False
    assert receipt['detail']['timed_out'] is True


def test_owned_directory_holds_lane_and_gate_receipts(tmp_path):
    module = load()
    repo = owned_repo(tmp_path)
    gate = tmp_path / 'gate-tmp'
    export = gate / 'export'
    export.mkdir(parents=True)
    identity = dict(
        release='7.0.0-34-generic', swiotlb_force=True,
        **{key: 'a' * 64 for key in (
            'config_sha', 'btf_sha', 'bridge_sha', 'consume_sha',
            'lc_sha', 'cp_sha', 'ko_sha')})
    body = json.dumps(identity)
    (export / 'bundle-identity.json').write_text(body)
    import hashlib
    (export / 'bundle-identity.json.sha256').write_text(
        hashlib.sha256(body.encode()).hexdigest() + '\n')
    gate_run = tmp_path / 'gate-run.py'
    gate_run.write_text(
        'import sys\n'
        'sys.path.insert(0, ' +
        repr(str(Path(__file__).resolve().parent)) + ')\n'
        'from test_attempt_capture import cleanup\n'
        'cleanup(sys.argv[1], "bundle")\n')
    fake_tool(repo, '#!/bin/sh\nif [ \"$1\" = gates ]; then '
              'python3 ' + str(gate_run) + ' ' + str(gate) +
              '; else exit 77; fi\n')
    out = tmp_path / 'out'
    assert module.run_suites(repo, out, ['gates', 'rest']) == 1
    assert not gate.exists()
    assert json.loads((out / 'gates/bundle/'
                             'receipt.json').read_text())['complete'] is True
    assert json.loads((out / 'gates/rest/'
                             'receipt.json').read_text())[
        'disposition'] == 'skipped'
