# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline tests for the paired-comparison math."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from compare import assess, compare, validate


def run(throughput, p99, valid=True, reason=""):
    return {"valid": valid, "counts_ok": valid,
            "invalid_reason": reason, "throughput": throughput,
            "p99": p99}


def test_validate_excludes_by_name():
    good, bad = validate([run(100, 10), run(0, 0, False, "counts bad")])
    assert len(good) == 1
    assert bad == [(1, "counts bad")]


def test_too_few_pairs_unqualified():
    verdict = compare("w", [run(100, 10)] * 2, [run(99, 11)] * 2)
    assert verdict["qualified"] is False
    assert verdict["pairs"] == 2
    status, _ = assess(verdict)
    assert status == "UNQUALIFIED"


def test_pass_within_targets():
    base = [run(100, 10)] * 5
    obs = [run(98, 10.5)] * 5
    verdict = compare("w", base, obs)
    assert verdict["qualified"] is True
    assert verdict["fields"]["throughput"]["median"] == 0.98
    status, _ = assess(verdict)
    assert status == "PASS"


def test_throughput_breach_fails():
    base = [run(100, 10)] * 5
    obs = [run(90, 10)] * 5
    status, reason = assess(compare("w", base, obs))
    assert status == "FAIL"
    assert "throughput" in reason


def test_p99_breach_fails():
    base = [run(100, 10)] * 5
    obs = [run(100, 12)] * 5
    status, reason = assess(compare("w", base, obs))
    assert status == "FAIL"
    assert "p99" in reason


def test_invalid_runs_never_silent():
    base = [run(100, 10)] * 5 + [run(0, 0, False, "env drift")]
    obs = [run(99, 10.5)] * 5
    verdict = compare("w", base, obs)
    assert verdict["qualified"] is True
    assert verdict["excluded"] == ["baseline#5: env drift", "observer#5: missing paired leg"]


def test_invalid_pair_cannot_cross_borrow_neighbor():
    base=[run(100+i,10) for i in range(6)]
    obs=[run(100+i,10) for i in range(6)]
    base[0]=run(0,0,False,'base failed')
    obs[1]=run(0,0,False,'observer failed')
    assert compare('w',base,obs)['pairs']==4
    assert compare('w',base,obs)['qualified'] is False


def test_absent_latency_cannot_earn_target_pass():
    verdict=compare('w',[run(100,None)]*5,[run(100,None)]*5)
    assert assess(verdict)[0]=='UNQUALIFIED'


def test_nonfinite_ratio_cannot_qualify():
    verdict=compare('w',[run(100,10)]*5,[run(float('nan'),10)]*5)
    assert assess(verdict)[0]=='UNQUALIFIED'


def test_dd_only_can_qualify_its_explicit_fields():
    verdict=compare('dd',[run(100,None)]*5,[run(100,None)]*5,fields=('throughput',))
    assert assess(verdict)[0]=='PASS'


def test_workload_requires_completed_latency_sample():
    from workloads import leg_runs
    leg=dict(ping=dict(tx=1000,rx=1000,seconds=1,p99_ms=1,
                       sample_tx=500,sample_rx=499,sample_count=499),
             dd=dict(bytes=32*16*65536,seconds=1))
    ping,dd=leg_runs(leg,0,'off')
    assert ping['valid'] is False


def perf_flow(tmp_path, monkeypatch, p99=1.0, observed_seconds=1.0, mutation=None, exports_mutation=None):
    import json
    from types import SimpleNamespace
    import workloads
    pairs = []
    for index in range(6):
        legs = []
        for mode in ('off', 'observed'):
            legs.append(dict(pair=index, mode=mode, end_ns=1, attach_ns=0, detach_ns=2,
                ping=dict(tx=1000, rx=1000, seconds=observed_seconds if mode == 'observed' else 1.0,
                          p99_ms=p99, sample_tx=500, sample_rx=500, sample_count=500),
                dd=dict(bytes=32*16*65536, seconds=1.0)))
        pairs.append(legs)
    if mutation:
        mutation(pairs)
    path = tmp_path / 'pairs.json'
    path.write_text(json.dumps(pairs))
    got = {'pairs.json': path}
    for index in range(6):
        for ring in ('lc', 'cp'):
            got['p%d-%s.txt' % (index, ring)] = tmp_path / ('p%d-%s.txt' % (index, ring))
    if exports_mutation:
        exports_mutation(got)
    monkeypatch.setattr(workloads, 'run_guest', lambda *a, **k: (tmp_path, SimpleNamespace(returncode=0)))
    monkeypatch.setattr(workloads, 'verify_exports', lambda *a, **k: got)
    # VM and raw decoding are separate gates; retain the real leg validity,
    # pair binding, comparator and native result propagation boundary here.
    monkeypatch.setattr(workloads, 'parse_consume_file', lambda *a: ([{'kind': 1}], {'cnt_fail': 0}))
    monkeypatch.setattr(workloads, 'check_conservation', lambda *a: [])
    cleaned = []
    monkeypatch.setattr(workloads, 'cleanup', lambda path: cleaned.append(path))
    return workloads.run_flow(), cleaned


def test_flow_healthy_distinct_pairs_pass(tmp_path, monkeypatch, capsys):
    code, cleaned = perf_flow(tmp_path, monkeypatch)
    assert code == 0 and cleaned == [tmp_path]
    assert 'PASS: paired laboratory' in capsys.readouterr().out


def test_flow_insufficient_latency_fails_and_preserves_evidence(tmp_path, monkeypatch, capsys):
    code, cleaned = perf_flow(tmp_path, monkeypatch, p99=0.0)
    output = capsys.readouterr().out
    assert code == 1 and not cleaned
    assert 'UNQUALIFIED' in output and 'gate artifacts kept' in output
    assert 'PASS: paired laboratory' not in output


def test_flow_valid_target_miss_retains_declared_limitation(tmp_path, monkeypatch, capsys):
    code, cleaned = perf_flow(tmp_path, monkeypatch, observed_seconds=2.0)
    output = capsys.readouterr().out
    assert code == 0 and cleaned == [tmp_path]
    assert 'LIMITATION: ping FAIL' in output


def test_flow_reused_pair_cannot_reuse_probe_windows(tmp_path, monkeypatch, capsys):
    def repeat(pairs):
        for legs in pairs:
            for leg in legs:
                leg['pair'] = 0
    code, cleaned = perf_flow(tmp_path, monkeypatch, mutation=repeat)
    assert code == 1 and not cleaned
    assert 'PASS: paired laboratory' not in capsys.readouterr().out


def test_flow_borrowed_window_is_refused(tmp_path, monkeypatch):
    def borrow(got):
        got['p1-lc.txt'] = got['p0-lc.txt']
    code, cleaned = perf_flow(tmp_path, monkeypatch, exports_mutation=borrow)
    assert code == 1 and not cleaned


def test_flow_missing_window_is_refused(tmp_path, monkeypatch):
    code, cleaned = perf_flow(tmp_path, monkeypatch,
                             exports_mutation=lambda got: got.pop('p5-lc.txt'))
    assert code == 1 and not cleaned


def test_flow_unexpected_window_is_refused(tmp_path, monkeypatch):
    code, cleaned = perf_flow(tmp_path, monkeypatch,
                             exports_mutation=lambda got: got.update({'p6-lc.txt': tmp_path / 'extra'}))
    assert code == 1 and not cleaned


def test_flow_one_named_exclusion_keeps_five_distinct_pairs(tmp_path, monkeypatch, capsys):
    def invalid(pairs):
        pairs[0][0]['ping']['rx'] = 999
    code, cleaned = perf_flow(tmp_path, monkeypatch, mutation=invalid)
    output = capsys.readouterr().out
    assert code == 0 and cleaned == [tmp_path]
    assert 'pairs=5' in output and 'excluded baseline#0:' in output



def test_flow_four_usable_latency_ratios_cannot_qualify(tmp_path, monkeypatch, capsys):
    def missing(pairs):
        for legs in pairs[:2]:
            legs[0]['ping']['p99_ms'] = 0.0
    code, cleaned = perf_flow(tmp_path, monkeypatch, mutation=missing)
    output = capsys.readouterr().out
    assert code == 1 and not cleaned
    assert "'samples': 4" in output and 'UNQUALIFIED' in output


def test_flow_missing_pair_identity_is_refused(tmp_path, monkeypatch):
    code, cleaned = perf_flow(tmp_path, monkeypatch, mutation=lambda pairs: pairs.pop())
    assert code == 1 and not cleaned
