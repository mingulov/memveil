#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Executed-copy witness and inner/outer boundary in the VM.

Window w runs the standard script with bounce readback and
device-write simulation: every executed copy carries a
verified-bytes witness, and the report loop compares reducer
metrics against witnessed bytes only. Window f adds the
fail probe with an unclamped inner-health retry: the module
proves outer failure plus inner health while the probes show
the inner map, the surviving copy, and the cleanup unmap.

Both windows compare against the frozen spec in
tests/vm/fixtures/witness-expectations.json, written before
the first witness boot. A laboratory translator result here
validates the oracle machinery; it is not shipping
qualification.
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import (author_reducer_fixture, check_conservation,
                     check_lifetime_ordering, check_oracle_witness,
                     check_record_flags, compare_live,
                     compare_multisets, parse_consume_file,
                     parse_oracle_log,
                     replay_oracle_witness_ledger,
                     translate_session)
from lifecycle_env import (CONSUMER, COPY_PROBE, LIFECYCLE_PROBE,
                           ensure_oracle_module,
                           require_lifecycle_env)
from vm_boot import cleanup, run_guest, verify_exports

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SPEC = os.path.join(REPO, "tests", "vm", "fixtures",
                    "witness-expectations.json")
MEMVEIL_BIN = os.path.join(REPO, "build", "memveil")


def _spec_multisets(spec):
    out = {}
    for key in ("maps", "unmaps", "syncs_dev", "syncs_cpu",
                "bounces"):
        out[key] = sorted(tuple(item)
                          for item in spec["probes"][key])
    return out


def _probe_eff(cp_events):
    todev = sum(e["eff"] for e in cp_events
                if e["kind"] == 2 and e["todev"] == 1)
    tocpu = sum(e["eff"] for e in cp_events
                if e["kind"] == 2 and e["todev"] == 0)
    return todev, tocpu


def check_window(got, tag, spec):
    lc, lc_sum = parse_consume_file(str(got["%s-lc.txt" % tag]))
    cp, cp_sum = parse_consume_file(str(got["%s-cp.txt" % tag]))
    bad = check_conservation(lc, lc_sum, tag + "-lc")
    bad += check_conservation(cp, cp_sum, tag + "-cp")
    ops_log, releases, complete = parse_oracle_log(
        str(got["%s-oracle.log" % tag]))
    bad += check_oracle_witness(ops_log, releases, complete,
                                spec, tag)
    bad += compare_multisets(lc, cp, _spec_multisets(spec), tag)
    bad += check_record_flags(lc, cp, tag)
    todev, tocpu = _probe_eff(cp)
    want = spec["witnessed"]
    if todev != want["original_to_bounce"] + spec["unwitnessed_gap"]:
        bad.append("%s: probe to-device eff %d != witnessed %d + gap %d"
                   % (tag, todev, want["original_to_bounce"],
                      spec["unwitnessed_gap"]))
    if tocpu != want["bounce_to_original"]:
        bad.append("%s: probe to-cpu eff %d != witnessed %d"
                   % (tag, tocpu, want["bounce_to_original"]))
    if todev + tocpu != spec["witnessed_total"] + spec["unwitnessed_gap"]:
        bad.append("%s: probe eff total %d != witnessed %d + gap %d"
                   % (tag, todev + tocpu, spec["witnessed_total"],
                      spec["unwitnessed_gap"]))
    return bad, lc, cp, ops_log, releases


def check_inner_outer(ops_log, lc, cp, tag):
    """The fail op exercises the internal/final boundary.

    Module side: outer failure plus a healthy unclamped
    retry (retry health alone does not prove the original
    failure is outer). Probe side: inner map ok, a surviving
    executed copy, and the cleanup unmap, checked against
    the failed outer mapping. The module never releases the
    failed outer mapping.
    """
    bad = []
    entry = ops_log[2]
    if entry.get("success") is not False:
        bad.append("%s: fail op unexpectedly succeeded" % tag)
    if entry.get("syncs"):
        bad.append("%s: fail op synced" % tag)
    if entry.get("inner", {}).get("health") != "healthy":
        bad.append("%s: fail op lacks healthy inner verdict"
                   % tag)
    inner_maps = [e for e in lc if e["kind"] == 1
                  and e["size"] == 2048 and e["ok"] == 1]
    if len(inner_maps) != 2:
        bad.append("%s: want fail map + retry map, got %d"
                   % (tag, len(inner_maps)))
    survivors = [e for e in cp if e["kind"] == 2
                 and e["req"] == 2048 and e["known"] == 1
                 and e["eff"] == 2048]
    if len(survivors) != 2:
        bad.append("%s: want fail copy + retry copy, got %d"
                   % (tag, len(survivors)))
    return sorted(bad)


def test_witness_windows(tmp_path):
    require_lifecycle_env(LIFECYCLE_PROBE, COPY_PROBE, CONSUMER)
    ensure_oracle_module()
    with open(SPEC) as handle:
        frozen = json.load(handle)
    assert frozen["frozen_for_module"] == "0.4.0", frozen
    tmp, proc = run_guest("witness")
    try:
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        got = verify_exports(tmp, "witness",
                             ["identity.json", "w-lc.txt",
                              "w-cp.txt", "w-oracle.log",
                              "f-lc.txt", "f-cp.txt",
                              "f-oracle.log"])
        ident = json.loads(got["identity.json"].read_text())
        assert ident["release"] == "7.0.0-34-generic", ident
        bad, w_lc, w_cp, w_ops, w_rel = check_window(
            got, "w", frozen["w"])
        assert not bad, "\n".join(bad)
        print("w: %d lc + %d cp, witnessed=%d, gap=0 ok"
              % (len(w_lc), len(w_cp),
                 frozen["w"]["witnessed_total"]))
        bad, f_lc, f_cp, f_ops, f_rel = check_window(
            got, "f", frozen["f"])
        bad += check_inner_outer(f_ops, f_lc, f_cp, "f")
        assert 2 not in f_rel, "fail op released a mapping"
        assert not bad, "\n".join(bad)
        ledger_f = replay_oracle_witness_ledger(f_ops, f_rel)
        f_entries = ledger_f.entries
        assert [e for e in f_entries
                if e["kind"] == "allocation" and e["op"] == 2] == []
        assert [e for e in f_entries
                if e["kind"] == "copy" and e["op"] == 2] == []
        inner_alloc = [
            e for e in f_entries
            if e["kind"] == "allocation" and e["op"] == "2:inner"]
        assert len(inner_alloc) == 1
        assert inner_alloc[0]["mapped_bytes"] == 2048
        print("f: failed op keeps no allocation/copy;"
              " retry replays as 2:inner")
        print("f: %d lc + %d cp, witnessed=%d, gap=%d ok"
              % (len(f_lc), len(f_cp),
                 frozen["f"]["witnessed_total"],
                 frozen["f"]["unwitnessed_gap"]))
        cap_dir = tmp_path / "cap-report"
        cap_dir.mkdir()
        probe_lifetimes = translate_session(
            w_lc, w_cp, w_ops, str(cap_dir), "witness-w-session",
            "linux-x86_64-7.0.0-34-generic")
        authored = tmp_path / "authored-reducer-fixture"
        author_reducer_fixture(cap_dir, authored)
        rep = subprocess.run(
            [MEMVEIL_BIN, "report", "--format", "json",
             str(authored)],
            capture_output=True, text=True, timeout=300)
        assert rep.returncode == 4, rep.stderr[-1000:]
        report = json.loads(rep.stdout)
        ledger = replay_oracle_witness_ledger(w_ops, w_rel)
        mismatches = compare_live(report, ledger,
                                  probe_lifetimes,
                                  witnessed=True)
        mismatches += check_lifetime_ordering(
            probe_lifetimes, w_rel, "w")
        assert not mismatches, "\n".join(mismatches)
        print("w: report metrics match witnessed executed bytes")
    except Exception:
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp)
