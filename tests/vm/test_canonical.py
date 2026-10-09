#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fixed canonical lifecycle/copy windows in the VM.

Five single-purpose windows (oracle 0.4.0 scenarios 1..5):
nested overlapping mappings, a request-only cpu sync, a
clamped over-sync, a sync after unmap (early return), and
sequential reuse. Every executed-copy claim carries a
bounce-slot readback witness; entry arguments alone never
count. All windows compare against the frozen spec in
tests/vm/fixtures/canonical-expectations.json, written
before the first canonical boot. A laboratory translator
result here validates the oracle machinery; it is not
shipping qualification.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import (check_conservation, check_oracle_witness,
                     compare_multisets, parse_consume_file,
                     parse_oracle_log,
                     replay_oracle_witness_ledger)
from lifecycle_env import (CONSUMER, COPY_PROBE, LIFECYCLE_PROBE,
                           ensure_oracle_module,
                           require_lifecycle_env)
from vm_boot import cleanup, run_guest, verify_exports

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SPEC = os.path.join(REPO, "tests", "vm", "fixtures",
                    "canonical-expectations.json")


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


def check_canonical_flags(lc, cp, tag, clamped=None, early=False):
    """Flag/executed-byte rules with clamp/early exceptions.

    Every map ok, every unmap skip-marked, every sync
    request-only, every generation assigned (no quiet-window
    miss may hide here). Copies are exact except the one
    clamped copy (clamped, eff < req) in window c and the
    one early copy (ezero, eff 0) in window e.
    """
    bad = []
    for e in lc:
        if e["gen"] == 0:
            bad.append("%s: lc seq=%d unassigned generation"
                       % (tag, e["seq"]))
        if e["kind"] == 1 and (e["ok"], e["skip"]) != (1, 0):
            bad.append("%s: map flags %r" % (tag, e))
        if e["kind"] == 2 and (e["ok"], e["skip"]) != (1, 1):
            bad.append("%s: unmap flags %r" % (tag, e))
    seen_clamped = 0
    seen_early = 0
    for e in cp:
        if e["kind"] == 1:
            if (e["known"], e["reason"], e["eff"]) != (0, 4, 0):
                bad.append("%s: sync carries bytes %r" % (tag, e))
            if (e["clamp"], e["ezero"]) != (0, 0):
                bad.append("%s: sync flags %r" % (tag, e))
        elif e["kind"] == 2:
            if (e["known"], e["reason"]) != (1, 0):
                bad.append("%s: copy unknown %r" % (tag, e))
            if e["todev"] != int(e["dir"] == 1):
                bad.append("%s: copy dir/todev %r" % (tag, e))
            if (clamped is not None and e["req"] == clamped[0]
                    and e["clamp"] == 1 and e["eff"] == clamped[1]
                    and e["ezero"] == 0):
                seen_clamped += 1
            elif (early and e["eff"] == 0 and e["ezero"] == 1
                    and e["clamp"] == 0):
                seen_early += 1
            elif (e["clamp"], e["ezero"]) != (0, 0):
                bad.append("%s: copy flags %r" % (tag, e))
            elif e["eff"] != e["req"]:
                bad.append("%s: copy eff %r" % (tag, e))
    if clamped is not None and seen_clamped != 1:
        bad.append("%s: want 1 clamped copy, got %d"
                   % (tag, seen_clamped))
    if early and seen_early != 1:
        bad.append("%s: want 1 early copy, got %d"
                   % (tag, seen_early))
    return sorted(bad)


def check_window(got, tag, spec, clamped=None, early=False):
    lc, lc_sum = parse_consume_file(str(got["%s-lc.txt" % tag]))
    cp, cp_sum = parse_consume_file(str(got["%s-cp.txt" % tag]))
    bad = check_conservation(lc, lc_sum, tag + "-lc")
    bad += check_conservation(cp, cp_sum, tag + "-cp")
    ops_log, releases, complete = parse_oracle_log(
        str(got["%s-oracle.log" % tag]))
    bad += check_oracle_witness(ops_log, releases, complete,
                                spec, tag)
    bad += compare_multisets(lc, cp, _spec_multisets(spec), tag)
    bad += check_canonical_flags(lc, cp, tag, clamped, early)
    todev, tocpu = _probe_eff(cp)
    want = spec["witnessed"]
    if todev != want["original_to_bounce"]:
        bad.append("%s: probe to-device eff %d != witnessed %d"
                   % (tag, todev, want["original_to_bounce"]))
    if tocpu != want["bounce_to_original"]:
        bad.append("%s: probe to-cpu eff %d != witnessed %d"
                   % (tag, tocpu, want["bounce_to_original"]))
    if todev + tocpu != spec["witnessed_total"]:
        bad.append("%s: probe eff total %d != witnessed %d"
                   % (tag, todev + tocpu,
                      spec["witnessed_total"]))
    return bad, lc, cp, ops_log, releases


def check_clamp_extras(ops_log, tag):
    bad = []
    found = [w for w in ops_log[0].get("witness", [])
             if w["copy"] == "clamped"]
    if len(found) != 1:
        return ["%s: want 1 clamped witness, got %d"
                % (tag, len(found))]
    w = found[0]
    if (w["copied"], w["verified"], w.get("pre"),
            w.get("post")) != (4096, 1024, 1024, 1024):
        bad.append("%s: clamped witness %r" % (tag, w))
    return bad


def check_early_extras(ops_log, tag):
    bad = []
    found = [w for w in ops_log[0].get("witness", [])
             if w["copy"] == "early"]
    if len(found) != 1:
        return ["%s: want 1 early witness, got %d"
                % (tag, len(found))]
    w = found[0]
    if (w["copied"], w["verified"], w.get("stale")) != (
            2048, 0, 2048):
        bad.append("%s: early witness %r" % (tag, w))
    return bad


def check_reuse_gens(lc, tag):
    """Sequential reuse must not conflate mapping identity.

    Address-blind: the two maps carry distinct nonzero
    generations and each unmap carries its own map's
    generation. Slot reuse is likely but never asserted.
    """
    bad = []
    maps = [e for e in lc if e["kind"] == 1]
    unmaps = [e for e in lc if e["kind"] == 2]
    if len(maps) != 2 or len(unmaps) != 2:
        return ["%s: want 2 maps + 2 unmaps" % tag]
    gens = [e["gen"] for e in maps]
    if gens[0] == 0 or gens[1] == 0:
        bad.append("%s: reuse map unassigned" % tag)
    if gens[0] == gens[1]:
        bad.append("%s: reuse maps share gen %d" % (tag, gens[0]))
    if unmaps[0]["gen"] != gens[0]:
        bad.append("%s: first unmap gen %d != map gen %d"
                   % (tag, unmaps[0]["gen"], gens[0]))
    if unmaps[1]["gen"] != gens[1]:
        bad.append("%s: second unmap gen %d != map gen %d"
                   % (tag, unmaps[1]["gen"], gens[1]))
    return bad


def test_canonical_windows():
    require_lifecycle_env(LIFECYCLE_PROBE, COPY_PROBE, CONSUMER)
    ensure_oracle_module()
    with open(SPEC) as handle:
        frozen = json.load(handle)
    assert frozen["frozen_for_module"] == "0.4.0", frozen
    tmp, proc = run_guest("canonical")
    try:
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        names = ["identity.json"]
        for tag in ("n", "s", "c", "e", "r"):
            names += ["%s-lc.txt" % tag, "%s-cp.txt" % tag,
                      "%s-oracle.log" % tag]
        got = verify_exports(tmp, "canonical", names)
        ident = json.loads(got["identity.json"].read_text())
        assert ident["release"] == "7.0.0-34-generic", ident
        bad, _, _, _, _ = check_window(got, "n", frozen["n"])
        assert not bad, "\n".join(bad)
        print("n: nested 4096+1024 -> 5120 ok")
        bad, _, _, _, _ = check_window(got, "s", frozen["s"])
        assert not bad, "\n".join(bad)
        print("s: request-only sync invents nothing ok")
        bad, _, _, c_ops, _ = check_window(
            got, "c", frozen["c"], clamped=(4096, 1024))
        bad += check_clamp_extras(c_ops, "c")
        assert not bad, "\n".join(bad)
        print("c: clamped 4096->1024 ok")
        bad, _, _, e_ops, _ = check_window(
            got, "e", frozen["e"], early=True)
        bad += check_early_extras(e_ops, "e")
        assert not bad, "\n".join(bad)
        print("e: early return ->0 ok")
        bad, r_lc, _, _, _ = check_window(got, "r", frozen["r"])
        bad += check_reuse_gens(r_lc, "r")
        assert not bad, "\n".join(bad)
        print("r: reuse generations distinct ok")
    except Exception:
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp)
