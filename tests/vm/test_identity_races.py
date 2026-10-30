#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Identity-race VM gate: pairing honesty under concurrent reuse.

Phase 1 runs scripted oracle ops alone (exact expectations,
same runner as the flood). Phase 2 overlaps paced oracle ops
with one direct-read dd leg per vCPU on an owned scsi_debug
disk while bpftrace counts the attach points and block stats
prove the load flowed.

Exit criteria (Q25-C6): no fabricated pairing (identity
closure is exact), the emitted-plus-loss identity holds on
both rings, probe counts agree with bpftrace within quiet-
guest slack, and the miss fraction stays under a
total-breakage ceiling. The pre/post fix miss comparison is
a receipt procedure, not an assertion: run this gate on the
pre-fix objects, record the retained miss counts, and bound
the post-fix run against them. A miss-rate regression fails
the task even when this gate is green.

Requires MEMVEIL_VM_LIFECYCLE=1 with qualified probes (see
tools/vm-lifecycle); unarmed runs skip without booting.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import (check_conservation, check_identity_closure,
                     check_oracle_script, compare_scripted,
                     parse_consume_file, parse_oracle_log)
from evidence_retention import (expected_from_verified,
                                retain_failure)
import gate_kernel  # noqa: E402
from lifecycle_env import (CONSUMER, COPY_PROBE, LIFECYCLE_PROBE,
                           ensure_oracle_module, require_lifecycle_env)
from vm_boot import cleanup, run_guest, verify_exports

P1_OPS = 200
P2_OPS = 2000
# Quiet-guest slack for stray DMA in the attach margins.
# Both oracles count the same firings; the margins hold no
# scripted traffic, so systematic divergence dwarfs this.
COUNT_SLACK = 64
# Total-breakage ceiling only: pre-change code also degrades
# to misses under races, so the ceiling trips solely when
# pairing collapses wholesale. The real bound is the
# pre-change baseline comparison in the receipt.
MISS_CEILING = 0.5


def miss_fraction(lc_events):
    if not lc_events:
        return 0.0
    missed = sum(1 for e in lc_events if e["gen"] == 0)
    return missed / len(lc_events)


def parse_bpftrace(text):
    out = {}
    for name in ("maps", "unmaps", "bounces"):
        m = re.search(r"@%s:\s+(\d+)" % name, text)
        if not m:
            raise ValueError("bpftrace count %r missing" % name)
        out[name] = int(m.group(1))
    return out


def check_phase1(got):
    tag = "races-p1"
    lc, lc_sum = parse_consume_file(str(got["p1-lc.txt"]))
    cp, cp_sum = parse_consume_file(str(got["p1-cp.txt"]))
    bad = check_conservation(lc, lc_sum, tag + "-lc")
    bad += check_conservation(cp, cp_sum, tag + "-cp")
    bad += check_identity_closure(lc, tag + "-lc")
    ops_log, releases, complete = parse_oracle_log(
        str(got["p1-oracle.log"]))
    bad += check_oracle_script(ops_log, releases, complete,
                               P1_OPS, -1, tag)
    bad += compare_scripted(lc, cp, P1_OPS, -1, tag)
    assert not bad, "\n".join(bad)
    print("%s: scripted %d ops exact" % (tag, P1_OPS))


def check_phase2(got):
    tag = "races-p2"
    lc, lc_sum = parse_consume_file(str(got["p2-lc.txt"]))
    cp, cp_sum = parse_consume_file(str(got["p2-cp.txt"]))
    bad = check_conservation(lc, lc_sum, tag + "-lc")
    bad += check_conservation(cp, cp_sum, tag + "-cp")
    bad += check_identity_closure(lc, tag + "-lc")
    bpf = parse_bpftrace(got["bpftrace.txt"].read_text())
    stats = json.loads(got["blockstats.json"].read_text())
    if stats["after"]["read_ios"] <= stats["before"]["read_ios"]:
        bad.append("%s: flood produced no block reads" % tag)
    lc_firings = bpf["maps"] + bpf["unmaps"]
    if abs(lc_sum["cnt_obs"] - lc_firings) > COUNT_SLACK:
        bad.append("%s: probe observed %d vs bpftrace %d "
                   "(maps %d + unmaps %d)" % (
                       tag, lc_sum["cnt_obs"], lc_firings,
                       bpf["maps"], bpf["unmaps"]))
    kind2 = sum(1 for e in cp if e["kind"] == 2)
    if kind2 > bpf["bounces"] + COUNT_SLACK:
        bad.append("%s: %d copy records vs %d bounce calls "
                   "(double-record?)" % (tag, kind2,
                                         bpf["bounces"]))
    if bpf["bounces"] > kind2 + cp_sum["cnt_fail"] + COUNT_SLACK:
        bad.append("%s: %d bounce calls vs %d records + %d "
                   "fail (silent drop?)" % (
                       tag, bpf["bounces"], kind2,
                       cp_sum["cnt_fail"]))
    miss = miss_fraction(lc)
    print("%s: lc=%d cp=%d miss=%.4f bpftrace=%r "
          "block_reads=+%d" % (
              tag, len(lc), len(cp), miss, bpf,
              stats["after"]["read_ios"] -
              stats["before"]["read_ios"]))
    if miss > MISS_CEILING:
        bad.append("%s: miss fraction %.4f over ceiling %.2f"
                   % (tag, miss, MISS_CEILING))
    assert not bad, "\n".join(bad)


def test_identity_races():
    require_lifecycle_env(LIFECYCLE_PROBE, COPY_PROBE, CONSUMER)
    ensure_oracle_module()
    tmp = None
    try:
        tmp, proc = run_guest("races")
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        names = ["identity.json", "p1-lc.txt", "p1-cp.txt",
                 "p1-oracle.log", "p2-lc.txt", "p2-cp.txt",
                 "p2-oracle.log", "bpftrace.txt",
                 "bpftrace.stderr", "dd.json",
                 "blockstats.json"]
        got = verify_exports(tmp, "races", names)
        expected = expected_from_verified(got, "races")
        ident = json.loads(got["identity.json"].read_text())
        assert ident["release"] == gate_kernel.selected().release, \
            ident
        check_phase1(got)
        check_phase2(got)
    except Exception:
        retain_failure(tmp, "races")
        print("gate artifacts kept at %s" % tmp)
        raise
    else:
        cleanup(tmp, "races", expected=expected)
