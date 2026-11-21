#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Late-attach gate guest flow: a held mapping across attach.

Runs as root inside the virtme-ng guest (one boot, two phases).

Phase A (late attach): the oracle module runs its scripted
traffic BEFORE the consumers attach, so every map, sync, and
unmap completes pre-attach except the script's final held-open
mapping, which the module keeps until unload. The consumers
then attach (the ready acknowledgements prove attachment) and
the module unloads, so the held mapping's release is the only
phase-A traffic the probes can observe. A pre-attach oracle
snapshot proves the maps completed before attachment; the post
snapshot proves the release landed after it.

Phase B (positive control): fresh consumers attach first, then
a full scripted run executes entirely post-attach and must be
observed exactly. The control proves attached observation
works, so phase A's absent pre-attach traffic is a genuine
miss pattern and a missed held release would fail the gate.

Every refusal aborts FAIL (exit 1), never skip. Exports carry
.sha256 sidecars; no DMA addresses ever cross.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guest_lifecycle import CP_SITES, LC_SITES, Gate, fail, mono_ns

SUB = "lateattach"
OPS = 4
HELD_OP = OPS - 1
CONSUMER_SECONDS = 30


def check_pre_attach(pre_path):
    """Guest-side sanity: maps done, held mapping still open."""
    with open(pre_path) as handle:
        body = handle.read()
    if "script complete ops=%d" % OPS not in body:
        fail("lateattach: pre-attach script incomplete")
    if "held-open" not in body:
        fail("lateattach: pre-attach held-open missing")
    if "exit-release" in body:
        fail("lateattach: pre-attach already released")
    if "mapping=%d release" % HELD_OP in body:
        fail("lateattach: held mapping released pre-attach")


def run_phase_a(gate, ledger):
    """Traffic first, attach second, release last."""
    gate.clear_dmesg()
    gate.insmod([])
    mapped_ns = mono_ns()
    pre = gate.oracle_log("a-pre-oracle.log")
    check_pre_attach(pre)
    lc = os.path.join(gate.work, "a-lc.txt")
    cp = os.path.join(gate.work, "a-cp.txt")
    plc = gate.start_consumer(
        gate.lc_obj, "mv_lifecycle", LC_SITES,
        CONSUMER_SECONDS, lc)
    pcp = gate.start_consumer(
        gate.cp_obj, "mv_copies", CP_SITES,
        CONSUMER_SECONDS, cp)
    gate.wait_ready(("mv_map_result", "mv_bounce"))
    attach_ns = mono_ns()
    gate.rmmod()
    released_ns = mono_ns()
    gate.wait_consumer(plc, "lateattach-a-lc")
    gate.wait_consumer(pcp, "lateattach-a-cp")
    gate.oracle_log("a-oracle.log")
    ledger["phase_a"] = {
        "mapped_ns": mapped_ns,
        "attach_ns": attach_ns,
        "released_ns": released_ns,
        "lc_exit": 0,
        "cp_exit": 0,
    }


def run_phase_b(gate, ledger):
    """Positive control: attach first, full traffic after."""
    gate.clear_dmesg()
    lc = os.path.join(gate.work, "b-lc.txt")
    cp = os.path.join(gate.work, "b-cp.txt")
    plc = gate.start_consumer(
        gate.lc_obj, "mv_lifecycle", LC_SITES,
        CONSUMER_SECONDS, lc)
    pcp = gate.start_consumer(
        gate.cp_obj, "mv_copies", CP_SITES,
        CONSUMER_SECONDS, cp)
    gate.wait_ready(("mv_map_result", "mv_bounce"))
    attach_ns = mono_ns()
    gate.insmod([])
    mapped_ns = mono_ns()
    time.sleep(2)
    gate.rmmod()
    released_ns = mono_ns()
    gate.wait_consumer(plc, "lateattach-b-lc")
    gate.wait_consumer(pcp, "lateattach-b-cp")
    gate.oracle_log("b-oracle.log")
    ledger["phase_b"] = {
        "attach_ns": attach_ns,
        "mapped_ns": mapped_ns,
        "released_ns": released_ns,
        "lc_exit": 0,
        "cp_exit": 0,
    }


def main(argv):
    if len(argv) != 5 or argv[1] != SUB:
        print("usage: late_attach_guest.py lateattach "
              "work export repo",
              file=sys.stderr)
        return 2
    gate = Gate(argv[1], argv[2], argv[3], argv[4])
    gate.write_json("identity.json", gate.identity())
    ledger = {"ops": OPS, "held_op": HELD_OP}
    run_phase_a(gate, ledger)
    run_phase_b(gate, ledger)
    gate.write_json("attach.json", ledger)
    gate.export(["identity.json", "a-pre-oracle.log",
                 "a-lc.txt", "a-cp.txt", "a-oracle.log",
                 "b-lc.txt", "b-cp.txt", "b-oracle.log",
                 "attach.json"])
    print("late_attach_guest: lateattach exported")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
