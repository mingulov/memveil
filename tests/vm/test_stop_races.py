#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Stop-race VM gate: bounded live stress for the stop protocol.

Requires MEMVEIL_VM_STOP=1 with qualified lifecycle probes.
Unarmed runs exit 77 without booting; armed runs boot one
guest and drive five stop-race cycles (STOP/continue both
consumers, SIGTERM victim, quiet window, STOP one consumer,
short window over slow traffic), then check conservation,
exact scripted traffic, honest victim incompleteness, and
quiet-window silence.
"""

import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import (check_conservation, check_oracle_script,
                     compare_scripted, consumed_multisets,
                     parse_consume_file, parse_oracle_log,
                     scripted_expectation)
from vm_boot import cleanup, run_guest, verify_exports


def need(path, what):
    if not os.path.isfile(path):
        print(f"FAIL vm-stop: armed but {what} missing: {path}")
        return False
    return True


def armed_preflight():
    ok = need(os.path.join(REPO, "build", "bpf",
                           "swiotlb_lifecycle.bpf.o"),
              "lifecycle probes")
    ok = need(os.path.join(REPO, "build", "bpf",
                           "swiotlb_copy.bpf.o"),
              "copy probes") and ok
    ok = need(os.path.join(REPO, "build", "vm", "mv_consume"),
              "consumer") and ok
    ko = os.path.join(REPO, "tests", "kernel",
                      "memveil_dma_oracle.ko")
    if not os.path.isfile(ko):
        kdir = "/lib/modules/%s/build" % os.uname().release
        if not os.path.isfile(os.path.join(kdir, "Makefile")):
            print("FAIL vm-stop: armed but no kernel build tree")
            return False
        build = subprocess.run(
            ["make", "-C", os.path.join(REPO, "tests", "kernel")],
            capture_output=True, text=True)
        if build.returncode != 0 or not os.path.isfile(ko):
            print("FAIL vm-stop: armed but module build failed")
            return False
    if not shutil.which("vng"):
        print("FAIL vm-stop: armed but vng not available")
        return False
    if not shutil.which("qemu-system-x86_64"):
        print("FAIL vm-stop: armed but qemu not available")
        return False
    if not os.path.exists("/dev/kvm"):
        print("FAIL vm-stop: armed but /dev/kvm not available")
        return False
    probe = subprocess.run(["sudo", "-n", "true"],
                           capture_output=True)
    if probe.returncode != 0:
        print("FAIL vm-stop: armed but no passwordless sudo")
        return False
    return ok


def check_full_cycle(got, tag):
    """Exact scripted comparison for one undisturbed window."""
    lc, lc_sum = parse_consume_file(str(got["%s-lc.txt" % tag]))
    cp, cp_sum = parse_consume_file(str(got["%s-cp.txt" % tag]))
    bad = check_conservation(lc, lc_sum, tag + "-lc")
    bad += check_conservation(cp, cp_sum, tag + "-cp")
    if lc_sum["cnt_fail"] != 0 or cp_sum["cnt_fail"] != 0:
        bad.append("%s: loss under STOP is unexpected" % tag)
    ops_log, releases, complete = parse_oracle_log(
        str(got["%s-oracle.log" % tag]))
    bad += check_oracle_script(ops_log, releases, complete, 4, -1,
                               tag)
    bad += compare_scripted(lc, cp, 4, -1, tag)
    return bad


def check_quiet_cycle(got, tag):
    """A window with no traffic observes nothing, honestly."""
    lc, lc_sum = parse_consume_file(str(got["%s-lc.txt" % tag]))
    cp, cp_sum = parse_consume_file(str(got["%s-cp.txt" % tag]))
    bad = check_conservation(lc, lc_sum, tag + "-lc")
    bad += check_conservation(cp, cp_sum, tag + "-cp")
    if lc or cp:
        bad.append("%s: quiet window observed %d+%d events"
                   % (tag, len(lc), len(cp)))
    for summary in (lc_sum, cp_sum):
        for key in ("cnt_obs", "cnt_obsb", "cnt_emit",
                    "cnt_emitb", "cnt_fail", "rx", "dlv"):
            if summary[key] != 0:
                bad.append("%s: quiet counter %s=%d"
                           % (tag, key, summary[key]))
    ops_log, releases, complete = parse_oracle_log(
        str(got["%s-oracle.log" % tag]))
    if ops_log or releases or complete is not None:
        bad.append("%s: quiet window has oracle traffic" % tag)
    return bad


def check_short_cycle(got, tag):
    """A window detached before the exit release: the held
    mapping's release triple is absent, everything else exact."""
    lc, lc_sum = parse_consume_file(str(got["%s-lc.txt" % tag]))
    cp, cp_sum = parse_consume_file(str(got["%s-cp.txt" % tag]))
    bad = check_conservation(lc, lc_sum, tag + "-lc")
    bad += check_conservation(cp, cp_sum, tag + "-cp")
    want = scripted_expectation(4, -1)
    want["unmaps"].remove((4096, 2, 1))
    want["syncs_cpu"].remove((4096, 2))
    want["bounces"].remove((0, 4096, 2))
    got_multi = consumed_multisets(lc, cp)
    for key in ("maps", "unmaps", "syncs_dev", "syncs_cpu",
                "bounces"):
        if got_multi[key] != want[key]:
            bad.append("%s: %s differs: got %d want %d"
                       % (tag, key, len(got_multi[key]),
                          len(want[key])))
    maps = [e for e in lc if e["kind"] == 1]
    if len(maps) != 4:
        bad.append("%s: short window missed a map" % tag)
    ops_log, releases, complete = parse_oracle_log(
        str(got["%s-oracle.log" % tag]))
    bad += check_oracle_script(ops_log, releases, complete, 4, -1,
                               tag)
    return bad


def run_flow():
    tmp, proc = run_guest("stop")
    try:
        if proc.returncode != 0:
            print("FAIL vm-stop: guest failed: %s"
                  % proc.stderr[-2000:])
            print(f"gate artifacts kept at {tmp}")
            return 1
        names = ["identity.json"]
        for cycle in range(5):
            tag = "c%d" % cycle
            names += ["%s-lc.txt" % tag, "%s-cp.txt" % tag,
                      "%s-oracle.log" % tag]
        names.append("ledger.json")
        cp_victim = tmp / "export" / "stop-c1-cp.txt"
        if not cp_victim.is_file():
            names.remove("c1-cp.txt")
        got = verify_exports(tmp, "stop", names)
        ledger = json.loads(got["ledger.json"].read_text())
        bad = []
        modes = [row["mode"] for row in ledger]
        if modes != ["stop-both", "term-cp", "quiet", "stop-lc",
                     "short"]:
            bad.append("ledger modes %r" % (modes,))
        bad += check_full_cycle(got, "c0")
        bad += check_full_cycle(got, "c3")
        bad += check_quiet_cycle(got, "c2")
        bad += check_short_cycle(got, "c4")
        # Victim cycle: the survivor is exact, the victim died
        # loud with no summary.
        lc, lc_sum = parse_consume_file(str(got["c1-lc.txt"]))
        bad += check_conservation(lc, lc_sum, "c1-lc")
        ops_log, releases, complete = parse_oracle_log(
            str(got["c1-oracle.log"]))
        bad += check_oracle_script(ops_log, releases, complete, 4,
                                   -1, "c1")
        want = scripted_expectation(4, -1)
        got_lc = consumed_multisets(lc, []) 
        if got_lc["maps"] != want["maps"]:
            bad.append("c1: survivor maps differ")
        if got_lc["unmaps"] != want["unmaps"]:
            bad.append("c1: survivor unmaps differ")
        victim = ledger[1]
        if victim.get("victim_rc", 0) == 0:
            bad.append("c1: victim exited 0")
        if "c1-cp.txt" in got:
            body = got["c1-cp.txt"].read_text()
            if body.startswith("summary ") or "\nsummary " in body:
                bad.append("c1: victim left a summary")
        elif victim.get("victim_file"):
            bad.append("c1: ledger claims a victim file")
        if bad:
            print("FAIL vm-stop:")
            for line in bad:
                print("  " + line)
            print(f"gate artifacts kept at {tmp}")
            return 1
        print("vm-stop: PASS: 5 cycles (stop, victim, quiet, "
              "stop-lc, short) with conservation + exact traffic")
    except Exception as exc:
        print(f"FAIL vm-stop: {exc}")
        print(f"gate artifacts kept at {tmp}")
        return 1
    else:
        cleanup(tmp)
        return 0


def main():
    if os.environ.get("MEMVEIL_VM_STOP", "0") != "1":
        print("vm-stop: SKIP: needs MEMVEIL_VM_STOP=1 "
              "with qualified probes")
        return 77
    if not armed_preflight():
        return 1
    return run_flow()


if __name__ == "__main__":
    sys.exit(main())
