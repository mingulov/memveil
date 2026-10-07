#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Saturation VM gate: live ring/staging exhaustion behavior.

Requires MEMVEIL_VM_SATURATION=1 with qualified probes.
Unarmed runs exit 77 without booting; armed runs boot one
guest, flood 300 scripted ops through 4 KiB ring variants
while the consumers are SIGSTOP'd, then check exact loss
accounting: observed equals emitted plus submit failures at
every boundary, persisted lines equal emitted, and the
BPF-observed totals match the module ground truth exactly.
"""

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import (check_conservation, check_oracle_script,
                     parse_consume_file, parse_oracle_log,
                     scripted_expectation)
from vm_boot import cleanup, run_guest, verify_exports

FLOOD_OPS = 300


def need(path, what):
    if not os.path.isfile(path):
        print(f"FAIL vm-saturation: armed but {what} missing")
        return False
    return True


def armed_preflight():
    ok = need(os.path.join(REPO, "build", "bpf",
                           "swiotlb_lifecycle-test.bpf.o"),
              "saturation lifecycle object")
    ok = need(os.path.join(REPO, "build", "bpf",
                           "swiotlb_copy-test.bpf.o"),
              "saturation copy object") and ok
    ok = need(os.path.join(REPO, "build", "vm", "mv_consume"),
              "consumer") and ok
    ko = os.path.join(REPO, "tests", "kernel",
                      "memveil_dma_oracle.ko")
    if not os.path.isfile(ko):
        kdir = "/lib/modules/%s/build" % os.uname().release
        if not os.path.isfile(os.path.join(kdir, "Makefile")):
            print("FAIL vm-saturation: armed but no kernel tree")
            return False
        build = subprocess.run(
            ["make", "-C", os.path.join(REPO, "tests", "kernel")],
            capture_output=True, text=True)
        if build.returncode != 0 or not os.path.isfile(ko):
            print("FAIL vm-saturation: armed but module failed")
            return False
    if not shutil.which("vng"):
        print("FAIL vm-saturation: armed but vng not available")
        return False
    if not shutil.which("qemu-system-x86_64"):
        print("FAIL vm-saturation: armed but qemu not available")
        return False
    if not os.path.exists("/dev/kvm"):
        print("FAIL vm-saturation: armed but /dev/kvm missing")
        return False
    probe = subprocess.run(["sudo", "-n", "true"],
                           capture_output=True)
    if probe.returncode != 0:
        print("FAIL vm-saturation: armed but no passwordless sudo")
        return False
    return ok


def run_flow():
    tmp, proc = run_guest("saturation")
    try:
        if proc.returncode != 0:
            print("FAIL vm-saturation: guest failed: %s"
                  % proc.stderr[-2000:])
            print(f"gate artifacts kept at {tmp}")
            return 1
        got = verify_exports(tmp, "saturation",
                             ["identity.json", "flood-lc.txt",
                              "flood-cp.txt", "flood-oracle.log"])
        lc, lc_sum = parse_consume_file(str(got["flood-lc.txt"]))
        cp, cp_sum = parse_consume_file(str(got["flood-cp.txt"]))
        bad = check_conservation(lc, lc_sum, "flood-lc")
        bad += check_conservation(cp, cp_sum, "flood-cp")
        if lc_sum["cnt_fail"] == 0 or cp_sum["cnt_fail"] == 0:
            bad.append("no loss induced: lc_fail=%d cp_fail=%d"
                       % (lc_sum["cnt_fail"], cp_sum["cnt_fail"]))
        ops_log, releases, complete = parse_oracle_log(
            str(got["flood-oracle.log"]))
        bad += check_oracle_script(ops_log, releases, complete,
                                   FLOOD_OPS, -1, "flood")
        want = scripted_expectation(FLOOD_OPS, -1)
        want_lc = len(want["maps"]) + len(want["unmaps"])
        want_cp = (len(want["syncs_dev"]) + len(want["syncs_cpu"])
                   + len(want["bounces"]))
        if lc_sum["cnt_obs"] != want_lc:
            bad.append("lc observed %d != module %d"
                       % (lc_sum["cnt_obs"], want_lc))
        if cp_sum["cnt_obs"] != want_cp:
            bad.append("cp observed %d != module %d"
                       % (cp_sum["cnt_obs"], want_cp))
        want_lc_bytes = (sum(s for s, _, _ in want["maps"])
                         + sum(s for s, _, _ in want["unmaps"]))
        want_cp_bytes = (sum(s for s, _ in want["syncs_dev"])
                         + sum(s for s, _ in want["syncs_cpu"])
                         + sum(s for _, s, _ in want["bounces"]))
        if lc_sum["cnt_obsb"] != want_lc_bytes:
            bad.append("lc observed bytes %d != module %d"
                       % (lc_sum["cnt_obsb"], want_lc_bytes))
        if cp_sum["cnt_obsb"] != want_cp_bytes:
            bad.append("cp observed bytes %d != module %d"
                       % (cp_sum["cnt_obsb"], want_cp_bytes))
        if len(lc) != lc_sum["cnt_emit"]:
            bad.append("lc persisted %d != emitted %d"
                       % (len(lc), lc_sum["cnt_emit"]))
        if len(cp) != cp_sum["cnt_emit"]:
            bad.append("cp persisted %d != emitted %d"
                       % (len(cp), cp_sum["cnt_emit"]))
        if bad:
            print("FAIL vm-saturation:")
            for line in bad:
                print("  " + line)
            print(f"gate artifacts kept at {tmp}")
            return 1
        print("vm-saturation: PASS: lc obs=%d emit=%d fail=%d, "
              "cp obs=%d emit=%d fail=%d, exact vs %d ops"
              % (lc_sum["cnt_obs"], lc_sum["cnt_emit"],
                 lc_sum["cnt_fail"], cp_sum["cnt_obs"],
                 cp_sum["cnt_emit"], cp_sum["cnt_fail"],
                 FLOOD_OPS))
    except Exception as exc:
        print(f"FAIL vm-saturation: {exc}")
        print(f"gate artifacts kept at {tmp}")
        return 1
    else:
        cleanup(tmp)
        return 0


def main():
    if os.environ.get("MEMVEIL_VM_SATURATION", "0") != "1":
        print("vm-saturation: SKIP: needs MEMVEIL_VM_SATURATION=1 "
              "with qualified probes")
        return 77
    if not armed_preflight():
        return 1
    return run_flow()


if __name__ == "__main__":
    sys.exit(main())
