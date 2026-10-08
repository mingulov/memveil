#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cleanup-failure VM gate: live resource-inventory cycles.

Requires MEMVEIL_VM_CLEANUP=1 with qualified probes. Unarmed
runs exit 77 without booting; armed runs boot one guest and
drive 100 owned start/stop/error cycles (consumer windows
with traffic every fifth cycle plus rotating error cases)
against a resource baseline, then check the per-cycle ledger
and the before/after inventory equality.
"""

import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vm_boot import cleanup, run_guest, verify_exports

CYCLES = 100


def need(path, what):
    if not os.path.isfile(path):
        print(f"FAIL vm-cleanup: armed but {what} missing")
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
    if not shutil.which("vng"):
        print("FAIL vm-cleanup: armed but vng not available")
        return False
    if not shutil.which("qemu-system-x86_64"):
        print("FAIL vm-cleanup: armed but qemu not available")
        return False
    if not os.path.exists("/dev/kvm"):
        print("FAIL vm-cleanup: armed but /dev/kvm missing")
        return False
    probe = subprocess.run(["sudo", "-n", "true"],
                           capture_output=True)
    if probe.returncode != 0:
        print("FAIL vm-cleanup: armed but no passwordless sudo")
        return False
    return ok


def run_flow():
    tmp, proc = run_guest("cleanup", timeout=1200)
    try:
        if proc.returncode != 0:
            print("FAIL vm-cleanup: guest failed: %s"
                  % proc.stderr[-2000:])
            print(f"gate artifacts kept at {tmp}")
            return 1
        got = verify_exports(tmp, "cleanup",
                             ["identity.json", "ledger.json",
                              "inventory.json"])
        ledger = json.loads(got["ledger.json"].read_text())
        inventory = json.loads(got["inventory.json"].read_text())
        bad = []
        if len(ledger) != CYCLES:
            bad.append("ledger has %d rows, want %d"
                       % (len(ledger), CYCLES))
        for row in ledger:
            cycle = row["cycle"]
            if row.get("traffic") != (cycle % 5 == 0):
                bad.append("cycle %d traffic %r" % (cycle, row))
            from consume import check_conservation
            for ring in ("lc", "cp"):
                health = row.get("health", {}).get(ring)
                if health is None or any(health[k] for k in ("badframe", "badrec", "cnt_fail", "cnt_flags", "mal", "drop")):
                    bad.append("cycle %d missing/bad %s health" % (cycle, ring))
            error = row.get("error", {})
            want_case = {1: "insmod-unarmed", 3: "bad-object",
                         5: "bad-ring"}.get(cycle % 7, "none")
            if error.get("case") != want_case:
                bad.append("cycle %d error case %r want %r"
                           % (cycle, error.get("case"), want_case))
            elif want_case == "none":
                if error.get("rc") != 0:
                    bad.append("cycle %d clean rc %r"
                               % (cycle, error.get("rc")))
            elif error.get("rc", 0) == 0:
                bad.append("cycle %d %s exited 0"
                           % (cycle, want_case))
        baseline = inventory["baseline"]
        after = inventory["after"]
        if after["bpf"] != baseline["bpf"]:
            bad.append("BPF inventory moved: %r -> %r"
                       % (baseline["bpf"], after["bpf"]))
        if min(after["io_tlb_used"]) != min(baseline["io_tlb_used"]):
            bad.append("io_tlb floor moved: %r -> %r"
                       % (baseline["io_tlb_used"],
                          after["io_tlb_used"]))
        # The guest samples `after` before writing the
        # ledger/inventory, so equality proves no leftovers.
        if after["files"] != baseline["files"]:
            bad.append("work files moved: %r -> %r"
                       % (baseline["files"], after["files"]))
        if inventory["suspicious"]:
            bad.append("suspicious dmesg: %r"
                       % (inventory["suspicious"],))
        if bad:
            print("FAIL vm-cleanup:")
            for line in bad:
                print("  " + line)
            print(f"gate artifacts kept at {tmp}")
            return 1
        print("vm-cleanup: PASS: %d cycles, BPF %r, floor %d, "
              "no leaks" % (CYCLES, after["bpf"],
                            min(after["io_tlb_used"])))
    except Exception as exc:
        print(f"FAIL vm-cleanup: {exc}")
        print(f"gate artifacts kept at {tmp}")
        return 1
    else:
        cleanup(tmp)
        return 0


def main():
    if os.environ.get("MEMVEIL_VM_CLEANUP", "0") != "1":
        print("vm-cleanup: SKIP: needs MEMVEIL_VM_CLEANUP=1 "
              "with qualified probes")
        return 77
    if not armed_preflight():
        return 1
    return run_flow()


if __name__ == "__main__":
    sys.exit(main())
