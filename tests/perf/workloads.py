#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Frozen live-workload protocol (recipes only until armed).

Default protocol per supported workload: 10 s warmup, 60 s
measured window, at least five interleaved baseline/observer
pairs per mode (off, attached-idle, 1 s summary, detailed
record, saturation) on scratch block and virtual network
paths already proved to reach the admitted hooks. Thresholds
freeze before measurement: summary mode targets <= 5%
throughput decrease and <= 10% p99 increase.

Requires MEMVEIL_VM_PERF=1 with qualified probes. Unarmed
runs exit 77 without booting; armed runs boot one guest and
run six interleaved off/observed pairs (validate-first may
exclude one) over pcnet ping and scsi_debug dd, then compare
with the frozen paired math. The gate passes on qualified
measurements; a ratio outside the frozen targets is a
declared LIMITATION, never a silent pass or a fudged number.

Scope note: off vs attached-and-consuming are the only two
observer states a gate consumer can take; summary/detail
modes are product-record concepts with no lifecycle
equivalent yet, so no claim about them is earned here.
"""

import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tests", "vm"))
sys.path.insert(0, os.path.join(REPO, "tests", "perf"))

from compare import assess, compare
from export_validation import validate_perf_pairs
from consume import check_conservation, parse_consume_file
from vm_boot import cleanup, run_guest, verify_exports


def need(path, what):
    if not os.path.isfile(path):
        print(f"FAIL perf-workload: armed but {what} missing")
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
        print("FAIL perf-workload: armed but vng not available")
        return False
    if not shutil.which("qemu-system-x86_64"):
        print("FAIL perf-workload: armed but qemu not available")
        return False
    if not os.path.exists("/dev/kvm"):
        print("FAIL perf-workload: armed but /dev/kvm missing")
        return False
    probe = subprocess.run(["sudo", "-n", "true"],
                           capture_output=True)
    if probe.returncode != 0:
        print("FAIL perf-workload: armed but no passwordless sudo")
        return False
    return ok


def leg_runs(leg, pair, mode):
    """Build the ping/dd run dicts for one leg (validity first)."""
    ping = leg["ping"]
    dd = leg["dd"]
    reasons = []
    if ping["tx"] != 1000 or ping["rx"] != 1000:
        reasons.append("ping %r/%r" % (ping["tx"], ping["rx"]))
    if ping["seconds"] is None or ping["seconds"] <= 0:
        reasons.append("ping time %r" % (ping["seconds"],))
    if dd["bytes"] != 32 * 16 * 65536:
        reasons.append("dd bytes %r" % (dd["bytes"],))
    if dd["seconds"] is None or dd["seconds"] <= 0:
        reasons.append("dd time %r" % (dd["seconds"],))
    if any(ping.get(k) != 500 for k in ("sample_tx", "sample_rx", "sample_count")):
        reasons.append("incomplete independently counted latency sample")
    valid = not reasons
    reason = "; ".join(reasons) if reasons else ""
    ping_run = {"valid": valid and ping["p99_ms"] is not None,
                "counts_ok": valid,
                "invalid_reason": reason or "no p99 sample",
                "throughput": (ping["rx"] / ping["seconds"]
                               if valid else None),
                "p99": ping["p99_ms"]}
    dd_run = {"valid": valid, "counts_ok": valid,
              "invalid_reason": reason,
              "throughput": (dd["bytes"] / dd["seconds"]
                             if valid else None),
              "p99": None}
    return ping_run, dd_run


def run_flow():
    tmp, proc = run_guest("perf", timeout=1500, network=True)
    try:
        if proc.returncode != 0:
            print("FAIL perf-workload: guest failed: %s"
                  % proc.stderr[-2000:])
            print(f"gate artifacts kept at {tmp}")
            return 1
        names = ["identity.json", "pairs.json"]
        for pair in range(6):
            names += ["p%d-lc.txt" % pair, "p%d-cp.txt" % pair]
        got = verify_exports(tmp, "perf", names)
        pairs = json.loads(got["pairs.json"].read_text())
        validate_perf_pairs(pairs, expected_count=6)
        windows = {"p%d-%s.txt" % (pair, ring)
                   for pair in range(6) for ring in ("lc", "cp")}
        exported_windows = {name for name in got if name.endswith(("-lc.txt", "-cp.txt"))}
        if exported_windows != windows:
            raise ValueError("missing or unexpected perf probe window")
        if len({got[name].resolve() for name in windows}) != len(windows):
            raise ValueError("reused perf probe window")
        ping_base, ping_obs, dd_base, dd_obs = [], [], [], []
        bad = []
        for legs in pairs:
            off, obs = legs
            assert off["mode"] == "off", legs
            assert obs["mode"] == "observed", legs
            tag = "p%d" % obs["pair"]
            lc, lc_sum = parse_consume_file(str(got[tag + "-lc.txt"]))
            cp, cp_sum = parse_consume_file(str(got[tag + "-cp.txt"]))
            conserved = (check_conservation(lc, lc_sum, tag + "-lc")
                         + check_conservation(cp, cp_sum, tag + "-cp"))
            if lc_sum["cnt_fail"] != 0 or cp_sum["cnt_fail"] != 0:
                conserved.append("%s: loss under load" % tag)
            if obs["end_ns"] >= obs["detach_ns"]:
                conserved.append("%s: workload overflowed window"
                                 % tag)
            if not lc or not cp:
                conserved.append("%s: empty observed window" % tag)
            base_ping, base_dd = leg_runs(off, obs["pair"], "off")
            obs_ping, obs_dd = leg_runs(obs, obs["pair"],
                                        "observed")
            if conserved:
                reason = "; ".join(conserved)
                obs_ping = {"valid": False, "counts_ok": False,
                            "invalid_reason": reason,
                            "throughput": None, "p99": None}
                obs_dd = {"valid": False, "counts_ok": False,
                          "invalid_reason": reason,
                          "throughput": None, "p99": None}
            ping_base.append(base_ping)
            ping_obs.append(obs_ping)
            dd_base.append(base_dd)
            dd_obs.append(obs_dd)
        ping_verdict = compare("ping", ping_base, ping_obs)
        dd_verdict = compare("dd", dd_base, dd_obs, fields=("throughput",))
        for verdict in (ping_verdict, dd_verdict):
            print("perf-workload: %s pairs=%d excluded=%d %s"
                  % (verdict["workload"], verdict["pairs"],
                     len(verdict["excluded"]),
                     verdict.get("fields", {})))
            for line in verdict["excluded"]:
                print("perf-workload: excluded %s" % line)
            if not verdict["qualified"]:
                bad.append("%s: %s" % (verdict["workload"],
                                      verdict.get("reason", "")))
        if bad:
            print("FAIL perf-workload:")
            for line in bad:
                print("  " + line)
            print(f"gate artifacts kept at {tmp}")
            return 1
        limits = []
        for verdict in (ping_verdict, dd_verdict):
            status, note = assess(verdict)
            print("perf-workload: %s target %s: %s"
                  % (verdict["workload"], status, note))
            if status == "UNQUALIFIED":
                bad.append("%s %s: %s" % (verdict["workload"], status, note))
            elif status == "FAIL":
                limits.append("%s %s: %s"
                              % (verdict["workload"], status, note))
        if bad:
            print("FAIL perf-workload:")
            for line in bad:
                print("  " + line)
            print(f"gate artifacts kept at {tmp}")
            return 1
        if limits:
            for line in limits:
                print("perf-workload: LIMITATION: " + line)
        print("perf-workload: PASS: paired laboratory "
              "measurement (off vs observed); full product overhead NOT RUN")
    except Exception as exc:
        print(f"FAIL perf-workload: {exc}")
        print(f"gate artifacts kept at {tmp}")
        return 1
    else:
        cleanup(tmp)
        return 0


def main():
    if os.environ.get("MEMVEIL_VM_PERF", "0") != "1":
        print("perf-workload: SKIP: needs MEMVEIL_VM_PERF=1 "
              "with qualified probes")
        return 77
    probe = os.path.join(REPO, "build", "bpf",
                         "swiotlb_lifecycle.bpf.o")
    if not os.path.isfile(probe):
        print("FAIL perf-workload: armed but lifecycle probes "
              "not qualified")
        return 1
    if not armed_preflight():
        return 1
    return run_flow()


if __name__ == "__main__":
    sys.exit(main())
