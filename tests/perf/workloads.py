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
runs exit 77 without booting; armed runs fail loudly until
the live workload flow is implemented.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(ROOT)

MODES = ("off", "attached-idle", "summary", "detail", "saturation")
WARMUP_S = 10
WINDOW_S = 60
MIN_PAIRS = 5


def main():
    if os.environ.get("MEMVEIL_VM_PERF", "0") != "1":
        print("perf-workload: SKIP: needs MEMVEIL_VM_PERF=1 "
              "with qualified probes")
        return 77
    probe = os.path.join(REPO, "build", "bpf",
                         "swiotlb_lifecycle.bpf.o")
    if not os.path.isfile(probe):
        print("perf-workload: SKIP: lifecycle probes not qualified")
        return 77
    print("FAIL perf-workload: armed but the live workload flow "
          "is not implemented")
    return 1


if __name__ == "__main__":
    sys.exit(main())
