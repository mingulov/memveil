#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cleanup-failure VM gate: live resource-inventory cycles.

Requires MEMVEIL_VM_CLEANUP=1 with qualified probes. Unarmed
runs exit 77 without booting; armed runs fail loudly until
the live cleanup flow (100 owned start/stop/error cycles
against a resource baseline) is implemented.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(ROOT)


def main():
    if os.environ.get("MEMVEIL_VM_CLEANUP", "0") != "1":
        print("vm-cleanup: SKIP: needs MEMVEIL_VM_CLEANUP=1 "
              "with qualified probes")
        return 77
    probe = os.path.join(REPO, "build", "bpf",
                         "swiotlb_lifecycle.bpf.o")
    if not os.path.isfile(probe):
        print("vm-cleanup: SKIP: lifecycle probes not qualified")
        return 77
    print("FAIL vm-cleanup: armed but the live cleanup flow "
          "is not implemented")
    return 1


if __name__ == "__main__":
    sys.exit(main())
