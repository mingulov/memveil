#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Stop-race VM gate: bounded live stress for the stop protocol.

Requires MEMVEIL_VM_STOP=1 with qualified lifecycle probes.
Unarmed runs exit 77 without booting; armed runs fail loudly
until the live stop-race flow is implemented.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(ROOT)


def main():
    if os.environ.get("MEMVEIL_VM_STOP", "0") != "1":
        print("vm-stop: SKIP: needs MEMVEIL_VM_STOP=1 "
              "with qualified probes")
        return 77
    probe = os.path.join(REPO, "build", "bpf",
                         "swiotlb_lifecycle.bpf.o")
    if not os.path.isfile(probe):
        print("FAIL vm-stop: armed but lifecycle probes not qualified")
        return 1
    print("FAIL vm-stop: armed but the live stop-race flow "
          "is not implemented")
    return 1


if __name__ == "__main__":
    sys.exit(main())
