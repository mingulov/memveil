#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Confidential late-attach gate: baseline-vs-new separation.

Offline-only reduction semantics already run offline (see the
late-attach and baseline fixtures in the reports lane). This
gate covers the live scenario on an admitted guest: attach
after conversions happened, and prove the capture separates
already-shared pool baseline from new conversions, allocation
release from reprivatization, and known observed subsets from
guest-wide totals.

Requires MEMVEIL_CONFIDENTIAL_LATE_ATTACH=1 with an admitted
guest manifest and qualified conversion probes. Unarmed runs
exit 77 without touching any guest; armed runs fail loudly
until the live late-attach flow ships with real guest access.
"""

import os
import sys

CONFIDENTIAL = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(CONFIDENTIAL))
CONVERSION_PROBE = os.path.join(REPO, "build", "bpf", "conversion.bpf.o")


def main():
    if os.environ.get("MEMVEIL_CONFIDENTIAL_LATE_ATTACH", "0") != "1":
        print("confidential-late-attach: SKIP: needs "
              "MEMVEIL_CONFIDENTIAL_LATE_ATTACH=1 with an admitted guest")
        return 77
    manifest = os.path.join(CONFIDENTIAL, "guest_manifest.json")
    if not os.path.isfile(manifest):
        print("confidential-late-attach: SKIP: no admitted guest manifest")
        return 77
    if not os.path.isfile(CONVERSION_PROBE):
        print("confidential-late-attach: SKIP: conversion probes "
              "not qualified")
        return 77
    print("FAIL confidential-late-attach: armed but the live "
          "late-attach flow is not implemented")
    return 1


if __name__ == "__main__":
    sys.exit(main())
