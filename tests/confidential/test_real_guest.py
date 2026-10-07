#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Confidential real-guest gate: owned conversion qualification.

Step 1 always runs where the kernel headers exist: build the
test-only region oracle module and check its modinfo, then
clean the tree. Step 2 needs MEMVEIL_CONFIDENTIAL_REAL=1 with
an admitted guest manifest and qualified conversion probes;
unarmed runs exit 77 without touching any guest. Armed runs
fail loudly until the live owned-sequence flow ships with
real guest access: frozen per-capability expectations, the
controlled shared-to-private owned-region sequence, real
scratch I/O, restricted-permission cases, fixture cleanup,
unprivileged replay of the exact capture, and the stop,
quality, and privacy reruns for the new writers.
"""

import os
import shutil
import subprocess
import sys

CONFIDENTIAL = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(CONFIDENTIAL))
KERNEL_DIR = os.path.join(REPO, "tests", "kernel")
CONVERSION_PROBE = os.path.join(REPO, "build", "bpf", "conversion.bpf.o")


def check_oracle_build():
    """Build the region oracle module; clean afterwards."""
    kdir = "/lib/modules/%s/build" % os.uname().release
    if not os.path.isfile(os.path.join(kdir, "Makefile")):
        print("confidential-real: oracle build skipped "
              "(no kernel build tree)")
        return True
    if not shutil.which("make"):
        print("confidential-real: oracle build skipped (no make)")
        return True
    build = subprocess.run(["make", "-C", KERNEL_DIR],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
    if build.returncode != 0:
        print("FAIL confidential-real: oracle module does not build")
        print(build.stdout[-2000:])
        return False
    koji = os.path.join(KERNEL_DIR, "memveil_region_oracle.ko")
    if not os.path.isfile(koji):
        print("FAIL confidential-real: oracle .ko missing after build")
        return False
    info = subprocess.run(["modinfo", koji], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True)
    if "mv_region_oracle_arm" not in info.stdout:
        print("FAIL confidential-real: oracle arm parameter missing")
        return False
    subprocess.run(["make", "-C", KERNEL_DIR, "clean"],
                   stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=False)
    print("confidential-real: oracle module builds "
          "(arm parameter present, tree cleaned)")
    return True


def main():
    if not check_oracle_build():
        return 1
    if os.environ.get("MEMVEIL_CONFIDENTIAL_REAL", "0") != "1":
        print("confidential-real: SKIP: needs "
              "MEMVEIL_CONFIDENTIAL_REAL=1 with an admitted guest")
        return 77
    manifest = os.path.join(CONFIDENTIAL, "guest_manifest.json")
    if not os.path.isfile(manifest):
        print("confidential-real: SKIP: no admitted guest manifest")
        return 77
    if not os.path.isfile(CONVERSION_PROBE):
        print("confidential-real: SKIP: conversion probes not qualified")
        return 77
    print("FAIL confidential-real: armed but the live owned-sequence "
          "flow is not implemented")
    return 1


if __name__ == "__main__":
    sys.exit(main())
