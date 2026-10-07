#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Oracle live gate: module build plus guest comparison.

test_module_builds compiles the test-only oracle module against
the running kernel's build tree and checks its modinfo; it runs
everywhere the headers exist. test_guest_comparison boots the
frozen virtme-ng harness, loads the module, replays its log
into the oracle ledger, and compares against a MemVeil report
with zero tolerated mismatches.

The comparison skips fast (no boot) until the lifecycle BPF
probes it validates against are qualified: without
adapters there is no report to compare, and the skip says so.
"""

import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KERNEL_DIR = os.path.join(REPO, "tests", "kernel")
LIFECYCLE_PROBE = os.path.join(
    REPO, "build", "bpf", "swiotlb_lifecycle.bpf.o")


def test_module_builds():
    kdir = "/lib/modules/%s/build" % os.uname().release
    if not os.path.isfile(os.path.join(kdir, "Makefile")):
        pytest.skip("kernel build tree not available: %s" % kdir)
    make = shutil.which("make")
    if not make:
        pytest.skip("make not available")
    build = subprocess.run(
        [make, "-C", KERNEL_DIR], capture_output=True, text=True)
    assert build.returncode == 0, build.stderr[-2000:]
    ko = os.path.join(KERNEL_DIR, "memveil_dma_oracle.ko")
    assert os.path.isfile(ko)
    info = subprocess.run(["modinfo", ko], capture_output=True,
                          text=True)
    assert info.returncode == 0
    assert "license:        GPL" in info.stdout
    assert "mv_oracle_arm" in info.stdout
    subprocess.run([make, "-C", KERNEL_DIR, "clean"],
                   capture_output=True)


def _require_qualified_probes():
    if not os.path.isfile(LIFECYCLE_PROBE):
        pytest.skip(
            "lifecycle probes not qualified; oracle live "
            "comparison awaits them")


def test_guest_comparison():
    # Boot the frozen harness, insmod the oracle module with
    # mv_oracle_arm=1, replay its mv-oracle: log lines into the
    # oracle ledger, capture with the lifecycle probes over the
    # same window, and compare with zero tolerated mismatches.
    _require_qualified_probes()
    pytest.fail("oracle guest comparison flow not yet implemented")
