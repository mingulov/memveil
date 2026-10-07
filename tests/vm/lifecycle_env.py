#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared preflight for the lifecycle VM gates.

The gates run only when explicitly armed
(MEMVEIL_VM_LIFECYCLE=1) with qualified lifecycle probes and a
working virtme-ng harness. Anything else skips fast without
booting. An armed gate with missing pieces fails instead of
skipping: explicit arming is a promise the environment is
ready.
"""

import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LIFECYCLE_PROBE = os.path.join(
    REPO, "build", "bpf", "swiotlb_lifecycle.bpf.o")
COPY_PROBE = os.path.join(REPO, "build", "bpf", "swiotlb_copy.bpf.o")
CONSUMER = os.path.join(REPO, "build", "vm", "mv_consume")
BRIDGE = os.path.join(
    REPO, "build", "deps", "lmb", "lib", "libbpf_mojo.so.1")
KERNEL_DIR = os.path.join(REPO, "tests", "kernel")
ORACLE_KO = os.path.join(KERNEL_DIR, "memveil_dma_oracle.ko")
BIN = os.path.join(REPO, "build", "memveil")


def require_lifecycle_env(*probes):
    """Preflight one lifecycle gate. Skips or fails honestly."""
    armed = os.environ.get("MEMVEIL_VM_LIFECYCLE") == "1"
    missing = [p for p in probes if not os.path.isfile(p)]
    if not armed:
        pytest.skip(
            "lifecycle VM gates need MEMVEIL_VM_LIFECYCLE=1 "
            "with qualified probes")
    if missing:
        pytest.fail("armed but missing probes: %s"
                    % ", ".join(missing))
    if not os.path.isfile(BIN):
        pytest.fail("armed but missing build/memveil")
    vng = shutil.which("vng") or os.path.expanduser("~/.venv/vng/bin/vng")
    if not (shutil.which("vng") or os.path.isfile(vng)):
        pytest.fail("armed but vng not available")
    if not shutil.which("qemu-system-x86_64"):
        pytest.fail("armed but qemu-system-x86_64 not available")
    if not os.path.exists("/dev/kvm"):
        pytest.fail("armed but /dev/kvm not available")
    probe = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    if probe.returncode != 0:
        pytest.fail("armed but no passwordless sudo for vng")


def ensure_oracle_module():
    """Build the oracle .ko against the running kernel if missing.

    Armed-only helper: failures fail loudly, never skip.
    """
    if os.path.isfile(ORACLE_KO):
        return
    kdir = "/lib/modules/%s/build" % os.uname().release
    if not os.path.isfile(os.path.join(kdir, "Makefile")):
        pytest.fail("armed but no kernel build tree: %s" % kdir)
    if not shutil.which("make"):
        pytest.fail("armed but make not available")
    build = subprocess.run(["make", "-C", KERNEL_DIR],
                           capture_output=True, text=True)
    if build.returncode != 0 or not os.path.isfile(ORACLE_KO):
        pytest.fail("armed but oracle module build failed: %s"
                    % build.stderr[-2000:])
