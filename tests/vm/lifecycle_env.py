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
import hashlib
import json
import tempfile
from pathlib import Path

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LIFECYCLE_PROBE = os.path.join(
    REPO, "build", "bpf", "swiotlb_lifecycle.bpf.o")
COPY_PROBE = os.path.join(REPO, "build", "bpf", "swiotlb_copy.bpf.o")
CONSUMER = os.path.join(REPO, "build", "vm", "mv_consume")
BRIDGE = os.path.join(
    REPO, "build", "deps", "lmb", "lib", "libbpf_mojo.so.1")
KERNEL_DIR = os.path.join(REPO, "tests", "kernel")
ORACLE_KO = os.path.join(REPO, "build", "vm", "oracle", "memveil_dma_oracle.ko")
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


def module_build_identity():
    """Identify owned source and exact running-kernel build inputs."""
    def sha(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    release = os.uname().release
    kdir = Path("/lib/modules") / release / "build"
    return dict(release=release,
                source_sha=sha(Path(KERNEL_DIR)/"memveil_dma_oracle.c"),
                make_sha=sha(Path(KERNEL_DIR)/"Makefile"),
                config_sha=sha(kdir/".config"),
                kernel_sha=sha(Path("/boot")/("vmlinuz-"+release)),
                btf_sha=sha("/sys/kernel/btf/vmlinux"))


def ensure_oracle_module():
    """Reuse only a hash-verified module built from this source/kernel.

    Build in an owned temporary directory, so other fixture module inputs
    and source-tree outputs are not overwritten between lanes.
    """
    kdir = "/lib/modules/%s/build" % os.uname().release
    if not os.path.isfile(os.path.join(kdir, "Makefile")):
        pytest.fail("armed but no kernel build tree: %s" % kdir)
    if not shutil.which("make"):
        pytest.fail("armed but make not available")
    identity = module_build_identity()
    module = Path(ORACLE_KO)
    manifest = module.with_suffix(".build.json")
    if module.is_file() and manifest.is_file():
        receipt = json.loads(manifest.read_text())
        if receipt.get("inputs") == identity and receipt.get("module_sha") == hashlib.sha256(module.read_bytes()).hexdigest():
            return
    module.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="oracle-build-", dir=module.parent) as tmp:
        for name in ("Makefile", "memveil_dma_oracle.c", "memveil_region_oracle.c"):
            shutil.copyfile(Path(KERNEL_DIR)/name, Path(tmp)/name)
        build = subprocess.run(["make", "-C", tmp, "KDIR="+kdir],
                               capture_output=True, text=True, timeout=120)
        made = Path(tmp)/module.name
        if build.returncode != 0 or not made.is_file():
            pytest.fail("armed but oracle module build failed: %s" % build.stderr[-2000:])
        info = subprocess.run(["modinfo", "-F", "vermagic", str(made)],
                              capture_output=True, text=True, timeout=10)
        if info.returncode or info.stdout.split()[0] != identity["release"]:
            pytest.fail("oracle module vermagic mismatch")
        # Recheck source/kernel inputs after the build before accepting bytes.
        if module_build_identity() != identity:
            pytest.fail("oracle build inputs changed during compilation")
        shutil.copyfile(made, module)
        manifest.write_text(json.dumps(dict(inputs=identity,
            module_sha=hashlib.sha256(module.read_bytes()).hexdigest()),sort_keys=True)+"\n")
