#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared preflight for the lifecycle VM gates.

The gates run only when explicitly armed
(MEMVEIL_VM_LIFECYCLE=1) with qualified lifecycle probes and a
working virtme-ng harness. Anything else skips fast without
booting. An armed gate with missing pieces fails instead of
skipping: explicit arming is a promise the environment is
ready.

The oracle module is built for the kernel the guests run.
That is normally the host kernel. When guests boot an older
admitted kernel through the VNG path, MEMVEIL_ORACLE_KVER
names the guest kernel release instead: the release, config,
and image come from that kernel's installed files, and the
BTF expectation comes from the shipped validated profile for
that release. The in-guest drift check then verifies the
live guest BTF against the pin on every run. A release with
no validated shipped profile fails closed. Processes already
running on the target kernel always measure live bytes, so
the guest-side measurement never consults the pin.
"""

import os
import shutil
import subprocess

import pytest
import hashlib
import json
import tempfile
from pathlib import Path

import gate_kernel

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
    prepare_gate_kernel()


def prepare_gate_kernel():
    """Select and live-verify the gate kernel, or fail the gate."""
    try:
        return gate_kernel.prepare()
    except gate_kernel.GateKernelError as exc:
        pytest.fail("armed but %s" % exc)


def profile_btf_pin(note):
    """BTF pin from a narrow identity note, or None when absent."""
    for field in (note or "").split():
        if field.startswith("btf=sha256:"):
            digest = field[len("btf=sha256:"):]
            if len(digest) == 64 and all(
                    c in "0123456789abcdef" for c in digest):
                return digest
            return None
    return None


def sha_file_maybe_sudo(path):
    """Hash a file, escalating to passwordless sudo when unreadable.

    Kernel images are root-readable; the harness already
    requires passwordless sudo for the guest runner, so the
    same grant covers this read. Raises OSError when the file
    cannot be hashed either way.
    """
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        pass
    proc = subprocess.run(["sudo", "-n", "sha256sum", path],
                          capture_output=True, text=True, timeout=30)
    if proc.returncode == 0:
        token = proc.stdout.split()
        if token and len(token[0]) == 64:
            return token[0]
    raise OSError("cannot hash %s directly or via sudo -n" % path)


def validated_btf_pin(release, profiles_dir=None):
    """BTF pin from the validated profile for a release.

    Scans the profiles manifest (the shipped profiles dir
    unless profiles_dir names a test dir) for a validated
    document whose source revision names the release. Fails
    closed when no such document exists or its note
    carries no well-formed pin: a guest kernel without a
    validated pin is not an admitted module target.
    """
    root = Path(profiles_dir) if profiles_dir \
        else Path(REPO) / "profiles"
    manifest = root / "manifest.txt"
    try:
        names = manifest.read_text().split()
    except OSError:
        pytest.fail("armed but profiles manifest unreadable: %s"
                    % manifest)
    for name in names:
        doc_path = root / name
        try:
            doc = json.loads(doc_path.read_text())
        except (OSError, ValueError):
            continue
        if doc.get("status") != "validated":
            continue
        source = doc.get("identity", {}).get("source", {})
        if source.get("revision") != release:
            continue
        pin = profile_btf_pin(source.get("note", ""))
        if pin is None:
            pytest.fail("armed but validated profile %s carries "
                        "no well-formed btf pin" % name)
        return pin
    pytest.fail("armed but no validated shipped profile names "
                "kernel release %s" % release)


def module_build_identity(host_release=None, modules_root="/lib/modules",
                          boot_root="/boot",
                          btf_path="/sys/kernel/btf/vmlinux",
                          profiles_dir=None):
    """Identify owned source and exact guest-kernel build inputs.

    host_release names the running kernel (default: the live
    uname release); modules_root, boot_root, and btf_path
    name the kernel file roots (defaults: the live host
    paths); profiles_dir names the profiles root holding
    the validated pin (default: the shipped profiles).
    Callers measuring the real host use the defaults;
    tests pass a fixture tree with controlled bytes. A
    same-release override measures live bytes exactly like no
    override; only a different release uses the profile pin.
    """
    def sha(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    host = host_release or os.uname().release
    override = os.environ.get("MEMVEIL_ORACLE_KVER", "")
    if override and override != host:
        release = override
        pinned = True
    else:
        release = host
        pinned = False
    kdir = Path(modules_root) / release / "build"
    if pinned:
        btf_sha = validated_btf_pin(release, profiles_dir)
        provenance = "profile-pinned"
    else:
        btf_sha = sha(btf_path)
        provenance = "live-bytes"
    return dict(release=release,
                source_sha=sha(Path(KERNEL_DIR)/"memveil_dma_oracle.c"),
                make_sha=sha(Path(KERNEL_DIR)/"Makefile"),
                config_sha=sha(kdir/".config"),
                kernel_sha=sha_file_maybe_sudo(
                    str(Path(boot_root)/("vmlinuz-"+release))),
                btf_sha=btf_sha,
                btf_provenance=provenance)


def ensure_oracle_module():
    """Reuse only a hash-verified module built from this source/kernel.

    Build in an owned temporary directory, so other fixture module inputs
    and source-tree outputs are not overwritten between lanes.
    """
    try:
        identity = module_build_identity()
    except OSError as exc:
        pytest.fail("armed but module identity unavailable: %s" % exc)
    kdir = "/lib/modules/%s/build" % identity["release"]
    if not os.path.isfile(os.path.join(kdir, "Makefile")):
        pytest.fail("armed but no kernel build tree: %s" % kdir)
    if not shutil.which("make"):
        pytest.fail("armed but make not available")
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
        try:
            rechecked = module_build_identity()
        except OSError as exc:
            pytest.fail("armed but module identity unavailable: %s" % exc)
        if rechecked != identity:
            pytest.fail("oracle build inputs changed during compilation")
        shutil.copyfile(made, module)
        manifest.write_text(json.dumps(dict(inputs=identity,
            module_sha=hashlib.sha256(module.read_bytes()).hexdigest()),sort_keys=True)+"\n")
