#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host-side boot helper for the lifecycle VM gates.

One vng boot per gate subcommand with swiotlb=force, an
exact-inventory export check (sha256 sidecars, no raw DMA
addresses cross), and cleanup. Boots share the host rootfs,
so repo paths resolve identically inside the guest.
"""

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_attempt_capture import cleanup, gate_prefix

REPO = Path(__file__).resolve().parent.parent.parent
GUEST_FLOW = REPO / "tests" / "vm" / "guest_lifecycle.py"


def run_guest(sub, timeout=900, network=False):
    """Boot the guest, run one lifecycle subcommand, return dir+proc."""
    prefix, env = gate_prefix()
    tmp = Path(tempfile.mkdtemp(prefix=f"vmgate-{sub}-"))
    work = "/tmp/vmgate-work"
    export = tmp / "export"
    export.mkdir()
    cmd = prefix + [
        "--run", "-m", "6G",
        "--append", "swiotlb=force",
    ]
    if network:
        cmd += [
            "--network", "user",
            "--qemu-opts=-cpu host",
            "--qemu-opts=-device pcnet,netdev=pcnet0"
            " -netdev user,id=pcnet0,net=10.0.3.0/24",
        ]
    cmd += [
        f"--rwdir=/tmp/export={export}",
        "--exec",
        f"python3 {GUEST_FLOW} {sub} {work} /tmp/export {REPO}",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout)
    return tmp, proc


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_exports(tmp, sub, names):
    """Check the exact export inventory with sidecar hashes."""
    export = tmp / "export"
    got = {}
    for name in names:
        target = export / f"{sub}-{name}"
        sidecar = Path(str(target) + ".sha256")
        assert target.is_file(), f"missing export {sub}-{name}"
        assert sidecar.is_file(), f"missing sidecar {sub}-{name}.sha256"
        want = sidecar.read_text().split()[0]
        assert sha_file(target) == want, f"hash mismatch {sub}-{name}"
        got[name] = target
    want_files = {f"{sub}-{n}" for n in names}
    want_files |= {f"{sub}-{n}.sha256" for n in names}
    have = {p.name for p in export.iterdir()}
    assert have == want_files, f"export inventory drift: {have ^ want_files}"
    for name in names:
        blob = got[name].read_bytes()
        assert b"dev_addr" not in blob, f"raw address in {sub}-{name}"
    return got


__all__ = ["REPO", "GUEST_FLOW", "run_guest", "verify_exports",
           "cleanup", "gate_prefix"]
