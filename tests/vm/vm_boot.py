#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host-side boot helper for the lifecycle VM gates.

One vng boot per gate subcommand with swiotlb=force, an
exact-inventory export check (sha256 sidecars, no raw DMA
addresses cross), and cleanup. Boots share the host rootfs,
so repo paths resolve identically inside the guest.
"""

import hashlib
import re
import json
import fcntl
import shutil
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_attempt_capture import cleanup, gate_prefix

REPO = Path(__file__).resolve().parent.parent.parent
GUEST_FLOW = REPO / "tests" / "vm" / "guest_lifecycle.py"
TESTS = Path(__file__).resolve().parent.parent


def guest_exec_command(sub, work, repo, selected=None):
    """Guest --exec string, with the candidate env when selected.

    Candidate mode prepends the manifest, tarball, and
    expected digest so the guest re-verifies the same
    candidate before any guest work.
    """
    if selected is None:
        return f"python3 {GUEST_FLOW} {sub} {work} /tmp/export {repo}"
    guest = ["python3", str(GUEST_FLOW), sub, work,
             "/tmp/export", str(repo)]
    return shlex.join(
        ["env",
         "MV_CANDIDATE_MANIFEST=" + str(selected.manifest_path),
         "MV_BUNDLE_TARBALL=" + str(selected.bundle),
         "MV_CANDIDATE_DIGEST=" + selected.digest,
         *guest])


def guest_artifact_paths(sub, repo, selected=None):
    """Host-side expected paths for guest identity hashes.

    Candidate mode resolves the lifecycle/copy objects
    under the verified root for every subcommand; a
    saturation guest still runs the dev test objects, so
    its identity refuses here instead of passing mixed
    bytes as qualified. The bundle leg runs the packaged
    record, never the dev consumer, so its table carries
    no consumer entry. Otherwise consume keeps its dev
    path (a fixture the candidate never carries); bridge
    keeps its dev path too, except the sealed bundle leg,
    which loads no bridge and pins the candidate runtime
    member under the verified root instead.
    """
    repo = str(repo)
    table = {
        "lc_sha": os.path.join(repo, "build", "bpf",
                               "swiotlb_lifecycle-test.bpf.o"
                               if sub == "saturation"
                               else "swiotlb_lifecycle.bpf.o"),
        "cp_sha": os.path.join(repo, "build", "bpf",
                               "swiotlb_copy-test.bpf.o"
                               if sub == "saturation"
                               else "swiotlb_copy.bpf.o"),
        "bridge_sha": os.path.join(repo, "build", "deps", "lmb",
                                   "lib", "libbpf_mojo.so.1"),
    }
    if sub != "bundle":
        table["consume_sha"] = os.path.join(
            repo, "build", "vm", "mv_consume")
    if selected is not None:
        table["lc_sha"] = str(selected.path(
            "bpf/swiotlb_lifecycle.bpf.o"))
        table["cp_sha"] = str(selected.path(
            "bpf/swiotlb_copy.bpf.o"))
        if sub == "bundle":
            table["bridge_sha"] = str(selected.path(
                "lib/memveil/libgcc_s.so.1"))
    return table


def run_guest(sub, timeout=900, network=False):
    """Boot the guest, run one lifecycle subcommand, return dir+proc."""
    sys.path.insert(0, str(TESTS))
    from support.candidate_input import load
    selected = load()
    prefix, env = gate_prefix()
    from lifecycle_env import (ensure_oracle_module,
                               sealed_profiles_dir)
    from harness_env import check_harness_versions
    harness = check_harness_versions(prefix[-1])
    lock_dir = REPO / "build" / "vm"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lease = (lock_dir / "suite.lock").open("a+")
    try:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lease.close()
        raise ValueError("VM suite lease already owned")
    try:
        if selected is None:
            ensure_oracle_module()
        else:
            ensure_oracle_module(
                profiles=sealed_profiles_dir(selected))
    except BaseException:
        lease.close()
        raise
    tmp = Path(tempfile.mkdtemp(prefix=f"vmgate-{sub}-"))
    work = "/tmp/vmgate-work"
    export = tmp / "export"
    export.mkdir()
    cmd = prefix + [
        "--run", "-m", "6G",
        "--append", "swiotlb=force",
    ]
    if network:
        # Microvm boots carry no pcnet NIC, so network guests
        # need the full machine (same flag as the attempt
        # lane's argv). Scoped to this branch: pcnet exists
        # only in network guests, and non-network lanes keep
        # their current boot path unchanged.
        cmd += [
            "--disable-microvm",
            "--network", "user",
            "--qemu-opts=-cpu host",
            "--qemu-opts=-device pcnet,netdev=pcnet0"
            " -netdev user,id=pcnet0,net=10.0.3.0/24",
        ]
    cmd += [
        f"--rwdir=/tmp/export={export}",
        "--exec",
        guest_exec_command(sub, work, REPO, selected),
    ]
    try:
        from vm_process import run_owned_guest
        proc = run_owned_guest(cmd, timeout=timeout)
        (tmp / "harness.json").write_text(json.dumps(harness,sort_keys=True)+"\n")
    except subprocess.TimeoutExpired as exc:
        (tmp / "timeout.json").write_text(json.dumps(dict(timeout=timeout,status="FAIL"))+"\n")
        print(f"timed-out gate artifacts kept at {tmp}")
        raise
    finally:
        lease.close()
    return tmp, proc


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_exports(tmp, sub, names):
    """Check the exact export inventory with sidecar hashes."""
    from evidence_retention import VerifiedExports, snapshot_exports
    export = tmp / "export"
    got, verified = snapshot_exports(tmp, sub, names)
    want_files = {f"{sub}-{n}" for n in names}
    want_files |= {f"{sub}-{n}.sha256" for n in names}
    have = {p.name for p in export.iterdir()}
    assert have == want_files, f"export inventory drift: {have ^ want_files}"
    from export_validation import validate_lifecycle_exports
    validate_lifecycle_exports(got, sub)
    if "identity.json" in got:
        sys.path.insert(0, str(TESTS))
        from support.candidate_input import load
        selected = load()
        from lifecycle_env import (ORACLE_KO, module_build_identity,
                                   sealed_profiles_dir)
        if selected is None:
            expected = module_build_identity()
        else:
            expected = module_build_identity(
                profiles_dir=sealed_profiles_dir(selected))
        identity = json.loads(got["identity.json"].read_text())
        for key in ("release", "config_sha", "btf_sha"):
            assert identity[key] == expected[key], "guest kernel identity drift: " + key
        paths = guest_artifact_paths(sub, REPO, selected)
        checks = dict(paths)
        checks["ko_sha"] = Path(ORACLE_KO)
        for key, path in checks.items():
            assert identity[key] == sha_file(path), "guest artifact mismatch: " + key
    return VerifiedExports(got, verified)


__all__ = ["REPO", "GUEST_FLOW", "guest_exec_command",
           "guest_artifact_paths", "run_guest", "verify_exports",
           "cleanup", "gate_prefix"]
