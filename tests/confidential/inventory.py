#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Confidential-guest environment inventory (read-only dry-run).

Collects kernel/platform evidence for SNP/TDX admission into one
manifest: CPU flags, guest device nodes, matched kernel-log
markers, BTF/probe/module permissions, boot identity, and a
conservative mode verdict. CPU flags, device marketing names,
or a user assertion alone never verify: an enabled verdict
needs flags plus the guest device node plus a kernel-log
marker, all with provenance.

The inventory only reads; it provisions nothing, converts
nothing, and writes only the manifest file it is given. It
records no credentials, full boot logs, or kernel command
lines. Python standard library only.
"""

import json
import os
import platform
import subprocess
import sys

SEV_GUEST_DEVICES = ("/dev/sev-guest",)
TDX_GUEST_DEVICES = ("/dev/tdx-guest", "/dev/tdx_guest")
LEGACY_SEV_DEVICES = ("/dev/sev",)

MAX_MARKERS = 8
MAX_MARKER_LEN = 256


def parse_cpu_flags(text):
    """Union the flags: lines of one cpuinfo-shaped text."""
    flags = set()
    for line in text.splitlines():
        if not line.startswith("flags"):
            continue
        _, _, rest = line.partition(":")
        for flag in rest.split():
            flags.add(flag)
    return flags


def judge_mode(evidence):
    """Return the conservative mode verdict for one evidence set."""
    flags = set(evidence.get("cpu_flags", ()))
    devices = set(evidence.get("devices", ()))
    log = ""
    if evidence.get("dmesg_readable"):
        log = evidence.get("dmesg_text", "")
    snp_log = ("Memory Encryption Features active" in log
               and "SNP" in log)
    lowered = log.lower()
    tdx_log = "tdx:" in lowered and "guest" in lowered
    snp_dev = any(d in devices for d in SEV_GUEST_DEVICES)
    tdx_dev = any(d in devices for d in TDX_GUEST_DEVICES)
    snp_flags = "sev_snp" in flags
    tdx_flags = "tdx_guest" in flags
    if snp_flags and snp_dev and snp_log:
        return {"mode": "sev-snp", "enabled": True,
                "reasons": ["sev_snp flag",
                            "sev-guest device node",
                            "kernel SNP-active marker"]}
    if tdx_flags and tdx_dev and tdx_log:
        return {"mode": "tdx", "enabled": True,
                "reasons": ["tdx_guest flag",
                            "tdx-guest device node",
                            "kernel TDX-guest marker"]}
    if not snp_flags and not tdx_flags and not snp_dev and not tdx_dev:
        extra = [d for d in devices if d in LEGACY_SEV_DEVICES]
        if not extra and not snp_log and not tdx_log:
            return {"mode": "none", "enabled": False,
                    "reasons": ["no SNP/TDX flags, devices, or markers"]}
    reasons = []
    if snp_flags or tdx_flags:
        reasons.append("CPU flags without device-plus-log proof")
    if snp_dev or tdx_dev:
        reasons.append("guest device without flag-plus-log proof")
    if snp_log or tdx_log:
        reasons.append("kernel marker without flag-plus-device proof")
    if any(d in devices for d in LEGACY_SEV_DEVICES):
        reasons.append("legacy SEV device only; not SNP/TDX evidence")
    if not reasons:
        reasons.append("partial signals; proof incomplete")
    return {"mode": "unverified", "enabled": False, "reasons": reasons}


def _read_text(path, cap=1 << 20):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(cap)
    except OSError:
        return None


def _dmesg_markers():
    """Matched kernel-log markers only, never the full log."""
    try:
        proc = subprocess.run(["dmesg"], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True,
                              timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return False, ""
    if proc.returncode != 0:
        return False, ""
    markers = []
    for line in proc.stdout.splitlines():
        if ("Memory Encryption Features active" in line
                or "cc_platform" in line
                or ("tdx:" in line.lower() and "guest" in line.lower())):
            markers.append(line.strip()[:MAX_MARKER_LEN])
            if len(markers) >= MAX_MARKERS:
                break
    return True, "\n".join(markers)


def _config_source(release):
    candidates = ("/proc/config.gz",
                  "/boot/config-%s" % release)
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def collect(out_path):
    """Gather evidence, judge the mode, write the manifest."""
    release = platform.uname().release
    cpuinfo = _read_text("/proc/cpuinfo")
    flags = sorted(parse_cpu_flags(cpuinfo)) if cpuinfo else []
    devices = [d for d in (SEV_GUEST_DEVICES + TDX_GUEST_DEVICES
                           + LEGACY_SEV_DEVICES)
               if os.path.exists(d)]
    dmesg_ok, markers = _dmesg_markers()
    try:
        with open("/proc/kallsyms", "r", encoding="utf-8",
                  errors="replace") as handle:
            handle.read(1)
        kallsyms = True
    except OSError:
        kallsyms = False
    ubpf_text = _read_text("/proc/sys/kernel/unprivileged_bpf_disabled",
                           cap=64)
    try:
        ubpf = int(ubpf_text.strip()) if ubpf_text else None
    except ValueError:
        ubpf = None
    boot_id = _read_text("/proc/sys/kernel/random/boot_id", cap=128)
    evidence = {"kernel_release": release,
                "cpu_flags": flags,
                "devices": devices,
                "dmesg_text": markers,
                "dmesg_readable": dmesg_ok,
                "btf_present": os.path.exists("/sys/kernel/btf/vmlinux"),
                "tracefs_writable": os.access("/sys/kernel/tracing",
                                              os.W_OK),
                "kallsyms_readable": kallsyms,
                "unprivileged_bpf_disabled": ubpf}
    verdict = judge_mode(evidence)
    restrictions = []
    if os.geteuid() != 0:
        restrictions.append("unprivileged: no attach or module load")
    if not verdict["enabled"]:
        restrictions.append("no verified SNP/TDX mode on this host")
    if not dmesg_ok:
        restrictions.append("kernel log unreadable here")
    if ubpf == 2:
        restrictions.append("unprivileged BPF disabled")
    manifest = {"collected_by": "memveil confidential inventory 1.0.0",
                "kernel_release": release,
                "arch": platform.machine(),
                "cpu_flags": flags,
                "cpuinfo_readable": cpuinfo is not None,
                "devices": devices,
                "dmesg_readable": dmesg_ok,
                "dmesg_markers": markers.splitlines() if markers else [],
                "btf_present": evidence["btf_present"],
                "kernel_config": _config_source(release),
                "tracefs_writable": evidence["tracefs_writable"],
                "kallsyms_readable": kallsyms,
                "unprivileged_bpf_disabled": ubpf,
                "boot_id": boot_id.strip() if boot_id else None,
                "privileges": {"euid": os.geteuid()},
                "admitted_profile": None,
                "verdict": verdict,
                "permitted_workloads": [],
                "restrictions": restrictions,
                "cleanup_ownership":
                    "inventory reads only and creates no guest "
                    "resources; nothing to clean beyond %s" % out_path}
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return manifest


def main(argv):
    if len(argv) != 2 or argv[1] in ("-h", "--help"):
        print("usage: inventory.py MANIFEST", file=sys.stderr)
        return 2
    manifest = collect(argv[1])
    print("inventory: mode=%s enabled=%s -> %s"
          % (manifest["verdict"]["mode"],
             manifest["verdict"]["enabled"], argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
