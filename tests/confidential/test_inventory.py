#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Confidential-guest inventory checks: evidence before mode claims.

Exercised two ways: frozen fixture vectors pin the flag parsing
and the conservative verdict matrix (flags alone never verify),
and one live run asserts the manifest is well-formed and the
dry-run wrote nothing besides the manifest itself. The live
verdict on any particular host is data for the qualification
receipt, not an assertion here: this same test must run
unchanged on the admitted SNP/TDX guest.

Runs unprivileged. Exit 0 when every assertion holds.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import inventory

CPUINFO_SNP = """\
processor\t: 0
vendor_id\t: AuthenticAMD
flags\t\t: fpu sme sev sev_snp hypervisor
processor\t: 1
vendor_id\t: AuthenticAMD
flags\t\t: fpu sme sev sev_snp hypervisor
"""

CPUINFO_TDX = """\
processor\t: 0
vendor_id\t: GenuineIntel
flags\t\t: fpu tdx_guest hypervisor
"""

CPUINFO_PLAIN = """\
processor\t: 0
vendor_id\t: AuthenticAMD
flags\t\t: fpu smep hypervisor
"""


def check_flag_parsing():
    flags = inventory.parse_cpu_flags(CPUINFO_SNP)
    assert flags == {"fpu", "sme", "sev", "sev_snp", "hypervisor"}, flags
    assert inventory.parse_cpu_flags(CPUINFO_TDX) == {
        "fpu", "tdx_guest", "hypervisor"}
    assert "sev_snp" not in inventory.parse_cpu_flags(CPUINFO_PLAIN)
    assert inventory.parse_cpu_flags("") == set()


def _evidence(flags=(), devices=(), dmesg="", btf=False, tracefs=False,
              kallsyms=False, ubpf=None):
    return {"kernel_release": "9.9.9-test",
            "cpu_flags": sorted(flags),
            "devices": sorted(devices),
            "dmesg_text": dmesg,
            "dmesg_readable": bool(dmesg),
            "btf_present": btf,
            "tracefs_writable": tracefs,
            "kallsyms_readable": kallsyms,
            "unprivileged_bpf_disabled": ubpf}


def check_verdict_matrix():
    cases = (
        # (label, evidence, want_mode, want_enabled)
        ("nothing", _evidence(), "none", False),
        ("flags-only-snp",
         _evidence(flags=("sev", "sev_snp")), "unverified", False),
        ("flags-only-tdx",
         _evidence(flags=("tdx_guest",)), "unverified", False),
        ("device-without-flags",
         _evidence(devices=("/dev/sev-guest",)), "unverified", False),
        ("snp-full",
         _evidence(flags=("sev", "sev_snp"),
                   devices=("/dev/sev-guest",),
                   dmesg="AMD Memory Encryption Features active: SNP"),
         "sev-snp", True),
        ("snp-no-log",
         _evidence(flags=("sev", "sev_snp"),
                   devices=("/dev/sev-guest",)),
         "unverified", False),
        ("tdx-full",
         _evidence(flags=("tdx_guest",),
                   devices=("/dev/tdx-guest",),
                   dmesg="tdx: Guest detected"),
         "tdx", True),
        ("tdx-no-device",
         _evidence(flags=("tdx_guest",),
                   dmesg="tdx: Guest detected"),
         "unverified", False),
    )
    for label, ev, want_mode, want_enabled in cases:
        verdict = inventory.judge_mode(ev)
        assert verdict["mode"] == want_mode, (label, verdict)
        assert verdict["enabled"] is want_enabled, (label, verdict)
        assert verdict["reasons"], (label, verdict)


def check_live_manifest(tmpdir):
    out = os.path.join(tmpdir, "manifest.json")
    before = set(os.listdir(tmpdir))
    manifest = inventory.collect(out)
    after = set(os.listdir(tmpdir))
    assert after - before == {"manifest.json"}, after - before
    for key in ("collected_by", "kernel_release", "arch",
                "cpu_flags", "devices", "dmesg_readable",
                "btf_present", "tracefs_writable",
                "kallsyms_readable",
                "unprivileged_bpf_disabled", "verdict",
                "restrictions", "cleanup_ownership"):
        assert key in manifest, key
    assert manifest["verdict"]["mode"] in (
        "none", "unverified", "sev-snp", "tdx"), manifest["verdict"]
    assert isinstance(manifest["verdict"]["enabled"], bool)
    assert "BOOT_IMAGE" not in json.dumps(manifest)
    with open(out, "r", encoding="utf-8") as handle:
        assert json.load(handle) == manifest
    return manifest


def main():
    import tempfile
    checks = (("flag-parsing", check_flag_parsing),
              ("verdict-matrix", check_verdict_matrix))
    failed = 0
    for label, check in checks:
        try:
            check()
        except AssertionError as exc:
            print("FAIL %s: %s" % (label, exc))
            failed += 1
            continue
        print("ok %s" % label)
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            manifest = check_live_manifest(tmpdir)
        except AssertionError as exc:
            print("FAIL live-manifest: %s" % exc)
            return 1
    print("ok live-manifest")
    print("live verdict: %s"
          % json.dumps(manifest["verdict"], sort_keys=True))
    if failed:
        return 1
    print("inventory: 3/3 checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
