#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Oracle live gate: module build plus guest comparison.

test_module_builds compiles the test-only oracle module against
the running kernel's build tree and checks its modinfo; it runs
everywhere the headers exist. test_guest_comparison boots the
frozen virtme-ng harness, loads the module, replays its log
into the oracle ledger, and compares against a MemVeil report
with zero tolerated mismatches.

The comparison runs only when armed (MEMVEIL_VM_ORACLE=1)
with qualified probes; otherwise it skips fast with no boot.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import (check_conservation, check_lifetime_ordering,
                     check_oracle_script, compare_live,
                     compare_scripted, parse_consume_file,
                     parse_oracle_log, replay_oracle_ledger,
                     translate_session)
from lifecycle_env import (CONSUMER, COPY_PROBE, LIFECYCLE_PROBE,
                           ensure_oracle_module)
from vm_boot import cleanup, run_guest, verify_exports

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KERNEL_DIR = os.path.join(REPO, "tests", "kernel")
MEMVEIL_BIN = os.path.join(REPO, "build", "memveil")


def test_module_builds():
    kdir = "/lib/modules/%s/build" % os.uname().release
    if not os.path.isfile(os.path.join(kdir, "Makefile")):
        pytest.skip("kernel build tree not available: %s" % kdir)
    make = shutil.which("make")
    if not make:
        pytest.skip("make not available")
    from lifecycle_env import ORACLE_KO
    from lifecycle_env import module_build_identity
    try:
        module_build_identity()
    except OSError as exc:
        if os.environ.get("MEMVEIL_VM_ORACLE") == "1":
            pytest.fail("armed but module identity unavailable: " + str(exc))
        pytest.skip("unarmed module identity unavailable: " + str(exc))
    ensure_oracle_module()
    info = subprocess.run(["modinfo", ORACLE_KO],capture_output=True,text=True)
    assert info.returncode == 0
    assert "license:        GPL" in info.stdout
    assert "mv_oracle_arm" in info.stdout


def test_guest_comparison(tmp_path):
    # Boot the frozen harness, insmod the oracle module with
    # mv_oracle_arm=1, replay its mv-oracle: log lines into the
    # oracle ledger, capture with the lifecycle probes over the
    # same window, and compare with zero tolerated mismatches.
    if os.environ.get("MEMVEIL_VM_ORACLE", "0") != "1":
        pytest.skip("oracle comparison needs MEMVEIL_VM_ORACLE=1 "
                    "with qualified probes")
    for path in (LIFECYCLE_PROBE, COPY_PROBE, CONSUMER,
                 MEMVEIL_BIN):
        if not os.path.isfile(path):
            pytest.fail("armed but missing: %s" % path)
    ensure_oracle_module()
    tmp, proc = run_guest("oracle")
    try:
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        got = verify_exports(tmp, "oracle",
                             ["identity.json", "cmp-lc.txt",
                              "cmp-cp.txt", "cmp-oracle.log"])
        lc, lc_sum = parse_consume_file(str(got["cmp-lc.txt"]))
        cp, cp_sum = parse_consume_file(str(got["cmp-cp.txt"]))
        bad = check_conservation(lc, lc_sum, "cmp-lc")
        bad += check_conservation(cp, cp_sum, "cmp-cp")
        ops_log, releases, complete = parse_oracle_log(
            str(got["cmp-oracle.log"]))
        bad += check_oracle_script(ops_log, releases, complete,
                                   4, -1, "cmp")
        bad += compare_scripted(lc, cp, 4, -1, "cmp")
        assert not bad, "\n".join(bad)
        cap_dir = tmp_path / "cap-report"
        cap_dir.mkdir()
        probe_lifetimes = translate_session(
            lc, cp, ops_log, str(cap_dir), "oracle-live-session",
            "linux-x86_64-7.0.0-34-generic")
        rep = subprocess.run(
            [MEMVEIL_BIN, "report", "--format", "json",
             str(cap_dir)],
            capture_output=True, text=True, timeout=300)
        assert rep.returncode == 4, rep.stderr[-1000:]
        report = json.loads(rep.stdout)
        ledger = replay_oracle_ledger(ops_log, releases)
        mismatches = compare_live(report, ledger, probe_lifetimes)
        mismatches += check_lifetime_ordering(
            probe_lifetimes, releases, "cmp")
        assert not mismatches, "\n".join(mismatches)
        print("oracle: 8 lc + 17 cp exact, report matches "
              "ledger with zero mismatches")
    except Exception:
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp)
