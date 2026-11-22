#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Oracle live gate: module build plus guest comparison.

SUPERSEDED by tests/vm/test_heldopen.py for the live
held-open leg (test_guest_comparison): the ported runner
drives the reviewed consumer with its real CLI, the sealed
objects and executable, the fixture, and the pinned
7.0.14 guest. test_module_builds remains the host
module-build check. This file keeps working defaults.

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

from consume import (author_reducer_fixture, check_conservation, check_lifetime_ordering,
                     check_oracle_script, compare_live,
                     compare_scripted, parse_consume_file,
                     parse_oracle_log, replay_oracle_ledger,
                     translate_session)
from evidence_retention import (expected_from_verified,
                                retain_failure)
import gate_kernel  # noqa: E402
from lifecycle_env import (prepare_gate_kernel, CONSUMER, COPY_PROBE, LIFECYCLE_PROBE,
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


def judge_oracle_comparison(got, work_dir, memveil_bin,
                            profile_id):
    """Judge one held-open window; returns a reason list (empty ok).

    Verbatim extraction of the test_guest_comparison judge
    block: conservation on both consumer files, the oracle
    script check plus the scripted multiset comparison
    (4 ops, no fail-op), then the separately authored
    synthetic reducer fixture rendered by the report
    command and compared against the replayed oracle
    ledger with zero tolerated mismatches, plus the
    lifetime-ordering check. The retired entry passes the
    build-tree binary and the prepared gate profile id;
    the held-open port passes the staged sealed binary
    and the seal-bound profile id. The retired asserts
    (window checks, report exit, ledger mismatches) return
    as reasons instead, so armed runners print them.
    """
    bad = []
    lc, lc_sum = parse_consume_file(str(got["cmp-lc.txt"]))
    cp, cp_sum = parse_consume_file(str(got["cmp-cp.txt"]))
    bad += check_conservation(lc, lc_sum, "cmp-lc")
    bad += check_conservation(cp, cp_sum, "cmp-cp")
    ops_log, releases, complete = parse_oracle_log(
        str(got["cmp-oracle.log"]))
    bad += check_oracle_script(ops_log, releases, complete,
                               4, -1, "cmp")
    bad += compare_scripted(lc, cp, 4, -1, "cmp")
    if bad:
        return sorted(bad)
    cap_dir = os.path.join(work_dir, "cap-report")
    os.makedirs(cap_dir, exist_ok=True)
    probe_lifetimes = translate_session(
        lc, cp, ops_log, cap_dir, "oracle-live-session",
        profile_id)
    authored = os.path.join(work_dir, "authored-reducer-fixture")
    author_reducer_fixture(cap_dir, authored)
    rep = subprocess.run(
        [memveil_bin, "report", "--format", "json",
         authored],
        capture_output=True, text=True, timeout=300)
    if rep.returncode != 0:
        return ["cmp: report exit %d: %s"
                % (rep.returncode, rep.stderr[-1000:])]
    report = json.loads(rep.stdout)
    ledger = replay_oracle_ledger(ops_log, releases)
    mismatches = compare_live(report, ledger, probe_lifetimes)
    mismatches += check_lifetime_ordering(
        probe_lifetimes, releases, "cmp")
    return sorted(mismatches)


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
    prepare_gate_kernel()
    ensure_oracle_module()
    tmp = None
    try:
        tmp, proc = run_guest("oracle")
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        got = verify_exports(tmp, "oracle",
                             ["identity.json", "cmp-lc.txt",
                              "cmp-cp.txt", "cmp-oracle.log"])
        expected = expected_from_verified(got, "oracle")
        bad = judge_oracle_comparison(
            got, str(tmp_path), MEMVEIL_BIN,
            gate_kernel.selected_profile_id())
        assert not bad, "\n".join(bad)
        print("oracle: 8 lc + 17 cp exact, report matches "
              "ledger in separately authored synthetic reducer fixture")
    except Exception:
        retain_failure(tmp, "oracle")
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp, "oracle", expected=expected)
