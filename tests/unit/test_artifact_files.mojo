# SPDX-License-Identifier: GPL-3.0-or-later

"""Pinned artifact files: snapshots, root joining, ownership repair.

Collection resolves bridge and object pathnames once, pins each
behind an open file description, hashes and loads through the
pin's /proc/self/fd/N alias, and hands root-made captures back
to the invoking user. These tests pin that filesystem boundary
through its own import path: evidence-root joining, sudo id
parsing, snapshot degradation for uncheckable paths, and the
silent no-op the repair reports outside a root run.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.artifact_files import (
    _parse_sudo_id,
    join_root,
    open_bridge_snapshot,
    restore_capture_ownership,
)
from memveil.platform.reader import _geteuid_live


def test_artifact_join_root_edges() raises:
    assert_equal(join_root(String(""), String("/a")), String("/a"))
    assert_equal(join_root(String("/"), String("/a")), String("/a"))
    assert_equal(
        join_root(String("/r"), String("/a")), String("/r/a")
    )


def test_artifact_parse_sudo_id_edges() raises:
    assert_equal(_parse_sudo_id(String("1001")), 1001)
    assert_equal(_parse_sudo_id(String("0")), 0)
    assert_equal(_parse_sudo_id(String("4294967295")), 4294967295)
    assert_equal(_parse_sudo_id(String("")), -1)
    assert_equal(_parse_sudo_id(String("nope")), -1)
    assert_equal(_parse_sudo_id(String("4294967296")), -1)
    assert_equal(_parse_sudo_id(String("-1")), -1)


def test_artifact_snapshot_missing_degrades() raises:
    var snap = open_bridge_snapshot(
        String("/nonexistent/memveil-bridge.so.1")
    )
    assert_equal(snap.sha, String(""))
    assert_equal(
        snap.load_path, String("/nonexistent/memveil-bridge.so.1")
    )


def test_artifact_restore_silent_outside_root() raises:
    # Outside a root run there is nothing to hand back:
    # the repair reports unattempted and stays silent.
    # The root-only transfer probes stay with the
    # ownership suite, which runs them under sudo.
    if _geteuid_live() == 0:
        print(
            String("SKIP test_artifact_restore_silent_outside_root: ")
            + String("running as root")
        )
        return
    var repair = restore_capture_ownership(
        String("/nonexistent-cap"), List[UInt64]()
    )
    assert_true(not repair.attempted)
    assert_true(not repair.repaired)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_artifact_join_root_edges]()
    suite.test[test_artifact_parse_sudo_id_edges]()
    suite.test[test_artifact_snapshot_missing_degrades]()
    suite.test[test_artifact_restore_silent_outside_root]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
