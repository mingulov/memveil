# SPDX-License-Identifier: GPL-3.0-or-later

"""Kernel gate unit tests: tracefs probing, hook identity, ftrace state."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.kernelgate import (
    count_filter_function,
    probe_tracefs,
    read_ftrace_enabled,
    tracefs_translate,
)
from memveil.platform.profiles import (
    Profile,
    parse_profile_bytes,
    verify_live_interfaces,
)
from memveil.platform.reader import open_evidence_reader, read_host_file


def gate(name: String) -> String:
    """Fixture directory path for one gate fixture name."""
    return "tests/fixtures/gate/" + name


def live_ref() raises -> Profile:
    """The scan-live-ref profile document for gate tests."""
    var raw = read_host_file(
        String("tests/fixtures/scan/profiles-live/live-ref.json"),
        String("profile"),
        1048576,
    )
    return parse_profile_bytes(raw^)


def one_cap(cap_id: String) -> List[String]:
    """One-element capability list for live verification."""
    var caps = List[String]()
    caps.append(cap_id)
    return caps^


def test_tracefs_root_order() raises:
    var base = open_evidence_reader(gate(String("base")))
    var pb = probe_tracefs(base)
    assert_equal(pb.root, String("/sys/kernel/tracing"))
    var dbg = open_evidence_reader(gate(String("debugfs-root")))
    var pd = probe_tracefs(dbg)
    assert_equal(pd.root, String("/sys/kernel/debug/tracing"))
    var den = open_evidence_reader(gate(String("debug-denied")))
    var pn = probe_tracefs(den)
    assert_equal(pn.root, String("/sys/kernel/tracing"))
    assert_equal(
        tracefs_translate(
            pd,
            String(
                "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"
            ),
        ),
        String(
            "/sys/kernel/debug/tracing"
            "/events/swiotlb/swiotlb_bounced/format"
        ),
    )


def test_hook_identity_shapes() raises:
    var dup = open_evidence_reader(gate(String("aff-dup")))
    var hd = count_filter_function(
        dup, probe_tracefs(dup), String("swiotlb_tbl_map_single")
    )
    assert_equal(hd.count, 2)
    var mod = open_evidence_reader(gate(String("aff-module")))
    var hm = count_filter_function(
        mod, probe_tracefs(mod), String("swiotlb_tbl_map_single")
    )
    assert_equal(hm.count, 1)
    var clo = open_evidence_reader(gate(String("aff-clone")))
    var hc = count_filter_function(
        clo, probe_tracefs(clo), String("swiotlb_tbl_map_single")
    )
    assert_equal(hc.count, 0)
    assert_equal(hc.clones, 1)
    var pre = open_evidence_reader(gate(String("aff-prefix")))
    var hp = count_filter_function(
        pre, probe_tracefs(pre), String("swiotlb_tbl_map_single")
    )
    assert_equal(hp.count, 1)


def test_live_hook_ambiguous() raises:
    var v = verify_live_interfaces(
        gate(String("aff-dup")),
        live_ref(),
        one_cap(String("mapping-lifecycle")),
    )
    assert_true(not v.ok)
    assert_true(not v.unknown)
    assert_equal(v.code, String("hook-ambiguous"))
    assert_equal(
        v.reason,
        String(
            "fexit:swiotlb_tbl_map_single: hook swiotlb_tbl_map_single"
            " ambiguous (2 available_filter_functions lines)"
        ),
    )


def test_live_ftrace() raises:
    var off = verify_live_interfaces(
        gate(String("ftrace-off")),
        live_ref(),
        one_cap(String("mapping-lifecycle")),
    )
    assert_true(not off.ok)
    assert_true(not off.unknown)
    assert_equal(off.code, String("ftrace-disabled"))
    assert_equal(
        off.reason,
        String("kernel.ftrace_enabled is 0 (function tracing disabled)"),
    )
    var den = verify_live_interfaces(
        gate(String("ftrace-denied")),
        live_ref(),
        one_cap(String("mapping-lifecycle")),
    )
    assert_true(not den.ok)
    assert_true(den.unknown)
    assert_equal(den.code, String("ftrace-unknown"))
    var mal = verify_live_interfaces(
        gate(String("ftrace-malformed")),
        live_ref(),
        one_cap(String("mapping-lifecycle")),
    )
    assert_true(not mal.ok)
    assert_true(mal.unknown)
    assert_equal(mal.code, String("ftrace-unknown"))
    var base = verify_live_interfaces(
        gate(String("base")),
        live_ref(),
        one_cap(String("mapping-lifecycle")),
    )
    assert_true(base.ok)
    var dbg = verify_live_interfaces(
        gate(String("debugfs-root")),
        live_ref(),
        one_cap(String("mapping-lifecycle")),
    )
    assert_true(dbg.ok)


def test_live_debugfs_attempt() raises:
    # Tracepoint format and id paths resolve under the
    # debugfs root too, so attempt-trace verifies there.
    var base = verify_live_interfaces(
        gate(String("base")),
        live_ref(),
        one_cap(String("attempt-trace")),
    )
    assert_true(base.ok)
    var dbg = verify_live_interfaces(
        gate(String("debugfs-root")),
        live_ref(),
        one_cap(String("attempt-trace")),
    )
    assert_true(dbg.ok)


def test_ftrace_states() raises:
    assert_equal(
        read_ftrace_enabled(
            open_evidence_reader(gate(String("base")))
        ).value,
        String("1"),
    )
    assert_equal(
        read_ftrace_enabled(
            open_evidence_reader(gate(String("ftrace-off")))
        ).value,
        String("0"),
    )
    assert_equal(
        read_ftrace_enabled(
            open_evidence_reader(gate(String("ftrace-denied")))
        ).value,
        String("denied"),
    )
    assert_equal(
        read_ftrace_enabled(
            open_evidence_reader(gate(String("ftrace-malformed")))
        ).value,
        String("malformed"),
    )


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_tracefs_root_order]()
    suite.test[test_hook_identity_shapes]()
    suite.test[test_live_hook_ambiguous]()
    suite.test[test_live_ftrace]()
    suite.test[test_live_debugfs_attempt]()
    suite.test[test_ftrace_states]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
