# SPDX-License-Identifier: GPL-3.0-or-later

"""Passive pre-check unit tests: privilege, memcg, object map bytes."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.btf import read_object_map_bytes
from memveil.platform.prechecks import (
    check_memcg,
    check_privilege,
    check_unprivileged_bpf,
)
from memveil.platform.reader import open_evidence_reader, read_host_file


def gate(name: String) -> String:
    """Fixture directory path for one gate fixture name."""
    return "tests/fixtures/gate/" + name


def contains(hay: String, needle: String) -> Bool:
    """True when needle occurs in hay at least once."""
    return len(hay.split(String(needle))) > 1


def _has_hex_run(s: String, width: Int) -> Bool:
    """True when s holds width straight hex digits."""
    var raw = s.as_bytes()
    var run = 0
    for i in range(len(raw)):
        var b = raw[i]
        var hex = (
            (b >= UInt8(48) and b <= UInt8(57))
            or (b >= UInt8(65) and b <= UInt8(70))
            or (b >= UInt8(97) and b <= UInt8(102))
        )
        if hex:
            run += 1
            if run >= width:
                return True
        else:
            run = 0
    return False


def test_object_map_bytes() raises:
    # 8388608 ring + 6*8 counts + 1*24 offsets.
    var ok_raw = read_host_file(
        String("tests/fixtures/elf/ok.o"), String("object"), 67108864
    )
    var ok = read_object_map_bytes(Span(ok_raw))
    assert_true(ok.ok)
    assert_equal(ok.bytes, 8388680)
    # 33554432 ring + 6*8 counts + 32768*24 gen_table + 8 gen_next
    # + 1024*24 quarantine + 8 dark.
    var lc_raw = read_host_file(
        String("tests/fixtures/elf/lc-ok.o"), String("object"), 67108864
    )
    var lc = read_object_map_bytes(Span(lc_raw))
    assert_true(lc.ok)
    assert_equal(lc.bytes, 34365504)
    # 33554432 ring + 6*8 counts + 4096*16 claims + 4*8 copy_fb.
    var cp_raw = read_host_file(
        String("tests/fixtures/elf/cp-ok.o"), String("object"), 67108864
    )
    var cp = read_object_map_bytes(Span(cp_raw))
    assert_true(cp.ok)
    assert_equal(cp.bytes, 33620048)


def test_privilege() raises:
    var base = check_privilege(open_evidence_reader(gate(String("base"))))
    assert_equal(base.state, String("pass"))
    assert_equal(base.code, String(""))
    assert_equal(
        base.reason,
        String("CapEff has CAP_BPF+CAP_PERFMON"),
    )
    var both = check_privilege(
        open_evidence_reader(gate(String("caps-bpf-perfmon")))
    )
    assert_equal(both.state, String("pass"))
    assert_equal(
        both.reason,
        String("CapEff has CAP_BPF+CAP_PERFMON"),
    )
    var admin = check_privilege(
        open_evidence_reader(gate(String("caps-sysadmin")))
    )
    assert_equal(admin.state, String("pass"))
    assert_equal(
        admin.reason,
        String("CapEff has CAP_SYS_ADMIN"),
    )
    var none = check_privilege(
        open_evidence_reader(gate(String("caps-none")))
    )
    assert_equal(none.state, String("fail"))
    assert_equal(none.code, String("no-bpf-privilege"))
    assert_equal(
        none.reason,
        String("CapEff lacks CAP_BPF+CAP_PERFMON and CAP_SYS_ADMIN"),
    )


def test_privilege_reason_has_no_raw_mask() raises:
    """Privilege reasons name the grant, never the raw mask.

    A raw 16-hex mask is indistinguishable from a kernel
    address to the export redaction gate.
    """
    var base = check_privilege(open_evidence_reader(gate(String("base"))))
    assert_true(not _has_hex_run(base.reason, 16))
    assert_true(contains(base.reason, String("CAP_BPF+CAP_PERFMON")))
    var none = check_privilege(
        open_evidence_reader(gate(String("caps-none")))
    )
    assert_true(not _has_hex_run(none.reason, 16))
    assert_true(contains(none.reason, String("lacks")))


def test_capeff_malformed() raises:
    var bad = check_privilege(
        open_evidence_reader(gate(String("caps-malformed")))
    )
    assert_equal(bad.state, String("unknown"))
    assert_equal(bad.code, String(""))
    var short = check_privilege(
        open_evidence_reader(gate(String("caps-short")))
    )
    assert_equal(short.state, String("unknown"))


def test_memcg_ancestor_min() raises:
    var small = check_memcg(
        open_evidence_reader(gate(String("memcg-ancestor"))), 8388680
    )
    assert_equal(small.state, String("pass"))
    var big = check_memcg(
        open_evidence_reader(gate(String("memcg-ancestor"))), 76374232
    )
    assert_equal(big.state, String("unknown"))
    assert_equal(big.code, String("memcg-headroom"))
    assert_true(contains(big.reason, String("50000000")))
    assert_true(contains(big.reason, String("/a")))
    var leaf = check_memcg(
        open_evidence_reader(gate(String("memcg-small"))), 8388680
    )
    assert_equal(leaf.state, String("unknown"))


def test_memcg_shortfall_unknown() raises:
    # memory.current counts reclaimable page cache and map
    # allocation reclaims, so a shortfall is not conclusive.
    var leaf = check_memcg(
        open_evidence_reader(gate(String("memcg-small"))), 8388680
    )
    assert_equal(leaf.state, String("unknown"))
    assert_equal(leaf.code, String("memcg-headroom"))
    var big = check_memcg(
        open_evidence_reader(gate(String("memcg-ancestor"))), 76374232
    )
    assert_equal(big.state, String("unknown"))
    assert_equal(big.code, String("memcg-headroom"))


def test_memcg_root_unknown() raises:
    # 0::/ is the namespace root or the host root; outer
    # limits may apply that this view cannot see.
    var root = check_memcg(
        open_evidence_reader(gate(String("memcg-root"))), 8388680
    )
    assert_equal(root.state, String("unknown"))
    assert_true(contains(root.reason, String("namespace")))


def test_privilege_userns_unknown() raises:
    # capable() checks the init namespace, so a namespaced
    # CapEff cannot pass the privilege check.
    var ns = check_privilege(
        open_evidence_reader(gate(String("caps-userns")))
    )
    assert_equal(ns.state, String("unknown"))
    assert_true(contains(ns.reason, String("user namespace")))


def test_memcg_malformed() raises:
    var bad = check_memcg(
        open_evidence_reader(gate(String("memcg-malformed"))), 8388680
    )
    assert_equal(bad.state, String("unknown"))
    var huge = check_memcg(
        open_evidence_reader(gate(String("memcg-huge"))), 8388680
    )
    assert_equal(huge.state, String("unknown"))
    var empty = check_memcg(
        open_evidence_reader(gate(String("memcg-empty"))), 8388680
    )
    assert_equal(empty.state, String("unknown"))
    var v1 = check_memcg(
        open_evidence_reader(gate(String("memcg-v1"))), 8388680
    )
    assert_equal(v1.state, String("unknown"))
    var base = check_memcg(
        open_evidence_reader(gate(String("base"))), 8388680
    )
    assert_equal(base.state, String("pass"))


def test_prechecks_denied_unknown() raises:
    var priv = check_privilege(
        open_evidence_reader(gate(String("denied-all")))
    )
    assert_equal(priv.state, String("unknown"))
    var mem = check_memcg(
        open_evidence_reader(gate(String("denied-all"))), 8388680
    )
    assert_equal(mem.state, String("unknown"))


def test_unprivileged_bpf() raises:
    var base = check_unprivileged_bpf(
        open_evidence_reader(gate(String("base")))
    )
    assert_equal(base.state, String("unknown"))
    var two = check_unprivileged_bpf(
        open_evidence_reader(gate(String("unpriv-bpf")))
    )
    assert_equal(two.state, String("pass"))
    assert_equal(two.reason, String("unprivileged_bpf_disabled=2"))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_object_map_bytes]()
    suite.test[test_privilege]()
    suite.test[test_privilege_reason_has_no_raw_mask]()
    suite.test[test_capeff_malformed]()
    suite.test[test_memcg_ancestor_min]()
    suite.test[test_memcg_shortfall_unknown]()
    suite.test[test_memcg_root_unknown]()
    suite.test[test_privilege_userns_unknown]()
    suite.test[test_memcg_malformed]()
    suite.test[test_prechecks_denied_unknown]()
    suite.test[test_unprivileged_bpf]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
