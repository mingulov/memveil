# SPDX-License-Identifier: GPL-3.0-or-later

"""BTF map-definition reads from BPF objects."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.btf import read_btf_maps
from memveil.platform.reader import read_host_file


def _read_fixture(path: String) raises -> List[UInt8]:
    return read_host_file(path, String("fixture"), 67108864)


def test_btf_ok() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/ok.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(v.ok)
    assert_equal(v.message, String(""))
    assert_equal(v.ring_bytes, 8388608)


def test_btf_badring() raises:
    # A smaller but sane ring passes the static read; only
    # the identity binding pins the exact expected value.
    var raw = _read_fixture(String("tests/fixtures/elf/badring.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(v.ok)
    assert_equal(v.ring_bytes, 4194304)


def test_btf_badmap() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/badmap.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("counts max_entries 7, want 6"))


def test_btf_nobtf() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/nobtf.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("no BTF section"))


def test_btf_extern() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/extern.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("counts linkage 2"))


def test_btf_tiny() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/tiny.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("no BTF section"))


def test_btf_nodatasec() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/nodatasec.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("no maps DATASEC"))


def test_btf_unlisted() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/unlisted.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("counts not in maps DATASEC"))


def test_btf_dupvar() raises:
    var raw = _read_fixture(String("tests/fixtures/elf/dupvar.o"))
    var v = read_btf_maps(Span(raw))
    assert_true(not v.ok)
    assert_equal(v.message, String("duplicate mv_counts"))


def test_btf_inline_edges() raises:
    var empty = List[UInt8]()
    var v = read_btf_maps(Span(empty))
    assert_true(not v.ok)
    assert_equal(v.message, String("no BTF section"))
    var text = String("not an object\n")
    var w = read_btf_maps(text.as_bytes())
    assert_true(not w.ok)
    assert_equal(w.message, String("no BTF section"))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_btf_ok]()
    suite.test[test_btf_badring]()
    suite.test[test_btf_badmap]()
    suite.test[test_btf_nobtf]()
    suite.test[test_btf_extern]()
    suite.test[test_btf_tiny]()
    suite.test[test_btf_nodatasec]()
    suite.test[test_btf_unlisted]()
    suite.test[test_btf_dupvar]()
    suite.test[test_btf_inline_edges]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
