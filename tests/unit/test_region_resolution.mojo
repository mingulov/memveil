# SPDX-License-Identifier: GPL-3.0-or-later

"""Range resolution tests: proved spans only, never guesses.

A contiguous virtual range with unproved physical relation
resolves to unavailable, never to a fabricated physical span.
A recycled identity resolves only under its admitted
generation; a mismatched namespace never matches an
admission; only an explicitly admitted proven span yields
physical_span. Identity-only tokens stay identity_only and
can never form a physical union. There is no address
arithmetic path: the same numeric offsets under two
namespaces resolve to distinct references.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.regions import (
    AdmittedMapping,
    RawRange,
    resolve_region,
)
from memveil.model.regions import RegionReference


def _raw(
    identity: String, namespace: String, generation: Int
) -> RawRange:
    var r = RawRange()
    r.identity = identity
    r.namespace = namespace
    r.offset = UInt64(4096)
    r.length = UInt64(4096)
    r.generation = generation
    return r^


def _admitted(
    identity: String, namespace: String, generation: Int,
    proven: Bool,
) -> AdmittedMapping:
    var m = AdmittedMapping()
    m.identity = identity
    m.namespace = namespace
    m.generation = generation
    m.proven_span = proven
    return m^


def _admissions() -> List[AdmittedMapping]:
    var out = List[AdmittedMapping]()
    out.append(_admitted(String("pool-a"), String("guest_physical"), 1, True))
    out.append(_admitted(String("pool-b"), String("guest_physical"), 1, False))
    return out^


def test_proven_span_resolves() raises:
    var got = resolve_region(
        _raw(String("pool-a"), String("guest_physical"), 1),
        _admissions(),
    )
    assert_equal(got.resolution, String("physical_span"))
    assert_equal(got.namespace, String("guest_physical"))
    assert_equal(got.identity, String("pool-a"))
    assert_equal(got.offset, UInt64(4096))
    assert_equal(got.length, UInt64(4096))
    assert_equal(got.generation, 1)


def test_unproved_stays_identity_only() raises:
    var got = resolve_region(
        _raw(String("pool-b"), String("guest_physical"), 1),
        _admissions(),
    )
    assert_equal(got.resolution, String("identity_only"))


def test_unknown_identity_unavailable() raises:
    var got = resolve_region(
        _raw(String("pool-z"), String("guest_physical"), 1),
        _admissions(),
    )
    assert_equal(got.resolution, String("unavailable"))


def test_recycled_identity_unavailable() raises:
    var got = resolve_region(
        _raw(String("pool-a"), String("guest_physical"), 2),
        _admissions(),
    )
    assert_equal(got.resolution, String("unavailable"))


def test_mismatched_namespace_unavailable() raises:
    var got = resolve_region(
        _raw(String("pool-a"), String("kernel_virtual"), 1),
        _admissions(),
    )
    assert_equal(got.resolution, String("unavailable"))


def test_identity_only_never_physical() raises:
    var got = resolve_region(
        _raw(String("pool-a"), String("identity_only"), 1),
        _admissions(),
    )
    assert_equal(got.resolution, String("identity_only"))


def test_namespaces_never_merge() raises:
    var g = resolve_region(
        _raw(String("pool-a"), String("guest_physical"), 1),
        _admissions(),
    )
    var k = resolve_region(
        _raw(String("pool-a"), String("kernel_virtual"), 1),
        _admissions(),
    )
    assert_true(g.key() != k.key())


def test_reference_checked() raises:
    var got = RegionReference.checked(
        String("guest_physical"), String("physical_span"),
        String("r1"), UInt64(0), UInt64(4096), 1,
    )
    assert_equal(got.resolution, String("physical_span"))
    var bad = 0
    try:
        _ = RegionReference.checked(
            String("gphys"), String("physical_span"), String("r1"),
            UInt64(0), UInt64(4096), 1,
        )
    except:
        bad += 1
    try:
        _ = RegionReference.checked(
            String("guest_physical"), String("resolved"), String("r1"),
            UInt64(0), UInt64(4096), 1,
        )
    except:
        bad += 1
    try:
        _ = RegionReference.checked(
            String("guest_physical"), String("physical_span"),
            String(""), UInt64(0), UInt64(4096), 1,
        )
    except:
        bad += 1
    try:
        _ = RegionReference.checked(
            String("guest_physical"), String("physical_span"),
            String("r1"), UInt64(0), UInt64(4096), 0,
        )
    except:
        bad += 1
    assert_equal(bad, 4)


def test_resolve_rejects_bad_input() raises:
    var bad = 0
    var r = _raw(String(""), String("guest_physical"), 1)
    try:
        _ = resolve_region(r, _admissions())
    except:
        bad += 1
    r = _raw(String("pool-a"), String("nope"), 1)
    try:
        _ = resolve_region(r, _admissions())
    except:
        bad += 1
    r = _raw(String("pool-a"), String("guest_physical"), 1)
    r.offset = ~UInt64(0)
    r.length = UInt64(1)
    try:
        _ = resolve_region(r, _admissions())
    except:
        bad += 1
    assert_equal(bad, 3)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_proven_span_resolves]()
    suite.test[test_unproved_stays_identity_only]()
    suite.test[test_unknown_identity_unavailable]()
    suite.test[test_recycled_identity_unavailable]()
    suite.test[test_mismatched_namespace_unavailable]()
    suite.test[test_identity_only_never_physical]()
    suite.test[test_namespaces_never_merge]()
    suite.test[test_reference_checked]()
    suite.test[test_resolve_rejects_bad_input]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
