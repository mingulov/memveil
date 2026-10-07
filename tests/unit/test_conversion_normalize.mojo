# SPDX-License-Identifier: GPL-3.0-or-later

"""Conversion normalization tests: transition vectors in, facts out.

Each vector file under tests/fixtures/conversions holds one
transition_result record. Success, integer failure, unavailable
return, unresolved range, and missing range identity all parse
with their request fields intact: the tracker counts requests
even when state inference is unavailable. Malformed lengths,
span overflow, bad enums, duplicate keys, missing fields, and
mistyped return codes are refused. No failure implies atomic
rollback: that proof has no wire representation.
"""

from std.pathlib import Path
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.model.event import Event, parse_event


def _read(rel: String) raises -> List[UInt8]:
    return Path(rel).read_bytes()


def _parse_vector(name: String) raises -> Event:
    return parse_event(
        _read(String("tests/fixtures/conversions/") + name)
    )


def _expect_reject(name: String, needle: String) raises:
    var raised = False
    try:
        _ = _parse_vector(name)
    except e:
        raised = True
        assert_true(String(e).find(needle) != -1)
    assert_true(raised)


def test_success_vector() raises:
    var ev = _parse_vector(String("events.ndjson"))
    assert_equal(ev.kind, String("transition_result"))
    assert_equal(ev.transition.region_id, "r1")
    assert_equal(ev.transition.requested_state, "shared")
    assert_true(ev.transition.success)
    assert_true(ev.transition.has_return_code)
    assert_equal(ev.transition.return_code, Int64(0))
    assert_equal(ev.transition.offset, UInt64(0))
    assert_equal(ev.transition.length, UInt64(8192))
    assert_true(ev.transition.has_address_space)
    assert_equal(ev.transition.address_space, "guest_physical")
    assert_true(ev.transition.has_resolution)
    assert_equal(ev.transition.resolution, "resolved")


def test_failure_int_vector() raises:
    var ev = _parse_vector(String("vector-failure-int.ndjson"))
    assert_true(not ev.transition.success)
    assert_true(ev.transition.has_return_code)
    assert_equal(ev.transition.return_code, Int64(-5))
    assert_equal(ev.transition.length, UInt64(4096))


def test_failure_unavailable_vector() raises:
    var ev = _parse_vector(String("vector-failure-unavailable.ndjson"))
    assert_true(not ev.transition.success)
    assert_true(not ev.transition.has_return_code)
    assert_equal(ev.transition.requested_state, "private")


def test_unresolved_vector() raises:
    var ev = _parse_vector(String("vector-unresolved.ndjson"))
    assert_true(ev.transition.success)
    assert_true(ev.transition.has_address_space)
    assert_equal(ev.transition.address_space, "identity_only")
    assert_true(ev.transition.has_resolution)
    assert_equal(ev.transition.resolution, "unresolved")


def test_missing_range_vector() raises:
    var ev = _parse_vector(String("vector-missing-range.ndjson"))
    assert_true(ev.transition.success)
    assert_true(not ev.transition.has_address_space)
    assert_true(not ev.transition.has_resolution)
    assert_equal(ev.transition.length, UInt64(2048))


def test_noop_vector() raises:
    var ev = _parse_vector(String("vector-noop.ndjson"))
    assert_true(ev.transition.success)
    assert_equal(ev.transition.requested_state, "shared")
    assert_equal(ev.transition.length, UInt64(8192))


def test_reject_overflow() raises:
    _expect_reject(
        String("reject-overflow.ndjson"),
        String("span overflows"),
    )


def test_reject_bad_enum() raises:
    _expect_reject(
        String("reject-bad-enum.ndjson"),
        String("bad enum"),
    )


def test_reject_dup_key() raises:
    _expect_reject(
        String("reject-dup-key.ndjson"), String("duplicate")
    )


def test_reject_missing_field() raises:
    _expect_reject(
        String("reject-missing-field.ndjson"),
        String("missing field"),
    )


def test_reject_bad_return() raises:
    _expect_reject(
        String("reject-bad-return.ndjson"),
        String("bad integer"),
    )


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_success_vector]()
    suite.test[test_failure_int_vector]()
    suite.test[test_failure_unavailable_vector]()
    suite.test[test_unresolved_vector]()
    suite.test[test_missing_range_vector]()
    suite.test[test_noop_vector]()
    suite.test[test_reject_overflow]()
    suite.test[test_reject_bad_enum]()
    suite.test[test_reject_dup_key]()
    suite.test[test_reject_missing_field]()
    suite.test[test_reject_bad_return]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
