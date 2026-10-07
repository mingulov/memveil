# SPDX-License-Identifier: GPL-3.0-or-later

"""Adversarial reader tests: exact boundaries, hostile bytes.

Capture-level consolidation of the untrusted-input contract:
exact 64 KiB line and depth boundaries, malformed UTF-8, NUL,
duplicate keys, unknown fields, integer spelling and range,
duplicate and reversed sequences, foreign sessions, and
u64-sum overflow. Every hostile capture is refused with an
exact code and line; nothing is repaired or skipped.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal

from memveil.capture.reader import (
    READ_INVALID,
    READ_PARSE,
    READ_TOO_BIG,
    CaptureReader,
    ReadError,
    ReaderLimits,
    default_limits,
    read_capture,
)
from memveil.model.event import Event


def drain_events(mut r: CaptureReader) raises ReadError -> List[Event]:
    var out = List[Event]()
    while r.has_more():
        out.append(r.next_event())
    return out^


def expect_read_error(
    dir: String,
    allow: Bool,
    limits: ReaderLimits,
    want_code: UInt32,
    want_line: Int,
) raises:
    var code = UInt32(0)
    var line = -1
    try:
        var r = read_capture(dir, allow, limits)
        _ = drain_events(r)
    except e:
        code = e.code
        line = e.line_no
    assert_equal(code, want_code)
    assert_equal(line, want_line)


def test_exact_line_boundary() raises:
    var limits = default_limits()
    expect_read_error(
        String("tests/fixtures/reader/size-ok"), False, limits,
        READ_PARSE, 1,
    )
    expect_read_error(
        String("tests/fixtures/reader/size-over"), False, limits,
        READ_TOO_BIG, 1,
    )


def test_malformed_utf8_refused() raises:
    expect_read_error(
        String("tests/fixtures/reader/adv-bad-utf8"), False,
        default_limits(), READ_PARSE, 1,
    )


def test_nul_byte_refused() raises:
    expect_read_error(
        String("tests/fixtures/reader/adv-nul"), False,
        default_limits(), READ_PARSE, 1,
    )


def test_duplicate_sequence_refused() raises:
    expect_read_error(
        String("tests/fixtures/reader/badseq"), False,
        default_limits(), READ_INVALID, 2,
    )


def test_reversed_sequence_refused() raises:
    expect_read_error(
        String("tests/fixtures/reader/adv-reversed-seq"), False,
        default_limits(), READ_INVALID, 2,
    )


def test_foreign_session_refused() raises:
    expect_read_error(
        String("tests/fixtures/reader/foreign"), False,
        default_limits(), READ_INVALID, 1,
    )


def test_depth_boundaries_rejected() raises:
    var limits = default_limits()
    expect_read_error(
        String("tests/fixtures/reader/adv-depth-64"), False, limits,
        READ_PARSE, 1,
    )
    expect_read_error(
        String("tests/fixtures/reader/adv-depth-65"), False, limits,
        READ_PARSE, 1,
    )


def test_unknown_field_refused() raises:
    expect_read_error(
        String("tests/fixtures/reader/adv-unknown-field"), False,
        default_limits(), READ_PARSE, 1,
    )


def test_duplicate_keys_refused() raises:
    # Three valid lines, then an unterminated tail repeating
    # "seq": the duplicate key is definitive on line 4.
    expect_read_error(
        String("tests/fixtures/reader/f4-definitive-dupkey"), False,
        default_limits(), READ_PARSE, 4,
    )


def test_integer_spelling_refused() raises:
    expect_read_error(
        String("tests/fixtures/reader/adv-bad-seq-int"), False,
        default_limits(), READ_PARSE, 1,
    )


def test_u64_sum_overflow_refused() raises:
    var limits = default_limits()
    expect_read_error(
        String("tests/fixtures/reader/overflow"), False, limits,
        READ_INVALID, 2,
    )
    expect_read_error(
        String("tests/fixtures/reader/f3-sum-overflow"), False, limits,
        READ_INVALID, 2,
    )


def test_unknown_major_refused() raises:
    expect_read_error(
        String("tests/fixtures/reader/compat-major"), False,
        default_limits(), READ_PARSE, 0,
    )


def test_unsupported_kind_refused() raises:
    expect_read_error(
        String("tests/fixtures/reader/badkind"), False,
        default_limits(), READ_PARSE, 1,
    )


def test_duplicate_operation_refused() raises:
    expect_read_error(
        String("tests/fixtures/reader/f2-duplicate-op"), False,
        default_limits(), READ_INVALID, 2,
    )


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_exact_line_boundary]()
    suite.test[test_malformed_utf8_refused]()
    suite.test[test_nul_byte_refused]()
    suite.test[test_duplicate_sequence_refused]()
    suite.test[test_reversed_sequence_refused]()
    suite.test[test_foreign_session_refused]()
    suite.test[test_depth_boundaries_rejected]()
    suite.test[test_unknown_field_refused]()
    suite.test[test_duplicate_keys_refused]()
    suite.test[test_integer_spelling_refused]()
    suite.test[test_u64_sum_overflow_refused]()
    suite.test[test_unknown_major_refused]()
    suite.test[test_unsupported_kind_refused]()
    suite.test[test_duplicate_operation_refused]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
