# SPDX-License-Identifier: GPL-3.0-or-later

"""Tracefs format discovery: parse live layouts, diff against known-good."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.narrow import (
    TraceFormat,
    diff_trace_format,
    known_trace_format,
    parse_trace_format,
)


def _good_format() -> String:
    var out = String("name: swiotlb_bounced\nID: 382\nformat:\n")
    out += String("\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n")
    out += String("\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n")
    out += String("\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n")
    out += String("\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n")
    out += String("\n")
    out += String("\tfield:__data_loc char[] dev_name;\toffset:8;\tsize:4;\tsigned:0;\n")
    out += String("\tfield:u64 dma_mask;\toffset:16;\tsize:8;\tsigned:0;\n")
    out += String("\tfield:dma_addr_t dev_addr;\toffset:24;\tsize:8;\tsigned:0;\n")
    out += String("\tfield:size_t size;\toffset:32;\tsize:8;\tsigned:0;\n")
    out += String("\tfield:bool force;\toffset:40;\tsize:1;\tsigned:0;\n")
    out += String("\nprint fmt: \"dev_name: %s\"\n")
    return out^


def test_parse_good_format() raises:
    var text = _good_format()
    var layout = parse_trace_format(text.as_bytes())
    assert_true(layout.ok)
    assert_equal(len(layout.fields), 9)
    assert_equal(layout.fields[0].name, String("common_type"))
    assert_equal(layout.fields[4].name, String("dev_name"))
    assert_equal(layout.fields[4].ftype, String("__data_loc char[]"))
    assert_equal(layout.fields[4].offset, 8)
    assert_equal(layout.fields[4].size, 4)
    assert_equal(layout.fields[8].name, String("force"))


def test_parse_unparseable_line() raises:
    var text = _good_format() + String("\tfield:bogus\n")
    var layout = parse_trace_format(text.as_bytes())
    assert_true(not layout.ok)
    assert_equal(layout.message, String("format line unparseable"))


def test_parse_duplicate_field() raises:
    var text = _good_format() + String(
        "\tfield:bool force;\toffset:40;\tsize:1;\tsigned:0;\n"
    )
    var layout = parse_trace_format(text.as_bytes())
    assert_true(not layout.ok)
    assert_equal(layout.message, String("duplicate field force"))


def _without_force() -> String:
    var out = String("name: swiotlb_bounced\nID: 382\nformat:\n")
    out += String("\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n")
    out += String("\tfield:__data_loc char[] dev_name;\toffset:8;\tsize:4;\tsigned:0;\n")
    out += String("\tfield:size_t size;\toffset:32;\tsize:8;\tsigned:0;\n")
    return out^


def _moved_size() -> String:
    var out = String("name: swiotlb_bounced\nID: 382\nformat:\n")
    out += String("\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n")
    out += String("\tfield:__data_loc char[] dev_name;\toffset:8;\tsize:4;\tsigned:0;\n")
    out += String("\tfield:size_t size;\toffset:40;\tsize:8;\tsigned:0;\n")
    out += String("\tfield:bool force;\toffset:48;\tsize:1;\tsigned:0;\n")
    return out^


def _retyped_force() -> String:
    var out = String("name: swiotlb_bounced\nID: 382\nformat:\n")
    out += String("\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n")
    out += String("\tfield:__data_loc char[] dev_name;\toffset:8;\tsize:4;\tsigned:0;\n")
    out += String("\tfield:size_t size;\toffset:32;\tsize:8;\tsigned:0;\n")
    out += String("\tfield:u8 force;\toffset:40;\tsize:1;\tsigned:0;\n")
    return out^


def test_diff_identical_is_empty() raises:
    var text = _good_format()
    var live = parse_trace_format(text.as_bytes())
    assert_true(live.ok)
    var known = known_trace_format()
    assert_equal(diff_trace_format(known, live), String(""))


def test_diff_missing_field() raises:
    var text = _without_force()
    var live = parse_trace_format(text.as_bytes())
    assert_true(live.ok)
    var known = known_trace_format()
    assert_equal(
        diff_trace_format(known, live), String("missing field force")
    )


def test_diff_moved_offset() raises:
    var text = _moved_size()
    var live = parse_trace_format(text.as_bytes())
    assert_true(live.ok)
    var known = known_trace_format()
    assert_equal(
        diff_trace_format(known, live),
        String("field size: want @32:8, live @40:8"),
    )


def test_diff_retyped_field() raises:
    var text = _retyped_force()
    var live = parse_trace_format(text.as_bytes())
    assert_true(live.ok)
    var known = known_trace_format()
    assert_equal(
        diff_trace_format(known, live),
        String("field force: want type bool, live u8"),
    )


def test_parse_empty_input() raises:
    var text = String("")
    var layout = parse_trace_format(text.as_bytes())
    assert_true(layout.ok)
    assert_equal(len(layout.fields), 0)


def test_parse_huge_offset_refused() raises:
    var text = String(
        "field:size_t size;\toffset:12345678901;\tsize:8;\tsigned:0;\n"
    )
    var layout = parse_trace_format(text.as_bytes())
    assert_true(not layout.ok)
    assert_equal(layout.message, String("format line unparseable"))


def test_parse_unterminated_final_line() raises:
    var text = String("field:int common_pid;\toffset:4;\tsize:4;\tsigned:0;")
    var layout = parse_trace_format(text.as_bytes())
    assert_true(layout.ok)
    assert_equal(len(layout.fields), 1)
    assert_equal(layout.fields[0].name, String("common_pid"))


def test_parse_data_loc_variant() raises:
    var text = String(
        "field:__data_loc unsigned char[] name;\toffset:8;\tsize:4;\tsigned:0;\n"
    )
    var layout = parse_trace_format(text.as_bytes())
    assert_true(layout.ok)
    assert_equal(layout.fields[0].ftype, String("__data_loc unsigned char[]"))


def test_parse_nul_name_refused() raises:
    var line = String("field:int ab;\toffset:0;\tsize:4;\tsigned:0;\n")
    var raw = List[UInt8]()
    for b in line.as_bytes():
        raw.append(b)
    raw[11] = UInt8(0)
    var layout = parse_trace_format(Span(raw))
    assert_true(not layout.ok)
    assert_equal(layout.message, String("format line unparseable"))


def test_diff_size_only_drift() raises:
    var text = String("name: swiotlb_bounced\nID: 382\nformat:\n")
    text += String("\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n")
    text += String("\tfield:__data_loc char[] dev_name;\toffset:8;\tsize:4;\tsigned:0;\n")
    text += String("\tfield:size_t size;\toffset:32;\tsize:4;\tsigned:0;\n")
    text += String("\tfield:bool force;\toffset:40;\tsize:1;\tsigned:0;\n")
    var live = parse_trace_format(text.as_bytes())
    assert_true(live.ok)
    var known = known_trace_format()
    assert_equal(
        diff_trace_format(known, live),
        String("field size: want @32:8, live @32:4"),
    )


def test_diff_invalid_inputs() raises:
    var bad = TraceFormat()
    var text = _good_format()
    var live = parse_trace_format(text.as_bytes())
    assert_true(live.ok)
    assert_equal(
        diff_trace_format(bad, live), String("want layout invalid")
    )
    var broken_text = String("field:bogus\n")
    var broken = parse_trace_format(broken_text.as_bytes())
    assert_true(not broken.ok)
    var known = known_trace_format()
    assert_equal(
        diff_trace_format(known, broken),
        String("live layout invalid: format line unparseable"),
    )


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_parse_good_format]()
    suite.test[test_parse_unparseable_line]()
    suite.test[test_parse_duplicate_field]()
    suite.test[test_diff_identical_is_empty]()
    suite.test[test_diff_missing_field]()
    suite.test[test_diff_moved_offset]()
    suite.test[test_diff_retyped_field]()
    suite.test[test_parse_empty_input]()
    suite.test[test_parse_huge_offset_refused]()
    suite.test[test_parse_unterminated_final_line]()
    suite.test[test_parse_data_loc_variant]()
    suite.test[test_parse_nul_name_refused]()
    suite.test[test_diff_size_only_drift]()
    suite.test[test_diff_invalid_inputs]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
