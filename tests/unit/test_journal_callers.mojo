# SPDX-License-Identifier: GPL-3.0-or-later
from std.testing import TestSuite, assert_equal, assert_true
from memveil.capture.journal_callers import resolve_caller_ranges


def test_bounded_allowlisted_symbols() raises:
    var table = resolve_caller_ranges(String("0000000000000010 T dma_direct_alloc\n0000000000000020 T next_symbol\n"), False)
    assert_equal(table[8].start, UInt64(16))
    assert_equal(table[8].end, UInt64(32))
    assert_true(not table[8].ambiguous)
    table = resolve_caller_ranges(String("0000000000000010 T dma_direct_alloc\n0000000000000010 T alias\n0000000000000020 T next_symbol\n"), False)
    assert_true(table[8].ambiguous)
    table = resolve_caller_ranges(String("0000000000000010 T dma_direct_alloc\n0000000000000020 T next_symbol\n0000000000000010 T alias\n"), False)
    assert_true(table[8].ambiguous)
    table = resolve_caller_ranges(String("0000000000000010 t mv_command_set [memveil_region_oracle]\n0000000000000020 t next [memveil_region_oracle]\n"), False)
    assert_equal(table[0].start, UInt64(0))
    table = resolve_caller_ranges(String("0000000000000010 t mv_command_set [memveil_region_oracle]\n0000000000000020 t next [memveil_region_oracle]\n"), True)
    assert_equal(table[0].start, UInt64(16))
    assert_equal(table[0].end, UInt64(32))
    table = resolve_caller_ranges(String("0000000000000000 T dma_direct_alloc\n0000000000000000 T next\n"), True)
    assert_equal(table[8].start, UInt64(0))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
