# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent request-only wire and selector contract checks."""
from std.testing import TestSuite, assert_equal, assert_true
from memveil.model.common import MaybeU64
from memveil.model.journal import (
    decode_journal, select_journal, classify_caller, requested_bytes,
    next_operation_token, validate_membership, OPERATION_CAPACITY, NESTING_CAPACITY,
    journal_admission, REPLAY_TOKEN_INTERVAL_CAPACITY, JournalWindow,
)


def test_selection() raises:
    var ordinary = select_journal(String(""), False, False)
    assert_true(ordinary.attempts and not ordinary.journal)
    var journal = select_journal(String("conversion-journal"), False, False)
    assert_true(journal.journal and not journal.attempts and not journal.callers)
    var mixed = select_journal(String("conversion-journal,copy-actual"), True, False)
    assert_true(mixed.journal and mixed.attempts and mixed.callers)
    for bad in [String("unknown"), String("conversion-journal,conversion-journal")]:
        var rejected = False
        try:
            _ = select_journal(bad, False, False)
        except:
            rejected = True
        assert_true(rejected)
    var rejected = False
    try:
        _ = select_journal(String("conversion-journal"), False, True)
    except:
        rejected = True
    assert_true(rejected)
    rejected = False
    try:
        _ = select_journal(String(""), True, False)
    except:
        rejected = True
    assert_true(rejected)


def test_admission_without_attempt_source() raises:
    var journal = select_journal(String("conversion-journal"), False, False)
    var decision = journal_admission(journal, False, String("admitted"), False)
    assert_equal(decision.exit_code, 0)
    assert_equal(decision.reason, String("ready_for_attachment"))
    for status in [String("provisional"), String("unadmitted"), String("unknown")]:
        decision = journal_admission(journal, True, status, True)
        assert_equal(decision.exit_code, 3)
        assert_equal(decision.reason, String("journal_profile_not_admitted"))
    var mixed = select_journal(String("copy-actual,conversion-journal"), False, False)
    for attempts, admitted, expected in [(False, False, 3), (True, False, 3), (False, True, 3), (True, True, 0)]:
        var status = String("unadmitted")
        if admitted:
            status = String("admitted")
        decision = journal_admission(mixed, attempts, status, True)
        assert_equal(decision.exit_code, expected)
    var callers = select_journal(String("conversion-journal"), True, False)
    decision = journal_admission(callers, False, String("admitted"), False)
    assert_equal(decision.exit_code, 3)
    assert_equal(decision.reason, String("journal_callers_not_admitted"))
    var ordinary = select_journal(String(""), False, False)
    decision = journal_admission(ordinary, True, String("unknown"), False)
    assert_equal(decision.exit_code, 0)
    decision = journal_admission(ordinary, False, String("admitted"), True)
    assert_equal(decision.exit_code, 3)
    assert_equal(decision.reason, String("attempts_not_admitted"))


def test_counts_and_classification() raises:
    assert_equal(requested_bytes(Int32(2147483647), UInt64(4096)), UInt64(8796093018112))
    assert_equal(classify_caller(False, False, 0, 1), 0)
    assert_equal(classify_caller(True, True, 1, 1), 4)
    assert_equal(classify_caller(True, False, 2, 1), 3)
    assert_equal(classify_caller(True, False, 0, 0), 2)
    assert_equal(classify_caller(True, False, 1, 1), 1)
    var rejected = False
    try:
        _ = requested_bytes(Int32(-1), UInt64(4096))
    except:
        rejected = True
    assert_true(rejected)


def _wire() -> List[UInt8]:
    var data = List[UInt8]()
    for _ in range(72):
        data.append(0)
    data[0] = 77
    data[1] = 86
    data[2] = 74
    data[3] = 82
    data[4] = 1
    data[6] = 1
    data[8] = 1
    data[10] = 1
    data[24] = 30
    data[32] = 1
    data[40] = 9
    data[48] = 20
    data[56] = 3
    return data^


def test_wire() raises:
    var data = _wire()
    var result = decode_journal(data)
    assert_equal(result.token, UInt64(9))
    assert_equal(result.pages, Int32(3))
    assert_equal(result.native_result, Int32(0))
    assert_equal(result.entry_ns, UInt64(20))
    data[60] = 251
    data[61] = 255
    data[62] = 255
    data[63] = 255
    result = decode_journal(data)
    assert_equal(result.native_result, Int32(-5))
    for offset in [4, 6, 8, 10, 64, 66, 68, 70]:
        var invalid = _wire()
        invalid[offset] = 255
        var rejected = False
        try:
            _ = decode_journal(invalid)
        except:
            rejected = True
        assert_true(rejected)
    data = _wire()
    data[40] = 1
    data[46] = 32
    var large = decode_journal(data)
    assert_equal(large.token, UInt64(9007199254740993))
    data[46] = 0
    data[40] = 0
    var rejected = False
    try:
        _ = decode_journal(data)
    except:
        rejected = True
    assert_true(rejected)


def test_budgets_and_window() raises:
    assert_equal(OPERATION_CAPACITY, 4096)
    assert_equal(NESTING_CAPACITY, 8)
    assert_equal(REPLAY_TOKEN_INTERVAL_CAPACITY, 65536)
    assert_equal(next_operation_token(UInt64(1), 4095, 7), UInt64(2))
    for capacity, depth in [(4096, 7), (4095, 8), (-1, 0)]:
        var rejected = False
        try:
            _ = next_operation_token(UInt64(1), capacity, depth)
        except:
            rejected = True
        assert_true(rejected)
    var rejected = False
    try:
        _ = next_operation_token(UInt64(18446744073709551614), 0, 0)
    except:
        rejected = True
    assert_true(rejected)
    var result = decode_journal(_wire())
    validate_membership(result, UInt64(1), UInt64(20), UInt64(25), UInt64(31))
    for epoch, start, cutoff, end in [(2, 20, 25, 31), (1, 21, 25, 31), (1, 20, 20, 31), (1, 20, 25, 30)]:
        rejected = False
        try:
            validate_membership(result, UInt64(epoch), UInt64(start), UInt64(cutoff), UInt64(end))
        except:
            rejected = True
        assert_true(rejected)


def test_nullable_checkpoint_window() raises:
    var start = MaybeU64()
    var end = MaybeU64()
    var initial = JournalWindow(UInt64(1), UInt64(10), UInt64(31), start, end, String("not_opened"), String("not_opened"), False)
    initial.validate()
    var rejected = False
    try:
        initial.validate_result(decode_journal(_wire()))
    except:
        rejected = True
    assert_true(rejected)
    start.has = True
    start.value = 20
    var opened = JournalWindow(UInt64(1), UInt64(10), UInt64(31), start, end, String(""), String("admission_open"), False)
    opened.validate_result(decode_journal(_wire()))
    opened.finalized = True
    rejected = False
    try:
        opened.validate()
    except:
        rejected = True
    assert_true(rejected)
    opened.end_reason = String("close_unproved")
    opened.validate_result(decode_journal(_wire()))
    opened.cutoff.has = True
    opened.cutoff.value = 25
    opened.end_reason = String("")
    opened.validate_result(decode_journal(_wire()))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
