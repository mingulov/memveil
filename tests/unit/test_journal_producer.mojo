# SPDX-License-Identifier: GPL-3.0-or-later
from std.testing import TestSuite, assert_equal, assert_true
from memveil.platform.reader import read_host_file
from memveil.capture.journal_kernel import journal_attach_specs, JournalKernel
from memveil.capture.conversions import JournalCapture, encode_journal_control, decode_journal_counters
from memveil.model.event import parse_event
from memveil.model.session import parse_session
from memveil.model.encode import encode_event_line, encode_session


def test_frozen_journal_event_and_session() raises:
    var raw = read_host_file(String("tests/fixtures/journal/success/events.ndjson"), String("fixture"), 65536)
    var event = parse_event(raw)
    assert_equal(event.kind, String("transition_result"))
    var again = parse_event(encode_event_line(event))
    assert_equal(again.seq, UInt64(0))
    raw = read_host_file(String("tests/fixtures/journal/success/session.json"), String("fixture"), 16777216)
    var session = parse_session(raw)
    var encoded = encode_session(session)
    assert_true(encoded.find('"schema_version":"0.2.0"') >= 0)



def test_all_frozen_windows_and_signed_results() raises:
    for name in [String("success"), String("failure"), String("orphan-encrypt"), String("overlap"), String("pre-attach"), String("unresolved"), String("disabled"), String("persistent"), String("invalid-pages"), String("initial-checkpoint"), String("open-checkpoint"), String("censored")]:
        var base = String("tests/fixtures/journal/") + name + "/"
        var checkpoint = name == "initial-checkpoint" or name == "open-checkpoint"
        var path = base + (String("checkpoint.json") if checkpoint else String("session.json"))
        var session = parse_session(read_host_file(path, String("fixture"), 16777216))
        assert_true(session.has_journal)
        var encoded = encode_session(session)
        var raw = List[UInt8]()
        raw.extend(encoded.as_bytes())
        var roundtrip = parse_session(raw)
        assert_equal(roundtrip.journal.epoch, session.journal.epoch)
        var data = read_host_file(base + "events.ndjson", String("fixture"), 16777216)
        var lines = String(from_utf8=Span(data))
        for line in lines.split("\n"):
            if line.byte_length() == 0:
                continue
            var event_bytes = List[UInt8]()
            event_bytes.extend(line.as_bytes())
            var event = parse_event(event_bytes)
            assert_true(event.has_journal and event.journal_version)
            var again = parse_event(encode_event_line(event))
            assert_equal(again.journal.native_result, event.journal.native_result)
            assert_equal(again.journal.requested_native_pages, event.journal.requested_native_pages)
            assert_equal(again.journal.operation_token.has, event.journal.operation_token.has)
            var window = session.journal.window(session.window_start_ns, session.finalized)
            window.validate_result(event.journal.to_result(event.ts_ns))


def test_normalization_sequence_and_unknown_counters() raises:
    var capture = JournalCapture(UInt64(23), UInt64(10))
    var counters = List[UInt64](length=15, fill=UInt64(0))
    var initial = capture.snapshot(UInt64(11), False, counters, True)
    assert_true(not initial.admission_start_ns.has and not initial.counters[4].has)
    assert_true(not initial.counters[10].has)
    capture.opened(UInt64(12))
    var raw = List[UInt8](length=72, fill=UInt8(0))
    raw[0]=77; raw[1]=86; raw[2]=74; raw[3]=82
    raw[4]=1; raw[6]=1; raw[8]=1; raw[10]=1
    raw[24]=30; raw[32]=23; raw[40]=9; raw[48]=20; raw[56]=3
    raw[60]=251; raw[61]=255; raw[62]=255; raw[63]=255
    var event = capture.consume(raw, String("capture"), UInt64(31))
    assert_equal(event.journal.native_result, Int32(-5))
    assert_equal(event.journal.requested_bytes.value, UInt64(12288))
    assert_equal(event.source_correlation, String("unpaired"))
    var refused = False
    try:
        _ = capture.consume(raw, String("capture"), UInt64(31))
    except:
        refused = True
    assert_true(refused)
    capture.closed(UInt64(32), True)
    raw[16]=3; raw[24]=40
    event = capture.consume(raw, String("capture"), UInt64(41))
    assert_equal(capture.sequence_gaps, UInt64(2))
    counters[12]=5; counters[4]=2
    var final = capture.snapshot(UInt64(42), True, counters, True)
    assert_equal(final.counters[4].value, UInt64(7))
    assert_equal(final.closure, String("unproved"))
    assert_true(not final.counters[10].has)
    var failed = capture.snapshot(UInt64(42), True, counters, False)
    assert_true(not failed.counters[4].has)
    assert_equal(failed.counter_reasons[4], String("read_failed"))
    counters[11]=UInt64(1)
    var overflow = capture.snapshot(UInt64(42), True, counters, True)
    assert_true(not overflow.counters[0].has)
    assert_equal(overflow.counter_reasons[0], String("overflow"))
    var control = encode_journal_control(UInt64(23), UInt64(12), UInt64(32), False, True, False)
    assert_equal(len(control), 48)
    assert_equal(control[32], UInt8(1))
    refused = False
    try:
        _ = decode_journal_counters(control)
    except:
        refused = True
    assert_true(refused)


def test_native_adapter_refuses_without_resources() raises:
    var specs = journal_attach_specs()
    assert_equal(len(specs), 4)
    assert_equal(specs[0].program, String("mv_jr_dec_exit"))
    assert_equal(specs[1].program, String("mv_jr_enc_exit"))
    assert_equal(specs[2].program, String("mv_jr_dec_enter"))
    assert_equal(specs[3].program, String("mv_jr_enc_enter"))
    var source = JournalKernel()
    assert_true(not source.attach().ok)
    assert_true(not source.poll(0).ok)
    assert_true(not source.counters().ok)
    assert_true(source.detach().ok and source.close().ok)

def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
