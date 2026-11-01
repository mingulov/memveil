# SPDX-License-Identifier: GPL-3.0-or-later
from std.testing import TestSuite, assert_equal, assert_true
from scripted import ScriptKernel, ScriptClock, ScriptSignal, NullWriter
from memveil.capture.collector import Collector, CollectorConfig
from memveil.capture.journal_kernel import JournalSource, JournalPoll, JournalCounters
from memveil.platform.outcome import OpOut
from memveil.model.session import parse_session
from memveil.model.event import parse_event


struct JournalFixture(JournalSource):
    var control_bytes: List[UInt8]
    var calls: List[String]
    var sent: Bool
    var attach_fail: Bool
    var read_fail: Bool

    def __init__(out self):
        self.control_bytes = List[UInt8]()
        self.calls = List[String]()
        self.sent = False
        self.attach_fail = False
        self.read_fail = False

    def prepare(mut self, control: List[UInt8]) -> OpOut:
        self.calls.append(String("prepare"))
        self.control_bytes = control.copy()
        return OpOut(True, String(""))

    def attach(mut self) -> OpOut:
        self.calls.append(String("attach"))
        return OpOut(not self.attach_fail, String("scripted attach"))

    def control(mut self, value: List[UInt8]) -> OpOut:
        self.calls.append(String("open") if value[24] == 1 else String("close-admission"))
        self.control_bytes = value.copy()
        return OpOut(True, String(""))

    def poll(mut self, timeout_ms: Int) -> JournalPoll:
        var raw = List[UInt8]()
        if self.sent or self.control_bytes[24] == 0:
            return JournalPoll(True, raw^)
        raw = List[UInt8](length=72, fill=UInt8(0))
        raw[0]=77; raw[1]=86; raw[2]=74; raw[3]=82; raw[4]=1; raw[6]=1; raw[8]=1; raw[10]=1
        var start = UInt64(0)
        for i in range(8):
            raw[32+i] = self.control_bytes[i]
            start |= UInt64(self.control_bytes[8+i]) << UInt64(8*i)
        for i in range(8):
            raw[48+i] = UInt8((start >> UInt64(i*8)) & 255)
            raw[24+i] = UInt8(((start+1) >> UInt64(i*8)) & 255)
        raw[40]=1; raw[56]=3
        self.sent = True
        return JournalPoll(True, raw^)

    def counters(mut self) -> JournalCounters:
        var values = List[UInt64](length=15, fill=UInt64(0))
        if self.sent:
            values[0]=1; values[1]=1; values[2]=1; values[14]=1
        return JournalCounters(not self.read_fail, values^)

    def detach(mut self) -> OpOut:
        self.calls.append(String("detach"))
        return OpOut(True, String(""))

    def close(mut self) -> OpOut:
        self.calls.append(String("release"))
        return OpOut(True, String(""))


def test_journal_only_uses_no_attempt_source() raises:
    var config = CollectorConfig()
    config.has_journal = True
    config.journal_only = True
    config.journal_profile = String("linux-7.0.14-x86-journal-provisional")
    config.duration_s = 1
    var collector = Collector(config)
    var kernel = ScriptKernel()
    var journal = JournalFixture()
    var clock = ScriptClock()
    clock.add(UInt64(1000))
    clock.step = 100000000
    var signal = ScriptSignal()
    var writer = NullWriter()
    var result = collector.run_with_journal(kernel, journal, clock, signal, writer)
    assert_equal(result.exit_code, 0)
    assert_true(writer.finalized)
    assert_equal(len(kernel.calls), 0)
    assert_equal(len(writer.lines), 1)
    var event = parse_event(writer.lines[0])
    assert_equal(event.journal.requested_bytes.value, UInt64(12288))
    var session = parse_session(writer.session_bytes)
    assert_true(session.has_journal and session.has_integrity)
    assert_equal(session.journal.closure, String("unproved"))
    assert_true(not session.journal.counters[10].has)
    assert_equal(session.cap_bounce_attempts.status, String("unavailable"))
    assert_equal(journal.calls[0], String("prepare"))
    assert_equal(journal.calls[1], String("attach"))
    assert_equal(journal.calls[len(journal.calls)-1], String("release"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
