# SPDX-License-Identifier: GPL-3.0-or-later
"""Journal wire normalization, bounded transport accounting and window control."""
from memveil.model.common import MaybeU64
from memveil.model.event import Event
from memveil.model.journal import JournalResult, decode_journal
from memveil.model.journal_event import JournalEvent, caller_status, caller_class, caller_label
from memveil.model.journal_session import JournalSession, JOURNAL_COUNTER_COUNT
from memveil.model.validate import ValidationError

comptime JOURNAL_STOP_NS = UInt64(5000000000)
comptime JOURNAL_NATIVE_COUNTERS = 15


def known(value: UInt64) -> MaybeU64:
    var out = MaybeU64()
    out.has = True
    out.value = value
    return out


def normalize_journal_result(result: JournalResult) raises -> JournalEvent:
    var out = JournalEvent()
    out.direction = String("decrypt") if result.direction == 1 else String("encrypt")
    out.requested_native_pages = result.pages
    if result.pages >= 0:
        out.requested_pages = known(UInt64(result.pages))
        out.requested_bytes = known(UInt64(result.pages) * 4096)
    else:
        out.size_reason = String("invalid_native_pages")
    out.native_result = result.native_result
    out.epoch = result.epoch
    if result.matched:
        out.operation_token = known(result.token)
        out.entry_ns = known(result.entry_ns)
        out.membership = String("admitted")
    out.caller_status = caller_status(result.caller_status)
    out.caller_class = caller_class(result.caller_class)
    out.caller_label = caller_label(result.caller_label)
    out.validate()
    return out


def normalize_journal_event(result: JournalResult, session_id: String, profile_id: String) raises -> Event:
    var out = Event()
    out.session_id = session_id
    out.kind = String("transition_result")
    out.ts_ns = result.exit_ns
    out.journal_version = True
    out.has_journal = True
    out.journal = normalize_journal_result(result)
    out.source_hook = String("set_memory_decrypted") if result.direction == 1 else String("set_memory_encrypted")
    out.source_backend = String("fentry_fexit")
    out.source_profile_id = profile_id
    out.source_measurement = String("observed")
    out.source_correlation = String("unpaired")
    return out^


def decode_journal_counters(raw: List[UInt8]) raises -> List[UInt64]:
    if len(raw) != JOURNAL_NATIVE_COUNTERS * 8:
        raise ValidationError("journal counters", "length")
    var out = List[UInt64]()
    for i in range(JOURNAL_NATIVE_COUNTERS):
        var value = UInt64(0)
        for j in range(8):
            value |= UInt64(raw[i * 8 + j]) << UInt64(j * 8)
        out.append(value)
    return out^


def encode_journal_control(epoch: UInt64, start: UInt64, end: UInt64, opened: Bool, observe: Bool, callers: Bool) -> List[UInt8]:
    var values: List[UInt64] = [epoch, start, end, UInt64(opened), UInt64(observe), UInt64(callers)]
    var out = List[UInt8]()
    for value in values:
        for i in range(8):
            out.append(UInt8((value >> UInt64(i * 8)) & 255))
    return out^


struct JournalCapture(Copyable):
    var session: JournalSession
    var capture_start: UInt64
    var invalid_records: UInt64
    var sequence_gaps: UInt64
    var sequences: Dict[UInt32, UInt64]
    var last_result: UInt64

    def __init__(out self, epoch: UInt64 = 1, start: UInt64 = 0, profile: String = String("linux-7.0.14-x86-journal-provisional"), callers: Bool = False):
        self.session = JournalSession()
        self.session.epoch = epoch
        self.session.profile_id = profile
        self.session.callers = callers
        self.capture_start = start
        self.invalid_records = 0
        self.sequence_gaps = 0
        self.sequences = Dict[UInt32, UInt64]()
        self.last_result = start

    def opened(mut self, start: UInt64) raises:
        if self.session.admission_start_ns.has or start < self.capture_start or self.session.epoch == 0:
            raise ValidationError("journal", "invalid admission opening")
        self.session.admission_start_ns = known(start)
        self.session.admission_start_reason = String("")
        self.session.admission_end_reason = String("admission_open")

    def closed(mut self, end: UInt64, proved_write: Bool) raises:
        if not self.session.admission_start_ns.has or end < self.session.admission_start_ns.value:
            raise ValidationError("journal", "invalid admission closing")
        if proved_write:
            self.session.admission_end_ns = known(end)
            self.session.admission_end_reason = String("")
        else:
            self.session.admission_end_reason = String("close_unproved")

    def consume(mut self, raw: List[UInt8], session_id: String, observation_cut: UInt64) raises -> Event:
        var result: JournalResult
        try:
            result = decode_journal(raw)
            var snapshot = self.session.copy()
            snapshot.observation_end_ns = observation_cut
            var window = snapshot.window(self.capture_start, self.session.admission_end_reason != "admission_open")
            window.validate_result(result)
            if not self.session.callers and result.caller_status != 0:
                raise ValidationError("journal", "unsolicited caller")
            if result.cpu not in self.sequences and len(self.sequences) >= 4096:
                raise ValidationError("journal", "cpu tracking budget")
            var wanted = self.sequences.get(result.cpu, UInt64(0))
            if result.sequence < wanted or result.sequence == UInt64(0xFFFFFFFFFFFFFFFF):
                raise ValidationError("journal", "transport sequence regression/exhaustion")
            var gap = result.sequence - wanted
            if gap > UInt64(0xFFFFFFFFFFFFFFFF) - self.sequence_gaps:
                raise ValidationError("journal", "sequence gap overflow")
            self.sequence_gaps += gap
            self.sequences[result.cpu] = result.sequence + 1
        except:
            if self.invalid_records != UInt64(0xFFFFFFFFFFFFFFFF):
                self.invalid_records += 1
            raise ValidationError("journal", "invalid wire/window/sequence")
        if result.exit_ns > self.last_result:
            self.last_result = result.exit_ns
        return normalize_journal_event(result, session_id, self.session.profile_id)

    def snapshot(self, cut: UInt64, finalized: Bool, counters: List[UInt64], readable: Bool) raises -> JournalSession:
        var out = self.session.copy()
        out.observation_end_ns = cut
        if finalized and out.admission_end_reason == "admission_open":
            out.admission_end_reason = String("close_unproved")
        var map_indices: List[Int] = [0, 1, 2, 3, 4, 6, 7, 8, 5, -1, -1]
        var ok = readable and len(counters) == JOURNAL_NATIVE_COUNTERS
        for i in range(JOURNAL_COUNTER_COUNT):
            var index = map_indices[i]
            if index >= 0:
                out.counter_reasons[i] = String("read_failed")
                if ok:
                    if counters[11] & (UInt64(1) << UInt64(index)):
                        out.counter_reasons[i] = String("overflow")
                    else:
                        out.counters[i] = known(counters[index])
                        out.counter_reasons[i] = String("")
        out.counters[9] = known(self.invalid_records)
        out.counter_reasons[9] = String("")
        if not finalized:
            out.counters[4] = MaybeU64()
            out.counter_reasons[4] = String("not_observable")
        elif ok and out.counters[4].has:
            if counters[12] > UInt64(0xFFFFFFFFFFFFFFFF) - counters[4]:
                out.counters[4] = MaybeU64()
                out.counter_reasons[4] = String("overflow")
            else:
                out.counters[4] = known(counters[4] + counters[12])
        _ = out.window(self.capture_start, finalized)
        return out^
