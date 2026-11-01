# SPDX-License-Identifier: GPL-3.0-or-later
"""Typed journal window and independent nullable counter evidence."""
from memveil.jsonscan import Scanner
from memveil.model.common import MaybeU64
from memveil.model.journal import JournalWindow
from memveil.model.validate import ValidationError, format_u64, check_bounded_text
from memveil.model.journal_json import fields, text, uint, required_uint, boolean, null_value, quoted, nullable_text, nullable_uint, member, object_text

comptime JOURNAL_COUNTER_COUNT = 11
comptime JOURNAL_COUNTER_NAMES = "entries,exits,matched_results,unmatched_exits,censored,operation_exhaustion,nesting_exhaustion,token_exhaustion,ring_drops,invalid_records,missed_callbacks"


def journal_counter_name(index: Int) -> String:
    return String(String(JOURNAL_COUNTER_NAMES).split(",")[index])


struct JournalSession(Copyable):
    var profile_id: String
    var evidence_class: String
    var epoch: UInt64
    var admission_start_ns: MaybeU64
    var admission_end_ns: MaybeU64
    var admission_start_reason: String
    var admission_end_reason: String
    var observation_end_ns: UInt64
    var callers: Bool
    var closure: String
    var closure_evidence: String
    var counters: List[MaybeU64]
    var counter_reasons: List[String]

    def __init__(out self):
        self.profile_id = String("")
        self.evidence_class = String("source_reviewed_provisional")
        self.epoch = UInt64(0)
        self.admission_start_ns = MaybeU64()
        self.admission_end_ns = MaybeU64()
        self.admission_start_reason = String("not_opened")
        self.admission_end_reason = String("not_opened")
        self.observation_end_ns = UInt64(0)
        self.callers = False
        self.closure = String("unproved")
        self.closure_evidence = String("")
        self.counters = List[MaybeU64]()
        self.counter_reasons = List[String]()
        for _ in range(JOURNAL_COUNTER_COUNT):
            self.counters.append(MaybeU64())
            self.counter_reasons.append(String("not_observable"))

    def validate(self) raises:
        check_bounded_text(self.profile_id, 1, 128, "journal profile")
        if self.evidence_class != "synthetic" and self.evidence_class != "source_reviewed_provisional" and self.evidence_class != "admitted":
            raise ValidationError("journal", "evidence class")
        if self.epoch == 0 or len(self.counters) != JOURNAL_COUNTER_COUNT or len(self.counter_reasons) != JOURNAL_COUNTER_COUNT:
            raise ValidationError("journal", "epoch/counter shape")
        if self.closure == "proved":
            check_bounded_text(self.closure_evidence, 1, 128, "closure evidence")
        elif self.closure != "unproved" or self.closure_evidence != "":
            raise ValidationError("journal", "closure")
        for i in range(JOURNAL_COUNTER_COUNT):
            var reason = self.counter_reasons[i]
            if self.counters[i].has:
                if reason != "":
                    raise ValidationError("journal", "known counter reason")
            elif reason != "not_observable" and reason != "read_failed" and reason != "overflow":
                raise ValidationError("journal", "unknown counter reason")

    def window(self, capture_start: UInt64, finalized: Bool) raises -> JournalWindow:
        self.validate()
        var out = JournalWindow(self.epoch, capture_start, self.observation_end_ns, self.admission_start_ns, self.admission_end_ns, self.admission_start_reason, self.admission_end_reason, finalized)
        out.validate()
        if not finalized and self.counters[4].has:
            raise ValidationError("journal", "open prefix has no terminal censored count")
        if self.admission_start_reason == "not_opened":
            for i in range(JOURNAL_COUNTER_COUNT):
                if self.counters[i].has and self.counters[i].value != 0:
                    raise ValidationError("journal", "counts before readiness")
        return out


def parse_journal_session(mut scan: Scanner) raises -> JournalSession:
    var f = fields(scan, String("profile_id,evidence_class,epoch,admission_start_ns,admission_end_ns,admission_start_reason,admission_end_reason,observation_end_ns,callers,operation_capacity,nesting_capacity,caller_frame_capacity,ring_bytes,closure,closure_evidence,counters,counter_reasons,region_identity,region_state,state_reason"))
    var out = JournalSession()
    out.profile_id = text(f["profile_id"])
    out.evidence_class = text(f["evidence_class"])
    out.epoch = required_uint(f["epoch"])
    out.admission_start_ns = uint(f["admission_start_ns"])
    out.admission_end_ns = uint(f["admission_end_ns"])
    out.admission_start_reason = text(f["admission_start_reason"], True)
    out.admission_end_reason = text(f["admission_end_reason"], True)
    out.observation_end_ns = required_uint(f["observation_end_ns"])
    out.callers = boolean(f["callers"])
    out.closure = text(f["closure"])
    out.closure_evidence = text(f["closure_evidence"], True)
    null_value(f["region_identity"])
    null_value(f["region_state"])
    if text(f["operation_capacity"]) != "4096" or text(f["nesting_capacity"]) != "8" or text(f["caller_frame_capacity"]) != "16" or text(f["ring_bytes"]) != "8388608" or text(f["state_reason"]) != "request_only_source":
        raise ValidationError("journal", "capacity/state contract")
    var counts_scan = Scanner(f["counters"])
    var counts = fields(counts_scan, String(JOURNAL_COUNTER_NAMES))
    var reasons_scan = Scanner(f["counter_reasons"])
    var reasons = fields(reasons_scan, String(JOURNAL_COUNTER_NAMES))
    for i in range(JOURNAL_COUNTER_COUNT):
        var name = journal_counter_name(i)
        out.counters[i] = uint(counts[name])
        out.counter_reasons[i] = text(reasons[name], True)
    out.validate()
    return out^


def encode_journal_session(value: JournalSession) raises -> String:
    value.validate()
    var p = List[String]()
    p.append(member(String("profile_id"), quoted(value.profile_id)))
    p.append(member(String("evidence_class"), quoted(value.evidence_class)))
    p.append(member(String("epoch"), quoted(format_u64(value.epoch))))
    p.append(member(String("admission_start_ns"), nullable_uint(value.admission_start_ns)))
    p.append(member(String("admission_end_ns"), nullable_uint(value.admission_end_ns)))
    p.append(member(String("admission_start_reason"), nullable_text(value.admission_start_reason)))
    p.append(member(String("admission_end_reason"), nullable_text(value.admission_end_reason)))
    p.append(member(String("observation_end_ns"), quoted(format_u64(value.observation_end_ns))))
    p.append(member(String("callers"), String("true") if value.callers else String("false")))
    p.append(String('"operation_capacity":"4096","nesting_capacity":"8","caller_frame_capacity":"16","ring_bytes":"8388608"'))
    p.append(member(String("closure"), quoted(value.closure)))
    p.append(member(String("closure_evidence"), nullable_text(value.closure_evidence)))
    var counts = List[String]()
    var reasons = List[String]()
    for i in range(JOURNAL_COUNTER_COUNT):
        var name = journal_counter_name(i)
        counts.append(member(name, nullable_uint(value.counters[i])))
        reasons.append(member(name, nullable_text(value.counter_reasons[i])))
    p.append(member(String("counters"), object_text(counts)))
    p.append(member(String("counter_reasons"), object_text(reasons)))
    p.append(String('"region_identity":null,"region_state":null,"state_reason":"request_only_source"'))
    return object_text(p)
