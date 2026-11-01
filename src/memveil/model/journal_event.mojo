# SPDX-License-Identifier: GPL-3.0-or-later
"""Typed result-only journal event payload; legacy region events stay separate."""
from memveil.jsonscan import Scanner
from memveil.model.common import MaybeU64
from memveil.model.journal import JournalResult, OPERATION_TOKEN_MAX, caller_label_class
from memveil.model.validate import ValidationError, format_u64
from memveil.model.journal_json import fields, text, uint, required_uint, native_int, null_value, quoted, nullable_text, nullable_uint, member, object_text


def caller_label(code: Int) -> String:
    var labels = [String(""), String("mv_command_set [memveil_region_oracle]"), String("mv_restore [memveil_region_oracle]"), String("swiotlb_init_late"), String("swiotlb_alloc_tlb"), String("swiotlb_free_tlb"), String("swiotlb_exit"), String("dma_set_decrypted"), String("dma_set_encrypted"), String("dma_direct_alloc"), String("dma_direct_free")]
    return labels[code] if code >= 0 and code <= 10 else String("")


def caller_status(code: Int) -> String:
    var names = [String("disabled"), String("resolved"), String("unresolved"), String("ambiguous"), String("truncated")]
    return names[code] if code >= 0 and code < 5 else String("")


def caller_class(code: Int) -> String:
    var names = [String(""), String("owned"), String("swiotlb"), String("direct_dma")]
    return names[code] if code >= 0 and code < 4 else String("")


struct JournalEvent(ImplicitlyCopyable):
    var direction: String
    var requested_native_pages: Int32
    var requested_pages: MaybeU64
    var requested_bytes: MaybeU64
    var size_reason: String
    var native_result: Int32
    var operation_token: MaybeU64
    var entry_ns: MaybeU64
    var epoch: UInt64
    var membership: String
    var caller_status: String
    var caller_class: String
    var caller_label: String

    def __init__(out self):
        self.direction = String("decrypt")
        self.requested_native_pages = Int32(0)
        self.requested_pages = MaybeU64()
        self.requested_bytes = MaybeU64()
        self.size_reason = String("")
        self.native_result = Int32(0)
        self.operation_token = MaybeU64()
        self.entry_ns = MaybeU64()
        self.epoch = UInt64(0)
        self.membership = String("unmatched_exit")
        self.caller_status = String("disabled")
        self.caller_class = String("")
        self.caller_label = String("")

    def validate(self) raises:
        if self.direction != "decrypt" and self.direction != "encrypt":
            raise ValidationError("journal", "direction")
        if self.epoch == 0:
            raise ValidationError("journal", "epoch")
        if self.requested_native_pages < 0:
            if self.requested_pages.has or self.requested_bytes.has or self.size_reason != "invalid_native_pages":
                raise ValidationError("journal", "invalid pages must remain unavailable")
        elif not self.requested_pages.has or not self.requested_bytes.has or self.size_reason != "" or self.requested_pages.value != UInt64(self.requested_native_pages) or self.requested_bytes.value != UInt64(self.requested_native_pages) * 4096:
            raise ValidationError("journal", "requested size disagreement")
        if self.membership == "admitted":
            if not self.operation_token.has or not self.entry_ns.has or self.operation_token.value == 0 or self.operation_token.value > OPERATION_TOKEN_MAX:
                raise ValidationError("journal", "admitted token")
        elif self.membership != "unmatched_exit" or self.operation_token.has or self.entry_ns.has:
            raise ValidationError("journal", "unmatched token")
        var valid_status = False
        for i in range(5):
            valid_status = valid_status or self.caller_status == caller_status(i)
        if not valid_status:
            raise ValidationError("journal", "caller status")
        if self.caller_status != "resolved":
            if self.caller_class != "" or self.caller_label != "":
                raise ValidationError("journal", "unavailable caller label")
        else:
            var valid = False
            for i in range(1, 11):
                if self.caller_label == caller_label(i) and self.caller_class == caller_class(caller_label_class(i)):
                    valid = True
            if not valid:
                raise ValidationError("journal", "caller label/class")

    def to_result(self, exit_ns: UInt64, cpu: UInt32 = 0) raises -> JournalResult:
        self.validate()
        if self.entry_ns.has and self.entry_ns.value > exit_ns:
            raise ValidationError("journal", "entry after result")
        var status = 0
        var label = 0
        for i in range(5):
            if self.caller_status == caller_status(i):
                status = i
        for i in range(1, 11):
            if self.caller_label == caller_label(i):
                label = i
        return JournalResult(1 if self.direction == "decrypt" else 2, cpu, UInt64(0), exit_ns, self.epoch, self.operation_token.value if self.operation_token.has else UInt64(0), self.entry_ns.value if self.entry_ns.has else UInt64(0), self.requested_native_pages, self.native_result, status, caller_label_class(label), label, self.membership == "admitted")


def parse_journal_event(mut scan: Scanner) raises -> JournalEvent:
    var f = fields(scan, String("direction,requested_state,requested_native_pages,requested_pages,requested_bytes,size_reason,page_size,native_result,operation_token,entry_ns,epoch,membership,region,region_reason,effect,caller"))
    var out = JournalEvent()
    out.direction = text(f["direction"])
    out.requested_native_pages = native_int(f["requested_native_pages"])
    out.requested_pages = uint(f["requested_pages"])
    out.requested_bytes = uint(f["requested_bytes"])
    out.size_reason = text(f["size_reason"], True)
    out.native_result = native_int(f["native_result"])
    out.operation_token = uint(f["operation_token"])
    out.entry_ns = uint(f["entry_ns"])
    out.epoch = required_uint(f["epoch"])
    out.membership = text(f["membership"])
    null_value(f["region"])
    if text(f["page_size"]) != "4096" or text(f["effect"]) != "request_only" or text(f["region_reason"]) != "request_only_source" or text(f["requested_state"]) != (String("shared") if out.direction == "decrypt" else String("private")):
        raise ValidationError("journal", "request-only source contract")
    var callers = Scanner(f["caller"])
    var c = fields(callers, String("status,class,label"))
    out.caller_status = text(c["status"])
    out.caller_class = text(c["class"], True)
    out.caller_label = text(c["label"], True)
    out.validate()
    return out


def encode_journal_event(value: JournalEvent) raises -> String:
    value.validate()
    var p = List[String]()
    p.append(member(String("direction"), quoted(value.direction)))
    p.append(member(String("requested_state"), quoted(String("shared") if value.direction == "decrypt" else String("private"))))
    p.append(member(String("requested_native_pages"), String(value.requested_native_pages)))
    p.append(member(String("requested_pages"), nullable_uint(value.requested_pages)))
    p.append(member(String("requested_bytes"), nullable_uint(value.requested_bytes)))
    p.append(member(String("size_reason"), nullable_text(value.size_reason)))
    p.append(String('"page_size":"4096"'))
    p.append(member(String("native_result"), String(value.native_result)))
    p.append(member(String("operation_token"), nullable_uint(value.operation_token)))
    p.append(member(String("entry_ns"), nullable_uint(value.entry_ns)))
    p.append(member(String("epoch"), quoted(format_u64(value.epoch))))
    p.append(member(String("membership"), quoted(value.membership)))
    p.append(String('"region":null,"region_reason":"request_only_source","effect":"request_only"'))
    var c: List[String] = [member(String("status"), quoted(value.caller_status)), member(String("class"), nullable_text(value.caller_class)), member(String("label"), nullable_text(value.caller_label))]
    p.append(member(String("caller"), object_text(c)))
    return object_text(p)
