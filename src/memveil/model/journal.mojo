# SPDX-License-Identifier: GPL-3.0-or-later
"""Provisional request-only journal wire and selection contracts."""
from memveil.model.validate import ValidationError
from memveil.model.common import MaybeU64

comptime JOURNAL_SCHEMA_VERSION = "0.2.0"
comptime JOURNAL_WIRE_VERSION = 1
comptime JOURNAL_WIRE_BYTES = 72
comptime OPERATION_CAPACITY = 4096
comptime NESTING_CAPACITY = 8
comptime REPLAY_TOKEN_INTERVAL_CAPACITY = 65536
comptime CALLER_FRAME_CAPACITY = 16
comptime JOURNAL_RING_BYTES = 8388608
comptime OPERATION_TOKEN_MAX = 18446744073709551614


@fieldwise_init
struct JournalSelection(ImplicitlyCopyable):
    var attempts: Bool
    var journal: Bool
    var callers: Bool


def select_journal(
    capabilities: String, callers: Bool, device: Bool,
    journal_object: Bool = False,
) raises -> JournalSelection:
    if capabilities.byte_length() > 256:
        raise ValidationError("capability", "selector too long")
    var journal = False
    var ordinary = capabilities == ""
    var seen = List[String]()
    if capabilities != "":
        for part in capabilities.split(","):
            var item = String(part)
            for previous in seen:
                if previous == item:
                    raise ValidationError("capability", "duplicate")
            seen.append(item)
            if item == "conversion-journal":
                journal = True
            elif (
                item == "attempt-trace" or item == "mapping-lifecycle"
                or item == "copy-actual" or item == "conversion-observe"
            ):
                ordinary = True
            else:
                raise ValidationError("capability", "unknown")
    if (callers or journal_object) and not journal:
        raise ValidationError("journal option", "requires conversion-journal")
    if journal and not ordinary and device:
        raise ValidationError("device", "journal-only scope is global")
    return JournalSelection(ordinary, journal, callers)


@fieldwise_init
struct JournalAdmission(ImplicitlyCopyable):
    var exit_code: Int
    var reason: String


def journal_admission(
    selection: JournalSelection, attempts_admitted: Bool,
    journal_status: String, callers_admitted: Bool,
) -> JournalAdmission:
    """Check declared admission only; attachment remains a separate gate."""
    if selection.journal and journal_status != "admitted":
        return JournalAdmission(3, String("journal_profile_not_admitted"))
    if selection.attempts and not attempts_admitted:
        return JournalAdmission(3, String("attempts_not_admitted"))
    if selection.callers and not callers_admitted:
        return JournalAdmission(3, String("journal_callers_not_admitted"))
    return JournalAdmission(0, String("ready_for_attachment"))


def requested_bytes(pages: Int32, page_size: UInt64) raises -> UInt64:
    if pages < 0:
        raise ValidationError("requested_pages", "invalid_native_pages")
    if page_size != 4096:
        raise ValidationError("page_size", "unadmitted size")
    return UInt64(pages) * page_size


def classify_caller(
    enabled: Bool, truncated: Bool, class_count: Int, unique_labels: Int,
) -> Int:
    if not enabled:
        return 0
    if truncated:
        return 4
    if class_count > 1 or unique_labels < 0:
        return 3
    if class_count != 1 or unique_labels == 0:
        return 2
    return 1


def next_operation_token(
    previous: UInt64, active: Int, depth: Int,
) raises -> UInt64:
    if active < 0 or active >= OPERATION_CAPACITY:
        raise ValidationError("journal", "operation_exhaustion")
    if depth < 0 or depth >= NESTING_CAPACITY:
        raise ValidationError("journal", "nesting_exhaustion")
    if previous >= OPERATION_TOKEN_MAX:
        raise ValidationError("journal", "token_exhaustion")
    return previous + 1


@fieldwise_init
struct JournalResult(ImplicitlyCopyable):
    var direction: Int
    var cpu: UInt32
    var sequence: UInt64
    var exit_ns: UInt64
    var epoch: UInt64
    var token: UInt64
    var entry_ns: UInt64
    var pages: Int32
    var native_result: Int32
    var caller_status: Int
    var caller_class: Int
    var caller_label: Int
    var matched: Bool


def _unsigned(raw: List[UInt8], offset: Int, width: Int) -> UInt64:
    var value = UInt64(0)
    for i in range(width):
        value |= UInt64(raw[offset + i]) << UInt64(8 * i)
    return value


def _signed(raw: List[UInt8], offset: Int) -> Int32:
    var value = Int64(_unsigned(raw, offset, 4))
    if value >= 2147483648:
        value -= 4294967296
    return Int32(value)


def caller_label_class(label: Int) -> Int:
    if label >= 1 and label <= 2:
        return 1
    if label >= 3 and label <= 6:
        return 2
    if label >= 7 and label <= 10:
        return 3
    return 0


def decode_journal(raw: List[UInt8]) raises -> JournalResult:
    if len(raw) != JOURNAL_WIRE_BYTES:
        raise ValidationError("journal wire", "length")
    if _unsigned(raw, 0, 4) != 0x524A564D:
        raise ValidationError("journal wire", "magic")
    if _unsigned(raw, 4, 2) != JOURNAL_WIRE_VERSION:
        raise ValidationError("journal wire", "version")
    if _unsigned(raw, 6, 2) != 1:
        raise ValidationError("journal wire", "kind")
    var flags = _unsigned(raw, 8, 2)
    var direction = Int(_unsigned(raw, 10, 2))
    var cpu = UInt32(_unsigned(raw, 12, 4))
    var status = Int(_unsigned(raw, 64, 2))
    var cls = Int(_unsigned(raw, 66, 2))
    var label = Int(_unsigned(raw, 68, 2))
    if flags > 1 or _unsigned(raw, 70, 2) != 0:
        raise ValidationError("journal wire", "flags/reserved")
    if direction < 1 or direction > 2 or cpu > 1048575:
        raise ValidationError("journal wire", "direction/cpu")
    if status > 4:
        raise ValidationError("journal wire", "caller status")
    if status == 1:
        if cls == 0 or caller_label_class(label) != cls:
            raise ValidationError("journal wire", "caller label/class")
    elif cls != 0 or label != 0:
        raise ValidationError("journal wire", "unavailable caller")
    var epoch = _unsigned(raw, 32, 8)
    var token = _unsigned(raw, 40, 8)
    var entry = _unsigned(raw, 48, 8)
    var end = _unsigned(raw, 24, 8)
    if epoch == 0 or token > OPERATION_TOKEN_MAX:
        raise ValidationError("journal wire", "epoch/token")
    if flags == 1:
        if token == 0 or entry > end:
            raise ValidationError("journal wire", "matched entry")
    elif token != 0 or entry != 0:
        raise ValidationError("journal wire", "unmatched exit")
    return JournalResult(
        direction, cpu, _unsigned(raw, 16, 8), end, epoch, token,
        entry, _signed(raw, 56), _signed(raw, 60), status, cls, label,
        flags == 1,
    )


def validate_membership(
    result: JournalResult, epoch: UInt64, start: UInt64,
    cutoff: UInt64, end: UInt64,
) raises:
    if epoch == 0 or result.epoch != epoch or start > cutoff or cutoff > end:
        raise ValidationError("journal window", "epoch/bounds")
    if result.exit_ns < start or result.exit_ns >= end:
        raise ValidationError("journal window", "exit outside observation")
    if result.matched and (result.entry_ns < start or result.entry_ns >= cutoff):
        raise ValidationError("journal window", "entry outside admission")


@fieldwise_init
struct JournalWindow(ImplicitlyCopyable):
    """Nullable admission evidence, independent of the capture/prefix clock."""
    var epoch: UInt64
    var capture_start: UInt64
    var observation_end: UInt64
    var start: MaybeU64
    var cutoff: MaybeU64
    var start_reason: String
    var end_reason: String
    var finalized: Bool

    def validate(self) raises:
        if self.epoch == 0 or self.capture_start > self.observation_end:
            raise ValidationError("journal window", "epoch/prefix bounds")
        if not self.start.has:
            if self.cutoff.has:
                raise ValidationError("journal window", "end without start")
            if self.start_reason == "not_opened" and self.end_reason == "not_opened":
                return
            if self.start_reason == "readiness_unproved" and self.end_reason == "close_unproved":
                return
            raise ValidationError("journal window", "unknown start reason")
        if self.start_reason != "" or self.start.value < self.capture_start or self.start.value > self.observation_end:
            raise ValidationError("journal window", "admission start")
        if self.cutoff.has:
            if self.end_reason != "" or self.cutoff.value < self.start.value or self.cutoff.value > self.observation_end:
                raise ValidationError("journal window", "admission end")
        elif self.finalized:
            if self.end_reason != "close_unproved":
                raise ValidationError("journal window", "unknown final close")
        elif self.end_reason != "admission_open":
            raise ValidationError("journal window", "open admission reason")

    def validate_result(self, result: JournalResult) raises:
        self.validate()
        if result.epoch != self.epoch or result.exit_ns < self.capture_start or result.exit_ns >= self.observation_end:
            raise ValidationError("journal window", "result epoch/prefix")
        if self.start_reason == "not_opened":
            raise ValidationError("journal window", "result before readiness")
        if result.matched:
            if not self.start.has:
                raise ValidationError("journal window", "unproved admitted entry")
            var ceiling = self.observation_end
            if self.cutoff.has:
                ceiling = self.cutoff.value
            if result.entry_ns < self.start.value or result.entry_ns >= ceiling:
                raise ValidationError("journal window", "entry outside admission")
