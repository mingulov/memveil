# SPDX-License-Identifier: GPL-3.0-or-later

"""Committed event-file measurements for capture format 0.1.4."""

from memveil.jsonscan import Scanner
from memveil.model.common import (
    object_is_empty,
    object_next,
    expect_colon,
    parse_u64_field,
    parse_maybe_u64,
)
from memveil.model.validate import ValidationError, checked_add

comptime EMPTY_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
comptime INTEGRITY_KIND_COUNT = 10


def integrity_kind(index: Int) -> String:
    if index == 0:
        return String("bounce_attempt")
    if index == 1:
        return String("map_result")
    if index == 2:
        return String("unmap")
    if index == 3:
        return String("copy")
    if index == 4:
        return String("sync_request")
    if index == 5:
        return String("transition_result")
    if index == 6:
        return String("pool_sample")
    if index == 7:
        return String("gap")
    if index == 8:
        return String("marker")
    if index == 9:
        return String("counter_snapshot")
    return String("")


def integrity_kind_index(name: String) -> Int:
    if name == "bounce_attempt":
        return 0
    if name == "map_result":
        return 1
    if name == "unmap":
        return 2
    if name == "copy":
        return 3
    if name == "sync_request":
        return 4
    if name == "transition_result":
        return 5
    if name == "pool_sample":
        return 6
    if name == "gap":
        return 7
    if name == "marker":
        return 8
    if name == "counter_snapshot":
        return 9
    return -1


struct Integrity(Copyable):
    """Committed-byte snapshot; presence does not establish verification."""

    var events_bytes: UInt64
    var line_count: UInt64
    var has_seq: Bool
    var first_seq: UInt64
    var last_seq: UInt64
    var events_sha256: String
    var kinds: Array[UInt64, INTEGRITY_KIND_COUNT]

    def __init__(out self):
        self.events_bytes = UInt64(0)
        self.line_count = UInt64(0)
        self.has_seq = False
        self.first_seq = UInt64(0)
        self.last_seq = UInt64(0)
        self.events_sha256 = String(EMPTY_SHA256)
        self.kinds = Array[UInt64, INTEGRITY_KIND_COUNT](fill=UInt64(0))

    def validate(self) raises:
        var total = UInt64(0)
        for i in range(INTEGRITY_KIND_COUNT):
            total = checked_add(total, self.kinds[i])
        if total != self.line_count:
            raise ValidationError(
                "capture.integrity.kinds", "sum differs from line_count"
            )
        if self.line_count == UInt64(0):
            if (
                self.has_seq
                or self.events_bytes != UInt64(0)
                or self.events_sha256 != EMPTY_SHA256
            ):
                raise ValidationError(
                    "capture.integrity", "invalid empty stream"
                )
        elif (
            not self.has_seq
            or self.first_seq != UInt64(0)
            or self.last_seq != self.line_count - UInt64(1)
            or self.events_bytes < self.line_count
        ):
            raise ValidationError(
                "capture.integrity", "invalid sequence bounds or byte count"
            )
        if self.events_sha256.byte_length() != 64:
            raise ValidationError(
                "capture.integrity.events_sha256", "digest length"
            )
        for b in self.events_sha256.as_bytes():
            if not (
                UInt8(48) <= b <= UInt8(57) or UInt8(97) <= b <= UInt8(102)
            ):
                raise ValidationError(
                    "capture.integrity.events_sha256",
                    "digest must be lowercase hex",
                )


def parse_integrity(mut scan: Scanner) raises -> Integrity:
    scan.begin_object()
    var out = Integrity()
    var seen = Dict[String, Bool]()
    var first_present = False
    var last_present = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            if key in seen:
                raise ValidationError("capture.integrity", "duplicate key")
            seen[key] = True
            expect_colon(scan, "capture.integrity")
            if key == "algorithm":
                if scan.parse_string() != "sha256":
                    raise ValidationError(
                        "capture.integrity.algorithm", "unsupported algorithm"
                    )
            elif key == "events_bytes":
                out.events_bytes = parse_u64_field(
                    scan, "capture.integrity.events_bytes"
                )
            elif key == "line_count":
                out.line_count = parse_u64_field(
                    scan, "capture.integrity.line_count"
                )
            elif key == "first_seq":
                var v = parse_maybe_u64(scan)
                first_present = v.has
                out.first_seq = v.value
            elif key == "last_seq":
                var v = parse_maybe_u64(scan)
                last_present = v.has
                out.last_seq = v.value
            elif key == "events_sha256":
                out.events_sha256 = scan.parse_string()
            elif key == "kinds":
                scan.begin_object()
                var kinds_seen = Dict[String, Bool]()
                if not object_is_empty(scan):
                    while True:
                        scan.skip_ws()
                        var name = scan.parse_string()
                        var index = integrity_kind_index(name)
                        if index < 0 or name in kinds_seen:
                            raise ValidationError(
                                "capture.integrity.kinds",
                                "unknown or duplicate kind",
                            )
                        kinds_seen[name] = True
                        expect_colon(scan, "capture.integrity.kinds")
                        out.kinds[index] = parse_u64_field(
                            scan, "capture.integrity.kinds"
                        )
                        if not object_next(scan, "capture.integrity.kinds"):
                            break
                scan.end_object()
                if len(kinds_seen) != INTEGRITY_KIND_COUNT:
                    raise ValidationError(
                        "capture.integrity.kinds", "missing kind"
                    )
            else:
                raise ValidationError("capture.integrity", "unknown field")
            if not object_next(scan, "capture.integrity"):
                break
    scan.end_object()
    if len(seen) != 7 or first_present != last_present:
        raise ValidationError(
            "capture.integrity", "missing field or mismatched sequence bounds"
        )
    out.has_seq = first_present
    out.validate()
    return out^
