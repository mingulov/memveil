# SPDX-License-Identifier: GPL-3.0-or-later

"""Real descriptor/durability probe driven by synthetic allowlisted records."""
from std.sys import argv, exit
from memveil.platform.stdout import write_stdout
from memveil.platform.signal import ignore_sigpipe
from memveil.cli.report import final_capture_summary
from std.ffi import external_call
from memveil.capture.writer import EventWriter, CommittedStream, MIN_EVENTS_BUDGET
from memveil.model.session import Session, parse_session
from memveil.model.event import parse_event
from memveil.model.encode import encode_session
from memveil.platform.reader import read_host_file


def bytes(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    return out^


def snapshot(template: Session, stream: CommittedStream, generation: UInt64, failures: UInt64) raises -> List[UInt8]:
    var session = template.copy()
    session.finalized = generation == 0
    session.has_checkpoint_generation = generation != 0
    session.checkpoint_generation = generation
    session.has_end_reason = True
    session.end_reason = String("checkpoint") if generation != 0 else String("duration")
    session.has_integrity = True
    session.integrity = stream.snapshot()
    session.stop.has_checkpoint_failures = True
    session.stop.checkpoint_failures = failures
    session.stop.outcome = String("partial")
    session.stop.reason = String("synthetic open measurement window")
    session.stop.admission_closed = False
    session.stop.quiescence_observed = False
    session.stop.drain_completed = False
    session.stop.counters_valid = False
    session.q_detail.status = String("partial")
    session.q_detail.reason = session.stop.reason
    session.q_terminal.status = String("partial")
    session.q_terminal.reason = session.stop.reason
    return bytes(encode_session(session))


def main() raises:
    _ = ignore_sigpipe()
    var args = argv()
    if len(args) != 4:
        exit(2)
    var template = parse_session(read_host_file(args[3] + "/session.json", "fixture", 16777216))
    var input = read_host_file(args[3] + "/events.ndjson", "fixture", 65536)
    var writer = EventWriter(args[2], MIN_EVENTS_BUDGET)
    try:
        writer.prepare()
    except e:
        print("prepare failed", String(e))
        _ = writer.abandon()
        exit(1)
    var stream = CommittedStream()
    var failures = UInt64(0)
    var generation = UInt64(1)
    try:
        writer.checkpoint(snapshot(template, stream, generation, failures))
    except e:
        print("readiness failed", String(e))
        _ = writer.abandon()
        exit(1)
    write_stdout("ready\n")
    if args[1] == "hold":
        var release = List[UInt8](length=1, fill=UInt8(0))
        _ = external_call["read", Int64](Int32(0), Span(release).unsafe_ptr(), UInt64(1))
    var line = List[UInt8]()
    for b in input:
        line.append(b)
        if b != 10:
            continue
        var event = parse_event(line)
        writer.append(line)
        stream.commit(line, event.kind)
        line = List[UInt8]()
        generation += UInt64(1)
        if generation <= UInt64(3):
            try:
                writer.checkpoint(snapshot(template, stream, generation, failures))
            except e:
                failures += UInt64(1)
                print("checkpoint failed", String(e))
    if args[1] == "partial":
        writer.discard()
        return
    var outcome = writer.finalize(snapshot(template, stream, UInt64(0), failures))
    print("final=" + outcome.status)
    if outcome.status != "finalized":
        exit(1)
    if args[1] == "stdout" or args[1] == "stdout0" or args[1] == "pipe" or args[1] == "pipe0" or args[1] == "stdout1" or args[1] == "pipe1":
        if args[1] == "pipe" or args[1] == "pipe0" or args[1] == "pipe1":
            var ends = List[Int32](length=2, fill=Int32(-1))
            if external_call["pipe2", Int32](Span(ends).unsafe_ptr(), Int32(524288)) != 0:
                exit(2)
            _ = external_call["close", Int32](ends[0])
            _ = external_call["dup2", Int32](ends[1], Int32(1))
            _ = external_call["close", Int32](ends[1])
            var code = 0 if args[1] == "pipe0" else (1 if args[1] == "pipe1" else 4)
            exit(final_capture_summary("durable capture summary\n", args[2], code))
        var full_name = bytes(String("/dev/full\0"))
        var full = external_call["openat", Int32](Int32(-100), Span(full_name).unsafe_ptr(), Int32(1), UInt32(0))
        _ = external_call["dup2", Int32](full, Int32(1))
        _ = external_call["close", Int32](full)
        var code = 0 if args[1] == "stdout0" else (1 if args[1] == "stdout1" else 4)
        exit(final_capture_summary("durable capture summary\n", args[2], code))
