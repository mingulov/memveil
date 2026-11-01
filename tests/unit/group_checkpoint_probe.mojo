# SPDX-License-Identifier: GPL-3.0-or-later

"""A rolled-back closing group must not enter a recovery checkpoint."""
from std.sys import argv, exit
from memveil.capture.writer import EventWriter, CommittedStream
from memveil.model.session import parse_session
from memveil.model.event import parse_event
from memveil.model.encode import encode_event_line, encode_session
from memveil.platform.reader import read_host_file
from std.ffi import external_call


def raw(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    return out^


def main() raises:
    var args = argv()
    var session = parse_session(read_host_file(args[2] + "/session.json", "fixture", 16777216))
    var input = read_host_file(args[2] + "/events.ndjson", "fixture", 65536)
    var first = List[UInt8]()
    for b in input:
        first.append(b)
        if b == 10:
            break
    var event = parse_event(first)
    var writer = EventWriter(args[1], 1048576)
    writer.prepare()
    var stream = CommittedStream()
    for i in range(999):
        event.seq = UInt64(i)
        event.bounce.operation_id = "group-op-" + String(i)
        var line = encode_event_line(event)
        writer.append(line)
        stream.commit(line, event.kind)
    session.finalized = False
    session.end_reason = String("checkpoint")
    session.has_end_reason = True
    session.has_checkpoint_generation = True
    session.checkpoint_generation = UInt64(1)
    session.stop.has_checkpoint_failures = True
    session.stop.checkpoint_failures = UInt64(0)
    session.stop.outcome = String("partial")
    session.stop.reason = String("synthetic open window")
    session.q_detail.status = String("partial")
    session.q_terminal.status = String("partial")
    session.integrity = stream.snapshot()
    writer.checkpoint(raw(encode_session(session)))
    var saved = stream.copy()
    var mark = writer.group_begin()
    event.seq = UInt64(999)
    event.bounce.operation_id = String("group-op-999")
    var line = encode_event_line(event)
    writer.append_closing(line)
    stream.commit(line, event.kind)
    session.integrity = stream.snapshot()
    session.checkpoint_generation = UInt64(2)
    var refused = False
    var candidate = raw(encode_session(session))
    try:
        writer.checkpoint(candidate)
    except:
        refused = True
    session.checkpoint_generation = UInt64(3)
    session.window_end_ns += UInt64(10000000000)
    var time_refused = False
    var timed_candidate = raw(encode_session(session))
    try:
        writer.checkpoint(timed_candidate)
    except:
        time_refused = True
    # The test shim fails the next grouped append after both threshold crossings.
    var key = raw(String("MV_GROUP_FAIL_NEXT\0"))
    var value = raw(String("1\0"))
    _ = external_call["setenv", Int32](Span(key).unsafe_ptr(), Span(value).unsafe_ptr(), Int32(1))
    var append_failed = False
    try:
        writer.append_closing(line)
    except e:
        append_failed = e.kind == "append_failed"
    writer.group_abort(mark)
    stream = saved^
    if stream.snapshot().events_bytes != UInt64(mark):
        exit(1)
    writer.discard()
    print("checkpoint_refused=" + String(refused))
    print("time_checkpoint_refused=" + String(time_refused))
    print("append_failed=" + String(append_failed))
    if not refused or not time_refused or not append_failed:
        exit(1)
