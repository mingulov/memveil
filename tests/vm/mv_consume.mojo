# SPDX-License-Identifier: GPL-3.0-or-later

"""Lifecycle/copy probe consumer for the VM gates (test-only).

Usage: mv_consume --bridge PATH <elf> <ring> <sites> <seconds> <out>

Attaches tracing programs (``prog:symbol`` pairs in <sites>) from
<elf>, polls the <ring> ring buffer (``mv_lifecycle`` or
``mv_copies``) for <seconds>, and writes decoded event lines plus
a summary line to <out>:

  lc kind=1 ok=1 skip=0 dir=1 seq=0 ktime=... size=512
  cp kind=2 todev=1 known=1 clamp=0 ezero=0 dir=1 reason=0 ...
  summary observed=.. badframe=.. badrec=.. cnt_obs=.. ...

Decoding mirrors bpf/include/memveil_events.h check order; any
rejected payload counts as a bad record, never an event. Counter
words come from the ``mv_counts`` map, transport words from bridge
stats. Exit 0 on a complete window, 77 on privilege denial
(EPERM anywhere, EACCES at attach; load-time EACCES fails
closed), 2 on usage errors, 1 on anything else.
"""

from std.sys import argv, exit
from std.pathlib import Path
from std.time import perf_counter_ns

from libbpf_mojo._ffi import (
    ATTACH_TRACING,
    OP_ATTACH,
    OP_LOAD,
    read_u16_le,
    read_u32_le,
    read_u64_le,
)
from libbpf_mojo.batch import decode_frame
from libbpf_mojo.error import EPERM, LmbError
from libbpf_mojo.session import AttachSpec, Session

comptime EACCES = Int32(-13)

comptime LC_LEN = 36
comptime LC_MAGIC = UInt32(0x434C564D)
comptime CP_LEN = 48
comptime CP_MAGIC = UInt32(0x5043564D)

comptime LC_KIND_MAP = UInt32(1)
comptime LC_KIND_UNMAP = UInt32(2)
comptime LC_FLAG_OK = UInt32(1)
comptime LC_FLAG_SKIP_SYNC = UInt32(2)

comptime CP_KIND_SYNC = UInt32(1)
comptime CP_KIND_COPY = UInt32(2)
comptime CP_FLAG_TO_DEVICE = UInt32(1)
comptime CP_FLAG_KNOWN = UInt32(2)
comptime CP_FLAG_CLAMPED = UInt32(4)
comptime CP_FLAG_EARLY_ZERO = UInt32(8)
comptime CP_REASON_NOT_COPY = UInt32(4)


@fieldwise_init
struct Fail(Copyable, Writable):
    """A fatal consumer failure carrying its exit code."""

    var code: Int
    var message: String


def u64_to_str(v: UInt64) -> String:
    """Render one u64 as decimal (no formatter dependency)."""
    if v == 0:
        return String("0")
    var digits = String("0123456789")
    var out = String("")
    var rest = v
    while rest > 0:
        var d = Int(rest % 10)
        out = String(digits[byte=d]) + out
        rest = rest // 10
    return out^


def u32_to_str(v: UInt32) -> String:
    return u64_to_str(UInt64(v))


def le_bytes(value: UInt64, count: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(count):
        out.append(UInt8((value >> UInt64(i * 8)) & UInt64(0xFF)))
    return out^


def decode_lc(payload: List[UInt8]) raises Fail -> String:
    """Decode one 36-byte lifecycle record (header check order)."""
    if len(payload) < LC_LEN:
        raise Fail(1, String("lc short"))
    if len(payload) > LC_LEN:
        raise Fail(1, String("lc long"))
    var base = Span(payload).unsafe_ptr()
    if read_u32_le(base, 0) != LC_MAGIC:
        raise Fail(1, String("lc magic"))
    if read_u16_le(base, 4) != UInt32(1):
        raise Fail(1, String("lc version"))
    var kind = read_u16_le(base, 6)
    if kind != LC_KIND_MAP and kind != LC_KIND_UNMAP:
        raise Fail(1, String("lc kind"))
    var flags = read_u16_le(base, 8)
    if flags & ~(LC_FLAG_OK | LC_FLAG_SKIP_SYNC) != UInt32(0):
        raise Fail(1, String("lc flags"))
    var direction = read_u16_le(base, 10)
    if direction > UInt32(2):
        raise Fail(1, String("lc dir"))
    var seq = read_u64_le(base, 12)
    var ktime = read_u64_le(base, 20)
    var size = read_u64_le(base, 28)
    var ok = UInt32(1) if (flags & LC_FLAG_OK) != UInt32(0) else UInt32(0)
    var skip = (
        UInt32(1)
        if (flags & LC_FLAG_SKIP_SYNC) != UInt32(0)
        else UInt32(0)
    )
    var line = String("lc kind=")
    line += u32_to_str(kind)
    line += String(" ok=")
    line += u32_to_str(ok)
    line += String(" skip=")
    line += u32_to_str(skip)
    line += String(" dir=")
    line += u32_to_str(direction)
    line += String(" seq=")
    line += u64_to_str(seq)
    line += String(" ktime=")
    line += u64_to_str(ktime)
    line += String(" size=")
    line += u64_to_str(size)
    return line^


def decode_cp(payload: List[UInt8]) raises Fail -> String:
    """Decode one 48-byte copy record (header check order)."""
    if len(payload) < CP_LEN:
        raise Fail(1, String("cp short"))
    if len(payload) > CP_LEN:
        raise Fail(1, String("cp long"))
    var base = Span(payload).unsafe_ptr()
    if read_u32_le(base, 0) != CP_MAGIC:
        raise Fail(1, String("cp magic"))
    if read_u16_le(base, 4) != UInt32(1):
        raise Fail(1, String("cp version"))
    var kind = read_u16_le(base, 6)
    if kind != CP_KIND_SYNC and kind != CP_KIND_COPY:
        raise Fail(1, String("cp kind"))
    var flags = read_u16_le(base, 8)
    var flag_cap = (
        CP_FLAG_TO_DEVICE | CP_FLAG_KNOWN | CP_FLAG_CLAMPED
    ) | CP_FLAG_EARLY_ZERO
    if flags & ~flag_cap != UInt32(0):
        raise Fail(1, String("cp flags"))
    var direction = read_u16_le(base, 10)
    if direction > UInt32(2) or (kind == CP_KIND_COPY and direction == 0):
        raise Fail(1, String("cp dir"))
    var reason = read_u16_le(base, 44)
    if reason > CP_REASON_NOT_COPY:
        raise Fail(1, String("cp reason"))
    var known = (flags & CP_FLAG_KNOWN) != UInt32(0)
    if known:
        if reason != UInt32(0):
            raise Fail(1, String("cp reason"))
    elif kind == CP_KIND_SYNC:
        if reason != CP_REASON_NOT_COPY:
            raise Fail(1, String("cp reason"))
    elif reason == UInt32(0) or reason == CP_REASON_NOT_COPY:
        raise Fail(1, String("cp reason"))
    var seq = read_u64_le(base, 12)
    var ktime = read_u64_le(base, 20)
    var requested = read_u64_le(base, 28)
    var effective = read_u64_le(base, 36)
    var todev = (
        UInt32(1)
        if (flags & CP_FLAG_TO_DEVICE) != UInt32(0)
        else UInt32(0)
    )
    var known_n = UInt32(1) if known else UInt32(0)
    var clamp = (
        UInt32(1)
        if (flags & CP_FLAG_CLAMPED) != UInt32(0)
        else UInt32(0)
    )
    var ezero = (
        UInt32(1)
        if (flags & CP_FLAG_EARLY_ZERO) != UInt32(0)
        else UInt32(0)
    )
    var line = String("cp kind=")
    line += u32_to_str(kind)
    line += String(" todev=")
    line += u32_to_str(todev)
    line += String(" known=")
    line += u32_to_str(known_n)
    line += String(" clamp=")
    line += u32_to_str(clamp)
    line += String(" ezero=")
    line += u32_to_str(ezero)
    line += String(" dir=")
    line += u32_to_str(direction)
    line += String(" reason=")
    line += u32_to_str(reason)
    line += String(" seq=")
    line += u64_to_str(seq)
    line += String(" ktime=")
    line += u64_to_str(ktime)
    line += String(" req=")
    line += u64_to_str(requested)
    line += String(" eff=")
    line += u64_to_str(effective)
    return line^


def parse_sites(text: String) raises Fail -> List[AttachSpec]:
    """Parse ``prog:symbol,prog:symbol`` into tracing specs."""
    var specs = List[AttachSpec]()
    var raw = text.as_bytes()
    var start = 0
    for i in range(len(raw) + 1):
        var end = i == len(raw)
        var comma = False
        if not end:
            comma = raw[i] == UInt8(44)
        if not end and not comma:
            continue
        if i == start:
            raise Fail(2, String("empty attach site"))
        var colon = -1
        for j in range(start, i):
            if raw[j] == UInt8(58):
                colon = j
        if colon < 0 or colon == start or colon + 1 == i:
            raise Fail(2, String("site needs prog:symbol"))
        var prog = List[UInt8]()
        for j in range(start, colon):
            prog.append(raw[j])
        var sym = List[UInt8]()
        for j in range(colon + 1, i):
            sym.append(raw[j])
        try:
            var prog_s = String(from_utf8=Span(prog))
            var sym_s = String(from_utf8=Span(sym))
            specs.append(
                AttachSpec(prog_s^, ATTACH_TRACING, sym_s^, String(""))
            )
        except e:
            raise Fail(2, String("site is not UTF-8"))
        start = i + 1
    if len(specs) == 0:
        raise Fail(2, String("no attach sites"))
    return specs^


def close_quietly(mut session: Session):
    try:
        session.close()
    except e:
        pass


def self_check() raises Fail -> Int:
    """Offline decoder check over fixed vectors (no privilege)."""
    var lc = List[UInt8]()
    for _ in range(LC_LEN):
        lc.append(UInt8(0))
    lc[0] = UInt8(0x4D)
    lc[1] = UInt8(0x56)
    lc[2] = UInt8(0x4C)
    lc[3] = UInt8(0x43)
    lc[4] = UInt8(1)
    lc[6] = UInt8(1)
    lc[8] = UInt8(1)
    lc[10] = UInt8(1)
    lc[28] = UInt8(0)
    lc[29] = UInt8(2)
    var line = decode_lc(lc.copy())
    if line != String(
        "lc kind=1 ok=1 skip=0 dir=1 seq=0 ktime=0 size=512"
    ):
        raise Fail(1, String("lc vector mismatch: ") + line)
    var bad = lc.copy()
    bad[0] = UInt8(0)
    try:
        _ = decode_lc(bad^)
        raise Fail(1, String("lc bad magic accepted"))
    except e:
        if e.code != 1 or e.message != String("lc magic"):
            raise Fail(1, String("lc bad magic wrong reason"))
    var cp = List[UInt8]()
    for _ in range(CP_LEN):
        cp.append(UInt8(0))
    cp[0] = UInt8(0x4D)
    cp[1] = UInt8(0x56)
    cp[2] = UInt8(0x43)
    cp[3] = UInt8(0x50)
    cp[4] = UInt8(1)
    cp[6] = UInt8(2)
    cp[8] = UInt8(3)
    cp[10] = UInt8(1)
    cp[12] = UInt8(7)
    cp[28] = UInt8(0)
    cp[29] = UInt8(4)
    cp[36] = UInt8(0)
    cp[37] = UInt8(4)
    var cline = decode_cp(cp.copy())
    if cline != String(
        "cp kind=2 todev=1 known=1 clamp=0 ezero=0 dir=1 reason=0"
        " seq=7 ktime=0 req=1024 eff=1024"
    ):
        raise Fail(1, String("cp vector mismatch: ") + cline)
    var badcp = cp.copy()
    badcp[44] = UInt8(4)
    try:
        _ = decode_cp(badcp^)
        raise Fail(1, String("cp known+reason accepted"))
    except e:
        if e.message != String("cp reason"):
            raise Fail(1, String("cp reason wrong reason"))
    print("self-check: 2 decoders ok")
    return 0


def run(args: List[String]) raises Fail -> Int:
    """Full consume flow; every failure carries its exit code."""
    if len(args) == 2 and args[1] == String("--self-check"):
        return self_check()
    if len(args) != 8 or args[1] != String("--bridge"):
        raise Fail(
            2,
            String(
                "usage: mv_consume --bridge PATH <elf> <ring>"
                " <prog:symbol,...> <seconds> <out>"
            ),
        )
    var lib_path = args[2]
    var elf_path = args[3]
    var ring = args[4]
    var is_lc = ring == String("mv_lifecycle")
    var is_cp = ring == String("mv_copies")
    if not is_lc and not is_cp:
        raise Fail(2, String("ring must be mv_lifecycle or mv_copies"))
    var specs = parse_sites(args[5])
    var seconds: Int
    try:
        seconds = Int(args[6])
        if seconds <= 0 or seconds > 3600:
            raise Error("seconds out of range")
    except e:
        raise Fail(2, String("usage error: ") + String(e))
    var out_path = args[7]
    var elf: List[UInt8]
    try:
        elf = Path(elf_path).read_bytes()
    except e:
        raise Fail(1, String("cannot read object: ") + String(e))
    var session: Session
    try:
        session = Session.open_with_lib(
            Span(elf), ring, UInt32(4096), lib_path
        )
    except e:
        raise Fail(1, String("open failed: ") + String(e))
    try:
        session.load()
        session.attach(specs^)
    except e:
        var skipped = e.code == EPERM or (
            e.code == EACCES and e.operation == OP_ATTACH
        )
        var detail = (
            String("setup failed op=")
            + String(Int(e.operation))
            + String(" code=")
            + String(Int(e.code))
            + String(": ")
            + e.message
        )
        if e.code == EACCES and e.operation == OP_LOAD:
            detail += String(" (load-time EACCES fails closed)")
        close_quietly(session)
        if skipped:
            raise Fail(77, detail)
        raise Fail(1, detail)
    print(String("ready ring=") + ring)
    var lines = List[String]()
    var observed = UInt64(0)
    var badframe = UInt64(0)
    var badrec = UInt64(0)
    var dst = List[UInt8](length=4104, fill=UInt8(0))
    var start_ns = perf_counter_ns()
    var budget_ns = seconds * 1000000000
    while True:
        var elapsed_ns = perf_counter_ns() - start_ns
        if elapsed_ns >= budget_ns:
            break
        var remain_ms = (budget_ns - elapsed_ns) // 1000000
        var wait_ms = Int32(1000)
        if remain_ms < 1000:
            wait_ms = Int32(remain_ms)
        if wait_ms <= 0:
            break
        var result = session.poll(dst, 0, UInt32(4104), wait_ms)
        if result.is_timeout():
            continue
        if result.is_error():
            if result.error.code == Int32(-4):
                continue
            close_quietly(session)
            raise Fail(1, String("poll: ") + String(result.error))
        if result.is_short():
            badframe += 1
            continue
        if not result.is_batch():
            badframe += 1
            continue
        try:
            var frame = decode_frame(Span(dst), 0, result.written)
            try:
                if is_lc:
                    lines.append(decode_lc(frame.payload.copy()))
                else:
                    lines.append(decode_cp(frame.payload.copy()))
                observed += 1
            except e:
                badrec += 1
        except e:
            badframe += 1
    var counts = List[UInt64]()
    var short_counters = False
    var rx = UInt64(0)
    var dlv = UInt64(0)
    var mal = UInt64(0)
    var drop = UInt64(0)
    try:
        for key in range(6):
            var kb = le_bytes(UInt64(key), 4)
            var got = session.map_read(
                String("mv_counts"), Span(kb), UInt32(8)
            )
            if got.is_short() or len(got.data) != 8:
                short_counters = True
                break
            counts.append(
                read_u64_le(Span(got.data).unsafe_ptr(), 0)
            )
        if not short_counters:
            var stats = session.stats()
            rx = stats.received
            dlv = stats.delivered
            mal = stats.malformed
            drop = stats.dropped
            session.detach()
    except e:
        close_quietly(session)
        raise Fail(1, String("settle: ") + String(e))
    if short_counters:
        close_quietly(session)
        raise Fail(1, String("settle: counter word short"))
    var text = String("")
    for i in range(len(lines)):
        text += lines[i]
        text += String("\n")
    text += String("summary observed=")
    text += u64_to_str(observed)
    text += String(" badframe=")
    text += u64_to_str(badframe)
    text += String(" badrec=")
    text += u64_to_str(badrec)
    text += String(" cnt_obs=")
    text += u64_to_str(counts[0])
    text += String(" cnt_obsb=")
    text += u64_to_str(counts[1])
    text += String(" cnt_emit=")
    text += u64_to_str(counts[2])
    text += String(" cnt_emitb=")
    text += u64_to_str(counts[3])
    text += String(" cnt_fail=")
    text += u64_to_str(counts[4])
    text += String(" cnt_flags=")
    text += u64_to_str(counts[5])
    text += String(" rx=")
    text += u64_to_str(rx)
    text += String(" dlv=")
    text += u64_to_str(dlv)
    text += String(" mal=")
    text += u64_to_str(mal)
    text += String(" drop=")
    text += u64_to_str(drop)
    text += String("\n")
    try:
        Path(out_path).write_text(text)
    except e:
        close_quietly(session)
        raise Fail(1, String("cannot write out: ") + String(e))
    close_quietly(session)
    return 0


def main() raises:
    var raw = argv()
    var args = List[String]()
    for i in range(len(raw)):
        args.append(raw[i])
    var code: Int
    try:
        code = run(args^)
    except e:
        print(e.message)
        code = e.code
    exit(code)
