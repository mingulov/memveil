# SPDX-License-Identifier: GPL-3.0-or-later

"""Mojo side of the attempts differential (test tool, not shipped).

Reads corpus.bin/corpus.txt, runs every vector through the
product decode_payload (payload records) and a reference
extractor that mirrors the BPF program's context walk (ctx
records, mirroring tests/native/test_attempt_decode.c), asserts
each verdict and all decoded fields, and writes the same verdict
dump format. The attempts lane diffs this output against the C
dump byte-for-byte.

Usage: dump_normalize.mojo corpus.bin corpus.txt out.dump
Exit 0 prints "dump: N vectors passed"; any mismatch exits 1.
"""

from std.sys import argv, exit

from memveil.capture.normalize import (
    NAME_MAX,
    bytes_to_hex,
    decode_payload,
)
from memveil.model.validate import format_u64, parse_u64
from memveil.platform.reader import (
    bytes_to_text,
    is_valid_utf8,
    read_host_file,
)


@fieldwise_init
struct DumpError(Copyable, Writable):
    """One fatal differential failure with its context."""

    var message: String


@fieldwise_init
struct CtxOut(Copyable, Movable):
    """Reference extractor output; fields valid only when reason is OK."""

    var reason: String
    var size: UInt64
    var force: Bool
    var name: List[UInt8]


@fieldwise_init
struct PayOut(Copyable, Movable):
    """Payload decode output; fields valid only when reason is OK."""

    var reason: String
    var size: UInt64
    var force: Bool
    var seq: UInt64
    var ktime: UInt64
    var name: List[UInt8]


def decode_for_dump(inp: List[UInt8]) -> PayOut:
    """Decode one payload without raising; reason carries rejection."""
    try:
        var got = decode_payload(inp)
        return PayOut(
            "OK",
            got.size,
            got.force,
            got.seq,
            got.ktime,
            got.name.copy(),
        )
    except e:
        return PayOut(
            e.reason,
            UInt64(0),
            False,
            UInt64(0),
            UInt64(0),
            List[UInt8](),
        )


comptime _CTX_FIXED = 41
comptime _READ_CAP = 512
comptime _KTIME_BASE = UInt64(1000000000)
comptime _MAX_VECTORS = 4096
comptime _MAX_INPUT = 65536
comptime _FILE_CAP = 1048576


def _ru32(blob: List[UInt8], pos: Int) raises DumpError -> UInt32:
    if pos < 0 or pos + 4 > len(blob):
        raise DumpError("truncated corpus record")
    var v = UInt32(blob[pos])
    v |= UInt32(blob[pos + 1]) << 8
    v |= UInt32(blob[pos + 2]) << 16
    v |= UInt32(blob[pos + 3]) << 24
    return v


def _le64_at(buf: List[UInt8], off: Int) -> UInt64:
    var v = UInt64(0)
    for i in range(8):
        v |= UInt64(buf[off + i]) << UInt64(8 * i)
    return v


def split_lines(text: String) -> List[String]:
    """Split on LF; a trailing unterminated line still counts."""
    var out = List[String]()
    var cur = String("")
    var raw = text.as_bytes()
    for i in range(len(raw)):
        if raw[i] == UInt8(0x0A):
            out.append(cur^)
            cur = String("")
        else:
            cur += String(text[byte=i])
    if cur != "":
        out.append(cur^)
    return out^


def tokenize(line: String) -> List[String]:
    """Split on runs of space/tab; no empty tokens."""
    var toks = List[String]()
    var cur = String("")
    var in_tok = False
    var raw = line.as_bytes()
    for i in range(len(raw)):
        var b = raw[i]
        if b == UInt8(0x20) or b == UInt8(0x09):
            if in_tok:
                toks.append(cur^)
                cur = String("")
                in_tok = False
        else:
            cur += String(line[byte=i])
            in_tok = True
    if in_tok:
        toks.append(cur^)
    return toks^


def has_prefix(text: String, pre: String) -> Bool:
    """Byte-wise prefix check (both sides are ASCII here)."""
    var traw = text.as_bytes()
    var praw = pre.as_bytes()
    if len(traw) < len(praw):
        return False
    for i in range(len(praw)):
        if traw[i] != praw[i]:
            return False
    return True


def strip_prefix(text: String, pre: String) -> String:
    """Bytes after a known prefix; caller must check has_prefix."""
    var out = String("")
    var n = pre.byte_length()
    for i in range(n, text.byte_length()):
        out += String(text[byte=i])
    return out^


def extract_ctx(ctx: List[UInt8]) -> CtxOut:
    """Mirror the BPF context walk over a byte buffer.

    Same predicate order as the C ref_extract: short context,
    dynamic-length faults, extent faults, NUL placement, then
    the force byte. Any skew fails the lane diff.
    """
    var empty = List[UInt8]()
    if len(ctx) < _CTX_FIXED:
        return CtxOut("CTX_SHORT", UInt64(0), False, empty^)
    var loc = (
        UInt32(ctx[8])
        | (UInt32(ctx[9]) << 8)
        | (UInt32(ctx[10]) << 16)
        | (UInt32(ctx[11]) << 24)
    )
    var off = Int(loc & UInt32(0xFFFF))
    var dlen = Int((loc >> UInt32(16)) & UInt32(0xFFFF))
    if dlen == 0:
        return CtxOut("CTX_DLEN_ZERO", UInt64(0), False, empty^)
    if dlen > NAME_MAX + 1:
        return CtxOut("CTX_DLEN_BIG", UInt64(0), False, empty^)
    if off < _CTX_FIXED:
        return CtxOut("CTX_LOC_OOB", UInt64(0), False, empty^)
    if off + dlen > _READ_CAP:
        return CtxOut("CTX_LOC_OOB", UInt64(0), False, empty^)
    if off + dlen > len(ctx):
        return CtxOut("CTX_LOC_OOB", UInt64(0), False, empty^)
    for i in range(dlen):
        var byte = ctx[off + i]
        if i + 1 == dlen:
            if byte != UInt8(0):
                return CtxOut(
                    "CTX_NUL_MISSING", UInt64(0), False, empty^
                )
        elif byte == UInt8(0):
            return CtxOut("CTX_NUL_EARLY", UInt64(0), False, empty^)
    if ctx[40] != UInt8(0) and ctx[40] != UInt8(1):
        return CtxOut("CTX_FORCE_BAD", UInt64(0), False, empty^)
    var name = List[UInt8]()
    for i in range(dlen - 1):
        name.append(ctx[off + i])
    return CtxOut(
        "OK", _le64_at(ctx, 32), ctx[40] == UInt8(1), name^
    )


def pack_attempt(
    size: UInt64, force: Bool, seq: UInt64, ktime: UInt64,
    name: List[UInt8],
) -> List[UInt8]:
    """Pack extractor fields into one 98-byte product payload."""
    var out = List[UInt8]()
    var magic = UInt32(0x3741564D)
    for i in range(4):
        out.append(UInt8((magic >> UInt32(8 * i)) & UInt32(0xFF)))
    out.append(UInt8(1))
    out.append(UInt8(0))
    if force:
        out.append(UInt8(1))
    else:
        out.append(UInt8(0))
    out.append(UInt8(0))
    for i in range(8):
        out.append(UInt8((seq >> UInt64(8 * i)) & UInt64(0xFF)))
    for i in range(8):
        out.append(UInt8((ktime >> UInt64(8 * i)) & UInt64(0xFF)))
    for i in range(8):
        out.append(UInt8((size >> UInt64(8 * i)) & UInt64(0xFF)))
    out.append(UInt8(len(name) & 0xFF))
    out.append(UInt8((len(name) >> 8) & 0xFF))
    for i in range(64):
        if i < len(name):
            out.append(name[i])
        else:
            out.append(UInt8(0))
    return out^


def _parse_u64_here(text: String, what: String) raises DumpError -> UInt64:
    try:
        return parse_u64(text)
    except:
        raise DumpError("bad " + what + ": " + text)


def _ok_line(
    idx: Int, tag: String, size: UInt64, force: Bool, seq: UInt64,
    ktime: UInt64, name: List[UInt8],
) -> String:
    var flag = String("0")
    if force:
        flag = String("1")
    return (
        String(idx)
        + " "
        + tag
        + " OK size="
        + format_u64(size)
        + " force="
        + flag
        + " seq="
        + format_u64(seq)
        + " ktime="
        + format_u64(ktime)
        + " namelen="
        + String(len(name))
        + " name="
        + bytes_to_hex(name)
        + "\n"
    )


def run(bin_path: String, txt_path: String, out_path: String) raises DumpError -> Int:
    """Run the corpus; return the vector count or raise DumpError."""
    var blob: List[UInt8]
    try:
        blob = read_host_file(bin_path, "corpus.bin", _FILE_CAP)
    except:
        raise DumpError("cannot read " + bin_path)
    var txt_bytes: List[UInt8]
    try:
        txt_bytes = read_host_file(txt_path, "corpus.txt", _FILE_CAP)
    except:
        raise DumpError("cannot read " + txt_path)
    if not is_valid_utf8(txt_bytes):
        raise DumpError("corpus.txt is not valid UTF-8")
    var count = Int(_ru32(blob, 0))
    if count > _MAX_VECTORS:
        raise DumpError("bad corpus count")
    var lines = split_lines(bytes_to_text(txt_bytes))
    if len(lines) == 0 or not has_prefix(lines[0], String("#")):
        raise DumpError("missing corpus header")
    var data = List[String]()
    for i in range(1, len(lines)):
        if lines[i] == "":
            continue
        if has_prefix(lines[i], String("#")):
            continue
        data.append(lines[i])
    if len(data) != count:
        raise DumpError("corpus line count desync")
    var dump = String("")
    var pos = 4
    for i in range(count):
        var kind = Int(_ru32(blob, pos))
        pos += 4
        var rlen = Int(_ru32(blob, pos))
        pos += 4
        if kind != 1 and kind != 2:
            raise DumpError("bad corpus record kind")
        if rlen > _MAX_INPUT or pos + rlen > len(blob):
            raise DumpError("bad corpus record length")
        var inp = List[UInt8]()
        for j in range(rlen):
            inp.append(blob[pos + j])
        pos += rlen
        var tag = String("ctx")
        if kind == 2:
            tag = String("payload")
        var toks = tokenize(data[i])
        if len(toks) < 3:
            raise DumpError("unparseable corpus line")
        var exp_idx = _parse_u64_here(toks[0], "idx")
        if exp_idx != UInt64(i) or toks[1] != tag:
            raise DumpError("corpus desync at " + String(i))
        var verdict = toks[2]
        if kind == 1:
            var ext = extract_ctx(inp)
            if ext.reason != verdict:
                raise DumpError(
                    "ctx "
                    + String(i)
                    + ": got "
                    + ext.reason
                    + " want "
                    + verdict
                )
            if ext.reason != "OK":
                dump += String(i) + " ctx " + verdict + "\n"
                continue
            if len(toks) != 9:
                raise DumpError("ctx OK line must carry fields")
            var seq = UInt64(i)
            var ktime = _KTIME_BASE + UInt64(i)
            var packed = pack_attempt(
                ext.size, ext.force, seq, ktime, ext.name
            )
            var decoded = decode_for_dump(packed)
            if decoded.reason != "OK":
                raise DumpError(
                    "ctx " + String(i) + " pipeline: " + decoded.reason
                )
            _check_ok_fields(
                toks, i, True, decoded.size, decoded.force,
                decoded.seq, decoded.ktime, decoded.name,
            )
            dump += _ok_line(
                i, tag, decoded.size, decoded.force, decoded.seq,
                decoded.ktime, decoded.name,
            )
        else:
            var decoded = decode_for_dump(inp)
            if decoded.reason != verdict:
                raise DumpError(
                    "payload "
                    + String(i)
                    + ": got "
                    + decoded.reason
                    + " want "
                    + verdict
                )
            if decoded.reason != "OK":
                dump += String(i) + " payload " + verdict + "\n"
                continue
            if len(toks) != 9:
                raise DumpError("payload OK line must carry fields")
            _check_ok_fields(
                toks, i, False, decoded.size, decoded.force,
                decoded.seq, decoded.ktime, decoded.name,
            )
            dump += _ok_line(
                i, tag, decoded.size, decoded.force, decoded.seq,
                decoded.ktime, decoded.name,
            )
    if pos != len(blob):
        raise DumpError("trailing corpus bytes")
    try:
        var handle = open(out_path, "w")
        handle.write(dump)
        handle.close()
    except:
        raise DumpError("cannot write " + out_path)
    return count


def _check_ok_fields(
    toks: List[String], idx: Int, is_ctx: Bool, size: UInt64,
    force: Bool, seq: UInt64, ktime: UInt64, name: List[UInt8],
) raises DumpError:
    """Compare one OK expectation line against decoded fields."""
    var where = String(idx)
    if not has_prefix(toks[3], String("size=")):
        raise DumpError("vector " + where + ": want size=")
    if _parse_u64_here(strip_prefix(toks[3], String("size=")), "size") != size:
        raise DumpError("vector " + where + ": size mismatch")
    if not has_prefix(toks[4], String("force=")):
        raise DumpError("vector " + where + ": want force=")
    var flag = strip_prefix(toks[4], String("force="))
    if (flag == "1") != force or (flag != "0" and flag != "1"):
        raise DumpError("vector " + where + ": force mismatch")
    if not has_prefix(toks[5], String("seq=")):
        raise DumpError("vector " + where + ": want seq=")
    var seq_text = strip_prefix(toks[5], String("seq="))
    if is_ctx:
        if seq_text != "-":
            raise DumpError("vector " + where + ": want seq=-")
    elif _parse_u64_here(seq_text, "seq") != seq:
        raise DumpError("vector " + where + ": seq mismatch")
    if not has_prefix(toks[6], String("ktime=")):
        raise DumpError("vector " + where + ": want ktime=")
    var ktime_text = strip_prefix(toks[6], String("ktime="))
    if is_ctx:
        if ktime_text != "-":
            raise DumpError("vector " + where + ": want ktime=-")
    elif _parse_u64_here(ktime_text, "ktime") != ktime:
        raise DumpError("vector " + where + ": ktime mismatch")
    if not has_prefix(toks[7], String("namelen=")):
        raise DumpError("vector " + where + ": want namelen=")
    var want_len = Int(
        _parse_u64_here(
            strip_prefix(toks[7], String("namelen=")), "namelen"
        )
    )
    if want_len > NAME_MAX or want_len != len(name):
        raise DumpError("vector " + where + ": namelen mismatch")
    if not has_prefix(toks[8], String("name=")):
        raise DumpError("vector " + where + ": want name=")
    var want_hex = strip_prefix(toks[8], String("name="))
    if want_hex.byte_length() != 2 * want_len:
        raise DumpError("vector " + where + ": name hex length")
    if want_hex != bytes_to_hex(name):
        raise DumpError("vector " + where + ": name mismatch")


def main() raises:
    var args = argv()
    if len(args) != 4:
        print("usage: dump_normalize.mojo corpus.bin corpus.txt out.dump")
        exit(2)
    var count = 0
    try:
        count = run(args[1], args[2], args[3])
    except e:
        print("dump: FAIL " + e.message)
        exit(1)
    print("dump: " + String(count) + " vectors passed")
