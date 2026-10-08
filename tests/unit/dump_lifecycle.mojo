# SPDX-License-Identifier: GPL-3.0-or-later

"""Mojo side of the lifecycle differential (test tool, not shipped).

Reads corpus.bin/corpus.txt, runs every vector through the
product decode_lifecycle / decode_copy / effective_bytes,
asserts each verdict and all decoded fields, and writes the
same verdict dump format as
tests/native/test_lifecycle_decode.c. The native-decode lane
diffs the two outputs byte-for-byte.

Usage: dump_lifecycle.mojo corpus.bin corpus.txt out.dump
Exit 0 prints "dump: N vectors passed"; any mismatch exits 1.
"""

from std.sys import argv, exit

from memveil.capture.lifecycle import (
    DecodedCopy,
    DecodedLifecycle,
    EffectiveOut,
    decode_copy,
    decode_lifecycle,
    effective_bytes,
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
struct LcOut(Copyable, Movable):
    """Lifecycle decode output; fields valid only on OK."""

    var reason: String
    var decoded: DecodedLifecycle


@fieldwise_init
struct CpOut(Copyable, Movable):
    """Copy decode output; fields valid only on OK."""

    var reason: String
    var decoded: DecodedCopy


comptime _MAX_VECTORS = 4096
comptime _MAX_INPUT = 65536
comptime _FILE_CAP = 1048576
comptime _EFF_INPUT_LEN = 25


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


def decode_lc_for_dump(inp: List[UInt8]) -> LcOut:
    """Decode one lifecycle record without raising."""
    try:
        var got = decode_lifecycle(inp)
        return LcOut("OK", got^)
    except e:
        var empty = DecodedLifecycle(
            UInt16(0), False, False, UInt16(0), UInt64(0),
            UInt64(0), UInt64(0),
        )
        return LcOut(e.reason, empty^)


def decode_cp_for_dump(inp: List[UInt8]) -> CpOut:
    """Decode one copy record without raising."""
    try:
        var got = decode_copy(inp)
        return CpOut("OK", got^)
    except e:
        var empty = DecodedCopy(
            UInt16(0), False, False, False, False, UInt16(0),
            UInt16(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0),
        )
        return CpOut(e.reason, empty^)


def _parse_u64_here(text: String, what: String) raises DumpError -> UInt64:
    try:
        return parse_u64(text)
    except:
        raise DumpError("bad " + what + ": " + text)


def _parse_bit_here(text: String, what: String) raises DumpError -> Bool:
    if text == "0":
        return False
    if text == "1":
        return True
    raise DumpError("bad " + what + ": " + text)


def _flag(v: Bool) -> String:
    if v:
        return String("1")
    return String("0")


def _ok_lc_line(idx: Int, d: DecodedLifecycle) -> String:
    return (
        String(idx)
        + " lifecycle OK kind="
        + String(Int(d.kind))
        + " ok="
        + _flag(d.ok)
        + " skip="
        + _flag(d.skip_sync)
        + " dir="
        + String(Int(d.dir))
        + " seq="
        + format_u64(d.seq)
        + " ktime="
        + format_u64(d.ktime)
        + " size="
        + format_u64(d.size)
        + "\n"
    )


def _ok_cp_line(idx: Int, d: DecodedCopy) -> String:
    return (
        String(idx)
        + " copy OK kind="
        + String(Int(d.kind))
        + " todevice="
        + _flag(d.to_device)
        + " known="
        + _flag(d.known)
        + " clamped="
        + _flag(d.clamped)
        + " earlyzero="
        + _flag(d.early_zero)
        + " dir="
        + String(Int(d.dir))
        + " reason="
        + String(Int(d.reason))
        + " seq="
        + format_u64(d.seq)
        + " ktime="
        + format_u64(d.ktime)
        + " requested="
        + format_u64(d.requested)
        + " effective="
        + format_u64(d.effective)
        + "\n"
    )


def _ok_eff_line(idx: Int, e: EffectiveOut) -> String:
    return (
        String(idx)
        + " effective OK effective="
        + format_u64(e.effective)
        + " clamped="
        + _flag(e.clamped)
        + " earlyzero="
        + _flag(e.early_zero)
        + "\n"
    )


def _check_lc_ok_fields(
    toks: List[String], idx: Int, d: DecodedLifecycle
) raises DumpError:
    """Compare one lifecycle OK line against decoded fields."""
    var where = String(idx)
    if len(toks) != 10:
        raise DumpError("vector " + where + ": want 7 lc fields")
    var keys = List[String]()
    keys.append(String("kind="))
    keys.append(String("ok="))
    keys.append(String("skip="))
    keys.append(String("dir="))
    keys.append(String("seq="))
    keys.append(String("ktime="))
    keys.append(String("size="))
    for k in range(7):
        if not has_prefix(toks[3 + k], keys[k]):
            raise DumpError(
                "vector " + where + ": want " + keys[k]
            )
    var kind = Int(_parse_u64_here(
        strip_prefix(toks[3], String("kind=")), "kind"))
    if kind != Int(d.kind):
        raise DumpError("vector " + where + ": kind mismatch")
    var ok = _parse_bit_here(
        strip_prefix(toks[4], String("ok=")), "ok")
    if ok != d.ok:
        raise DumpError("vector " + where + ": ok mismatch")
    var skip = _parse_bit_here(
        strip_prefix(toks[5], String("skip=")), "skip")
    if skip != d.skip_sync:
        raise DumpError("vector " + where + ": skip mismatch")
    var dir = Int(_parse_u64_here(
        strip_prefix(toks[6], String("dir=")), "dir"))
    if dir != Int(d.dir):
        raise DumpError("vector " + where + ": dir mismatch")
    if _parse_u64_here(
        strip_prefix(toks[7], String("seq=")), "seq"
    ) != d.seq:
        raise DumpError("vector " + where + ": seq mismatch")
    if _parse_u64_here(
        strip_prefix(toks[8], String("ktime=")), "ktime"
    ) != d.ktime:
        raise DumpError("vector " + where + ": ktime mismatch")
    if _parse_u64_here(
        strip_prefix(toks[9], String("size=")), "size"
    ) != d.size:
        raise DumpError("vector " + where + ": size mismatch")


def _check_cp_ok_fields(
    toks: List[String], idx: Int, d: DecodedCopy
) raises DumpError:
    """Compare one copy OK line against decoded fields."""
    var where = String(idx)
    if len(toks) != 14:
        raise DumpError("vector " + where + ": want 11 cp fields")
    var keys = List[String]()
    keys.append(String("kind="))
    keys.append(String("todevice="))
    keys.append(String("known="))
    keys.append(String("clamped="))
    keys.append(String("earlyzero="))
    keys.append(String("dir="))
    keys.append(String("reason="))
    keys.append(String("seq="))
    keys.append(String("ktime="))
    keys.append(String("requested="))
    keys.append(String("effective="))
    for k in range(11):
        if not has_prefix(toks[3 + k], keys[k]):
            raise DumpError(
                "vector " + where + ": want " + keys[k]
            )
    var kind = Int(_parse_u64_here(
        strip_prefix(toks[3], String("kind=")), "kind"))
    if kind != Int(d.kind):
        raise DumpError("vector " + where + ": kind mismatch")
    if _parse_bit_here(
        strip_prefix(toks[4], String("todevice=")), "todevice"
    ) != d.to_device:
        raise DumpError("vector " + where + ": todevice mismatch")
    if _parse_bit_here(
        strip_prefix(toks[5], String("known=")), "known"
    ) != d.known:
        raise DumpError("vector " + where + ": known mismatch")
    if _parse_bit_here(
        strip_prefix(toks[6], String("clamped=")), "clamped"
    ) != d.clamped:
        raise DumpError("vector " + where + ": clamped mismatch")
    if _parse_bit_here(
        strip_prefix(toks[7], String("earlyzero=")), "earlyzero"
    ) != d.early_zero:
        raise DumpError("vector " + where + ": earlyzero mismatch")
    var dir = Int(_parse_u64_here(
        strip_prefix(toks[8], String("dir=")), "dir"))
    if dir != Int(d.dir):
        raise DumpError("vector " + where + ": dir mismatch")
    var reason = Int(_parse_u64_here(
        strip_prefix(toks[9], String("reason=")), "reason"))
    if reason != Int(d.reason):
        raise DumpError("vector " + where + ": reason mismatch")
    if _parse_u64_here(
        strip_prefix(toks[10], String("seq=")), "seq"
    ) != d.seq:
        raise DumpError("vector " + where + ": seq mismatch")
    if _parse_u64_here(
        strip_prefix(toks[11], String("ktime=")), "ktime"
    ) != d.ktime:
        raise DumpError("vector " + where + ": ktime mismatch")
    if _parse_u64_here(
        strip_prefix(toks[12], String("requested=")), "requested"
    ) != d.requested:
        raise DumpError("vector " + where + ": requested mismatch")
    if _parse_u64_here(
        strip_prefix(toks[13], String("effective=")), "effective"
    ) != d.effective:
        raise DumpError("vector " + where + ": effective mismatch")


def _check_eff_ok_fields(
    toks: List[String], idx: Int, e: EffectiveOut
) raises DumpError:
    """Compare one effective OK line against the computed rule."""
    var where = String(idx)
    if len(toks) != 6:
        raise DumpError("vector " + where + ": want 3 eff fields")
    if not has_prefix(toks[3], String("effective=")):
        raise DumpError("vector " + where + ": want effective=")
    if _parse_u64_here(
        strip_prefix(toks[3], String("effective=")), "effective"
    ) != e.effective:
        raise DumpError("vector " + where + ": effective mismatch")
    if _parse_bit_here(
        strip_prefix(toks[4], String("clamped=")), "clamped"
    ) != e.clamped:
        raise DumpError("vector " + where + ": clamped mismatch")
    if _parse_bit_here(
        strip_prefix(toks[5], String("earlyzero=")), "earlyzero"
    ) != e.early_zero:
        raise DumpError("vector " + where + ": earlyzero mismatch")


def run(
    bin_path: String, txt_path: String, out_path: String
) raises DumpError -> Int:
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
        if kind != 1 and kind != 2 and kind != 3:
            raise DumpError("bad corpus record kind")
        if rlen > _MAX_INPUT or pos + rlen > len(blob):
            raise DumpError("bad corpus record length")
        var inp = List[UInt8]()
        for j in range(rlen):
            inp.append(blob[pos + j])
        pos += rlen
        var tag = String("lifecycle")
        if kind == 2:
            tag = String("copy")
        elif kind == 3:
            tag = String("effective")
        var toks = tokenize(data[i])
        if len(toks) < 3:
            raise DumpError("unparseable corpus line")
        var exp_idx = _parse_u64_here(toks[0], "idx")
        if exp_idx != UInt64(i) or toks[1] != tag:
            raise DumpError("corpus desync at " + String(i))
        var verdict = toks[2]
        if kind == 1:
            var decoded = decode_lc_for_dump(inp)
            if decoded.reason != verdict:
                raise DumpError(
                    "lifecycle "
                    + String(i)
                    + ": got "
                    + decoded.reason
                    + " want "
                    + verdict
                )
            if decoded.reason != "OK":
                dump += String(i) + " lifecycle " + verdict + "\n"
                continue
            _check_lc_ok_fields(toks, i, decoded.decoded)
            dump += _ok_lc_line(i, decoded.decoded)
        elif kind == 2:
            var decoded = decode_cp_for_dump(inp)
            if decoded.reason != verdict:
                raise DumpError(
                    "copy "
                    + String(i)
                    + ": got "
                    + decoded.reason
                    + " want "
                    + verdict
                )
            if decoded.reason != "OK":
                dump += String(i) + " copy " + verdict + "\n"
                continue
            _check_cp_ok_fields(toks, i, decoded.decoded)
            dump += _ok_cp_line(i, decoded.decoded)
        else:
            if rlen != _EFF_INPUT_LEN:
                raise DumpError("bad effective input length")
            if verdict != "OK":
                raise DumpError("effective vector must expect OK")
            var size = _le64_at(inp, 0)
            var off_bits = _le64_at(inp, 8)
            var off = Int64(off_bits)
            var alloc = _le64_at(inp, 16)
            var valid = inp[24] != UInt8(0)
            var e = effective_bytes(size, off, alloc, valid)
            _check_eff_ok_fields(toks, i, e)
            dump += _ok_eff_line(i, e)
    if pos != len(blob):
        raise DumpError("trailing corpus bytes")
    try:
        var handle = open(out_path, "w")
        handle.write(dump)
        handle.close()
    except:
        raise DumpError("cannot write " + out_path)
    return count


def main() raises:
    var args = argv()
    if len(args) != 4:
        print("usage: dump_lifecycle.mojo corpus.bin corpus.txt out.dump")
        exit(2)
    var count = 0
    try:
        count = run(args[1], args[2], args[3])
    except e:
        print("dump: FAIL " + e.message)
        exit(1)
    print("dump: " + String(count) + " vectors passed")
