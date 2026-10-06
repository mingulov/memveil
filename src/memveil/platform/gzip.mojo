"""Single-member gzip inflation via the system zlib.

`/proc/config.gz` is gzip-framed deflate; the config
binding hashes the INFLATED bytes. Decompression runs
through raw `inflate` (-15 window) from `libz.so.1`,
opened with `OwnedDLHandle` at call time: no link-time
dependency, and a missing zlib reports uncheckable
instead of failing the run. Framing is strict-parsed
(magic, method, flags, name/comment terminators, header
CRC when present, stream CRC32, ISIZE); only trailing
bytes after the first member are ignored.
"""

from std.ffi import OwnedDLHandle

comptime _MAX_GUNZIP_BYTES = 16777216
comptime _ZSTREAM_BYTES = 112
comptime _Z_FINISH = 4
comptime _Z_STREAM_END = 1


@fieldwise_init
struct GunzipOut(Copyable, Movable):
    """One inflation outcome (data valid only when ok)."""

    var ok: Bool
    var data: List[UInt8]
    var message: String


def _u16le(data: Span[UInt8, _], at: Int) -> Int:
    return Int(data[at]) | (Int(data[at + 1]) << 8)


def _u32le(data: Span[UInt8, _], at: Int) -> Int:
    return (
        Int(data[at])
        | (Int(data[at + 1]) << 8)
        | (Int(data[at + 2]) << 16)
        | (Int(data[at + 3]) << 24)
    )


def _fail(message: String) -> GunzipOut:
    return GunzipOut(False, List[UInt8](), message)


def _cstr_bytes(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


def _poke_u64(mut buf: List[UInt8], at: Int, v: UInt64):
    for i in range(8):
        buf[at + i] = UInt8((v >> UInt64(8 * i)) & UInt64(0xFF))


def _poke_u32(mut buf: List[UInt8], at: Int, v: UInt32):
    for i in range(4):
        buf[at + i] = UInt8((v >> UInt32(8 * i)) & UInt32(0xFF))


def _read_u64(buf: Span[UInt8, _], at: Int) -> UInt64:
    var v = UInt64(0)
    for i in range(8):
        v |= UInt64(buf[at + i]) << UInt64(8 * i)
    return v


def gunzip_member(data: Span[UInt8, _], lib_name: String) -> GunzipOut:
    """Inflate the first gzip member of data.

    lib_name is the zlib soname (normally libz.so.1);
    callers pass a bogus name only to prove the
    missing-library path stays uncheckable, never fatal.
    """
    var total = len(data)
    if total < 18:
        return _fail(String("gzip too short"))
    if total > 4294967295:
        return _fail(String("gzip input too big"))
    if data[0] != UInt8(0x1F) or data[1] != UInt8(0x8B):
        return _fail(String("gzip bad magic"))
    if data[2] != UInt8(8):
        return _fail(String("gzip not deflate"))
    var flg = Int(data[3])
    if flg & 0xE0 != 0:
        return _fail(String("gzip reserved flags"))
    var pos = 10
    if flg & 0x04 != 0:
        if pos + 2 > total:
            return _fail(String("gzip truncated extra"))
        pos += 2 + _u16le(data, pos)
        if pos > total:
            return _fail(String("gzip truncated extra"))
    if flg & 0x08 != 0:
        while True:
            if pos >= total:
                return _fail(String("gzip unterminated name"))
            if data[pos] == UInt8(0):
                break
            pos += 1
        pos += 1
    if flg & 0x10 != 0:
        while True:
            if pos >= total:
                return _fail(String("gzip unterminated comment"))
            if data[pos] == UInt8(0):
                break
            pos += 1
        pos += 1
    var header_end = pos
    if flg & 0x02 != 0:
        if pos + 2 > total:
            return _fail(String("gzip truncated header crc"))
        pos += 2
    if pos + 8 > total:
        return _fail(String("gzip truncated stream"))
    var want_crc = _u32le(data, total - 8)
    var isize = _u32le(data, total - 4)
    if isize > _MAX_GUNZIP_BYTES:
        return _fail(String("gzip output too big"))
    if isize == 0:
        if want_crc != 0:
            return _fail(String("gzip crc mismatch"))
        return GunzipOut(True, List[UInt8](), String(""))
    var lib: OwnedDLHandle
    try:
        lib = OwnedDLHandle(lib_name)
    except:
        return _fail(String("zlib unavailable"))
    try:
        var crc32f = lib.get_function[UInt64](String("crc32"))
        if flg & 0x02 != 0:
            var header_crc = crc32f(
                UInt64(0), data.unsafe_ptr(), UInt64(header_end)
            )
            if Int(header_crc & UInt64(0xFFFF)) != _u16le(
                data, header_end
            ):
                return _fail(String("gzip header crc mismatch"))
        # Raw inflate through a hand-built z_stream (LP64
        # layout, 112 bytes; next_in@0, avail_in@8,
        # next_out@24, avail_out@32, total_out@40, the rest
        # zero for default allocation). Only inflateInit2_'s
        # version[0] ('1') and the struct size are checked
        # by zlib, so this holds across zlib 1.x.
        var out = List[UInt8](length=isize, fill=UInt8(0))
        var out_span = Span(out)
        var zs = List[UInt8](length=_ZSTREAM_BYTES, fill=UInt8(0))
        _poke_u64(
            zs, 0, UInt64(data.unsafe_ptr().unsafe_offset(pos))
        )
        _poke_u32(zs, 8, UInt32(total - 8 - pos))
        _poke_u64(zs, 24, UInt64(out_span.unsafe_ptr()))
        _poke_u32(zs, 32, UInt32(isize))
        var versa = _cstr_bytes(String("1.2.0"))
        var zs_span = Span(zs)
        var init = lib.get_function[Int32](String("inflateInit2_"))
        var irc = init(
            zs_span.unsafe_ptr(),
            Int32(-15),
            Span(versa).unsafe_ptr(),
            Int32(_ZSTREAM_BYTES),
        )
        if Int(irc) != 0:
            return _fail(
                String("zlib init error ") + String(Int(irc))
            )
        var inflate = lib.get_function[Int32](String("inflate"))
        var frc = inflate(
            zs_span.unsafe_ptr(), Int32(_Z_FINISH)
        )
        var endf = lib.get_function[Int32](String("inflateEnd"))
        _ = endf(zs_span.unsafe_ptr())
        if Int(frc) != _Z_STREAM_END:
            return _fail(
                String("zlib inflate error ") + String(Int(frc))
            )
        if _read_u64(zs_span, 40) != UInt64(isize):
            return _fail(String("gzip length mismatch"))
        var got_crc = crc32f(
            UInt64(0), out_span.unsafe_ptr(), UInt64(isize)
        )
        if Int(got_crc & UInt64(0xFFFFFFFF)) != want_crc:
            return _fail(String("gzip crc mismatch"))
        return GunzipOut(True, out^, String(""))
    except e:
        return _fail(String("zlib call failed: ") + String(e))
