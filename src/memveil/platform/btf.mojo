# SPDX-License-Identifier: GPL-3.0-or-later

"""Minimal BTF map-definition reader for admission.

Locates the `.BTF` section of a BPF object, walks its type
section, and extracts the map definitions the product
needs: `mv_counts` (ARRAY geometry, pinned exactly),
`mv_attempts` (RINGBUF type plus its declared ring size),
and, for the attempt object only, `mv_offsets` (ARRAY
geometry, pinned exactly). The ring size becomes the live
`ring_bytes` identity value and the collector's post-load
gate; the exact expected value is pinned by the admitting
profile binding, never here. Anything structurally off
refuses: this never loads or executes anything.

BTF layout follows `linux/btf.h` (magic 0xeB9F, kind ids
0..19). `__uint` members resolve as PTR straight to ARRAY
with the value in `nr_elems`; `__type` members resolve as
PTR through modifiers to INT with the size in bytes, or
to STRUCT with the size in bytes for the offsets value.
"""

comptime _BTF_MAGIC = 0xEB9F
comptime _BTF_VERSION = 1
comptime MAX_KERNEL_BTF_BYTES = 67108864
comptime _MAP_ARRAY = 2
comptime _MAP_RINGBUF = 27
comptime _MIN_RING_BYTES = 4096
comptime _MAX_RING_BYTES = 2147483648
# Total spell-depth budget: each pointer, modifier,
# or array level consumes one step of _spell_btf_type,
# and each modifier hop consumes one step of
# int_size. Hook prototypes nest a few levels deep;
# 32 is generous and cycle-safe (cycles refuse via
# this budget). Pinned by the chain31/chain32 tests.
comptime _MAX_SPELL_DEPTH = 32


struct BtfMaps(ImplicitlyCopyable):
    """One BTF map read: geometry verdict plus the ring size."""

    var ok: Bool
    var message: String
    var ring_bytes: Int

    def __init__(out self):
        self.ok = False
        self.message = String("")
        self.ring_bytes = 0


struct _BtfSection(ImplicitlyCopyable):
    var found: Bool
    var offset: Int
    var size: Int

    def __init__(out self):
        self.found = False
        self.offset = 0
        self.size = 0


def _u16(data: Span[UInt8, _], at: Int) -> Int:
    return Int(data[at]) | (Int(data[at + 1]) << 8)


def _u32(data: Span[UInt8, _], at: Int) -> Int:
    return (
        Int(data[at])
        | (Int(data[at + 1]) << 8)
        | (Int(data[at + 2]) << 16)
        | (Int(data[at + 3]) << 24)
    )


def _u64(data: Span[UInt8, _], at: Int) -> Int:
    return (
        Int(data[at])
        | (Int(data[at + 1]) << 8)
        | (Int(data[at + 2]) << 16)
        | (Int(data[at + 3]) << 24)
        | (Int(data[at + 4]) << 32)
        | (Int(data[at + 5]) << 40)
        | (Int(data[at + 6]) << 48)
        | (Int(data[at + 7]) << 56)
    )


def _table_text(
    data: Span[UInt8, _],
    base: Int,
    limit: Int,
    off: Int,
    mut text: String,
) -> Bool:
    """NUL-terminated string at base+off, bounded by limit."""
    if off < 0 or base + off >= limit:
        return False
    var end = base + off
    while end < limit and data[end] != UInt8(0):
        end += 1
    if end >= limit:
        return False
    var raw = List[UInt8]()
    for i in range(base + off, end):
        raw.append(data[i])
    try:
        text = String(from_utf8=Span(raw))
    except:
        return False
    return True


def _find_section(data: Span[UInt8, _], want: String) -> _BtfSection:
    """Locate one ELF section by exact name (fail-closed)."""
    var out = _BtfSection()
    var total = len(data)
    if total < 64:
        return out^
    if (
        data[0] != UInt8(0x7F)
        or data[1] != UInt8(0x45)
        or data[2] != UInt8(0x4C)
        or data[3] != UInt8(0x46)
        or data[4] != UInt8(2)
        or data[5] != UInt8(1)
        or data[6] != UInt8(1)
    ):
        return out^
    if _u16(data, 0x10) != 1 or _u16(data, 0x12) != 247:
        return out^
    var shoff = _u64(data, 0x28)
    var shentsize = _u16(data, 0x3A)
    var shnum = _u16(data, 0x3C)
    var shstrndx = _u16(data, 0x3E)
    if shentsize != 64 or shnum == 0 or shstrndx >= shnum:
        return out^
    if shoff < 0 or shoff > total or shnum > (total - shoff) // 64:
        return out^
    var str_base = shoff + shstrndx * 64
    var str_off = _u64(data, str_base + 24)
    var str_size = _u64(data, str_base + 32)
    if str_off < 0 or str_size < 0 or str_off > total:
        return out^
    if str_size > total - str_off:
        return out^
    var str_end = str_off + str_size
    for i in range(shnum):
        var base = shoff + i * 64
        var sh_name = _u32(data, base)
        var sec_name = String("")
        if not _table_text(data, str_off, str_end, sh_name, sec_name):
            return out^
        if sec_name == want:
            var sec_off = _u64(data, base + 24)
            var sec_size = _u64(data, base + 32)
            if sec_off < 0 or sec_size < 0 or sec_off > total:
                return out^
            if sec_size > total - sec_off:
                return out^
            out.found = True
            out.offset = sec_off
            out.size = sec_size
            return out^
    return out^


struct _BtfWalk(Copyable):
    """One walked BTF blob: type records plus string bounds."""

    var ok: Bool
    var message: String
    var offsets: List[Int]
    var kinds: List[Int]
    var kflags: List[Int]
    var vlens: List[Int]
    var sizes: List[Int]
    var str_base: Int
    var str_end: Int

    def __init__(out self):
        self.ok = False
        self.message = String("")
        self.offsets = List[Int]()
        self.kinds = List[Int]()
        self.kflags = List[Int]()
        self.vlens = List[Int]()
        self.sizes = List[Int]()
        self.str_base = 0
        self.str_end = 0

    def type_name(
        self, data: Span[UInt8, _], rec: Int, mut text: String
    ) -> Bool:
        """Name of one walked record (index into the walk lists)."""
        var name_off = _u32(data, self.offsets[rec])
        return _table_text(
            data, self.str_base, self.str_end, name_off, text
        )

    def find_var(self, data: Span[UInt8, _], want: String) -> Int:
        """Walk-list index of the VAR named want.

        -1 missing, -2 strings corrupt, -3 duplicate name:
        a map name must associate with exactly one VAR.
        """
        var found = -1
        for i in range(len(self.offsets)):
            if self.kinds[i] != 14:
                continue
            var text = String("")
            if not self.type_name(data, i, text):
                return -2
            if text == want:
                if found >= 0:
                    return -3
                found = i
        return found

    def datasec_var(
        self, data: Span[UInt8, _], sec: String, var_rec: Int
    ) -> Int:
        """Membership of VAR rec in DATASEC sec.

        1 member, 0 no such DATASEC, -1 strings corrupt,
        -2 duplicate DATASEC, -4 VAR not listed: each map
        VAR must sit in the one maps DATASEC exactly.
        """
        var found = -1
        for i in range(len(self.offsets)):
            if self.kinds[i] != 15:
                continue
            var text = String("")
            if not self.type_name(data, i, text):
                return -1
            if text != sec:
                continue
            if found >= 0:
                return -2
            found = i
        if found < 0:
            return 0
        var base = self.offsets[found]
        var want = var_rec + 1
        for m in range(self.vlens[found]):
            if _u32(data, base + 12 + m * 12) == want:
                return 1
        return -4

    def member_type(
        self, data: Span[UInt8, _], rec: Int, want: String
    ) -> Int:
        """Type id of the STRUCT member named want, or -1."""
        var base = self.offsets[rec]
        for m in range(self.vlens[rec]):
            var name_off = _u32(data, base + 12 + m * 12)
            var text = String("")
            if not _table_text(
                data, self.str_base, self.str_end, name_off, text
            ):
                return -2
            if text == want:
                return _u32(data, base + 12 + m * 12 + 4)
        return -1

    def rec_valid(self, tid: Int) -> Bool:
        return tid >= 1 and tid <= len(self.offsets)

    def uint_value(self, data: Span[UInt8, _], tid: Int) -> Int:
        """nr_elems behind a direct PTR to ARRAY, or -1."""
        if not self.rec_valid(tid) or self.kinds[tid - 1] != 2:
            return -1
        var arr = self.sizes[tid - 1]
        if not self.rec_valid(arr) or self.kinds[arr - 1] != 3:
            return -1
        return _u32(data, self.offsets[arr - 1] + 20)

    def int_size(self, data: Span[UInt8, _], tid: Int) -> Int:
        """Pointee INT size through modifiers, or -1."""
        if not self.rec_valid(tid) or self.kinds[tid - 1] != 2:
            return -1
        var cur = self.sizes[tid - 1]
        for _ in range(_MAX_SPELL_DEPTH):
            if not self.rec_valid(cur):
                return -1
            var kind = self.kinds[cur - 1]
            if kind == 1:
                return self.sizes[cur - 1]
            if (
                kind != 8
                and kind != 9
                and kind != 10
                and kind != 11
                and kind != 18
            ):
                return -1
            cur = self.sizes[cur - 1]
        return -1

    def struct_size(self, data: Span[UInt8, _], tid: Int) -> Int:
        """Pointee STRUCT size through modifiers, or -1."""
        if not self.rec_valid(tid) or self.kinds[tid - 1] != 2:
            return -1
        var cur = self.sizes[tid - 1]
        for _ in range(_MAX_SPELL_DEPTH):
            if not self.rec_valid(cur):
                return -1
            var kind = self.kinds[cur - 1]
            if kind == 4:
                return self.sizes[cur - 1]
            if (
                kind != 8
                and kind != 9
                and kind != 10
                and kind != 11
                and kind != 18
            ):
                return -1
            cur = self.sizes[cur - 1]
        return -1

    def var_linkage(self, data: Span[UInt8, _], rec: Int) -> Int:
        return _u32(data, self.offsets[rec] + 12)


def _refuse_walk(message: String) -> _BtfWalk:
    var out = _BtfWalk()
    out.ok = False
    out.message = message
    return out^


def _walk_btf(data: Span[UInt8, _], base: Int, size: Int) -> _BtfWalk:
    """Walk one BTF blob into indexed type records (1-based ids)."""
    if size < 24:
        return _refuse_walk(String("BTF too small"))
    if (
        _u16(data, base) != _BTF_MAGIC
        or Int(data[base + 2]) != _BTF_VERSION
    ):
        return _refuse_walk(String("bad BTF header"))
    var hdr_len = _u32(data, base + 4)
    var type_off = _u32(data, base + 8)
    var type_len = _u32(data, base + 12)
    var str_off = _u32(data, base + 16)
    var str_len = _u32(data, base + 20)
    if hdr_len < 24 or hdr_len > size:
        return _refuse_walk(String("bad BTF header"))
    if type_off < 0 or type_len < 0 or type_off > size - hdr_len:
        return _refuse_walk(String("BTF sections out of range"))
    if type_len > size - hdr_len - type_off:
        return _refuse_walk(String("BTF sections out of range"))
    if str_off < 0 or str_len < 0 or str_off > size - hdr_len:
        return _refuse_walk(String("BTF sections out of range"))
    if str_len > size - hdr_len - str_off:
        return _refuse_walk(String("BTF sections out of range"))
    var tbase = base + hdr_len + type_off
    var tend = tbase + type_len
    var out = _BtfWalk()
    out.str_base = base + hdr_len + str_off
    out.str_end = out.str_base + str_len
    var p = tbase
    while p < tend:
        if p + 12 > tend:
            return _refuse_walk(String("BTF types corrupt"))
        var info = _u32(data, p + 4)
        var kind = (info >> 24) & 31
        var kflag = (info >> 31) & 1
        # kind_flag (bit 31) changes interpretation, not
        # record layout: STRUCT/UNION members stay 12
        # bytes (bitfield offsets pack into the offset
        # word) and ENUM/ENUM64 entries stay 8/12 bytes.
        # The walk below consumes only name/type/size
        # fields the flag never relocates, so flagged
        # records stay aligned and accepted; the flag is
        # recorded per type for future consumers.
        var vlen = info & 65535
        var extra = -1
        if kind == 1 or kind == 14 or kind == 17:
            extra = 4
        elif kind == 3:
            extra = 12
        elif kind == 4 or kind == 5 or kind == 15:
            extra = vlen * 12
        elif kind == 6 or kind == 13:
            extra = vlen * 8
        elif kind == 19:
            extra = vlen * 12
        elif (
            kind == 0
            or kind == 2
            or kind == 7
            or kind == 8
            or kind == 9
            or kind == 10
            or kind == 11
            or kind == 12
            or kind == 16
            or kind == 18
        ):
            extra = 0
        if extra < 0:
            return _refuse_walk(String(t"unknown BTF kind {kind}"))
        if p + 12 + extra > tend:
            return _refuse_walk(String("BTF types corrupt"))
        out.offsets.append(p)
        out.kinds.append(kind)
        out.kflags.append(kflag)
        out.vlens.append(vlen)
        out.sizes.append(_u32(data, p + 8))
        p += 12 + extra
    if p != tend:
        return _refuse_walk(String("BTF types corrupt"))
    out.ok = True
    out.message = String("")
    return out^


def classify_btf_message(message: String) -> String:
    """Map one BTF reader message to a health code, else "".

    Structural failures classify as truncated or
    malformed; anything else (missing names, prototype
    detail) is not structural and stays unclassified.
    """
    if message == String("BTF too small"):
        return String("btf-truncated")
    if message == String("BTF sections out of range"):
        return String("btf-truncated")
    if message == String("bad BTF header"):
        return String("btf-malformed")
    if message == String("BTF types corrupt"):
        return String("btf-malformed")
    if message == String("BTF strings corrupt"):
        return String("btf-malformed")
    if message.startswith(String("unknown BTF kind ")):
        return String("btf-malformed")
    return String("")


struct BtfHealth(Copyable):
    """One BTF blob health verdict: ok, or a stable code."""

    var ok: Bool
    var code: String
    var message: String

    def __init__(out self):
        self.ok = False
        self.code = String("")
        self.message = String("")


def check_btf_health(data: Span[UInt8, _]) -> BtfHealth:
    """Classify one raw BTF blob: healthy, split, or broken.

    A blob that walks but whose string section starts
    past a NUL needs its base BTF; anything failing the
    walk classifies as truncated or malformed, never ok.
    """
    var out = BtfHealth()
    var walk = _walk_btf(data, 0, len(data))
    if not walk.ok:
        out.code = classify_btf_message(walk.message.copy())
        out.message = walk.message.copy()
        return out^
    if walk.str_end > walk.str_base and data[walk.str_base] != UInt8(0):
        out.code = String("btf-split")
        out.message = String(
            "split BTF needs base (string section does not start with NUL)"
        )
        return out^
    out.ok = True
    return out^


def _refuse_maps(message: String) -> BtfMaps:
    var out = BtfMaps()
    out.ok = False
    out.message = message
    out.ring_bytes = 0
    return out^


def _is_pow2(v: Int) -> Bool:
    return v > 0 and (v & (v - 1)) == 0


def read_btf_maps(data: Span[UInt8, _]) -> BtfMaps:
    """Read the mv_counts/mv_attempts/mv_offsets definitions.

    mv_counts geometry is pinned exactly (ARRAY, key 4,
    value 8, 6 entries); mv_attempts must be RINGBUF with
    a sane power-of-two ring size, which is returned; the
    mv_offsets table geometry is pinned exactly (ARRAY,
    key 4, value 24, 1 entry). The exact expected ring
    size is the profile binding's job, never this
    reader's.
    """
    return _read_btf_maps(
        data, String("mv_attempts"), String("attempts"), True)


def read_btf_maps_ring(
    data: Span[UInt8, _], ring_var: String, ring_word: String
) -> BtfMaps:
    """Read mv_counts plus one named ringbuf map definition.

    Same pinned mv_counts geometry as read_btf_maps; the
    named ring variable must be RINGBUF with a sane
    power-of-two size. Diagnostics name ring_word (short
    channel word) and ring_var (BTF variable name).
    Tracing channels carry no offset table, so no
    offsets pin applies here.
    """
    return _read_btf_maps(data, ring_var, ring_word, False)


def _check_offsets_map(data: Span[UInt8, _], walk: _BtfWalk) -> String:
    """Offsets-table geometry verdict for one walk, else "".

    mv_offsets must be a defined VAR in the maps DATASEC
    with exactly ARRAY type, 1 entry, key width 4, and a
    24-byte struct value (struct mv_offsets).
    """
    var found = walk.find_var(data, String("mv_offsets"))
    if found == -1:
        return String("missing mv_offsets")
    if found == -2:
        return String("BTF strings corrupt")
    if found == -3:
        return String("duplicate mv_offsets")
    var mem = walk.datasec_var(data, String(".maps"), found)
    if mem == 0:
        return String("no maps DATASEC")
    if mem == -1:
        return String("BTF strings corrupt")
    if mem == -2:
        return String("duplicate maps DATASEC")
    if mem == -4:
        return String("offsets not in maps DATASEC")
    var def_struct = walk.sizes[found]
    if not walk.rec_valid(def_struct):
        return String("offsets not a struct")
    var rec = def_struct - 1
    if walk.kinds[rec] != 4:
        return String("offsets not a struct")
    var link = walk.var_linkage(data, found)
    if link != 0 and link != 1:
        return String(t"offsets linkage {link}")
    var otype = walk.member_type(data, rec, String("type"))
    if otype == -1:
        return String("offsets missing type")
    if otype == -2:
        return String("BTF strings corrupt")
    var otype_v = walk.uint_value(data, otype)
    if otype_v < 0:
        return String("offsets bad type")
    if otype_v != _MAP_ARRAY:
        return String(t"offsets type {otype_v}, want 2")
    var omax = walk.member_type(data, rec, String("max_entries"))
    if omax == -1:
        return String("offsets missing max_entries")
    if omax == -2:
        return String("BTF strings corrupt")
    var omax_v = walk.uint_value(data, omax)
    if omax_v < 0:
        return String("offsets bad max_entries")
    if omax_v != 1:
        return String(t"offsets max_entries {omax_v}, want 1")
    var okey = walk.member_type(data, rec, String("key"))
    if okey == -1:
        return String("offsets missing key")
    if okey == -2:
        return String("BTF strings corrupt")
    var okey_v = walk.int_size(data, okey)
    if okey_v < 0:
        return String("offsets bad key")
    if okey_v != 4:
        return String(t"offsets key {okey_v}, want 4")
    var oval = walk.member_type(data, rec, String("value"))
    if oval == -1:
        return String("offsets missing value")
    if oval == -2:
        return String("BTF strings corrupt")
    var oval_v = walk.struct_size(data, oval)
    if oval_v < 0:
        return String("offsets bad value")
    if oval_v != 24:
        return String(t"offsets value {oval_v}, want 24")
    return String("")


def _read_btf_maps(
    data: Span[UInt8, _],
    ring_var: String,
    ring_word: String,
    want_offsets: Bool,
) -> BtfMaps:
    """Shared worker: read_btf_maps with a ring variable name."""
    var sec = _find_section(data, String(".BTF"))
    if not sec.found:
        return _refuse_maps(String("no BTF section"))
    var walk = _walk_btf(data, sec.offset, sec.size)
    if not walk.ok:
        return _refuse_maps(walk.message.copy())
    var counts = walk.find_var(data, String("mv_counts"))
    if counts == -1:
        return _refuse_maps(String("missing mv_counts"))
    if counts == -2:
        return _refuse_maps(String("BTF strings corrupt"))
    if counts == -3:
        return _refuse_maps(String("duplicate mv_counts"))
    var cmem = walk.datasec_var(data, String(".maps"), counts)
    if cmem == 0:
        return _refuse_maps(String("no maps DATASEC"))
    if cmem == -1:
        return _refuse_maps(String("BTF strings corrupt"))
    if cmem == -2:
        return _refuse_maps(String("duplicate maps DATASEC"))
    if cmem == -4:
        return _refuse_maps(String("counts not in maps DATASEC"))
    var counts_struct = walk.sizes[counts]
    if not walk.rec_valid(counts_struct):
        return _refuse_maps(String("counts not a struct"))
    var cs = counts_struct - 1
    if walk.kinds[cs] != 4:
        return _refuse_maps(String("counts not a struct"))
    var link = walk.var_linkage(data, counts)
    if link != 0 and link != 1:
        return _refuse_maps(String(t"counts linkage {link}"))
    var ctype = walk.member_type(data, cs, String("type"))
    if ctype == -1:
        return _refuse_maps(String("counts missing type"))
    if ctype == -2:
        return _refuse_maps(String("BTF strings corrupt"))
    var ctype_v = walk.uint_value(data, ctype)
    if ctype_v < 0:
        return _refuse_maps(String("counts bad type"))
    if ctype_v != _MAP_ARRAY:
        return _refuse_maps(String(t"counts type {ctype_v}, want 2"))
    var cmax = walk.member_type(data, cs, String("max_entries"))
    if cmax == -1:
        return _refuse_maps(String("counts missing max_entries"))
    if cmax == -2:
        return _refuse_maps(String("BTF strings corrupt"))
    var cmax_v = walk.uint_value(data, cmax)
    if cmax_v < 0:
        return _refuse_maps(String("counts bad max_entries"))
    if cmax_v != 6:
        return _refuse_maps(String(t"counts max_entries {cmax_v}, want 6"))
    var ckey = walk.member_type(data, cs, String("key"))
    if ckey == -1:
        return _refuse_maps(String("counts missing key"))
    if ckey == -2:
        return _refuse_maps(String("BTF strings corrupt"))
    var ckey_v = walk.int_size(data, ckey)
    if ckey_v < 0:
        return _refuse_maps(String("counts bad key"))
    if ckey_v != 4:
        return _refuse_maps(String(t"counts key {ckey_v}, want 4"))
    var cval = walk.member_type(data, cs, String("value"))
    if cval == -1:
        return _refuse_maps(String("counts missing value"))
    if cval == -2:
        return _refuse_maps(String("BTF strings corrupt"))
    var cval_v = walk.int_size(data, cval)
    if cval_v < 0:
        return _refuse_maps(String("counts bad value"))
    if cval_v != 8:
        return _refuse_maps(String(t"counts value {cval_v}, want 8"))
    var attempts = walk.find_var(data, ring_var)
    if attempts == -1:
        return _refuse_maps(String("missing ") + ring_var)
    if attempts == -2:
        return _refuse_maps(String("BTF strings corrupt"))
    if attempts == -3:
        return _refuse_maps(String("duplicate ") + ring_var)
    var amem = walk.datasec_var(data, String(".maps"), attempts)
    if amem == 0:
        return _refuse_maps(String("no maps DATASEC"))
    if amem == -1:
        return _refuse_maps(String("BTF strings corrupt"))
    if amem == -2:
        return _refuse_maps(String("duplicate maps DATASEC"))
    if amem == -4:
        return _refuse_maps(ring_word + String(" not in maps DATASEC"))
    var attempts_struct = walk.sizes[attempts]
    if not walk.rec_valid(attempts_struct):
        return _refuse_maps(ring_word + String(" not a struct"))
    var aus = attempts_struct - 1
    if walk.kinds[aus] != 4:
        return _refuse_maps(ring_word + String(" not a struct"))
    var alink = walk.var_linkage(data, attempts)
    if alink != 0 and alink != 1:
        return _refuse_maps(String(t"{ring_word} linkage {alink}"))
    var atype = walk.member_type(data, aus, String("type"))
    if atype == -1:
        return _refuse_maps(ring_word + String(" missing type"))
    if atype == -2:
        return _refuse_maps(String("BTF strings corrupt"))
    var atype_v = walk.uint_value(data, atype)
    if atype_v < 0:
        return _refuse_maps(ring_word + String(" bad type"))
    if atype_v != _MAP_RINGBUF:
        return _refuse_maps(String(t"{ring_word} type {atype_v}, want 27"))
    var amax = walk.member_type(data, aus, String("max_entries"))
    if amax == -1:
        return _refuse_maps(ring_word + String(" missing max_entries"))
    if amax == -2:
        return _refuse_maps(String("BTF strings corrupt"))
    var ring = walk.uint_value(data, amax)
    if ring < 0:
        return _refuse_maps(ring_word + String(" bad max_entries"))
    if (
        ring < _MIN_RING_BYTES
        or ring > _MAX_RING_BYTES
        or not _is_pow2(ring)
    ):
        return _refuse_maps(
            String(t"{ring_word} ring size {ring} rejected"))
    if want_offsets:
        var bad = _check_offsets_map(data, walk)
        if bad != String(""):
            return _refuse_maps(bad)
    var out = BtfMaps()
    out.ok = True
    out.message = String("")
    out.ring_bytes = ring
    return out^


def read_btf_copy_fb(data: Span[UInt8, _]) -> BtfMaps:
    """Read the mv_copy_fb fallback counter definition.

    Pinned exactly (ARRAY, key 4, value 8, 4 entries:
    deferred, recovered, flags, armed). Ring size unused (0).
    """
    var sec = _find_section(data, String(".BTF"))
    if not sec.found:
        return _refuse_maps(String("no BTF section"))
    var walk = _walk_btf(data, sec.offset, sec.size)
    if not walk.ok:
        return _refuse_maps(walk.message.copy())
    var found = walk.find_var(data, String("mv_copy_fb"))
    if found == -1:
        return _refuse_maps(String("missing mv_copy_fb"))
    if found == -2:
        return _refuse_maps(String("BTF strings corrupt"))
    if found == -3:
        return _refuse_maps(String("duplicate mv_copy_fb"))
    var mem = walk.datasec_var(data, String(".maps"), found)
    if mem == 0:
        return _refuse_maps(String("no maps DATASEC"))
    if mem == -1:
        return _refuse_maps(String("BTF strings corrupt"))
    if mem == -2:
        return _refuse_maps(String("duplicate maps DATASEC"))
    if mem == -4:
        return _refuse_maps(String("fallback not in maps DATASEC"))
    var fb_struct = walk.sizes[found]
    if not walk.rec_valid(fb_struct):
        return _refuse_maps(String("fallback not a struct"))
    var rec = fb_struct - 1
    if walk.kinds[rec] != 4:
        return _refuse_maps(String("fallback not a struct"))
    var link = walk.var_linkage(data, found)
    if link != 0 and link != 1:
        return _refuse_maps(String(t"fallback linkage {link}"))
    var ftype = walk.member_type(data, rec, String("type"))
    if ftype == -1:
        return _refuse_maps(String("fallback missing type"))
    if ftype == -2:
        return _refuse_maps(String("BTF strings corrupt"))
    var ftype_v = walk.uint_value(data, ftype)
    if ftype_v < 0:
        return _refuse_maps(String("fallback bad type"))
    if ftype_v != _MAP_ARRAY:
        return _refuse_maps(String(t"fallback type {ftype_v}, want 2"))
    var fmax = walk.member_type(data, rec, String("max_entries"))
    if fmax == -1:
        return _refuse_maps(String("fallback missing max_entries"))
    if fmax == -2:
        return _refuse_maps(String("BTF strings corrupt"))
    var fmax_v = walk.uint_value(data, fmax)
    if fmax_v < 0:
        return _refuse_maps(String("fallback bad max_entries"))
    if fmax_v != 4:
        return _refuse_maps(String(t"fallback max_entries {fmax_v}, want 4"))
    var fkey = walk.member_type(data, rec, String("key"))
    if fkey == -1:
        return _refuse_maps(String("fallback missing key"))
    if fkey == -2:
        return _refuse_maps(String("BTF strings corrupt"))
    var fkey_v = walk.int_size(data, fkey)
    if fkey_v < 0:
        return _refuse_maps(String("fallback bad key"))
    if fkey_v != 4:
        return _refuse_maps(String(t"fallback key {fkey_v}, want 4"))
    var fval = walk.member_type(data, rec, String("value"))
    if fval == -1:
        return _refuse_maps(String("fallback missing value"))
    if fval == -2:
        return _refuse_maps(String("BTF strings corrupt"))
    var fval_v = walk.int_size(data, fval)
    if fval_v < 0:
        return _refuse_maps(String("fallback bad value"))
    if fval_v != 8:
        return _refuse_maps(String(t"fallback value {fval_v}, want 8"))
    var out = BtfMaps()
    out.ok = True
    out.message = String("")
    out.ring_bytes = 0
    return out^


struct BtfFuncProto(Copyable, Movable):
    """One BTF function prototype read (canonical iff ok)."""

    var ok: Bool
    var message: String
    var canonical: String

    def __init__(out self):
        self.ok = False
        self.message = String("")
        self.canonical = String("")


struct _TypeSpell(ImplicitlyCopyable):
    """One canonical type spelling plus its pointer depth."""

    var ok: Bool
    var message: String
    var text: String
    var stars: Int

    def __init__(out self):
        self.ok = False
        self.message = String("")
        self.text = String("")
        self.stars = 0


def _normalize_int_name(name: String) -> String:
    """One C spelling for equivalent BTF integer names.

    Kernel BTF spells some integers ("long unsigned int")
    differently from C sources ("unsigned long"). Pairs
    below name the same LP64 x86-64 type; anything unlisted
    passes through verbatim so unknown spellings mismatch
    loudly at comparison instead of equating silently.
    """
    if name == String("long unsigned int"):
        return String("unsigned long")
    if name == String("long long unsigned int"):
        return String("unsigned long long")
    if name == String("short unsigned int"):
        return String("unsigned short")
    if name == String("short int"):
        return String("short")
    if name == String("long int"):
        return String("long")
    if name == String("long long int"):
        return String("long long")
    return name


def _lp64_int_size(name: String) -> Int:
    """Expected BTF size of one normalized integer name.

    LP64 x86-64 only, the product's single supported
    shape. -1 for unknown spellings: those pass through
    unchecked (as today) and mismatch loudly at
    comparison instead of equating silently.
    """
    if name == String("char"):
        return 1
    if name == String("signed char"):
        return 1
    if name == String("unsigned char"):
        return 1
    if name == String("bool"):
        return 1
    if name == String("short"):
        return 2
    if name == String("unsigned short"):
        return 2
    if name == String("int"):
        return 4
    if name == String("unsigned int"):
        return 4
    if name == String("long"):
        return 8
    if name == String("unsigned long"):
        return 8
    if name == String("long long"):
        return 8
    if name == String("unsigned long long"):
        return 8
    if name == String("size_t"):
        return 8
    return -1


def _spell_btf_type(
    walk: _BtfWalk, data: Span[UInt8, _], tid: Int, budget: Int
) -> _TypeSpell:
    """Canonical structural spelling of one BTF type id.

    Modifiers and tags resolve silently, pointers add one
    star each, and the first named type stops the walk with
    its own name (typedef names are kept, never expanded).
    Arrays spell as element plus [n]. Anything anonymous,
    cyclic, nested-functional, or otherwise unnameable
    refuses: discovery must not guess at kernel types.
    """
    var out = _TypeSpell()
    var stars = 0
    var cur = tid
    var left = budget
    while True:
        if left <= 0:
            out.message = String("type graph too deep")
            return out^
        left -= 1
        if cur == 0:
            # Void spells alone or terminates pointer
            # chains (const void *, the kfree shape).
            out.ok = True
            out.text = String("void")
            out.stars = stars
            for _ in range(stars):
                out.text += String(" *")
            return out^
        if not walk.rec_valid(cur):
            out.message = String("type id out of range")
            return out^
        var kind = walk.kinds[cur - 1]
        if kind == 2:
            stars += 1
            cur = walk.sizes[cur - 1]
            continue
        if kind == 9 or kind == 10 or kind == 11 or kind == 18:
            cur = walk.sizes[cur - 1]
            continue
        if kind == 3:
            var base = walk.offsets[cur - 1]
            var elem = _u32(data, base + 12)
            var count = _u32(data, base + 20)
            var sub = _spell_btf_type(walk, data, elem, left)
            if not sub.ok:
                return sub^
            out.ok = True
            out.text = sub.text + String("[") + String(count) + String("]")
            out.stars = stars
            for _ in range(stars):
                out.text += String(" *")
            return out^
        var name = String("")
        if not walk.type_name(data, cur - 1, name):
            out.message = String("BTF strings corrupt")
            return out^
        var base: String
        if kind == 1 or kind == 16:
            base = _normalize_int_name(name)
            var want = _lp64_int_size(base)
            if want >= 0 and walk.sizes[cur - 1] != want:
                var have = walk.sizes[cur - 1]
                out.message = String(t"BTF int size {have} mismatch for {base}, want {want}")
                return out^
        elif kind == 4:
            base = String("struct ") + name
        elif kind == 5:
            base = String("union ") + name
        elif kind == 6 or kind == 19:
            base = String("enum ") + name
        elif kind == 8:
            base = name
        elif kind == 13:
            out.message = String("function pointer in prototype")
            return out^
        else:
            out.message = String(t"unsupported type kind {kind}")
            return out^
        if name == String(""):
            out.message = String("anonymous type in prototype")
            return out^
        out.ok = True
        out.text = base
        out.stars = stars
        for _ in range(stars):
            out.text += String(" *")
        return out^


def read_btf_func_proto(data: Span[UInt8, _], name: String) -> BtfFuncProto:
    """Find FUNC name in a raw BTF blob; spell its prototype.

    The blob is a header-at-zero BTF image such as
    /sys/kernel/btf/vmlinux. The canonical form is
    "<ret> (<t0> <n0>, ...)" with typedef names kept and
    one " *" per pointer level; empty parameter lists
    spell "(void)". A missing, duplicated, or unspellable
    function refuses with the exact cause.
    """
    var out = BtfFuncProto()
    var walk = _walk_btf(data, 0, len(data))
    if not walk.ok:
        out.message = walk.message.copy()
        return out^
    var found = -1
    for i in range(len(walk.offsets)):
        if walk.kinds[i] != 12:
            continue
        var text = String("")
        if not walk.type_name(data, i, text):
            out.message = String("BTF strings corrupt")
            return out^
        if text == name:
            if found >= 0:
                out.message = String(t"duplicate function {name}")
                return out^
            found = i
    if found < 0:
        out.message = String(t"function {name} not found")
        return out^
    var proto = walk.sizes[found]
    if not walk.rec_valid(proto) or walk.kinds[proto - 1] != 13:
        out.message = String("function has no prototype")
        return out^
    var ret = _spell_btf_type(
        walk, data, walk.sizes[proto - 1], _MAX_SPELL_DEPTH
    )
    if not ret.ok:
        out.message = ret.message.copy()
        return out^
    var canon = ret.text + String(" (")
    var pbase = walk.offsets[proto - 1]
    var pcount = walk.vlens[proto - 1]
    if pcount == 0:
        canon += String("void")
    for m in range(pcount):
        var pname_off = _u32(data, pbase + 12 + m * 8)
        var ptype = _u32(data, pbase + 12 + m * 8 + 4)
        var pname = String("")
        if not _table_text(
            data, walk.str_base, walk.str_end, pname_off, pname
        ):
            out.message = String("BTF strings corrupt")
            return out^
        if pname == String(""):
            out.message = String("unnamed parameter in prototype")
            return out^
        var ps = _spell_btf_type(walk, data, ptype, _MAX_SPELL_DEPTH)
        if not ps.ok:
            out.message = ps.message.copy()
            return out^
        if m > 0:
            canon += String(", ")
        canon += ps.text
        if ps.stars == 0:
            canon += String(" ")
        canon += pname
    canon += String(")")
    out.ok = True
    out.message = String("")
    out.canonical = canon
    return out^


struct BtfFuncSig(Copyable):
    """One BTF function signature read: types without names."""

    var ok: Bool
    var message: String
    var ret: String
    var params: List[String]
    var widths: List[Int]

    def __init__(out self):
        self.ok = False
        self.message = String("")
        self.ret = String("")
        self.params = List[String]()
        self.widths = List[Int]()


def _typedef_width(
    walk: _BtfWalk, data: Span[UInt8, _], tid: Int
) -> Int:
    """Resolved INT bit width when tid is a bare typedef, else 0.

    Modifiers peel to the first named stop: a typedef
    with no pointer level resolves below itself (through
    nested typedefs and modifiers) to INT; pointers,
    direct types, and broken chains carry no width.
    """
    var cur = tid
    for _ in range(_MAX_SPELL_DEPTH):
        if not walk.rec_valid(cur):
            return 0
        var kind = walk.kinds[cur - 1]
        if kind == 2:
            return 0
        if kind == 9 or kind == 10 or kind == 11 or kind == 18:
            cur = walk.sizes[cur - 1]
            continue
        if kind != 8:
            return 0
        cur = walk.sizes[cur - 1]
        for _ in range(_MAX_SPELL_DEPTH):
            if not walk.rec_valid(cur):
                return 0
            var sub = walk.kinds[cur - 1]
            if sub == 1:
                return walk.sizes[cur - 1] * 8
            if (
                sub != 8
                and sub != 9
                and sub != 10
                and sub != 11
                and sub != 18
            ):
                return 0
            cur = walk.sizes[cur - 1]
        return 0
    return 0


def _spell_proto_sig(
    walk: _BtfWalk, data: Span[UInt8, _], proto: Int
) -> BtfFuncSig:
    """Spell one FUNC_PROTO record as types without names.

    Parameter names are validated but never kept: only
    typedef-level type spellings compare, so unnamed
    parameters spell fine.
    """
    var out = BtfFuncSig()
    var ret = _spell_btf_type(
        walk, data, walk.sizes[proto - 1], _MAX_SPELL_DEPTH
    )
    if not ret.ok:
        out.message = ret.message.copy()
        return out^
    out.ret = ret.text.copy()
    var pbase = walk.offsets[proto - 1]
    var pcount = walk.vlens[proto - 1]
    for m in range(pcount):
        var pname_off = _u32(data, pbase + 12 + m * 8)
        var ptype = _u32(data, pbase + 12 + m * 8 + 4)
        var pname = String("")
        if not _table_text(
            data, walk.str_base, walk.str_end, pname_off, pname
        ):
            out.message = String("BTF strings corrupt")
            return out^
        var ps = _spell_btf_type(walk, data, ptype, _MAX_SPELL_DEPTH)
        if not ps.ok:
            out.message = ps.message.copy()
            return out^
        out.params.append(ps.text.copy())
        out.widths.append(_typedef_width(walk, data, ptype))
    out.ok = True
    return out^


def _func_sig_same(a: BtfFuncSig, b: BtfFuncSig) -> Bool:
    """True when two spelled signatures agree on types and widths."""
    if a.ret != b.ret:
        return False
    if len(a.params) != len(b.params):
        return False
    for i in range(len(a.params)):
        if a.params[i] != b.params[i]:
            return False
        if a.widths[i] != b.widths[i]:
            return False
    return True


def read_btf_func_sig(data: Span[UInt8, _], name: String) -> BtfFuncSig:
    """Find FUNC name in a raw BTF blob; spell types sans names.

    The blob is a header-at-zero BTF image such as
    /sys/kernel/btf/vmlinux. Parameters spell at typedef
    level without names, each carrying its resolved INT
    bit width when it is a bare typedef, else zero.
    Duplicate FUNC entries are accepted only when every
    prototype spells (and widths) identically.
    """
    var out = BtfFuncSig()
    var walk = _walk_btf(data, 0, len(data))
    if not walk.ok:
        out.message = walk.message.copy()
        return out^
    var found = List[Int]()
    for i in range(len(walk.offsets)):
        if walk.kinds[i] != 12:
            continue
        var text = String("")
        if not walk.type_name(data, i, text):
            out.message = String("BTF strings corrupt")
            return out^
        if text == name:
            found.append(i)
    if len(found) == 0:
        out.message = String(t"function {name} not found")
        return out^
    var first_proto = walk.sizes[found[0]]
    if not walk.rec_valid(first_proto) or walk.kinds[first_proto - 1] != 13:
        out.message = String("function has no prototype")
        return out^
    var first = _spell_proto_sig(walk, data, first_proto)
    if not first.ok:
        out.message = first.message.copy()
        return out^
    for f in range(1, len(found)):
        var proto = walk.sizes[found[f]]
        if not walk.rec_valid(proto) or walk.kinds[proto - 1] != 13:
            out.message = String("function has no prototype")
            return out^
        var sp = _spell_proto_sig(walk, data, proto)
        if not sp.ok:
            out.message = sp.message.copy()
            return out^
        if not _func_sig_same(first, sp):
            var n = len(found)
            out.message = String(
                t"ambiguous FUNC {name} ({n} prototypes differ)"
            )
            return out^
    return first^


struct BtfMember(Copyable, Movable):
    """One BTF struct member read (offsets valid iff ok)."""

    var ok: Bool
    var message: String
    var bit_offset: Int
    var bit_size: Int

    def __init__(out self):
        self.ok = False
        self.message = String("")
        self.bit_offset = 0
        self.bit_size = 0


def read_btf_member(
    data: Span[UInt8, _], struct_name: String, field_name: String
) -> BtfMember:
    """Find STRUCT struct_name's member field_name in a raw BTF blob.

    The blob is a header-at-zero BTF image such as
    /sys/kernel/btf/vmlinux. The member's bit offset comes
    straight from its record; its bit size is the member
    type's byte width times eight, resolved through
    typedefs and modifiers (pointers are 8 bytes, integers
    use their size field). Anything else refuses with the
    exact cause.
    """
    var out = BtfMember()
    var walk = _walk_btf(data, 0, len(data))
    if not walk.ok:
        out.message = walk.message.copy()
        return out^
    var found = -1
    for i in range(len(walk.offsets)):
        if walk.kinds[i] != 4:
            continue
        var text = String("")
        if not walk.type_name(data, i, text):
            out.message = String("BTF strings corrupt")
            return out^
        if text == struct_name:
            if found >= 0:
                out.message = String(t"duplicate struct {struct_name}")
                return out^
            found = i
    if found < 0:
        out.message = String(t"struct {struct_name} not found")
        return out^
    var base = walk.offsets[found]
    var member_tid = -1
    var member_off = 0
    var member_found = False
    for m in range(walk.vlens[found]):
        var name_off = _u32(data, base + 12 + m * 12)
        var text = String("")
        if not _table_text(
            data, walk.str_base, walk.str_end, name_off, text
        ):
            out.message = String("BTF strings corrupt")
            return out^
        if text == field_name:
            member_tid = _u32(data, base + 12 + m * 12 + 4)
            member_off = _u32(data, base + 12 + m * 12 + 8)
            member_found = True
            break
    if not member_found:
        out.message = String(
            t"member {field_name} not found in {struct_name}"
        )
        return out^
    var pos = _member_pos(member_off, walk.kflags[found])
    if pos.bitfield_size != 0:
        out.message = String(
            t"bitfield member {struct_name}.{field_name} unsupported"
        )
        return out^
    var size_bytes = -1
    var cur = member_tid
    for _ in range(_MAX_SPELL_DEPTH):
        if not walk.rec_valid(cur):
            out.message = String("type id out of range")
            return out^
        var kind = walk.kinds[cur - 1]
        if kind == 2:
            size_bytes = 8
            break
        if kind == 1:
            size_bytes = walk.sizes[cur - 1]
            var enc = _u32(data, walk.offsets[cur - 1] + 12) & 0xFF
            if enc != size_bytes * 8 or pos.bit_offset % 8 != 0:
                out.message = String(
                    t"bitfield member {struct_name}.{field_name} unsupported"
                )
                return out^
            break
        if (
            kind != 8
            and kind != 9
            and kind != 10
            and kind != 11
            and kind != 18
        ):
            out.message = String(t"unsupported member type kind {kind}")
            return out^
        cur = walk.sizes[cur - 1]
    if size_bytes < 0:
        out.message = String("type graph too deep")
        return out^
    out.ok = True
    out.message = String("")
    out.bit_offset = pos.bit_offset
    out.bit_size = size_bytes * 8
    return out^


struct _MemberPos(ImplicitlyCopyable):
    """One decoded member offset word."""

    var bit_offset: Int
    var bitfield_size: Int

    def __init__(out self):
        self.bit_offset = 0
        self.bitfield_size = 0


def _member_pos(word: Int, kflag: Int) -> _MemberPos:
    """Split one member offset word by its struct kind_flag.

    Flagged structs pack the bitfield size into the top
    byte and the bit offset into the low 24 bits; plain
    structs hold the bit offset alone.
    """
    var out = _MemberPos()
    if kflag != 0:
        out.bit_offset = word & 0xFFFFFF
        out.bitfield_size = (word >> 24) & 0xFF
    else:
        out.bit_offset = word
        out.bitfield_size = 0
    return out^


struct _TypeBits(ImplicitlyCopyable):
    """One resolved member type: kind word plus bit width."""

    var ok: Bool
    var message: String
    var kind: String
    var bits: Int
    var is_int: Bool
    var int_bits: Int
    var int_size: Int

    def __init__(out self):
        self.ok = False
        self.message = String("")
        self.kind = String("")
        self.bits = 0
        self.is_int = False
        self.int_bits = 0
        self.int_size = 0


def _type_bits(
    walk: _BtfWalk, data: Span[UInt8, _], tid: Int, budget: Int
) -> _TypeBits:
    """Resolve one member type id to a kind word and bit width.

    Typedefs, modifiers, and tags resolve silently within
    the hop budget; anything else spells by its own kind.
    """
    var out = _TypeBits()
    var cur = tid
    var left = budget
    while True:
        if left <= 0:
            out.message = String("type chain too long")
            return out^
        left -= 1
        if not walk.rec_valid(cur):
            out.message = String("type id out of range")
            return out^
        var kind = walk.kinds[cur - 1]
        if (
            kind == 8
            or kind == 9
            or kind == 10
            or kind == 11
            or kind == 18
        ):
            cur = walk.sizes[cur - 1]
            continue
        if kind == 2:
            out.ok = True
            out.kind = String("ptr")
            out.bits = 64
            return out^
        if kind == 1 or kind == 16:
            out.ok = True
            out.is_int = kind == 1
            out.int_size = walk.sizes[cur - 1]
            out.bits = walk.sizes[cur - 1] * 8
            if kind == 1:
                out.kind = String("int")
                var enc = _u32(data, walk.offsets[cur - 1] + 12)
                out.int_bits = enc & 0xFF
            else:
                out.kind = String("float")
                out.int_bits = out.bits
            return out^
        if kind == 3:
            var base = walk.offsets[cur - 1]
            var elem = _u32(data, base + 12)
            var count = _u32(data, base + 20)
            var sub = _type_bits(walk, data, elem, left)
            if not sub.ok:
                return sub^
            out.ok = True
            out.kind = String("array")
            out.bits = count * sub.bits
            return out^
        if kind == 4 or kind == 5 or kind == 6 or kind == 19:
            out.ok = True
            if kind == 4:
                out.kind = String("struct")
            elif kind == 5:
                out.kind = String("union")
            else:
                out.kind = String("enum")
            out.bits = walk.sizes[cur - 1] * 8
            return out^
        if kind == 7:
            out.message = String("member type is a forward declaration")
            return out^
        out.message = String(t"unsupported member type kind {kind}")
        return out^


struct _MemberHit(ImplicitlyCopyable):
    """One member search outcome inside a single struct."""

    var found: Bool
    var failed: Bool
    var message: String
    var bit_offset: Int
    var member_tid: Int
    var bitfield_size: Int

    def __init__(out self):
        self.found = False
        self.failed = False
        self.message = String("")
        self.bit_offset = 0
        self.member_tid = 0
        self.bitfield_size = 0


def _find_member(
    walk: _BtfWalk,
    data: Span[UInt8, _],
    rec: Int,
    field: String,
    acc: Int,
    depth: Int,
) -> _MemberHit:
    """Depth-first member search through anonymous members.

    Anonymous STRUCT/UNION members recurse with
    accumulated offsets; any other empty-named member is
    skipped, never descended into.
    """
    var out = _MemberHit()
    if depth > _MAX_SPELL_DEPTH:
        out.failed = True
        out.message = String("type graph too deep")
        return out^
    var base = walk.offsets[rec]
    var kflag = walk.kflags[rec]
    for m in range(walk.vlens[rec]):
        var name_off = _u32(data, base + 12 + m * 12)
        var tid = _u32(data, base + 12 + m * 12 + 4)
        var word = _u32(data, base + 12 + m * 12 + 8)
        var pos = _member_pos(word, kflag)
        if name_off == 0:
            if walk.rec_valid(tid):
                var mkind = walk.kinds[tid - 1]
                if mkind == 4 or mkind == 5:
                    var sub = _find_member(
                        walk,
                        data,
                        tid - 1,
                        field,
                        acc + pos.bit_offset,
                        depth + 1,
                    )
                    if sub.found or sub.failed:
                        return sub^
            continue
        var text = String("")
        if not _table_text(
            data, walk.str_base, walk.str_end, name_off, text
        ):
            out.failed = True
            out.message = String("BTF strings corrupt")
            return out^
        if text == field:
            out.found = True
            out.bit_offset = acc + pos.bit_offset
            out.member_tid = tid
            out.bitfield_size = pos.bitfield_size
            return out^
    return out^


struct BtfResolved(Copyable, Movable):
    """One BTF member, type, or enumerator resolution."""

    var ok: Bool
    var struct_found: Bool
    var found: Bool
    var ambiguous: Bool
    var bitfield: Bool
    var bit_offset: Int
    var bit_size: Int
    var kind: String
    var message: String

    def __init__(out self):
        self.ok = False
        self.struct_found = False
        self.found = False
        self.ambiguous = False
        self.bitfield = False
        self.bit_offset = 0
        self.bit_size = 0
        self.kind = String("")
        self.message = String("")


def _refuse_resolved(message: String) -> BtfResolved:
    var out = BtfResolved()
    out.message = message
    return out^


def resolve_btf_member(
    data: Span[UInt8, _], struct_name: String, field: String
) -> BtfResolved:
    """Resolve STRUCT/UNION struct_name's member field in raw BTF.

    Every same-named struct or union is a candidate; the
    search descends into anonymous members and candidates
    lacking the member are ignored. Candidates holding it
    must agree on offset, size, kind, and bitfield state.
    """
    var walk = _walk_btf(data, 0, len(data))
    if not walk.ok:
        return _refuse_resolved(walk.message.copy())
    var cands = List[Int]()
    for i in range(len(walk.offsets)):
        if walk.kinds[i] != 4 and walk.kinds[i] != 5:
            continue
        var text = String("")
        if not walk.type_name(data, i, text):
            return _refuse_resolved(String("BTF strings corrupt"))
        if text == struct_name:
            cands.append(i)
    var out = BtfResolved()
    if len(cands) == 0:
        out.ok = True
        return out^
    out.struct_found = True
    var offs = List[Int]()
    var sizes = List[Int]()
    var kinds = List[String]()
    var bfs = List[Bool]()
    for c in range(len(cands)):
        var hit = _find_member(
            walk, data, cands[c], field, 0, 0
        )
        if hit.failed:
            return _refuse_resolved(hit.message.copy())
        if not hit.found:
            continue
        var tb = _type_bits(
            walk, data, hit.member_tid, _MAX_SPELL_DEPTH
        )
        if not tb.ok:
            return _refuse_resolved(tb.message.copy())
        var is_bf = hit.bitfield_size != 0
        var bsize = tb.bits
        if is_bf:
            bsize = hit.bitfield_size
        elif tb.is_int and (
            tb.int_bits != tb.int_size * 8 or hit.bit_offset % 8 != 0
        ):
            is_bf = True
            bsize = tb.int_bits
        offs.append(hit.bit_offset)
        sizes.append(bsize)
        kinds.append(tb.kind.copy())
        bfs.append(is_bf)
    if len(offs) == 0:
        out.ok = True
        return out^
    for h in range(1, len(offs)):
        if (
            offs[h] != offs[0]
            or sizes[h] != sizes[0]
            or kinds[h] != kinds[0]
            or bfs[h] != bfs[0]
        ):
            out.ambiguous = True
            var ndefs = len(offs)
            var dtext = String(" definitions disagree on ")
            out.message = String(t"struct {struct_name}: {ndefs}")
            out.message += dtext + field
            return out^
    out.ok = True
    out.found = True
    out.bitfield = bfs[0]
    out.bit_offset = offs[0]
    out.bit_size = sizes[0]
    out.kind = kinds[0].copy()
    out.message = String("")
    return out^


def resolve_btf_type(
    data: Span[UInt8, _], name: String, kind: String
) -> BtfResolved:
    """Resolve one named STRUCT, UNION, ENUM, or TYPEDEF.

    Same-named candidates must agree on kind and size;
    typedefs resolve through to their terminal kind.
    """
    var want_struct = kind == String("struct")
    var want_union = kind == String("union")
    var want_enum = kind == String("enum")
    var want_typedef = kind == String("typedef")
    if (
        not want_struct
        and not want_union
        and not want_enum
        and not want_typedef
    ):
        return _refuse_resolved(String(t"unknown type kind {kind}"))
    var walk = _walk_btf(data, 0, len(data))
    if not walk.ok:
        return _refuse_resolved(walk.message.copy())
    var cands = List[Int]()
    for i in range(len(walk.offsets)):
        var k = walk.kinds[i]
        var match = False
        if want_struct and k == 4:
            match = True
        if want_union and k == 5:
            match = True
        if want_enum and (k == 6 or k == 19):
            match = True
        if want_typedef and k == 8:
            match = True
        if not match:
            continue
        var text = String("")
        if not walk.type_name(data, i, text):
            return _refuse_resolved(String("BTF strings corrupt"))
        if text == name:
            cands.append(i)
    var out = BtfResolved()
    if len(cands) == 0:
        out.ok = True
        return out^
    out.struct_found = True
    var sizes = List[Int]()
    var kinds = List[String]()
    for c in range(len(cands)):
        var rec = cands[c]
        var k = walk.kinds[rec]
        if k == 4:
            sizes.append(walk.sizes[rec] * 8)
            kinds.append(String("struct"))
        elif k == 5:
            sizes.append(walk.sizes[rec] * 8)
            kinds.append(String("union"))
        elif k == 6 or k == 19:
            sizes.append(walk.sizes[rec] * 8)
            kinds.append(String("enum"))
        else:
            var tb = _type_bits(
                walk, data, walk.sizes[rec], _MAX_SPELL_DEPTH
            )
            if not tb.ok:
                return _refuse_resolved(tb.message.copy())
            sizes.append(tb.bits)
            kinds.append(tb.kind.copy())
    for h in range(1, len(sizes)):
        if sizes[h] != sizes[0] or kinds[h] != kinds[0]:
            out.ambiguous = True
            var ndefs = len(sizes)
            var dtext = String(" definitions disagree")
            out.message = String(t"type {name}: {ndefs}") + dtext
            return out^
    out.ok = True
    out.found = True
    out.bit_offset = 0
    out.bit_size = sizes[0]
    out.kind = kinds[0].copy()
    out.message = String("")
    return out^


def resolve_btf_enumerator(
    data: Span[UInt8, _], enum_name: String, name: String
) -> BtfResolved:
    """Resolve one enumerator inside a named ENUM or ENUM64.

    Candidates lacking the enumerator are ignored; the
    rest must agree on the enum width.
    """
    var walk = _walk_btf(data, 0, len(data))
    if not walk.ok:
        return _refuse_resolved(walk.message.copy())
    var cands = List[Int]()
    for i in range(len(walk.offsets)):
        if walk.kinds[i] != 6 and walk.kinds[i] != 19:
            continue
        var text = String("")
        if not walk.type_name(data, i, text):
            return _refuse_resolved(String("BTF strings corrupt"))
        if text == enum_name:
            cands.append(i)
    var out = BtfResolved()
    if len(cands) == 0:
        out.ok = True
        return out^
    out.struct_found = True
    var widths = List[Int]()
    for c in range(len(cands)):
        var rec = cands[c]
        var base = walk.offsets[rec]
        var step = 8
        if walk.kinds[rec] == 19:
            step = 12
        var has = False
        for e in range(walk.vlens[rec]):
            var name_off = _u32(data, base + 12 + e * step)
            var text = String("")
            if not _table_text(
                data, walk.str_base, walk.str_end, name_off, text
            ):
                return _refuse_resolved(String("BTF strings corrupt"))
            if text == name:
                has = True
                break
        if has:
            widths.append(walk.sizes[rec] * 8)
    if len(widths) == 0:
        out.ok = True
        return out^
    for h in range(1, len(widths)):
        if widths[h] != widths[0]:
            out.ambiguous = True
            var ndefs = len(widths)
            var dtext = String(" definitions disagree on ")
            out.message = String(t"enum {enum_name}: {ndefs}")
            out.message += dtext + name
            return out^
    out.ok = True
    out.found = True
    out.bit_offset = 0
    out.bit_size = widths[0]
    out.kind = String("enum")
    out.message = String("")
    return out^
