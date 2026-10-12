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
