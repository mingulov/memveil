# SPDX-License-Identifier: GPL-3.0-or-later

"""Narrow identity bindings: grammar, live reads, checks.

A profile carries narrow bindings in
`identity.source.note` as ordered space-separated `k=v`
pairs (section 5 grammar). This module strict-parses the
note, reads the live identity sources under a root
(`/` live, fixture dir in tests), and compares live
values against bindings. Outcomes: bound, mismatch with
the key, or uncheckable with the key. A note that does
not parse is an unbound reference, never an error.
"""

from memveil.capture.normalize import bytes_to_hex
from memveil.platform.btf import MAX_KERNEL_BTF_BYTES
from memveil.platform.gzip import gunzip_member
from memveil.platform.hash import sha256_hex
from memveil.platform.reader import (
    EVIDENCE_DENIED,
    EVIDENCE_OK,
    EvidenceReader,
    bytes_to_text,
    file_state,
    open_evidence_reader,
    read_evidence,
    read_host_file,
)
from memveil.platform.tracefs import probe_tracefs, tracefs_translate

comptime _ZLIB = "libz.so.1"
comptime MAX_NARROW_CONFIG_BYTES = 8388608
comptime MAX_NARROW_BTF_BYTES = MAX_KERNEL_BTF_BYTES
comptime MAX_NARROW_FORMAT_BYTES = 1048576
comptime MAX_NARROW_OBJECT_BYTES = 67108864
comptime MAX_NARROW_IMAGE_BYTES = 268435456
comptime MAX_NARROW_NOTES_BYTES = 1048576
comptime MAX_NARROW_RING_BYTES = 4294967295


struct NarrowBindings(ImplicitlyCopyable):
    """Parsed section 5 grammar bindings (rings are canonical decimal).

    Extended lifecycle/copy bindings stay empty for 8-field
    attempt-only notes; a capture requesting those channels
    refuses unless the note binds them.
    """

    var config: String
    var config_src: String
    var btf: String
    var format: String
    var object: String
    var image: String
    var image_bid: String
    var ring: String
    var lc_object: String
    var lc_ring: String
    var cp_object: String
    var cp_ring: String

    def __init__(out self):
        self.config = String("")
        self.config_src = String("")
        self.btf = String("")
        self.format = String("")
        self.object = String("")
        self.image = String("")
        self.image_bid = String("")
        self.ring = String("")
        self.lc_object = String("")
        self.lc_ring = String("")
        self.cp_object = String("")
        self.cp_ring = String("")


struct NarrowParse(ImplicitlyCopyable):
    """One note parse (bindings valid only when ok)."""

    var ok: Bool
    var bindings: NarrowBindings
    var message: String

    def __init__(out self):
        self.ok = False
        self.bindings = NarrowBindings()
        self.message = String("")


struct LiveValue(ImplicitlyCopyable):
    """One live identity read: value hex, or uncheckable."""

    var state: String
    var value: String
    var detail: String

    def __init__(out self):
        self.state = String("")
        self.value = String("")
        self.detail = String("")


struct ConfigLive(ImplicitlyCopyable):
    """Live kernel-config read plus the source that served it."""

    var value: LiveValue
    var src: String

    def __init__(out self):
        self.value = LiveValue()
        self.src = String("")


struct NarrowLive(ImplicitlyCopyable):
    """Live values for every grammar key (rings set by record)."""

    var config: LiveValue
    var config_src: String
    var btf: LiveValue
    var format: LiveValue
    var object: LiveValue
    var image: LiveValue
    var image_bid: LiveValue
    var ring: LiveValue
    var lc_object: LiveValue
    var lc_ring: LiveValue
    var cp_object: LiveValue
    var cp_ring: LiveValue

    def __init__(out self):
        self.config = LiveValue()
        self.config_src = String("")
        self.btf = LiveValue()
        self.format = LiveValue()
        self.object = LiveValue()
        self.image = LiveValue()
        self.image_bid = LiveValue()
        self.ring = LiveValue()
        self.lc_object = LiveValue()
        self.lc_ring = LiveValue()
        self.cp_object = LiveValue()
        self.cp_ring = LiveValue()


struct NarrowVerdict(ImplicitlyCopyable):
    """One binding check: bound, mismatch, or uncheckable + key."""

    var state: String
    var key: String

    def __init__(out self):
        self.state = String("")
        self.key = String("")


struct LayoutCheck(ImplicitlyCopyable):
    """Trace-format layout verdict against the program pins."""

    var ok: Bool
    var message: String

    def __init__(out self):
        self.ok = False
        self.message = String("")


struct ObjectCheck(ImplicitlyCopyable):
    """BPF object admission verdict (static ELF checks only)."""

    var ok: Bool
    var message: String

    def __init__(out self):
        self.ok = False
        self.message = String("")


def _is_hex(b: UInt8) -> Bool:
    return (
        (b >= UInt8(0x30) and b <= UInt8(0x39))
        or (b >= UInt8(0x61) and b <= UInt8(0x66))
    )


def _split_spaces(note: String) -> List[String]:
    """Split on single spaces; empty pieces stay (strictness)."""
    var out = List[String]()
    var cur = List[UInt8]()
    for b in note.as_bytes():
        if b == UInt8(0x20):
            try:
                out.append(String(from_utf8=Span(cur)))
            except:
                out.append(String(""))
            cur = List[UInt8]()
        else:
            cur.append(b)
    try:
        out.append(String(from_utf8=Span(cur)))
    except:
        out.append(String(""))
    return out^


def _field_value(field: String, key: String) -> String:
    """Value after `key=`, or "" when the key does not match."""
    var want = key + String("=")
    var fb = field.as_bytes()
    var wb = want.as_bytes()
    if len(fb) <= len(wb):
        return String("")
    for i in range(len(wb)):
        if fb[i] != wb[i]:
            return String("")
    var tail = List[UInt8]()
    for i in range(len(wb), len(fb)):
        tail.append(fb[i])
    try:
        return String(from_utf8=Span(tail))
    except:
        return String("")


def is_sha256_value(text: String) -> Bool:
    """True for exactly "sha256:" plus 64 lowercase hex digits."""
    var pre = String("sha256:")
    var tb = text.as_bytes()
    var pb = pre.as_bytes()
    if len(tb) != len(pb) + 64:
        return False
    for i in range(len(pb)):
        if tb[i] != pb[i]:
            return False
    for i in range(len(pb), len(tb)):
        if not _is_hex(tb[i]):
            return False
    return True


def _sha256_hex_value(text: String) -> String:
    var tb = text.as_bytes()
    var out = List[UInt8]()
    for i in range(7, len(tb)):
        out.append(tb[i])
    try:
        return String(from_utf8=Span(out))
    except:
        return String("")


def _is_bid_value(text: String) -> Bool:
    var tb = text.as_bytes()
    if len(tb) != 40:
        return False
    for i in range(len(tb)):
        if not _is_hex(tb[i]):
            return False
    return True


def _parse_ring_value(text: String) -> String:
    """Canonical decimal ring size, or "" when invalid."""
    var tb = text.as_bytes()
    if len(tb) == 0 or len(tb) > 10:
        return String("")
    if tb[0] < UInt8(0x31) or tb[0] > UInt8(0x39):
        return String("")
    var v = 0
    for i in range(len(tb)):
        var b = tb[i]
        if b < UInt8(0x30) or b > UInt8(0x39):
            return String("")
        var d = Int(b) - 0x30
        if v > (MAX_NARROW_RING_BYTES - d) // 10:
            return String("")
        v = v * 10 + d
    return text


def parse_narrow_note(note: String) -> NarrowParse:
    """Strict-parse the section 5 grammar note.

    Fixed order, exact keys, single spaces, lowercase
    hex, exact lengths: 8 fields for attempt-only notes,
    12 with the appended lc_object/lc_ring_bytes/cp_object/
    cp_ring_bytes bindings. Anything else is an unbound
    reference (ok False, key named, never an error).
    """
    var out = NarrowParse()
    var fields = _split_spaces(note)
    if len(fields) != 8 and len(fields) != 12:
        out.message = String("narrow note: want 8 or 12 fields")
        return out^
    var config = _field_value(fields[0], String("config"))
    var config_src = _field_value(fields[1], String("config_src"))
    var btf = _field_value(fields[2], String("btf"))
    var format = _field_value(fields[3], String("format"))
    var object = _field_value(fields[4], String("object"))
    var image = _field_value(fields[5], String("image"))
    var image_bid = _field_value(fields[6], String("image_bid"))
    var ring = _field_value(fields[7], String("ring_bytes"))
    if config == String("") or not is_sha256_value(config):
        out.message = String("narrow note: bad config")
        return out^
    if config_src != String("gz") and config_src != String("file"):
        out.message = String("narrow note: bad config_src")
        return out^
    if btf == String("") or not is_sha256_value(btf):
        out.message = String("narrow note: bad btf")
        return out^
    if format == String("") or not is_sha256_value(format):
        out.message = String("narrow note: bad format")
        return out^
    if object == String("") or not is_sha256_value(object):
        out.message = String("narrow note: bad object")
        return out^
    if image == String("") or not is_sha256_value(image):
        out.message = String("narrow note: bad image")
        return out^
    if image_bid == String("") or not _is_bid_value(image_bid):
        out.message = String("narrow note: bad image_bid")
        return out^
    var ring_ok = _parse_ring_value(ring)
    if ring_ok == String(""):
        out.message = String("narrow note: bad ring_bytes")
        return out^
    out.ok = True
    out.bindings.config = _sha256_hex_value(config)
    out.bindings.config_src = config_src
    out.bindings.btf = _sha256_hex_value(btf)
    out.bindings.format = _sha256_hex_value(format)
    out.bindings.object = _sha256_hex_value(object)
    out.bindings.image = _sha256_hex_value(image)
    out.bindings.image_bid = image_bid
    out.bindings.ring = ring_ok
    if len(fields) == 12:
        var lc_object = _field_value(fields[8], String("lc_object"))
        var lc_ring = _field_value(fields[9], String("lc_ring_bytes"))
        var cp_object = _field_value(fields[10], String("cp_object"))
        var cp_ring = _field_value(fields[11], String("cp_ring_bytes"))
        if lc_object == String("") or not is_sha256_value(lc_object):
            out.ok = False
            out.message = String("narrow note: bad lc_object")
            return out^
        var lc_ring_ok = _parse_ring_value(lc_ring)
        if lc_ring_ok == String(""):
            out.ok = False
            out.message = String("narrow note: bad lc_ring_bytes")
            return out^
        if cp_object == String("") or not is_sha256_value(cp_object):
            out.ok = False
            out.message = String("narrow note: bad cp_object")
            return out^
        var cp_ring_ok = _parse_ring_value(cp_ring)
        if cp_ring_ok == String(""):
            out.ok = False
            out.message = String("narrow note: bad cp_ring_bytes")
            return out^
        out.bindings.lc_object = _sha256_hex_value(lc_object)
        out.bindings.lc_ring = lc_ring_ok
        out.bindings.cp_object = _sha256_hex_value(cp_object)
        out.bindings.cp_ring = cp_ring_ok
    out.message = String("")
    return out^


def _join(root: String, path: String) -> String:
    if root == String("/") or root == String(""):
        return path
    return root + path


def _uncheckable(detail: String) -> LiveValue:
    var v = LiveValue()
    v.state = String("uncheckable")
    v.value = String("")
    v.detail = detail
    return v^


def _valued(hex: String) -> LiveValue:
    var v = LiveValue()
    v.state = String("value")
    v.value = hex
    v.detail = String("")
    return v^


def read_live_config(
    root: String, release: String, zlib: String
) -> ConfigLive:
    """First available config source, hashed (bytes, gunzipped)."""
    var out = ConfigLive()
    var gz_path = _join(root, String("/proc/config.gz"))
    try:
        var gz = read_host_file(gz_path, String("config"), MAX_NARROW_CONFIG_BYTES)
        out.src = String("gz")
        if len(gz) >= 2 and gz[0] == UInt8(0x1F) and gz[1] == UInt8(0x8B):
            var inflated = gunzip_member(Span(gz), zlib)
            if not inflated.ok:
                out.value = _uncheckable(inflated.message)
                return out^
            out.value = _valued(sha256_hex(Span(inflated.data)))
            return out^
        out.value = _valued(sha256_hex(Span(gz)))
        return out^
    except:
        pass
    var file_path = _join(
        root, String("/boot/config-") + release
    )
    try:
        var raw = read_host_file(
            file_path, String("config"), MAX_NARROW_CONFIG_BYTES
        )
        out.src = String("file")
        out.value = _valued(sha256_hex(Span(raw)))
        return out^
    except:
        pass
    out.src = String("")
    out.value = _uncheckable(String("no config source"))
    return out^


struct ConfigText(Copyable):
    """One kernel config text read: text, denied, none, unreadable."""

    var state: String
    var src: String
    var text: String

    def __init__(out self):
        self.state = String("none")
        self.src = String("")
        self.text = String("")


def read_live_config_text(
    reader: EvidenceReader, release: String, zlib: String
) -> ConfigText:
    """First available config source, decoded to text.

    Mirrors read_live_config source order (/proc/config.gz
    then /boot/config-<release>) but stays denied-aware:
    denied evidence is never read through, and a denied
    source with no readable fallback reports denied.
    """
    var out = ConfigText()
    var gz_path = String("/proc/config.gz")
    var boot_path = String("/boot/config-") + release
    var gz_st = file_state(reader, gz_path)
    var boot_st = file_state(reader, boot_path)
    if gz_st == EVIDENCE_OK:
        try:
            var gz = read_evidence(
                reader, gz_path, MAX_NARROW_CONFIG_BYTES
            )
            out.src = String("gz")
            var is_gz = (
                len(gz) >= 2
                and gz[0] == UInt8(0x1F)
                and gz[1] == UInt8(0x8B)
            )
            if is_gz:
                var inflated = gunzip_member(Span(gz), zlib)
                if not inflated.ok:
                    out.state = String("unreadable")
                    return out^
                out.text = bytes_to_text(inflated.data^)
                out.state = String("text")
                return out^
            out.text = bytes_to_text(gz^)
            out.state = String("text")
            return out^
        except:
            pass
    if boot_st == EVIDENCE_OK:
        try:
            var raw = read_evidence(
                reader, boot_path, MAX_NARROW_CONFIG_BYTES
            )
            out.src = String("file")
            out.text = bytes_to_text(raw^)
            out.state = String("text")
            return out^
        except:
            out.src = String("file")
            out.state = String("unreadable")
            return out^
    if gz_st == EVIDENCE_DENIED or boot_st == EVIDENCE_DENIED:
        out.state = String("denied")
        if gz_st == EVIDENCE_DENIED:
            out.src = String("gz")
        else:
            out.src = String("file")
        return out^
    out.state = String("none")
    return out^


def read_live_bytes(
    root: String, path: String, what: String, cap: Int
) -> LiveValue:
    """Hash one raw identity file (btf, format, image)."""
    try:
        var raw = read_host_file(_join(root, path), what, cap)
        return _valued(sha256_hex(Span(raw)))
    except:
        return _uncheckable(what + String(" unreadable"))


def _tracefs_format_path(root: String, format_path: String) -> String:
    """Translate one profile format path onto the live tracefs root.

    An unopenable root keeps the profile path: the read
    itself still fails closed downstream.
    """
    try:
        var reader = open_evidence_reader(root)
        return tracefs_translate(probe_tracefs(reader), format_path)
    except:
        return format_path


def read_live_object(path: String) -> LiveValue:
    """Hash the BPF object file bytes (explicit path)."""
    try:
        var raw = read_host_file(path, String("object"), MAX_NARROW_OBJECT_BYTES)
        return _valued(sha256_hex(Span(raw)))
    except:
        return _uncheckable(String("object unreadable"))


def _notes_u32(data: Span[UInt8, _], at: Int) -> Int:
    return (
        Int(data[at])
        | (Int(data[at + 1]) << 8)
        | (Int(data[at + 2]) << 16)
        | (Int(data[at + 3]) << 24)
    )


def parse_notes_bid(data: Span[UInt8, _]) -> LiveValue:
    """First NT_GNU_BUILD_ID (type 3, name GNU) as 40 hex.

    Malformed notes, a GNU note with a non-20-byte
    descriptor, or no GNU note all report uncheckable.
    """
    var total = len(data)
    var pos = 0
    while pos + 12 <= total:
        var namesz = _notes_u32(data, pos)
        var descsz = _notes_u32(data, pos + 4)
        var ntype = _notes_u32(data, pos + 8)
        pos += 12
        if namesz < 0 or descsz < 0:
            return _uncheckable(String("notes unparseable"))
        var name_end = pos + ((namesz + 3) // 4) * 4
        if name_end > total:
            return _uncheckable(String("notes unparseable"))
        var is_gnu = (
            ntype == 3
            and namesz == 4
            and data[pos] == UInt8(0x47)
            and data[pos + 1] == UInt8(0x4E)
            and data[pos + 2] == UInt8(0x55)
            and data[pos + 3] == UInt8(0)
        )
        pos = name_end
        var desc_end = pos + ((descsz + 3) // 4) * 4
        if desc_end > total:
            return _uncheckable(String("notes unparseable"))
        if is_gnu:
            if descsz != 20:
                return _uncheckable(String("build-id malformed"))
            var desc = List[UInt8]()
            for i in range(20):
                desc.append(data[pos + i])
            return _valued(bytes_to_hex(desc))
        pos = desc_end
    return _uncheckable(String("no build-id note"))


def read_live_bid(root: String) -> LiveValue:
    """Running kernel GNU build-id from /sys/kernel/notes."""
    try:
        var raw = read_host_file(
            _join(root, String("/sys/kernel/notes")),
            String("notes"),
            MAX_NARROW_NOTES_BYTES,
        )
        return parse_notes_bid(Span(raw))
    except:
        return _uncheckable(String("notes unreadable"))


def measure_live_bindings(
    root: String,
    release: String,
    zlib: String,
    format_path: String,
    mut bindings: NarrowBindings,
) -> String:
    """Measure live identity values; "" when all six read.

    Reads config, BTF, trace format, image, and build-id
    from the evidence tree under root into bindings.
    Object and ring bindings stay empty: object bytes come
    from an explicit path and ring sizes from the loaded
    object, neither of which measuring owns. Shared by
    qualify planning and live receipt verification so both
    read the same six files the same way.
    """
    var cfg = read_live_config(root, release, zlib)
    if cfg.src == String("") or cfg.value.state != String("value"):
        return String("live bindings unmeasurable: config")
    var btf = read_live_bytes(
        root, String("/sys/kernel/btf/vmlinux"), String("btf"),
        MAX_NARROW_BTF_BYTES,
    )
    if btf.state != String("value"):
        return String("live bindings unmeasurable: btf")
    var form = read_live_bytes(
        root,
        _tracefs_format_path(root, format_path),
        String("format"),
        MAX_NARROW_FORMAT_BYTES,
    )
    if form.state != String("value"):
        return String("live bindings unmeasurable: format")
    var image = read_live_bytes(
        root,
        String("/boot/vmlinuz-") + release,
        String("image"),
        MAX_NARROW_IMAGE_BYTES,
    )
    if image.state != String("value"):
        return String("live bindings unmeasurable: image")
    var bid = read_live_bid(root)
    if bid.state != String("value"):
        return String("live bindings unmeasurable: image_bid")
    bindings.config = cfg.value.value.copy()
    bindings.config_src = cfg.src.copy()
    bindings.btf = btf.value.copy()
    bindings.format = form.value.copy()
    bindings.image = image.value.copy()
    bindings.image_bid = bid.value.copy()
    return String("")


def check_narrow(
    bind: NarrowBindings, live: NarrowLive
) -> NarrowVerdict:
    """Compare live values against bindings (grammar order).

    First failure wins: config_src, config, btf, format,
    object, image, image_bid, ring_bytes.
    """
    var out = NarrowVerdict()
    if live.config_src == String(""):
        out.state = String("uncheckable")
        out.key = String("config")
        return out^
    if live.config_src != bind.config_src:
        out.state = String("mismatch")
        out.key = String("config_src")
        return out^
    if live.config.state != String("value"):
        out.state = String("uncheckable")
        out.key = String("config")
        return out^
    if live.config.value != bind.config:
        out.state = String("mismatch")
        out.key = String("config")
        return out^
    if live.btf.state != String("value"):
        out.state = String("uncheckable")
        out.key = String("btf")
        return out^
    if live.btf.value != bind.btf:
        out.state = String("mismatch")
        out.key = String("btf")
        return out^
    if live.format.state != String("value"):
        out.state = String("uncheckable")
        out.key = String("format")
        return out^
    if live.format.value != bind.format:
        out.state = String("mismatch")
        out.key = String("format")
        return out^
    if live.object.state != String("value"):
        out.state = String("uncheckable")
        out.key = String("object")
        return out^
    if live.object.value != bind.object:
        out.state = String("mismatch")
        out.key = String("object")
        return out^
    if live.image.state != String("value"):
        out.state = String("uncheckable")
        out.key = String("image")
        return out^
    if live.image.value != bind.image:
        out.state = String("mismatch")
        out.key = String("image")
        return out^
    if live.image_bid.state != String("value"):
        out.state = String("uncheckable")
        out.key = String("image_bid")
        return out^
    if live.image_bid.value != bind.image_bid:
        out.state = String("mismatch")
        out.key = String("image_bid")
        return out^
    if live.ring.state != String("value"):
        out.state = String("uncheckable")
        out.key = String("ring_bytes")
        return out^
    if live.ring.value != bind.ring:
        out.state = String("mismatch")
        out.key = String("ring_bytes")
        return out^
    out.state = String("bound")
    out.key = String("")
    return out^


def check_identity_bindings(
    root: String,
    release: String,
    note: String,
    zlib: String,
    format_path: String,
) -> NarrowVerdict:
    """Check identity bindings against live reads (no object/ring).

    Compares config_src, config, btf, format, image, and
    image_bid from the note against the evidence tree under
    root, in grammar order with first failure winning. The
    object and ring bindings stay record-time checks: object
    bytes come from an explicit path and ring sizes from the
    loaded object, neither of which passive selection owns.
    """
    var out = NarrowVerdict()
    var parsed = parse_narrow_note(note)
    if not parsed.ok:
        out.state = String("uncheckable")
        out.key = String("note")
        return out^
    var bind = parsed.bindings
    var cfg = read_live_config(root, release, zlib)
    if cfg.src == String(""):
        out.state = String("uncheckable")
        out.key = String("config")
        return out^
    if cfg.src != bind.config_src:
        out.state = String("mismatch")
        out.key = String("config_src")
        return out^
    if cfg.value.state != String("value"):
        out.state = String("uncheckable")
        out.key = String("config")
        return out^
    if cfg.value.value != bind.config:
        out.state = String("mismatch")
        out.key = String("config")
        return out^
    var btf = read_live_bytes(
        root, String("/sys/kernel/btf/vmlinux"), String("btf"),
        MAX_NARROW_BTF_BYTES,
    )
    if btf.state != String("value"):
        out.state = String("uncheckable")
        out.key = String("btf")
        return out^
    if btf.value != bind.btf:
        out.state = String("mismatch")
        out.key = String("btf")
        return out^
    var form = read_live_bytes(
        root,
        _tracefs_format_path(root, format_path),
        String("format"),
        MAX_NARROW_FORMAT_BYTES,
    )
    if form.state != String("value"):
        out.state = String("uncheckable")
        out.key = String("format")
        return out^
    if form.value != bind.format:
        out.state = String("mismatch")
        out.key = String("format")
        return out^
    var image = read_live_bytes(
        root,
        String("/boot/vmlinuz-") + release,
        String("image"),
        MAX_NARROW_IMAGE_BYTES,
    )
    if image.state != String("value"):
        out.state = String("uncheckable")
        out.key = String("image")
        return out^
    if image.value != bind.image:
        out.state = String("mismatch")
        out.key = String("image")
        return out^
    var bid = read_live_bid(root)
    if bid.state != String("value"):
        out.state = String("uncheckable")
        out.key = String("image_bid")
        return out^
    if bid.value != bind.image_bid:
        out.state = String("mismatch")
        out.key = String("image_bid")
        return out^
    out.state = String("bound")
    out.key = String("")
    return out^


def check_narrow_extra(
    bind: NarrowBindings, live: NarrowLive, want_lc: Bool,
    want_cp: Bool,
) -> NarrowVerdict:
    """Compare requested extended bindings (lc before cp).

    Unrequested channels bind vacuously. A requested
    channel without a note binding mismatches on its
    object key; otherwise object bytes then ring size
    must match exactly, like the base grammar.
    """
    var out = NarrowVerdict()
    if want_lc:
        if bind.lc_object == String(""):
            out.state = String("mismatch")
            out.key = String("lc_object")
            return out^
        if live.lc_object.state != String("value"):
            out.state = String("uncheckable")
            out.key = String("lc_object")
            return out^
        if live.lc_object.value != bind.lc_object:
            out.state = String("mismatch")
            out.key = String("lc_object")
            return out^
        if live.lc_ring.state != String("value"):
            out.state = String("uncheckable")
            out.key = String("lc_ring_bytes")
            return out^
        if live.lc_ring.value != bind.lc_ring:
            out.state = String("mismatch")
            out.key = String("lc_ring_bytes")
            return out^
    if want_cp:
        if bind.cp_object == String(""):
            out.state = String("mismatch")
            out.key = String("cp_object")
            return out^
        if live.cp_object.state != String("value"):
            out.state = String("uncheckable")
            out.key = String("cp_object")
            return out^
        if live.cp_object.value != bind.cp_object:
            out.state = String("mismatch")
            out.key = String("cp_object")
            return out^
        if live.cp_ring.state != String("value"):
            out.state = String("uncheckable")
            out.key = String("cp_ring_bytes")
            return out^
        if live.cp_ring.value != bind.cp_ring:
            out.state = String("mismatch")
            out.key = String("cp_ring_bytes")
            return out^
    out.state = String("bound")
    out.key = String("")
    return out^


struct _FieldPin(ImplicitlyCopyable):
    """One pinned trace-format field (name, type, offset, size)."""

    var name: String
    var ftype: String
    var offset: Int
    var size: Int

    def __init__(out self, name: String, ftype: String, offset: Int, size: Int):
        self.name = name
        self.ftype = ftype
        self.offset = offset
        self.size = size


def _layout_pins() -> List[_FieldPin]:
    """Fields the BPF program reads, plus the common_type anchor.

    Derived from the pinned tracepoint header plus natural
    alignment: dev_name __data_loc u32 @8, padding to @16,
    dma_mask u64 @16, dev_addr u64 @24, size u64 @32,
    force bool @40.
    """
    var pins = List[_FieldPin]()
    pins.append(_FieldPin(String("common_type"), String("unsigned short"), 0, 2))
    pins.append(
        _FieldPin(String("dev_name"), String("__data_loc char[]"), 8, 4)
    )
    pins.append(_FieldPin(String("size"), String("size_t"), 32, 8))
    pins.append(_FieldPin(String("force"), String("bool"), 40, 1))
    return pins^


def _split_lines(data: Span[UInt8, _]) -> List[List[UInt8]]:
    var out = List[List[UInt8]]()
    var cur = List[UInt8]()
    for b in data:
        if b == UInt8(0x0A):
            out.append(cur.copy())
            cur = List[UInt8]()
        else:
            cur.append(b)
    if len(cur) > 0:
        out.append(cur.copy())
    return out^


def _bytes_equal(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def _starts_with(line: Span[UInt8, _], pre: String) -> Bool:
    var pb = pre.as_bytes()
    if len(line) < len(pb):
        return False
    for i in range(len(pb)):
        if line[i] != pb[i]:
            return False
    return True


def _parse_decimal(digits: Span[UInt8, _]) -> Int:
    """Decimal value, or -1 when empty, long, or non-decimal."""
    if len(digits) == 0 or len(digits) > 10:
        return -1
    var v = 0
    for i in range(len(digits)):
        var b = digits[i]
        if b < UInt8(0x30) or b > UInt8(0x39):
            return -1
        var d = Int(b) - 0x30
        if v > (2147483647 - d) // 10:
            return -1
        v = v * 10 + d
    return v


def _split_tabs(line: Span[UInt8, _]) -> List[List[UInt8]]:
    var out = List[List[UInt8]]()
    var cur = List[UInt8]()
    for b in line:
        if b == UInt8(0x09):
            out.append(cur.copy())
            cur = List[UInt8]()
        else:
            cur.append(b)
    out.append(cur.copy())
    return out^


struct _FormatField(ImplicitlyCopyable):
    var ok: Bool
    var name: String
    var ftype: String
    var offset: Int
    var size: Int

    def __init__(out self):
        self.ok = False
        self.name = String("")
        self.ftype = String("")
        self.offset = -1
        self.size = -1


def _has_nul(text: String) -> Bool:
    """True when the text holds an embedded NUL byte."""
    var raw = text.as_bytes()
    for i in range(len(raw)):
        if raw[i] == UInt8(0):
            return True
    return False


def _parse_format_field(line: Span[UInt8, _]) -> _FormatField:
    """Strict-parse one `field:TYPE NAME;\\toffset:O;\\tsize:S;` line."""
    var out = _FormatField()
    var parts = _split_tabs(line)
    if len(parts) < 3:
        return out^
    var head = Span(parts[0])
    if not _starts_with(head, String("field:")) or head[len(head) - 1] != UInt8(
        0x3B
    ):
        return out^
    var inner = head[6 : len(head) - 1]
    var cut = -1
    for i in range(len(inner)):
        if inner[i] == UInt8(0x20):
            cut = i
    if cut <= 0 or cut + 1 >= len(inner):
        return out^
    var off = Span(parts[1])
    if (
        not _starts_with(off, String("offset:"))
        or off[len(off) - 1] != UInt8(0x3B)
        or len(off) <= 8
    ):
        return out^
    var siz = Span(parts[2])
    if (
        not _starts_with(siz, String("size:"))
        or siz[len(siz) - 1] != UInt8(0x3B)
        or len(siz) <= 6
    ):
        return out^
    var offset = _parse_decimal(off[7 : len(off) - 1])
    var size = _parse_decimal(siz[5 : len(siz) - 1])
    if offset < 0 or size < 0:
        return out^
    try:
        out.ftype = String(from_utf8=inner[0:cut])
    except:
        return out^
    try:
        out.name = String(from_utf8=inner[cut + 1 : len(inner)])
    except:
        return out^
    if out.ftype == String("") or out.name == String(""):
        out.ok = False
        return out^
    out.offset = offset
    out.size = size
    out.ok = True
    return out^


def check_trace_layout(data: Span[UInt8, _]) -> LayoutCheck:
    """Verify the live format against the pinned program layout.

    Non-field lines are skipped and leading blanks are
    tolerated (tracefs indents field lines); every pinned
    field must appear exactly once with the pinned type,
    offset, and size. Anything else refuses: the program
    would read the wrong bytes.
    """
    var out = LayoutCheck()
    var pins = _layout_pins()
    var seen = List[Bool]()
    for _ in range(len(pins)):
        seen.append(False)
    for line in _split_lines(data):
        var lb = Span(line)
        var s = 0
        while s < len(lb) and (lb[s] == UInt8(9) or lb[s] == UInt8(0x20)):
            s += 1
        if s >= len(lb):
            continue
        var body = lb[s : len(lb)]
        if not _starts_with(body, String("field:")):
            continue
        var f = _parse_format_field(body)
        if not f.ok:
            out.message = String("format line unparseable")
            return out^
        for i in range(len(pins)):
            if f.name == pins[i].name:
                if seen[i]:
                    out.message = String(t"duplicate field {f.name}")
                    return out^
                seen[i] = True
                if f.ftype != pins[i].ftype:
                    out.message = String(
                        t"field {f.name}: want type {pins[i].ftype}"
                    )
                    return out^
                if f.offset != pins[i].offset or f.size != pins[i].size:
                    out.message = String(
                        t"field {f.name}: want @{pins[i].offset}:{pins[i].size}"
                    )
                    return out^
    for i in range(len(pins)):
        if not seen[i]:
            out.message = String(t"missing field {pins[i].name}")
            return out^
    out.ok = True
    out.message = String("")
    return out^


struct TraceField(ImplicitlyCopyable):
    """One discovered tracefs format field."""

    var name: String
    var ftype: String
    var offset: Int
    var size: Int

    def __init__(out self):
        self.name = String("")
        self.ftype = String("")
        self.offset = -1
        self.size = -1

    def __init__(out self, name: String, ftype: String, offset: Int, size: Int):
        self.name = name
        self.ftype = ftype
        self.offset = offset
        self.size = size


struct TraceFormat(Copyable, Movable):
    """Discovered layout of one tracefs event format (fields valid iff ok)."""

    var ok: Bool
    var message: String
    var fields: List[TraceField]

    def __init__(out self):
        self.ok = False
        self.message = String("")
        self.fields = List[TraceField]()


def parse_trace_format(data: Span[UInt8, _]) -> TraceFormat:
    """Strict-parse a tracefs event format into its field layout.

    Non-field lines are skipped and leading blanks are
    tolerated (tracefs indents field lines). Any unparseable
    field line, NUL byte in a field name or type, or
    duplicate field name refuses: offsets derived from a
    misread layout would read wrong bytes. Bytes in skipped
    lines and ignored trailing columns are never inspected.
    """
    var out = TraceFormat()
    for line in _split_lines(data):
        var lb = Span(line)
        var s = 0
        while s < len(lb) and (lb[s] == UInt8(9) or lb[s] == UInt8(0x20)):
            s += 1
        if s >= len(lb):
            continue
        var body = lb[s : len(lb)]
        if not _starts_with(body, String("field:")):
            continue
        var f = _parse_format_field(body)
        if not f.ok:
            out.message = String("format line unparseable")
            return out^
        if _has_nul(f.name) or _has_nul(f.ftype):
            out.message = String("format line unparseable")
            return out^
        for i in range(len(out.fields)):
            if out.fields[i].name == f.name:
                out.message = String(t"duplicate field {f.name}")
                return out^
        out.fields.append(
            TraceField(f.name.copy(), f.ftype.copy(), f.offset, f.size)
        )
    out.ok = True
    out.message = String("")
    return out^


def known_trace_format() -> TraceFormat:
    """Known-good attempt layout, as the program pins it."""
    var out = TraceFormat()
    var pins = _layout_pins()
    for i in range(len(pins)):
        out.fields.append(
            TraceField(
                pins[i].name.copy(),
                pins[i].ftype.copy(),
                pins[i].offset,
                pins[i].size,
            )
        )
    out.ok = True
    out.message = String("")
    return out^


def diff_trace_format(want: TraceFormat, live: TraceFormat) -> String:
    """First structural difference of live against want, else "".

    Every wanted field must exist in live with the same type,
    offset, and size; extra live fields are tolerated because
    kernels may extend the record. The message names exact
    wanted and live values so diagnostics can quote it.
    """
    if not want.ok:
        return String("want layout invalid")
    if not live.ok:
        return String("live layout invalid: ") + live.message
    for i in range(len(want.fields)):
        var w = want.fields[i]
        var found = -1
        for j in range(len(live.fields)):
            if live.fields[j].name == w.name:
                found = j
                break
        if found < 0:
            return String(t"missing field {w.name}")
        var got = live.fields[found]
        if got.ftype != w.ftype:
            return String(
                t"field {w.name}: want type {w.ftype}, live {got.ftype}"
            )
        if got.offset != w.offset or got.size != w.size:
            var msg = t"field {w.name}: want @{w.offset}:{w.size}, live @{got.offset}:{got.size}"
            return String(msg)
    return String("")


comptime MV_OFF_TABLE_MAGIC = 0x35464D4D
comptime MV_OFF_TABLE_VERSION = 1
comptime MV_FIXED_MAX = 128
comptime MV_OFFSETS_TABLE_LEN = 24


struct OffsetProbe(ImplicitlyCopyable):
    """One live-layout probe: table offsets, or a named refusal.

    ``ok`` True carries the probed ``__data_loc`` slot,
    size, and force offsets plus the dynamic-data floor
    (``fixed_end``) for the load-time offset table;
    ``moved`` tells a drifted-but-readable layout from
    the pinned one. ``ok`` False carries the refusing
    drift class in ``message``.
    """

    var ok: Bool
    var message: String
    var moved: Bool
    var loc_off: Int
    var size_off: Int
    var force_off: Int
    var fixed_end: Int

    def __init__(out self):
        self.ok = False
        self.message = String("")
        self.moved = False
        self.loc_off = -1
        self.size_off = -1
        self.force_off = -1
        self.fixed_end = -1


def _refuse_probe(message: String) -> OffsetProbe:
    var out = OffsetProbe()
    out.ok = False
    out.message = message
    return out^


def _extents_overlap(a_off: Int, a_w: Int, b_off: Int, b_w: Int) -> Bool:
    return a_off < b_off + b_w and b_off < a_off + a_w


def _find_live_field(
    fields: List[TraceField], want: String
) -> Int:
    """Index of the live field named want, or -1."""
    for i in range(len(fields)):
        if fields[i].name == want:
            return i
    return -1


def validate_table_extents(
    loc_off: Int, size_off: Int, force_off: Int, fixed_end: Int
) -> String:
    """Bounds/overlap verdict for one offset table, else "".

    Every tabled extent must sit inside the fixed-region
    cap, no two pinned extents (including the
    common_type anchor) may overlap, and the dynamic
    floor must stay within the cap with margin under the
    context read cap while covering every tabled
    extent. The collector re-runs this on its
    configured values before install; the BPF program
    re-checks the same properties at runtime.
    """
    if loc_off < 0 or size_off < 0 or force_off < 0 or fixed_end < 0:
        return String("negative table extent")
    if loc_off + 4 > MV_FIXED_MAX:
        return String(
            t"field dev_name extent @{loc_off}:4 exceeds fixed cap {MV_FIXED_MAX}"
        )
    if size_off + 8 > MV_FIXED_MAX:
        return String(
            t"field size extent @{size_off}:8 exceeds fixed cap {MV_FIXED_MAX}"
        )
    if force_off + 1 > MV_FIXED_MAX:
        return String(
            t"field force extent @{force_off}:1 exceeds fixed cap {MV_FIXED_MAX}"
        )
    if _extents_overlap(0, 2, loc_off, 4):
        return String("overlapping extents common_type and dev_name")
    if _extents_overlap(0, 2, size_off, 8):
        return String("overlapping extents common_type and size")
    if _extents_overlap(0, 2, force_off, 1):
        return String("overlapping extents common_type and force")
    if _extents_overlap(loc_off, 4, size_off, 8):
        return String("overlapping extents dev_name and size")
    if _extents_overlap(loc_off, 4, force_off, 1):
        return String("overlapping extents dev_name and force")
    if _extents_overlap(size_off, 8, force_off, 1):
        return String("overlapping extents size and force")
    if fixed_end > MV_FIXED_MAX:
        return String(
            t"fixed region end {fixed_end} exceeds cap {MV_FIXED_MAX}"
        )
    if fixed_end < loc_off + 4:
        return String(
            t"fixed region end {fixed_end} below dev_name extent @{loc_off}:4"
        )
    if fixed_end < size_off + 8:
        return String(
            t"fixed region end {fixed_end} below size extent @{size_off}:8"
        )
    if fixed_end < force_off + 1:
        return String(
            t"fixed region end {fixed_end} below force extent @{force_off}:1"
        )
    return String("")


def probe_trace_offsets(data: Span[UInt8, _]) -> OffsetProbe:
    """Probe the live format into load-time table offsets.

    Pure classifier over already-read bytes: callers pass
    the same buffer the format binding hashes, so probed
    offsets inherit that binding (same-buffer derivation,
    no re-read). The common_type anchor must match the
    pins exactly; dev_name, size, and force keep their
    pinned type spellings and widths but may sit at
    probed offsets; extra live fields are tolerated and
    the dynamic floor is the max end over every parsed
    field, __data_loc descriptors included. Any retype,
    resize, missing or
    duplicate field, unparseable line, anchor drift,
    overlap, or cap breach refuses naming its class.
    """
    var fmt = parse_trace_format(data)
    if not fmt.ok:
        return _refuse_probe(fmt.message.copy())
    var anchor = _find_live_field(fmt.fields, String("common_type"))
    if anchor < 0:
        return _refuse_probe(String("missing field common_type"))
    var got_anchor = fmt.fields[anchor]
    if got_anchor.ftype != String("unsigned short"):
        return _refuse_probe(
            String(
                t"field common_type: want type unsigned short, live {got_anchor.ftype}"
            )
        )
    if got_anchor.offset != 0 or got_anchor.size != 2:
        return _refuse_probe(
            String(
                t"field common_type: want @0:2, live @{got_anchor.offset}:{got_anchor.size}"
            )
        )
    var pins = _layout_pins()
    var offs = List[Int]()
    for _ in range(4):
        offs.append(-1)
    for i in range(1, 4):
        var at = _find_live_field(fmt.fields, pins[i].name)
        if at < 0:
            return _refuse_probe(
                String(t"missing field {pins[i].name}")
            )
        var got = fmt.fields[at]
        if got.ftype != pins[i].ftype:
            return _refuse_probe(
                String(
                    t"field {pins[i].name}: want type {pins[i].ftype}, live {got.ftype}"
                )
            )
        if got.size != pins[i].size:
            return _refuse_probe(
                String(
                    t"field {pins[i].name}: want size {pins[i].size}, live size {got.size}"
                )
            )
        offs[i] = got.offset
    var moved = (
        offs[1] != pins[1].offset
        or offs[2] != pins[2].offset
        or offs[3] != pins[3].offset
    )
    var fixed_end = 0
    for i in range(len(fmt.fields)):
        var field = fmt.fields[i]
        # Every declared field occupies its fixed slot,
        # including __data_loc descriptors: each is a
        # fixed u32 holding an offset/length pair, not
        # dynamic data itself.
        var end = field.offset + field.size
        if end > fixed_end:
            fixed_end = end
    var bad = validate_table_extents(
        offs[1], offs[2], offs[3], fixed_end
    )
    if bad != String(""):
        return _refuse_probe(bad.copy())
    var out = OffsetProbe()
    out.ok = True
    out.message = String("")
    out.moved = moved
    out.loc_off = offs[1]
    out.size_off = offs[2]
    out.force_off = offs[3]
    out.fixed_end = fixed_end
    return out^


def _append_le32(mut buf: List[UInt8], v: Int):
    for i in range(4):
        buf.append(UInt8((v >> (8 * i)) & 0xFF))


def encode_offsets_table(
    loc_off: Int, size_off: Int, force_off: Int, fixed_end: Int
) -> List[UInt8]:
    """Encode one offset table: 24 bytes, little-endian.

    Layout mirrors ``struct mv_offsets`` (magic, version,
    reserved, loc/size/force offsets, fixed end). A
    negative input encodes to empty, which install
    refuses; callers pass probe-admitted or
    validator-checked values.
    """
    var out = List[UInt8]()
    if loc_off < 0 or size_off < 0 or force_off < 0 or fixed_end < 0:
        return out^
    _append_le32(out, MV_OFF_TABLE_MAGIC)
    out.append(UInt8(MV_OFF_TABLE_VERSION & 0xFF))
    out.append(UInt8((MV_OFF_TABLE_VERSION >> 8) & 0xFF))
    out.append(UInt8(0))
    out.append(UInt8(0))
    _append_le32(out, loc_off)
    _append_le32(out, size_off)
    _append_le32(out, force_off)
    _append_le32(out, fixed_end)
    return out^


def _le16(data: Span[UInt8, _], at: Int) -> Int:
    return Int(data[at]) | (Int(data[at + 1]) << 8)


def _le32(data: Span[UInt8, _], at: Int) -> Int:
    return (
        Int(data[at])
        | (Int(data[at + 1]) << 8)
        | (Int(data[at + 2]) << 16)
        | (Int(data[at + 3]) << 24)
    )


def _le64(data: Span[UInt8, _], at: Int) -> Int:
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


def _strtab_text(
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


def _str_starts_with(text: String, pre: String) -> Bool:
    return _starts_with(text.as_bytes(), pre)


def _refuse(message: String) -> ObjectCheck:
    var out = ObjectCheck()
    out.ok = False
    out.message = message
    return out^


def verify_object(data: Span[UInt8, _], want_program: String) -> ObjectCheck:
    """Static admission for a BPF object: class, machine, sections, symbol.

    Requires ELF64LE relocatable EM_BPF with a tracepoint
    section, a .maps section, a license section, and the
    named program as a defined global function living in a
    tracepoint section. Required sections must be PROGBITS
    inside the file, and the program symbol must name a
    non-empty extent within its section. Any structural
    defect refuses; this never executes or loads anything.
    """
    return _verify_object(data, want_program, String("tracepoint/"))


def verify_object_program(
    data: Span[UInt8, _], want_program: String, section_prefix: String
) -> ObjectCheck:
    """Static admission for one program in a known section kind.

    Same ELF/.maps/license/symbol checks as verify_object,
    but the program must live in a section starting with
    section_prefix, one of tracepoint/, fentry/, or fexit/.
    Anything else refuses without reading the object.
    """
    if (
        section_prefix != String("tracepoint/")
        and section_prefix != String("fentry/")
        and section_prefix != String("fexit/")
    ):
        return _refuse(String("bad section kind"))
    return _verify_object(data, want_program, section_prefix)


def _verify_object(
    data: Span[UInt8, _], want_program: String, prefix: String
) -> ObjectCheck:
    """Shared worker: verify_object with a section-kind prefix."""
    var total = len(data)
    if total < 64:
        return _refuse(String("object too small"))
    if (
        data[0] != UInt8(0x7F)
        or data[1] != UInt8(0x45)
        or data[2] != UInt8(0x4C)
        or data[3] != UInt8(0x46)
        or data[4] != UInt8(2)
        or data[5] != UInt8(1)
        or data[6] != UInt8(1)
    ):
        return _refuse(String("not an ELF64LE object"))
    if _le16(data, 0x10) != 1:
        return _refuse(String("not relocatable"))
    if _le32(data, 0x14) != 1:
        return _refuse(String("bad ELF version"))
    if _le16(data, 0x12) != 247:
        return _refuse(String("not a BPF object"))
    var shoff = _le64(data, 0x28)
    var shentsize = _le16(data, 0x3A)
    var shnum = _le16(data, 0x3C)
    var shstrndx = _le16(data, 0x3E)
    if shentsize != 64 or shnum == 0:
        return _refuse(String("no section table"))
    if shstrndx >= shnum or shoff < 0 or shoff > total:
        return _refuse(String("section table out of range"))
    if shnum > (total - shoff) // 64:
        return _refuse(String("section table out of range"))
    var str_base = shoff + shstrndx * 64
    var str_off = _le64(data, str_base + 24)
    var str_size = _le64(data, str_base + 32)
    if str_off < 0 or str_size < 0 or str_off > total:
        return _refuse(String("names out of range"))
    if str_size > total - str_off:
        return _refuse(String("names out of range"))
    var str_end = str_off + str_size
    var names = List[String]()
    var types = List[Int]()
    var offs = List[Int]()
    var sizes = List[Int]()
    var has_want = False
    var has_maps = False
    var has_license = False
    var symtab = -1
    for i in range(shnum):
        var base = shoff + i * 64
        var sh_name = _le32(data, base)
        var sh_type = _le32(data, base + 4)
        var sec_name = String("")
        if not _strtab_text(data, str_off, str_end, sh_name, sec_name):
            return _refuse(String("section names corrupt"))
        names.append(sec_name.copy())
        types.append(sh_type)
        offs.append(_le64(data, base + 24))
        sizes.append(_le64(data, base + 32))
        if _str_starts_with(sec_name, prefix):
            has_want = True
        if sec_name == String(".maps"):
            has_maps = True
        if sec_name == String("license"):
            has_license = True
        if sh_type == 2 and symtab < 0:
            symtab = i
    if not has_want:
        var display = String("")
        var praw = prefix.as_bytes()
        for i in range(len(praw)):
            if praw[i] == UInt8(0x2F):
                break
            display += String(prefix[byte=i])
        return _refuse(String("no ") + display + String(" section"))
    if not has_maps:
        return _refuse(String("no .maps section"))
    if not has_license:
        return _refuse(String("no license section"))
    # Required sections must be real PROGBITS content inside
    # the file: names alone admit out-of-file ranges and
    # wrong-type sections that later readers would misparse.
    for i in range(shnum):
        var required = _str_starts_with(
            names[i], prefix
        ) or names[i] == String(".maps") or names[i] == String(
            "license"
        )
        if not required:
            continue
        if types[i] != 1:
            return _refuse(names[i] + String(" section bad type"))
        if (
            offs[i] < 0
            or sizes[i] < 0
            or offs[i] > total
            or sizes[i] > total - offs[i]
        ):
            return _refuse(
                names[i] + String(" section out of range")
            )
    if symtab < 0:
        return _refuse(String("no symbol table"))
    var sym_base = shoff + symtab * 64
    var sym_off = _le64(data, sym_base + 24)
    var sym_size = _le64(data, sym_base + 32)
    var sym_link = _le32(data, sym_base + 40)
    var sym_entsize = _le64(data, sym_base + 56)
    if sym_entsize != 24:
        return _refuse(String("bad symtab entry size"))
    if sym_off < 0 or sym_size < 0 or sym_off > total:
        return _refuse(String("symbols out of range"))
    if sym_size > total - sym_off:
        return _refuse(String("symbols out of range"))
    if sym_link < 0 or sym_link >= shnum:
        return _refuse(String("bad symtab link"))
    var tab_base = shoff + sym_link * 64
    var tab_off = _le64(data, tab_base + 24)
    var tab_size = _le64(data, tab_base + 32)
    if tab_off < 0 or tab_size < 0 or tab_off > total:
        return _refuse(String("symbols out of range"))
    if tab_size > total - tab_off:
        return _refuse(String("symbols out of range"))
    var tab_end = tab_off + tab_size
    var detail = String("")
    var count = sym_size // 24
    for s in range(count):
        var sb = sym_off + s * 24
        var st_name = _le32(data, sb)
        var st_info = Int(data[sb + 4])
        var st_shndx = _le16(data, sb + 6)
        var sym_name = String("")
        if not _strtab_text(data, tab_off, tab_end, st_name, sym_name):
            return _refuse(String("symbol names corrupt"))
        if sym_name != want_program:
            continue
        var bind = st_info >> 4
        var typ = st_info & 15
        if bind != 1 or typ != 2:
            detail = String(t"bad binding/type @{st_shndx}")
            continue
        if st_shndx == 0 or st_shndx >= shnum:
            detail = String("program undefined")
            continue
        if not _str_starts_with(names[st_shndx], prefix):
            detail = String(t"program in {names[st_shndx]}")
            continue
        var st_value = _le64(data, sb + 8)
        var st_size = _le64(data, sb + 16)
        if st_size <= 0:
            detail = String("program empty")
            continue
        var sec_size = sizes[st_shndx]
        if st_value < 0 or st_value > sec_size or st_size > sec_size - st_value:
            detail = String("program outside section")
            continue
        var out = ObjectCheck()
        out.ok = True
        out.message = String("")
        return out^
    if detail != String(""):
        return _refuse(String(t"program symbol unusable: {detail}"))
    return _refuse(String("program symbol missing"))
