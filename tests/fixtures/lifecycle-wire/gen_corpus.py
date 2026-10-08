#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Lifecycle/copy-vector corpus generator (single source for C and Mojo tests).

Emits tests/fixtures/lifecycle-wire/corpus.bin (length-prefixed inputs)
and corpus.txt (one expectation line per record):

    <idx> <lifecycle|copy|effective> <verdict> [fields...]

lifecycle OK fields: kind=N ok=N skip=N dir=N seq=N ktime=N size=N
copy OK fields: kind=N todevice=N known=N clamped=N earlyzero=N
    dir=N reason=N seq=N ktime=N requested=N effective=N
effective vectors always carry verdict OK with fields:
    effective=N clamped=N earlyzero=N

The bin record for kind effective is 25 bytes: u64 size, i64
tlb_offset, u64 alloc_size, u8 orig_valid. Verdicts are the shared
reason vocabulary from bpf/include/memveil_events.h. Regeneration
is byte-identical; `--check` fails on any drift.
"""

import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BIN_PATH = os.path.join(HERE, "corpus.bin")
TXT_PATH = os.path.join(HERE, "corpus.txt")

U64MAX = (1 << 64) - 1
I64MIN = -(1 << 63)
KIND_LIFECYCLE = 1
KIND_COPY = 2
KIND_EFFECTIVE = 3

LC_MAGIC = 0x434C564D  # "MVLC" little-endian
CP_MAGIC = 0x5043564D  # "MVCP" little-endian


def lc_raw(kind=1, flags=1, dir=1, seq=7, ktime=9, size=4096,
           magic=LC_MAGIC, version=1):
    """36-byte MVLC record."""
    raw = struct.pack("<IHHHHQQQ", magic, version, kind, flags,
                      dir, seq, ktime, size)
    assert len(raw) == 36, len(raw)
    return raw


def cp_raw(kind=2, flags=3, dir=1, seq=3, ktime=4, requested=4096,
           effective=1024, reason=0, magic=CP_MAGIC, version=1):
    """48-byte MVCP record (reason u16 plus 2 pad bytes)."""
    raw = struct.pack("<IHHHHQQQQH", magic, version, kind, flags,
                      dir, seq, ktime, requested, effective,
                      reason) + b"\0\0"
    assert len(raw) == 48, len(raw)
    return raw


def eff_raw(size, off, alloc, valid):
    """25-byte effective-rule input: size/off/alloc/valid."""
    raw = struct.pack("<Q", size) + struct.pack("<q", off) + \
        struct.pack("<Q", alloc) + struct.pack("<B", valid)
    assert len(raw) == 25, len(raw)
    return raw


def build_vectors():
    vecs = []

    def lc_vec(buf, verdict, **fields):
        vecs.append((KIND_LIFECYCLE, buf, verdict, fields or None))

    def cp_vec(buf, verdict, **fields):
        vecs.append((KIND_COPY, buf, verdict, fields or None))

    def eff_vec(buf, **fields):
        vecs.append((KIND_EFFECTIVE, buf, "OK", fields))

    # --- lifecycle valid vectors ---
    lc_vec(lc_raw(1, 1, 1, 7, 9, 4096), "OK",
           kind=1, ok=1, skip=0, dir=1, seq=7, ktime=9, size=4096)
    lc_vec(lc_raw(2, 3, 2, 8, 10, 1024), "OK",
           kind=2, ok=1, skip=1, dir=2, seq=8, ktime=10, size=1024)
    lc_vec(lc_raw(1, 0, 1, 11, 12, 4096), "OK",
           kind=1, ok=0, skip=0, dir=1, seq=11, ktime=12, size=4096)
    lc_vec(lc_raw(1, 1, 0, 13, 14, 512), "OK",
           kind=1, ok=1, skip=0, dir=0, seq=13, ktime=14, size=512)
    lc_vec(lc_raw(2, 1, 0, U64MAX, U64MAX, U64MAX), "OK",
           kind=2, ok=1, skip=0, dir=0, seq=U64MAX, ktime=U64MAX,
           size=U64MAX)
    # --- lifecycle rejections ---
    good = lc_raw()
    lc_vec(good[:35], "PAY_SHORT")
    lc_vec(good + b"\0", "PAY_LONG")
    bad = bytearray(lc_raw())
    bad[0] = 0
    lc_vec(bytes(bad), "PAY_MAGIC")
    bad = bytearray(lc_raw())
    bad[4] = 2
    lc_vec(bytes(bad), "PAY_VERSION")
    lc_vec(lc_raw(kind=3), "PAY_KIND")
    lc_vec(lc_raw(flags=4), "PAY_FLAGS")
    lc_vec(lc_raw(dir=3), "PAY_DIR")
    # precedence: magic beats kind; kind beats flags; flags beat dir.
    bad = bytearray(lc_raw(kind=9))
    bad[0] = 0
    lc_vec(bytes(bad), "PAY_MAGIC")
    lc_vec(lc_raw(kind=9, flags=4, dir=3), "PAY_KIND")
    lc_vec(lc_raw(kind=1, flags=4, dir=3), "PAY_FLAGS")

    # --- copy valid vectors ---
    cp_vec(cp_raw(2, 3, 1, 3, 4, 4096, 1024, 0), "OK",
           kind=2, todevice=1, known=1, clamped=0, earlyzero=0,
           dir=1, reason=0, seq=3, ktime=4, requested=4096,
           effective=1024)
    cp_vec(cp_raw(1, 1, 2, 5, 6, 512, 0, 4), "OK",
           kind=1, todevice=1, known=0, clamped=0, earlyzero=0,
           dir=2, reason=4, seq=5, ktime=6, requested=512,
           effective=0)
    cp_vec(cp_raw(2, 7, 1, 21, 22, 4096, 1024, 0), "OK",
           kind=2, todevice=1, known=1, clamped=1, earlyzero=0,
           dir=1, reason=0, seq=21, ktime=22, requested=4096,
           effective=1024)
    cp_vec(cp_raw(2, 11, 2, 23, 24, 512, 0, 0), "OK",
           kind=2, todevice=1, known=1, clamped=0, earlyzero=1,
           dir=2, reason=0, seq=23, ktime=24, requested=512,
           effective=0)
    cp_vec(cp_raw(2, 2, 2, 25, 26, 2048, 2048, 0), "OK",
           kind=2, todevice=0, known=1, clamped=0, earlyzero=0,
           dir=2, reason=0, seq=25, ktime=26, requested=2048,
           effective=2048)
    cp_vec(cp_raw(2, 0, 1, 27, 28, 4096, 0, 1), "OK",
           kind=2, todevice=0, known=0, clamped=0, earlyzero=0,
           dir=1, reason=1, seq=27, ktime=28, requested=4096,
           effective=0)
    cp_vec(cp_raw(1, 0, 0, 29, 30, 0, 0, 4), "OK",
           kind=1, todevice=0, known=0, clamped=0, earlyzero=0,
           dir=0, reason=4, seq=29, ktime=30, requested=0,
           effective=0)
    cp_vec(cp_raw(2, 3, 1, U64MAX, U64MAX, U64MAX, U64MAX, 0),
           "OK", kind=2, todevice=1, known=1, clamped=0,
           earlyzero=0, dir=1, reason=0, seq=U64MAX, ktime=U64MAX,
           requested=U64MAX, effective=U64MAX)
    # --- copy rejections ---
    good = cp_raw()
    cp_vec(good[:47], "PAY_SHORT")
    cp_vec(good + b"\0", "PAY_LONG")
    bad = bytearray(cp_raw())
    bad[0] = 0
    cp_vec(bytes(bad), "PAY_MAGIC")
    bad = bytearray(cp_raw())
    bad[4] = 2
    cp_vec(bytes(bad), "PAY_VERSION")
    cp_vec(cp_raw(kind=9), "PAY_KIND")
    cp_vec(cp_raw(flags=16), "PAY_FLAGS")
    cp_vec(cp_raw(kind=2, flags=2, dir=0), "PAY_DIR")
    cp_vec(cp_raw(dir=3), "PAY_DIR")
    cp_vec(cp_raw(reason=5), "PAY_REASON")
    cp_vec(cp_raw(kind=2, flags=2, reason=1), "PAY_REASON")
    cp_vec(cp_raw(kind=1, flags=0, reason=0), "PAY_REASON")
    cp_vec(cp_raw(kind=2, flags=0, reason=0), "PAY_REASON")
    cp_vec(cp_raw(kind=2, flags=0, reason=4), "PAY_REASON")
    # precedence: kind beats flags; flags beat dir; dir beats reason.
    cp_vec(cp_raw(kind=9, flags=16, dir=3, reason=5), "PAY_KIND")
    cp_vec(cp_raw(kind=2, flags=16, dir=3, reason=5), "PAY_FLAGS")
    cp_vec(cp_raw(kind=2, flags=2, dir=3, reason=5), "PAY_DIR")

    # --- canonical shipping cases (valid vectors, exact numbers) ---
    # nested 4096+1024 copies -> 5120 effective.
    cp_vec(cp_raw(2, 3, 1, 101, 1001, 4096, 4096, 0), "OK",
           kind=2, todevice=1, known=1, clamped=0, earlyzero=0,
           dir=1, reason=0, seq=101, ktime=1001, requested=4096,
           effective=4096)
    cp_vec(cp_raw(2, 3, 1, 102, 1002, 1024, 1024, 0), "OK",
           kind=2, todevice=1, known=1, clamped=0, earlyzero=0,
           dir=1, reason=0, seq=102, ktime=1002, requested=1024,
           effective=1024)
    # copy before a failed mapping.
    cp_vec(cp_raw(2, 3, 1, 111, 1011, 4096, 4096, 0), "OK",
           kind=2, todevice=1, known=1, clamped=0, earlyzero=0,
           dir=1, reason=0, seq=111, ktime=1011, requested=4096,
           effective=4096)
    lc_vec(lc_raw(1, 0, 1, 112, 1012, 4096), "OK",
           kind=1, ok=0, skip=0, dir=1, seq=112, ktime=1012,
           size=4096)
    # same numeric request reused with distinct seqs.
    lc_vec(lc_raw(1, 1, 1, 121, 1021, 4096), "OK",
           kind=1, ok=1, skip=0, dir=1, seq=121, ktime=1021,
           size=4096)
    lc_vec(lc_raw(1, 1, 1, 122, 1022, 4096), "OK",
           kind=1, ok=1, skip=0, dir=1, seq=122, ktime=1022,
           size=4096)

    # --- effective-rule vectors: (size, off, alloc, valid) -> out ---
    eff_vec(eff_raw(4096, 0, 4096, 0),
            effective=0, clamped=0, earlyzero=1)
    eff_vec(eff_raw(4096, 3072, 4096, 1),
            effective=1024, clamped=1, earlyzero=0)
    eff_vec(eff_raw(1024, 0, 4096, 1),
            effective=1024, clamped=0, earlyzero=0)
    eff_vec(eff_raw(100, -50, 100, 1),
            effective=100, clamped=0, earlyzero=0)
    eff_vec(eff_raw(4096, 4096, 4096, 1),
            effective=0, clamped=1, earlyzero=0)
    eff_vec(eff_raw(1, I64MIN, 0, 1),
            effective=1, clamped=0, earlyzero=0)
    eff_vec(eff_raw(U64MAX, -1, U64MAX, 1),
            effective=U64MAX, clamped=0, earlyzero=0)
    eff_vec(eff_raw(8, 9, 8, 1),
            effective=0, clamped=1, earlyzero=0)
    eff_vec(eff_raw(0, 0, 0, 1),
            effective=0, clamped=0, earlyzero=0)
    eff_vec(eff_raw(7, 0, 0, 1),
            effective=0, clamped=1, earlyzero=0)
    return vecs


LC_FIELDS = ("kind", "ok", "skip", "dir", "seq", "ktime", "size")
CP_FIELDS = ("kind", "todevice", "known", "clamped", "earlyzero",
             "dir", "reason", "seq", "ktime", "requested",
             "effective")
EFF_FIELDS = ("effective", "clamped", "earlyzero")


def render_txt(vecs):
    lines = ["# <idx> <lifecycle|copy|effective> <verdict> [k=v ...]"]
    for idx, (kind, _buf, verdict, fields) in enumerate(vecs):
        name = {KIND_LIFECYCLE: "lifecycle", KIND_COPY: "copy",
                KIND_EFFECTIVE: "effective"}[kind]
        if fields is None:
            lines.append("%d %s %s" % (idx, name, verdict))
            continue
        order = {KIND_LIFECYCLE: LC_FIELDS, KIND_COPY: CP_FIELDS,
                 KIND_EFFECTIVE: EFF_FIELDS}[kind]
        tail = " ".join("%s=%s" % (k, fields[k]) for k in order)
        lines.append("%d %s %s %s" % (idx, name, verdict, tail))
    return "\n".join(lines) + "\n"


def render_bin(vecs):
    out = struct.pack("<I", len(vecs))
    for kind, buf, _verdict, _fields in vecs:
        out += struct.pack("<II", kind, len(buf)) + buf
    return out


def main(argv):
    vecs = build_vectors()
    want_bin = render_bin(vecs)
    want_txt = render_txt(vecs)
    if len(argv) == 2 and argv[1] == "--check":
        try:
            with open(BIN_PATH, "rb") as handle:
                got_bin = handle.read()
            with open(TXT_PATH, "r") as handle:
                got_txt = handle.read()
        except OSError as exc:
            print("lifecycle-wire corpus missing: %s" % exc)
            return 1
        if got_bin != want_bin or got_txt != want_txt:
            print("lifecycle-wire corpus drifted; regenerate")
            return 1
        print("lifecycle-wire corpus: %d vectors match" % len(vecs))
        return 0
    if len(argv) != 1:
        print("usage: gen_corpus.py [--check]")
        return 2
    for path, data, mode in ((BIN_PATH, want_bin, "wb"),
                             (TXT_PATH, want_txt, "w")):
        tmp = tempfile.NamedTemporaryFile(
            mode=mode, dir=HERE, delete=False)
        try:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp.close()
            os.replace(tmp.name, path)
        except BaseException:
            os.unlink(tmp.name)
            raise
    print("lifecycle-wire corpus: %d vectors written" % len(vecs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
