#!/usr/bin/env python3
"""Attempt-vector corpus generator (single source for C and Mojo tests).

Emits tests/fixtures/attempts/corpus.bin (length-prefixed inputs)
and corpus.txt (one expectation line per record):

    <idx> <ctx|payload> <verdict> [size=N force=N seq=N|- ktime=N|-
    namelen=N name=<hex>]

`seq`/`ktime` are `-` for ctx records (the extractor assigns them;
the test passes seq=<idx> and a fixed ktime, so dumps stay
deterministic). Verdicts are the shared reason vocabulary from
bpf/include/memveil_events.h. Regeneration is byte-identical;
`--check` fails on any drift.
"""

import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BIN_PATH = os.path.join(HERE, "corpus.bin")
TXT_PATH = os.path.join(HERE, "corpus.txt")

U64MAX = (1 << 64) - 1
KIND_CTX = 1
KIND_PAYLOAD = 2

MAGIC = 0x3741564D  # "MVA7" little-endian


def ctx_fixed(dev_off, dev_dlen, size=98, force=0):
    """41-byte fixed tracepoint context for swiotlb_bounced id 382."""
    loc = ((dev_dlen & 0xFFFF) << 16) | (dev_off & 0xFFFF)
    return struct.pack(
        "<HBBiI4sQQQB",
        382, 0, 0, 1234, loc, b"\0\0\0\0",
        0xFFFFFFFF, 0x123456789ABCDEF0, size, force,
    )


def payload(magic=MAGIC, version=1, flags=0, seq=7, ktime=123456789,
            size=98, name=b"0000:00:02.0"):
    """98-byte product payload; name must exclude its NUL."""
    if len(name) > 63:
        raise ValueError("name too long for a valid payload")
    body = struct.pack("<IHHQQQH", magic, version, flags, seq,
                       ktime, size, len(name))
    raw = body + name + b"\0" * (64 - len(name))
    assert len(raw) == 98, len(raw)
    return raw


def hexed(data):
    return data.hex()


# Each vector: (kind, input bytes, verdict, fields dict or None).
# Fields for OK: size, force, seq ("-" for ctx), ktime ("-" for ctx),
# namelen, name hex.
def build_vectors():
    vecs = []

    def ctx_vec(buf, verdict, **fields):
        vecs.append((KIND_CTX, buf, verdict, fields or None))

    def pay_vec(buf, verdict, **fields):
        vecs.append((KIND_PAYLOAD, buf, verdict, fields or None))

    name12 = b"0000:00:02.0"
    # 0: valid normal ctx.
    ctx_vec(ctx_fixed(41, 13) + name12 + b"\0", "OK",
            size=98, force=0, seq="-", ktime="-", namelen=12,
            name=hexed(name12))
    # 1: valid forced ctx, 63-byte name.
    name63 = b"D" * 63
    ctx_vec(ctx_fixed(41, 64, size=4096, force=1) + name63 + b"\0",
            "OK", size=4096, force=1, seq="-", ktime="-",
            namelen=63, name=hexed(name63))
    # 2: empty name.
    ctx_vec(ctx_fixed(41, 1, size=0) + b"\0", "OK",
            size=0, force=0, seq="-", ktime="-", namelen=0, name="")
    # 3-5: bad offsets.
    ctx_vec(ctx_fixed(0, 13) + name12 + b"\0", "CTX_LOC_OOB")
    ctx_vec(ctx_fixed(40, 13) + name12 + b"\0", "CTX_LOC_OOB")
    ctx_vec(ctx_fixed(41, 13) + name12, "CTX_LOC_OOB")  # truncated NUL
    # 6-7: bad dynamic lengths.
    ctx_vec(ctx_fixed(41, 0) + b"\0", "CTX_DLEN_ZERO")
    ctx_vec(ctx_fixed(41, 65) + b"E" * 64 + b"\0", "CTX_DLEN_BIG")
    # 8-9: NUL placement.
    ctx_vec(ctx_fixed(41, 64) + b"A" * 64, "CTX_NUL_MISSING")
    ctx_vec(ctx_fixed(41, 10) + b"ab\0defghij", "CTX_NUL_EARLY")
    # 10: bad force value.
    ctx_vec(ctx_fixed(41, 13, force=2) + name12 + b"\0",
            "CTX_FORCE_BAD")
    # 11: short context.
    ctx_vec(ctx_fixed(41, 13)[:20], "CTX_SHORT")
    # 12: string after a gap (off 48 is legal).
    ctx_vec(ctx_fixed(48, 13) + b"\0" * 7 + name12 + b"\0", "OK",
            size=98, force=0, seq="-", ktime="-", namelen=12,
            name=hexed(name12))
    # 13: non-UTF8 name bytes pass extraction untouched.
    raw13 = b"\xff\xfe\x41"
    ctx_vec(ctx_fixed(41, 4) + raw13 + b"\0", "OK",
            size=98, force=0, seq="-", ktime="-", namelen=3,
            name=hexed(raw13))
    # 14: max-u64 requested size.
    ctx_vec(ctx_fixed(41, 13, size=U64MAX) + name12 + b"\0", "OK",
            size=U64MAX, force=0, seq="-", ktime="-", namelen=12,
            name=hexed(name12))
    # 15-16: 512-byte read-cap boundary.
    ctx_vec(ctx_fixed(448, 64) + b"\0" * 407 + b"F" * 63 + b"\0",
            "OK", size=98, force=0, seq="-", ktime="-",
            namelen=63, name=hexed(b"F" * 63))
    ctx_vec(ctx_fixed(449, 64) + b"\0" * 408 + b"F" * 63 + b"\0",
            "CTX_LOC_OOB")
    # 17: valid normal payload.
    pay_vec(payload(), "OK", size=98, force=0, seq=7,
            ktime=123456789, namelen=12, name=hexed(name12))
    # 18: valid forced payload at max values.
    pay_vec(payload(version=1, flags=1, seq=U64MAX, ktime=U64MAX,
                    size=U64MAX, name=name63),
            "OK", size=U64MAX, force=1, seq=U64MAX, ktime=U64MAX,
            namelen=63, name=hexed(name63))
    # 19-20: bad lengths.
    pay_vec(payload()[:97], "PAY_SHORT")
    pay_vec(payload() + b"\0", "PAY_LONG")
    # 21-23: bad header fields.
    pay_vec(payload(magic=0x0), "PAY_MAGIC")
    pay_vec(payload(version=2), "PAY_VERSION")
    pay_vec(payload(flags=0x2), "PAY_FLAGS")
    # 24-27: bad name framing.
    bad = bytearray(payload())
    struct.pack_into("<H", bad, 32, 64)
    pay_vec(bytes(bad), "PAY_NAMELEN")
    bad = bytearray(payload())
    bad[34 + 12] = ord("X")
    pay_vec(bytes(bad), "PAY_NUL")
    bad = bytearray(payload())
    bad[34 + 3] = 0
    pay_vec(bytes(bad), "PAY_NUL")
    bad = bytearray(payload())
    bad[34 + 13] = 0xFF
    pay_vec(bytes(bad), "PAY_PAD")
    # 28-29: empty and non-UTF8 names decode fine.
    pay_vec(payload(name=b""), "OK", size=98, force=0, seq=7,
            ktime=123456789, namelen=0, name="")
    pay_vec(payload(name=raw13), "OK", size=98, force=0, seq=7,
            ktime=123456789, namelen=3, name=hexed(raw13))
    return vecs


def render(vecs):
    out_bin = [struct.pack("<I", len(vecs))]
    lines = ["# memveil attempts corpus v1"]
    for idx, (kind, buf, verdict, fields) in enumerate(vecs):
        out_bin.append(struct.pack("<II", kind, len(buf)))
        out_bin.append(buf)
        tag = "ctx" if kind == KIND_CTX else "payload"
        line = "%d %s %s" % (idx, tag, verdict)
        if fields is not None:
            line += (" size=%s force=%s seq=%s ktime=%s namelen=%s"
                     " name=%s") % (
                         fields["size"], fields["force"],
                         fields["seq"], fields["ktime"],
                         fields["namelen"], fields["name"])
        lines.append(line)
    return b"".join(out_bin), "\n".join(lines) + "\n"


def main(argv):
    vecs = build_vectors()
    blob, text = render(vecs)
    if len(argv) == 2 and argv[1] == "--check":
        with open(BIN_PATH, "rb") as handle:
            good_bin = handle.read()
        with open(TXT_PATH, "r", encoding="utf-8") as handle:
            good_txt = handle.read()
        if good_bin != blob or good_txt != text:
            print("corpus: committed outputs differ from the "
                  "generator; rerun gen_corpus.py", file=sys.stderr)
            return 1
        print("corpus: %d vectors byte-identical" % len(vecs))
        return 0
    if len(argv) != 1:
        print("usage: gen_corpus.py [--check]", file=sys.stderr)
        return 2
    with open(BIN_PATH, "wb") as handle:
        handle.write(blob)
    with open(TXT_PATH, "w", encoding="utf-8") as handle:
        handle.write(text)
    print("corpus: wrote %d vectors" % len(vecs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
