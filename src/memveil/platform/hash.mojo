# SPDX-License-Identifier: GPL-3.0-or-later

"""SHA-256 over bytes (narrow identity bindings).

Pure Mojo, no dependencies: the standard FIPS 180-4
compression function with wrapping UInt32 arithmetic.
Used to hash kernel config bytes, BTF, hook format
text, the BPF object, and the boot image for narrow
identity binding checks.
"""

from memveil.capture.normalize import bytes_to_hex


def _rotr(x: UInt32, n: UInt32) -> UInt32:
    return (x >> n) | (x << (UInt32(32) - n))


def _sha256_block(mut h: Array[UInt32, 8], data: Span[UInt8, _], base: Int):
    """Compress the 64 bytes at base into the running state."""
    var k = [
        UInt32(0x428A2F98), UInt32(0x71374491), UInt32(0xB5C0FBCF),
        UInt32(0xE9B5DBA5), UInt32(0x3956C25B), UInt32(0x59F111F1),
        UInt32(0x923F82A4), UInt32(0xAB1C5ED5), UInt32(0xD807AA98),
        UInt32(0x12835B01), UInt32(0x243185BE), UInt32(0x550C7DC3),
        UInt32(0x72BE5D74), UInt32(0x80DEB1FE), UInt32(0x9BDC06A7),
        UInt32(0xC19BF174), UInt32(0xE49B69C1), UInt32(0xEFBE4786),
        UInt32(0x0FC19DC6), UInt32(0x240CA1CC), UInt32(0x2DE92C6F),
        UInt32(0x4A7484AA), UInt32(0x5CB0A9DC), UInt32(0x76F988DA),
        UInt32(0x983E5152), UInt32(0xA831C66D), UInt32(0xB00327C8),
        UInt32(0xBF597FC7), UInt32(0xC6E00BF3), UInt32(0xD5A79147),
        UInt32(0x06CA6351), UInt32(0x14292967), UInt32(0x27B70A85),
        UInt32(0x2E1B2138), UInt32(0x4D2C6DFC), UInt32(0x53380D13),
        UInt32(0x650A7354), UInt32(0x766A0ABB), UInt32(0x81C2C92E),
        UInt32(0x92722C85), UInt32(0xA2BFE8A1), UInt32(0xA81A664B),
        UInt32(0xC24B8B70), UInt32(0xC76C51A3), UInt32(0xD192E819),
        UInt32(0xD6990624), UInt32(0xF40E3585), UInt32(0x106AA070),
        UInt32(0x19A4C116), UInt32(0x1E376C08), UInt32(0x2748774C),
        UInt32(0x34B0BCB5), UInt32(0x391C0CB3), UInt32(0x4ED8AA4A),
        UInt32(0x5B9CCA4F), UInt32(0x682E6FF3), UInt32(0x748F82EE),
        UInt32(0x78A5636F), UInt32(0x84C87814), UInt32(0x8CC70208),
        UInt32(0x90BEFFFA), UInt32(0xA4506CEB), UInt32(0xBEF9A3F7),
        UInt32(0xC67178F2),
    ]
    var w = Array[UInt32, 64](fill=UInt32(0))
    for i in range(16):
        var o = base + 4 * i
        w[i] = (
            (UInt32(data[o]) << 24)
            | (UInt32(data[o + 1]) << 16)
            | (UInt32(data[o + 2]) << 8)
            | UInt32(data[o + 3])
        )
    for i in range(16, 64):
        var s0 = (
            _rotr(w[i - 15], UInt32(7))
            ^ _rotr(w[i - 15], UInt32(18))
            ^ (w[i - 15] >> 3)
        )
        var s1 = (
            _rotr(w[i - 2], UInt32(17))
            ^ _rotr(w[i - 2], UInt32(19))
            ^ (w[i - 2] >> 10)
        )
        w[i] = w[i - 16] + s0 + w[i - 7] + s1
    var a = h[0]
    var b = h[1]
    var c = h[2]
    var d = h[3]
    var e = h[4]
    var f = h[5]
    var g = h[6]
    var hh = h[7]
    for i in range(64):
        var big_s1 = (
            _rotr(e, UInt32(6))
            ^ _rotr(e, UInt32(11))
            ^ _rotr(e, UInt32(25))
        )
        var ch = (e & f) ^ ((~e) & g)
        var t1 = hh + big_s1 + ch + k[i] + w[i]
        var big_s0 = (
            _rotr(a, UInt32(2))
            ^ _rotr(a, UInt32(13))
            ^ _rotr(a, UInt32(22))
        )
        var maj = (a & b) ^ (a & c) ^ (b & c)
        var t2 = big_s0 + maj
        hh = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    h[0] = h[0] + a
    h[1] = h[1] + b
    h[2] = h[2] + c
    h[3] = h[3] + d
    h[4] = h[4] + e
    h[5] = h[5] + f
    h[6] = h[6] + g
    h[7] = h[7] + hh


def sha256_hex(data: Span[UInt8, _]) -> String:
    """SHA-256 digest of data as 64 lowercase hex chars."""
    var h = Array[UInt32, 8](fill=UInt32(0))
    h[0] = UInt32(0x6A09E667)
    h[1] = UInt32(0xBB67AE85)
    h[2] = UInt32(0x3C6EF372)
    h[3] = UInt32(0xA54FF53A)
    h[4] = UInt32(0x510E527F)
    h[5] = UInt32(0x9B05688C)
    h[6] = UInt32(0x1F83D9AB)
    h[7] = UInt32(0x5BE0CD19)
    var total = len(data)
    var full = total // 64
    for bi in range(full):
        _sha256_block(h, data, bi * 64)
    var tail = List[UInt8]()
    for i in range(full * 64, total):
        tail.append(data[i])
    tail.append(UInt8(0x80))
    while len(tail) % 64 != 56:
        tail.append(UInt8(0))
    var bits = UInt64(total) * UInt64(8)
    for i in range(8):
        var shift = UInt64(8 * (7 - i))
        tail.append(UInt8((bits >> shift) & UInt64(0xFF)))
    var padded = Span(tail)
    var nblocks = len(tail) // 64
    for bi in range(nblocks):
        _sha256_block(h, padded, bi * 64)
    var digest = List[UInt8]()
    for i in range(8):
        digest.append(UInt8((h[i] >> 24) & UInt32(0xFF)))
        digest.append(UInt8((h[i] >> 16) & UInt32(0xFF)))
        digest.append(UInt8((h[i] >> 8) & UInt32(0xFF)))
        digest.append(UInt8(h[i] & UInt32(0xFF)))
    return bytes_to_hex(digest)
