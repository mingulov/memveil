#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Minimal ELF section reader shared by producer and proof."""

import struct


def elf_sections(path):
    """Map section name to raw bytes (64-bit EM_BPF only)."""
    with open(path, "rb") as handle:
        data = handle.read()
    if data[0:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("%s: not a 64-bit ELF" % path)
    if struct.unpack_from("<H", data, 18)[0] != 247:
        raise ValueError("%s: not EM_BPF" % path)
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsz, = struct.unpack_from("<H", data, 0x3a)
    shnum, = struct.unpack_from("<H", data, 0x3c)
    shstr, = struct.unpack_from("<H", data, 0x3e)
    so = shoff + shstr * shentsz
    stro, _ = struct.unpack_from("<QQ", data, so + 24)
    out = {}
    for i in range(shnum):
        name, _, _, _, off, size = struct.unpack_from(
            "<IIQQQQ", data, shoff + i * shentsz)
        end = data.index(b"\0", stro + name)
        out[data[stro + name:end].decode()] = \
            data[off:off + size]
    return out
