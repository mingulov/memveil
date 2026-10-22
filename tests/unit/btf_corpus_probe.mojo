# SPDX-License-Identifier: GPL-3.0-or-later

"""Raw-BTF corpus probe (K2 verification tool, not shipped).

Usage: btf_corpus_probe <btf-file>

Reads one raw BTF blob (header at zero, as in
/sys/kernel/btf/vmlinux) and prints machine-readable lines
for health, the seven reference layout fields, three extra
members, and the five hook signatures. The K2 report
compares these lines against the independent truth table.
"""

from std.sys import argv, exit

from memveil.platform.btf import (
    check_btf_health,
    read_btf_func_sig,
    resolve_btf_member,
)
from memveil.platform.reader import read_host_file


def _yn(v: Bool) -> String:
    if v:
        return String("1")
    return String("0")


def _member_line(
    data: Span[UInt8, _], tag: String, struct_name: String, field: String
) -> String:
    var r = resolve_btf_member(data, struct_name, field)
    return (
        tag
        + String(" ")
        + struct_name
        + String(".")
        + field
        + String(" ok=")
        + _yn(r.ok)
        + String(" bit_offset=")
        + String(r.bit_offset)
        + String(" bit_size=")
        + String(r.bit_size)
        + String(" kind=")
        + r.kind
        + String(" bitfield=")
        + _yn(r.bitfield)
        + String(" ambiguous=")
        + _yn(r.ambiguous)
        + String(" found=")
        + _yn(r.found)
        + String(" struct_found=")
        + _yn(r.struct_found)
    )


def _sig_line(data: Span[UInt8, _], name: String) -> String:
    var s = read_btf_func_sig(data, name)
    var params = String("")
    for i in range(len(s.params)):
        if i != 0:
            params += String(",")
        params += s.params[i]
    var widths = String("")
    for i in range(len(s.widths)):
        if i != 0:
            widths += String(",")
        widths += String(s.widths[i])
    return (
        String("sig ")
        + name
        + String(" ok=")
        + _yn(s.ok)
        + String(" ret=")
        + s.ret
        + String(" params=")
        + params
        + String(" widths=")
        + widths
        + String(" message=")
        + s.message
    )


def main() raises:
    var args = argv()
    if len(args) != 2:
        print("usage: btf_corpus_probe <btf-file>")
        exit(2)
    var raw = read_host_file(args[1], String("btf"), 67108864)
    var data = Span(raw)
    var health = check_btf_health(data)
    print(
        String("health ok=")
        + _yn(health.ok)
        + String(" code=")
        + health.code
    )
    var layouts = List[String]()
    layouts.append(String("io_tlb_pool start"))
    layouts.append(String("io_tlb_pool nslabs"))
    layouts.append(String("io_tlb_pool slots"))
    layouts.append(String("io_tlb_slot orig_addr"))
    layouts.append(String("io_tlb_slot alloc_size"))
    layouts.append(String("device_dma_parameters min_align_mask"))
    layouts.append(String("device dma_parms"))
    for i in range(len(layouts)):
        var parts = layouts[i].split(String(" "))
        print(
            _member_line(
                data,
                String("layout"),
                String(parts[0]),
                String(parts[1]),
            )
        )
    print(_member_line(data, String("extra"), String("device"), String("offline_disabled")))
    print(_member_line(data, String("extra"), String("page"), String("mapping")))
    print(_member_line(data, String("extra"), String("console"), String("flags")))
    var hooks = List[String]()
    hooks.append(String("swiotlb_tbl_map_single"))
    hooks.append(String("__swiotlb_tbl_unmap_single"))
    hooks.append(String("__swiotlb_sync_single_for_device"))
    hooks.append(String("__swiotlb_sync_single_for_cpu"))
    hooks.append(String("swiotlb_bounce"))
    for i in range(len(hooks)):
        print(_sig_line(data, hooks[i]))
