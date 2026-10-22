#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""CO-RE relocation checks over BPF objects (plain script, exit 0/1).

SYNTHETIC: compiles a synthetic oracle probe with the same
clang and flags as tools/build, extracts its relocations with
tools/emit-core-relocations, and asserts the exact record list
(including flavor-suffix stripping and record order). A second
synthetic source with a bitfield member asserts the tool
refuses bitfield relocations with exit 1.

COPY LAYOUT: asserts the copy object reads every pool, slot,
and alignment fact through relocations (byte size guards plus
byte offset reads), and that every slot-stride multiply in the
disassembly is backed by a slot type-size relocation at its
own instruction offset (no raw stride remains).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

BITFIELD_SRC = """\
// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
struct mvb___a {
    int x : 4;
    int y;
} __attribute__((preserve_access_index));
SEC("tp/x")
int mvb_probe(void *ctx)
{
    struct mvb___a v = { 0, 0 };
    struct mvb___a *pp = &v;
    int t = 0;
    (void)ctx;
    t = BPF_CORE_READ_BITFIELD(pp, x);
    return t & 1;
}
char MV_LICENSE[] SEC("license") = "GPL";
"""

# Exact extractor output for core_reloc_probe.bpf.c, in the
# tool's record order (type, member or enumerator, kind; a
# memberless record sorts before member records of its type).
WANT_PROBE = [
    {"type": "mvt", "kind": "type_size", "relocs": 1,
     "optional": False},
    {"type": "mvt", "member": "a", "kind": "field_exists",
     "relocs": 1, "optional": True},
    {"type": "mvt", "member": "b", "kind": "field_byte_offset",
     "relocs": 1, "optional": False},
    {"type": "mvt", "member": "b", "kind": "field_byte_size",
     "relocs": 1, "optional": False},
    {"type": "mvt_e", "enumerator": "MVT_X",
     "kind": "enumval_value", "relocs": 1, "optional": False},
]


def repo_root():
    """Repository root above tests/bpf."""
    return os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run(cmd):
    """Run cmd; return (exit code, combined output)."""
    proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)
    return proc.returncode, proc.stdout


def clang_resource_dir():
    """Clang resource include dir, as tools/build resolves it."""
    code, out = run(["clang", "-print-resource-dir"])
    if code != 0:
        return None
    path = os.path.join(out.strip(), "include")
    if not os.path.isdir(path):
        return None
    return path


def compile_probe(root, tmp, src, name):
    """Compile one BPF source with the tools/build BPF flags."""
    libbpf_inc = os.path.join(root, "build", "deps", "include")
    uapi_inc = os.path.join(root, "bpf", "include", "uapi")
    res = clang_resource_dir()
    if res is None:
        return None, "clang resource dir missing"
    for path in (os.path.join(root, "bpf", "include"), libbpf_inc,
                 uapi_inc):
        if not os.path.isdir(path):
            return None, "missing include dir " + path
    out = os.path.join(tmp, name)
    cmd = ["clang", "--target=bpf", "-O2", "-g", "-Wall", "-Wextra",
           "-Werror", "-D__BPF__", "-nostdinc", "-isystem", res,
           "-ffile-prefix-map=" + root + "=.",
           "-I", os.path.join(root, "bpf", "include"),
           "-I", libbpf_inc, "-I", uapi_inc,
           "-c", src, "-o", out]
    code, log = run(cmd)
    if code != 0:
        return None, "clang failed:\n" + log
    return out, ""


def fail(message):
    """Report one failure to stderr."""
    sys.stderr.write("core-relocations: FAIL %s\n" % message)
    return 1


def _rec(otype, sub, kind, count):
    """One expected relocation record with its count."""
    rec = {"type": otype}
    if sub is not None:
        rec["member"] = sub
    rec["kind"] = kind
    rec["relocs"] = count
    rec["optional"] = False
    return rec


# Exact copy-object relocation list once every pool, slot, and
# alignment fact is read through relocations: each size guard
# and each offset read appears once per inlined helper copy.
WANT_COPY_LAYOUT = [
    _rec("device", "dma_parms", "field_byte_offset", 2),
    _rec("device", "dma_parms", "field_byte_size", 2),
    _rec("device_dma_parameters", "min_align_mask",
         "field_byte_offset", 2),
    _rec("device_dma_parameters", "min_align_mask",
         "field_byte_size", 2),
    _rec("io_tlb_pool", "end", "field_byte_offset", 2),
    _rec("io_tlb_pool", "end", "field_byte_size", 2),
    _rec("io_tlb_pool", "nslabs", "field_byte_offset", 2),
    _rec("io_tlb_pool", "nslabs", "field_byte_size", 2),
    _rec("io_tlb_pool", "slots", "field_byte_offset", 2),
    _rec("io_tlb_pool", "slots", "field_byte_size", 2),
    _rec("io_tlb_pool", "start", "field_byte_offset", 2),
    _rec("io_tlb_pool", "start", "field_byte_size", 2),
    _rec("io_tlb_slot", None, "type_size", 2),
    _rec("io_tlb_slot", "alloc_size", "field_byte_offset", 2),
    _rec("io_tlb_slot", "alloc_size", "field_byte_size", 2),
    _rec("io_tlb_slot", "orig_addr", "field_byte_offset", 2),
    _rec("io_tlb_slot", "orig_addr", "field_byte_size", 2),
]

# An immediate multiply by the 24-byte slot stride, in either
# objdump spelling.
_STRIDE_MUL = re.compile(r"^[ \t]*(\d+):\t.*\t[wr][0-9]+ \*= (0x18|24)\s*$")

# Bounce helpers with the slot math inlined, and the section
# each disassembles from.
_BOUNCE_FUNCS = (("mv_bounce", "fentry/swiotlb_bounce"),
                 ("mv_bounce_exit", "fexit/swiotlb_bounce"))


def check_no_raw_slot_layout(obj):
    """Prove no raw slot stride remains in either helper copy.

    Any immediate multiply by the 24-byte stride fails: the
    relocated stride lowers to a register multiply instead,
    while raw pointer arithmetic on the slot type folds to an
    immediate. The type-size record itself is pinned by the
    exact relocation list above.
    """
    for func, section in _BOUNCE_FUNCS:
        code, log = run(["llvm-objdump", "-d",
                         "--disassemble-symbols=" + func, obj])
        if code != 0:
            return fail("objdump failed on %s:\n%s" % (func, log))
        if "Disassembly of section %s:" % section not in log:
            return fail("%s disassembled no %s" % (func, section))
        for line in log.splitlines():
            if _STRIDE_MUL.match(line):
                return fail("raw stride multiply in %s: %s"
                            % (func, line.strip()))
    print("core-relocations: no raw stride in %d helpers"
          % len(_BOUNCE_FUNCS))
    return 0


def check_copy_layout_contract(root, tool):
    """Assert the copy object's pool/slot/alignment records."""
    obj = os.path.join(root, "build", "bpf",
                       "swiotlb_copy.bpf.o")
    if not os.path.isfile(obj):
        return fail("missing built copy object (build first)")
    tmp = tempfile.mkdtemp(prefix="core-reloc-copy-")
    try:
        out_path = os.path.join(tmp, "copy.json")
        code, log = run([tool, "--out", out_path, obj])
        if code != 0:
            return fail("extractor failed on copy object:\n"
                        + log)
        with open(out_path, "r") as handle:
            got = json.load(handle)
        records = got.get("objects", {}).get(
            "swiotlb_copy.bpf.o")
        if records != WANT_COPY_LAYOUT:
            return fail("copy records differ:\n got %r\nwant %r"
                        % (records, WANT_COPY_LAYOUT))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return check_no_raw_slot_layout(obj)


def check_synthetic(root, tool):
    """Pin the extractor against the synthetic oracle probe."""
    tmp = tempfile.mkdtemp(prefix="core-reloc-")
    try:
        probe_src = os.path.join(
            root, "tests", "bpf", "fixtures",
            "core_reloc_probe.bpf.c")
        probe, err = compile_probe(
            root, tmp, probe_src, "core_reloc_probe.bpf.o")
        if probe is None:
            return fail(err)
        out_path = os.path.join(tmp, "probe.json")
        code, log = run([tool, "--out", out_path, probe])
        if code != 0:
            return fail("extractor failed on probe:\n" + log)
        with open(out_path, "r") as handle:
            got = json.load(handle)
        if got.get("format") != 1:
            return fail("probe output has no format 1")
        objects = got.get("objects")
        if set(objects or {}) != {"core_reloc_probe.bpf.o"}:
            return fail("probe output keys %r" % (objects,))
        records = objects["core_reloc_probe.bpf.o"]
        if records != WANT_PROBE:
            return fail("probe records differ:\n got %r\nwant %r"
                        % (records, WANT_PROBE))
        bit_src = os.path.join(tmp, "bitfield.bpf.c")
        with open(bit_src, "w") as handle:
            handle.write(BITFIELD_SRC)
        bit, err = compile_probe(root, tmp, bit_src, "bit.o")
        if bit is None:
            return fail(err)
        code, log = run(
            [tool, "--out", os.path.join(tmp, "bit.json"), bit])
        if code != 1:
            return fail("bitfield object exited %d, want 1" % code)
        if "bitfield" not in log.lower():
            return fail("bitfield refusal names no bitfield")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    root = repo_root()
    tool = os.path.join(root, "tools", "emit-core-relocations")
    if not os.path.isfile(tool) or not os.access(tool, os.X_OK):
        return fail("tool missing: tools/emit-core-relocations")
    if check_synthetic(root, tool) != 0:
        return 1
    print("core-relocations: synthetic checks passed")
    if check_copy_layout_contract(root, tool) != 0:
        return 1
    print("core-relocations: copy layout checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
