#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""CO-RE relocation checks over BPF objects (plain script, exit 0/1).

SYNTHETIC: compiles a synthetic oracle probe with the same
clang and flags as tools/build, extracts its relocations with
tools/emit-core-relocations, and asserts the exact record list
(including flavor-suffix stripping and record order). A second
synthetic source with a bitfield member asserts the tool
refuses bitfield relocations with exit 1.
"""

import json
import os
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
