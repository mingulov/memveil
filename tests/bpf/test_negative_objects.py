#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Negative copy object checks (plain script, exit 0/1).

SYNTHETIC: four wrapper sources under tests/bpf/negative
include the product copy probe with one macro override each
(a renamed pool field, a widened local width, a doubled slot
count, a wrong hook argument count). They must refuse or
degrade, never misread.

BUILT: all four objects exist under build/bpf-negative.

RELOCATIONS: the renamed object relocates mvt_nslabs where
the product relocates nslabs and is otherwise identical;
the three guard-only variants keep the product records
exactly.

SECTIONS: for the three guard-only variants, each bounce
program section differs from the product while both sync
program sections are identical, so a no-op override fails.

COMPARES: the layout object compares the min_align_mask
field size against 8 where the product compares 4; the
argcnt object compares the bounce hook argument count
against 4 while the sync hooks still compare 5.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

NAMES = ("renamed_field", "widened_layout", "wrong_shift",
         "wrong_argcnt")
GUARD_NAMES = ("widened_layout", "wrong_shift", "wrong_argcnt")
BOUNCE_FUNCS = (("mv_bounce", "fentry/swiotlb_bounce"),
                ("mv_bounce_exit", "fexit/swiotlb_bounce"))
SYNC_FUNCS = (("mv_sync_device",
               "fentry/__swiotlb_sync_single_for_device"),
              ("mv_sync_cpu",
               "fentry/__swiotlb_sync_single_for_cpu"))

_LOAD_PAT = re.compile(
    r"^\s*[0-9a-f]+:[ \t]+[0-9a-f ]+[ \t]+r(\d+) = 0x4\s*$")
_CMP_PAT = re.compile(
    r"^\s*[0-9a-f]+:[ \t]+[0-9a-f ]+[ \t]+if w(\d+) != "
    r"0x([0-9a-f]+)")
_ARGCNT_CMP_PAT = re.compile(
    r"^\s*[0-9a-f]+:[ \t]+[0-9a-f ]+[ \t]+if r(\d+) == "
    r"0x([0-9a-f]+)")
_WRITE_PAT = re.compile(r"\b[wr](\d+)\s*[+\-*/|&^]?=(?!=)")


def repo_root():
    """Repository root above tests/bpf."""
    return os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run(cmd):
    """Run cmd; return (exit code, combined output)."""
    proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)
    return proc.returncode, proc.stdout


def fail(message):
    """Report one failure to stderr."""
    sys.stderr.write("negative-objects: FAIL %s\n" % message)
    return 1


def helper_ids(root):
    """Helper numbers from the pinned helper definitions."""
    path = os.path.join(root, "build", "deps", "include", "bpf",
                        "bpf_helper_defs.h")
    try:
        with open(path, "r") as handle:
            text = handle.read()
    except OSError:
        return None
    hit = re.search(r"\*\s*const\s+bpf_get_func_arg_cnt"
                    r"\)[^=]*=\s*\(void\s*\*\)\s*(\d+)", text)
    if not hit:
        return None
    return int(hit.group(1))


def negative_path(root, name):
    """Build output for one negative object."""
    return os.path.join(root, "build", "bpf-negative",
                        "swiotlb_copy-%s.bpf.o" % name)


def product_path(root):
    """Built product copy object."""
    return os.path.join(root, "build", "bpf",
                        "swiotlb_copy.bpf.o")


def section_text(obj, func, section):
    """Disassembly of one function, without the file header."""
    code, log = run(["llvm-objdump", "-d",
                     "--disassemble-symbols=" + func, obj])
    if code != 0:
        return None, "objdump failed on %s:\n%s" % (func, log)
    marker = "Disassembly of section %s:" % section
    if marker not in log:
        return None, "%s disassembled no %s" % (func, section)
    return log[log.index(marker):], None


def records_for(tool, obj):
    """Extractor records for one object, or (None, error)."""
    tmp = tempfile.mkdtemp(prefix="negative-reloc-")
    try:
        out_path = os.path.join(tmp, "reloc.json")
        code, log = run([tool, "--out", out_path, obj])
        if code != 0:
            return None, "extractor failed on %s:\n%s" % (
                os.path.basename(obj), log)
        with open(out_path, "r") as handle:
            got = json.load(handle)
        records = got.get("objects", {}).get(
            os.path.basename(obj))
        if records is None:
            return None, "no records for %s" % (
                os.path.basename(obj),)
        return records, None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_built(root):
    """All four negative objects exist."""
    for name in NAMES:
        if not os.path.isfile(negative_path(root, name)):
            return fail("missing %s (build first)" % (
                negative_path(root, name),))
    print("negative-objects: four objects built")
    return 0


def check_renamed(root, tool):
    """The renamed object relocates mvt_nslabs, nothing else."""
    renamed, err = records_for(
        tool, negative_path(root, "renamed_field"))
    if err is not None:
        return fail(err)
    product, err = records_for(tool, product_path(root))
    if err is not None:
        return fail(err)
    moved = [rec for rec in renamed
             if rec.get("member") == "mvt_nslabs"
             and rec.get("type") == "io_tlb_pool"]
    if not moved:
        return fail("no mvt_nslabs record on io_tlb_pool")
    stale = [rec for rec in renamed
             if rec.get("member") == "nslabs"]
    if stale:
        return fail("renamed object still relocates nslabs")
    restored = [dict(rec, member="nslabs")
                if rec.get("member") == "mvt_nslabs"
                else rec for rec in renamed]
    if restored != product:
        return fail("renamed records differ beyond nslabs:\n"
                    " got %r\nwant %r" % (restored, product))
    print("negative-objects: renamed relocation moved, rest equal")
    return 0


def check_guard_relocations(root, tool):
    """Guard-only variants keep the product records exactly."""
    product, err = records_for(tool, product_path(root))
    if err is not None:
        return fail(err)
    for name in GUARD_NAMES:
        records, err = records_for(
            tool, negative_path(root, name))
        if err is not None:
            return fail(err)
        if records != product:
            return fail("%s records differ:\n got %r\nwant %r"
                        % (name, records, product))
    print("negative-objects: guard variants keep relocations")
    return 0


def check_sections(root):
    """Bounce sections differ, sync sections are identical."""
    product = product_path(root)
    for name in GUARD_NAMES:
        obj = negative_path(root, name)
        for func, section in BOUNCE_FUNCS:
            want, err = section_text(product, func, section)
            if err is not None:
                return fail(err)
            got, err = section_text(obj, func, section)
            if err is not None:
                return fail(err)
            if got == want:
                return fail("%s %s identical to product "
                            "(override is a no-op)"
                            % (name, func))
        for func, section in SYNC_FUNCS:
            want, err = section_text(product, func, section)
            if err is not None:
                return fail(err)
            got, err = section_text(obj, func, section)
            if err is not None:
                return fail(err)
            if got != want:
                return fail("%s %s differs from product"
                            % (name, func))
    print("negative-objects: bounce differs, sync identical")
    return 0


def _following_compare(lines, i, reg, cmp_pat):
    """Compare immediate on reg up to two lines after i.

    Stops at any write to reg; the gap covers scheduler
    interleaving of unrelated stores. None when no such
    compare follows.
    """
    for j in (i + 1, i + 2):
        if j >= len(lines):
            return None
        hit = cmp_pat.match(lines[j])
        if hit and hit.group(1) == reg:
            return int(hit.group(2), 16)
        written = {m.group(1)
                   for m in _WRITE_PAT.finditer(lines[j])}
        if reg in written:
            return None
    return None


def width_pairs(text):
    """Compare immediates for each 4-width guard pair."""
    pairs = []
    lines = text.splitlines()
    for i in range(len(lines)):
        load = _LOAD_PAT.match(lines[i])
        if not load:
            continue
        imm = _following_compare(lines, i, load.group(1),
                                 _CMP_PAT)
        if imm is not None:
            pairs.append(imm)
    return pairs


def check_layout_eight(root):
    """The layout object compares the mask width against 8."""
    product = product_path(root)
    obj = negative_path(root, "widened_layout")
    for func, section in BOUNCE_FUNCS:
        want, err = section_text(product, func, section)
        if err is not None:
            return fail(err)
        pairs = width_pairs(want)
        if pairs != [4]:
            return fail("product %s width pairs %r, want [4]"
                        % (func, pairs))
        got, err = section_text(obj, func, section)
        if err is not None:
            return fail(err)
        pairs = width_pairs(got)
        if pairs != [8]:
            return fail("layout %s width pairs %r, want [8]"
                        % (func, pairs))
    print("negative-objects: layout compares 8, product 4")
    return 0


def argcnt_compares(text, helper_id):
    """Compare immediates after each argument-count call."""
    arg_pat = re.compile(r"call (0x%x|%d)\s*$"
                         % (helper_id, helper_id))
    out = []
    lines = text.splitlines()
    for i in range(len(lines)):
        if not arg_pat.search(lines[i]):
            continue
        imm = _following_compare(lines, i, "0",
                                 _ARGCNT_CMP_PAT)
        if imm is not None:
            out.append(imm)
    return out


def check_argcnt_four(root):
    """The argcnt object compares bounce counts against 4."""
    helper_id = helper_ids(root)
    if helper_id is None:
        return fail("cannot read helper ids")
    product = product_path(root)
    obj = negative_path(root, "wrong_argcnt")
    for func, section in BOUNCE_FUNCS:
        want, err = section_text(product, func, section)
        if err is not None:
            return fail(err)
        if argcnt_compares(want, helper_id) != [5]:
            return fail("product %s argcnt compare is not 5"
                        % func)
        got, err = section_text(obj, func, section)
        if err is not None:
            return fail(err)
        if argcnt_compares(got, helper_id) != [4]:
            return fail("argcnt %s argcnt compare is not 4"
                        % func)
    for func, section in SYNC_FUNCS:
        got, err = section_text(obj, func, section)
        if err is not None:
            return fail(err)
        if argcnt_compares(got, helper_id) != [5]:
            return fail("argcnt %s sync compare is not 5"
                        % func)
    print("negative-objects: argcnt compares 4, sync still 5")
    return 0


def check_product_unchanged(tool):
    """Tracked relocations still match the built objects."""
    code, log = run([tool, "--check"])
    if code != 0:
        return fail("product relocations changed:\n" + log)
    print("negative-objects: product relocations unchanged")
    return 0


def main():
    root = repo_root()
    tool = os.path.join(root, "tools", "emit-core-relocations")
    if not os.path.isfile(tool) or not os.access(tool, os.X_OK):
        return fail("tool missing: tools/emit-core-relocations")
    if check_built(root) != 0:
        return 1
    if check_renamed(root, tool) != 0:
        return 1
    if check_guard_relocations(root, tool) != 0:
        return 1
    if check_sections(root) != 0:
        return 1
    if check_layout_eight(root) != 0:
        return 1
    if check_argcnt_four(root) != 0:
        return 1
    if check_product_unchanged(tool) != 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
