#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline proofs for the negative copy objects.

No boots, no privileged calls, no network. Each check compares a
staged mutant object against the base fixture
(`tests/vm/fixtures/aya/swiotlb_copy.bpf.o`) and the pinned
sources, using the local toolchain (llvm-objdump disassembly,
the loader's own aya-obj parser via the oracle crate, and a
small ELF/BTF reader). Run as a script (exit 0/1, one line per
check) or import the `check_*` functions from pytest.

Proof shape per mutant (mirrors the retired C negative test):
the surrounding Aya ABI stays intact (section set, declared
maps, program exact-set, sync programs, no CO-RE relocations)
while exactly the intended defect lands in the bounce path.
"""

import collections
import difflib
import json
import os
import re
import shutil
import struct
import subprocess
import sys

NAMES = ("renamed_field", "widened_layout",
         "wrong_shift", "wrong_argcnt")

BOUNCE = (("mv_bounce", "fentry/swiotlb_bounce"),
          ("mv_bounce_exit", "fexit/swiotlb_bounce"))
SYNC = (("mv_sync_device",
         "fentry/__swiotlb_sync_single_for_device"),
        ("mv_sync_cpu",
         "fentry/__swiotlb_sync_single_for_cpu"))

# Loader-frozen attach targets (src/bpf/attach.rs `copy_specs`):
# the positive control resolves each as a BTF FUNC.
FROZEN_TARGETS = ("swiotlb_bounce",
                  "__swiotlb_sync_single_for_device",
                  "__swiotlb_sync_single_for_cpu")

# Pinned scalar-deref neighborhoods in the renamed mutant
# (asm text, 6 insns before + the load + 2 after; derived from
# the pinned-recipe bytes, fail-closed on codegen drift). Each
# window visibly builds the dereferenced address from scalar
# stack spills (`+=`), never from a map value (r0) or the
# context: the kernel verifier rejects the load at PROG_LOAD.
RENAMED_WINDOW = {
    "mv_bounce": (
        "r1 = *(u64 *)(r10 - 0x70)",
        "r3 += r1",
        "r1 = *(u64 *)(r10 - 0x50)",
        "r9 += r1",
        "r1 = *(u64 *)(r10 - 0x30)",
        "*(u64 *)(r10 - 0x50) = r1",
        "r9 = *(u64 *)(r9 + 0x0)",
        "r1 = r10",
        "r1 += -0x30",
    ),
    "mv_bounce_exit": (
        "r1 = *(u64 *)(r10 - 0x80)",
        "r3 += r1",
        "r1 = *(u64 *)(r10 - 0x78)",
        "r6 += r1",
        "r1 = *(u64 *)(r10 - 0x30)",
        "*(u64 *)(r10 - 0x78) = r1",
        "r1 = *(u64 *)(r6 + 0x0)",
        "*(u64 *)(r10 - 0x50) = r1",
        "r1 = r10",
    ),
}

# Defect load triple per bounce function: (width, base reg,
# offset). The mutant carries exactly one more load of this
# triple than base; every other non-stack load triple keeps
# its count (destination-register renumbering inside a triple
# is neutral compiler ripple and is allowed).
RENAMED_TRIPLE = {
    "mv_bounce": ("u64", "r9", "0x0"),
    "mv_bounce_exit": ("u64", "r6", "0x0"),
}

_LOAD_RE = re.compile(
    r"(r\d+) = \*\(u(64|32|16|8) \*\)\(r(\d+) \+ (0x[0-9a-f]+)\)")


class ProofFailure(AssertionError):
    """One named proof leg failed."""


def repo_root():
    """Repository root above tests/vm/negatives."""
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))
    root = os.path.dirname(root)
    if not os.path.isfile(os.path.join(
            root, "crates", "ebpf", "Cargo.toml")):
        raise ProofFailure("cannot find repository root above "
                           + here)
    return root


def base_object(root):
    """Base fixture path (must exist)."""
    path = os.path.join(root, "tests", "vm", "fixtures",
                        "aya", "swiotlb_copy.bpf.o")
    if not os.path.isfile(path):
        raise ProofFailure("missing base fixture " + path)
    return path


def mutant_object(root, name):
    """Staged mutant path (must exist: build first)."""
    path = os.path.join(root, "build", "bpf-negative",
                        "swiotlb_copy-%s.bpf.o" % name)
    if not os.path.isfile(path):
        raise ProofFailure("missing %s (build first)" % path)
    return path


def mutant_source(root, name):
    """Staged mutant copy.rs (must exist: build first)."""
    path = os.path.join(root, "build", "bpf-negative", "src",
                        name, "ebpf", "src", "copy.rs")
    if not os.path.isfile(path):
        raise ProofFailure("missing %s (build first)" % path)
    return path


# -- ELF ------------------------------------------------------


def elf_sections(path):
    """Map section name to raw bytes."""
    with open(path, "rb") as handle:
        data = handle.read()
    if data[0:4] != b"\x7fELF" or data[4] != 2:
        raise ProofFailure("%s: not a 64-bit ELF" % path)
    if struct.unpack_from("<H", data, 18)[0] != 247:
        raise ProofFailure("%s: not EM_BPF" % path)
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


def elf_symbols(path):
    """Symtab rows: (name, type, bind, ndx, value, size)."""
    with open(path, "rb") as handle:
        data = handle.read()
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsz, = struct.unpack_from("<H", data, 0x3a)
    shnum, = struct.unpack_from("<H", data, 0x3c)
    shstr, = struct.unpack_from("<H", data, 0x3e)
    so = shoff + shstr * shentsz
    stro, _ = struct.unpack_from("<QQ", data, so + 24)

    def name_of(off):
        end = data.index(b"\0", stro + off)
        return data[stro + off:end].decode()
    symsec = strsec = None
    for i in range(shnum):
        name, stype, _, _, off, size = struct.unpack_from(
            "<IIQQQQ", data, shoff + i * shentsz)
        if name_of(name) == ".symtab":
            symsec = (off, size)
        if name_of(name) == ".strtab":
            strsec = (off, size)
    if symsec is None or strsec is None:
        raise ProofFailure("%s: no symtab" % path)
    rows = []
    for at in range(symsec[0], symsec[0] + symsec[1], 24):
        name, info, _, ndx, value, size = struct.unpack_from(
            "<IBBHQQ", data, at)
        end = data.index(b"\0", strsec[0] + name)
        rows.append((
            data[strsec[0] + name:end].decode(),
            info & 0xf, info >> 4, ndx, value, size))
    return [row for row in rows if row[0]]


def btf_ext_core_relo_len(sections):
    """BTF.ext core_relo record bytes (0 when CO-RE-free)."""
    ext = sections.get(".BTF.ext")
    if ext is None:
        raise ProofFailure("object has no .BTF.ext")
    magic, _, _, hdr = struct.unpack_from("<HBBI", ext, 0)
    if magic != 0xeb9f or hdr < 32:
        raise ProofFailure("bad .BTF.ext header")
    _, _, _, _, _, core_len = struct.unpack_from(
        "<IIIIII", ext, 8)
    return core_len


# -- disassembly ------------------------------------------------


def need_objdump():
    """llvm-objdump path, or fail closed."""
    path = shutil.which("llvm-objdump")
    if path is None:
        raise ProofFailure("llvm-objdump not on PATH (proof "
                           "tool required)")
    return path


def disasm(obj, func, section):
    """Disassembly body lines for one function."""
    proc = subprocess.run(
        [need_objdump(), "-d",
         "--disassemble-symbols=" + func, obj],
        capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise ProofFailure("objdump failed on %s" % func)
    marker = "Disassembly of section %s:" % section
    if marker not in proc.stdout:
        raise ProofFailure("%s disassembled no %s"
                           % (func, section))
    return proc.stdout.split(marker, 1)[1].splitlines()


def asm_text(line):
    """Last tab field: the bare instruction text."""
    return line.split("\t")[-1].strip()


def nonstack_loads(lines):
    """Non-stack loads as (dest, width, base, off) rows."""
    rows = []
    for line in lines:
        hit = _LOAD_RE.search(line)
        if hit and hit.group(3) != "10":
            rows.append((hit.group(1), "u" + hit.group(2),
                         "r" + hit.group(3), hit.group(4)))
    return rows


# -- ABI legs ---------------------------------------------------


def check_sections_identical(root, name):
    """Section-name set matches base exactly."""
    base = set(elf_sections(base_object(root)))
    mutant = set(elf_sections(mutant_object(root, name)))
    if base != mutant:
        raise ProofFailure(
            "%s: sections differ: only-base %s only-mutant %s"
            % (name, sorted(base - mutant),
               sorted(mutant - base)))
    return "section set identical (%d)" % len(base)


def check_maps_identical(root, name):
    """Declared maps identical: `maps` bytes plus symbols."""
    base = elf_sections(base_object(root))
    mutant = elf_sections(mutant_object(root, name))
    if base.get("maps") != mutant.get("maps"):
        raise ProofFailure("%s: maps section differs" % name)
    want = sorted(row for row in
                  elf_symbols(base_object(root))
                  if row[1] == 1)
    got = sorted(row for row in
                 elf_symbols(mutant_object(root, name))
                 if row[1] == 1)
    if want != got:
        raise ProofFailure("%s: object symbols differ:\n%r\n%r"
                           % (name, want, got))
    names = sorted(row[0] for row in want
                   if row[0].startswith("mv_"))
    if set(names) != {"mv_counts", "mv_claims", "mv_copy_fb",
                      "mv_copies", "mv_copy_offs"}:
        raise ProofFailure("%s: map set %r" % (name, names))
    return "maps identical (%s)" % ",".join(names)


def check_sync_identical(root, name):
    """Both sync program sections byte-identical to base."""
    base = elf_sections(base_object(root))
    mutant = elf_sections(mutant_object(root, name))
    for _, section in SYNC:
        if base.get(section) != mutant.get(section):
            raise ProofFailure("%s: %s differs from base"
                               % (name, section))
    funcs = {row[0]: row[5] for row in
             elf_symbols(base_object(root)) if row[1] == 2}
    mfuncs = {row[0]: row[5] for row in
              elf_symbols(mutant_object(root, name))
              if row[1] == 2}
    for func, _ in SYNC:
        if funcs.get(func) != mfuncs.get(func):
            raise ProofFailure("%s: %s size drifted"
                               % (name, func))
    return "sync programs identical"


def check_programs_exact(root, name):
    """Program exact-set: 4 names in their section kinds."""
    want = {func: section.split("/")[0]
            for func, section in BOUNCE + SYNC}
    base_funcs = sorted((row[0], row[3]) for row in
                       elf_symbols(base_object(root))
                       if row[1] == 2)
    mut_funcs = sorted((row[0], row[3]) for row in
                      elf_symbols(mutant_object(root, name))
                      if row[1] == 2)
    if base_funcs != mut_funcs:
        raise ProofFailure("%s: func symbols differ:\n%r\n%r"
                           % (name, base_funcs, mut_funcs))
    progs = oracle_judgment(
        root, [mutant_object(root, name)]
    )[mutant_object(root, name)]["programs"]
    got = {row["name"]: row["section"] for row in progs}
    if got != want:
        raise ProofFailure("%s: loader programs %r, want %r"
                           % (name, got, want))
    return "program exact-set holds"


def check_bounce_differs(root, name):
    """Both bounce sections differ (a no-op fails)."""
    base = elf_sections(base_object(root))
    mutant = elf_sections(mutant_object(root, name))
    for _, section in BOUNCE:
        if base.get(section) == mutant.get(section):
            raise ProofFailure("%s: %s identical to base "
                               "(mutation is a no-op)"
                               % (name, section))
    return "bounce programs differ"


def check_no_core_relocations(root, name):
    """Neither base nor mutant carries CO-RE relocations."""
    base_len = btf_ext_core_relo_len(
        elf_sections(base_object(root)))
    mutant_len = btf_ext_core_relo_len(
        elf_sections(mutant_object(root, name)))
    if base_len != 0 or mutant_len != 0:
        raise ProofFailure(
            "%s: core_relo bytes base=%d mutant=%d, want 0"
            % (name, base_len, mutant_len))
    return "no CO-RE relocations either side"


def check_no_path_leaks(root, name):
    """Object bytes carry no checkout/home/user paths."""
    with open(mutant_object(root, name), "rb") as handle:
        blob = handle.read()
    home = os.path.expanduser("~").encode()
    user = os.path.basename(os.path.expanduser("~")).encode()
    for needle, label in ((root.encode(), "checkout"),
                          (home, "home"), (user, "user")):
        if needle and needle in blob:
            raise ProofFailure("%s: bytes leak %s path"
                               % (name, label))
    return "no path leaks"


# -- oracle (loader's own parser) --------------------------------


def oracle_binary(root):
    """Build (if missing) and return the oracle binary."""
    here = os.path.dirname(os.path.abspath(__file__))
    binary = os.path.join(here, "oracle", "target", "release",
                          "negative-oracle")
    if os.path.isfile(binary):
        return binary
    if shutil.which("cargo") is None:
        raise ProofFailure("cargo not on PATH (oracle build "
                           "required)")
    proc = subprocess.run(
        ["cargo", "build", "--offline", "--release"],
        capture_output=True, text=True, timeout=600,
        cwd=os.path.join(here, "oracle"))
    if proc.returncode != 0 or not os.path.isfile(binary):
        raise ProofFailure("oracle build failed: %s"
                           % proc.stderr[-2000:])
    return binary


def oracle_judgment(root, paths):
    """Aya-obj parse per path (maps, programs, relocations)."""
    proc = subprocess.run(
        [oracle_binary(root)] + list(paths),
        capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise ProofFailure("oracle refused: %s"
                           % proc.stderr.strip())
    try:
        return json.loads(proc.stdout)
    except ValueError as exc:
        raise ProofFailure("oracle output unparsable: %s"
                           % exc)


def check_oracle_agrees(root, name):
    """Loader-parse maps/programs match base exactly."""
    base = base_object(root)
    mutant = mutant_object(root, name)
    got = oracle_judgment(root, [base, mutant])
    for key in ("maps", "programs", "btf_relocations"):
        if got[base][key] != got[mutant][key]:
            raise ProofFailure(
                "%s: oracle %s differs:\n%r\n%r"
                % (name, key, got[base][key],
                   got[mutant][key]))
    if got[base]["btf_relocations"]:
        raise ProofFailure("base carries BTF relocations")
    return "loader parse identical"


# -- defect legs --------------------------------------------------


def check_layout_eight(root):
    """Mask-width guard compares 8 where base compares 4."""
    name = "widened_layout"
    mutant = mutant_object(root, name)
    base = base_object(root)
    for func, section in BOUNCE:
        want = disasm(base, func, section)
        got = disasm(mutant, func, section)
        diff = [line for line in difflib.unified_diff(
            want, got, lineterm="")
            if line.startswith(("+", "-"))
            and not line.startswith(("+++", "---"))]
        if len(diff) != 2:
            raise ProofFailure(
                "%s %s: %d changed lines, want 2"
                % (name, func, len(diff)))
        minus, plus = diff
        expect = minus.replace("04 00 00 00", "08 00 00 00") \
            .replace("0x4 goto", "0x8 goto")
        if not minus.startswith("-") or not plus.startswith(
                "+") or expect[1:] != plus[1:]:
            raise ProofFailure(
                "%s %s: not a 4->8 immediate swap:\n%s\n%s"
                % (name, func, minus, plus))
        at = want.index(minus[1:])
        if not re.search(r"w1 = \*\(u32 \*\)\(r0 \+ 0x",
                         asm_text(want[at - 1])):
            raise ProofFailure(
                "%s %s: swap not on a table-width load"
                % (name, func))
    return "layout compares 8, base 4"


def check_argcnt_four(root):
    """Bounce argcnt compares 4; base and sync compare 5."""
    name = "wrong_argcnt"
    mutant = mutant_object(root, name)
    base = base_object(root)
    for func, section in BOUNCE:
        want = disasm(base, func, section)
        got = disasm(mutant, func, section)
        diff = [line for line in difflib.unified_diff(
            want, got, lineterm="")
            if line.startswith(("+", "-"))
            and not line.startswith(("+++", "---"))]
        if len(diff) != 2:
            raise ProofFailure(
                "%s %s: %d changed lines, want 2"
                % (name, func, len(diff)))
        minus, plus = diff
        expect = minus.replace("05 00 00 00", "04 00 00 00") \
            .replace("0x5 goto", "0x4 goto")
        if not minus.startswith("-") or not plus.startswith(
                "+") or expect[1:] != plus[1:]:
            raise ProofFailure(
                "%s %s: not a 5->4 immediate swap:\n%s\n%s"
                % (name, func, minus, plus))
        at = want.index(minus[1:])
        if asm_text(want[at - 1]) != "call 0xb9":
            raise ProofFailure(
                "%s %s: swap not on the arg-count call"
                % (name, func))
    for func, section in SYNC:
        lines = disasm(base, func, section)
        found = any(
            asm_text(line) == "call 0xb9"
            and re.search(r"if r0 != 0x5 goto",
                          asm_text(lines[i + 1]))
            for i, line in enumerate(lines[:-1]))
        if not found:
            raise ProofFailure("base %s: no argcnt-5 guard"
                               % func)
    return "bounce compares 4, sync still 5"


def check_shift_doubled(root):
    """Slot count doubled: span shift 0xb becomes 0xc."""
    name = "wrong_shift"
    mutant = mutant_object(root, name)
    base = base_object(root)
    for func, section in BOUNCE:
        want = "\n".join(disasm(base, func, section))
        got = "\n".join(disasm(mutant, func, section))

        def counts(text):
            return (
                len(re.findall(r"<<= 0x1\b", text)),
                len(re.findall(r"<<= 0xb\b", text)),
                len(re.findall(r"<<= 0xc\b", text)),
            )
        if counts(want) != (0, 1, 0):
            raise ProofFailure(
                "%s %s: base shifts %r, want (0, 1, 0)"
                % (name, func, counts(want)))
        if counts(got) != (1, 0, 1):
            raise ProofFailure(
                "%s %s: mutant shifts %r, want (1, 0, 1)"
                % (name, func, counts(got)))
    return "doubling shift plus span shift 0xc"


def check_renamed_deref(root):
    """One probe read becomes a scalar deref per bounce fn."""
    name = "renamed_field"
    mutant = mutant_object(root, name)
    base = base_object(root)
    for func, section in BOUNCE:
        want = disasm(base, func, section)
        got = disasm(mutant, func, section)
        calls = lambda lines: sum(
            1 for line in lines
            if asm_text(line) == "call 0x71")  # noqa: E731
        if calls(want) != 11 or calls(got) != 10:
            raise ProofFailure(
                "%s %s: probe reads base=%d mutant=%d, "
                "want 11/10" % (name, func, calls(want),
                                calls(got)))
        triples = lambda lines: collections.Counter(  # noqa: E731
            row[1:] for row in nonstack_loads(lines))
        base_t, mut_t = triples(want), triples(got)
        defect = RENAMED_TRIPLE[func]
        if mut_t.get(defect, 0) != \
                base_t.get(defect, 0) + 1:
            raise ProofFailure(
                "%s %s: defect triple %r counts base=%d "
                "mutant=%d, want +1"
                % (name, func, defect,
                   base_t.get(defect, 0),
                   mut_t.get(defect, 0)))
        for triple in set(base_t) | set(mut_t):
            if triple == defect:
                continue
            if base_t.get(triple, 0) != mut_t.get(triple, 0):
                raise ProofFailure(
                    "%s %s: triple %r counts base=%d "
                    "mutant=%d, want equal"
                    % (name, func, triple,
                       base_t.get(triple, 0),
                       mut_t.get(triple, 0)))
        width, reg, off = defect
        cands = [i for i, line in enumerate(got)
                 if asm_text(line)
                 == "%s = *(%s *)(%s + %s)"
                 % (asm_text(line).split(" = ")[0], width,
                    reg, off)]
        if not cands:
            raise ProofFailure("%s %s: defect load missing"
                               % (name, func))
        window = RENAMED_WINDOW[func]
        pinned = [i for i in cands
                  if [asm_text(line) for line in
                      got[i - 6:i + 3]] == list(window)]
        if len(pinned) != 1:
            raise ProofFailure(
                "%s %s: %d loads match the pinned window, "
                "want 1" % (name, func, len(pinned)))
    return "scalar deref replaces one probe read"


# -- source anchors -------------------------------------------------


def check_source_anchors(root, name):
    """Mutant source carries the marker plus its delta."""
    with open(mutant_source(root, name), "r",
              encoding="utf-8") as handle:
        text = handle.read()
    if "NEGATIVE (test-only, deterministic)" not in text:
        raise ProofFailure("%s: marker missing" % name)
    if name == "renamed_field":
        if "as *const u64).read()" not in text:
            raise ProofFailure("%s: direct read missing"
                               % name)
        if "let Ok(nslabs) = kread_u64" in text:
            raise ProofFailure("%s: base read survives"
                               % name)
        # Eight renamed bindings plus the marker's own mention.
        if len(re.findall(r"\bmvt_nslabs\b", text)) != 9:
            raise ProofFailure("%s: rename count drifted"
                               % name)
    elif name == "widened_layout":
        if "tab.mask_size != 8" not in text:
            raise ProofFailure("%s: width 8 missing" % name)
    elif name == "wrong_shift":
        if "nslabs.wrapping_mul(2)" not in text:
            raise ProofFailure("%s: doubling missing" % name)
    elif name == "wrong_argcnt":
        if "const MV_ARGS_BOUNCE: i64 = 4;" not in text:
            raise ProofFailure("%s: arity 4 missing" % name)
        if "const MV_ARGS_SYNC: i64 = 5;" not in text:
            raise ProofFailure("%s: sync arity moved" % name)
    return "source anchor holds"


# -- positive control -------------------------------------------------


def check_frozen_targets_resolve(root):
    """Loader's frozen targets resolve as BTF FUNCs (control).

    Skips when the host exposes no readable kernel BTF: the
    leg then proves nothing either way.
    """
    path = "/sys/kernel/btf/vmlinux"
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return "SKIP: no readable %s" % path
    magic, _, _, hdrlen, toff, tlen, soff, _ = \
        struct.unpack_from("<HBBIIIII", data, 0)
    if magic != 0xeb9f:
        return "SKIP: %s is not BTF" % path
    strs = data[hdrlen + soff:]
    found = {}
    pos = hdrlen + toff
    end = pos + tlen
    while pos < end:
        noff, info, _ = struct.unpack_from("<III", data, pos)
        kind = (info >> 24) & 0x1f
        vlen = info & 0xffff
        pos += 12
        if kind == 1:
            pos += 4
        elif kind == 3:
            pos += 12
        elif kind in (4, 5):
            pos += 12 * vlen
        elif kind == 6:
            pos += 8 * vlen
        elif kind == 13:
            pos += 8 * vlen
        elif kind == 14:
            pos += 4
        elif kind == 15:
            pos += 12 * vlen
        elif kind == 17:
            pos += 4
        elif kind == 19:
            pos += 12 * vlen
        if kind == 12:
            stop = strs.find(b"\0", noff)
            label = strs[noff:stop].decode()
            if label in FROZEN_TARGETS:
                found[label] = True
    missing = [target for target in FROZEN_TARGETS
               if target not in found]
    if missing:
        raise ProofFailure("frozen targets missing from BTF: "
                           + ",".join(missing))
    return "frozen targets resolve (%d)" % len(found)


PER_OBJECT_CHECKS = (
    ("sections", check_sections_identical),
    ("maps", check_maps_identical),
    ("sync", check_sync_identical),
    ("programs", check_programs_exact),
    ("bounce-differs", check_bounce_differs),
    ("no-core-relocations", check_no_core_relocations),
    ("no-path-leaks", check_no_path_leaks),
    ("oracle", check_oracle_agrees),
    ("source", check_source_anchors),
)

DEFECT_CHECKS = {
    "renamed_field": check_renamed_deref,
    "widened_layout": lambda root: check_layout_eight(root),
    "wrong_shift": lambda root: check_shift_doubled(root),
    "wrong_argcnt": lambda root: check_argcnt_four(root),
}


def prove_object(root, name):
    """Run every leg for one object; return detail lines."""
    lines = []
    for leg, func in PER_OBJECT_CHECKS:
        lines.append("%s[%s]: %s" % (name, leg,
                                     func(root, name)))
    lines.append("%s[defect]: %s"
                 % (name, DEFECT_CHECKS[name](root)))
    return lines


def main():
    """Prove all four objects; exit 0/1."""
    root = repo_root()
    try:
        print("negatives: control[%s]"
              % check_frozen_targets_resolve(root))
        for name in NAMES:
            for line in prove_object(root, name):
                print("negatives: " + line)
    except ProofFailure as exc:
        print("negatives: FAIL %s" % exc)
        return 1
    print("negatives: all proofs hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
