#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host-side journal producer differential (replaces the old C simulation).

The old `producer.c` host simulation is NOT carried as C: the shippable
producer is the Aya program `crates/ebpf/src/bin/conversion_journal.rs`,
which cannot execute on the host. This module proves the next-best
offline facts instead:

1. Wire layout: every byte of the shared corpus is re-derived from the
   Aya program's documented layout constants and must equal the bytes
   the Rust capture path constructs (`tests/journal_producer.rs`
   `dump_wire_corpus`, run here via cargo).
2. Wire meaning: each corpus vector decodes under the carried-header C
   decoder (built with ASan/UBSan, like `test_wire.py`) with exactly
   the shared accept/refuse verdict.
3. Kernel-site inventory: the Aya source carries exactly the frozen
   producer surface -- four fentry/fexit hooks on the two conversion
   wrappers, the seven maps plus the host-resolved offset table, one
   bounded task-birth read, one bounded stack read, ring reserve and
   submit -- with no addresses, frames, or task names reaching the
   ring. Aya emits no field relocations, so the offset table (resolved
   from live BTF by the host, installed before attach) replaces the
   old CO-RE read; the inventory below pins that shape.
"""

import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AYA_BIN = ROOT / "crates" / "ebpf" / "src" / "bin" / "conversion_journal.rs"
HEADER = ROOT / "bpf" / "include" / "memveil_journal.h"

# MVJR v1 field layout per the carried header: (name, offset, struct
# format). The Aya program's constants must reproduce every offset.
FROZEN_FIELDS = (
    ("magic", 0, "<I"),
    ("version", 4, "<H"),
    ("kind", 6, "<H"),
    ("flags", 8, "<H"),
    ("direction", 10, "<H"),
    ("cpu", 12, "<I"),
    ("sequence", 16, "<Q"),
    ("exit_ns", 24, "<Q"),
    ("epoch", 32, "<Q"),
    ("token", 40, "<Q"),
    ("entry_ns", 48, "<Q"),
    ("pages", 56, "<i"),
    ("result", 60, "<i"),
    ("caller_status", 64, "<H"),
    ("caller_class", 66, "<H"),
    ("caller_label", 68, "<H"),
    ("reserved", 70, "<H"),
)
FROZEN_LEN = 72
FROZEN_MAGIC = 0x524A564D

# Corpus constructors shared with tests/journal_producer.rs: each
# entry names the mutations applied to the canonical matched record.
def _base():
    return dict(magic=FROZEN_MAGIC, version=1, kind=1, flags=1, direction=1,
                cpu=2, sequence=0, exit_ns=1100, epoch=1000, token=1,
                entry_ns=1050, pages=3, result=-5, caller_status=0,
                caller_class=0, caller_label=0, reserved=0)

CORPUS = (
    ("matched", True, {}),
    ("unmatched", True, {"flags": 0, "token": 0, "entry_ns": 0}),
    ("i32-extremes", True, {"pages": -2147483648, "result": 2147483647}),
    ("direction-2", True, {"direction": 2}),
    ("caller-triple", True, {"caller_status": 1, "caller_class": 2,
                             "caller_label": 6}),
    ("bad-magic", False, {"magic": 0}),
    ("truncated", False, {"truncate": 71}),
    ("token-ceiling", False, {"token": 2**64 - 1}),
    ("long-73", False, {"extend": 1}),
    ("label-overflow", False, {"caller_status": 1, "caller_class": 3,
                               "caller_label": 11}),
    ("label-class-mismatch", False, {"caller_status": 1, "caller_class": 2,
                                     "caller_label": 1}),
    ("unmatched-caller", True, {"flags": 0, "token": 0, "entry_ns": 0,
                                "caller_status": 1, "caller_class": 3,
                                "caller_label": 10}),
)


def fail(message):
    print("producer_reference: %s" % message, file=sys.stderr)
    sys.exit(1)


def aya_source():
    if not AYA_BIN.is_file():
        fail("shippable Aya producer missing: %s" % AYA_BIN)
    return AYA_BIN.read_text()


def cargo_env():
    # The repository pins its own toolchains (root 1.100.0 via
    # rust-toolchain.toml); a leaked ambient override would mix
    # compilers exactly like the E0514 nested-build skew, so the
    # child cargo runs without it.
    env = dict(os.environ)
    env.pop("RUSTUP_TOOLCHAIN", None)
    env.pop("RUSTC", None)
    env.pop("RUSTC_WORKSPACE_WRAPPER", None)
    env.pop("RUSTC_WRAPPER", None)
    return env


def rust_corpus():
    """{name: (accept, raw)} from the Rust suite's dump."""
    try:
        proc = subprocess.run(
            ["cargo", "test", "--locked", "--test", "journal_producer",
             "dump_wire_corpus", "--", "--exact", "--nocapture"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=str(ROOT), env=cargo_env(), timeout=900)
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail("cannot run the Rust corpus dump: %s" % exc)
    if proc.returncode != 0:
        fail("Rust corpus dump failed:\n%s" % proc.stderr[-4000:])
    out = {}
    for line in proc.stdout.splitlines():
        if not line.startswith("CORPUS "):
            continue
        parts = line.split(" ")
        if len(parts) != 4:
            fail("malformed corpus line: %r" % line)
        _, name, accept, hexed = parts
        try:
            raw = bytes.fromhex(hexed)
        except ValueError:
            fail("corpus %s is not hex" % name)
        out[name] = (accept == "1", raw)
    if sorted(out) != sorted(name for name, _, _ in CORPUS):
        fail("corpus names drifted: %s" % sorted(out))
    return out


def aya_layout(text):
    """{field: offset} plus the record length from the Aya source."""
    offsets = {}
    for name, _, _ in FROZEN_FIELDS:
        match = re.search(r"MV_JR_OFF_%s\s*:\s*usize\s*=\s*(\d+)"
                          % name.upper(), text)
        if not match:
            fail("Aya source lacks MV_JR_OFF_%s" % name.upper())
        offsets[name] = int(match.group(1))
    match = re.search(r"MV_JR_LEN\s*:\s*usize\s*=\s*(\d+)", text)
    if not match:
        fail("Aya source lacks MV_JR_LEN")
    return offsets, int(match.group(1))


def build_vectors(offsets):
    """Corpus bytes built at the Aya program's documented offsets."""
    out = {}
    for name, accept, changes in CORPUS:
        fields = _base()
        fields.update({k: v for k, v in changes.items()
                       if k not in ("truncate", "extend")})
        raw = bytearray(FROZEN_LEN)
        for field, _, fmt in FROZEN_FIELDS:
            struct.pack_into(fmt, raw, offsets[field], fields[field])
        if "truncate" in changes:
            del raw[changes["truncate"]:]
        if "extend" in changes:
            raw.extend(b"\0" * changes["extend"])
        out[name] = (accept, bytes(raw))
    return out


DECODE_C = '''#include <stdio.h>
#include "bpf/include/memveil_journal.h"
int main(void) {
    unsigned char b[73]; struct mv_journal out;
    size_t n = fread(b, 1, sizeof(b), stdin);
    int rc = mv_decode_journal(b, n, &out);
    if (rc != MV_OK) return 2;
    printf("%u %u %llu %llu %llu %llu %llu %d %d %u %u %u %u\\n",
           out.direction, out.cpu, (unsigned long long)out.sequence,
           (unsigned long long)out.exit_ns, (unsigned long long)out.epoch,
           (unsigned long long)out.token, (unsigned long long)out.entry_ns,
           out.pages, out.native_result, out.caller_status, out.caller_class,
           out.caller_label, out.matched);
    return 0;
}
'''


def check_decoder(vectors):
    """Every vector decodes under the carried header exactly as shared."""
    with tempfile.TemporaryDirectory() as temporary:
        tmp = Path(temporary)
        source = tmp / "decode.c"
        source.write_text(DECODE_C)
        binary = tmp / "decode"
        try:
            subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined",
                            "-I", str(ROOT), str(source), "-o", str(binary)],
                           check=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
        except (OSError, subprocess.CalledProcessError) as exc:
            fail("cannot build the carried-header decoder: %s" % exc)
        env = dict(os.environ, UBSAN_OPTIONS="halt_on_error=1")
        for name, accept, _ in CORPUS:
            raw = vectors[name][1]
            try:
                got = subprocess.run([str(binary)], input=raw,
                                     capture_output=True, env=env, timeout=60)
            except (OSError, subprocess.TimeoutExpired) as exc:
                fail("decoder run failed for %s: %s" % (name, exc))
            if not accept:
                if got.returncode != 2 or got.stdout or got.stderr:
                    fail("vector %s must refuse under the C decoder: %r"
                         % (name, got))
                continue
            if got.returncode != 0 or got.stderr:
                fail("vector %s must decode under the C decoder: %r"
                     % (name, got))
            fields = struct.unpack("<IHHHHIQQQQQiiHHHH", raw)
            order = [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 3]
            expected = (" ".join(str(fields[i]) for i in order) + "\n").encode()
            if got.stdout != expected:
                fail("vector %s decoded fields drifted: %r vs %r"
                     % (name, got.stdout, expected))


def check_layout(offsets, length):
    for name, want, _ in FROZEN_FIELDS:
        if offsets[name] != want:
            fail("Aya offset %s is %d, carried header says %d"
                 % (name, offsets[name], want))
    if length != FROZEN_LEN:
        fail("Aya record length is %d, carried header says %d"
             % (length, FROZEN_LEN))


def check_inventory(text):
    """The Aya source carries exactly the frozen producer surface."""
    hooks = re.findall(r"fn mv_jr_(dec|enc)_(enter|exit)\b", text)
    if sorted(hooks) != [("dec", "enter"), ("dec", "exit"),
                         ("enc", "enter"), ("enc", "exit")]:
        fail("hook set drifted: %r" % (hooks,))
    if len(re.findall(r"#\[fentry\(function = ", text)) != 2:
        fail("fentry attach sites are not exactly two")
    if len(re.findall(r"#\[fexit\(function = ", text)) != 2:
        fail("fexit attach sites are not exactly two")
    if "set_memory_decrypted" not in text or "set_memory_encrypted" not in text:
        fail("conversion wrapper targets missing")
    maps = re.findall(r"#\[map\(name = \"(mv_[a-z_]+)\"\)\]", text)
    if sorted(maps) != ["mv_journal", "mv_jr_control", "mv_jr_counts",
                        "mv_jr_offs", "mv_jr_ops", "mv_jr_sequence",
                        "mv_jr_symbols", "mv_jr_tasks"]:
        fail("map inventory drifted: %r" % (maps,))
    if text.count("PerCpuArray") < 1:
        fail("per-CPU sequence map missing")
    if text.count("bpf_get_current_task_btf(") != 1:
        fail("current-task read is not exactly one call site")
    if text.count("bpf_probe_read_kernel(") != 1:
        fail("task-birth read is not exactly one call site")
    if text.count("bpf_get_stack(") != 1:
        fail("bounded stack read is not exactly one call site")
    if text.count("reserve_bytes(") != 1:
        fail("ring reserve is not exactly one call site")
    if text.count(".submit(0)") != 1:
        fail("ring submit is not exactly one call site")
    if "BPF_NOEXIST" not in text:
        fail("existence-claimed pairing inserts missing")
    for token in ("NO_ADDRESSES", "NO_FRAMES", "NO_TASK_NAMES"):
        if token not in text:
            fail("emission ban marker %s missing" % token)
    for token in ("current_task_pointer", "start_boottime",
                  "memveil_journal_control.h"):
        if token not in text:
            fail("control-plane citation %s missing" % token)


def built_object():
    """Newest linked journal object under the workspace target dir."""
    cands = sorted(ROOT.glob("target/debug/build/memveil/*/out/ebpf-target/"
                             "bpfel-unknown-none/release/memveil-ebpf-journal"))
    cands += sorted(ROOT.glob("target/release/build/memveil/*/out/ebpf-target/"
                              "bpfel-unknown-none/release/memveil-ebpf-journal"))
    if not cands:
        fail("no built journal object; run cargo build first")
    return max(cands, key=lambda path: path.stat().st_mtime)


def elf_sections(path):
    """{name: bytes} for the 64-bit little-endian ELF at path."""
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        fail("%s is not a 64-bit little-endian ELF" % path)
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != 247:
        fail("%s has machine %d, want Linux BPF (247)" % (path, machine))
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    base = e_shoff + e_shstrndx * e_shentsize
    str_off, str_size = struct.unpack_from("<QQ", data, base + 24)
    names = data[str_off:str_off + str_size]
    out = {}
    for index in range(e_shnum):
        base = e_shoff + index * e_shentsize
        sh_name, = struct.unpack_from("<I", data, base)
        name = names[sh_name:].split(b"\0", 1)[0].decode("ascii", "replace")
        sh_offset, sh_size = struct.unpack_from("<QQ", data, base + 24)
        out[name] = data[sh_offset:sh_offset + sh_size]
    return out


def check_object():
    """Linked-object inventory: programs, marker, zero relocations."""
    sections = elf_sections(built_object())
    progs = sorted(name for name in sections
                   if name.startswith("fentry/") or name.startswith("fexit/"))
    if progs != ["fentry/set_memory_decrypted", "fentry/set_memory_encrypted",
                 "fexit/set_memory_decrypted", "fexit/set_memory_encrypted"]:
        fail("program sections drifted: %r" % (progs,))
    marker = sections.get("memveil_channel")
    if marker != b"memveil-channel:journal\0":
        fail("channel marker drifted: %r" % (marker,))
    ext = sections.get(".BTF.ext")
    if ext is None or len(ext) < 32:
        fail(".BTF.ext missing or truncated")
    magic, ver, _, hdr_len = struct.unpack_from("<HBBI", ext, 0)
    if magic != 0xEB9F or ver != 1 or hdr_len != 32:
        fail(".BTF.ext header drifted")
    relo_len = struct.unpack_from("<I", ext, 28)[0]
    if relo_len != 0:
        fail("core_relo subsection is %d bytes, want 0 (the offset "
             "table replaces field relocations)" % relo_len)


def main():
    text = aya_source()
    offsets, length = aya_layout(text)
    check_layout(offsets, length)
    check_inventory(text)
    check_object()
    derived = build_vectors(offsets)
    rust = rust_corpus()
    for name, accept, _ in CORPUS:
        want_accept, want_raw = rust[name]
        got_accept, got_raw = derived[name]
        if want_accept != accept or got_accept != accept:
            fail("verdict drift on %s" % name)
        if got_raw != want_raw:
            fail("byte drift on %s: Aya layout %s vs Rust capture %s"
                 % (name, got_raw.hex(), want_raw.hex()))
    check_decoder(derived)
    print("producer reference: 12 corpus vectors byte-identical "
          "(Aya layout vs Rust capture), C decoder agrees ASan/UBSan "
          "clean, linked object carries 4 programs + marker + zero "
          "relocations")


if __name__ == "__main__":
    main()