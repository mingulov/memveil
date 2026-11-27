#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Journal producer gates: the Aya program builds pinned and its wire
layout matches the carried header byte-for-byte.

This replaces the old host simulation run: instead of compiling the
retired C program, it checks the shippable Aya program compiles for
the BPF target under the repository pin and runs the host-side
differential (`producer_reference.py`). Real verifier/load/attach
stays lease-gated in the completion slice and is never attempted
here.
"""
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EBPF_MANIFEST = ROOT / "crates" / "ebpf" / "Cargo.toml"
EBPF_TOOLCHAIN = ROOT / "crates" / "ebpf" / "rust-toolchain.toml"
AYA_BIN = ROOT / "crates" / "ebpf" / "src" / "bin" / "conversion_journal.rs"
RETIRED_C = ROOT / "bpf" / "programs" / "conversion_journal.bpf.c"


def fail(message):
    print("test_producer: %s" % message, file=sys.stderr)
    sys.exit(1)


def pinned_channel():
    try:
        text = EBPF_TOOLCHAIN.read_text()
    except OSError as exc:
        fail("cannot read %s: %s" % (EBPF_TOOLCHAIN, exc))
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "channel":
            return value.strip().strip('"')
    fail("no channel pin in %s" % EBPF_TOOLCHAIN)


def main():
    if RETIRED_C.exists():
        fail("retired C producer must not be carried: %s" % RETIRED_C)
    if not AYA_BIN.is_file():
        fail("shippable Aya producer missing: %s" % AYA_BIN)
    manifest = EBPF_MANIFEST.read_text()
    bins = re.findall(r'\[\[bin\]\]\s*\nname = "([^"]+)"\s*\n'
                      r'path = "([^"]+)"', manifest)
    if ("memveil-ebpf-journal", "src/bin/conversion_journal.rs") not in bins:
        fail("Cargo.toml lacks the journal [[bin]] stanza")
    if len(bins) != 4:
        fail("expected exactly 4 [[bin]] stanzas, found %d" % len(bins))
    # Pinned BPF-target check (no link step, so no linker needed):
    # the workspace build links every bin for real through build.rs.
    channel = pinned_channel()
    with tempfile.TemporaryDirectory() as target:
        env = dict(os.environ)
        for knob in ("RUSTUP_TOOLCHAIN", "RUSTC", "RUSTC_WORKSPACE_WRAPPER",
                     "RUSTC_WRAPPER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
            env.pop(knob, None)
        try:
            proc = subprocess.run(
                ["rustup", "run", channel, "cargo", "check", "--locked",
                 "--manifest-path", str(EBPF_MANIFEST), "--target",
                 "bpfel-unknown-none", "-Z", "build-std=core",
                 "--target-dir", target],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=str(ROOT), env=env, timeout=900)
        except (OSError, subprocess.TimeoutExpired) as exc:
            fail("pinned BPF check failed to run: %s" % exc)
        if proc.returncode != 0:
            fail("pinned BPF check failed:\n%s" % proc.stderr[-4000:])
    reference = str(ROOT / "tests" / "journal" / "producer_reference.py")
    try:
        proc = subprocess.run([sys.executable, reference],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, cwd=str(ROOT), timeout=1200)
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail("producer reference failed to run: %s" % exc)
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        fail("producer reference differential failed")
    print("journal producer: Aya program builds pinned; wire differential green")


if __name__ == "__main__":
    main()
