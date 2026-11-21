#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage release docs from the built binary for packaging.

Runs the sibling generators against one memveil binary and
stages their outputs for the packaging scripts to embed:

  OUT/man/          memveil.1 plus one memveil-<verb>.1
  OUT/completions/  memveil (bash) and _memveil (zsh)

Usage: scripts/gen-docs.py --out DIR [--binary PATH] [--build]
  --out DIR      staging directory (required)
  --binary PATH  memveil binary to query (default: the
                 release binary beside the sources)
  --build        run `cargo build --release --locked
                 --offline` first (repository pin wins)

The default binary is `<root>/target/release/memveil`, or
`$CARGO_TARGET_DIR/release/memveil` when that variable is
set. Without --build the binary must already exist: the
driver fails closed naming `cargo build --release` rather
than querying a stale or missing binary. --build refreshes
only that default target-dir binary; an explicit --binary
PATH is queried as-is, so combine --build with --binary
only when PATH already holds a fresh build.
"""

import os
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(HERE)


def fail(message):
    print("gen-docs: %s" % message, file=sys.stderr)
    sys.exit(1)


def default_binary():
    target = os.environ.get("CARGO_TARGET_DIR") or os.path.join(
        ROOT_DIR, "target")
    return os.path.join(target, "release", "memveil")


def remap_build_paths(env):
    """Append path remaps so the built binary names no build machine.

    Home directory first, then the checkout root last, so
    checkout paths land under /build-root (the same pair the
    packager and the BPF build script apply). The binary
    lands on the default packaging input path, so it must be
    shippable as-is. Extends the encoded flags: that spelling
    wins over RUSTFLAGS when both reach cargo, so merge
    RUSTFLAGS in and drop it rather than clobber it. A
    missing or empty HOME contributes no remap.
    """
    flags = []
    encoded = env.get("CARGO_ENCODED_RUSTFLAGS", "")
    if encoded:
        flags.extend(flag for flag in encoded.split("\x1f")
                     if flag)
    rustflags = env.get("RUSTFLAGS", "")
    if rustflags:
        try:
            flags.extend(shlex.split(rustflags))
        except ValueError as exc:
            fail("cannot parse RUSTFLAGS: %s" % exc)
    home = env.get("HOME", "")
    if home:
        flags.append("--remap-path-prefix=%s=/build-prefix" % home)
    flags.append("--remap-path-prefix=%s=/build-root"
                 % os.path.abspath(ROOT_DIR))
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
    env.pop("RUSTFLAGS", None)


def run(argv):
    try:
        proc = subprocess.run(argv)
    except OSError as err:
        fail("cannot run %s: %s" % (" ".join(argv), err))
    if proc.returncode != 0:
        fail("%s exits %d" % (" ".join(argv), proc.returncode))


def main(argv):
    binary = None
    out_dir = None
    build = False
    args = list(argv)
    while args:
        opt = args.pop(0)
        if opt in ("--help", "-h"):
            print(__doc__)
            return 0
        if opt == "--binary" and args:
            binary = args.pop(0)
            continue
        if opt == "--out" and args:
            out_dir = args.pop(0)
            continue
        if opt == "--build":
            build = True
            continue
        fail("unknown option: %s" % opt)
    if not out_dir:
        fail("--out DIR is required")
    if build:
        # Mirror the tarball build: locked + offline, with the
        # ambient RUSTUP_TOOLCHAIN stripped so the repository
        # pin wins, and build-machine paths remapped out of
        # the binary, which lands on the default packaging
        # input path.
        env = dict(os.environ)
        env.pop("RUSTUP_TOOLCHAIN", None)
        remap_build_paths(env)
        try:
            proc = subprocess.run(
                ["cargo", "build", "--release", "--locked",
                 "--offline"], cwd=ROOT_DIR, env=env)
        except OSError as err:
            fail("cannot run cargo build --release: %s" % err)
        if proc.returncode != 0:
            fail("cargo build --release exits %d" % proc.returncode)
    if binary is None:
        binary = default_binary()
    if not os.path.isfile(binary):
        fail("binary is not a file: %s (run cargo build --release,"
             " or pass --build)" % binary)
    os.makedirs(out_dir, exist_ok=True)
    run([sys.executable, os.path.join(HERE, "gen-man.py"),
         "--binary", binary, "--out",
         os.path.join(out_dir, "man")])
    run([sys.executable, os.path.join(HERE, "gen-completions.py"),
         "--out", os.path.join(out_dir, "completions")])
    print("gen-docs: staged -> %s" % out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
