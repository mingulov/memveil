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
import subprocess
import sys
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(HERE)


def fail(message):
    print("gen-docs: %s" % message, file=sys.stderr)
    sys.exit(1)


def default_binary():
    target = os.environ.get("CARGO_TARGET_DIR") or os.path.join(
        ROOT_DIR, "target")
    return os.path.join(target, "release", "memveil")


def config_file_rustflags(path):
    """build.rustflags from one Cargo config file, else None.

    A string value splits on whitespace (Cargo keeps
    quotes literal); an array passes through verbatim.
    Fails closed on anything this reader cannot reproduce
    exactly: an include list, target-specific rustflags
    (those shadow build.rustflags), or a mistyped value.
    """
    try:
        with open(path, "rb") as handle:
            doc = tomllib.load(handle)
    except OSError as exc:
        fail("cannot read cargo config %s: %s" % (path, exc))
    except tomllib.TOMLDecodeError as exc:
        fail("cannot parse cargo config %s: %s" % (path, exc))
    if "include" in doc:
        fail("cargo config %s uses include: pass its flags "
             "through RUSTFLAGS instead" % path)
    target = doc.get("target")
    if target is not None:
        if not isinstance(target, dict):
            fail("cargo config %s has a non-table target"
                 % path)
        for table in target.values():
            if isinstance(table, dict) and "rustflags" in table:
                fail("cargo config %s sets target rustflags: "
                     "pass its flags through RUSTFLAGS instead"
                     % path)
    build = doc.get("build")
    if build is None:
        return None
    if not isinstance(build, dict):
        fail("cargo config %s has a non-table build" % path)
    if "rustflags" not in build:
        return None
    value = build["rustflags"]
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list) \
            and all(isinstance(item, str) for item in value):
        return list(value)
    fail("cargo config %s has a non-string build.rustflags"
         % path)


def config_layer_rustflags(build_dir, env):
    """Config-layer flags for a build with no channel set.

    Only consulted when neither CARGO_ENCODED_RUSTFLAGS nor
    RUSTFLAGS is set: Cargo checks the encoded spelling,
    then RUSTFLAGS, then the config layer, and a set-but-
    empty channel still shadows everything below it. Joins
    the home config first, then each ancestor config down
    to the build directory, then CARGO_BUILD_RUSTFLAGS
    last; at one directory the extensionless config wins
    over config.toml for the key. Fails closed rather than
    shadowing flags it cannot see.
    """
    for name in env:
        if name.startswith("CARGO_TARGET_") \
                and name.endswith("_RUSTFLAGS") \
                and len(name) > len("CARGO_TARGET__RUSTFLAGS"):
            fail("%s sets target rustflags: pass its flags "
                 "through RUSTFLAGS instead" % name)
    home = env.get("CARGO_HOME")
    if home is None:
        parent = env.get("HOME", "")
        home = os.path.join(parent, ".cargo") if parent else ""
    if home and not os.path.isabs(home):
        home = os.path.join(os.path.abspath(build_dir), home)
    flag_dirs = []
    if home:
        flag_dirs.append(home)
    build_dir = os.path.abspath(build_dir)
    chain = [build_dir]
    while True:
        parent = os.path.dirname(chain[-1])
        if parent == chain[-1]:
            break
        chain.append(parent)
    for ancestor in reversed(chain):
        flag_dirs.append(os.path.join(ancestor, ".cargo"))
    flags = []
    for flag_dir in flag_dirs:
        values = []
        for leaf in ("config", "config.toml"):
            path = os.path.join(flag_dir, leaf)
            if os.path.isfile(path):
                values.append(config_file_rustflags(path))
            elif os.path.lexists(path):
                fail("cargo config %s is not a readable file"
                     % path)
        for value in values:
            if value is not None:
                flags.extend(value)
                break
    dotted = env.get("CARGO_BUILD_RUSTFLAGS")
    if dotted is not None:
        flags.extend(dotted.split())
    return flags


def split_rustflags(text):
    """Split a flag string the way Cargo splits RUSTFLAGS.

    Words break on the space character alone; every other
    byte stays literal, so quotes and backslashes reach the
    compiler untouched. Empty words never form: leading,
    trailing, and repeated spaces vanish.
    """
    return [word for word in text.split(" ") if word]


def remap_build_paths(env):
    """Append path remaps so the built binary names no build machine.

    Home directory first, then the checkout root last, so
    checkout paths land under /build-root (the same pair the
    packager and the BPF build script apply). The binary
    lands on the default packaging input path, so it must be
    shippable as-is. Starts from the flag set Cargo itself
    would use: the encoded spelling when set, else RUSTFLAGS
    when set (a set-but-empty channel still shadows the
    rest), else the config layer carried forward so this
    export shadows nothing. The remap pair lands exactly
    once at the end and leaves through the encoded channel
    alone. A missing or empty HOME contributes no remap.
    """
    if "CARGO_ENCODED_RUSTFLAGS" in env:
        encoded = env["CARGO_ENCODED_RUSTFLAGS"]
        flags = encoded.split("\x1f") if encoded else []
    elif "RUSTFLAGS" in env:
        flags = split_rustflags(env["RUSTFLAGS"])
    else:
        flags = config_layer_rustflags(ROOT_DIR, env)
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
