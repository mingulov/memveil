#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Deterministic inventory of admitted source/build inputs.

Walks the owned input set (sources, BPF, profiles, docs, schemas,
examples, licenses, manifests, locks, builders, vendored inputs),
recording per-file kind, mode, size, identity hash, and filesystem
timestamps. Standard library only.

The digest covers path/kind/mode/size/hash only, so it compares
across checkouts. compare() additionally checks mtimes/ctimes, so
a modify-then-restore inside one tree still trips: content may be
equal again, but the kernel-controlled ctime advances on every
write even when mtime is restored with utime.

Detection assumes the mutation and the restore land in distinct
timestamp quanta (nanosecond on Linux filesystems): a rewrite
sharing one quantum with mtime restored is invisible. Symlink
inputs are recorded and always trip: compilers follow links, so
target bytes outside the admitted set cannot establish identity.

Usage: source_inventory.py [ROOT] [--out FILE]
  Writes the inventory JSON to stdout or FILE. Exit 0 on success,
  2 on invalid usage or an unreadable tree.
"""

import hashlib
import json
import os
import stat
import sys

FORMAT = "memveil-source-inventory"
VERSION = 1

# Owned directories walked for inputs (missing ones contribute
# nothing). build/, dist/, .pixi/ and VCS metadata are never
# inputs; neither are test-only fixtures or the tests themselves.
INPUT_DIRS = (
    "src",
    "bpf",
    "profiles",
    "docs",
    "schemas",
    "examples/real-capture",
    "tests/native",
    "tests/shim",
    "tests/vm",
    "third_party",
    "tools",
    "LICENSES",
)

# Owned top-level input files.
INPUT_FILES = (
    "toolchain.lock.json",
    "pixi.toml",
    "pixi.lock",
    "LICENSE",
    "THIRD-PARTY-NOTICES.md",
)

# Top-level names excluded from the tree walk: outputs,
# environments, and version control. These match only the
# first path component, so tools/build stays admitted.
EXCLUDED_TOP = frozenset((
    ".git",
    "build",
    "dist",
    ".pixi",
))

# Names excluded at any depth: interpreter and tool caches
# (importing tools modules writes __pycache__ mid-flow,
# which must not trip the seal).
EXCLUDED_ANY = frozenset((
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
))

# Suffixes excluded at any depth.
EXCLUDED_SUFFIXES = (".pyc",)


def sha256_of(handle):
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(65536), b""):
        digest.update(chunk)
    return digest.hexdigest()


def describe(root, rel, exclude_top=EXCLUDED_TOP,
             exclude_any=EXCLUDED_ANY,
             exclude_suffixes=EXCLUDED_SUFFIXES):
    """One inventory entry for rel, or None when excluded."""
    parts = rel.replace(os.sep, "/").split("/")
    if parts[0] in exclude_top:
        return None
    if any(part in exclude_any for part in parts):
        return None
    if parts[-1].endswith(exclude_suffixes):
        return None
    full = os.path.join(root, rel)
    try:
        info = os.lstat(full)
    except OSError:
        return None
    # Paths stay relative with forward slashes so the digest
    # compares across checkouts and platforms.
    entry = {
        "path": "/".join(parts),
        "mode": oct(stat.S_IMODE(info.st_mode)),
    }
    if stat.S_ISLNK(info.st_mode):
        entry["kind"] = "symlink"
        entry["target"] = os.readlink(full)
        return entry
    if stat.S_ISDIR(info.st_mode):
        entry["kind"] = "dir"
        return entry
    if not stat.S_ISREG(info.st_mode):
        entry["kind"] = "other"
        return entry
    entry["kind"] = "file"
    entry["size"] = info.st_size
    entry["mtime_ns"] = info.st_mtime_ns
    entry["ctime_ns"] = info.st_ctime_ns
    with open(full, "rb") as handle:
        entry["sha256"] = sha256_of(handle)
    return entry


def take_inventory(root, dirs=INPUT_DIRS, files=INPUT_FILES,
                   exclude_top=EXCLUDED_TOP,
                   exclude_any=EXCLUDED_ANY,
                   exclude_suffixes=EXCLUDED_SUFFIXES,
                   label=FORMAT):
    """Walk admitted inputs; return the inventory dict."""
    root = os.path.realpath(root)
    entries = {}

    def record(rel):
        entry = describe(
            root, rel, exclude_top=exclude_top,
            exclude_any=exclude_any,
            exclude_suffixes=exclude_suffixes)
        if entry is not None:
            entries[entry["path"]] = entry

    for top in dirs:
        base = os.path.join(root, top)
        if not os.path.isdir(base) and not os.path.islink(base):
            continue
        for current, subdirs, names in os.walk(base,
                                               followlinks=False):
            subdirs.sort()
            for name in sorted(subdirs):
                # os.walk never descends into symlinked
                # directories: describe them so a retarget
                # cannot hide (describe() never follows).
                full = os.path.join(current, name)
                if os.path.islink(full):
                    record(os.path.relpath(full, root))
            rel_dir = os.path.relpath(current, root)
            if rel_dir != ".":
                record(rel_dir)
            for name in sorted(names):
                record(os.path.relpath(
                    os.path.join(current, name), root))
    for rel in files:
        if os.path.lexists(os.path.join(root, rel)):
            record(rel)
    ordered = [entries[path] for path in sorted(entries)]
    digest = hashlib.sha256()
    for entry in ordered:
        digest.update(json.dumps(
            {key: entry[key] for key in sorted(entry)
             if key not in ("mtime_ns", "ctime_ns")},
            sort_keys=True, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
    return {
        "format": label,
        "version": VERSION,
        "files": ordered,
        "digest": digest.hexdigest(),
    }


def compare(before, after):
    """Human-readable differences from before to after.

    Content, mode, size, and membership diffs plus timestamp-only
    touches (a rewrite restoring identical bytes still changes
    the kernel ctime). Empty means identical.
    """
    problems = []
    old = {entry["path"]: entry for entry in before.get("files", [])}
    new = {entry["path"]: entry for entry in after.get("files", [])}
    for path in sorted(set(old) | set(new)):
        if path not in old:
            problems.append("added input: %s" % path)
            continue
        if path not in new:
            problems.append("removed input: %s" % path)
            continue
        first, second = old[path], new[path]
        if first.get("kind") == "symlink" \
                or second.get("kind") == "symlink":
            problems.append("symlink inputs unsupported: %s" % path)
            continue
        if first.get("kind") != second.get("kind"):
            problems.append("kind changed: %s" % path)
            continue
        if first.get("mode") != second.get("mode"):
            problems.append("mode changed: %s" % path)
        if first.get("kind") == "symlink":
            if first.get("target") != second.get("target"):
                problems.append("symlink retargeted: %s" % path)
            continue
        if first.get("kind") != "file":
            continue
        if first.get("sha256") != second.get("sha256") \
                or first.get("size") != second.get("size"):
            problems.append("content changed: %s" % path)
        elif first.get("mtime_ns") != second.get("mtime_ns") \
                or first.get("ctime_ns") != second.get("ctime_ns"):
            problems.append("touched without content change: %s"
                            % path)
    return problems


def main(argv):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = None
    args = list(argv)
    while args:
        opt = args.pop(0)
        if opt in ("--help", "-h"):
            print(__doc__)
            return 0
        if opt == "--out" and args:
            out = args.pop(0)
            continue
        if opt.startswith("-"):
            print("usage: source_inventory.py [ROOT] [--out FILE]",
                  file=sys.stderr)
            return 2
        root = opt
    if not os.path.isdir(root):
        print("source_inventory: no such tree: %s" % root,
              file=sys.stderr)
        return 2
    try:
        inventory = take_inventory(root)
    except OSError as exc:
        print("source_inventory: %s" % exc, file=sys.stderr)
        return 2
    text = json.dumps(inventory, indent=2, sort_keys=True) + "\n"
    if out is None:
        sys.stdout.write(text)
        return 0
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
