#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Seal build inputs and bind outputs to a versioned receipt.

tools/build seals the source inventory before compiling and
finalizes the receipt after: any mid-build input change (content,
mode, membership, or touch restoring identical bytes) fails the
build. tools/package verifies the receipt against the live tree
and the live build outputs before staging anything.

Usage:
  build_receipt.py seal --root ROOT --out PRE.json [--build-dir DIR]
  build_receipt.py finalize --root ROOT --build-dir DIR --pre PRE.json
  build_receipt.py verify --root ROOT --receipt FILE [--build-dir DIR]
Exit 0 on success, 1 on a seal break or missing input, 2 on
invalid usage. Standard library only.
"""

import hashlib
import json
import os
import stat
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import source_inventory  # noqa: E402

FORMAT = "memveil-build-receipt"
VERSION = 1
DEPS_FORMAT = "memveil-deps-inputs"
PRE_FORMAT = "memveil-build-seal"
PRE_VERSION = 1

PROBES = [
    ("pixi", ["pixi", "--version"]),
    ("mojo", ["pixi", "run", "--frozen", "mojo", "--version"]),
    ("clang", ["clang", "--version"]),
    ("bpftool", ["bpftool", "--version"]),
    ("python", ["python3", "--version"]),
]

# Build outputs bound by the receipt, relative to the build
# directory. Missing entries are simply absent: packaging
# enforces the ones it consumes.
OUTPUT_GLOBS = (
    ("memveil",),
    ("bpf",),
    ("native",),
    ("shim",),
    ("vm",),
    ("deps", "lmb"),
    ("deps", "include", "bpf"),
)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def output_entries(build_dir):
    """Hash every regular file under the output roots."""
    found = {}

    def record(rel, full):
        info = os.stat(full)
        found[rel] = {
            "sha256": sha256_file(full),
            "mode": oct(stat.S_IMODE(info.st_mode)),
            "size": info.st_size,
            "mtime_ns": info.st_mtime_ns,
            "ctime_ns": info.st_ctime_ns,
        }

    for root in OUTPUT_GLOBS:
        base = os.path.join(build_dir, *root)
        if os.path.isfile(base):
            record("/".join(root), base)
            continue
        if not os.path.isdir(base):
            continue
        for current, dirs, files in os.walk(base):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(current, name)
                if not os.path.isfile(full) or os.path.islink(full):
                    continue
                record(os.path.relpath(full, build_dir).replace(
                    os.sep, "/"), full)
    return found


def take_deps_inputs(deps_dir):
    """Full inventory of resolved dependency inputs."""
    return source_inventory.take_inventory(
        deps_dir, dirs=(".",), files=(),
        exclude_top=frozenset(), exclude_any=frozenset(),
        exclude_suffixes=(), label=DEPS_FORMAT)


def probe_toolchain(probes):
    """First stdout line per probe; missing tools fail closed."""
    observed = {}
    for name, cmd in probes:
        try:
            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True)
        except OSError as exc:
            return None, "cannot run %s: %s" % (cmd[0], exc)
        if proc.returncode != 0:
            return None, "%s exited %d" % (
                cmd[0], proc.returncode)
        first = proc.stdout.splitlines()[0] if proc.stdout else ""
        observed[name] = first.strip()
    return observed, ""


def dependency_identities(root):
    """Pinned dependency bytes the build consumed."""
    lock_path = os.path.join(root, "toolchain.lock.json")
    with open(lock_path, "r", encoding="utf-8") as handle:
        lock = json.load(handle)
    identities = {
        "libbpf-mojo_tarball_sha256": lock["dependencies"][
            "libbpf-mojo"]["tarball_sha256"],
        "libbpf_tarball_sha256": lock["toolchain"][
            "libbpf_source"]["tarball_sha256"],
    }
    kept = {
        "lmb-package.tgz": os.path.join(
            root, "build", "deps", "lmb-package.tgz"),
        "libbpf.tgz": os.path.join(
            root, "build", "deps", "libbpf.tgz"),
    }
    for name, path in sorted(kept.items()):
        if os.path.isfile(path):
            identities[name + "_sha256"] = sha256_file(path)
    return identities


def git_descriptive(root):
    """HEAD for humans; the inventory digest is the identity."""
    proc = subprocess.run(
        ["git", "-C", root, "rev-parse", "--show-toplevel"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True)
    if proc.returncode != 0 or not proc.stdout.strip() \
            or os.path.realpath(proc.stdout.strip()) != \
            os.path.realpath(root):
        return "export"
    proc = subprocess.run(
        ["git", "-C", root, "rev-parse", "HEAD"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True)
    sha = proc.stdout.strip() if proc.returncode == 0 else ""
    return sha if sha else "export"


def load_json(path, what):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        return None, "%s unreadable: %s" % (what, exc)
    if not isinstance(data, dict):
        return None, "%s is not an object" % what
    return data, ""


def compare_outputs(receipt_outputs, build_dir):
    """Live outputs against receipt entries; [] means match."""
    problems = []
    current = output_entries(build_dir)
    for rel in sorted(set(receipt_outputs) | set(current)):
        if rel not in receipt_outputs:
            problems.append("new build output: %s" % rel)
            continue
        if rel not in current:
            problems.append("missing build output: %s" % rel)
            continue
        want, got = receipt_outputs[rel], current[rel]
        if want["sha256"] != got["sha256"] \
                or want["size"] != got["size"]:
            problems.append("build output changed: %s" % rel)
        elif want["mtime_ns"] != got["mtime_ns"] \
                or want["ctime_ns"] != got["ctime_ns"]:
            problems.append("build output touched: %s" % rel)
    return problems


def cmd_seal(root, out, build_dir="build"):
    try:
        inventory = source_inventory.take_inventory(root)
        deps = take_deps_inputs(
            os.path.join(root, build_dir, "deps"))
    except OSError as exc:
        print("receipt: seal failed: %s" % exc, file=sys.stderr)
        return 1
    sealed = {
        "format": PRE_FORMAT,
        "version": PRE_VERSION,
        "sources": inventory,
        "deps": deps,
    }
    try:
        with open(out, "w", encoding="utf-8") as handle:
            json.dump(sealed, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError as exc:
        print("receipt: cannot write %s: %s" % (out, exc),
              file=sys.stderr)
        return 1
    return 0


def cmd_finalize(root, build_dir, pre, probes):
    full_build = os.path.join(root, build_dir)
    if not os.path.isdir(full_build):
        print("receipt: no such build dir: %s" % build_dir,
              file=sys.stderr)
        return 1
    before, error = load_json(pre, "pre-build seal")
    if before is None:
        print("receipt: %s" % error, file=sys.stderr)
        return 1
    if before.get("format") != PRE_FORMAT \
            or before.get("version") != PRE_VERSION \
            or not isinstance(before.get("sources"), dict) \
            or not isinstance(before.get("deps"), dict):
        print("receipt: pre-build seal has the wrong format",
              file=sys.stderr)
        return 1
    try:
        sealed = source_inventory.take_inventory(root)
        deps = take_deps_inputs(
            os.path.join(full_build, "deps"))
    except OSError as exc:
        print("receipt: seal failed: %s" % exc, file=sys.stderr)
        return 1
    problems = source_inventory.compare(
        before["sources"], sealed)
    if problems:
        print("receipt: sources changed during the build:",
              file=sys.stderr)
        for problem in problems[:10]:
            print("receipt:   %s" % problem, file=sys.stderr)
        return 1
    problems = source_inventory.compare(before["deps"], deps)
    if problems:
        print("receipt: resolved dependencies changed during "
              "the build:", file=sys.stderr)
        for problem in problems[:10]:
            print("receipt:   %s" % problem, file=sys.stderr)
        return 1
    try:
        identities = dependency_identities(root)
    except (OSError, ValueError, KeyError) as exc:
        print("receipt: dependency identities unreadable: %s"
              % exc, file=sys.stderr)
        return 1
    observed, error = probe_toolchain(probes)
    if observed is None:
        print("receipt: %s" % error, file=sys.stderr)
        return 1
    receipt = {
        "format": FORMAT,
        "version": VERSION,
        "git_descriptive": git_descriptive(root),
        "inventory": sealed,
        "toolchain_observed": observed,
        "mojo_target_cpu": "x86-64-v2",
        "dependencies": identities,
        "outputs": output_entries(full_build),
    }
    path = os.path.join(full_build, "build-receipt.json")
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError as exc:
        print("receipt: cannot write %s: %s" % (path, exc),
              file=sys.stderr)
        return 1
    print("receipt: %s" % path)
    return 0


def verify_loaded(receipt, root, build_dir):
    """Loaded receipt against live tree and outputs.

    Callers with one pinned baseline (packaging) verify
    every phase against these same bytes instead of
    re-reading the receipt path. [] means match.
    """
    if receipt.get("format") != FORMAT \
            or receipt.get("version") != VERSION:
        return ["wrong receipt format"]
    sealed = receipt.get("inventory")
    if not isinstance(sealed, dict):
        return ["receipt carries no inventory"]
    try:
        current = source_inventory.take_inventory(root)
    except OSError as exc:
        return ["seal failed: %s" % exc]
    return source_inventory.compare(sealed, current) + \
        compare_outputs(receipt.get("outputs", {}),
                        os.path.join(root, build_dir))


def cmd_verify(root, receipt_path, build_dir):
    receipt, error = load_json(receipt_path, "build receipt")
    if receipt is None:
        print("receipt: %s" % error, file=sys.stderr)
        return 1
    problems = verify_loaded(receipt, root, build_dir)
    if problems:
        print("receipt: tree or outputs drifted from the seal:",
              file=sys.stderr)
        for problem in problems[:10]:
            print("receipt:   %s" % problem, file=sys.stderr)
        return 1
    return 0


def usage():
    print("usage: build_receipt.py seal --root ROOT --out PRE.json "
          "[--build-dir DIR]", file=sys.stderr)
    print("       build_receipt.py finalize --root ROOT "
          "--build-dir DIR --pre PRE.json", file=sys.stderr)
    print("       build_receipt.py verify --root ROOT "
          "--receipt FILE [--build-dir DIR]", file=sys.stderr)


def main(argv):
    args = list(argv)
    if not args or args[0] in ("--help", "-h"):
        print(__doc__)
        return 0
    command = args.pop(0)
    root = None
    out = None
    build_dir = "build"
    pre = None
    receipt = None
    while args:
        opt = args.pop(0)
        if opt == "--root" and args:
            root = args.pop(0)
            continue
        if opt == "--out" and args:
            out = args.pop(0)
            continue
        if opt == "--build-dir" and args:
            build_dir = args.pop(0)
            continue
        if opt == "--pre" and args:
            pre = args.pop(0)
            continue
        if opt == "--receipt" and args:
            receipt = args.pop(0)
            continue
        usage()
        return 2
    if root is None or not os.path.isdir(root):
        print("receipt: no such tree: %s" % root, file=sys.stderr)
        return 2
    if command == "seal":
        if out is None:
            usage()
            return 2
        return cmd_seal(root, out, build_dir)
    if command == "finalize":
        if pre is None:
            usage()
            return 2
        return cmd_finalize(root, build_dir, pre, PROBES)
    if command == "verify":
        if receipt is None:
            usage()
            return 2
        return cmd_verify(root, receipt, build_dir)
    usage()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
