#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Source-export gate: HEAD exports cleanly; the candidate needs a commit.

Verifies the export mechanism against HEAD (required inputs
present, sealed file set, no generated paths), then enforces the
candidate rule: a dirty worktree cannot produce a candidate
export. Post-commit flow: clean tree -> this lane -> build the
export with tools/build --check-toolchain + tools/build ->
tools/package. Exits nonzero while BLOCKED.
Standard library only.
"""

import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))

REQUIRED = (
    "pixi.toml",
    "pixi.lock",
    "toolchain.lock.json",
    "tools/build",
    "tools/test",
    "tools/package",
    "src/memveil/main.mojo",
    "bpf/programs/swiotlb_attempt.bpf.c",
    "bpf/include/memveil_events.h",
    "profiles/manifest.txt",
    "schemas/session-v0.1.0.schema.json",
    "README.md",
    "LICENSE",
)

GENERATED_MARKERS = (
    "/build/", "/dist/", "/.pixi/", "/__pycache__/",
    "/.pytest_cache/", "/.mypy_cache/",
)


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def export_head(dest):
    archive = subprocess.run(
        ["git", "archive", "HEAD"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if archive.returncode != 0:
        print("FAIL export-head: git archive failed")
        sys.exit(1)
    with tempfile.NamedTemporaryFile(suffix=".tar") as tmp:
        tmp.write(archive.stdout)
        tmp.flush()
        with tarfile.open(tmp.name) as tar:
            tar.extractall(dest)


def seal(tree):
    sealed = {}
    for base, _, files in os.walk(tree):
        for name in files:
            full = os.path.join(base, name)
            rel = os.path.relpath(full, tree)
            digest = hashlib.sha256()
            with open(full, "rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
            sealed[rel] = digest.hexdigest()
    return sealed


def main():
    rev = subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    check("head-readable", rev.returncode == 0)
    head = rev.stdout.strip()
    print("source-export: HEAD %s" % head)

    with tempfile.TemporaryDirectory(
            prefix="mv-export-a-") as first, \
            tempfile.TemporaryDirectory(
                prefix="mv-export-b-") as second:
        export_head(first)
        missing = [rel for rel in REQUIRED
                   if not os.path.isfile(os.path.join(first, rel))]
        check("export-required-inputs", not missing,
              "; ".join(missing[:5]))
        generated = [rel for rel, _, files in os.walk(first)
                     for rel in [os.path.relpath(rel, first)]
                     for marker in GENERATED_MARKERS
                     if ("/" + rel + "/").startswith(marker)
                     or rel in ("build", "dist", ".pixi")]
        check("export-no-generated-dirs", not generated,
              "; ".join(sorted(set(generated))[:5]))
        # Committed fixtures under tests/fixtures are source
        # inputs (object-validation vectors); binaries anywhere
        # else are leaked build outputs.
        stray = []
        for base, _, files in os.walk(first):
            for name in files:
                rel = os.path.relpath(os.path.join(base, name), first)
                if rel.startswith("tests/fixtures/"):
                    continue
                if name.endswith((".o", ".so", ".pyc")) \
                        or ".so." in name:
                    stray.append(rel)
        check("export-no-binaries", not stray, "; ".join(stray[:5]))
        export_head(second)
        check("export-sealed",
              seal(first) == seal(second))
        print("source-export: HEAD export verified "
              "(%d files, mechanism only)" % len(seal(first)))

    status = subprocess.run(["git", "-C", ROOT, "status", "--short"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    if status.returncode != 0:
        print("FAIL candidate-clean-tree: cannot inspect worktree")
        sys.exit(1)
    dirty = [line for line in status.stdout.splitlines() if line.strip()]
    if dirty:
        print("source-export: BLOCKED: worktree has uncommitted "
              "changes; commit first (%d paths)" % len(dirty))
        sys.exit(1)
    check("candidate-clean-tree", True)
    print("source-export: candidate export ready at HEAD %s" % head)
    return 0


if __name__ == "__main__":
    sys.exit(main())
