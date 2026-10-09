#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Source-export gate: HEAD exports cleanly and packages git-free.

Verifies the export mechanism against HEAD (required inputs
present, sealed file set, no generated paths), then proves a
git-free export builds and packages: tools/package runs inside
the export with LMB_PACKAGE pointed at the export's own
vendored tarball, and the resulting manifest records revision
"export" with every referenced manual shipped. Finally enforces
the candidate rule: a dirty worktree cannot produce a candidate
export. Exits nonzero while BLOCKED.
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
    "schemas/session-v0.1.1.schema.json",
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

    # Git-free proof: build and package inside a fresh export.
    # tools/package runs tools/build first; LMB_PACKAGE points
    # at the export's own vendored tarball, never the checkout.
    with tempfile.TemporaryDirectory(prefix="mv-export-c-") as parent:
        # An ignored source export must not inherit even a clean parent's
        # identity, nor refuse packaging because the parent later becomes dirty.
        subprocess.run(["git", "-C", parent, "init", "-q"], check=True)
        with open(os.path.join(parent, ".gitignore"), "w") as handle:
            handle.write("export/\n")
        subprocess.run(["git", "-C", parent, "add", ".gitignore"], check=True)
        subprocess.run(["git", "-C", parent, "-c", "user.name=Test", "-c",
                        "user.email=test@example.invalid", "commit", "-qm",
                        "unrelated"], check=True)
        third = os.path.join(parent, "export")
        os.mkdir(third)
        export_head(third)
        vendored = os.path.join(
            third, "third_party", "libbpf-mojo-0.1.0.tar.gz")
        check("export-vendored-bridge", os.path.isfile(vendored),
              vendored)
        env = dict(os.environ)
        env["LMB_PACKAGE"] = vendored
        pkg = subprocess.run(
            [os.path.join(third, "tools", "package"),
             "--out", os.path.join(third, "dist")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=third, env=env, timeout=1500)
        if pkg.returncode != 0:
            print("FAIL export-package: tools/package exited %d"
                  % pkg.returncode)
            print("--- stdout ---")
            print(pkg.stdout[-3000:])
            print("--- stderr ---")
            print(pkg.stderr[-3000:])
            sys.exit(1)
        check("export-package", True)
        import json as _json
        bundles = [name for name in os.listdir(
            os.path.join(third, "dist"))
            if name.startswith("memveil-")
            and os.path.isdir(os.path.join(third, "dist", name))]
        check("export-bundle-dir", len(bundles) == 1,
              "; ".join(bundles))
        manifest = _json.load(open(os.path.join(
            third, "dist", bundles[0], "MANIFEST.json")))
        check("export-revision", manifest.get("memveil_revision")
              == "export", repr(manifest.get("memveil_revision")))
        for rel, want in manifest["files"].items():
            full = os.path.join(third, "dist", bundles[0], rel)
            with open(full, "rb") as handle:
                check("export-hash-%s" % rel,
                      hashlib.sha256(handle.read()).hexdigest() == want)
        for name in ("troubleshooting.md", "performance.md",
                     "resource-limits.md", "permissions.md",
                     "oracles.md"):
            dest = os.path.join(third, "dist", bundles[0],
                                "docs", name)
            check("export-docs-%s" % name, os.path.isfile(dest),
                  dest)
        with open(os.path.join(parent, "unrelated-dirty.txt"), "w") as handle:
            handle.write("dirty parent\n")
        repeated = subprocess.run(
            [os.path.join(third, "tools", "package"),
             "--out", os.path.join(third, "dist")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=third, env=env, timeout=1500)
        check("export-dirty-parent-package", repeated.returncode == 0,
              repeated.stderr[-3000:])
        with open(os.path.join(third, "dist", bundles[0], "MANIFEST.json")) as handle:
            repeated_manifest = _json.load(handle)
        check("export-dirty-parent-revision",
              repeated_manifest.get("memveil_revision") == "export")

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
