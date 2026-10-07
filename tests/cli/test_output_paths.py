#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Output-path checks: hostile paths refuse without mutation.

Drives the built record verb over existing dirs/files,
symlinks, traversal spellings, absolute paths, file-parents,
and read-only parents. Every case must refuse (exit 2 or 3)
while the scratch tree — including a sentinel file — stays
byte-identical: refusal happens before any filesystem
mutation. Exits nonzero on the first failure.
"""

import hashlib
import os
import subprocess
import sys
import tempfile

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
BIN = os.path.join(REPO, "build", "memveil")
ELF = os.path.join(REPO, "tests", "fixtures", "elf", "ok.o")


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def snapshot(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames + dirnames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if os.path.islink(full):
                out.append((rel, "link", os.readlink(full)))
            elif os.path.isdir(full):
                out.append((rel, "dir", ""))
            else:
                with open(full, "rb") as fh:
                    digest = hashlib.sha256(fh.read()).hexdigest()
                out.append((rel, "file", digest))
    return out


def main():
    if not os.path.isfile(BIN):
        print("FAIL output-paths: missing %s (run tools/build first)"
              % BIN)
        sys.exit(1)
    tmp = tempfile.mkdtemp(prefix="mvpaths")
    os.mkdir(os.path.join(tmp, "existing"))
    with open(os.path.join(tmp, "afile"), "w") as fh:
        fh.write("plain file\n")
    os.symlink("existing", os.path.join(tmp, "goodlink"))
    os.symlink("nowhere", os.path.join(tmp, "danglink"))
    os.mkdir(os.path.join(tmp, "sub"))
    with open(os.path.join(tmp, "sentinel"), "w") as fh:
        fh.write("sentinel-data\n")
    os.mkdir(os.path.join(tmp, "rodir"))
    os.chmod(os.path.join(tmp, "rodir"), 0o555)
    before = snapshot(tmp)

    cases = ["existing", "afile", "goodlink", "danglink",
             os.path.join("sub", "..", "escape"),
             os.path.join(tmp, "abs"), os.path.join("afile", "child"),
             os.path.join("rodir", "child")]
    for case in cases:
        target = case if os.path.isabs(case) else os.path.join(tmp, case)
        p = subprocess.run([BIN, "record", "--output", target,
                            "--object", ELF, "--bridge",
                            os.path.join(tmp, "nolib.so")],
                           capture_output=True, text=True, cwd=tmp)
        name = case.replace(os.sep, "_")
        check("refuse-%s" % name, p.returncode in (2, 3),
              "exit %d" % p.returncode)
        check("stderr-%s" % name, p.stderr != "")
        check("silent-%s" % name, p.stdout == "",
              "stdout %r" % p.stdout[:60])
    after = snapshot(tmp)
    check("tree-identical", before == after)
    with open(os.path.join(tmp, "sentinel")) as fh:
        check("sentinel", fh.read() == "sentinel-data\n")


if __name__ == "__main__":
    main()
