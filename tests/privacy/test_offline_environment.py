#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline-environment checks: replay needs nothing live.

Replays a fixture capture under a scrubbed environment
(PATH-only, foreign cwd): output is byte-identical to the
normal run, and a strace audit (shared with the packaging
lane) proves no network, BPF, BTF, tracefs, or checkout
access. Exits nonzero on the first failure.
"""

import os
import shutil
import subprocess
import sys
import tempfile

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
sys.path.insert(0, os.path.join(REPO, "tests", "package"))
from cleanroom import audit_trace  # noqa: E402

BIN = os.path.join(REPO, "build", "memveil")
CAP = os.path.join(REPO, "tests", "fixtures", "attempts")


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def main():
    if not os.path.isfile(BIN):
        print("FAIL offline-environment: missing %s (run tools/build first)"
              % BIN)
        sys.exit(1)
    if not shutil.which("strace"):
        print("FAIL offline-environment: strace is required")
        sys.exit(1)

    scrub = {"PATH": "/usr/bin:/bin"}
    for fmt in ("text", "json"):
        normal = subprocess.run([BIN, "report", "--format", fmt, CAP],
                                capture_output=True)
        bare = subprocess.run([BIN, "report", "--format", fmt, CAP],
                              capture_output=True, env=scrub, cwd="/")
        check("exit-%s" % fmt, bare.returncode == normal.returncode,
              "scrubbed %d vs %d" % (bare.returncode, normal.returncode))
        check("identical-%s" % fmt, bare.stdout == normal.stdout)

    tmp = tempfile.mkdtemp(prefix="mvoffline")
    trace = os.path.join(tmp, "trace.log")
    # The replayed capture is staged outside the checkout: any
    # remaining checkout open is a genuine bundling leak.
    import shutil as _shutil
    staged = os.path.join(tmp, "cap")
    _shutil.copytree(CAP, staged)
    proc = subprocess.run(
        ["strace", "-f", "-o", trace, "-e",
         "trace=openat,open,openat2,socket,connect,sendto,bpf,"
         "execve,chdir,fchdir",
         BIN, "report", "--format", "json", staged],
        capture_output=True, env=scrub, cwd="/")
    check("traced-exit", proc.returncode == 0,
          "exit %d: %s" % (proc.returncode, proc.stderr[:120]))
    with open(trace, encoding="utf-8", errors="replace") as fh:
        violations = audit_trace(fh.read(), "/", os.path.realpath(REPO))
    # The dev binary links its Mojo runtime from the checkout's
    # .pixi tree; that toolchain linkage is out of scope here
    # (the packaged binary is audited separately). Everything
    # else — network, BPF, BTF, tracefs, source opens — must
    # stay clean.
    scoped = [v for v in violations if "/.pixi/" not in v]
    check("trace-clean", scoped == [], "; ".join(scoped[:5]))


if __name__ == "__main__":
    main()
