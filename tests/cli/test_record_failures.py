#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Record-failure checks: death, replay purity, cycles, signals.

Drives the built binary: an abruptly-ended capture (events
without a session) exits 2 without forging metadata; replay
never mutates the capture tree; 100 denied-record plus replay
cycles leave no residue with stable exits; and SIGINT/SIGTERM
mid-spawn never hang or litter. Exits nonzero on the first
failure.
"""

import hashlib
import os
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import time

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
BIN = os.path.join(REPO, "build", "memveil")
ATTEMPTS = os.path.join(REPO, "tests", "fixtures", "attempts")
ELF = os.path.join(REPO, "tests", "fixtures", "elf", "ok.o")


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def tree_hash(root):
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            h.update(os.path.relpath(full, root).encode())
            with open(full, "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()


def main():
    if not os.path.isfile(BIN):
        print("FAIL record-failures: missing %s (run tools/build first)"
              % BIN)
        sys.exit(1)

    # Abrupt death: events survived, session.json did not.
    tmp = tempfile.mkdtemp(prefix="mvdeath")
    shutil.copy(os.path.join(ATTEMPTS, "events.ndjson"),
                os.path.join(tmp, "events.ndjson"))
    p = subprocess.run([BIN, "report", tmp], capture_output=True, text=True)
    check("death-exit", p.returncode == 2, "exit %d" % p.returncode)
    check("death-stdout", p.stdout == "")
    check("death-noforge", not os.path.exists(os.path.join(tmp, "session.json")))
    check("death-partial", subprocess.run(
        [BIN, "report", "--allow-partial", tmp],
        capture_output=True, text=True).returncode == 2)

    # Replay purity: report and top never mutate the capture.
    work = tempfile.mkdtemp(prefix="mvpure")
    cap = os.path.join(work, "cap")
    shutil.copytree(ATTEMPTS, cap)
    before = tree_hash(cap)
    r1 = subprocess.run([BIN, "report", cap], capture_output=True, text=True)
    check("pure-report", r1.returncode in (0, 4), "exit %d" % r1.returncode)
    r2 = subprocess.run([BIN, "top", cap], capture_output=True, text=True)
    check("pure-top", r2.returncode in (0, 4), "exit %d" % r2.returncode)
    check("pure-identical", tree_hash(cap) == before)

    # 100 denied-record plus replay cycles: stable exits, no residue.
    cyc = tempfile.mkdtemp(prefix="mvcyc")
    for i in range(100):
        out = os.path.join(cyc, "cap-%d" % i)
        p = subprocess.run(
            [BIN, "record", "--output", out, "--object", ELF,
             "--bridge", os.path.join(cyc, "nolib.so")],
            capture_output=True, text=True)
        if p.returncode not in (2, 3) or os.path.exists(out):
            check("cycle-%d" % i, False, "exit %d residue %s"
                  % (p.returncode, os.path.exists(out)))
        q = subprocess.run([BIN, "report", ATTEMPTS],
                           capture_output=True, text=True)
        if q.returncode not in (0, 4):
            check("cycle-report-%d" % i, False,
                  "exit %d" % q.returncode)
    check("cycles-clean", os.listdir(cyc) == [])
    check("cycles", True)

    # Signals mid-spawn: die promptly, leave nothing behind.
    rng = random.Random(20261007)
    sigdir = tempfile.mkdtemp(prefix="mvsig")
    for i in range(20):
        out = os.path.join(sigdir, "cap-%d" % i)
        child = subprocess.Popen(
            [BIN, "record", "--output", out, "--object", ELF,
             "--bridge", os.path.join(sigdir, "nolib.so")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(rng.random() * 0.01)
        child.send_signal(rng.choice([signal.SIGINT, signal.SIGTERM]))
        try:
            child.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate()
            check("signal-hang-%d" % i, False)
        if os.path.exists(out):
            check("signal-residue-%d" % i, False, out)
    check("signals", True)


if __name__ == "__main__":
    main()
