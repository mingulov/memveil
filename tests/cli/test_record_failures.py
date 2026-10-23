#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Record-failure checks: death, replay purity, cycles, signals.

Drives the built binary: an abruptly-ended capture (events
without a session) exits 2 without forging metadata; replay
never mutates the capture tree; 100 denied-record plus replay
cycles leave no residue with stable exits; SIGINT/SIGTERM
mid-spawn never hang or litter; and a refusal explains
itself on fd 2 even when /dev/stderr is rebound elsewhere.
Exits nonzero on the first failure.
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
SHIM = os.path.join(REPO, "build", "shim", "mvshim.so")
BRIDGE = os.path.join(REPO, "build", "deps", "lmb", "lib",
                      "libbpf_mojo.so.1")
ATTEMPT_O = os.path.join(REPO, "build", "bpf",
                         "swiotlb_attempt.bpf.o")
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

    # Stderr follows fd 2, not the /dev/stderr path: with the
    # path rebound to a decoy (as virtme guests do), a refusal
    # must still explain itself on the captured fd.
    if not os.path.isfile(SHIM):
        print("FAIL record-failures: missing %s (run tools/build first)"
              % SHIM)
        sys.exit(1)
    fd = tempfile.mkdtemp(prefix="mvstderr")
    decoy = os.path.join(fd, "decoy.log")
    env = dict(os.environ)
    env.pop("LMB_NATIVE_LIB", None)
    env["LD_PRELOAD"] = SHIM
    env["MVSHIM"] = "stderr_decoy:%s" % decoy
    p = subprocess.run(
        [BIN, "record", "--output", os.path.join(fd, "cap"),
         "--object", ELF],
        capture_output=True, text=True, env=env)
    check("stderr-fd-exit", p.returncode == 3,
          "exit %d" % p.returncode)
    check("stderr-fd-pipe", "memveil record:" in p.stderr,
          "stderr %r" % p.stderr[:120])
    leaked = os.path.isfile(decoy) and os.path.getsize(decoy) > 0
    check("stderr-fd-decoy", not leaked, decoy)

    # Tracefs root probes use effective access: with plain
    # access() denied on both roots, record must refuse
    # exactly as without the shim (faccessat passes
    # through). The precondition keeps this non-vacuous:
    # a root must exist, and the base refusal must depend
    # on the root probe (lockdown and config refusals fire
    # before it, so they would compare equal either way).
    for path, name in ((BRIDGE, "bridge"), (ATTEMPT_O, "object")):
        if not os.path.isfile(path):
            print("FAIL record-failures: missing %s %s "
                  "(run tools/build first)" % (name, path))
            sys.exit(1)
    roots = ["/sys/kernel/debug/tracing", "/sys/kernel/tracing"]
    check("eaccess-root-present",
          any(os.path.exists(r) for r in roots),
          "no tracefs root on this host")
    gd = tempfile.mkdtemp(prefix="mveaccess")
    gate_env = dict(os.environ)
    gate_env.pop("LMB_NATIVE_LIB", None)
    gate_argv = [BIN, "record", "--output", os.path.join(gd, "cap"),
                 "--object", ATTEMPT_O, "--bridge", BRIDGE]
    base = subprocess.run(gate_argv, capture_output=True, text=True,
                          env=gate_env)
    check("eaccess-base-exit", base.returncode == 3,
          "exit %d" % base.returncode)
    independent = ("kernel lockdown is confidentiality" in base.stderr
                   or "kernel has no BPF tracing support (config"
                   in base.stderr)
    check("eaccess-base-rooted", not independent,
          "stderr %r" % base.stderr[:160])
    shim_env = dict(gate_env)
    shim_env["LD_PRELOAD"] = SHIM
    shim_env["MVSHIM"] = "deny_access:%s,deny_access:%s" % (
        roots[0], roots[1])
    shimmed = subprocess.run(gate_argv, capture_output=True, text=True,
                             env=shim_env)
    check("eaccess-shim-exit", shimmed.returncode == 3,
          "exit %d" % shimmed.returncode)
    check("eaccess-shim-same", shimmed.stderr == base.stderr,
          "base %r shimmed %r"
          % (base.stderr[:160], shimmed.stderr[:160]))


if __name__ == "__main__":
    main()
