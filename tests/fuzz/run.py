#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Deterministic mutation fuzz over capture replay.

Mutates seed captures with a seeded RNG and replays each case
through the built report verb. The oracle is strict and
independent of the mutator: every case must exit 0, 2, or 4
within the timeout; exit 2 must leave stdout empty with a
non-empty stderr; exit 0 and exit 4 JSON output must parse;
no case may print a crash marker. Violations retain their
seed and input under tests/fuzz/regressions/ and fail the
run.

Usage: tests/fuzz/run.py --seeds N [--start S] [--binary PATH]
       [--regress DIR] [--timeout SEC]
"""

import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
SEED_DIRS = [
    os.path.join("tests", "fixtures", "attempts"),
    os.path.join("tests", "fixtures", "lifecycle", "lifecycle-nested"),
    os.path.join("tests", "fixtures", "reader", "quality-detail-counters"),
    os.path.join("tests", "fixtures", "reader", "counters"),
]
CRASH_MARKERS = (b"Traceback", b"panic", b"AssertionError",
                 b"Segmentation fault", b"mojo: error")


def mutate(rng, data):
    ops = ["flip", "truncate", "dupkey", "intspell", "hugeint",
           "utf8break", "nul", "dropkey", "nest", "dupkey_top",
           "cutline", "swaplines"]
    op = rng.choice(ops)
    if op == "flip" and data:
        i = rng.randrange(len(data))
        b = rng.randrange(256)
        return data[:i] + bytes([b]) + data[i + 1:]
    if op == "truncate" and len(data) > 4:
        return data[:rng.randrange(1, len(data))]
    if op == "dupkey":
        return data.replace(b'"seq":', b'"seq": "9", "seq":', 1)
    if op == "intspell":
        return data.replace(b'"1"', b'"01"', 1)
    if op == "hugeint":
        return data.replace(b'"4096"', b'"9' + b'9' * 40 + b'"', 1)
    if op == "utf8break":
        return data.replace(b'dev', b'd\xff', 1)
    if op == "nul":
        pos = rng.randrange(len(data)) if data else 0
        return data[:pos] + b"\x00" + data[pos:]
    if op == "dropkey":
        return data.replace(b'"kind": "bounce_attempt", ', b"", 1)
    if op == "nest":
        return data.replace(b'"data": {', b'"data": {"n": ' * 70, 1)
    if op == "dupkey_top":
        return data.replace(b'{"schema_version"',
                            b'{"schema_version": "0.1.1", "schema_version"', 1)
    if op == "cutline":
        lines = data.split(b"\n")
        if len(lines) > 2:
            lines.pop(rng.randrange(len(lines) - 1))
        return b"\n".join(lines)
    if op == "swaplines":
        lines = data.split(b"\n")
        if len(lines) > 3:
            a, b = rng.sample(range(len(lines) - 1), 2)
            lines[a], lines[b] = lines[b], lines[a]
        return b"\n".join(lines)
    return data + b"\n{\"truncated\": "


def run_case(binary, path, timeout):
    try:
        p = subprocess.run([binary, "report", "--format", "json", path],
                           capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ("timeout", b"", b"replay timed out")
    return (p.returncode, p.stdout, p.stderr)


def check(case, code, out, err):
    if code == "timeout":
        return "replay timed out"
    if code not in (0, 2, 4):
        return "exit %r not in {0, 2, 4}" % (code,)
    for marker in CRASH_MARKERS:
        if marker in out or marker in err:
            return "crash marker %r in output" % (marker,)
    if code == 2:
        if out != b"":
            return "exit 2 with %d stdout bytes" % len(out)
        if err == b"":
            return "exit 2 with empty stderr"
    if code == 0:
        try:
            json.loads(out.decode("utf-8"))
        except Exception as exc:
            return "exit 0 with invalid JSON: %s" % (exc,)
    if code == 4:
        if out == b"":
            return "exit 4 with empty stdout"
        # run_case always requests --format json, so a usable
        # incomplete report must still parse as JSON.
        try:
            json.loads(out.decode("utf-8"))
        except Exception as exc:
            return "exit 4 with invalid JSON: %s" % (exc,)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, required=True)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--binary", default=os.path.join(REPO, "build", "memveil"))
    ap.add_argument("--regress",
                    default=os.path.join(REPO, "tests", "fuzz", "regressions"))
    ap.add_argument("--timeout", type=int, default=10)
    args = ap.parse_args()
    if args.seeds is None or args.seeds <= 0:
        print("FAIL fuzz: --seeds must be positive, got %r"
              % (args.seeds,))
        return 1
    if not os.path.isfile(args.binary):
        print("FAIL fuzz: missing %s (run tools/build first)"
              % args.binary)
        return 1
    with open(args.binary, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    print("fuzz: binary %s sha256 %.16s..." % (args.binary, digest))
    fails = 0
    for n in range(args.start, args.start + args.seeds):
        rng = random.Random(n)
        seed = SEED_DIRS[n % len(SEED_DIRS)]
        tmp = tempfile.mkdtemp(prefix="mvfuzz")
        try:
            shutil.copy(os.path.join(REPO, seed, "session.json"),
                        os.path.join(tmp, "session.json"))
            with open(os.path.join(REPO, seed, "events.ndjson"), "rb") as fh:
                data = fh.read()
            if rng.random() < 0.2:
                with open(os.path.join(tmp, "session.json"), "rb") as fh:
                    sdata = fh.read()
                with open(os.path.join(tmp, "session.json"), "wb") as fh:
                    fh.write(mutate(rng, sdata))
                # Mutated session beside intact events: a valid
                # mutation proceeds through a complete capture
                # instead of tripping on a missing events file.
                with open(os.path.join(tmp, "events.ndjson"), "wb") as fh:
                    fh.write(data)
            else:
                with open(os.path.join(tmp, "events.ndjson"), "wb") as fh:
                    fh.write(mutate(rng, data))
            code, out, err = run_case(args.binary, tmp, args.timeout)
            problem = check(n, code, out, err)
            if problem is not None:
                fails += 1
                dest = os.path.join(args.regress, "seed-%d" % n)
                if os.path.isdir(dest):
                    shutil.rmtree(dest)
                shutil.copytree(tmp, dest)
                with open(os.path.join(dest, "oracle.txt"), "w") as fh:
                    fh.write("seed %d: %s\n" % (n, problem))
                print("FAIL seed %d: %s" % (n, problem))
                if fails >= 5:
                    print("fuzz: stopping after 5 failures")
                    break
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    ran = min(args.seeds, n - args.start + 1) if args.seeds else 0
    print("fuzz: %d cases, %d failures" % (ran, fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
