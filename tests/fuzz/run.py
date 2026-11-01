#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Deterministic capture mutation with independent accepted-report oracles.

Every accepted finalized or recovered report is schema-checked and compared
against literal input bytes and independently recomputed arithmetic. Pristine
positive controls prevent an always-refuse binary from passing. Receipts name
sampled corpus families and outcomes separately from unavailable instrumentation.
"""

from report_oracle import accepted_report

from collections import Counter
from pathlib import Path
import time

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
    os.path.join("tests", "fixtures", "reader", "sealed-complete"),
    os.path.join("tests", "fixtures", "reader", "sealed-partial"),
    os.path.join("tests", "fixtures", "reader", "sealed-empty"),
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


def run_case(binary, path, timeout, *flags):
    try:
        p = subprocess.run([binary, "report", "--format", "json", *flags, str(path)],
                           capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ("timeout", b"", b"replay timed out")
    return (p.returncode, p.stdout, p.stderr)


def check(case, code, out, err, *, strict=False, allow_partial=False):
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
    if code in (0, 4):
        try:
            accepted_report(case, out, code, strict=strict, allow_partial=allow_partial)
        except Exception as exc:
            return "accepted report violates oracle: %s" % (exc,)
    return None


def checkpoint(path):
    source = Path(path) / 'session.json'
    doc = json.loads(source.read_bytes())
    doc['capture'].update(finalized=False, end_reason='checkpoint', checkpoint_generation='1')
    doc['stop'].update(outcome='partial', reason='checkpoint: measurement window remains open')
    for key in ('admission_closed', 'quiescence_observed', 'drain_completed', 'counters_valid'):
        doc['stop'][key] = False
    for channel in doc['quality'].values():
        if isinstance(channel, dict) and channel.get('status') == 'complete_for_scope':
            channel.update(status='partial', reason='checkpoint: measurement window remains open')
    if 'verdict' in doc:
        doc['verdict']['name'] = 'partial_unknown_loss'
    (Path(path) / 'checkpoint.json').write_text(json.dumps(doc))
    source.unlink()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, required=True)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--binary", default=os.path.join(REPO, "build", "memveil"))
    ap.add_argument("--regress",
                    default=os.path.join(REPO, "build", "fuzz-regressions"))
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--receipt", type=Path)
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
    started = time.monotonic()
    outcomes = Counter()
    families = Counter()
    for seed in SEED_DIRS:
        code, out, err = run_case(args.binary, os.path.join(REPO, seed), args.timeout)
        problem = check(os.path.join(REPO, seed), code, out, err)
        if code != 0 or problem:
            print("FAIL pristine positive %s: exit %r %s" % (seed, code, problem))
            return 1
    with tempfile.TemporaryDirectory(prefix='mvfuzz-positive-') as positive:
        for name in ('session.json', 'events.ndjson'):
            shutil.copy(os.path.join(REPO, SEED_DIRS[4], name), positive)
        checkpoint(positive)
        with open(os.path.join(positive, 'events.ndjson'), 'ab') as stream:
            stream.write(b'unverified suffix\x00\xff')
        for strict in (False, True):
            flags = ('--allow-partial', '--strict') if strict else ('--allow-partial',)
            code, out, err = run_case(args.binary, positive, args.timeout, *flags)
            problem = check(positive, code, out, err, strict=strict, allow_partial=True)
            if code != 4 or problem:
                print('FAIL pristine checkpoint positive: exit %r %s' % (code, problem))
                return 1
    fails = 0
    for n in range(args.start, args.start + args.seeds):
        rng = random.Random(n)
        recover = n % (len(SEED_DIRS) + 1) == len(SEED_DIRS)
        seed = SEED_DIRS[n % len(SEED_DIRS)] if not recover else SEED_DIRS[4]
        strict = bool(n % 2)
        flags = (("--allow-partial",) if recover else ()) + (("--strict",) if strict else ())
        families["checkpoint" if recover else seed] += 1
        tmp = tempfile.mkdtemp(prefix="mvfuzz")
        try:
            shutil.copy(os.path.join(REPO, seed, "session.json"),
                        os.path.join(tmp, "session.json"))
            with open(os.path.join(REPO, seed, "events.ndjson"), "rb") as fh:
                data = fh.read()
            if recover:
                checkpoint(tmp)
            metadata = "checkpoint.json" if recover else "session.json"
            if rng.random() < 0.2:
                with open(os.path.join(tmp, metadata), "rb") as fh:
                    sdata = fh.read()
                with open(os.path.join(tmp, metadata), "wb") as fh:
                    fh.write(mutate(rng, sdata))
                # Mutated session beside intact events: a valid
                # mutation proceeds through a complete capture
                # instead of tripping on a missing events file.
                with open(os.path.join(tmp, "events.ndjson"), "wb") as fh:
                    fh.write(data)
            else:
                with open(os.path.join(tmp, "events.ndjson"), "wb") as fh:
                    fh.write(mutate(rng, data))
            code, out, err = run_case(args.binary, tmp, args.timeout, *flags)
            outcomes[str(code)] += 1
            problem = check(tmp, code, out, err, strict=strict, allow_partial=recover)
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
    seed_hashes = {seed: {name: hashlib.sha256(Path(REPO, seed, name).read_bytes()).hexdigest()
                           for name in ('session.json', 'events.ndjson')} for seed in SEED_DIRS}
    receipt = dict(binary_sha256=digest, seed_sha256=seed_hashes, start=args.start, requested=args.seeds,
                   executed=ran, failures=fails, timeout=args.timeout,
                   elapsed_seconds=time.monotonic()-started, outcomes=dict(outcomes),
                   corpus_families=dict(families),
                   parser_branch_coverage=dict(status='NOT_MEASURED', reason=
                       'Pinned Mojo compiler exposes no documented coverage instrumentation; case counts are sampling, not branch coverage.'))
    if args.receipt:
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, sort_keys=True))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
