#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Canary checks: hostile metadata renders neutralized, never raw.

Replays the privacy-canary capture (control bytes, terminal
sequences, and markdown-active punctuation in every
metadata-text channel) through report in all formats plus
top. No output may carry a raw ESC/BEL/DEL byte or a raw
control newline inside a rendered field; observer context
never renders at all; opaque identities refuse canary
punctuation at parse. Exits nonzero on the first failure.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
BIN = os.path.join(REPO, "build", "memveil")
CANARY = os.path.join(REPO, "tests", "fixtures", "reader", "privacy-canary")


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def run(args):
    return subprocess.run([BIN] + args, capture_output=True)


def main():
    if not os.path.isfile(BIN):
        print("FAIL canaries: missing %s (run tools/build first)" % BIN)
        sys.exit(1)

    outputs = {}
    for fmt in ("text", "markdown", "json"):
        p = run(["report", "--format", fmt, CANARY])
        check("canary-%s-exit" % fmt, p.returncode == 0,
              "exit %d: %s" % (p.returncode, p.stderr[:120]))
        outputs[fmt] = p.stdout
    p = run(["top", CANARY])
    check("canary-top-exit", p.returncode == 0, "exit %d" % p.returncode)
    outputs["top"] = p.stdout

    for name, blob in outputs.items():
        check("no-esc-%s" % name, b"\x1b" not in blob)
        check("no-bel-%s" % name, b"\x07" not in blob)
        check("no-del-%s" % name, b"\x7f" not in blob)
        # Observer context is execution context: it never renders.
        check("no-comm-%s" % name, b"MV-CANARY-COMM" not in blob)
        check("no-plain-comm-%s" % name, b"plain-comm" not in blob)

    # The driver canary's controls render neutralized in text.
    text = outputs["text"].decode("utf-8")
    check("text-newline", "MV-CANARY-DRIVER-L1\\nL2" in text)
    check("text-esc", "\x1b[2J" not in text)
    check("text-tab", "\\ttab" in text)

    # Markdown-active punctuation in the device name is escaped.
    md = outputs["markdown"].decode("utf-8")
    check("md-pipe", "pipe\\|tick" in md)
    check("md-tick", "tick\\`" in md)
    check("md-star", "star\\*" in md)
    check("md-brack", "brack\\[et\\]" in md)
    check("md-amp", "amp&amp;lt;" in md)
    # The name renders on one line: no raw pipe, no split row.
    check("md-no-raw-pipe", "pipe|tick" not in md)
    hits = [ln for ln in md.split("\n") if "MV-CANARY-NAME" in ln]
    check("md-one-line", len(hits) == 1, "%d lines" % len(hits))

    # JSON output parses and round-trips the escaped form.
    doc = json.loads(outputs["json"].decode("utf-8"))
    check("json-parses", isinstance(doc, dict))
    blob = outputs["json"]
    check("json-esc", b"\\u001b" in blob)
    check("json-del", b"\\u007f" in blob)

    # Opaque identities refuse canary punctuation at parse.
    tmp = tempfile.mkdtemp(prefix="mvcanary")
    try:
        shutil.copy(os.path.join(CANARY, "session.json"),
                    os.path.join(tmp, "session.json"))
        with open(os.path.join(CANARY, "events.ndjson")) as fh:
            line = fh.readline()
        hostile = line.replace('"op-1"', '"op|1`$(id)"')
        with open(os.path.join(tmp, "events.ndjson"), "w") as fh:
            fh.write(hostile)
        p = run(["report", tmp])
        check("opaque-refuses", p.returncode == 2,
              "exit %d" % p.returncode)
        check("opaque-silent", p.stdout == b"")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Stderr diagnostics scrub directory components: an echoed
    # argument keeps only its basename, never home layout.
    p = run(["record", "/home/canary-alice/evil"])
    check("stderr-arg-exit", p.returncode == 2, "exit %d" % p.returncode)
    check("stderr-arg-basename",
          b"unexpected argument: evil" in p.stderr, p.stderr[:200])
    check("stderr-no-user", b"canary-alice" not in p.stderr)
    check("stderr-no-home", b"/home/" not in p.stderr)
    check("stderr-arg-silent", p.stdout == b"")


if __name__ == "__main__":
    main()
