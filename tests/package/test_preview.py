#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Preview qualification: the built tree as release candidate.

Exercises every supported command through the built binary
(help, version, doctor, record refusal, report, top),
including denial, known-empty, and explicit-partial cases;
repeats the boundary negatives on this optimized binary;
and audits user docs for absolute claims versus visible
limitations. Bundle assembly stays in the package lane
(which needs a clean tree); this lane qualifies behavior.
Exits nonzero on the first failure.
"""

import hashlib
import os
import subprocess
import sys

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
BIN = os.path.join(REPO, "build", "memveil")
READER = os.path.join(REPO, "tests", "fixtures", "reader")
EMPTY = os.path.join(REPO, "tests", "package", "valid-empty")
ATTEMPTS = os.path.join(REPO, "tests", "fixtures", "attempts")

FORBIDDEN_CLAIMS = (
    "always-on", "complete terminal coverage",
    "fully qualified", "proves confidentiality",
    "attestation", "tamper-proof", "bank-grade",
)
# "attestation" needs a scoped exception: docs may only say it
# is NOT performed.
ATT_OK = "attestation\": \"not_performed"


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def run(args, **kw):
    return subprocess.run([BIN] + args, capture_output=True, text=True,
                          **kw)


def main():
    if not os.path.isfile(BIN):
        print("FAIL preview-package: missing %s (run tools/build first)"
              % BIN)
        sys.exit(1)
    with open(BIN, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    print("preview: binary %s sha256 %.16s..." % (BIN, digest))

    p = run(["help"])
    check("help", p.returncode == 0 and "usage:" in p.stdout)
    p = run(["version"])
    check("version", p.returncode == 0 and p.stdout.strip() != "",
          repr(p.stdout[:40]))
    print("preview: version %s" % p.stdout.strip())
    p = run(["doctor"])
    check("doctor", p.returncode in (0, 3), "exit %d" % p.returncode)
    p = run(["doctor", "--json"])
    check("doctor-json", p.returncode in (0, 3))

    p = run(["record", "--output", os.path.join(TESTS, "nope"),
             "--object", os.path.join(REPO, "tests", "fixtures",
                                      "elf", "ok.o")])
    check("denial", p.returncode == 3, "exit %d" % p.returncode)
    check("denial-stderr", p.stderr != "")

    p = run(["report", EMPTY])
    check("empty", p.returncode == 4, "exit %d" % p.returncode)
    check("empty-zeros", "bounce_attempts = 0 count" in p.stdout)
    check("empty-null", "successful_allocations = unavailable"
          in p.stdout)
    p = run(["report", ATTEMPTS])
    check("report", p.returncode in (0, 4), "exit %d" % p.returncode)
    p = run(["top", "--interval", "60s", ATTEMPTS])
    check("top", p.returncode in (0, 4), "exit %d" % p.returncode)
    p = run(["report", "--allow-partial",
             os.path.join(READER, "partial-tail")])
    check("partial", p.returncode == 4, "exit %d" % p.returncode)

    # Boundary negatives, repeated on this optimized binary.
    for name in ("compat-major", "badkind", "size-over",
                 "adv-bad-utf8", "adv-nul", "adv-reversed-seq",
                 "overflow", "corrupt-tail"):
        extra = ["--allow-partial"] if name == "corrupt-tail" else []
        p = run(["report"] + extra + [os.path.join(READER, name)])
        check("neg-%s" % name,
              p.returncode == 2 and p.stdout == "",
              "exit %d out %d" % (p.returncode, len(p.stdout)))

    # Claim-vs-receipt audit over user-facing docs.
    docs = [os.path.join(REPO, "README.md")]
    for root, _, files in os.walk(os.path.join(REPO, "docs")):
        for name in sorted(files):
            if name.endswith(".md"):
                docs.append(os.path.join(root, name))
    check("docs-present", len(docs) >= 5, "%d docs" % len(docs))
    for path in docs:
        text = open(path).read()
        rel = os.path.relpath(path, REPO)
        # The pools doc legitimately discusses pressure rules;
        # only absolute product claims are forbidden.
        for claim in FORBIDDEN_CLAIMS:
            if claim == "always-on":
                # May only appear beside an explicit negation.
                bad = [ln for ln in text.split("\n")
                       if "always-on" in ln.lower()
                       and "no always-on" not in ln.lower()]
                check("claim-%s-always-on" % rel, not bad,
                      "; ".join(bad[:2])[:120])
            elif claim == "attestation":
                # "attestation" may only appear beside an
                # explicit negation (it is never performed).
                bad = [ln for ln in text.split("\n")
                       if "attestation" in ln.lower()
                       and not any(neg in ln.lower() for neg in
                                   ("not_performed", "not performed",
                                    "any attestation", " no ",
                                    " not ", "unsupported"))]
                check("claim-%s-attestation" % rel, not bad,
                      "; ".join(bad[:2])[:120])
            else:
                check("claim-%s-%s" % (rel, claim[:12]),
                      claim not in text.lower())
    support = open(os.path.join(REPO, "docs", "support.md")).read()
    for phrase in ("partial", "out of scope"):
        check("support-%s" % phrase.replace(" ", "-"),
              phrase in support.lower())


if __name__ == "__main__":
    main()
