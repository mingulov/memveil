#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Journal CLI matrix: admission precedes all native resource creation.

Ports the old selector checks to the Rust CLI: journal selections
refuse with the frozen admission code (exit 3) before any output or
native resource exists, malformed selectors are usage errors
(exit 2), and conversion-observe stays channel-less. Also pins the
capability-parser compatibility change: duplicate names are usage
errors, and ordinary channels resolve the attempt base implicitly.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "cli"))
from memveil_bin import resolve_memveil_bin  # noqa: E402


def fail(message):
    print("test_cli: %s" % message, file=sys.stderr)
    sys.exit(1)


def run(binary, args):
    try:
        return subprocess.run([binary] + args, capture_output=True, text=True,
                              cwd=str(ROOT), timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail("cannot run %s %s: %s" % (binary, args, exc))


def main():
    binary = resolve_memveil_bin()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for verb in ("record", "top", "qualify"):
            base = [binary, verb, "--output", str(tmp / verb)]
            for extra, expected, reason in [
                (["--capability", "conversion-journal"], 3,
                 "journal_profile_not_admitted"),
                (["--capability", "conversion-journal", "--journal-callers"],
                 3, "journal_profile_not_admitted"),
                (["--capability", "conversion-journal", "--journal-object",
                  "absent.o"], 3, "journal_profile_not_admitted"),
                (["--capability", "attempt-trace,conversion-journal",
                  "--journal-callers"], 3, "journal_profile_not_admitted"),
                (["--journal-callers"], 2, "requires conversion-journal"),
                (["--journal-object", "absent.o"], 2,
                 "requires conversion-journal"),
                (["--unknown-journal-control"], 2, "unknown option"),
                (["--capability", "attempt-trace,attempt-trace"], 2,
                 "duplicate capability: attempt-trace"),
                (["--capability", "conversion-observe",
                  "--profiles-dir", "profiles",
                  "--object", "tests/fixtures/elf/ok.o"], 3,
                 "conversion-observe has no record channel"),
            ]:
                got = run(binary, [verb, "--output", str(tmp / verb)] + extra)
                if got.returncode != expected or reason not in got.stderr:
                    fail("%s %s: want exit %d with %r, got exit %d: %r"
                         % (verb, extra, expected, reason, got.returncode,
                            got.stderr))
                if (tmp / verb).exists():
                    fail("%s %s created output on refusal" % (verb, extra))
        # Pure-journal collection rejects device filtering (exit 2);
        # mixed collection keeps ordinary filtering.
        for verb in ("record", "top"):
            got = run(binary, [verb, "--output", str(tmp / "pure"),
                               "--capability", "conversion-journal",
                               "--device", "device"])
            if got.returncode != 2 or "global" not in got.stderr:
                fail("%s pure journal + device: want exit 2 naming the "
                     "global scope, got exit %d: %r"
                     % (verb, got.returncode, got.stderr))
        # Lifecycle-only resolves the attempt base instead of naming
        # the old missing-base refusal: it must reach profile
        # loading (exit 3), not fail capability parsing (exit 2).
        # The Rust parser test pins the resolution itself; this
        # leg pins the end-to-end exit shape.
        got = run(binary, ["record", "--output", str(tmp / "lc"),
                           "--capability", "mapping-lifecycle",
                           "--profiles-dir", str(tmp / "empty-profiles")])
        if got.returncode != 3:
            fail("lifecycle-only: want exit 3 past capability parsing, "
                 "got exit %d: %r" % (got.returncode, got.stderr))
        if "attempt-trace is required" in got.stderr:
            fail("lifecycle-only still names the retired refusal: %r"
                 % got.stderr)
    print("journal CLI: frozen admission, usage matrix, observe refusal, "
          "device control, and capability compat passed")


if __name__ == "__main__":
    main()
