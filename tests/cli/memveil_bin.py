#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""One binary selector for the CLI Python drivers.

Mirrors tools/test's memveil_bin/rust_bin_setup exactly, so the
binary the runner blesses is provably the binary each driver
executes:

- MEMVEIL_BIN set to a value containing a slash: it must name
  an executable file, used verbatim (no rebuild, no relink, no
  default fallback).
- MEMVEIL_BIN set to a bare name: looked up on PATH, left to
  right, resolving to an absolute canonical path. The lookup is
  explicit so validation and dispatch cannot disagree about
  which file a bare name means. An empty PATH entry means the
  current directory; an unset or empty PATH refuses every bare
  name.
- MEMVEIL_BIN unset: the build/memveil default (which tools/test
  links at the release binary before dispatch).
- MEMVEIL_BIN set to anything else (missing, not a file, not
  executable, empty, unresolvable on PATH): refuse loudly before
  dispatch (a stderr diagnostic naming the value, then
  SystemExit 1), never silently fall back to the default.

Every tests/cli driver resolves its BIN through
resolve_memveil_bin().
"""

import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BIN = str(ROOT / "build" / "memveil")


def resolve_memveil_bin():
    """Return the binary under test: MEMVEIL_BIN or the default.

    A set-but-unusable knob refuses with SystemExit(1) after a
    stderr diagnostic, matching tools/test's fail-closed setup.
    """
    knob = os.environ.get("MEMVEIL_BIN")
    if knob is None:
        return DEFAULT_BIN
    if "/" in knob:
        if os.path.isfile(knob) and os.access(knob, os.X_OK):
            return knob
    else:
        # Bare name: explicit PATH lookup, mirroring the
        # runner's resolver (an unset or empty PATH refuses
        # every bare name on both sides), then resolved to
        # an absolute canonical path.
        found = shutil.which(knob, path=os.environ.get("PATH", ""))
        if found is not None:
            resolved = os.path.realpath(found)
            if os.path.isfile(resolved) and os.access(resolved, os.X_OK):
                return resolved
    print("memveil_bin: MEMVEIL_BIN=%s missing or not executable"
          % knob, file=sys.stderr)
    raise SystemExit(1)
