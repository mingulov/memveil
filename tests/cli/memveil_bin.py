#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""One binary selector for the CLI Python drivers (R82).

Mirrors tools/test's memveil_bin/rust_bin_setup exactly, so the
binary the runner blesses is provably the binary each driver
executes:

- MEMVEIL_BIN set and naming an executable file: use it verbatim
  (no rebuild, no relink, no default fallback).
- MEMVEIL_BIN unset: the build/memveil default (which tools/test
  links at the release binary before dispatch).
- MEMVEIL_BIN set to anything else (missing, not a file, not
  executable, empty): refuse loudly before dispatch (a stderr
  diagnostic naming the value, then SystemExit 1), never
  silently fall back to the default.

Every tests/cli driver resolves its BIN through
resolve_memveil_bin(), closing the R81 divergence where setup
blessed the knob binary while the drivers ran build/memveil.
"""

import os
from pathlib import Path
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
    if os.path.isfile(knob) and os.access(knob, os.X_OK):
        return knob
    print("memveil_bin: MEMVEIL_BIN=%s missing or not executable"
          % knob, file=sys.stderr)
    raise SystemExit(1)
