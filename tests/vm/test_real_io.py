#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real block/vnet I/O slice in the disposable VM.

Runs real block and vnet I/O through the swiotlb path with the
lifecycle probes attached and checks that captures stay
internally consistent (no orphan releases, live bytes
reconcilable, completed lifetimes sane). No fixture traffic:
the workload is ordinary guest I/O.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lifecycle_env import COPY_PROBE, LIFECYCLE_PROBE
from lifecycle_env import require_lifecycle_env


def test_real_io_slice():
    require_lifecycle_env(LIFECYCLE_PROBE, COPY_PROBE)
    pytest.fail("real I/O slice gate not yet implemented")
