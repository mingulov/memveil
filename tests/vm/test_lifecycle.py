#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Low-rate lifecycle matrix in the disposable VM.

Loads the oracle module at stepped rates (1, 10, 100 maps/s),
captures with the lifecycle probes, and compares every report
against the oracle ledger with zero tolerated mismatches. Also
checks the effective-copy equality at each step.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lifecycle_env import LIFECYCLE_PROBE, require_lifecycle_env


def test_low_rate_matrix():
    require_lifecycle_env(LIFECYCLE_PROBE)
    pytest.fail("low-rate lifecycle matrix not yet implemented")
