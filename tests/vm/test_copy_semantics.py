#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Copy semantics in the disposable VM.

Verifies request-vs-copy accounting on live traffic: sync
requests alone add no copy bytes, nested copies before a map
result stay counted, and copies under a failed mapping survive
while the failure creates no mapping.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lifecycle_env import COPY_PROBE, LIFECYCLE_PROBE
from lifecycle_env import require_lifecycle_env


def test_copy_semantics():
    require_lifecycle_env(LIFECYCLE_PROBE, COPY_PROBE)
    pytest.fail("copy semantics gate not yet implemented")
