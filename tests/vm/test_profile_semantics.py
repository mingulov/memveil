#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Hook-definition admission tests over JSON fixtures.

Every fixture carries its expected verdict; the comparator
must admit the two ok shapes and refuse each negative with
the expected reason. Default deny and effective-length rules
have dedicated cases.
"""

import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from semantics import MAX_ADAPTER_BYTES, admit, effective_length

SEMANTICS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "semantics")


def test_fixtures():
    paths = sorted(glob.glob(os.path.join(SEMANTICS, "*.json")))
    assert len(paths) == 15, paths
    for path in paths:
        with open(path) as handle:
            case = json.load(handle)
        ok, reason = admit(case["definition"], case["recorded"])
        name = os.path.basename(path)
        assert ok == case["expect_ok"], (name, reason)
        if not ok:
            assert case["expect_reason"] in reason, (name, reason)


def test_max_adapter_bytes():
    assert MAX_ADAPTER_BYTES == 2048


def test_default_deny_empty():
    ok, reason = admit({}, {})
    assert not ok
    assert "missing field" in reason


def test_effective_length():
    src = ("// comment\n"
           "\n"
           "int x = 1; // trailing stays\n"
           "# hash comment\n"
           "int y = 2;\n")
    assert effective_length(src) == len("int x = 1; // trailing stays\n") \
        + len("int y = 2;\n")
    assert effective_length("") == 0
    # Flags and blank/comment reshuffles never change it.
    assert effective_length("\n\n// only comments\n") == 0
