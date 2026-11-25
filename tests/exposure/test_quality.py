#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Source quality contracts: independence, unknown loss, offline purity.

Offline checks over ``fixtures/contracts/quality_matrix.json``: the
five quality channels evaluate independently, an unobserved loss
never collapses to a measured zero, and the evaluation itself is a
pure function of persisted bytes with no live dependency and no
hidden sidecars. The Rust lane modules implement the same contract;
this file is their independent oracle.
"""

import json
import os

import pytest

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(TESTS, "exposure", "fixtures", "contracts")

CHANNELS = ("detail", "aggregate", "identity", "baseline", "terminal")


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as handle:
        return json.load(handle)


def channel_usable(status):
    return status in ("complete_for_scope", "partial")


def loss_known(loss):
    return loss is not None


def evaluate_case(case):
    return [channel_usable(status) for status in case["statuses"]]


def test_quality_dimensions_independent():
    matrix = load("quality_matrix.json")
    assert len(matrix["cases"]) == 7, "settled plus five singles plus zero"
    for case in matrix["cases"]:
        assert list(case.keys()) == ["name", "statuses", "losses",
                                     "expected_usable"], case["name"]
        assert len(case["statuses"]) == 5, case["name"]
        assert evaluate_case(case) == case["expected_usable"], case["name"]
    singles = [case for case in matrix["cases"]
               if case["name"].startswith("only-")]
    assert len(singles) == 5
    for index, case in enumerate(singles):
        assert case["name"] == "only-" + CHANNELS[index] + "-unavailable"
        assert case["expected_usable"] == \
            [cell != index for cell in range(5)], case["name"]


def test_unknown_loss_is_not_zero():
    matrix = load("quality_matrix.json")
    by_name = {case["name"]: case for case in matrix["cases"]}
    zero = by_name["measured-zero-kept"]
    assert zero["losses"][0] == "0", "measured zero stays a string zero"
    assert loss_known(zero["losses"][0])
    assert loss_known(zero["losses"][2]), "measured loss stays known"
    assert evaluate_case(zero) == [True] * 5
    single = by_name["only-detail-unavailable"]
    assert single["losses"][0] is None, "unobserved loss stays null"
    assert not loss_known(single["losses"][0])
    assert single["losses"][1] == "0"
    assert loss_known(single["losses"][1])
    assert evaluate_case(single) == [False, True, True, True, True]


def test_offline_evaluation_is_deterministic_and_sidecar_free():
    before = sorted(os.listdir(FIX))
    first = [evaluate_case(case)
             for case in load("quality_matrix.json")["cases"]]
    second = [evaluate_case(case)
              for case in load("quality_matrix.json")["cases"]]
    assert first == second, "pure evaluation repeats exactly"
    assert sorted(os.listdir(FIX)) == before, "no sidecar files appear"
    for name in ("test_contracts.py", "test_quality.py"):
        with open(os.path.join(TESTS, "exposure", name),
                  encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        imports = sorted(line for line in lines
                         if line.startswith(("import ", "from ")))
        assert imports, "%s has no imports to audit" % name
        for statement in imports:
            # jsonschema is an offline document validator, not a live
            # dependency; everything else stays standard library.
            assert statement.split()[1].split(".")[0] in \
                ("hashlib", "json", "jsonschema", "os", "re",
                 "pytest"), statement


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
