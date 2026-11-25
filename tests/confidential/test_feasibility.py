#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validator for the confidential-guest source feasibility matrix.

Checks the sibling ``feasibility.json`` against the frozen exposure
catalog: exact per-source/per-cell coverage, catalog vocabulary,
per-row evidence contracts, verdict/reason consistency, and the
no-claims guard. The guard rejects any platform milestone id, any
non-negated admission wording anywhere in the matrix, and any PASS
proof state in the row proof columns or the top-level proof_status.

Runs two ways: ``python3 -m pytest test_feasibility.py`` for the
regression suite, or ``python3 test_feasibility.py [matrix catalog]``
as a RED/GREEN command. With no arguments it self-checks the
committed matrix plus every RED/GREEN rejection scenario.
"""

import json
import os
import sys
import tempfile

try:
    import pytest
    _parametrize = pytest.mark.parametrize
except ImportError:  # direct run on a box without pytest
    pytest = None

    def _parametrize(*args, **kwargs):
        def wrap(func):
            return func
        return wrap


HERE = os.path.dirname(os.path.abspath(__file__))
MATRIX_PATH = os.path.join(HERE, "feasibility.json")
CATALOG_PATH = os.path.join(
    HERE, "..", "..", "profiles", "exposure", "catalog.json")

REQUIRED_CELLS = ("sev-snp", "tdx-standalone", "hyper-v")

VERDICT_REASONS = {
    "feasible-unproven": "cell-unselected",
    "blocked-no-lease": "lease-pending",
    "no-safe-source": "no-safe-source",
    "not-applicable": "not-applicable-platform",
}

ROW_COLUMNS = ("availability", "verifier_acceptance", "real_semantics")

MILESTONE_IDS = (
    "snp_admitted", "tdx_admitted", "hyperv_admitted", "catalog_frozen")

NEGATED_ADMISSION = (
    "no admitted cell selected", "no admitted cell is selected")


def _load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def validate(matrix_path, catalog_path):
    """Return a list of finding strings; empty means GREEN."""
    errors = []
    try:
        matrix = _load(matrix_path)
    except (OSError, ValueError) as exc:
        return ["cannot read matrix %s: %s" % (matrix_path, exc)]
    try:
        catalog = _load(catalog_path)
    except (OSError, ValueError) as exc:
        return ["cannot read catalog %s: %s" % (catalog_path, exc)]

    rows = matrix.get("rows")
    if not rows:
        return ["no rows: matrix is empty"]

    catalog_version = catalog.get("exposure_catalog_version")
    if matrix.get("catalog_version") != catalog_version:
        errors.append("catalog_version %r does not match catalog %r" % (
            matrix.get("catalog_version"), catalog_version))

    source_capability = {entry["source_id"]: entry["capability"]
                         for entry in catalog.get("sources", [])}
    reason_codes = {entry["code"]
                    for entry in catalog.get("source_reasons", [])}
    cell_capabilities = {entry["cell"]: set(entry.get("for_capabilities", ()))
                         for entry in catalog.get("platforms", [])}
    declared_refs = {entry.get("source_ref")
                     for entry in matrix.get("sources_reviewed", [])}

    seen = set()
    for index, row in enumerate(rows):
        label = "row %d" % index
        for key in ("source_id", "capability", "cell", "verdict", "reason",
                    "availability", "verifier_acceptance", "real_semantics",
                    "evidence", "lease_gated", "reviewer_notes"):
            if key not in row:
                errors.append("%s: missing %r" % (label, key))
        source_id = row.get("source_id")
        capability = row.get("capability")
        cell = row.get("cell")
        verdict = row.get("verdict")
        reason = row.get("reason")
        if source_id not in source_capability:
            errors.append("%s: unknown source_id %r" % (label, source_id))
        elif capability != source_capability[source_id]:
            errors.append("%s: capability %r is not the catalog one %r" % (
                label, capability, source_capability[source_id]))
        if cell not in REQUIRED_CELLS:
            errors.append("%s: cell %r is not required" % (label, cell))
        elif capability not in cell_capabilities.get(cell, ()):
            errors.append("%s: capability %r is not listed for cell %r" % (
                label, capability, cell))
        if verdict not in VERDICT_REASONS:
            errors.append("%s: unknown verdict %r" % (label, verdict))
        if reason not in reason_codes:
            errors.append("%s: unknown reason %r" % (label, reason))
        if (verdict in VERDICT_REASONS and reason in reason_codes
                and VERDICT_REASONS[verdict] != reason):
            errors.append("%s: verdict %r needs reason %r, has %r" % (
                label, verdict, VERDICT_REASONS[verdict], reason))
        for column in ROW_COLUMNS:
            value = row.get(column)
            if verdict == "not-applicable":
                if value != "not-applicable":
                    errors.append("%s: %s must stay not-applicable, has %r"
                                  % (label, column, value))
            elif not value:
                errors.append("%s: empty %s" % (label, column))
        for column in ("verifier_acceptance", "real_semantics"):
            value = row.get(column)
            if isinstance(value, str) and value.strip().lower() == "pass":
                errors.append("%s: %s claims PASS without proof"
                              % (label, column))
        evidence = row.get("evidence")
        if not evidence:
            errors.append("%s: empty evidence" % label)
        else:
            for entry in evidence:
                if entry.get("source_ref") not in declared_refs:
                    errors.append("%s: evidence cites undeclared source %r"
                                  % (label, entry.get("source_ref")))
                if not entry.get("pointer") or not entry.get("what"):
                    errors.append("%s: evidence needs pointer and what"
                                  % label)
        if not isinstance(row.get("lease_gated"), list):
            errors.append("%s: lease_gated must be a list" % label)
        if not row.get("reviewer_notes"):
            errors.append("%s: empty reviewer_notes" % label)
        key = (source_id, cell)
        if key in seen:
            errors.append("duplicate row for %s/%s" % (source_id, cell))
        seen.add(key)

    want = {(source_id, cell) for source_id in source_capability
            for cell in REQUIRED_CELLS}
    if seen != want:
        missing = sorted(want - seen)
        extra = sorted(seen - want)
        if missing:
            errors.append("missing %d row(s), first %s/%s"
                          % (len(missing), missing[0][0], missing[0][1]))
        if extra:
            errors.append("unexpected %d row(s), first %s/%s"
                          % (len(extra), extra[0][0], extra[0][1]))

    proof_status = matrix.get("proof_status")
    if isinstance(proof_status, dict):
        for key, value in proof_status.items():
            if isinstance(value, str) and value.strip().lower() == "pass":
                errors.append("proof_status %r claims PASS without proof"
                              % (key,))

    blob = json.dumps(matrix, sort_keys=True).lower()
    for milestone in MILESTONE_IDS:
        if milestone in blob:
            errors.append("matrix claims milestone id %s" % milestone)
    scrubbed = blob
    for negation in NEGATED_ADMISSION:
        scrubbed = scrubbed.replace(negation, "")
    if "admitted" in scrubbed:
        errors.append("matrix contains a non-negated admission claim")

    return errors


def summarize(matrix_path):
    matrix = _load(matrix_path)
    rows = matrix.get("rows", [])
    sources = {row.get("source_id") for row in rows}
    cells = {row.get("cell") for row in rows}
    return "GREEN: %d rows cover %d sources x %d cells" % (
        len(rows), len(sources), len(cells))


def _write(tmpdir, name, obj):
    path = os.path.join(tmpdir, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle, indent=2, sort_keys=True)
    return path


def _mutated(tmpdir, name, change):
    matrix = _load(MATRIX_PATH)
    change(matrix)
    return _write(tmpdir, name, matrix)


def check_green():
    assert validate(MATRIX_PATH, CATALOG_PATH) == []


def check_empty_red(tmpdir):
    path = _write(tmpdir, "empty.json", {"rows": []})
    errors = validate(path, CATALOG_PATH)
    assert errors and errors[0].startswith("no rows"), errors


def check_milestone_red(tmpdir, milestone):
    def plant(matrix):
        matrix["rows"][0]["claim"] = "%s: PASS" % milestone
    path = _mutated(tmpdir, "mut-%s.json" % milestone, plant)
    errors = validate(path, CATALOG_PATH)
    assert any(milestone in error for error in errors), errors


def check_admission_red(tmpdir):
    def plant(matrix):
        matrix["rows"][0]["reviewer_notes"] = (
            "The cell is admitted for this source.")
    path = _mutated(tmpdir, "mut-admitted.json", plant)
    errors = validate(path, CATALOG_PATH)
    assert any("admission claim" in error for error in errors), errors


def check_negation_ok(tmpdir):
    def plant(matrix):
        matrix["rows"][2]["reviewer_notes"] += " No admitted cell selected."
    path = _mutated(tmpdir, "negation.json", plant)
    assert validate(path, CATALOG_PATH) == []


def check_coverage_red(tmpdir):
    def drop(matrix):
        matrix["rows"] = matrix["rows"][:-1]
    path = _mutated(tmpdir, "dropped.json", drop)
    errors = validate(path, CATALOG_PATH)
    assert any("missing" in error for error in errors), errors


def check_reason_red(tmpdir):
    def flip(matrix):
        matrix["rows"][0]["reason"] = "lease-pending"
    path = _mutated(tmpdir, "reason.json", flip)
    errors = validate(path, CATALOG_PATH)
    assert any("needs reason" in error for error in errors), errors


def check_proof_columns_red(tmpdir):
    def plant(matrix):
        matrix["rows"][0].update(verifier_acceptance="PASS",
                                 real_semantics="PASS")
    path = _mutated(tmpdir, "mut-proof-cols.json", plant)
    errors = validate(path, CATALOG_PATH)
    assert any("claims PASS" in error for error in errors), errors


def check_proof_single_column_red(tmpdir, column):
    def plant(matrix):
        matrix["rows"][0][column] = "PASS"
    path = _mutated(tmpdir, "mut-%s.json" % column, plant)
    errors = validate(path, CATALOG_PATH)
    assert any("claims PASS" in error for error in errors), errors


def check_proof_status_red(tmpdir):
    def plant(matrix):
        matrix["proof_status"] = dict.fromkeys(matrix["proof_status"], "PASS")
    path = _mutated(tmpdir, "mut-proof-status.json", plant)
    errors = validate(path, CATALOG_PATH)
    assert any("proof_status" in error for error in errors), errors


def run_self_checks():
    failed = 0
    with tempfile.TemporaryDirectory() as tmpdir:
        scenarios = [
            ("green", lambda: check_green()),
            ("empty-red", lambda: check_empty_red(tmpdir)),
            ("milestone-red", lambda: [check_milestone_red(tmpdir, mid)
                                       for mid in MILESTONE_IDS]),
            ("admission-red", lambda: check_admission_red(tmpdir)),
            ("negation-ok", lambda: check_negation_ok(tmpdir)),
            ("coverage-red", lambda: check_coverage_red(tmpdir)),
            ("reason-red", lambda: check_reason_red(tmpdir)),
            ("proof-columns-red",
             lambda: check_proof_columns_red(tmpdir)),
            ("proof-each-column-red",
             lambda: [check_proof_single_column_red(tmpdir, column)
                      for column in ("verifier_acceptance",
                                     "real_semantics")]),
            ("proof-status-red", lambda: check_proof_status_red(tmpdir)),
        ]
        for label, scenario in scenarios:
            try:
                scenario()
            except AssertionError as exc:
                print("FAIL %s: %s" % (label, exc))
                failed += 1
                continue
            print("ok %s" % label)
    if failed:
        return 1
    print(summarize(MATRIX_PATH))
    return 0


def main(argv):
    if argv:
        matrix_path = argv[0]
        catalog_path = argv[1] if len(argv) > 1 else CATALOG_PATH
        errors = validate(matrix_path, catalog_path)
        if errors:
            print("RED: %s" % errors[0])
            return 1
        print(summarize(matrix_path))
        return 0
    return run_self_checks()


def test_committed_matrix_is_green():
    check_green()


def test_empty_matrix_is_red(tmp_path):
    check_empty_red(str(tmp_path))


@_parametrize("milestone", MILESTONE_IDS)
def test_milestone_ids_rejected(tmp_path, milestone):
    check_milestone_red(str(tmp_path), milestone)


def test_plain_admission_claim_rejected(tmp_path):
    check_admission_red(str(tmp_path))


def test_negated_admission_accepted(tmp_path):
    check_negation_ok(str(tmp_path))


def test_dropped_row_breaks_coverage(tmp_path):
    check_coverage_red(str(tmp_path))


def test_verdict_reason_mismatch_rejected(tmp_path):
    check_reason_red(str(tmp_path))


def test_proof_columns_reject_pass(tmp_path):
    check_proof_columns_red(str(tmp_path))


@_parametrize("column", ["verifier_acceptance", "real_semantics"])
def test_each_proof_column_rejects_pass(tmp_path, column):
    check_proof_single_column_red(str(tmp_path), column)


def test_proof_status_rejects_pass(tmp_path):
    check_proof_status_red(str(tmp_path))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
