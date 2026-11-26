#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline exposure acceptance: the ten catalog scenarios.

Pure-offline acceptance over the Wave-1/Wave-2 exposure
fixtures, consumed read-only. Each of the ten catalog
scenarios loads its mapped case files through the
independent oracle (strict ledger validation plus the
positive self-check) inside an explicit time/growth budget
from ``tests/perf/exposure.py``. Two focused legs prove the
suite is not vacuous: fixed identical metadata with
different protected data yields identical metadata-only
findings, and a modeled unobservable host read leaves no
observable difference.

Non-vacuity proof: setting ``EXPOSURE_OFFLINE_PROOF`` to a
scenario id (``spec-01`` .. ``spec-10``) feeds that leg's
stated mutation into its passing assertions, so the leg
must FAIL. Live collection, live measurement and real-guest
legs are controller-owned and recorded here as explicit skips:
BLOCKED-not-attempted in the offline slice, never PASS. Suite
registration was the fourth handoff; it is complete, so its leg
asserts the dispatch instead of skipping.
"""

import copy
import importlib.util
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CASES = os.path.join(HERE, "cases")
MANIFEST = os.path.join(HERE, "cases.json")


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oracle = _load_module("exposure_oracle", os.path.join(HERE, "oracle.py"))
bounds = _load_module("exposure_bounds",
                      os.path.join(ROOT, "tests", "perf", "exposure.py"))

PROOF = os.environ.get("EXPOSURE_OFFLINE_PROOF", "")

SPEC_IDS = tuple("spec-%02d" % number for number in range(1, 11))

# Content-bearing key fragments: no offline acceptance input
# may carry guest content under any of these names.
CONTENT_KEYS = ("payload", "content", "secret", "plaintext", "ciphertext")


def manifest():
    return oracle.load_manifest(MANIFEST)


def spec_cases(spec_id):
    data = manifest()
    by_id = {entry["id"]: entry for entry in data["spec_scenarios"]}
    return by_id[spec_id]["cases"]


def case_path(case_id):
    data = manifest()
    by_id = {entry["id"]: entry for entry in data["cases"]}
    return os.path.join(HERE, by_id[case_id]["file"])


def proof_case(spec_id, case):
    """Empty the control flow when this scenario is proven.

    Mutation (all ten legs): drop every control-flow step from
    the in-memory case, so the derived event list is empty and
    the positive count assertions fail.
    """
    if PROOF in (spec_id, "all"):
        case = copy.deepcopy(case)
        case["control_flow"] = []
    return case


# Each scenario's mapped cases, in manifest order. The leg
# asserts this mapping (not just counts) so a swapped-in
# unrelated case fails instead of passing vacuously.
SCENARIO_CASES = {
    "spec-01": ("persistent-queue-traffic", "conversion-request-result",
                "bounced-and-direct-paths"),
    "spec-02": ("authored-policy-finding",),
    "spec-03": ("shared-to-private-lifecycle", "shared-heap-retention"),
    "spec-04": ("existing-sharing-baseline", "channel-lifetimes"),
    "spec-05": ("loss-and-bounds",),
    "spec-06": ("mapping-dax-inventory",),
    "spec-07": ("interface-activity", "tdx-ve-interface-activity"),
    "spec-08": ("egress-control-facts",),
    "spec-09": ("channel-lifetimes", "mapping-dax-inventory",
                "shared-heap-retention"),
    "spec-10": ("before-after-delta", "operator-walkthrough"),
}


def check_defining_outcome(case_id, case, summary, events):
    """Assert the defining outcome of one mapped case.

    Event counts and ledger partitions pass for any
    well-formed case, so each case additionally asserts the
    outcome that makes it that case: result codes, status
    transitions, generation advances and key actions.
    """
    assert summary["scenario"] == case_id, \
        "summary carries scenario %r for %r" % (summary["scenario"], case_id)
    groups = case["expectation"]
    results = [event["native_result"] for event in events]
    actions = [step["action"] for step in case["control_flow"]]
    before = {entry["object_token"]: entry for entry in case["before_ledger"]}
    after = {entry["object_token"]: entry for entry in case["after_ledger"]}
    if case_id == "persistent-queue-traffic":
        assert results == [0, 0, 0], "sustained traffic must stay clean"
        assert groups["transitioned"] == [] and groups["added"] == [] \
            and groups["removed"] == [], "zero new conversions expected"
        assert "confirm-zero-new-conversions" in actions
        assert "drive-steady-queue-traffic" in actions
        assert "drive-steady-control-traffic" in actions
        # The zero-conversion confirmation is only
        # meaningful after the sustained traffic it
        # reports on: a confirmation recorded before
        # either traffic step ran cannot establish that
        # the traffic completed with zero new
        # conversions. Both the sequence position and
        # the authored ordinal must put both traffic
        # steps first.
        flow = case["control_flow"]
        traffic_pos = [index for index, step in enumerate(flow)
                       if step["action"] in ("drive-steady-queue-traffic",
                                             "drive-steady-control-traffic")]
        confirm_pos = [index for index, step in enumerate(flow)
                       if step["action"] == "confirm-zero-new-conversions"]
        assert max(traffic_pos) < min(confirm_pos), \
            "sustained traffic must precede the zero-conversion confirmation"
        traffic_ord = [int(step["ordinal"]) for step in flow
                       if step["action"] in ("drive-steady-queue-traffic",
                                             "drive-steady-control-traffic")]
        confirm_ord = [int(step["ordinal"]) for step in flow
                       if step["action"] == "confirm-zero-new-conversions"]
        assert max(traffic_ord) < min(confirm_ord), \
            "sustained-traffic ordinal must precede the confirmation ordinal"
    elif case_id == "conversion-request-result":
        assert case["before_ledger"] == [] and case["after_ledger"] == []
        assert all(step["object"] == "none"
                   for step in case["control_flow"])
        # The case must show actually successful sustained
        # I/O, not just empty ledgers: the sustained-I/O step
        # itself must succeed, and so must the defining
        # observation. Success is per step, never pooled: a
        # failed sustain step with a clean observation (or the
        # reverse) is a failed leg, not a pass.
        sustain = [step for step in case["control_flow"]
                   if step["action"] == "sustain-io-no-conversion"]
        assert sustain and all(step["native_result"] == 0
                               for step in sustain), \
            "conversion request/result shows no successful sustained I/O"
        assert results == [0, 0], \
            "conversion request/result steps must both succeed"
        assert "sustain-io-no-conversion" in actions
        assert "observe-zero-new-conversions" in actions
        # The zero-conversion observation is only meaningful
        # after the sustained I/O it reports on: an
        # observation recorded before the I/O ran cannot
        # establish that the I/O completed with zero new
        # conversions. Both the sequence position and the
        # authored ordinal must put the sustained I/O first.
        flow = case["control_flow"]
        sustain_pos = [index for index, step in enumerate(flow)
                       if step["action"] == "sustain-io-no-conversion"]
        observe_pos = [index for index, step in enumerate(flow)
                       if step["action"] == "observe-zero-new-conversions"]
        assert max(sustain_pos) < min(observe_pos), \
            "sustained I/O must precede the zero-conversion observation"
        sustain_ord = [int(step["ordinal"]) for step in flow
                       if step["action"] == "sustain-io-no-conversion"]
        observe_ord = [int(step["ordinal"]) for step in flow
                       if step["action"] == "observe-zero-new-conversions"]
        assert max(sustain_ord) < min(observe_ord), \
            "sustained-I/O ordinal must precede the observation ordinal"
    elif case_id == "bounced-and-direct-paths":
        assert results == [0, 0, 0]
        assert "complete-bounced-segment" in actions
        assert "complete-admitted-direct-segment" in actions
        assert "confirm-outer-completion" in actions
        # The outer-completion confirmation is only
        # meaningful after both segments it confirms: a
        # confirmation recorded before either segment
        # completed cannot establish that both paths
        # finished. Both the sequence position and the
        # authored ordinal must put both segments first.
        flow = case["control_flow"]
        segment_pos = [index for index, step in enumerate(flow)
                       if step["action"] in ("complete-bounced-segment",
                                             "complete-admitted-direct-segment")]
        confirm_pos = [index for index, step in enumerate(flow)
                       if step["action"] == "confirm-outer-completion"]
        assert max(segment_pos) < min(confirm_pos), \
            "both segments must precede the outer-completion confirmation"
        segment_ord = [int(step["ordinal"]) for step in flow
                       if step["action"] in ("complete-bounced-segment",
                                             "complete-admitted-direct-segment")]
        confirm_ord = [int(step["ordinal"]) for step in flow
                       if step["action"] == "confirm-outer-completion"]
        assert max(segment_ord) < min(confirm_ord), \
            "segment ordinals must precede the confirmation ordinal"
    elif case_id == "authored-policy-finding":
        assert "trip-authored-rule" in actions
        assert "prove-lifecycle-violation" in actions
        assert "establish-known-deviation" in actions
        assert "admit-inconclusive-on-unknown" in actions
        assert groups["transitioned"] == []
    elif case_id == "shared-to-private-lifecycle":
        assert groups["transitioned"] == ["obj-stp-buf-1"]
        assert before["obj-stp-buf-1"]["generation"] == "1"
        assert after["obj-stp-buf-1"]["generation"] == "2"
        assert "convert-shared-to-private" in actions
    elif case_id == "shared-heap-retention":
        assert after["obj-shr-heap-1"]["status"] == "released"
        assert after["obj-shr-heap-2"]["status"] == "live"
        assert after["obj-shr-heap-3"]["status"] == "quarantined"
        assert sorted(results) == [-5, -5, 0, 0, 0, 0]
        assert "quarantine-unproved-pages" in actions
    elif case_id == "existing-sharing-baseline":
        assert groups["added"] == ["obj-esb-pre-1"]
        assert after["obj-esb-pre-1"]["status"] == "created"
        assert results == [0, 0, 0]
    elif case_id == "channel-lifetimes":
        assert len(events) == 6
        assert sorted(groups["transitioned"]) == ["obj-chl-chan-1",
                                                  "obj-chl-peer-1"]
        assert (before["obj-chl-peer-1"]["generation"],
                after["obj-chl-peer-1"]["generation"]) == ("1", "2")
        assert (before["obj-chl-chan-1"]["status"],
                after["obj-chl-chan-1"]["status"]) == ("created", "live")
        assert "confirm-generations-never-alias" in actions
    elif case_id == "loss-and-bounds":
        assert results == [0, -1, -13, -19, -12]
        assert groups["transitioned"] == ["obj-lb-detail-1"]
        assert after["obj-lb-detail-1"]["status"] == "unknown"
    elif case_id == "mapping-dax-inventory":
        pair1 = before["obj-mdx-pair-1"]
        pair2 = before["obj-mdx-pair-2"]
        assert (pair1["pages"], pair1["generation"]) == \
            (pair2["pages"], pair2["generation"])
        assert after["obj-mdx-pair-2"]["status"] == "unknown"
        assert "obj-mdx-pair-2" in groups["transitioned"]
        assert any(step["object"] == "obj-mdx-pair-2"
                   and step["operation"] == "op-mdx-protect-6"
                   and step["action"] == "probe-pair-protection-differs"
                   and step["native_result"] == -22
                   for step in case["control_flow"]), \
            "no protection probe on pair-2"
        assert groups["added"] == ["obj-mdx-unsupported-1"]
    elif case_id == "interface-activity":
        assert results == [0, -22, 0]
        assert "record-authored-native-rejection" in actions
    elif case_id == "tdx-ve-interface-activity":
        assert results == [0, -22, 0]
        assert "record-authored-native-rejection" in actions
    elif case_id == "egress-control-facts":
        assert len(events) == 7
        assert case["control_flow"][3]["action"] == \
            "model-host-read-without-trace-change"
        assert before == after
    elif case_id == "before-after-delta":
        assert len(events) == 9
        assert results.count(-22) == 3
        assert groups["added"] == ["obj-bad-right-1"]
        assert "reapply-rule-reordered" in actions
        assert "refuse-empty-scope-without-delta" in actions
    elif case_id == "operator-walkthrough":
        assert results == [0, 0, 0, 0]
        assert groups["added"] == ["obj-opw-seeded-1"]
        assert "explain-seeded-finding" in actions
    else:
        raise AssertionError("no defining outcome for %r" % case_id)


def run_spec_leg(spec_id):
    assert spec_id in SPEC_IDS, "unknown scenario %r" % (spec_id,)
    case_ids = spec_cases(spec_id)
    expected = SCENARIO_CASES[spec_id]
    assert tuple(case_ids) == expected, \
        "%s maps to %r, expected %r" % (spec_id, case_ids, list(expected))
    summaries = []
    for case_id in case_ids:
        case = oracle.load_case(case_path(case_id))
        case = proof_case(spec_id, case)
        assert case["scenario"] == case_id, \
            "case file for %r carries scenario %r" \
            % (case_id, case["scenario"])
        summary = oracle.verify_case(case)
        events = oracle.derive_events(case)
        assert len(events) == len(case["control_flow"]) > 0, \
            "%s: no derived events" % case_id
        # Ledger sizes stay informational only: request/result-only
        # cases legitimately carry empty ledgers, and the partition
        # re-derivation below (not a size check) guards vacuity.
        # The ledgers compared by the oracle are the authored
        # expectation: re-derive the partition here so a silent
        # ledger swap fails instead of passing vacuously.
        before = {entry["object_token"] for entry in case["before_ledger"]}
        after = {entry["object_token"] for entry in case["after_ledger"]}
        groups = case["expectation"]
        assert before == set(groups["conserved"] + groups["transitioned"]
                             + groups["removed"]), "%s: before split" % case_id
        assert after == set(groups["conserved"] + groups["transitioned"]
                            + groups["added"]), "%s: after split" % case_id
        check_defining_outcome(case_id, case, summary, events)
        summaries.append(summary)
    return summaries


def walk_keys(value, found):
    if isinstance(value, dict):
        for key, item in value.items():
            found.append(key)
            walk_keys(item, found)
    elif isinstance(value, list):
        for item in value:
            walk_keys(item, found)
    return found


def token_metadata_variant(case, token):
    """Project one ledger token to metadata scalars only (never content)."""
    return tuple((entry["generation"], entry["pages"])
                 for name in ("before_ledger", "after_ledger")
                 for entry in case[name]
                 if entry["object_token"] == token)


def metadata_finding(variant):
    """Derive a metadata-only finding summary from one token variant."""
    return (len(variant), tuple(sorted(variant)))


def test_manifest_covers_ten_scenarios():
    data = manifest()
    assert [entry["id"] for entry in data["spec_scenarios"]] == list(SPEC_IDS)
    assert len(data["cases"]) == 15


@pytest.mark.parametrize("spec_id", SPEC_IDS)
def test_spec_leg(spec_id):
    bounds.run_bounded(spec_id, run_spec_leg, spec_id)


def test_spec_06_identical_metadata_finding():
    # Mutation: perturb one variant's metadata copy (pages "2" ->
    # "3"), so the two metadata-only findings differ and the
    # equality assertion fails.
    def body():
        with open(case_path("mapping-dax-inventory"),
                  encoding="utf-8") as handle:
            raw = json.load(handle)
        case = oracle.load_case(case_path("mapping-dax-inventory"))
        before = {entry["object_token"]: entry
                  for entry in case["before_ledger"]}
        after = {entry["object_token"]: entry
                 for entry in case["after_ledger"]}
        first = before["obj-mdx-pair-1"]
        second = before["obj-mdx-pair-2"]
        assert (first["pages"], first["generation"]) == \
            (second["pages"], second["generation"]), \
            "equal-metadata pair differs in metadata"
        # The pair must actually differ in protection outcome:
        # pair-1 stays live while pair-2 transitions to unknown
        # through a denied protection probe.
        assert after["obj-mdx-pair-1"]["status"] == "live"
        assert after["obj-mdx-pair-2"]["status"] == "unknown", \
            "equal-metadata pair shows no protection difference"
        assert "obj-mdx-pair-2" in case["expectation"]["transitioned"]
        # The probe is the actual protection operation,
        # not any negative result on the second token.
        probes = [step for step in case["control_flow"]
                  if step["object"] == "obj-mdx-pair-2"
                  and step["operation"] == "op-mdx-protect-6"
                  and step["action"] == "probe-pair-protection-differs"
                  and step["native_result"] < 0]
        assert probes, "no denied protection probe on pair-2"
        for key in walk_keys(raw, []):
            lowered = key.lower()
            assert not any(fragment in lowered
                           for fragment in CONTENT_KEYS), \
                "content-bearing key %r in offline input" % (key,)
        oracle.scan_no_addresses(raw, "mapping-dax-inventory")
        variant_a = token_metadata_variant(case, "obj-mdx-pair-1")
        variant_b = token_metadata_variant(case, "obj-mdx-pair-2")
        assert variant_a and variant_b, "pair token missing from a ledger"
        if PROOF in ("spec-06", "all"):
            variant_b = (("1", "3"),) + tuple(variant_b[1:])
        assert metadata_finding(variant_a) == metadata_finding(variant_b), \
            "identical metadata yielded differing findings"

    bounds.run_bounded("spec-06-finding", body)


def test_spec_08_unobservable_host_read():
    # Mutation: change one re-read page count, so the first-read
    # and re-read facts differ and the indistinguishability
    # assertion fails.
    def body():
        case = oracle.load_case(case_path("egress-control-facts"))
        if PROOF in ("spec-08", "all"):
            case = copy.deepcopy(case)
            case["after_ledger"][3]["pages"] = "2"
        before = {entry["object_token"]: entry
                  for entry in case["before_ledger"]}
        after = {entry["object_token"]: entry
                  for entry in case["after_ledger"]}
        assert before == after, "modeled read changed the ledgers"
        pairs = (("obj-ecf-swap-1", "obj-ecf-swap-2"),
                 ("obj-ecf-dump-1", "obj-ecf-dump-2"),
                 ("obj-ecf-driver-1", "obj-ecf-driver-2"))
        for first_id, second_id in pairs:
            first, second = before[first_id], before[second_id]
            assert (first["pages"], first["generation"],
                    first["status"]) == (second["pages"],
                                         second["generation"],
                                         second["status"]), \
                "first read and re-read differ for %s" % first_id
        events = oracle.derive_events(case)
        assert len(events) == 7
        # The indistinguishability claim requires the modeled host
        # read itself: the fourth step must be that read, not just
        # any step that touches no ledger object.
        modeled = case["control_flow"][3]
        assert modeled["operation"] == "op-ecf-model-4", \
            "fourth step is not the modeled host read"
        assert modeled["action"] == "model-host-read-without-trace-change", \
            "fourth step is not the modeled host read"
        assert events[3]["object_token"] == "none", \
            "modeled step must touch no ledger object"
        for left, right in ((0, 4), (1, 5), (2, 6)):
            assert (events[left]["pages"], events[left]["native_result"]) \
                == (events[right]["pages"],
                    events[right]["native_result"]), \
                "trace events %d and %d differ" % (left + 1, right + 1)

    bounds.run_bounded("spec-08-reread", body)


def test_live_collection_leg():
    pytest.skip("controller-owned live collection: "
                "BLOCKED-not-attempted in the offline slice")


def test_live_perf_measurement_leg():
    pytest.skip("controller-owned live perf measurement: "
                "BLOCKED-not-attempted in the offline slice")


def test_suite_registration_leg():
    # Controller-completed handoff: the offline suites this lane
    # specified must be dispatched by tools/test (function + dispatch
    # entry each). Live legs below stay skipped, never passing.
    with open(os.path.join(ROOT, "tools", "test"),
              encoding="utf-8") as stream:
        runner = stream.read()
    for name in ("exposure-adversarial", "exposure-acceptance"):
        func = "suite_" + name.replace("-", "_")
        assert (func + "() {") in runner, name
        assert ("    " + name + ")\n"
                "        " + func) in runner, name


def test_real_guest_leg():
    pytest.skip("controller-owned real-guest leg: "
                "BLOCKED-not-attempted in the offline slice")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
