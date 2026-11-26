#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline exposure adversarial checks: harness negatives and limits.

Pure-offline self-tests over the Wave-1/Wave-2 exposure
fixtures, consumed read-only. Every fixture is loaded into
memory and only the in-memory copy is ever mutated; no test
writes to the fixture tree, the catalog, or any product
source. Each check has a passing leg over intact data and a
refusing leg over mutated data, and every check runs inside
an explicit time/growth budget from
``tests/perf/exposure.py``: over-budget work fails.

Non-vacuity proof: setting ``EXPOSURE_OFFLINE_PROOF`` to a
family name (or ``all``) feeds that family's stated mutation
into its passing leg, so the check must FAIL. Each test
names its exact mutation in a comment below.

Covered families: wrong hashes, empty/missing ledger,
unarmed gate, wrong platform, hidden rebuild,
kill/recovery/checkpoint mutation, scan/reference side
effects, lost final events, map/edge exhaustion,
generation wrap, clocks, concurrent activity, denied
sources.
"""

import copy
import hashlib
import importlib.util
import json
import os
import threading

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CASES = os.path.join(HERE, "cases")
CONTRACTS = os.path.join(HERE, "fixtures", "contracts")
COMPARE = os.path.join(HERE, "fixtures", "compare")
CATALOG = os.path.join(ROOT, "profiles", "exposure", "catalog.json")


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oracle = _load_module("exposure_oracle", os.path.join(HERE, "oracle.py"))
bounds = _load_module("exposure_bounds",
                      os.path.join(ROOT, "tests", "perf", "exposure.py"))

# Active non-vacuity proof: "" runs every passing leg over
# intact data; a family name (or "all") injects that family's
# stated mutation into its passing leg so the test must fail.
PROOF = os.environ.get("EXPOSURE_OFFLINE_PROOF", "")

FAMILIES = (
    "wrong-hash", "empty-ledger", "missing-ledger", "unarmed-gate",
    "wrong-platform", "hidden-rebuild", "kill-recovery",
    "scan-side-effects", "lost-final", "map-exhaustion",
    "generation-wrap", "clocks", "concurrent", "denied-sources",
)


class GateRefused(ValueError):
    """A gated evaluation was attempted without arming."""


class PlatformRefused(ValueError):
    """A platform cell outside the frozen catalog was requested."""


class DigestMismatch(ValueError):
    """Recorded bytes no longer match their recorded digest."""


class TruncatedCapture(ValueError):
    """A sealed capture lost lines or its checkpoint disagrees."""


class OrdinalBreak(ValueError):
    """An event stream is not contiguous 1..N in order."""


class DeniedComplete(ValueError):
    """A denied/absent source was reported as a complete result."""


def proof_input(family, value, mutate):
    """Return the control input, mutated when this family is proven."""
    if PROOF in (family, "all"):
        return mutate(copy.deepcopy(value))
    return value


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def require_armed(record):
    """Proceed only with an explicit arming record; else refuse."""
    if not isinstance(record, dict) or record.get("armed") is not True:
        raise GateRefused("evaluation attempted without an arming record")
    scope = record.get("scope")
    if not isinstance(scope, str) or not scope:
        raise GateRefused("arming record carries no scope")
    return scope


def catalog_cells():
    """Return the frozen platform cells (catalog read-only)."""
    return [entry["cell"] for entry in load_json(CATALOG)["platforms"]]


def check_platform(cell):
    """Accept only a frozen catalog cell; else refuse."""
    if cell not in catalog_cells():
        raise PlatformRefused("platform %r is outside the catalog" % (cell,))
    return cell


def verify_bytes_digest(digest, data):
    """Refuse when bytes no longer match their recorded digest."""
    if hashlib.sha256(data).hexdigest() != digest:
        raise DigestMismatch("bytes differ from the recorded digest")
    return True


def check_seq_continuity(lines):
    """Require contiguous seq 0..N-1 across sealed event lines."""
    seqs = [str(json.loads(line)["seq"]) for line in lines]
    if seqs != [str(position) for position in range(len(lines))]:
        raise TruncatedCapture("event seqs are not contiguous: %r" % (seqs,))
    return len(lines)


def verify_finalized(lines, integrity):
    """Refuse a sealed capture whose lines or checkpoint disagree."""
    check_seq_continuity(lines)
    if len(lines) != int(integrity["line_count"]):
        raise TruncatedCapture("line count differs from the checkpoint")
    if str(len(lines) - 1) != str(integrity["last_seq"]):
        raise TruncatedCapture("last seq differs from the checkpoint")
    literal = "".join(lines).encode("utf-8")
    if len(literal) != int(integrity["events_bytes"]):
        raise TruncatedCapture("sealed byte count differs from the checkpoint")
    if hashlib.sha256(literal).hexdigest() != integrity["events_sha256"]:
        raise TruncatedCapture("event bytes differ from the checkpoint")
    return True


def find_added(before, after):
    """Return listing entries that appeared after the scan."""
    return sorted(set(after) - set(before))


def check_ordinals(events):
    """Require contiguous ordinals 1..N across derived events."""
    ordinals = [event["ordinal"] for event in events]
    if ordinals != [str(position) for position in range(1, len(events) + 1)]:
        raise OrdinalBreak("ordinals are not contiguous 1..N: %r" % (ordinals,))
    return len(events)


# ASCII whitespace for the shared blank definition:
# space, tab, line feed, carriage return, vertical tab,
# form feed. Mirrors the comparison contract so both sides
# always agree on what counts as a blank clock domain.
ASCII_WHITESPACE = " \t\n\r\x0b\x0c"


def is_blank(value):
    """A clock domain counts as blank when it is empty or every
    character is ASCII whitespace. Mirrors the comparison
    contract: a whitespace-only domain names no clock."""
    return isinstance(value, str) and (
        value == "" or all(char in ASCII_WHITESPACE for char in value))


def clocks_compatible(left, right):
    """Independently decide whether two compare windows may compare.

    Returns (True, "compatible") only when both windows carry
    well-formed bounds in the same non-blank clock domain;
    otherwise returns (False, reason) and never guesses.
    """
    for side in (left, right):
        window = side.get("window", {})
        start, end = window.get("start"), window.get("end")
        domain = window.get("clock_domain")
        if not oracle.is_canonical_u64(start) \
                or not oracle.is_canonical_u64(end):
            return False, "window-not-canonical"
        if int(end) < int(start):
            return False, "window-reversed"
        if not isinstance(domain, str) or is_blank(domain):
            return False, "clock-blank"
    if left["window"]["clock_domain"] != right["window"]["clock_domain"]:
        return False, "clock-mismatch"
    return True, "compatible"


def check_denied_partial(case):
    """Require denied/absent objects to stay a scoped partial result."""
    after = {entry["object_token"]: entry for entry in case["after_ledger"]}
    for event in oracle.derive_events(case):
        if event["object_token"] == "none":
            continue
        if event["native_result"] < 0 \
                and after[event["object_token"]]["status"] != "unknown":
            raise DeniedComplete(
                "object %r hit native result %d yet is not unknown"
                % (event["object_token"], event["native_result"]))
    return True


def fixture_tree_files():
    """List every consumed fixture file plus the frozen catalog.

    The platform checks read the catalog, so the snapshot must
    cover it: a post-snapshot catalog change is a hidden rebuild.
    Read-only walk; nothing here is ever written.
    """
    roots = [CASES, COMPARE, CONTRACTS,
             os.path.join(HERE, "fixtures", "policy")]
    found = []
    for root in roots:
        for name in sorted(os.listdir(root)):
            path = os.path.join(root, name)
            if os.path.isfile(path):
                found.append(path)
    found.append(CATALOG)
    return found


def snapshot_tree():
    """Digest every consumed fixture file (read-only)."""
    return {path: hashlib.sha256(read_bytes(path)).hexdigest()
            for path in fixture_tree_files()}


def test_proof_switch_names_known_families():
    assert PROOF in ("", "all") or PROOF in FAMILIES, \
        "unknown proof family %r" % (PROOF,)


def test_harness_wrong_hash_refuses():
    # Mutation: flip one byte of the second sealed event line.
    def mutate(lines):
        lines[1] = lines[1].replace("ev-2", "ev-3", 1)
        return lines

    def body():
        snapshot = load_json(os.path.join(CONTRACTS, "sealed_snapshot.json"))
        integrity = snapshot["session"]["capture"]["integrity"]
        lines = proof_input("wrong-hash", snapshot["event_lines"], mutate)
        assert verify_finalized(lines, integrity) is True
        with pytest.raises(TruncatedCapture):
            verify_finalized(mutate(list(snapshot["event_lines"])),
                             integrity)

    bounds.run_bounded("wrong-hash", body)


def test_harness_empty_ledger_refuses():
    # Mutation: drop every entry from the expected ledger.
    def mutate(entries):
        return []

    def body():
        case = oracle.load_case(
            os.path.join(CASES, "exposure-loss-and-bounds.json"))
        expected = proof_input("empty-ledger",
                               oracle.derive_events(case), mutate)
        assert oracle.compare_entries(expected, expected, "control") \
            == len(expected) > 0
        with pytest.raises(oracle.LedgerMismatch):
            oracle.compare_entries([], oracle.derive_events(case), "empty")
        with pytest.raises(oracle.LedgerMismatch):
            oracle.compare_entries(oracle.derive_events(case), [], "empty")

    bounds.run_bounded("empty-ledger", body)


def test_harness_missing_ledger_refuses():
    # Mutation: resolve the control path against a missing ledger file.
    def mutate(path):
        return path + ".absent"

    def body():
        control = proof_input(
            "missing-ledger",
            os.path.join(CASES, "exposure-loss-and-bounds.json"), mutate)
        assert oracle.load_case(control)["scenario"] == "loss-and-bounds"
        with pytest.raises(oracle.FixtureError):
            oracle.load_case(os.path.join(CASES, "no-such-case.json"))
        with pytest.raises(oracle.FixtureError):
            oracle.load_case(os.path.join(CASES, "no-such-dir", "x.json"))

    bounds.run_bounded("missing-ledger", body)


def test_harness_unarmed_gate_refuses():
    # Mutation: remove the arming flag from the gate record.
    def mutate(record):
        record.pop("armed", None)
        return record

    def body():
        record = proof_input("unarmed-gate",
                             {"armed": True, "scope": "offline-adversarial"},
                             mutate)
        assert require_armed(record) == "offline-adversarial"
        for bad in ({}, {"armed": False, "scope": "offline-adversarial"},
                    {"armed": True, "scope": ""}, None):
            with pytest.raises(GateRefused):
                require_armed(bad)

    bounds.run_bounded("unarmed-gate", body)


def test_harness_wrong_platform_refuses():
    # Mutation: substitute an unlisted platform cell.
    def mutate(cell):
        return "unlisted-platform"

    def body():
        assert "ordinary-linux" in catalog_cells()
        cell = proof_input("wrong-platform", "ordinary-linux", mutate)
        assert check_platform(cell) == "ordinary-linux"
        for bad in ("unlisted-platform", "", "ORDINARY-LINUX"):
            with pytest.raises(PlatformRefused):
                check_platform(bad)

    bounds.run_bounded("wrong-platform", body)


def test_harness_hidden_rebuild_refuses():
    # Mutation: flip one byte of a re-read fixture file.
    def mutate(digests):
        victim = sorted(digests)[0]
        raw = bytearray(read_bytes(victim))
        raw[len(raw) // 2] ^= 1
        digests[victim] = hashlib.sha256(bytes(raw)).hexdigest()
        return digests

    def body():
        before = snapshot_tree()
        assert len(before) >= 40, "fixture corpus unexpectedly small"
        after = proof_input("hidden-rebuild", snapshot_tree(), mutate)
        assert after == before, "fixture bytes changed mid-run"
        recorded = before[sorted(before)[0]]
        assert verify_bytes_digest(recorded,
                                   read_bytes(sorted(before)[0])) is True
        raw = bytearray(read_bytes(sorted(before)[0]))
        raw[0] ^= 1
        with pytest.raises(DigestMismatch):
            verify_bytes_digest(recorded, bytes(raw))

    bounds.run_bounded("hidden-rebuild", body)


def test_kill_recovery_checkpoint():
    # Mutation: drop the final sealed event line (kill before the
    # last write). The checkpoint leg rewrites last_seq instead.
    def mutate(lines):
        return lines[:-1]

    def body():
        snapshot = load_json(os.path.join(CONTRACTS, "sealed_snapshot.json"))
        integrity = snapshot["session"]["capture"]["integrity"]
        lines = proof_input("kill-recovery", snapshot["event_lines"], mutate)
        assert verify_finalized(lines, integrity) is True
        with pytest.raises(TruncatedCapture):
            verify_finalized(snapshot["event_lines"][:-1], integrity)
        moved = copy.deepcopy(integrity)
        moved["last_seq"] = "9"
        with pytest.raises(TruncatedCapture):
            verify_finalized(snapshot["event_lines"], moved)
        resized = copy.deepcopy(integrity)
        resized["events_bytes"] = "1"
        with pytest.raises(TruncatedCapture):
            verify_finalized(snapshot["event_lines"], resized)

    bounds.run_bounded("kill-recovery", body)


def test_scan_reference_side_effects(tmp_path):
    # Mutation: inject a sidecar entry into the post-scan listing.
    def mutate(listing):
        return listing + ["injected-sidecar.tmp"]

    def body():
        digests_before = snapshot_tree()
        first = [oracle.verify_case(oracle.load_case(os.path.join(CASES, name)))
                 for name in sorted(os.listdir(CASES))]
        second = [oracle.verify_case(oracle.load_case(os.path.join(CASES, name)))
                  for name in sorted(os.listdir(CASES))]
        assert first == second and len(first) == 15
        digests_after = snapshot_tree()
        assert digests_after == digests_before, "scan changed fixture bytes"
        listing_before = sorted(os.listdir(CASES))
        listing_after = proof_input("scan-side-effects",
                                    sorted(os.listdir(CASES)), mutate)
        assert find_added(listing_before, listing_after) == []
        # The detector itself is not vacuous: it flags a decoy
        # sidecar planted in a scratch directory (never the fixtures).
        decoy = tmp_path / "decoy-sidecar.tmp"
        decoy.write_text("planted", encoding="utf-8")
        assert find_added([], [entry.name for entry in tmp_path.iterdir()]) \
            == ["decoy-sidecar.tmp"]

    bounds.run_bounded("scan-side-effects", body)


def test_lost_final_events():
    # Mutation: remove the final derived event from the actual ledger.
    def mutate(events):
        return events[:-1]

    def body():
        case = oracle.load_case(
            os.path.join(CASES, "exposure-loss-and-bounds.json"))
        actual = proof_input("lost-final", oracle.derive_events(case), mutate)
        # The expectation is rebuilt straight from the control
        # flow, never copied from the derived-event helper under
        # test: a helper that drops the final event on every read
        # must fail here instead of matching its own output.
        expected = [{"ordinal": step["ordinal"],
                     "operation_token": step["operation"],
                     "object_token": step["object"],
                     "pages": step["pages"],
                     "native_result": step["native_result"]}
                    for step in case["control_flow"]]
        assert oracle.compare_entries(expected, actual, "control") \
            == len(expected)
        with pytest.raises(oracle.LedgerMismatch):
            oracle.compare_entries(expected, expected[:-1], "lost-final")

    bounds.run_bounded("lost-final", body)


def test_map_edge_exhaustion():
    # Mutation: raise the control page count past the 256-page ceiling.
    def mutate(pages):
        return "257"

    def body():
        pages = proof_input("map-exhaustion", "256", mutate)
        assert oracle.check_pages(pages, "control") == 256
        assert oracle.check_pages("1", "control") == 1
        for bad in ("257", "0", "0256", "1e2", ""):
            with pytest.raises(oracle.FixtureError):
                oracle.check_pages(bad, "exhausted")
        # The affected fixture state is evaluated too: the
        # loss-and-bounds case records its exhausted bound as a
        # failed final step, so success there must fail here.
        case = oracle.load_case(
            os.path.join(CASES, "exposure-loss-and-bounds.json"))
        exhausted = [step for step in case["control_flow"]
                     if step["action"] == "record-exhausted-bound"]
        assert len(exhausted) == 1, "exhausted-bound step missing"
        assert exhausted[0]["native_result"] == -12, \
            "exhausted bound reported success"

    bounds.run_bounded("map-exhaustion", body)


def test_generation_wrap():
    # Mutation: advance the control generation one past the u64 maximum.
    def mutate(generation):
        return "18446744073709551616"

    def body():
        generation = proof_input(
            "generation-wrap", "18446744073709551615", mutate)
        assert oracle.is_canonical_u64(generation) is True
        assert int(generation) == 2 ** 64 - 1
        assert oracle.is_canonical_u64("18446744073709551616") is False
        assert oracle.is_canonical_u64("18446744073709551616x") is False
        # The affected fixture state is evaluated too: the
        # channel-lifetimes case reoffers its recycled token under
        # a new generation, so reusing the prior generation must
        # fail here.
        case = oracle.load_case(
            os.path.join(CASES, "exposure-channel-lifetimes.json"))
        before = {entry["object_token"]: entry
                  for entry in case["before_ledger"]}
        after = {entry["object_token"]: entry
                 for entry in case["after_ledger"]}
        assert "obj-chl-peer-1" in case["expectation"]["transitioned"]
        assert (before["obj-chl-peer-1"]["generation"],
                after["obj-chl-peer-1"]["generation"]) == ("1", "2"), \
            "recycled token reused the prior generation"

    bounds.run_bounded("generation-wrap", body)


def test_clocks():
    # Mutation: rewrite the right window clock domain to match the left.
    def mutate(pair):
        pair["right"]["window"]["clock_domain"] = \
            pair["left"]["window"]["clock_domain"]
        return pair

    def body():
        fixture = load_json(os.path.join(COMPARE, "clock_mismatch.json"))
        pair = proof_input("clocks",
                           {"left": fixture["left"],
                            "right": fixture["right"]}, mutate)
        assert clocks_compatible(pair["left"], pair["right"]) == \
            (False, "clock-mismatch")
        assert len(fixture["expected"]) == 1
        for row in fixture["expected"]:
            assert row["compatibility"] == "incompatible"
            assert row["reason"] == "clock-mismatch"
        blank = copy.deepcopy(fixture["right"])
        blank["window"]["clock_domain"] = ""
        assert clocks_compatible(fixture["left"], blank) == \
            (False, "clock-blank")
        whitespace = copy.deepcopy(fixture["right"])
        whitespace["window"]["clock_domain"] = " \t"
        assert clocks_compatible(fixture["left"], whitespace) == \
            (False, "clock-blank")
        skewed = copy.deepcopy(fixture["right"])
        skewed["window"]["start"], skewed["window"]["end"] = "2000", "1000"
        assert clocks_compatible(fixture["left"], skewed) == \
            (False, "window-reversed")

    bounds.run_bounded("clocks", body)


def test_concurrent_activity():
    # Mutation: rewrite one worker's summary so unanimity breaks.
    # The interleave leg merges two event streams and breaks
    # ordinal continuity instead.
    def body():
        main = oracle.load_case(
            os.path.join(CASES, "exposure-channel-lifetimes.json"))
        other = oracle.load_case(
            os.path.join(CASES, "exposure-loss-and-bounds.json"))
        # The unanimous worker result must also equal the summary
        # counted straight from the case: unanimous wrong summaries
        # (for example zero events from every worker) must fail.
        expected = {"scenario": main["scenario"],
                    "events": len(main["control_flow"]),
                    "before": len(main["before_ledger"]),
                    "after": len(main["after_ledger"])}
        summaries, lock = [], threading.Lock()

        def worker():
            for _ in range(4):
                summary = oracle.verify_case(main)
                with lock:
                    summaries.append(summary)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(summaries) == 32
        # The proof mutation rewrites one worker's summary, which
        # must break the unanimous result.
        if PROOF in ("concurrent", "all"):
            summaries[0] = dict(summaries[0], scenario="mutated-scenario")
        assert all(summary == summaries[0] for summary in summaries), \
            "concurrent evaluations diverged"
        assert summaries[0] == expected, \
            "concurrent evaluations agree on the wrong summary"
        merged = oracle.derive_events(oracle.load_case(
            os.path.join(CASES, "exposure-channel-lifetimes.json")))
        merged = merged + oracle.derive_events(other)
        with pytest.raises(OrdinalBreak):
            check_ordinals(merged)

    bounds.run_bounded("concurrent", body)


def test_denied_sources():
    # Mutation: flip the denied object's recorded status from
    # unknown to live, as if a denied source were reported complete.
    def mutate(case):
        case["after_ledger"][0]["status"] = "live"
        return case

    def body():
        path = os.path.join(CASES, "exposure-loss-and-bounds.json")
        assert oracle.load_case(path)["scenario"] == "loss-and-bounds"
        case = proof_input("denied-sources", load_json(path), mutate)
        # The denial codes are asserted on the same evaluated
        # input, never on a separate fixture read: erasing the
        # denial from the evaluated input must fail here.
        assert {event["native_result"] for event in
                oracle.derive_events(case)} >= {-13, -19}, \
            "denial codes missing from the evaluated input"
        assert check_denied_partial(case) is True
        assert case["after_ledger"][0]["status"] == "unknown"
        with pytest.raises(DeniedComplete):
            check_denied_partial(mutate(copy.deepcopy(load_json(path))))

    bounds.run_bounded("denied-sources", body)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
