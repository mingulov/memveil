# SPDX-License-Identifier: GPL-3.0-or-later

"""Baseline tests: real initial state, separately from events.

read_baseline extracts the retained session observations that
seed the region tracker: producer-attested initial intervals
with provenance, never invented transitions. check_observation
validates directly built observations for API users; the
session parser already validated extracted ones. End to end,
a parsed session seeds exact tracker unions.
"""

from std.pathlib import Path
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.regions import RegionTracker
from memveil.model.regions import RegionObservation
from memveil.model.session import Session, parse_session
from memveil.platform.baseline import check_observation, read_baseline


def _session_bytes(rel: String) raises -> List[UInt8]:
    return Path(rel).read_bytes()


def _valid() -> RegionObservation:
    var o = RegionObservation()
    o.region_id = String("r1")
    o.state = String("shared")
    o.offset = UInt64(0)
    o.length = UInt64(8192)
    o.address_space = String("guest_physical")
    o.provenance = String("test-provenance")
    o.generation = 1
    return o^


def test_read_baseline_extracts() raises:
    var s = parse_session(
        _session_bytes(String("tests/fixtures/baseline/session.json"))
    )
    assert_true(s.baseline_complete)
    var obs = read_baseline(s)
    assert_equal(len(obs), 2)
    assert_equal(obs[0].region_id, "r1")
    assert_equal(obs[0].state, "shared")
    assert_equal(obs[0].length, UInt64(8192))
    assert_equal(obs[0].address_space, "guest_physical")
    assert_equal(obs[0].provenance, "test-provenance-a")
    assert_equal(obs[1].region_id, "r2")
    assert_equal(obs[1].state, "unknown")
    assert_equal(obs[1].address_space, "iova")


def test_read_baseline_empty() raises:
    var s = parse_session(
        _session_bytes(String("tests/fixtures/attempts/session.json"))
    )
    assert_equal(len(read_baseline(s)), 0)


def test_check_observation_valid() raises:
    check_observation(_valid())


def test_check_observation_rejects() raises:
    var bad = 0
    var o = _valid()
    o.state = String("encrypted")
    try:
        check_observation(o)
    except:
        bad += 1
    o = _valid()
    o.address_space = String("gphys")
    try:
        check_observation(o)
    except:
        bad += 1
    o = _valid()
    o.offset = ~UInt64(0)
    o.length = UInt64(1)
    try:
        check_observation(o)
    except:
        bad += 1
    o = _valid()
    o.region_id = String("")
    try:
        check_observation(o)
    except:
        bad += 1
    o = _valid()
    o.provenance = String("")
    try:
        check_observation(o)
    except:
        bad += 1
    o = _valid()
    o.generation = 0
    try:
        check_observation(o)
    except:
        bad += 1
    assert_equal(bad, 6)


def test_baseline_seeds_tracker() raises:
    var s = parse_session(
        _session_bytes(String("tests/fixtures/baseline/session.json"))
    )
    var t = RegionTracker(True, s.baseline_complete)
    t.seed_baseline(read_baseline(s))
    assert_true(t.sees_regions())
    var rows = t.metrics(String("window [0,2000)"))
    var shared = UInt64(0)
    var unknown = UInt64(0)
    for i in range(len(rows)):
        if rows[i].name == "known_shared_region_bytes":
            shared = rows[i].value
        if rows[i].name == "unknown_region_bytes":
            unknown = rows[i].value
    assert_equal(shared, UInt64(8192))
    assert_equal(unknown, UInt64(0))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_read_baseline_extracts]()
    suite.test[test_read_baseline_empty]()
    suite.test[test_check_observation_valid]()
    suite.test[test_check_observation_rejects]()
    suite.test[test_baseline_seeds_tracker]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
