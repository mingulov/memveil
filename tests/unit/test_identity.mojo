# SPDX-License-Identifier: GPL-3.0-or-later

"""Identity unit tests: opaque tokens, namespaces, pairing keys.

Correlation keys are namespace-aware: the same numeric token under
another device or address namespace never merges. Generations are
positive; raw kernel addresses never appear here.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.model.identity import (
    ACTIVE_MAX,
    DEVICE_MAX_ID,
    NESTED_MAX,
    PENDING_MAX,
    POOL_MAX,
    RESOLVED_MAX,
    RETIRED_MAX,
    DeviceRef,
    MappingId,
    OperationId,
    PairingKey,
    PoolRef,
    check_address_space,
    check_generation,
)


def test_budgets_match_contract() raises:
    assert_equal(PENDING_MAX, 65536)
    assert_equal(ACTIVE_MAX, 65536)
    assert_equal(NESTED_MAX, 8)
    assert_equal(RESOLVED_MAX, 16384)
    assert_equal(RETIRED_MAX, 16384)
    assert_equal(DEVICE_MAX_ID, 4096)
    assert_equal(POOL_MAX, 1024)


def test_operation_id_roundtrip() raises:
    var op = OperationId.parse("op12")
    assert_equal(op.value, String("op12"))
    var raised = False
    try:
        _ = OperationId.parse("")
    except:
        raised = True
    assert_true(raised)
    raised = False
    try:
        _ = OperationId.parse("has space")
    except:
        raised = True
    assert_true(raised)


def test_mapping_and_device_tokens() raises:
    var m = MappingId.parse("map-1.0")
    assert_equal(m.value, String("map-1.0"))
    var d = DeviceRef.parse("d000001")
    assert_equal(d.value, String("d000001"))
    var p = PoolRef.parse("pool0")
    assert_equal(p.value, String("pool0"))
    var long = String("")
    for _ in range(129):
        long += "a"
    var raised = False
    try:
        _ = MappingId.parse(long)
    except:
        raised = True
    assert_true(raised)


def test_address_space() raises:
    check_address_space("kvirt")
    check_address_space("gphys")
    check_address_space("iova")
    check_address_space("tlb-phys")
    var raised = False
    try:
        check_address_space("phys")
    except:
        raised = True
    assert_true(raised)


def test_pairing_key_namespaces() raises:
    var a = PairingKey("d000001", "kvirt", "tok9")
    var b = PairingKey("d000001", "gphys", "tok9")
    var c = PairingKey("d000001", "kvirt", "tok9")
    assert_true(a.render() != b.render())
    assert_equal(a.render(), c.render())
    var d = PairingKey("d000002", "kvirt", "tok9")
    assert_true(a.render() != d.render())


def test_pairing_key_rejects_raw() raises:
    var raised = False
    try:
        _ = PairingKey.checked("d000001", "kvirt", "bad token")
    except:
        raised = True
    assert_true(raised)
    raised = False
    try:
        _ = PairingKey.checked("d000001", "raw", "tok9")
    except:
        raised = True
    assert_true(raised)


def test_generation_positive() raises:
    check_generation(1)
    var raised = False
    try:
        check_generation(0)
    except:
        raised = True
    assert_true(raised)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_budgets_match_contract]()
    suite.test[test_operation_id_roundtrip]()
    suite.test[test_mapping_and_device_tokens]()
    suite.test[test_address_space]()
    suite.test[test_pairing_key_namespaces]()
    suite.test[test_pairing_key_rejects_raw]()
    suite.test[test_generation_positive]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
