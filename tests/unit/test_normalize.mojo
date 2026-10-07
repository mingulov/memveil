# SPDX-License-Identifier: GPL-3.0-or-later

"""Normalize unit tests: decoder contract, device table, rejections.

The corpus differential (dump_normalize.mojo vs the C reference)
covers every decode/extraction vector; these tests pin the
normalize LOGIC: device-id assignment, UTF-8 rejection vs fatal
exhaustion, and operation/requested-bytes/ts mappings.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.normalize import (
    DEVICE_MAX,
    NAME_MAX,
    PAYLOAD_LEN,
    DecodeError,
    DecodedAttempt,
    DeviceTable,
    NormalizeError,
    bytes_to_hex,
    decode_payload,
    device_id_for,
    hex_to_bytes,
    is_pci_scope,
    normalize_attempt,
)


def u64max() -> UInt64:
    """All-ones UInt64 without an out-of-range literal."""
    return ~UInt64(0)


def make_payload(size: UInt64, force: Bool, seq: UInt64,
                 name: List[UInt8]) -> List[UInt8]:
    """Build one valid 98-byte payload for the given fields."""
    var out = List[UInt8]()
    var magic = 0x3741564D
    for i in range(4):
        out.append(UInt8((magic >> (8 * i)) & 0xFF))
    out.append(UInt8(1))
    out.append(UInt8(0))
    if force:
        out.append(UInt8(1))
    else:
        out.append(UInt8(0))
    out.append(UInt8(0))
    for i in range(8):
        out.append(UInt8((seq >> UInt64(8 * i)) & UInt64(0xFF)))
    for _ in range(8):
        out.append(UInt8(0))
    for i in range(8):
        out.append(UInt8((size >> UInt64(8 * i)) & UInt64(0xFF)))
    out.append(UInt8(len(name) & 0xFF))
    out.append(UInt8((len(name) >> 8) & 0xFF))
    for i in range(64):
        if i < len(name):
            out.append(name[i])
        else:
            out.append(UInt8(0))
    return out^


def name_bytes(text: String) -> List[UInt8]:
    """Encode an ASCII name to bytes."""
    var out = List[UInt8]()
    for i in range(text.byte_length()):
        var slice = text[byte=i]
        var raw = slice.as_bytes()
        out.append(raw[0])
    return out^


def test_decode_valid() raises:
    var raw = make_payload(UInt64(98), False, UInt64(7),
                           name_bytes(String("dev0")))
    var got = decode_payload(raw)
    assert_equal(got.size, UInt64(98))
    assert_equal(got.seq, UInt64(7))
    assert_equal(got.name_len, 4)
    assert_true(not got.force)
    assert_equal(bytes_to_hex(got.name), String("64657630"))


def test_decode_short() raises:
    var raw = make_payload(UInt64(1), False, UInt64(0),
                           name_bytes(String("a")))
    _ = raw.pop()
    var raised = False
    try:
        _ = decode_payload(raw)
    except e:
        raised = True
        assert_equal(e.reason, String("PAY_SHORT"))
    assert_true(raised)


def test_decode_magic() raises:
    var raw = make_payload(UInt64(1), False, UInt64(0),
                           name_bytes(String("a")))
    raw[0] = UInt8(0)
    var raised = False
    try:
        _ = decode_payload(raw)
    except e:
        raised = True
        assert_equal(e.reason, String("PAY_MAGIC"))
    assert_true(raised)


def test_decode_max_values() raises:
    var big = List[UInt8]()
    for _ in range(63):
        big.append(UInt8(0x44))
    var raw = make_payload(UInt64(18446744073709551615), True,
                           UInt64(18446744073709551615), big)
    var got = decode_payload(raw)
    assert_equal(got.size, UInt64(18446744073709551615))
    assert_equal(got.seq, UInt64(18446744073709551615))
    assert_true(got.force)
    assert_equal(got.name_len, 63)


def test_device_ids() raises:
    var table = DeviceTable()
    var first = table.device_for(name_bytes(String("eth0")))
    assert_equal(first, String("d000001"))
    var second = table.device_for(name_bytes(String("wlan0")))
    assert_equal(second, String("d000002"))
    var repeat = table.device_for(name_bytes(String("eth0")))
    assert_equal(repeat, String("d000001"))
    assert_equal(table.len(), 2)


def test_device_id_format() raises:
    assert_equal(device_id_for(1), String("d000001"))
    assert_equal(device_id_for(4096), String("d004096"))


def test_normalize_fields() raises:
    var table = DeviceTable()
    var raw = make_payload(UInt64(1500), True, UInt64(123),
                           name_bytes(String("pc")))
    var decoded = decode_payload(raw)
    var norm = normalize_attempt(decoded, table)
    assert_equal(norm.device_id, String("d000001"))
    assert_equal(norm.requested_bytes, UInt64(1500))
    assert_true(norm.forced)
    assert_equal(norm.operation_id, String("op123"))
    assert_equal(norm.ts_ns, UInt64(0))


def test_normalize_utf8_reject() raises:
    var table = DeviceTable()
    var bad = List[UInt8]()
    bad.append(UInt8(0xFF))
    bad.append(UInt8(0xFE))
    var raw = make_payload(UInt64(8), False, UInt64(3), bad)
    var decoded = decode_payload(raw)
    var raised = False
    try:
        _ = normalize_attempt(decoded, table)
    except e:
        raised = True
        assert_equal(e.reason, String("UTF8"))
        assert_true(not e.fatal)
    assert_true(raised)
    assert_equal(table.len(), 0)


def test_normalize_exhaustion() raises:
    var table = DeviceTable()
    for i in range(DEVICE_MAX):
        var nm = name_bytes(String("d") + String(i))
        _ = table.device_for(nm)
    assert_equal(table.len(), DEVICE_MAX)
    var raised = False
    try:
        _ = table.device_for(name_bytes(String("one-too-many")))
    except e:
        raised = True
        assert_equal(e.reason, String("EXHAUSTED"))
        assert_true(e.fatal)
    assert_true(raised)


def test_normalize_exhaustion_counts() raises:
    var table = DeviceTable()
    for i in range(DEVICE_MAX):
        var nm = name_bytes(String("x") + String(i))
        _ = table.device_for(nm)
    var raw = make_payload(UInt64(8), False, UInt64(9),
                           name_bytes(String("new-device")))
    var decoded = decode_payload(raw)
    var raised = False
    try:
        _ = normalize_attempt(decoded, table)
    except e:
        raised = True
        assert_true(e.fatal)
    assert_true(raised)


def test_bytes_to_hex() raises:
    var raw = List[UInt8]()
    raw.append(UInt8(0))
    raw.append(UInt8(0xFF))
    raw.append(UInt8(0x0A))
    assert_equal(bytes_to_hex(raw), String("00ff0a"))
    assert_equal(bytes_to_hex(List[UInt8]()), String(""))
    assert_equal(PAYLOAD_LEN, 98)
    assert_equal(NAME_MAX, 63)


def test_catalog_entries() raises:
    var table = DeviceTable()
    var second = table.device_for(name_bytes(String("0000:00:0c.0")))
    var first = table.device_for(name_bytes(String("eth0")))
    assert_equal(second, String("d000001"))
    assert_equal(first, String("d000002"))
    assert_equal(
        table.device_for(name_bytes(String("0000:00:0c.0"))), second
    )
    var got = table.entries()
    assert_equal(len(got), 2)
    assert_equal(got[0].device_id, String("d000001"))
    assert_equal(got[0].name, String("0000:00:0c.0"))
    assert_equal(got[1].device_id, String("d000002"))
    assert_equal(got[1].name, String("unresolved"))


def test_pci_scope_vectors() raises:
    var good = List[String]()
    good.append(String("0000:00:0c.0"))
    good.append(String("FFFF:FF:1F.7"))
    good.append(String("abcd:12:34.5"))
    for i in range(len(good)):
        assert_true(is_pci_scope(good[i]))
    var bad = List[String]()
    bad.append(String(""))
    bad.append(String("eth0"))
    bad.append(String("ffff888012345000"))
    bad.append(String("0000:00:0c"))
    bad.append(String("0000:00:0c.00"))
    bad.append(String("0000:00:0c.0 "))
    bad.append(String(" 0000:00:0c.0"))
    bad.append(String("0000-00-0c.0"))
    bad.append(String("0000:00:0c:0"))
    bad.append(String("gggg:00:0c.0"))
    bad.append(String("0000:00:0c.g"))
    bad.append(String("/etc/passwd"))
    bad.append(String("0000:00:0c.0/extra"))
    for i in range(len(bad)):
        assert_true(not is_pci_scope(bad[i]))


def test_hex_roundtrip() raises:
    var raw = name_bytes(String("pci-00:1f.6"))
    var back = hex_to_bytes(bytes_to_hex(raw))
    assert_equal(len(back), len(raw))
    for i in range(len(raw)):
        assert_equal(back[i], raw[i])
    for bad in range(3):
        var text = String("zz")
        if bad == 1:
            text = String("abc")
        if bad == 2:
            text = String("AB")
        var raised = False
        try:
            _ = hex_to_bytes(text)
        except e:
            raised = True
            assert_equal(e.reason, String("INTERNAL"))
            assert_true(e.fatal)
        assert_true(raised)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_catalog_entries]()
    suite.test[test_pci_scope_vectors]()
    suite.test[test_hex_roundtrip]()
    suite.test[test_decode_valid]()
    suite.test[test_decode_short]()
    suite.test[test_decode_magic]()
    suite.test[test_decode_max_values]()
    suite.test[test_device_ids]()
    suite.test[test_device_id_format]()
    suite.test[test_normalize_fields]()
    suite.test[test_normalize_utf8_reject]()
    suite.test[test_normalize_exhaustion]()
    suite.test[test_normalize_exhaustion_counts]()
    suite.test[test_bytes_to_hex]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
