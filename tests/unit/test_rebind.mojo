# SPDX-License-Identifier: GPL-3.0-or-later

"""Single-binding object rebinds: one stale hash drifts one binding."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.narrow import (
    format_narrow_note,
    parse_narrow_note,
    rebind_note_object,
)

comptime _CONFIG = "a5af36b05630b51bb596bc68f955ab97bb8802e857cd2fc1de05c0628e398fbb"
comptime _BTF = "785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9"
comptime _FORMAT = "039a1a6bc665b91c4f846f735f9b2f9ec89d106d7d63a5e9d0b35e20213e80fb"
comptime _OBJECT = "7549adfdf9837cefd566373a0efeee8550abdb4cd678b6fa15fe11f3f4785a37"
comptime _IMAGE = "11a663ae36f0cdbecf94b8b7319503bbd0fffc2c3ba02c01cf81600d423dd251"
comptime _BID = "0102030405060708090a0b0c0d0e0f1011121314"
comptime _LC_OBJECT = "9c8e7d6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e"
comptime _CP_OBJECT = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
comptime _NEW_OBJECT = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
comptime _NEW_LC = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
comptime _NEW_CP = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"


def _base_fields() -> List[String]:
    var out = List[String]()
    out.append(String("config=sha256:") + String(_CONFIG))
    out.append(String("config_src=gz"))
    out.append(String("btf=sha256:") + String(_BTF))
    out.append(String("format=sha256:") + String(_FORMAT))
    out.append(String("object=sha256:") + String(_OBJECT))
    out.append(String("image=sha256:") + String(_IMAGE))
    out.append(String("image_bid=") + String(_BID))
    out.append(String("ring_bytes=8388608"))
    return out^


def _join(fields: List[String]) -> String:
    var out = String("")
    for i in range(len(fields)):
        if i > 0:
            out += String(" ")
        out += fields[i]
    return out^


def _eight() -> String:
    return _join(_base_fields())


def _twelve() -> String:
    var fields = _base_fields()
    fields.append(String("lc_object=sha256:") + String(_LC_OBJECT))
    fields.append(String("lc_ring_bytes=33554432"))
    fields.append(String("cp_object=sha256:") + String(_CP_OBJECT))
    fields.append(String("cp_ring_bytes=33554432"))
    return _join(fields^)


def _assert_base_siblings(bind_old: String, bind_new: String) raises:
    # Every non-object binding survives the rebind byte-identical.
    var old = parse_narrow_note(bind_old).bindings
    var new = parse_narrow_note(bind_new).bindings
    assert_equal(new.config, old.config)
    assert_equal(new.config_src, old.config_src)
    assert_equal(new.btf, old.btf)
    assert_equal(new.format, old.format)
    assert_equal(new.image, old.image)
    assert_equal(new.image_bid, old.image_bid)
    assert_equal(new.ring, old.ring)


def test_rebind_attempt_only() raises:
    var note = _eight()
    var rebound = rebind_note_object(
        note, String("object"), String(_NEW_OBJECT)
    )
    var parsed = parse_narrow_note(rebound)
    assert_true(parsed.ok)
    assert_equal(parsed.bindings.object, String(_NEW_OBJECT))
    assert_equal(parsed.bindings.lc_object, String(""))
    assert_equal(parsed.bindings.cp_object, String(""))
    _assert_base_siblings(note, rebound)
    assert_equal(format_narrow_note(parsed.bindings, False), rebound)


def test_rebind_lifecycle_only() raises:
    var note = _twelve()
    var rebound = rebind_note_object(
        note, String("lc_object"), String(_NEW_LC)
    )
    var parsed = parse_narrow_note(rebound)
    assert_true(parsed.ok)
    assert_equal(parsed.bindings.lc_object, String(_NEW_LC))
    assert_equal(parsed.bindings.object, String(_OBJECT))
    assert_equal(parsed.bindings.cp_object, String(_CP_OBJECT))
    assert_equal(parsed.bindings.lc_ring, String("33554432"))
    assert_equal(parsed.bindings.cp_ring, String("33554432"))
    _assert_base_siblings(note, rebound)
    assert_equal(format_narrow_note(parsed.bindings, True), rebound)


def test_rebind_copy_only() raises:
    var note = _twelve()
    var rebound = rebind_note_object(
        note, String("cp_object"), String(_NEW_CP)
    )
    var parsed = parse_narrow_note(rebound)
    assert_true(parsed.ok)
    assert_equal(parsed.bindings.cp_object, String(_NEW_CP))
    assert_equal(parsed.bindings.object, String(_OBJECT))
    assert_equal(parsed.bindings.lc_object, String(_LC_OBJECT))
    assert_equal(parsed.bindings.lc_ring, String("33554432"))
    assert_equal(parsed.bindings.cp_ring, String("33554432"))
    _assert_base_siblings(note, rebound)
    assert_equal(format_narrow_note(parsed.bindings, True), rebound)


def test_rebind_attempt_on_twelve_keeps_extra() raises:
    var note = _twelve()
    var rebound = rebind_note_object(
        note, String("object"), String(_NEW_OBJECT)
    )
    var parsed = parse_narrow_note(rebound)
    assert_true(parsed.ok)
    assert_equal(parsed.bindings.object, String(_NEW_OBJECT))
    assert_equal(parsed.bindings.lc_object, String(_LC_OBJECT))
    assert_equal(parsed.bindings.cp_object, String(_CP_OBJECT))
    assert_equal(format_narrow_note(parsed.bindings, True), rebound)


def test_rebind_refusals() raises:
    var eight = _eight()
    var twelve = _twelve()
    var refused = 0
    try:
        _ = rebind_note_object(
            eight, String("image"), String(_NEW_OBJECT)
        )
    except:
        refused += 1
    try:
        _ = rebind_note_object(
            eight, String("object"), String("abc")
        )
    except:
        refused += 1
    try:
        _ = rebind_note_object(
            eight,
            String("object"),
            String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        )
    except:
        refused += 1
    try:
        _ = rebind_note_object(
            String("not a note"),
            String("object"),
            String(_NEW_OBJECT),
        )
    except:
        refused += 1
    try:
        _ = rebind_note_object(
            eight, String("lc_object"), String(_NEW_LC)
        )
    except:
        refused += 1
    try:
        _ = rebind_note_object(
            eight, String("cp_object"), String(_NEW_CP)
        )
    except:
        refused += 1
    assert_equal(refused, 6)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_rebind_attempt_only]()
    suite.test[test_rebind_lifecycle_only]()
    suite.test[test_rebind_copy_only]()
    suite.test[test_rebind_attempt_on_twelve_keeps_extra]()
    suite.test[test_rebind_refusals]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
