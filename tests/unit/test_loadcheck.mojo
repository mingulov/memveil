# SPDX-License-Identifier: GPL-3.0-or-later

"""Load diagnostics unit tests: errno names, messages, verifier tail."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from libbpf_mojo.error import LmbError
from memveil.capture.kernel import _lmb_message
from memveil.capture.loadcheck import errno_name, verifier_tail
from memveil.platform.reader import bytes_to_text


def contains(hay: String, needle: String) -> Bool:
    """True when needle occurs in hay at least once."""
    return hay.find(needle) != -1


def test_errno_names() raises:
    assert_equal(errno_name(Int32(-1)), String("EPERM"))
    assert_equal(errno_name(Int32(-2)), String("ENOENT"))
    assert_equal(errno_name(Int32(-7)), String("E2BIG"))
    assert_equal(errno_name(Int32(-12)), String("ENOMEM"))
    assert_equal(errno_name(Int32(-13)), String("EACCES"))
    assert_equal(errno_name(Int32(-16)), String("EBUSY"))
    assert_equal(errno_name(Int32(-22)), String("EINVAL"))
    assert_equal(errno_name(Int32(-28)), String("ENOSPC"))
    assert_equal(errno_name(Int32(-38)), String("ENOSYS"))
    assert_equal(errno_name(Int32(-95)), String("EOPNOTSUPP"))
    assert_equal(errno_name(Int32(-524)), String("ENOTSUPP"))
    assert_equal(errno_name(Int32(-99)), String("errno -99"))


def test_lmb_message_names_errno() raises:
    var e = LmbError(
        UInt32(3),
        UInt32(1),
        Int32(-1),
        String("lmb_load: object load failed"),
    )
    assert_true(
        contains(
            _lmb_message(e),
            String(
                "code=-1 EPERM: needs CAP_BPF and CAP_PERFMON:"
                " lmb_load: object load failed"
            ),
        )
    )


def _log_bytes(lines: List[String]) -> List[UInt8]:
    """One LF-terminated byte log for the given lines."""
    var out = List[UInt8]()
    for i in range(len(lines)):
        var b = lines[i].as_bytes()
        for j in range(len(b)):
            out.append(b[j])
        out.append(UInt8(0x0A))
    return out^


def test_verifier_tail_truncated() raises:
    var lines = List[String]()
    for n in range(1, 6):
        lines.append(String("line") + String(n))
    lines.append(String(""))
    for n in range(6, 11):
        lines.append(String("line") + String(n))
    var tail = verifier_tail(_log_bytes(lines), True)
    assert_equal(len(tail), 5)
    assert_equal(
        tail[0], String("verifier log truncated at 65536 bytes")
    )
    assert_equal(tail[1], String("line7"))
    assert_equal(tail[2], String("line8"))
    assert_equal(tail[3], String("line9"))
    assert_equal(tail[4], String("line10"))
    var wide = List[UInt8]()
    for _ in range(300):
        wide.append(UInt8(0x41))
    wide.append(UInt8(0x0A))
    var cut = verifier_tail(wide, False)
    assert_equal(len(cut), 1)
    assert_equal(len(cut[0].as_bytes()), 256)
    var dirty = List[UInt8]()
    for b in String("l8").as_bytes():
        dirty.append(b)
    dirty.append(UInt8(0x07))
    dirty.append(UInt8(0x78))
    dirty.append(UInt8(0x0A))
    var clean = verifier_tail(dirty, False)
    assert_equal(len(clean), 1)
    var want = List[UInt8]()
    want.append(UInt8(0x6C))
    want.append(UInt8(0x38))
    want.append(UInt8(0xEF))
    want.append(UInt8(0xBF))
    want.append(UInt8(0xBD))
    want.append(UInt8(0x78))
    assert_equal(clean[0], bytes_to_text(want^))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_errno_names]()
    suite.test[test_lmb_message_names_errno]()
    suite.test[test_verifier_tail_truncated]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
