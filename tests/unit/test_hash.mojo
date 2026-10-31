# SPDX-License-Identifier: GPL-3.0-or-later

"""SHA-256 vectors (FIPS 180-4, cross-checked with hashlib)."""

from std.sys import exit
from std.testing import TestSuite, assert_equal

from memveil.platform.hash import Sha256, sha256_hex


def _bytes(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    return out^


def test_empty() raises:
    var data = List[UInt8]()
    assert_equal(
        sha256_hex(Span(data)),
        String(
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        ),
    )


def test_abc() raises:
    var data = _bytes(String("abc"))
    assert_equal(
        sha256_hex(Span(data)),
        String(
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad"
        ),
    )


def test_56_bytes() raises:
    # 448-bit boundary: padding spills into a second block.
    var data = _bytes(
        String("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    )
    assert_equal(len(data), 56)
    assert_equal(
        sha256_hex(Span(data)),
        String(
            "248d6a61d20638b8e5c026930c3e603"
            "9a33ce45964ff2167f6ecedd419db06c1"
        ),
    )


def test_64_bytes() raises:
    var data = _bytes(
        String(
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        )
    )
    assert_equal(len(data), 64)
    assert_equal(
        sha256_hex(Span(data)),
        String(
            "2ff100b36c386c65a1afc462ad53e254"
            "79bec9498ed00aa5a04de584bc25301b"
        ),
    )


def test_million_a() raises:
    var data = List[UInt8]()
    for _ in range(1000000):
        data.append(UInt8(0x61))
    assert_equal(
        sha256_hex(Span(data)),
        String(
            "cdc76e5c9914fb9281a1c7e284d73e6"
            "7f1809a48a497200e046d39ccc7112cd0"
        ),
    )


def test_incremental_snapshots() raises:
    var state = Sha256()
    assert_equal(state.copy_finish(), sha256_hex(Span(List[UInt8]())))
    var all_bytes = List[UInt8]()
    var expected = [
        String("29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488"),
        String("85c3bb135868f1433c5ec5f878d8b697acd27f3ed0c9f79af206ea416bca0d38"),
        String("9ee5f9064bf5ad41d0c1daea1b5218cff51e99e29b6052e36089ac4b9fee10ad"),
        String("a5ca14441f7f93913610bec51b63dc7f3c215ce8c7b23f8eb8761047ebfa6f4f"),
        String("9114e2764fd7046bf8673bbdb07260abf1e6682dbdbeb19905edb0dd1148fbee")
    ]
    var step = 0
    for size in [63, 64, 65, 1, 127]:
        var chunk = List[UInt8]()
        for i in range(size):
            chunk.append(UInt8(i % 251))
            all_bytes.append(UInt8(i % 251))
        state.update(Span(chunk))
        assert_equal(state.copy_finish(), expected[step])
        step += 1
        assert_equal(state.copy_finish(), sha256_hex(Span(all_bytes)))
        assert_equal(state.copy_finish(), sha256_hex(Span(all_bytes)))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_incremental_snapshots]()
    suite.test[test_empty]()
    suite.test[test_abc]()
    suite.test[test_56_bytes]()
    suite.test[test_64_bytes]()
    suite.test[test_million_a]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
