# SPDX-License-Identifier: GPL-3.0-or-later

"""Recording-selection contract: literal device scope, full retention.

A capture-time device selector narrows only attributed
bounce attempts to one exact literal name; unattributed
lifecycle/copy records and global counter, pool, conversion,
gap, and marker records are always retained, so every
included relationship keeps its completion evidence. These
tests drive the real collector admission path with scripted
sources: keep/drop decisions, catalog interning, delayed
discovery, unavailable names, session metadata, and the
loss-accounting boundary for deliberate drops.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.collector import (
    Collector,
    CollectorConfig,
    PollOut,
    SnapOut,
    StatsOut,
)
from memveil.model.encode import encode_session
from memveil.model.session import parse_session

from scripted import (
    NullWriter,
    ScriptClock,
    ScriptKernel,
    ScriptSignal,
)


def _sel_le16(v: Int) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(UInt8(v & 0xFF))
    out.append(UInt8((v >> 8) & 0xFF))
    return out^


def _sel_le32(v: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(4):
        out.append(UInt8((v >> (i * 8)) & 0xFF))
    return out^


def _sel_le64(v: UInt64) -> List[UInt8]:
    var out = List[UInt8]()
    var x = v
    for _ in range(8):
        out.append(UInt8(x & UInt64(0xFF)))
        x >>= UInt64(8)
    return out^


def _sel_attempt(
    seq: UInt64, ktime: UInt64, size: UInt64, name: String
) -> List[UInt8]:
    var out = List[UInt8]()
    for b in _sel_le32(0x3741564D):
        out.append(b)
    for b in _sel_le16(1):
        out.append(b)
    for b in _sel_le16(0):
        out.append(b)
    for b in _sel_le64(seq):
        out.append(b)
    for b in _sel_le64(ktime):
        out.append(b)
    for b in _sel_le64(size):
        out.append(b)
    var raw = name.as_bytes()
    var nlen = len(raw)
    for b in _sel_le16(nlen):
        out.append(b)
    for i in range(nlen):
        out.append(raw[i])
    for _ in range(63 - nlen):
        out.append(UInt8(0))
    out.append(UInt8(0))
    return out^


def _sel_attempt_raw(
    seq: UInt64, ktime: UInt64, size: UInt64, name: List[UInt8]
) -> List[UInt8]:
    var out = List[UInt8]()
    for b in _sel_le32(0x3741564D):
        out.append(b)
    for b in _sel_le16(1):
        out.append(b)
    for b in _sel_le16(0):
        out.append(b)
    for b in _sel_le64(seq):
        out.append(b)
    for b in _sel_le64(ktime):
        out.append(b)
    for b in _sel_le64(size):
        out.append(b)
    for b in _sel_le16(len(name)):
        out.append(b)
    for i in range(len(name)):
        out.append(name[i])
    for _ in range(63 - len(name)):
        out.append(UInt8(0))
    out.append(UInt8(0))
    return out^


def _sel_lifecycle(kind: Int, gen: UInt64) -> List[UInt8]:
    # MVLC v2 map/unmap, OK flag, direction 1.
    var out = List[UInt8]()
    for b in _sel_le32(0x434C564D):
        out.append(b)
    for b in _sel_le16(2):
        out.append(b)
    for b in _sel_le16(kind):
        out.append(b)
    for b in _sel_le16(1):
        out.append(b)
    for b in _sel_le16(1):
        out.append(b)
    for b in _sel_le64(UInt64(7)):
        out.append(b)
    for b in _sel_le64(UInt64(100)):
        out.append(b)
    for b in _sel_le64(UInt64(4096)):
        out.append(b)
    for b in _sel_le64(gen):
        out.append(b)
    return out^


def _sel_copy() -> List[UInt8]:
    # MVCP v1 executed copy, known outcome, direction 1.
    var out = List[UInt8]()
    for b in _sel_le32(0x5043564D):
        out.append(b)
    for b in _sel_le16(1):
        out.append(b)
    for b in _sel_le16(2):
        out.append(b)
    for b in _sel_le16(3):
        out.append(b)
    for b in _sel_le16(1):
        out.append(b)
    for b in _sel_le64(UInt64(9)):
        out.append(b)
    for b in _sel_le64(UInt64(200)):
        out.append(b)
    for b in _sel_le64(UInt64(4096)):
        out.append(b)
    for b in _sel_le64(UInt64(4096)):
        out.append(b)
    for b in _sel_le16(0):
        out.append(b)
    out.append(UInt8(0))
    out.append(UInt8(0))
    return out^


def _sel_config(filt: String) -> CollectorConfig:
    var cfg = CollectorConfig()
    cfg.profile_id = String("sel")
    cfg.output = String("sel-out")
    if filt != String(""):
        cfg.has_device_filter = True
        cfg.device_filter = filt
    return cfg^


def _sel_deadline() -> UInt64:
    return ~UInt64(0)


def _sel_contains(hay: String, needle: String) -> Bool:
    return len(hay.split(String(needle))) > 1


def _sel_bytes(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    var raw = text.as_bytes()
    for i in range(len(raw)):
        out.append(raw[i])
    return out^


def _sel_repeat(unit: String, n: Int) -> String:
    var out = String("")
    for _ in range(n):
        out += unit
    return out^


def _sel_eacute() raises -> String:
    var raw = List[UInt8]()
    raw.append(UInt8(0xC3))
    raw.append(UInt8(0xA9))
    try:
        return String(from_utf8=Span(raw))
    except:
        raise Error("bad test utf-8")


def _sel_frame(payload: List[UInt8]) -> List[UInt8]:
    var out = _sel_le32(len(payload))
    for b in _sel_le16(1):
        out.append(b)
    for b in _sel_le16(0):
        out.append(b)
    for b in payload:
        out.append(b)
    return out^


def _sel_batch(payload: List[UInt8]) -> PollOut:
    return PollOut(
        String("batch"), _sel_frame(payload), UInt32(0), String("")
    )


def _sel_timeout() -> PollOut:
    return PollOut(
        String("timeout"), List[UInt8](), UInt32(0), String("")
    )


def _sel_stats(r: UInt64, d: UInt64) -> StatsOut:
    return StatsOut(
        True, r, d, UInt64(0), UInt64(0), UInt64(0), String("")
    )


def _sel_snap(
    o: UInt64, ob: UInt64, e: UInt64, eb: UInt64
) -> SnapOut:
    var vals = List[UInt64]()
    vals.append(o)
    vals.append(ob)
    vals.append(e)
    vals.append(eb)
    vals.append(UInt64(0))
    vals.append(UInt64(0))
    return SnapOut(True, vals^, String(""))


struct SelRunOut(Movable):
    """One scripted selection run: result plus session bytes."""

    var exit_code: Int
    var end_reason: String
    var outcome: String
    var finalized: Bool
    var session: List[UInt8]
    var persisted_attempt: UInt64
    var filtered: UInt64
    var catalog_len: Int

    def __init__(
        out self, exit_code: Int, end_reason: String,
        outcome: String, finalized: Bool,
        session: List[UInt8], persisted_attempt: UInt64,
        filtered: UInt64, catalog_len: Int,
    ):
        self.exit_code = exit_code
        self.end_reason = end_reason
        self.outcome = outcome
        self.finalized = finalized
        self.session = session.copy()
        self.persisted_attempt = persisted_attempt
        self.filtered = filtered
        self.catalog_len = catalog_len


def _sel_run(names: List[String], filt: String) raises -> SelRunOut:
    """Run one scripted attempt capture under a selector.

    Every named device delivers exactly one valid attempt
    payload; bridge stats and the end cut agree on that
    count, and a signal stops the run after the last
    batch. An empty name list runs an idle capture.
    """
    var cfg = _sel_config(filt)
    var n = UInt64(len(names))
    var kernel = ScriptKernel()
    kernel.add_snap(_sel_snap(
        UInt64(0), UInt64(0), UInt64(0), UInt64(0)
    ))
    kernel.add_snap(_sel_snap(
        UInt64(0), UInt64(0), UInt64(0), UInt64(0)
    ))
    kernel.add_snap(_sel_snap(n, n * UInt64(64), n, n * UInt64(64)))
    kernel.add_snap(_sel_snap(n, n * UInt64(64), n, n * UInt64(64)))
    kernel.add_stats(_sel_stats(UInt64(0), UInt64(0)))
    for _ in range(4):
        kernel.add_stats(_sel_stats(n, n))
    for i in range(len(names)):
        kernel.add_poll(
            _sel_batch(
                _sel_attempt(
                    UInt64(i + 1), UInt64(10 + i), UInt64(64),
                    names[i],
                )
            ), 1,
        )
    kernel.add_poll(_sel_timeout(), 110)
    var signal = ScriptSignal()
    for _ in range(2 * len(names)):
        signal.add(String("none"))
    signal.add(String("pending"))
    var clock = ScriptClock()
    clock.add(UInt64(0))
    var writer = NullWriter()
    var coll = Collector(cfg^)
    var result = coll.run(kernel, clock, signal, writer)
    var out = SelRunOut(
        result.exit_code,
        result.end_reason,
        result.outcome,
        writer.finalized,
        writer.session_bytes.copy(),
        coll.persisted_attempt,
        coll.filtered,
        coll.table.len(),
    )
    return out^


def test_selection_keeps_matching_drops_others() raises:
    var coll = Collector(_sel_config(String("dev-a")))
    coll.session_id = String("sel-test")
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    var r1 = coll._admit_attempt(
        _sel_attempt(UInt64(1), UInt64(10), UInt64(64),
                     String("dev-b")),
        clock,
        signal,
        writer,
        _sel_deadline(),
    )
    var r2 = coll._admit_attempt(
        _sel_attempt(UInt64(2), UInt64(11), UInt64(64),
                     String("dev-a")),
        clock,
        signal,
        writer,
        _sel_deadline(),
    )
    assert_equal(r1, String(""))
    assert_equal(r2, String(""))
    assert_equal(coll.persisted_attempt, UInt64(1))
    assert_equal(coll.filtered, UInt64(1))
    assert_equal(coll.rejected, UInt64(0))
    assert_equal(len(writer.lines), 1)
    # Dropped devices consume no catalog ids: the kept
    # device is first-seen even though it arrived second.
    assert_equal(coll.table.len(), 1)
    var entries = coll.table.entries()
    assert_equal(len(entries), 1)
    assert_equal(entries[0].device_id, String("d000001"))


def test_selection_disabled_keeps_all() raises:
    var coll = Collector(_sel_config(String("")))
    coll.session_id = String("sel-test")
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    _ = coll._admit_attempt(
        _sel_attempt(UInt64(1), UInt64(10), UInt64(64),
                     String("dev-a")),
        clock,
        signal,
        writer,
        _sel_deadline(),
    )
    _ = coll._admit_attempt(
        _sel_attempt(UInt64(2), UInt64(11), UInt64(64),
                     String("dev-b")),
        clock,
        signal,
        writer,
        _sel_deadline(),
    )
    assert_equal(coll.persisted_attempt, UInt64(2))
    assert_equal(coll.filtered, UInt64(0))
    assert_equal(coll.table.len(), 2)


def test_selection_late_discovery_matches() raises:
    # No pre-registration: a device first observed late in
    # the capture still matches per event.
    var coll = Collector(_sel_config(String("dev-late")))
    coll.session_id = String("sel-test")
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    for i in range(5):
        _ = coll._admit_attempt(
            _sel_attempt(UInt64(i + 1), UInt64(10 + i), UInt64(64),
                         String("dev-early")),
            clock,
            signal,
            writer,
            _sel_deadline(),
        )
    _ = coll._admit_attempt(
        _sel_attempt(UInt64(6), UInt64(20), UInt64(64),
                     String("dev-late")),
        clock,
        signal,
        writer,
        _sel_deadline(),
    )
    assert_equal(coll.persisted_attempt, UInt64(1))
    assert_equal(coll.filtered, UInt64(5))
    assert_equal(coll.table.len(), 1)


def test_selection_unavailable_name_finalizes_empty() raises:
    var coll = Collector(_sel_config(String("never-seen")))
    coll.session_id = String("sel-test")
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    _ = coll._admit_attempt(
        _sel_attempt(UInt64(1), UInt64(10), UInt64(64),
                     String("dev-a")),
        clock,
        signal,
        writer,
        _sel_deadline(),
    )
    assert_equal(coll.persisted_attempt, UInt64(0))
    assert_equal(coll.filtered, UInt64(1))
    assert_equal(coll.table.len(), 0)
    assert_equal(len(writer.lines), 0)
    var sess = coll.assemble()
    assert_true(sess.has_filter_device)
    assert_equal(sess.filter_device, String("never-seen"))
    assert_true(sess.finalized)


def test_selection_non_utf8_stays_rejected() raises:
    # Malformed names stay malformed under a filter; they
    # are rejected, never counted as selection drops.
    var coll = Collector(_sel_config(String("dev-a")))
    coll.session_id = String("sel-test")
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    var raw = List[UInt8]()
    raw.append(UInt8(0xFF))
    raw.append(UInt8(0xFE))
    var res = coll._admit_attempt(
        _sel_attempt_raw(UInt64(1), UInt64(10), UInt64(64), raw),
        clock,
        signal,
        writer,
        _sel_deadline(),
    )
    assert_equal(res, String(""))
    assert_equal(coll.persisted_attempt, UInt64(0))
    assert_equal(coll.filtered, UInt64(0))
    assert_equal(coll.rejected, UInt64(1))


def test_selection_lifecycle_pair_retained() raises:
    # Unattributed lifecycle records ignore the device
    # selector: every map keeps its unmap completion.
    var coll = Collector(_sel_config(String("dev-a")))
    coll.session_id = String("sel-test")
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    var r1 = coll._admit_lifecycle(
        _sel_lifecycle(1, UInt64(1)),
        clock,
        signal,
        writer,
        _sel_deadline(),
    )
    var r2 = coll._admit_lifecycle(
        _sel_lifecycle(2, UInt64(1)),
        clock,
        signal,
        writer,
        _sel_deadline(),
    )
    assert_equal(r1, String(""))
    assert_equal(r2, String(""))
    assert_equal(coll.persisted_map, UInt64(1))
    assert_equal(coll.persisted_unmap, UInt64(1))
    assert_equal(coll.filtered, UInt64(0))
    assert_equal(len(writer.lines), 2)


def test_selection_copy_retained() raises:
    var coll = Collector(_sel_config(String("dev-a")))
    coll.session_id = String("sel-test")
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    var res = coll._admit_copy(
        _sel_copy(), clock, signal, writer, _sel_deadline()
    )
    assert_equal(res, String(""))
    assert_equal(coll.persisted_copy, UInt64(1))
    assert_equal(coll.filtered, UInt64(0))
    assert_equal(len(writer.lines), 1)


def test_selection_session_scope_names_drops() raises:
    var coll = Collector(_sel_config(String("dev-a")))
    coll.session_id = String("sel-test")
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    _ = coll._admit_attempt(
        _sel_attempt(UInt64(1), UInt64(10), UInt64(64),
                     String("dev-b")),
        clock,
        signal,
        writer,
        _sel_deadline(),
    )
    _ = coll._admit_attempt(
        _sel_attempt(UInt64(2), UInt64(11), UInt64(64),
                     String("dev-a")),
        clock,
        signal,
        writer,
        _sel_deadline(),
    )
    var sess = coll.assemble()
    assert_true(sess.has_filter_device)
    assert_equal(sess.filter_device, String("dev-a"))
    assert_true(_sel_contains(sess.q_detail.scope, String("dev-a")))
    assert_true(_sel_contains(sess.q_detail.scope, String("1")))


def test_selection_drops_are_not_loss() raises:
    # Deliberate narrowing is recorded scope, not evidence
    # loss: with proven closure and nothing else missing,
    # detail quality stays complete despite drops.
    var coll = Collector(_sel_config(String("dev-a")))
    coll.session_id = String("sel-test")
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = NullWriter()
    _ = coll._admit_attempt(
        _sel_attempt(UInt64(1), UInt64(10), UInt64(64),
                     String("dev-b")),
        clock,
        signal,
        writer,
        _sel_deadline(),
    )
    _ = coll._admit_attempt(
        _sel_attempt(UInt64(2), UInt64(11), UInt64(64),
                     String("dev-a")),
        clock,
        signal,
        writer,
        _sel_deadline(),
    )
    assert_equal(coll.filtered, UInt64(1))
    coll.has_end_cut = True
    coll.end_vals = List[UInt64]()
    for _ in range(6):
        coll.end_vals.append(UInt64(0))
    coll.has_final_stats = True
    coll.has_recursion = True
    var sess = coll.assemble()
    assert_equal(sess.q_detail.status, String("complete_for_scope"))
    assert_true(sess.q_detail.has_loss_count)
    assert_equal(sess.q_detail.loss_count, UInt64(0))


def test_selection_absent_without_filter() raises:
    var coll = Collector(_sel_config(String("")))
    coll.session_id = String("sel-test")
    var sess = coll.assemble()
    assert_true(not sess.has_filter_device)
    assert_true(
        not _sel_contains(sess.q_detail.scope, String("selection"))
    )


def test_selection_full_run_control_finalizes() raises:
    # Harness sanity: the same script without a selector
    # finalizes with complete detail and zero loss.
    var names = List[String]()
    names.append(String("dev-a"))
    names.append(String("dev-b"))
    var c = _sel_run(names, String(""))
    assert_equal(c.outcome, String("finalized"))
    assert_equal(c.end_reason, String("signal"))
    assert_true(c.finalized)
    assert_equal(c.persisted_attempt, UInt64(2))
    assert_equal(c.filtered, UInt64(0))
    assert_equal(c.catalog_len, 2)
    var sess = parse_session(c.session)
    assert_true(not sess.has_filter_device)
    assert_equal(sess.q_detail.status, String("complete_for_scope"))
    assert_true(sess.q_detail.has_loss_count)
    assert_equal(sess.q_detail.loss_count, UInt64(0))


def test_selection_full_run_finalizes_with_drops() raises:
    # One retained attempt plus one selection drop must
    # finalize exactly like the unfiltered control: drops
    # are delivered payloads with a known disposition, so
    # the close-out delivery identity must count them.
    var names = List[String]()
    names.append(String("dev-b"))
    names.append(String("dev-a"))
    var c = _sel_run(names, String("dev-a"))
    var base = List[String]()
    base.append(String("dev-a"))
    base.append(String("dev-b"))
    var c0 = _sel_run(base, String(""))
    assert_equal(c.outcome, String("finalized"))
    assert_equal(c.end_reason, String("signal"))
    assert_true(c.finalized)
    assert_equal(c.exit_code, c0.exit_code)
    assert_equal(c.persisted_attempt, UInt64(1))
    assert_equal(c.filtered, UInt64(1))
    assert_equal(c.catalog_len, 1)
    var sess = parse_session(c.session)
    assert_true(sess.has_filter_device)
    assert_equal(sess.filter_device, String("dev-a"))
    assert_equal(sess.q_detail.status, String("complete_for_scope"))
    assert_true(sess.q_detail.has_loss_count)
    assert_equal(sess.q_detail.loss_count, UInt64(0))
    assert_true(_sel_contains(sess.q_detail.scope, String("dev-a")))


def test_selection_full_run_unavailable_name_finalizes() raises:
    # A selector matching nothing still finalizes when
    # other devices emit attempts: every delivered
    # payload is either persisted or deliberately
    # dropped, never unaccounted.
    var names = List[String]()
    names.append(String("dev-a"))
    names.append(String("dev-b"))
    var c = _sel_run(names, String("never-seen"))
    var base = List[String]()
    base.append(String("dev-a"))
    base.append(String("dev-b"))
    var c0 = _sel_run(base, String(""))
    assert_equal(c.outcome, String("finalized"))
    assert_equal(c.end_reason, String("signal"))
    assert_true(c.finalized)
    assert_equal(c.exit_code, c0.exit_code)
    assert_equal(c.persisted_attempt, UInt64(0))
    assert_equal(c.filtered, UInt64(2))
    assert_equal(c.catalog_len, 0)
    var sess = parse_session(c.session)
    assert_true(sess.has_filter_device)
    assert_equal(sess.filter_device, String("never-seen"))
    assert_equal(sess.q_detail.status, String("complete_for_scope"))
    assert_true(sess.q_detail.has_loss_count)
    assert_equal(sess.q_detail.loss_count, UInt64(0))
    assert_true(
        _sel_contains(sess.q_detail.scope, String("never-seen"))
    )


def test_selection_scope_boundary_round_trip() raises:
    # An idle capture scopes "0 bounce_attempt events"
    # (23) plus "; device selection " (19), the selector,
    # " dropped " (9), "0" (1), and " non-matching
    # attempts" (22): the literal selector stays in the
    # scope phrase through 182 characters and is elided
    # past it, while the recorded filter keeps the exact
    # selector and every session reparses.
    var fitting = _sel_repeat(String("s"), 182)
    var c = _sel_run(List[String](), fitting)
    assert_equal(c.outcome, String("finalized"))
    assert_true(c.finalized)
    var sess = parse_session(c.session)
    assert_true(sess.has_filter_device)
    assert_equal(sess.filter_device, fitting)
    assert_equal(sess.q_detail.scope.count_codepoints(), 256)
    assert_true(_sel_contains(sess.q_detail.scope, fitting))
    var text = encode_session(sess)
    var back = parse_session(_sel_bytes(text))
    assert_equal(back.filter_device, fitting)
    assert_equal(back.q_detail.scope, sess.q_detail.scope)
    var past = _sel_repeat(String("s"), 183)
    var c2 = _sel_run(List[String](), past)
    assert_equal(c2.outcome, String("finalized"))
    assert_true(c2.finalized)
    var sess2 = parse_session(c2.session)
    assert_true(sess2.has_filter_device)
    assert_equal(sess2.filter_device, past)
    assert_true(sess2.q_detail.scope.count_codepoints() <= 256)
    assert_true(not _sel_contains(sess2.q_detail.scope, past))
    assert_true(
        _sel_contains(
            sess2.q_detail.scope,
            String("dropped 0 non-matching attempts"),
        )
    )
    var longest = _sel_repeat(String("q"), 256)
    var c3 = _sel_run(List[String](), longest)
    assert_equal(c3.outcome, String("finalized"))
    assert_true(c3.finalized)
    var sess3 = parse_session(c3.session)
    assert_equal(sess3.filter_device, longest)
    assert_true(sess3.q_detail.scope.count_codepoints() <= 256)
    var text3 = encode_session(sess3)
    var back3 = parse_session(_sel_bytes(text3))
    assert_equal(back3.filter_device, longest)
    assert_equal(back3.q_detail.scope, sess3.q_detail.scope)


def test_selection_scope_counts_codepoints() raises:
    # Scope fit is measured in characters, not bytes: 180
    # two-byte codepoints (434 scope bytes, 254 scope
    # characters) still name the selector verbatim, and a
    # full 256-codepoint multibyte selector records
    # literally and reparses with a bounded scope.
    var eacute = _sel_eacute()
    var fitting = _sel_repeat(eacute, 180)
    assert_equal(fitting.count_codepoints(), 180)
    var c = _sel_run(List[String](), fitting)
    assert_equal(c.outcome, String("finalized"))
    var sess = parse_session(c.session)
    assert_equal(sess.filter_device, fitting)
    assert_equal(sess.q_detail.scope.count_codepoints(), 254)
    assert_true(_sel_contains(sess.q_detail.scope, fitting))
    var longest = _sel_repeat(eacute, 256)
    assert_equal(longest.count_codepoints(), 256)
    var c2 = _sel_run(List[String](), longest)
    assert_equal(c2.outcome, String("finalized"))
    var sess2 = parse_session(c2.session)
    assert_equal(sess2.filter_device, longest)
    assert_true(sess2.q_detail.scope.count_codepoints() <= 256)
    var text2 = encode_session(sess2)
    var back2 = parse_session(_sel_bytes(text2))
    assert_equal(back2.filter_device, longest)
    assert_equal(back2.q_detail.scope, sess2.q_detail.scope)


def test_selection_long_selector_run_replayable() raises:
    # A longest accepted selector over live traffic
    # finalizes with delivery accounting intact (drops
    # counted, loss still zero) and a session the reader
    # accepts, even though the scope phrase cannot name
    # the selector verbatim.
    var filt = _sel_repeat(String("q"), 256)
    var names = List[String]()
    names.append(String("dev-a"))
    names.append(String("dev-b"))
    var c = _sel_run(names, filt)
    var base = List[String]()
    base.append(String("dev-a"))
    base.append(String("dev-b"))
    var c0 = _sel_run(base, String(""))
    assert_equal(c.outcome, String("finalized"))
    assert_true(c.finalized)
    assert_equal(c.exit_code, c0.exit_code)
    assert_equal(c.persisted_attempt, UInt64(0))
    assert_equal(c.filtered, UInt64(2))
    var sess = parse_session(c.session)
    assert_true(sess.has_filter_device)
    assert_equal(sess.filter_device, filt)
    assert_true(sess.q_detail.has_loss_count)
    assert_equal(sess.q_detail.loss_count, UInt64(0))
    assert_true(sess.q_detail.scope.count_codepoints() <= 256)
    assert_true(not _sel_contains(sess.q_detail.scope, filt))
    assert_true(
        _sel_contains(
            sess.q_detail.scope,
            String("dropped 2 non-matching attempts"),
        )
    )


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_selection_keeps_matching_drops_others]()
    suite.test[test_selection_disabled_keeps_all]()
    suite.test[test_selection_late_discovery_matches]()
    suite.test[test_selection_unavailable_name_finalizes_empty]()
    suite.test[test_selection_non_utf8_stays_rejected]()
    suite.test[test_selection_lifecycle_pair_retained]()
    suite.test[test_selection_copy_retained]()
    suite.test[test_selection_session_scope_names_drops]()
    suite.test[test_selection_drops_are_not_loss]()
    suite.test[test_selection_absent_without_filter]()
    suite.test[test_selection_full_run_control_finalizes]()
    suite.test[test_selection_full_run_finalizes_with_drops]()
    suite.test[test_selection_full_run_unavailable_name_finalizes]()
    suite.test[test_selection_scope_boundary_round_trip]()
    suite.test[test_selection_scope_counts_codepoints]()
    suite.test[test_selection_long_selector_run_replayable]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
