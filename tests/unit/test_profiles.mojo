# SPDX-License-Identifier: GPL-3.0-or-later

"""Profile-layer unit tests: reader, evidence, and profiles.

Reader tests pin the meta.txt grammar and the absent/denied split.
Evidence tests pin floor checks and every guest-technology branch,
including conflicts and fixture-only assertions. Profile tests pin
strict manifest/document parsing plus identity selection. Fixture
trees live under tests/fixtures/capabilities/.
"""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.capabilities import (
    CapEntry,
    CapabilityReport,
    discover_capabilities,
)
from memveil.platform.evidence import detect_environment, parse_kernel_triple
from memveil.platform.profiles import (
    Profile,
    load_profiles,
    parse_profile_bytes,
    select_profile,
)
from memveil.platform.reader import (
    EVIDENCE_ABSENT,
    EVIDENCE_DENIED,
    EVIDENCE_OK,
    E_ABSENT,
    E_DENIED,
    E_META_BAD,
    E_META_MISSING,
    E_TOO_BIG,
    bytes_to_text,
    file_state,
    is_valid_utf8,
    open_evidence_reader,
    read_evidence,
)


def fx(name: String) -> String:
    """Fixture directory path for one capabilities fixture name."""
    return "tests/fixtures/capabilities/" + name


def bytes_of(s: String) -> List[UInt8]:
    """Copy a String into a byte list for the document parser."""
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def contains(hay: String, needle: String) -> Bool:
    """True when needle occurs in hay at least once."""
    return len(hay.split(String(needle))) > 1


def has_signal(signals: List[String], want: String) -> Bool:
    """True when the signal list holds want exactly."""
    for i in range(len(signals)):
        if signals[i] == want:
            return True
    return False


def test_meta_ok() raises:
    var r = open_evidence_reader(fx("ordinary-7.0"))
    assert_equal(r.arch, String("x86_64"))
    assert_equal(r.release, String("7.0.0-34-generic"))
    assert_equal(r.euid, 1001)
    assert_equal(len(r.denied), 0)
    assert_equal(r.asserted_guest_tech, String(""))


def test_meta_missing() raises:
    var raised = False
    try:
        _ = open_evidence_reader(fx("profiles-test"))
    except e:
        raised = True
        assert_equal(e.code, E_META_MISSING)
    assert_true(raised)


def test_meta_dup() raises:
    var raised = False
    try:
        _ = open_evidence_reader(fx("meta-bad-dup"))
    except e:
        raised = True
        assert_equal(e.code, E_META_BAD)
    assert_true(raised)


def test_meta_unknown_key() raises:
    var raised = False
    try:
        _ = open_evidence_reader(fx("meta-bad-unknown-key"))
    except e:
        raised = True
        assert_equal(e.code, E_META_BAD)
    assert_true(raised)


def test_meta_euid_alpha() raises:
    var raised = False
    try:
        _ = open_evidence_reader(fx("meta-bad-euid-alpha"))
    except e:
        raised = True
        assert_equal(e.code, E_META_BAD)
    assert_true(raised)


def test_meta_euid_huge() raises:
    var raised = False
    try:
        _ = open_evidence_reader(fx("meta-bad-euid-huge"))
    except e:
        raised = True
        assert_equal(e.code, E_META_BAD)
    assert_true(raised)


def test_meta_denied_relative() raises:
    var raised = False
    try:
        _ = open_evidence_reader(fx("meta-bad-denied-relative"))
    except e:
        raised = True
        assert_equal(e.code, E_META_BAD)
    assert_true(raised)


def test_meta_bad_tech() raises:
    var raised = False
    try:
        _ = open_evidence_reader(fx("meta-bad-tech"))
    except e:
        raised = True
        assert_equal(e.code, E_META_BAD)
    assert_true(raised)


def test_meta_arch_long() raises:
    var raised = False
    try:
        _ = open_evidence_reader(fx("meta-bad-arch-long"))
    except e:
        raised = True
        assert_equal(e.code, E_META_BAD)
    assert_true(raised)


def test_meta_release_long() raises:
    var raised = False
    try:
        _ = open_evidence_reader(fx("meta-bad-release-long"))
    except e:
        raised = True
        assert_equal(e.code, E_META_BAD)
    assert_true(raised)


def test_meta_denied_long() raises:
    var raised = False
    try:
        _ = open_evidence_reader(fx("meta-bad-denied-long"))
    except e:
        raised = True
        assert_equal(e.code, E_META_BAD)
    assert_true(raised)


def test_meta_nul() raises:
    var raised = False
    try:
        _ = open_evidence_reader(fx("meta-bad-nul"))
    except e:
        raised = True
        assert_equal(e.code, E_META_BAD)
    assert_true(raised)


def test_meta_utf8() raises:
    var raised = False
    try:
        _ = open_evidence_reader(fx("meta-bad-utf8"))
    except e:
        raised = True
        assert_equal(e.code, E_META_BAD)
    assert_true(raised)


def test_asserted_tech_ok() raises:
    var r = open_evidence_reader(fx("user-asserted-snp"))
    assert_equal(r.asserted_guest_tech, String("snp"))


def test_denied_list_ok() raises:
    var r = open_evidence_reader(fx("denied-tracepoint"))
    assert_equal(len(r.denied), 1)
    assert_equal(
        r.denied[0],
        String("/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"),
    )


def test_file_state_split() raises:
    var r = open_evidence_reader(fx("ordinary-7.0"))
    assert_equal(file_state(r, String("/proc/cpuinfo")), EVIDENCE_OK)
    assert_equal(
        file_state(r, String("/proc/no-such-memveil")), EVIDENCE_ABSENT
    )
    var d = open_evidence_reader(fx("denied-tracepoint"))
    assert_equal(
        file_state(
            d,
            String(
                "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"
            ),
        ),
        EVIDENCE_DENIED,
    )


def _test_cstr(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


def _test_chmod_all(base: String):
    var c = _test_cstr(base + String("/sub"))
    _ = external_call["chmod", Int32](Span(c).unsafe_ptr(), 493)
    var f = _test_cstr(base + String("/sub/f"))
    _ = external_call["unlink", Int32](Span(f).unsafe_ptr())
    _ = external_call["rmdir", Int32](Span(c).unsafe_ptr())
    var b = _test_cstr(base)
    _ = external_call["rmdir", Int32](Span(b).unsafe_ptr())


def test_eacces_parent_is_denied() raises:
    if Int(external_call["geteuid", UInt32]()) == 0:
        return
    var base = String("/tmp/memveil-m1-perm")
    _test_chmod_all(base)
    var b = _test_cstr(base)
    _ = external_call["mkdir", Int32](Span(b).unsafe_ptr(), 493)
    var s = _test_cstr(base + String("/sub"))
    _ = external_call["mkdir", Int32](Span(s).unsafe_ptr(), 493)
    var f = _test_cstr(base + String("/sub/f"))
    var m = _test_cstr("w")
    var fp = external_call["fopen", UInt64](
        Span(f).unsafe_ptr(), Span(m).unsafe_ptr()
    )
    assert_true(fp != 0)
    _ = external_call["fclose", Int32](fp)
    var z = _test_cstr(base + String("/sub"))
    _ = external_call["chmod", Int32](Span(z).unsafe_ptr(), 0)
    var r = open_evidence_reader(String(""))
    assert_equal(
        file_state(r, base + String("/sub/f")), EVIDENCE_DENIED
    )
    assert_equal(
        file_state(r, base + String("/no-such-memveil")), EVIDENCE_ABSENT
    )
    var up = _test_cstr(base + String("/sub"))
    _ = external_call["chmod", Int32](Span(up).unsafe_ptr(), 493)
    _test_chmod_all(base)


def test_read_absent() raises:
    var r = open_evidence_reader(fx("ordinary-7.0"))
    var raised = False
    try:
        _ = read_evidence(r, String("/proc/no-such-memveil"), 1024)
    except e:
        raised = True
        assert_equal(e.code, E_ABSENT)
    assert_true(raised)


def test_read_denied() raises:
    var r = open_evidence_reader(fx("denied-tracepoint"))
    var raised = False
    try:
        _ = read_evidence(
            r,
            String("/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"),
            65536,
        )
    except e:
        raised = True
        assert_equal(e.code, E_DENIED)
    assert_true(raised)


def test_read_too_big() raises:
    var r = open_evidence_reader(fx("ordinary-7.0"))
    var raised = False
    try:
        _ = read_evidence(r, String("/proc/cpuinfo"), 10)
    except e:
        raised = True
        assert_equal(e.code, E_TOO_BIG)
    assert_true(raised)


def test_bytes_to_text() raises:
    var raw = bytes_of(String("ab"))
    assert_equal(bytes_to_text(raw^), String("ab"))
    var bad = List[UInt8]()
    bad.append(UInt8(0xFF))
    var rep = bytes_to_text(bad^)
    assert_equal(rep.byte_length(), 3)


def bytes_from_ints(vals: List[Int]) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(len(vals)):
        out.append(UInt8(vals[i]))
    return out^


def test_utf8_valid() raises:
    assert_true(is_valid_utf8(bytes_of(String("abc"))))
    assert_true(is_valid_utf8(bytes_of(String(""))))
    var cafe = List[Int]()
    cafe.append(0x63)
    cafe.append(0xC3)
    cafe.append(0xA9)
    assert_true(is_valid_utf8(bytes_from_ints(cafe^)))
    var cjk = List[Int]()
    cjk.append(0xE6)
    cjk.append(0x97)
    cjk.append(0xA5)
    assert_true(is_valid_utf8(bytes_from_ints(cjk^)))
    var emoji = List[Int]()
    emoji.append(0xF0)
    emoji.append(0x9F)
    emoji.append(0x98)
    emoji.append(0x80)
    assert_true(is_valid_utf8(bytes_from_ints(emoji^)))


def test_utf8_invalid() raises:
    var lone = List[Int]()
    lone.append(0xFF)
    assert_true(not is_valid_utf8(bytes_from_ints(lone^)))
    var cont = List[Int]()
    cont.append(0x80)
    assert_true(not is_valid_utf8(bytes_from_ints(cont^)))
    var over2 = List[Int]()
    over2.append(0xC0)
    over2.append(0xAF)
    assert_true(not is_valid_utf8(bytes_from_ints(over2^)))
    var over3 = List[Int]()
    over3.append(0xE0)
    over3.append(0x80)
    over3.append(0x80)
    assert_true(not is_valid_utf8(bytes_from_ints(over3^)))
    var surr = List[Int]()
    surr.append(0xED)
    surr.append(0xA0)
    surr.append(0x80)
    assert_true(not is_valid_utf8(bytes_from_ints(surr^)))
    var over4 = List[Int]()
    over4.append(0xF0)
    over4.append(0x80)
    over4.append(0x80)
    over4.append(0x80)
    assert_true(not is_valid_utf8(bytes_from_ints(over4^)))
    var past = List[Int]()
    past.append(0xF4)
    past.append(0x90)
    past.append(0x80)
    past.append(0x80)
    assert_true(not is_valid_utf8(bytes_from_ints(past^)))
    var f5 = List[Int]()
    f5.append(0xF5)
    f5.append(0x80)
    f5.append(0x80)
    f5.append(0x80)
    assert_true(not is_valid_utf8(bytes_from_ints(f5^)))
    var trunc = List[Int]()
    trunc.append(0xE2)
    trunc.append(0x82)
    assert_true(not is_valid_utf8(bytes_from_ints(trunc^)))
    var badcont = List[Int]()
    badcont.append(0xE2)
    badcont.append(0x28)
    badcont.append(0xA1)
    assert_true(not is_valid_utf8(bytes_from_ints(badcont^)))


def test_triple_parse() raises:
    var t = parse_kernel_triple(String("7.0.0-34-generic"))
    assert_true(t.ok)
    assert_equal(t.major, 7)
    assert_equal(t.minor, 0)
    assert_equal(t.patch, 0)
    var u = parse_kernel_triple(String("6.8.0"))
    assert_true(u.ok and u.major == 6 and u.minor == 8 and u.patch == 0)
    var v = parse_kernel_triple(String("7"))
    assert_true(v.ok and v.major == 7 and v.minor == 0 and v.patch == 0)
    var w = parse_kernel_triple(String("8.1"))
    assert_true(w.ok and w.major == 8 and w.minor == 1)
    assert_true(not parse_kernel_triple(String("nope")).ok)
    assert_true(not parse_kernel_triple(String("")).ok)
    assert_true(not parse_kernel_triple(String("7.")).ok)
    assert_true(not parse_kernel_triple(String(".7")).ok)
    var x = parse_kernel_triple(String("7.0.0.0"))
    assert_true(x.ok and x.major == 7 and x.minor == 0 and x.patch == 0)
    assert_true(
        not parse_kernel_triple(String("123456789012345678901234567890")).ok
    )


def test_floor_pass() raises:
    var r = open_evidence_reader(fx("ordinary-7.0"))
    var env = detect_environment(r)
    assert_true(env.kernel.eligible_floor)
    assert_equal(
        env.kernel.floor_reason,
        String("release 7.0.0-34-generic meets the 7.0 floor"),
    )


def test_floor_fail() raises:
    var r = open_evidence_reader(fx("kernel-6.8"))
    var env = detect_environment(r)
    assert_true(not env.kernel.eligible_floor)
    assert_equal(
        env.kernel.floor_reason,
        String("release 6.8.0-41-generic is below the 7.0 floor"),
    )


def test_floor_unparseable() raises:
    var r = open_evidence_reader(fx("malformed-release"))
    var env = detect_environment(r)
    assert_true(not env.kernel.eligible_floor)
    assert_equal(
        env.kernel.floor_reason,
        String("release not-a-kernel-release is unparseable; floor unknown"),
    )


def test_guest_ordinary() raises:
    var r = open_evidence_reader(fx("ordinary-7.0"))
    var env = detect_environment(r)
    assert_equal(env.guest.tech, String("ordinary"))
    assert_true(not env.guest.asserted)
    assert_equal(env.guest.conflict, String(""))
    assert_equal(len(env.guest.signals), 8)
    assert_equal(env.guest.signals[0], String("sev-node:absent"))
    assert_equal(env.guest.signals[1], String("tdx-node:absent"))
    assert_equal(env.guest.signals[2], String("cpu-flags:ok:none"))
    assert_equal(
        env.guest.signals[3], String("ordinary:absent-nodes-inference")
    )
    assert_equal(env.guest.signals[4], String("info:btf:present:24B"))
    assert_equal(env.guest.signals[5], String("info:config-gz:absent"))
    assert_equal(env.guest.signals[6], String("info:os:ubuntu:24.04"))
    assert_equal(env.guest.signals[7], String("info:boot-config:absent"))


def test_guest_snp() raises:
    var r = open_evidence_reader(fx("snp-7.0"))
    var env = detect_environment(r)
    assert_equal(env.guest.tech, String("snp"))
    assert_true(not env.guest.asserted)
    assert_true(has_signal(env.guest.signals, String("sev-node:present")))
    assert_true(
        has_signal(env.guest.signals, String("cpu-flags:ok:sev+sev_snp"))
    )


def test_guest_tdx() raises:
    var r = open_evidence_reader(fx("tdx-7.0"))
    var env = detect_environment(r)
    assert_equal(env.guest.tech, String("tdx"))
    assert_true(
        has_signal(env.guest.signals, String("cpu-flags:ok:tdx_guest"))
    )


def test_guest_sev_classic() raises:
    var r = open_evidence_reader(fx("sev-classic-7.0"))
    var env = detect_environment(r)
    assert_equal(env.guest.tech, String("sev-classic"))
    assert_true(has_signal(env.guest.signals, String("cpu-flags:ok:sev")))


def test_guest_unavailable() raises:
    var r = open_evidence_reader(fx("unavailable-evidence"))
    var env = detect_environment(r)
    assert_equal(env.guest.tech, String("unknown"))
    assert_equal(env.guest.conflict, String(""))
    assert_true(has_signal(env.guest.signals, String("cpu-flags:absent")))


def test_guest_conflict_nodes() raises:
    var r = open_evidence_reader(fx("conflicting-evidence"))
    var env = detect_environment(r)
    assert_equal(env.guest.tech, String("unknown"))
    assert_equal(
        env.guest.conflict,
        String("sev-guest and tdx-guest nodes both present"),
    )


def test_guest_conflict_flags() raises:
    var r = open_evidence_reader(fx("conflicting-flags"))
    var env = detect_environment(r)
    assert_equal(env.guest.tech, String("unknown"))
    assert_equal(
        env.guest.conflict,
        String("sev-guest node present but cpu flags lack sev"),
    )


def test_guest_conflict_mixed_sev() raises:
    var r = open_evidence_reader(fx("conflicting-flags-sev-tdx"))
    var env = detect_environment(r)
    assert_equal(env.guest.tech, String("unknown"))
    assert_equal(
        env.guest.conflict,
        String("sev-guest node present with tdx_guest cpu flag"),
    )


def test_guest_conflict_mixed_tdx() raises:
    var r = open_evidence_reader(fx("conflicting-flags-tdx-sev"))
    var env = detect_environment(r)
    assert_equal(env.guest.tech, String("unknown"))
    assert_equal(
        env.guest.conflict,
        String("tdx-guest node present with sev cpu flags"),
    )


def test_asserted_tiebreak() raises:
    var r = open_evidence_reader(fx("user-asserted-snp"))
    var env = detect_environment(r)
    assert_equal(env.guest.tech, String("snp"))
    assert_true(env.guest.asserted)
    assert_true(has_signal(env.guest.signals, String("asserted:snp")))


def test_asserted_agree() raises:
    var r = open_evidence_reader(fx("user-asserted-agree"))
    var env = detect_environment(r)
    assert_equal(env.guest.tech, String("snp"))
    assert_true(env.guest.asserted)
    assert_equal(env.guest.conflict, String(""))


def test_asserted_conflict() raises:
    var r = open_evidence_reader(fx("user-asserted-conflict"))
    var env = detect_environment(r)
    assert_equal(env.guest.tech, String("unknown"))
    assert_true(env.guest.asserted)
    assert_equal(
        env.guest.conflict, String("evidence says snp, asserted tdx")
    )


def test_denied_guest_node() raises:
    var r = open_evidence_reader(fx("denied-guest-node"))
    var env = detect_environment(r)
    assert_equal(env.guest.tech, String("unknown"))
    assert_equal(len(env.denied), 1)
    assert_equal(env.denied[0], String("/dev/sev-guest"))
    assert_true(has_signal(env.guest.signals, String("sev-node:denied")))


def test_btf_states() raises:
    var r = open_evidence_reader(fx("ordinary-7.0"))
    var env = detect_environment(r)
    assert_equal(env.btf_state, EVIDENCE_OK)
    assert_equal(env.btf_bytes, 24)
    var m = open_evidence_reader(fx("missing-btf"))
    var menv = detect_environment(m)
    assert_equal(menv.btf_state, EVIDENCE_ABSENT)
    assert_true(has_signal(menv.guest.signals, String("info:btf:absent")))


def test_hostile_release() raises:
    var r = open_evidence_reader(fx("meta-release-hostile"))
    var env = detect_environment(r)
    assert_true(env.kernel.eligible_floor)
    assert_true(
        has_signal(
            env.guest.signals,
            String("info:boot-config:skipped-unsafe-release"),
        )
    )


def minimal_doc() -> String:
    """One minimal valid profile document."""
    return String(
        '{"schema_version":"0.1.0","profile_id":"t",'
        '"status":"reference-unvalidated","identity":{"arch":"x86_64",'
        '"min_kernel":"7.0","source":{"origin":"o","revision":"r"}},'
        '"hooks":[{"name":"h","kind":"tracepoint","id_path":"/i",'
        '"format_path":"/f"}],"capabilities":[{"id":"attempt-trace",'
        '"status":"candidate","hooks":["h"],"reason":"r"}]}'
    )


def expect_reject(doc: String) raises:
    """Assert the document parser rejects one document."""
    var raised = False
    try:
        _ = parse_profile_bytes(bytes_of(doc))
    except e:
        raised = True
        assert_true(String(e).byte_length() > 0)
    assert_true(raised)


def test_parse_conversion_capability() raises:
    var doc = minimal_doc().replace(
        String('"id":"attempt-trace"'),
        String('"id":"conversion-observe"'),
    )
    var p = parse_profile_bytes(bytes_of(doc))
    assert_equal(len(p.caps), 1)
    assert_equal(p.caps[0].id, String("conversion-observe"))


def test_admitted_profiles_lack_conversion() raises:
    # Guard: no shipped profile declares conversion hooks
    # until kernel-source evidence admits them (E02 blocked).
    var ps = load_profiles(String("profiles"))
    for i in range(len(ps)):
        for j in range(len(ps[i].caps)):
            assert_true(ps[i].caps[j].id != String("conversion-observe"))


def test_parse_minimal_ok() raises:
    var p = parse_profile_bytes(bytes_of(minimal_doc()))
    assert_equal(p.profile_id, String("t"))
    assert_equal(p.status, String("reference-unvalidated"))
    assert_equal(p.identity.arch, String("x86_64"))
    assert_equal(p.identity.min_major, 7)
    assert_equal(p.identity.min_minor, 0)
    assert_equal(p.identity.min_patch, 0)
    assert_equal(len(p.hooks), 1)
    assert_true(not p.hooks[0].format_has)
    assert_equal(len(p.caps), 1)
    assert_equal(len(p.notes), 0)


def test_parse_reference_file() raises:
    var ps = load_profiles(String("profiles"))
    assert_equal(len(ps), 2)
    assert_equal(ps[0].profile_id, String("linux-x86_64-7.0-reference"))
    assert_equal(ps[0].status, String("reference-unvalidated"))
    assert_equal(len(ps[0].hooks), 1)
    assert_equal(len(ps[0].caps), 3)
    assert_equal(len(ps[0].notes), 3)
    # Manifest order stays reference-first; the narrow gate
    # doc appends for the two-phase collection scan. Its
    # status is asserted by the VM gate, not pinned here.
    assert_equal(
        ps[1].profile_id, String("linux-x86_64-7.0.0-34-generic")
    )
    assert_equal(len(ps[1].hooks), 1)
    assert_true(ps[1].hooks[0].format_has)


def test_parse_validated_file() raises:
    var ps = load_profiles(fx("profiles-test"))
    assert_equal(len(ps), 1)
    assert_equal(ps[0].status, String("validated"))
    assert_true(ps[0].hooks[0].format_has)
    assert_equal(ps[0].hooks[0].format_text.byte_length(), 144)


def test_parse_bad_status() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t","status":"draft",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[]}'
        )
    )


def test_parse_bad_version() raises:
    expect_reject(
        String(
            '{"schema_version":"0.2.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[]}'
        )
    )


def test_parse_unknown_key() raises:
    var parts = minimal_doc().split(String("}]}"))
    assert_equal(len(parts), 2)
    expect_reject(String(parts[0]) + String(',"zzz":1}]}'))


def test_parse_dup_key() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t","profile_id":"u",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[]}'
        )
    )


def test_parse_bad_profile_id() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"-lead",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[]}'
        )
    )


def test_parse_bad_min_kernel() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.x",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[]}'
        )
    )


def test_parse_short_min_kernel() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[]}'
        )
    )


def test_parse_bad_kind() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},'
            '"hooks":[{"name":"h","kind":"kprobe","id_path":"/i",'
            '"format_path":"/f"}],"capabilities":[]}'
        )
    )


def test_parse_dup_hook() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},'
            '"hooks":[{"name":"h","kind":"tracepoint","id_path":"/i",'
            '"format_path":"/f"},{"name":"h","kind":"tracepoint",'
            '"id_path":"/i2","format_path":"/f2"}],"capabilities":[]}'
        )
    )


def test_parse_dangling_ref() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[{"id":"attempt-trace","status":"candidate",'
            '"hooks":["nope"],"reason":"r"}]}'
        )
    )


def test_parse_dup_cap() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[{"id":"attempt-trace","status":"candidate",'
            '"hooks":[],"reason":"r"},{"id":"attempt-trace",'
            '"status":"unsupported","hooks":[],"reason":"s"}]}'
        )
    )


def test_parse_bad_cap_id() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[{"id":"trace-all","status":"candidate",'
            '"hooks":[],"reason":"r"}]}'
        )
    )


def test_parse_bad_cap_status() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[{"id":"attempt-trace","status":"maybe",'
            '"hooks":[],"reason":"r"}]}'
        )
    )


def test_parse_missing_field() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[{"id":"attempt-trace","status":"candidate",'
            '"hooks":[]}]}'
        )
    )


def test_parse_trailing_data() raises:
    expect_reject(minimal_doc() + String("x"))


def test_parse_format_type() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},'
            '"hooks":[{"name":"h","kind":"tracepoint","id_path":"/i",'
            '"format_path":"/f","format_text":123}],"capabilities":[]}'
        )
    )


def test_parse_overlong_name() raises:
    var name = String("")
    for _ in range(129):
        name += "n"
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},'
            '"hooks":[{"name":"'
        )
        + name
        + String(
            '","kind":"tracepoint","id_path":"/i","format_path":"/f"}],'
            '"capabilities":[]}'
        )
    )


def test_parse_hook_path_traversal() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},'
            '"hooks":[{"name":"h","kind":"tracepoint",'
            '"id_path":"/../outside/id","format_path":"/f"}],'
            '"capabilities":[]}'
        )
    )


def test_parse_hook_path_dot() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},'
            '"hooks":[{"name":"h","kind":"tracepoint","id_path":"/i",'
            '"format_path":"/a/./b"}],"capabilities":[]}'
        )
    )


def test_parse_hook_path_relative() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},'
            '"hooks":[{"name":"h","kind":"tracepoint",'
            '"id_path":"relative/id","format_path":"/f"}],'
            '"capabilities":[]}'
        )
    )


def test_parse_hook_path_nul() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.0","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},'
            '"hooks":[{"name":"h","kind":"tracepoint","id_path":"/i",'
            '"format_path":"/f\\u0000ignored"}],"capabilities":[]}'
        )
    )


def test_parse_empty_note_ok() raises:
    var parts = minimal_doc().split(String("}]}"))
    assert_equal(len(parts), 2)
    var p = parse_profile_bytes(
        bytes_of(String(parts[0]) + String('}],"notes":[""]}'))
    )
    assert_equal(len(p.notes), 1)
    assert_equal(p.notes[0], String(""))


def test_parse_too_many_hooks() raises:
    var doc = String(
        '{"schema_version":"0.1.0","profile_id":"t",'
        '"status":"reference-unvalidated",'
        '"identity":{"arch":"x86_64","min_kernel":"7.0",'
        '"source":{"origin":"o","revision":"r"}},"hooks":['
    )
    for i in range(33):
        if i != 0:
            doc += ","
        doc += (
            String('{"name":"h')
            + String(i)
            + String(
                '","kind":"tracepoint","id_path":"/i","format_path":"/f"}'
            )
        )
    doc += String('],"capabilities":[]}')
    expect_reject(doc)


def expect_manifest_reject(name: String, needle: String) raises:
    """Assert loading one profiles dir fails, naming needle."""
    var raised = False
    try:
        _ = load_profiles(fx(name))
    except e:
        raised = True
        assert_true(contains(String(e), needle))
    assert_true(raised)


def test_manifest_empty() raises:
    var ps = load_profiles(fx("profiles-empty"))
    assert_equal(len(ps), 0)


def test_manifest_blank() raises:
    expect_manifest_reject(
        String("profiles-bad-manifest-blank"), String("manifest")
    )


def test_manifest_dup() raises:
    expect_manifest_reject(
        String("profiles-bad-manifest-dup"), String("manifest")
    )


def test_manifest_escape() raises:
    expect_manifest_reject(
        String("profiles-bad-manifest-escape"), String("manifest")
    )


def test_manifest_bad_doc() raises:
    expect_manifest_reject(String("profiles-bad-doc"), String("bad.json"))


def test_manifest_missing() raises:
    expect_manifest_reject(String("ordinary-7.0"), String("manifest.txt"))


def test_select_reference_cover() raises:
    var r = open_evidence_reader(fx("ordinary-7.0"))
    var env = detect_environment(r)
    var ps = load_profiles(String("profiles"))
    var d = select_profile(env.kernel, ps^)
    assert_true(not d.matched)
    assert_true(d.has_profile)
    assert_equal(d.profile.profile_id, String("linux-x86_64-7.0-reference"))
    assert_equal(
        d.reason,
        String(
            "profile linux-x86_64-7.0-reference covers this identity"
            " but is reference-unvalidated"
        ),
    )


def test_select_validated_match() raises:
    var r = open_evidence_reader(fx("ready-validated"))
    var env = detect_environment(r)
    var ps = load_profiles(fx("profiles-test"))
    var d = select_profile(env.kernel, ps^)
    assert_true(d.matched)
    assert_true(d.has_profile)
    assert_equal(d.profile.profile_id, String("test-validated"))
    assert_equal(
        d.reason, String("profile test-validated matched (validated)")
    )


def test_select_arch_mismatch() raises:
    var r = open_evidence_reader(fx("arch-mismatch"))
    var env = detect_environment(r)
    var ps = load_profiles(String("profiles"))
    var d = select_profile(env.kernel, ps^)
    assert_true(not d.matched)
    assert_true(not d.has_profile)
    assert_true(contains(d.reason, String("no profile covers")))


def test_select_release_below_min() raises:
    var r = open_evidence_reader(fx("kernel-6.8"))
    var env = detect_environment(r)
    var ps = load_profiles(String("profiles"))
    var d = select_profile(env.kernel, ps^)
    assert_true(not d.has_profile)
    assert_true(contains(d.reason, String("no profile covers")))


def test_select_empty() raises:
    var r = open_evidence_reader(fx("ordinary-7.0"))
    var env = detect_environment(r)
    var ps = load_profiles(fx("profiles-empty"))
    var d = select_profile(env.kernel, ps^)
    assert_true(not d.has_profile)
    assert_equal(d.reason, String("no profiles admitted"))


def test_select_unparseable() raises:
    var r = open_evidence_reader(fx("malformed-release"))
    var env = detect_environment(r)
    var ps = load_profiles(String("profiles"))
    var d = select_profile(env.kernel, ps^)
    assert_true(not d.has_profile)
    assert_true(contains(d.reason, String("unparseable")))


def judge(fxname: String, profdir: String) raises -> CapabilityReport:
    """Run discovery for one fixture against one profiles dir."""
    var r = open_evidence_reader(fx(fxname))
    var env = detect_environment(r)
    var ps = load_profiles(profdir)
    var d = select_profile(env.kernel, ps^)
    return discover_capabilities(r, d^)


def find_entry(rep: CapabilityReport, cap_id: String) -> CapEntry:
    """Copy one entry out of a report; blank when missing."""
    for i in range(len(rep.entries)):
        if rep.entries[i].id == cap_id:
            return rep.entries[i].copy()
    return CapEntry(String(""), String(""), String(""))


def validated_doc(cap_status: String) -> String:
    """One validated doc declaring attempt-trace with no hooks."""
    return (
        String(
            '{"schema_version":"0.1.0","profile_id":"t2",'
            '"status":"validated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[{"id":"attempt-trace","status":"'
        )
        + cap_status
        + String('","hooks":[],"reason":"r"}]}')
    )


def test_discover_candidate_unknown() raises:
    var rep = judge(String("ordinary-7.0"), String("profiles"))
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("unknown"))
    assert_equal(
        a.reason,
        String(
            "hook swiotlb:swiotlb_bounced has no recorded format"
            " in profile linux-x86_64-7.0-reference"
        ),
    )
    var l = find_entry(rep, String("mapping-lifecycle"))
    assert_equal(l.status, String("unsupported"))
    assert_equal(
        l.reason,
        String("No validated lifecycle mechanism exists in this profile."),
    )
    var c = find_entry(rep, String("copy-actual"))
    assert_equal(c.status, String("unsupported"))


def test_discover_hook_absent() raises:
    var rep = judge(String("missing-tracepoint"), String("profiles"))
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("unavailable"))
    assert_equal(
        a.reason,
        String(
            "hook swiotlb:swiotlb_bounced id"
            " /sys/kernel/tracing/events/swiotlb/swiotlb_bounced/id"
            " absent"
        ),
    )


def test_discover_hook_denied() raises:
    var rep = judge(String("denied-tracepoint"), String("profiles"))
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("unknown"))
    assert_equal(
        a.reason,
        String(
            "hook swiotlb:swiotlb_bounced format"
            " /sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"
            " denied (privilege)"
        ),
    )
    assert_equal(len(rep.denied), 1)
    assert_equal(
        rep.denied[0],
        String("/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"),
    )


def test_discover_floor() raises:
    var rep = judge(String("kernel-6.8"), String("profiles"))
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("unavailable"))
    assert_equal(
        a.reason,
        String("kernel 6.8.0-41-generic is below the 7.0 floor"),
    )


def test_discover_no_cover() raises:
    var rep = judge(String("arch-mismatch"), String("profiles"))
    assert_equal(len(rep.entries), 3)
    for i in range(len(rep.entries)):
        assert_equal(rep.entries[i].status, String("unknown"))
        assert_equal(
            rep.entries[i].reason, String("no profile covers this identity")
        )


def test_discover_unparseable() raises:
    var rep = judge(String("malformed-release"), String("profiles"))
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("unknown"))
    assert_equal(
        a.reason,
        String("release not-a-kernel-release is unparseable; floor unknown"),
    )


def test_discover_available() raises:
    var rep = judge(String("ready-validated"), fx("profiles-test"))
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("available"))
    assert_equal(
        a.reason, String("verified under validated profile test-validated")
    )


def test_discover_changed() raises:
    var rep = judge(String("changed-signature"), fx("profiles-test"))
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("unavailable"))
    assert_equal(
        a.reason,
        String(
            "hook swiotlb:swiotlb_bounced format differs from profile"
            " test-validated signature"
        ),
    )


def test_discover_unreadable_format() raises:
    var rep = judge(String("oversized-format"), fx("profiles-test"))
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("unknown"))
    assert_equal(
        a.reason,
        String(
            "hook swiotlb:swiotlb_bounced format unreadable after probe"
        ),
    )
    assert_equal(len(rep.denied), 0)


def test_discover_denied_id_changed() raises:
    var rep = judge(String("denied-id-changed"), fx("profiles-test"))
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("unavailable"))
    assert_equal(
        a.reason,
        String(
            "hook swiotlb:swiotlb_bounced format differs from profile"
            " test-validated signature"
        ),
    )
    assert_equal(len(rep.denied), 1)
    assert_equal(
        rep.denied[0],
        String("/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/id"),
    )


def test_discover_validated_absent() raises:
    var rep = judge(String("missing-tracepoint"), fx("profiles-test"))
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("unavailable"))
    assert_true(contains(a.reason, String("absent")))


def test_discover_undeclared() raises:
    var r = open_evidence_reader(fx("ordinary-7.0"))
    var env = detect_environment(r)
    var ps = List[Profile]()
    ps.append(parse_profile_bytes(bytes_of(minimal_doc())))
    var d = select_profile(env.kernel, ps^)
    assert_true(d.has_profile)
    var rep = discover_capabilities(r, d^)
    var l = find_entry(rep, String("mapping-lifecycle"))
    assert_equal(l.status, String("unknown"))
    assert_equal(
        l.reason, String("profile t does not declare mapping-lifecycle")
    )
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("unavailable"))
    assert_equal(
        a.reason, String("hook h id /i absent")
    )


def low_floor_doc() -> String:
    """One validated doc with min_kernel 6.0 for floor interplay.

    Covers a 6.8 kernel while the 7.0 floor fails, so the attempt
    and available demotions plus the unsupported terminal apply.
    """
    return String(
        '{"schema_version":"0.1.0","profile_id":"t-low",'
        '"status":"validated",'
        '"identity":{"arch":"x86_64","min_kernel":"6.0",'
        '"source":{"origin":"o","revision":"r"}},"hooks":[],'
        '"capabilities":[{"id":"attempt-trace","status":"supported",'
        '"hooks":[],"reason":"r"},'
        '{"id":"mapping-lifecycle","status":"supported",'
        '"hooks":[],"reason":"r"},'
        '{"id":"copy-actual","status":"unsupported",'
        '"hooks":[],"reason":"never"}]}'
    )


def test_discover_unsupported_terminal() raises:
    var r = open_evidence_reader(fx("kernel-6.8"))
    var env = detect_environment(r)
    var ps = List[Profile]()
    ps.append(parse_profile_bytes(bytes_of(low_floor_doc())))
    var d = select_profile(env.kernel, ps^)
    assert_true(d.matched)
    var rep = discover_capabilities(r, d^)
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("unavailable"))
    assert_equal(
        a.reason,
        String("kernel 6.8.0-41-generic is below the 7.0 floor"),
    )
    var l = find_entry(rep, String("mapping-lifecycle"))
    assert_equal(l.status, String("unavailable"))
    assert_equal(
        l.reason,
        String("kernel 6.8.0-41-generic is below the 7.0 floor"),
    )
    var c = find_entry(rep, String("copy-actual"))
    assert_equal(c.status, String("unsupported"))
    assert_equal(c.reason, String("never"))


def reference_recorded_doc() -> String:
    """One reference doc recording the ready-validated format bytes."""
    return String(
        '{"schema_version":"0.1.0","profile_id":"t3",'
        '"status":"reference-unvalidated",'
        '"identity":{"arch":"x86_64","min_kernel":"7.0",'
        '"source":{"origin":"o","revision":"r"}},'
        '"hooks":[{"name":"swiotlb:swiotlb_bounced","kind":"tracepoint",'
        '"id_path":"/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/id",'
        '"format_path":"/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format",'
        '"format_text":"name: swiotlb_bounced\\nID: 1901\\nformat:\\n'
        '\\tfield:unsigned int test_field;\\toffset:0;\\tsize:4;'
        '\\tsigned:0;\\n\\nprint fmt: \\"test_field=%u\\",'
        ' REC->test_field\\n"}],'
        '"capabilities":[{"id":"attempt-trace","status":"candidate",'
        '"hooks":["swiotlb:swiotlb_bounced"],"reason":"r"}]}'
    )


def test_discover_candidate_reference_verified() raises:
    var r = open_evidence_reader(fx("ready-validated"))
    var env = detect_environment(r)
    var ps = List[Profile]()
    ps.append(parse_profile_bytes(bytes_of(reference_recorded_doc())))
    var d = select_profile(env.kernel, ps^)
    assert_true(not d.matched)
    assert_true(d.has_profile)
    var rep = discover_capabilities(r, d^)
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("unknown"))
    assert_equal(
        a.reason,
        String(
            "candidate under reference-unvalidated profile t3:"
            " hooks present, semantics unproven"
        ),
    )


def test_discover_candidate_validated() raises:
    var r = open_evidence_reader(fx("ordinary-7.0"))
    var env = detect_environment(r)
    var ps = List[Profile]()
    ps.append(parse_profile_bytes(bytes_of(validated_doc(String("candidate")))))
    var d = select_profile(env.kernel, ps^)
    assert_true(d.matched)
    var rep = discover_capabilities(r, d^)
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("unknown"))
    assert_equal(
        a.reason,
        String(
            "candidate under validated profile t2:"
            " hooks present, support unproven"
        ),
    )


def test_discover_vacuous_available() raises:
    var r = open_evidence_reader(fx("ordinary-7.0"))
    var env = detect_environment(r)
    var ps = List[Profile]()
    ps.append(parse_profile_bytes(bytes_of(validated_doc(String("supported")))))
    var d = select_profile(env.kernel, ps^)
    var rep = discover_capabilities(r, d^)
    var a = find_entry(rep, String("attempt-trace"))
    assert_equal(a.status, String("available"))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_meta_ok]()
    suite.test[test_meta_missing]()
    suite.test[test_meta_dup]()
    suite.test[test_meta_unknown_key]()
    suite.test[test_meta_euid_alpha]()
    suite.test[test_meta_euid_huge]()
    suite.test[test_meta_denied_relative]()
    suite.test[test_meta_bad_tech]()
    suite.test[test_meta_arch_long]()
    suite.test[test_meta_release_long]()
    suite.test[test_meta_denied_long]()
    suite.test[test_meta_nul]()
    suite.test[test_meta_utf8]()
    suite.test[test_asserted_tech_ok]()
    suite.test[test_denied_list_ok]()
    suite.test[test_file_state_split]()
    suite.test[test_eacces_parent_is_denied]()
    suite.test[test_read_absent]()
    suite.test[test_read_denied]()
    suite.test[test_read_too_big]()
    suite.test[test_bytes_to_text]()
    suite.test[test_utf8_valid]()
    suite.test[test_utf8_invalid]()
    suite.test[test_triple_parse]()
    suite.test[test_floor_pass]()
    suite.test[test_floor_fail]()
    suite.test[test_floor_unparseable]()
    suite.test[test_guest_ordinary]()
    suite.test[test_guest_snp]()
    suite.test[test_guest_tdx]()
    suite.test[test_guest_sev_classic]()
    suite.test[test_guest_unavailable]()
    suite.test[test_guest_conflict_nodes]()
    suite.test[test_guest_conflict_flags]()
    suite.test[test_guest_conflict_mixed_sev]()
    suite.test[test_guest_conflict_mixed_tdx]()
    suite.test[test_asserted_tiebreak]()
    suite.test[test_asserted_agree]()
    suite.test[test_asserted_conflict]()
    suite.test[test_denied_guest_node]()
    suite.test[test_btf_states]()
    suite.test[test_hostile_release]()
    suite.test[test_parse_conversion_capability]()
    suite.test[test_admitted_profiles_lack_conversion]()
    suite.test[test_parse_minimal_ok]()
    suite.test[test_parse_reference_file]()
    suite.test[test_parse_validated_file]()
    suite.test[test_parse_bad_status]()
    suite.test[test_parse_bad_version]()
    suite.test[test_parse_unknown_key]()
    suite.test[test_parse_dup_key]()
    suite.test[test_parse_bad_profile_id]()
    suite.test[test_parse_bad_min_kernel]()
    suite.test[test_parse_short_min_kernel]()
    suite.test[test_parse_bad_kind]()
    suite.test[test_parse_dup_hook]()
    suite.test[test_parse_dangling_ref]()
    suite.test[test_parse_dup_cap]()
    suite.test[test_parse_bad_cap_id]()
    suite.test[test_parse_bad_cap_status]()
    suite.test[test_parse_missing_field]()
    suite.test[test_parse_trailing_data]()
    suite.test[test_parse_format_type]()
    suite.test[test_parse_overlong_name]()
    suite.test[test_parse_hook_path_traversal]()
    suite.test[test_parse_hook_path_dot]()
    suite.test[test_parse_hook_path_relative]()
    suite.test[test_parse_hook_path_nul]()
    suite.test[test_parse_empty_note_ok]()
    suite.test[test_parse_too_many_hooks]()
    suite.test[test_manifest_empty]()
    suite.test[test_manifest_blank]()
    suite.test[test_manifest_dup]()
    suite.test[test_manifest_escape]()
    suite.test[test_manifest_bad_doc]()
    suite.test[test_manifest_missing]()
    suite.test[test_select_reference_cover]()
    suite.test[test_select_validated_match]()
    suite.test[test_select_arch_mismatch]()
    suite.test[test_select_release_below_min]()
    suite.test[test_select_empty]()
    suite.test[test_select_unparseable]()
    suite.test[test_discover_candidate_unknown]()
    suite.test[test_discover_hook_absent]()
    suite.test[test_discover_hook_denied]()
    suite.test[test_discover_floor]()
    suite.test[test_discover_no_cover]()
    suite.test[test_discover_unparseable]()
    suite.test[test_discover_available]()
    suite.test[test_discover_changed]()
    suite.test[test_discover_unreadable_format]()
    suite.test[test_discover_denied_id_changed]()
    suite.test[test_discover_validated_absent]()
    suite.test[test_discover_undeclared]()
    suite.test[test_discover_unsupported_terminal]()
    suite.test[test_discover_candidate_reference_verified]()
    suite.test[test_discover_candidate_validated]()
    suite.test[test_discover_vacuous_available]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
