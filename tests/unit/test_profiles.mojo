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

from memveil.capture.run import decide_record
from memveil.platform.evidence import detect_environment, parse_kernel_triple
from memveil.platform.narrow import (
    NarrowBindings,
    measure_live_bindings,
    parse_narrow_note,
)
from memveil.platform.profiles import (
    CapQualification,
    Profile,
    TraceWant,
    cp_trace,
    default_receipts_dir,
    frozen_sig_types,
    lc_trace,
    load_profiles,
    mint_qualification_receipt,
    parse_profile_bytes,
    select_attempt_hook,
    select_profile,
    select_profile_bound,
    verify_core_layouts,
    verify_hook_signatures,
    verify_live_interfaces,
    verify_live_receipt,
    verify_qualification_receipt,
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
    read_host_file,
)


comptime _MINT_BRIDGE = "5e2e29c1dbc50b9041b2c1ad803fe2e71f1231c1f9a179aa29e72ebcb0b8d270"
comptime _FOREIGN_BRIDGE = "0000000000000000000000000000000000000000000000000000000000000000"


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
        String("release 7.0.0-34-generic meets the 6.0 floor"),
    )


def test_floor_68_pass() raises:
    var r = open_evidence_reader(fx("kernel-6.8"))
    var env = detect_environment(r)
    assert_true(env.kernel.eligible_floor)
    assert_equal(
        env.kernel.floor_reason,
        String("release 6.8.0-41-generic meets the 6.0 floor"),
    )


def test_floor_515_fail() raises:
    var r = open_evidence_reader(fx("kernel-5.15"))
    var env = detect_environment(r)
    assert_true(not env.kernel.eligible_floor)
    assert_equal(
        env.kernel.floor_reason,
        String("release 5.15.0-test is below the 6.0 floor"),
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
        '{"schema_version":"0.1.1","profile_id":"t",'
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


def _note_doc(n: Int) -> String:
    var pad = String("")
    for i in range(n):
        pad += String("x")
    return minimal_doc().replace(
        String('"revision":"r"'),
        String('"revision":"r","note":"') + pad + String('"'),
    )


def test_parse_source_note_700_ok() raises:
    # Twelve-field narrow notes need ~700 chars; the
    # 1024 cap admits them.
    var p = parse_profile_bytes(bytes_of(_note_doc(700)))
    assert_equal(p.identity.source.note.byte_length(), 700)


def test_parse_source_note_1025_rejects() raises:
    expect_reject(_note_doc(1025))


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
    assert_equal(len(ps), 3)
    assert_equal(ps[0].profile_id, String("linux-x86_64-7.0-reference"))
    assert_equal(ps[0].status, String("reference-unvalidated"))
    assert_equal(len(ps[0].hooks), 6)
    assert_equal(len(ps[0].caps), 3)
    assert_equal(len(ps[0].notes), 3)
    assert_equal(len(ps[0].layouts), 7)
    assert_equal(ps[0].hooks[0].kind, String("tracepoint"))
    assert_equal(
        ps[0].hooks[1].name, String("fexit:swiotlb_tbl_map_single")
    )
    assert_equal(len(ps[0].hooks[1].signature_alt), 1)
    # Manifest order stays reference-first; the narrow gate
    # doc appends for the two-phase collection scan. Its
    # status is asserted by the VM gate, not pinned here.
    assert_equal(
        ps[1].profile_id, String("linux-x86_64-7.0.0-34-generic")
    )
    assert_equal(len(ps[1].hooks), 6)
    assert_true(ps[1].hooks[0].format_has)
    assert_equal(len(ps[1].caps), 3)
    # The 6plus reference reuses the same pins with a 6.0 floor.
    assert_equal(
        ps[2].profile_id, String("linux-x86_64-6plus-reference")
    )
    assert_equal(ps[2].status, String("reference-unvalidated"))
    assert_equal(ps[2].identity.min_kernel, String("6.0"))
    assert_equal(len(ps[2].hooks), 6)
    assert_equal(len(ps[2].layouts), 7)
    assert_equal(len(ps[2].hooks[1].signature_alt), 1)


def test_gate_doc_tracing_caps_supported() raises:
    # The admission flip: the gate doc carries the frozen
    # tracing set with both extra caps supported. Names and
    # membership are pinned; the freeze moves only by
    # re-qualification of every lane together.
    var ps = load_profiles(String("profiles"))
    assert_equal(
        ps[1].profile_id, String("linux-x86_64-7.0.0-34-generic")
    )
    var want = List[String]()
    want.append(String("fexit:swiotlb_tbl_map_single"))
    want.append(String("fentry:__swiotlb_tbl_unmap_single"))
    want.append(String("fentry:__swiotlb_sync_single_for_device"))
    want.append(String("fentry:__swiotlb_sync_single_for_cpu"))
    want.append(String("fentry:swiotlb_bounce"))
    for i in range(len(want)):
        assert_equal(ps[1].hooks[i + 1].name, want[i])
        assert_equal(ps[1].hooks[i + 1].kind, String("tracing"))
        assert_true(ps[1].hooks[i + 1].signature.byte_length() > 0)
    for i in range(len(ps[1].caps)):
        if ps[1].caps[i].id == String("attempt-trace"):
            assert_equal(ps[1].caps[i].status, String("supported"))
            assert_equal(len(ps[1].caps[i].hooks), 1)
        elif ps[1].caps[i].id == String("mapping-lifecycle"):
            assert_equal(ps[1].caps[i].status, String("supported"))
            assert_equal(len(ps[1].caps[i].hooks), 2)
            assert_equal(ps[1].caps[i].hooks[0], want[0])
            assert_equal(ps[1].caps[i].hooks[1], want[1])
        elif ps[1].caps[i].id == String("copy-actual"):
            assert_equal(ps[1].caps[i].status, String("supported"))
            assert_equal(len(ps[1].caps[i].hooks), 3)
            assert_equal(ps[1].caps[i].hooks[0], want[2])
            assert_equal(ps[1].caps[i].hooks[1], want[3])
            assert_equal(ps[1].caps[i].hooks[2], want[4])
        else:
            assert_true(False)


def test_parse_validated_file() raises:
    var ps = load_profiles(fx("profiles-test"))
    assert_equal(len(ps), 1)
    assert_equal(ps[0].status, String("validated"))
    assert_true(ps[0].hooks[0].format_has)
    assert_equal(ps[0].hooks[0].format_text.byte_length(), 144)


def test_parse_bad_status() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.1","profile_id":"t","status":"draft",'
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
            '{"schema_version":"0.1.1","profile_id":"t","profile_id":"u",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[]}'
        )
    )


def test_parse_bad_profile_id() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.1","profile_id":"-lead",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[]}'
        )
    )


def test_parse_bad_min_kernel() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.1","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.x",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[]}'
        )
    )


def test_parse_short_min_kernel() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.1","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7",'
            '"source":{"origin":"o","revision":"r"}},"hooks":[],'
            '"capabilities":[]}'
        )
    )


def test_parse_bad_kind() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.1","profile_id":"t",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},'
            '"hooks":[{"name":"h","kind":"kprobe","id_path":"/i",'
            '"format_path":"/f"}],"capabilities":[]}'
        )
    )


def tracing_doc() -> String:
    """One minimal 0.1.1 document with a tracing hook."""
    return String(
        '{"schema_version":"0.1.1","profile_id":"t",'
        '"status":"reference-unvalidated","identity":{"arch":"x86_64",'
        '"min_kernel":"7.0","source":{"origin":"o","revision":"r"}},'
        '"hooks":[{"name":"fexit:swiotlb_tbl_map_single",'
        '"kind":"tracing","function":"swiotlb_tbl_map_single",'
        '"attach":"fexit","signature":"phys_addr_t swiotlb_tbl_map_single'
        '(struct device *dev)"}],'
        '"capabilities":[{"id":"mapping-lifecycle",'
        '"status":"candidate","hooks":["fexit:swiotlb_tbl_map_single"],'
        '"reason":"r"}]}'
    )


def test_parse_tracing_hook_ok() raises:
    var p = parse_profile_bytes(bytes_of(tracing_doc()))
    assert_equal(len(p.hooks), 1)
    assert_equal(p.hooks[0].kind, String("tracing"))
    assert_equal(
        p.hooks[0].function, String("swiotlb_tbl_map_single")
    )
    assert_equal(p.hooks[0].attach, String("fexit"))
    assert_true(p.hooks[0].signature.byte_length() > 0)
    assert_true(not p.hooks[0].format_has)


def test_parse_tracing_missing_signature_rejects() raises:
    var doc = tracing_doc().replace(
        String(',"signature":"phys_addr_t swiotlb_tbl_map_single'
               '(struct device *dev)"'),
        String(""),
    )
    expect_reject(doc)


def test_parse_tracing_bad_attach_rejects() raises:
    var doc = tracing_doc().replace(
        String('"attach":"fexit"'), String('"attach":"kprobe"')
    )
    expect_reject(doc)


def test_parse_tracing_with_format_path_rejects() raises:
    var doc = tracing_doc().replace(
        String('"attach":"fexit"'),
        String('"attach":"fexit","format_path":"/f"'),
    )
    expect_reject(doc)


def test_parse_tracepoint_with_function_rejects() raises:
    var doc = minimal_doc().replace(
        String('"format_path":"/f"'),
        String('"format_path":"/f","function":"swiotlb_bounce"'),
    )
    expect_reject(doc)


def test_parse_dup_hook() raises:
    expect_reject(
        String(
            '{"schema_version":"0.1.1","profile_id":"t",'
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
            '{"schema_version":"0.1.1","profile_id":"t",'
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
            '{"schema_version":"0.1.1","profile_id":"t",'
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
            '{"schema_version":"0.1.1","profile_id":"t",'
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
            '{"schema_version":"0.1.1","profile_id":"t",'
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
            '{"schema_version":"0.1.1","profile_id":"t",'
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
            '{"schema_version":"0.1.1","profile_id":"t",'
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
            '{"schema_version":"0.1.1","profile_id":"t",'
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
            '{"schema_version":"0.1.1","profile_id":"t",'
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
            '{"schema_version":"0.1.1","profile_id":"t",'
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
            '{"schema_version":"0.1.1","profile_id":"t",'
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
            '{"schema_version":"0.1.1","profile_id":"t",'
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
        '{"schema_version":"0.1.1","profile_id":"t",'
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


def test_select_bound_prefers_validated() raises:
    # Reference is listed first in profiles-bound, but the
    # validated doc's identity bindings hold, so it wins.
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var ps = load_profiles(fx("profiles-bound"))
    var d = select_profile_bound(
        env.kernel, ps^, fx("bound-host"), String("libz.so.1"),
        fx("profiles-bound"),
        String(""),
    )
    assert_true(d.matched)
    assert_true(d.has_profile)
    assert_equal(d.profile.profile_id, String("test-bound-validated"))
    assert_equal(
        d.reason,
        String("profile test-bound-validated matched (validated)"),
    )


def test_select_bound_multi_hook() raises:
    # A decoy tracepoint precedes the attempt hook; the
    # capability-named hook (whose format binds) must win,
    # mirroring record's hook selection exactly.
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var ps = load_profiles(fx("profiles-bound-multi"))
    var d = select_profile_bound(
        env.kernel, ps^, fx("bound-host"), String("libz.so.1"),
        fx("profiles-bound"),
        String(""),
    )
    assert_true(d.matched)
    assert_true(d.has_profile)
    assert_equal(d.profile.profile_id, String("test-bound-multi"))
    assert_equal(
        d.reason,
        String("profile test-bound-multi matched (validated)"),
    )


def _receipt_doc() raises -> Profile:
    var ps = load_profiles(fx("profiles-bound"))
    return ps[1].copy()


def _receipt_caps() raises -> List[CapQualification]:
    var caps = List[CapQualification]()
    caps.append(
        CapQualification(
            String("attempt-trace"),
            String("layout match; smoke attached, conservation holds"),
        )
    )
    return caps^


def test_receipt_roundtrip() raises:
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    var parsed = parse_narrow_note(doc.identity.source.note)
    assert_true(parsed.ok)
    var js = mint_qualification_receipt(
        doc.profile_id,
        env.kernel,
        parsed.bindings,
        UInt64(123456789),
        _receipt_caps(),
        String("0.1.0"),
        String(
            "sha256:5e2e29c1dbc50b9041b2c1ad803fe2e71f1231c1f9a179aa29e72ebcb0b8d270"
        ),
        String("sha256:") + parsed.bindings.object,
        String(""),
        String(""),
        UInt64(3),
        String("smoke: attach/poll/detach, no traffic required"),
    )
    var v = verify_qualification_receipt(js.as_bytes(), doc, env.kernel, String(_MINT_BRIDGE))
    assert_true(v.ok)
    assert_equal(v.message, String(""))


def test_receipt_verdict_caps() raises:
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    var js = _mint_good()
    var v = verify_qualification_receipt(js.as_bytes(), doc, env.kernel, String(_MINT_BRIDGE))
    assert_true(v.ok)
    assert_equal(len(v.caps), 1)
    assert_equal(v.caps[0], String("attempt-trace"))


def test_receipt_verdict_caps_multi() raises:
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    # The fixture note carries attempt bindings only; extend
    # it with lifecycle/copy bindings so the multi-cap
    # receipt has hashes to match per qualified channel.
    doc.identity.source.note += String(
        " lc_object=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        " lc_ring_bytes=8388608"
        " cp_object=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        " cp_ring_bytes=8388608"
    )
    var parsed = parse_narrow_note(doc.identity.source.note)
    assert_true(parsed.ok)
    var caps = _receipt_caps()
    caps.append(
        CapQualification(
            String("mapping-lifecycle"),
            String("fentry attach/poll/detach ok"),
        )
    )
    caps.append(
        CapQualification(
            String("copy-actual"),
            String("fentry attach/poll/detach ok"),
        )
    )
    var js = mint_qualification_receipt(
        doc.profile_id,
        env.kernel,
        parsed.bindings,
        UInt64(123456789),
        caps^,
        String("0.1.0"),
        String(
            "sha256:5e2e29c1dbc50b9041b2c1ad803fe2e71f1231c1f9a179aa29e72ebcb0b8d270"
        ),
        String("sha256:") + parsed.bindings.object,
        String("sha256:") + parsed.bindings.lc_object,
        String("sha256:") + parsed.bindings.cp_object,
        UInt64(3),
        String("smoke: attach/poll/detach, no traffic required"),
    )
    var v = verify_qualification_receipt(js.as_bytes(), doc, env.kernel, String(_MINT_BRIDGE))
    assert_true(v.ok)
    assert_equal(len(v.caps), 3)
    assert_equal(v.caps[0], String("attempt-trace"))
    assert_equal(v.caps[1], String("mapping-lifecycle"))
    assert_equal(v.caps[2], String("copy-actual"))


def test_receipt_lifecycle_missing_hash_refuses() raises:
    # A receipt qualifying mapping-lifecycle without a
    # lifecycle object hash must refuse: otherwise a
    # changed lifecycle object inherits qualification.
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    var parsed = parse_narrow_note(doc.identity.source.note)
    assert_true(parsed.ok)
    var caps = _receipt_caps()
    caps.append(
        CapQualification(
            String("mapping-lifecycle"),
            String("fentry attach/poll/detach ok"),
        )
    )
    var js = mint_qualification_receipt(
        doc.profile_id,
        env.kernel,
        parsed.bindings,
        UInt64(123456789),
        caps^,
        String("0.1.0"),
        String(
            "sha256:5e2e29c1dbc50b9041b2c1ad803fe2e71f1231c1f9a179aa29e72ebcb0b8d270"
        ),
        String("sha256:") + parsed.bindings.object,
        String(""),
        String(""),
        UInt64(3),
        String("smoke: attach/poll/detach, no traffic required"),
    )
    var v = verify_qualification_receipt(js.as_bytes(), doc, env.kernel, String(_MINT_BRIDGE))
    assert_true(not v.ok)
    assert_equal(
        v.message,
        String(
            "receipt lacks lifecycle hash for qualified"
            " mapping-lifecycle"
        ),
    )


def test_receipt_verdict_caps_empty_on_refusal() raises:
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    var js = _mint_good()
    var bad_kernel = env.kernel.copy()
    bad_kernel.release = String("9.9.9-fake")
    var v = verify_qualification_receipt(js.as_bytes(), doc, bad_kernel, String(_MINT_BRIDGE))
    assert_true(not v.ok)
    assert_equal(len(v.caps), 0)


def _swap_segment(
    js: String, start_key: String, end_key: String, replacement: String
) -> String:
    """Replace from "start_key" up to (not incl.) "end_key"."""
    var a = js.split(String('"' + start_key + '"'))
    var b = String(a[1]).split(String('"' + end_key + '"'))
    return (
        String(a[0]) + replacement + String('"' + end_key + '"')
        + String(b[1])
    )


def _swap_tail(js: String, key: String, replacement: String) -> String:
    """Replace from "key" to the end of the document."""
    var a = js.split(String('"' + key + '"'))
    return String(a[0]) + replacement


def test_receipt_artifacts_null() raises:
    var js = _mint_good()
    var bad = _swap_segment(
        js, String("artifacts"), String("workload"),
        String('"artifacts": null, '),
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt unparseable")))


def test_receipt_workload_false() raises:
    var js = _mint_good()
    var bad = _swap_tail(
        js, String("workload"), String('"workload": false}\n')
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt unparseable")))


def test_receipt_trailing_data() raises:
    var js = _mint_good() + String("{}\n")
    var msg = _verify_text(js)
    assert_true(contains(msg, String("trailing data")))


def test_receipt_bridge_shape() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"bridge": "sha256:5e2e29c1'),
        String('"bridge": "sha256:ZZZZZZZZ'),
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt.artifacts")))


def test_receipt_trailing_data_beats_bridge_mismatch() raises:
    # A foreign bridge hash plus appended garbage must
    # report trailing data (with no bridge verdict), not
    # a bridge-only mismatch: JSON consumption
    # validation finishes before the bridge compares.
    var js = _mint_good() + String("{}\n")
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    var v = verify_qualification_receipt(
        js.as_bytes(), doc, env.kernel, String(_FOREIGN_BRIDGE)
    )
    assert_true(not v.ok)
    assert_true(contains(v.message, String("trailing data")))
    assert_true(not v.bridge_mismatch)


def test_receipt_bridge_mismatch_refuses() raises:
    # The receipt is otherwise valid, but it was minted
    # for another bridge: verification must refuse with
    # the bridge named, so a swapped bridge cannot
    # inherit qualification.
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    var js = _mint_good()
    var v = verify_qualification_receipt(
        js.as_bytes(), doc, env.kernel, String(_FOREIGN_BRIDGE)
    )
    assert_true(not v.ok)
    assert_equal(
        v.message, String("receipt bridge differs from resolved bridge")
    )
    assert_true(v.bridge_mismatch)


def test_receipt_workload_kind() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"kind": "smoke"'), String('"kind": "fuzz')
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt.workload")))


def test_receipt_traffic_true() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"traffic_required": false'),
        String('"traffic_required": true'),
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt.workload")))


def test_receipt_duration_shape() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"duration_s": "3"'), String('"duration_s": "03"')
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt.workload")))


def test_receipt_u64_max() raises:
    var js = _mint_good()
    var good = js.replace(
        String('"created_ns": "123456789"'),
        String('"created_ns": "18446744073709551615"'),
    ).replace(
        String('"duration_s": "3"'),
        String('"duration_s": "18446744073709551615"'),
    )
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    var v = verify_qualification_receipt(
        good.as_bytes(), doc, env.kernel, String(_MINT_BRIDGE)
    )
    assert_true(v.ok)
    assert_equal(v.message, String(""))


def test_receipt_created_ns_range() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"created_ns": "123456789"'),
        String('"created_ns": "18446744073709551616"'),
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt.created_ns")))


def test_receipt_created_ns_huge() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"created_ns": "123456789"'),
        String('"created_ns": "99999999999999999999"'),
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt.created_ns")))


def test_receipt_duration_range() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"duration_s": "3"'),
        String('"duration_s": "18446744073709551616"'),
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt.workload")))


def test_receipt_duration_huge() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"duration_s": "3"'),
        String('"duration_s": "99999999999999999999"'),
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt.workload")))


def test_receipt_note_empty() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"note": "smoke: attach/poll/detach, no traffic required"'),
        String('"note": ""'),
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt.workload")))


def test_receipt_memveil_empty() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"memveil": "0.1.0"'), String('"memveil": ""')
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt.artifacts")))


def test_receipt_objects_unknown_field() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"objects": {"attempt"'),
        String('"objects": {"evil": "x", "attempt"'),
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt.artifacts")))


def test_receipt_objects_empty() raises:
    var js = _mint_good()
    var bad = _swap_segment(
        js, String("objects"), String("workload"),
        String('"objects": {}, '),
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt.artifacts")))


def test_receipt_artifacts_unknown_field() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"artifacts": {"memveil"'),
        String('"artifacts": {"evil": "x", "memveil"'),
    )
    var msg = _verify_text(bad)
    assert_true(contains(msg, String("receipt.artifacts")))


def test_receipt_artifact_mismatch() raises:
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    var parsed = parse_narrow_note(doc.identity.source.note)
    assert_true(parsed.ok)
    var js = _mint_good()
    var bad = js.replace(
        String('"attempt": "sha256:') + parsed.bindings.object + String('"'),
        String('"attempt": "sha256:0000000000000000000000000000000000000000000000000000000000000000"'),
    )
    assert_true(bad != js)
    var v = verify_qualification_receipt(bad.as_bytes(), doc, env.kernel, String(_MINT_BRIDGE))
    assert_true(not v.ok)
    assert_equal(v.message, String("receipt artifacts differ from note"))


def test_receipt_revision_mismatch() raises:
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    var parsed = parse_narrow_note(doc.identity.source.note)
    assert_true(parsed.ok)
    var fake = env.kernel.copy()
    fake.release = String("9.9.9-fake")
    var js = mint_qualification_receipt(
        doc.profile_id,
        fake,
        parsed.bindings,
        UInt64(123456789),
        _receipt_caps(),
        String("0.1.0"),
        String(
            "sha256:5e2e29c1dbc50b9041b2c1ad803fe2e71f1231c1f9a179aa29e72ebcb0b8d270"
        ),
        String("sha256:") + parsed.bindings.object,
        String(""),
        String(""),
        UInt64(3),
        String("smoke: attach/poll/detach, no traffic required"),
    )
    var v = verify_qualification_receipt(js.as_bytes(), doc, fake, String(_MINT_BRIDGE))
    assert_true(not v.ok)
    assert_equal(
        v.message, String("receipt kernel differs from profile revision")
    )


def _mint_good() raises -> String:
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    var parsed = parse_narrow_note(doc.identity.source.note)
    return mint_qualification_receipt(
        doc.profile_id,
        env.kernel,
        parsed.bindings,
        UInt64(123456789),
        _receipt_caps(),
        String("0.1.0"),
        String(
            "sha256:5e2e29c1dbc50b9041b2c1ad803fe2e71f1231c1f9a179aa29e72ebcb0b8d270"
        ),
        String("sha256:") + parsed.bindings.object,
        String(""),
        String(""),
        UInt64(3),
        String("smoke: attach/poll/detach, no traffic required"),
    )


def _verify_text(js: String) raises -> String:
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    var v = verify_qualification_receipt(js.as_bytes(), doc, env.kernel, String(_MINT_BRIDGE))
    assert_true(not v.ok)
    return v.message


def test_receipt_wrong_kernel() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"release": "7.0.0-test"'), String('"release": "9.9.9-x"')
    )
    assert_equal(_verify_text(bad), String("receipt names another kernel"))


def test_receipt_wrong_binding() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"config": "sha256:a5af'),
        String('"config": "sha256:b5af'),
    )
    assert_equal(
        _verify_text(bad), String("receipt bindings differ from note")
    )


def test_receipt_wrong_profile() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"profile_id": "test-bound-validated"'),
        String('"profile_id": "other-profile"'),
    )
    assert_equal(
        _verify_text(bad), String("receipt names another profile")
    )


def test_receipt_bad_json() raises:
    var js = _mint_good()
    var cut = js.as_bytes()[0 : js.byte_length() - 20]
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    var v = verify_qualification_receipt(cut, doc, env.kernel, String(_MINT_BRIDGE))
    assert_true(not v.ok)
    assert_true(v.message.startswith(String("receipt unparseable: ")))


def test_receipt_empty_capabilities() raises:
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var doc = _receipt_doc()
    var parsed = parse_narrow_note(doc.identity.source.note)
    var js = mint_qualification_receipt(
        doc.profile_id,
        env.kernel,
        parsed.bindings,
        UInt64(1),
        List[CapQualification](),
        String("0.1.0"),
        String("sha256:00"),
        String("sha256:00"),
        String(""),
        String(""),
        UInt64(3),
        String("empty"),
    )
    assert_true(
        _verify_text(js).startswith(String("receipt unparseable: "))
    )


def test_receipt_wrong_grade() raises:
    var js = _mint_good()
    var bad = js.replace(
        String('"grade": "local-auto"'), String('"grade": "validated"')
    )
    assert_true(
        _verify_text(bad).startswith(String("receipt unparseable: "))
    )


def test_select_bound_receipt_beats_first_covering() raises:
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var scan_raw = read_host_file(
        String("tests/fixtures/scan/profiles/ref.json"),
        String("profile"),
        1048576,
    )
    var ps = List[Profile]()
    ps.append(parse_profile_bytes(scan_raw))
    var refs = load_profiles(fx("profiles-bound-ref"))
    ps.append(refs[0].copy())
    var d = select_profile_bound(
        env.kernel,
        ps^,
        fx("bound-host"),
        String("libz.so.1"),
        fx("profiles-bound-ref"),
        String(_MINT_BRIDGE),
    )
    assert_true(d.matched)
    assert_true(d.has_profile)
    assert_equal(d.profile.profile_id, String("ref-bindable"))
    assert_equal(
        d.reason, String("profile ref-bindable matched (local-auto)")
    )


def test_select_bound_receipt_match() raises:
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var ps = load_profiles(fx("profiles-bound-ref"))
    var d = select_profile_bound(
        env.kernel,
        ps^,
        fx("bound-host"),
        String("libz.so.1"),
        fx("profiles-bound-ref"),
        String(_MINT_BRIDGE),
    )
    assert_true(d.matched)
    assert_true(d.has_profile)
    assert_equal(d.profile.profile_id, String("ref-bindable"))
    assert_equal(
        d.reason, String("profile ref-bindable matched (local-auto)")
    )


def test_select_bound_receipt_stale() raises:
    var r = open_evidence_reader(fx("ordinary-7.0"))
    var env = detect_environment(r)
    var ps = load_profiles(fx("profiles-bound-ref"))
    var d = select_profile_bound(
        env.kernel,
        ps^,
        fx("ordinary-7.0"),
        String("libz.so.1"),
        fx("profiles-bound-ref"),
        String(_MINT_BRIDGE),
    )
    assert_true(not d.matched)
    assert_true(d.has_profile)
    assert_equal(d.profile.profile_id, String("ref-bindable"))
    assert_equal(
        d.reason,
        String(
            "profile ref-bindable covers this identity"
            " but is reference-unvalidated; ref-bindable"
            " receipt names another kernel"
        ),
    )


def test_select_bound_receipt_bridge_mismatch() raises:
    # The bound-host receipt verifies everywhere except
    # the bridge: no local-auto match, and the fallback
    # reason names the bridge mismatch.
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var ps = load_profiles(fx("profiles-bound-ref"))
    var d = select_profile_bound(
        env.kernel,
        ps^,
        fx("bound-host"),
        String("libz.so.1"),
        fx("profiles-bound-ref"),
        String(_FOREIGN_BRIDGE),
    )
    assert_true(not d.matched)
    assert_true(d.has_profile)
    assert_equal(d.profile.profile_id, String("ref-bindable"))
    assert_equal(
        d.reason,
        String(
            "profile ref-bindable covers this identity"
            " but is reference-unvalidated; ref-bindable"
            " receipt bridge differs from resolved bridge"
        ),
    )


def test_select_bound_receipt_bridge_unchecked() raises:
    # The passive path performs no bridge binding
    # (empty hash): the otherwise-verifying receipt must
    # report unchecked explicitly instead of implying a
    # mismatch against a resolution that never ran.
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var ps = load_profiles(fx("profiles-bound-ref"))
    var d = select_profile_bound(
        env.kernel,
        ps^,
        fx("bound-host"),
        String("libz.so.1"),
        fx("profiles-bound-ref"),
        String(""),
    )
    assert_true(not d.matched)
    assert_true(d.has_profile)
    assert_equal(d.profile.profile_id, String("ref-bindable"))
    assert_equal(
        d.reason,
        String(
            "profile ref-bindable covers this identity"
            " but is reference-unvalidated; ref-bindable"
            " receipt bridge unchecked:"
            " no binding performed on this path"
        ),
    )


def test_select_bound_falls_back_with_reason() raises:
    # ordinary-7.0 runs 7.0.0-34-generic while the validated
    # doc records revision 7.0.0-test, so it cannot bind;
    # reference covers with the near-miss named in the reason.
    var r = open_evidence_reader(fx("ordinary-7.0"))
    var env = detect_environment(r)
    var ps = load_profiles(fx("profiles-bound"))
    var d = select_profile_bound(
        env.kernel, ps^, fx("ordinary-7.0"), String("libz.so.1"),
        fx("profiles-bound"),
        String(""),
    )
    assert_true(not d.matched)
    assert_true(d.has_profile)
    assert_equal(d.profile.profile_id, String("linux-x86_64-7.0-reference"))
    assert_equal(
        d.reason,
        String(
            "profile linux-x86_64-7.0-reference covers this identity"
            " but is reference-unvalidated; test-bound-validated"
            " identity mismatch: revision"
        ),
    )


def test_select_arch_mismatch() raises:
    var r = open_evidence_reader(fx("arch-mismatch"))
    var env = detect_environment(r)
    var ps = load_profiles(String("profiles"))
    var d = select_profile(env.kernel, ps^)
    assert_true(not d.matched)
    assert_true(not d.has_profile)
    assert_true(contains(d.reason, String("no profile covers")))


def test_select_68_covers_6plus_reference() raises:
    # A 6.8 kernel misses the 7.0 docs but the 6plus
    # reference covers it (still reference-unvalidated).
    var r = open_evidence_reader(fx("kernel-6.8"))
    var env = detect_environment(r)
    var ps = load_profiles(String("profiles"))
    var d = select_profile(env.kernel, ps^)
    assert_true(not d.matched)
    assert_true(d.has_profile)
    assert_equal(
        d.profile.profile_id, String("linux-x86_64-6plus-reference")
    )
    assert_equal(
        d.reason,
        String(
            "profile linux-x86_64-6plus-reference covers this identity"
            " but is reference-unvalidated"
        ),
    )


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


def test_decide_oversized_format_judges() raises:
    # Oversized formats are judged on content through
    # bounded reads, never waved through as unknown: the
    # NUL-filled stand-in fails the layout probe.
    var r = open_evidence_reader(fx("oversized-format"))
    var env = detect_environment(r)
    var pdir = fx("profiles-test")
    var d = decide_record(
        fx("oversized-format"),
        env.kernel,
        load_profiles(pdir.copy()),
        String(""),
        False,
        String("tests/fixtures/elf/ok.o"),
        String(""),
        String(""),
        String("attempt-trace"),
        pdir,
        String(""),
    )
    assert_true(not d.ok)
    assert_true(not d.refusal_unknown)
    assert_equal(d.refusal, String("layout: missing field common_type"))
    assert_equal(d.refusal_code, String("profile"))


def test_decide_hookless_refuses() raises:
    # A supported capability with no hooks proves nothing:
    # admission refuses instead of admitting blindly.
    var doc = String(
        '{"schema_version":"0.1.1","profile_id":"t",'
        '"status":"reference-unvalidated","identity":{"arch":"x86_64",'
        '"min_kernel":"7.0","source":{"origin":"o","revision":"r"}},'
        '"hooks":[],"capabilities":[{"id":"attempt-trace",'
        '"status":"supported","hooks":[],"reason":"r"}]}'
    )
    var one = List[Profile]()
    one.append(parse_profile_bytes(bytes_of(doc)))
    var r = open_evidence_reader(fx("ordinary-7.0"))
    var env = detect_environment(r)
    var d = decide_record(
        fx("ordinary-7.0"),
        env.kernel,
        one^,
        String(""),
        False,
        String("tests/fixtures/elf/ok.o"),
        String(""),
        String(""),
        String("attempt-trace"),
        String(""),
        String(""),
    )
    assert_true(not d.ok)
    assert_true(not d.refusal_unknown)
    assert_equal(d.refusal, String("no tracepoint hook"))
    assert_equal(d.refusal_code, String("profile"))




def _frozen_hooks_json(wants: List[TraceWant]) -> String:
    """Hook array JSON rendered from frozen wants, in order."""
    var out = String("")
    for i in range(len(wants)):
        if i > 0:
            out += String(",")
        var w = wants[i].copy()
        out += String('{"name":"') + w.name.copy()
        out += String('","kind":"tracing","function":"') + w.function.copy()
        out += String('","attach":"') + w.attach.copy()
        out += String('","signature":"') + w.signature.copy()
        out += String('"}')
    return out^


def _frozen_hook_names_json(wants: List[TraceWant]) -> String:
    """Quoted hook-name list JSON from frozen wants, in order."""
    var out = String("")
    for i in range(len(wants)):
        if i > 0:
            out += String(",")
        out += String('"') + wants[i].name + String('"')
    return out^


def live_ref_doc() -> String:
    """One unbound reference doc with all five frozen hooks.

    No narrow note, so exact binding can never apply; the
    live path verifies the tracing signatures plus
    attachability instead. Lifecycle and copy declare
    candidate, attempt declares supported with no hooks.
    """
    return (
        String(
            '{"schema_version":"0.1.1","profile_id":"t-live",'
            '"status":"reference-unvalidated",'
            '"identity":{"arch":"x86_64","min_kernel":"7.0",'
            '"source":{"origin":"o","revision":"r"}},'
            '"hooks":['
            '{"name":"swiotlb:swiotlb_bounced","kind":"tracepoint",'
            '"id_path":"/sys/kernel/tracing/events/swiotlb/'
            'swiotlb_bounced/id","format_path":"/sys/kernel/'
            'tracing/events/swiotlb/swiotlb_bounced/format"},'
        )
        + _frozen_hooks_json(lc_trace())
        + String(",")
        + _frozen_hooks_json(cp_trace())
        + String(
            '],"capabilities":[{"id":"attempt-trace",'
            '"status":"supported","hooks":[],"reason":"r"},'
            '{"id":"mapping-lifecycle","status":"candidate",'
            '"hooks":['
        )
        + _frozen_hook_names_json(lc_trace())
        + String(
            '],"reason":"r"},'
            '{"id":"copy-actual","status":"candidate",'
            '"hooks":['
        )
        + _frozen_hook_names_json(cp_trace())
        + String('],"reason":"r"}]}')
    )


def _frozen_map_73() -> String:
    """Frozen 7.3 map signature: attrs arrives as a pointer."""
    return String(
        "phys_addr_t swiotlb_tbl_map_single(struct device *dev,"
        " phys_addr_t orig_addr, size_t mapping_size,"
        " unsigned int alloc_align_mask,"
        " enum dma_data_direction dir, unsigned long *attrs)"
    )


def _live_doc_with_map_alt(alt: String) -> String:
    """live_ref_doc plus one map signature_alt entry."""
    var frozen70 = String(
        "phys_addr_t swiotlb_tbl_map_single(struct device *dev,"
        " phys_addr_t orig_addr, size_t mapping_size,"
        " unsigned int alloc_align_mask,"
        " enum dma_data_direction dir, unsigned long attrs)"
    )
    return live_ref_doc().replace(
        String('"signature":"') + frozen70 + String('"'),
        String('"signature":"') + frozen70
        + String('","signature_alt":["') + alt + String('"]'),
    )


def _live_doc_with_layouts(layouts_json: String) -> String:
    """live_ref_doc plus a layouts array from caller JSON."""
    var parts = live_ref_doc().split(String("}]}"))
    return (
        String(parts[0])
        + String('}],"layouts":[')
        + layouts_json
        + String("]}")
    )


def _seven_layouts_json() -> String:
    """The seven verified swiotlb member layouts as JSON."""
    return String(
        '{"struct":"io_tlb_pool","field":"start",'
        '"bit_offset":0,"bit_size":64},'
        '{"struct":"io_tlb_pool","field":"nslabs",'
        '"bit_offset":192,"bit_size":64},'
        '{"struct":"io_tlb_pool","field":"slots",'
        '"bit_offset":448,"bit_size":64},'
        '{"struct":"io_tlb_slot","field":"orig_addr",'
        '"bit_offset":0,"bit_size":64},'
        '{"struct":"io_tlb_slot","field":"alloc_size",'
        '"bit_offset":64,"bit_size":64},'
        '{"struct":"device_dma_parameters","field":"min_align_mask",'
        '"bit_offset":32,"bit_size":32},'
        '{"struct":"device","field":"dma_parms",'
        '"bit_offset":5056,"bit_size":64}'
    )


def test_verify_live_ok() raises:
    var doc = parse_profile_bytes(bytes_of(live_ref_doc()))
    var caps = List[String]()
    caps.append(String("attempt-trace"))
    caps.append(String("mapping-lifecycle"))
    var v = verify_live_interfaces(
        fx("kernel-38"), doc^, caps^
    )
    assert_true(v.ok)
    assert_equal(v.reason, String(""))


def test_verify_live_sig_mismatch() raises:
    var doc = parse_profile_bytes(
        bytes_of(
            live_ref_doc().replace(
                String("unsigned long attrs)"),
                String("unsigned long long attrs)"),
            )
        )
    )
    var caps = List[String]()
    caps.append(String("mapping-lifecycle"))
    var v = verify_live_interfaces(
        fx("kernel-38"), doc^, caps^
    )
    assert_true(not v.ok)
    assert_equal(
        v.reason,
        String(
            "fexit:swiotlb_tbl_map_single: signature mismatch"
            " (live: phys_addr_t (struct device *dev,"
            " phys_addr_t orig_addr, size_t mapping_size,"
            " unsigned int alloc_align_mask,"
            " enum dma_data_direction dir, unsigned long attrs))"
        ),
    )


def test_verify_live_unattachable() raises:
    # swiotlb_map is present in the fixture BTF (with the
    # bounce prototype, so the signature matches) but
    # absent from the fixture filter-function list.
    var doc = parse_profile_bytes(
        bytes_of(
            live_ref_doc()
            .replace(
                String('swiotlb_bounce"'), String('swiotlb_map"')
            )
            .replace(
                String("swiotlb_bounce("), String("swiotlb_map(")
            )
        )
    )
    var caps = List[String]()
    caps.append(String("copy-actual"))
    var v = verify_live_interfaces(
        fx("kernel-38"), doc^, caps^
    )
    assert_true(not v.ok)
    assert_equal(
        v.reason,
        String(
            "fentry:swiotlb_map: function swiotlb_map not listed in"
            " available_filter_functions"
        ),
    )


def test_verify_live_btf_absent() raises:
    var doc = parse_profile_bytes(bytes_of(live_ref_doc()))
    var caps = List[String]()
    caps.append(String("mapping-lifecycle"))
    var v = verify_live_interfaces(
        fx("missing-btf"), doc^, caps^
    )
    assert_true(not v.ok)
    assert_true(not v.unknown)
    assert_true(v.reason.startswith(String("BTF absent")))


def test_verify_live_btf_corrupt() raises:
    var doc = parse_profile_bytes(bytes_of(live_ref_doc()))
    var caps = List[String]()
    caps.append(String("mapping-lifecycle"))
    var v = verify_live_interfaces(
        fx("kernel-6.8"), doc^, caps^
    )
    assert_true(not v.ok)
    assert_equal(v.reason, String("bad BTF header"))


def test_verify_live_btf_corrupt_unknown() raises:
    var doc = parse_profile_bytes(bytes_of(live_ref_doc()))
    var caps = List[String]()
    caps.append(String("mapping-lifecycle"))
    var v = verify_live_interfaces(
        fx("kernel-6.8"), doc^, caps^
    )
    assert_true(not v.ok)
    assert_true(v.unknown)
    assert_equal(v.code, String("btf-malformed"))
    assert_equal(v.reason, String("bad BTF header"))


def test_verify_live_btf_split_unknown() raises:
    # Split BTF needs its base blob: unknown, never admitted.
    var doc = parse_profile_bytes(bytes_of(live_ref_doc()))
    var caps = List[String]()
    caps.append(String("mapping-lifecycle"))
    var v = verify_live_interfaces(
        fx("../gate/btf-split"), doc^, caps^
    )
    assert_true(not v.ok)
    assert_true(v.unknown)
    assert_equal(v.code, String("btf-split"))


def test_verify_live_signame_accepted() raises:
    # Parameter names never compare on the live path.
    var doc = parse_profile_bytes(bytes_of(live_ref_doc()))
    var caps = List[String]()
    caps.append(String("mapping-lifecycle"))
    var v = verify_live_interfaces(
        fx("../gate/sig-rename"), doc^, caps^
    )
    assert_true(v.ok)


def test_verify_live_sigswap_mismatch() raises:
    var doc = parse_profile_bytes(bytes_of(live_ref_doc()))
    var caps = List[String]()
    caps.append(String("mapping-lifecycle"))
    var v = verify_live_interfaces(
        fx("../gate/sig-swap"), doc^, caps^
    )
    assert_true(not v.ok)
    assert_true(not v.unknown)
    assert_equal(v.code, String("signature-mismatch"))
    assert_true(
        v.reason.startswith(
            String("fexit:swiotlb_tbl_map_single: signature mismatch")
        )
    )


def test_verify_live_sigwidth_refused() raises:
    var doc = parse_profile_bytes(bytes_of(live_ref_doc()))
    var caps = List[String]()
    caps.append(String("mapping-lifecycle"))
    var v = verify_live_interfaces(
        fx("../gate/sig-width"), doc^, caps^
    )
    assert_true(not v.ok)
    assert_true(not v.unknown)
    assert_equal(v.code, String("signature-width"))
    assert_equal(
        v.reason,
        String(
            "fexit:swiotlb_tbl_map_single:"
            " size_t width 32 bits (want 64)"
        ),
    )


def test_frozen_sig_unnamed_params() raises:
    # Unnamed multi-word types keep every word; only a
    # well-formed trailing name strips, and malformed
    # trailing words stay whole and mismatch loudly.
    var u = frozen_sig_types(
        String("void f(unsigned long, size_t)"), String("f")
    )
    assert_true(u.has)
    assert_equal(len(u.params), 2)
    assert_equal(u.params[0], String("unsigned long"))
    assert_equal(u.params[1], String("size_t"))
    var n = frozen_sig_types(
        String("void f(unsigned long x, size_t y)"), String("f")
    )
    assert_true(n.has)
    assert_equal(n.params[0], String("unsigned long"))
    assert_equal(n.params[1], String("size_t"))
    var e = frozen_sig_types(
        String("void f(enum dma_data_direction)"), String("f")
    )
    assert_true(e.has)
    assert_equal(e.params[0], String("enum dma_data_direction"))
    var m = frozen_sig_types(
        String("void f(unsigned long attrs!)"), String("f")
    )
    assert_true(m.has)
    assert_equal(m.params[0], String("unsigned long attrs!"))


def test_verify_live_73_sig_mismatch() raises:
    # The 7.3 map shape passes attrs as a pointer; without
    # an alt the frozen 7.0 spelling mismatches loudly.
    var doc = parse_profile_bytes(bytes_of(live_ref_doc()))
    var caps = List[String]()
    caps.append(String("mapping-lifecycle"))
    var v = verify_live_interfaces(
        fx("kernel-38-73"), doc^, caps^
    )
    assert_true(not v.ok)
    assert_equal(
        v.reason,
        String(
            "fexit:swiotlb_tbl_map_single: signature mismatch"
            " (live: phys_addr_t (struct device *dev,"
            " phys_addr_t orig_addr, size_t mapping_size,"
            " unsigned int alloc_align_mask,"
            " enum dma_data_direction dir, unsigned long *attrs))"
        ),
    )


def test_verify_live_73_alt_ok() raises:
    var doc = parse_profile_bytes(
        bytes_of(_live_doc_with_map_alt(_frozen_map_73()))
    )
    var caps = List[String]()
    caps.append(String("mapping-lifecycle"))
    var v = verify_live_interfaces(
        fx("kernel-38-73"), doc^, caps^
    )
    assert_true(v.ok)
    assert_equal(v.reason, String(""))
    # The primary spelling still admits the 7.0 shape.
    var doc70 = parse_profile_bytes(
        bytes_of(_live_doc_with_map_alt(_frozen_map_73()))
    )
    var caps70 = List[String]()
    caps70.append(String("mapping-lifecycle"))
    var v70 = verify_live_interfaces(
        fx("kernel-38"), doc70^, caps70^
    )
    assert_true(v70.ok)


def test_verify_live_alt_malformed() raises:
    var doc = parse_profile_bytes(
        bytes_of(_live_doc_with_map_alt(String("not a signature")))
    )
    var caps = List[String]()
    caps.append(String("mapping-lifecycle"))
    var v = verify_live_interfaces(
        fx("kernel-38"), doc^, caps^
    )
    assert_true(not v.ok)
    assert_equal(
        v.reason,
        String(
            "fexit:swiotlb_tbl_map_single:"
            " frozen signature_alt malformed"
        ),
    )


def test_verify_live_layout_ok() raises:
    var doc = parse_profile_bytes(
        bytes_of(_live_doc_with_layouts(_seven_layouts_json()))
    )
    var caps = List[String]()
    caps.append(String("copy-actual"))
    var v = verify_live_interfaces(
        fx("kernel-38"), doc^, caps^
    )
    assert_true(v.ok)
    assert_equal(v.reason, String(""))


def test_verify_live_layout_mismatch() raises:
    # A single drifted bit offset refuses with the live
    # geometry quoted.
    var layouts = String(
        '{"struct":"io_tlb_pool","field":"start",'
        '"bit_offset":8,"bit_size":64}'
    )
    var doc = parse_profile_bytes(
        bytes_of(_live_doc_with_layouts(layouts))
    )
    var caps = List[String]()
    caps.append(String("copy-actual"))
    var v = verify_live_interfaces(
        fx("kernel-38"), doc^, caps^
    )
    assert_true(not v.ok)
    assert_equal(
        v.reason,
        String(
            "io_tlb_pool.start: layout mismatch"
            " (live offset 0 size 64)"
        ),
    )


def test_verify_live_layout_skipped_for_lifecycle() raises:
    # Layouts bind copy-actual only; a drifted layout
    # never refuses the lifecycle cap.
    var layouts = String(
        '{"struct":"io_tlb_pool","field":"start",'
        '"bit_offset":8,"bit_size":64}'
    )
    var doc = parse_profile_bytes(
        bytes_of(_live_doc_with_layouts(layouts))
    )
    var caps = List[String]()
    caps.append(String("mapping-lifecycle"))
    var v = verify_live_interfaces(
        fx("kernel-38"), doc^, caps^
    )
    assert_true(v.ok)
    assert_equal(v.reason, String(""))


def test_parse_signature_alt_ok() raises:
    var doc = tracing_doc().replace(
        String('"attach":"fexit"'),
        String('"attach":"fexit","signature_alt":["x","y"]'),
    )
    var p = parse_profile_bytes(bytes_of(doc))
    assert_equal(len(p.hooks[0].signature_alt), 2)
    assert_equal(p.hooks[0].signature_alt[0], String("x"))
    assert_equal(p.hooks[0].signature_alt[1], String("y"))


def test_parse_signature_alt_empty_rejects() raises:
    var doc = tracing_doc().replace(
        String('"attach":"fexit"'),
        String('"attach":"fexit","signature_alt":[""]'),
    )
    expect_reject(doc)


def test_parse_signature_alt_too_many_rejects() raises:
    var doc = tracing_doc().replace(
        String('"attach":"fexit"'),
        String(
            '"attach":"fexit",'
            '"signature_alt":["a","b","c","d","e"]'
        ),
    )
    expect_reject(doc)


def test_parse_signature_alt_on_tracepoint_rejects() raises:
    var doc = minimal_doc().replace(
        String('"format_path":"/f"'),
        String('"format_path":"/f","signature_alt":["x"]'),
    )
    expect_reject(doc)


def test_parse_layouts_ok() raises:
    var parts = minimal_doc().split(String("}]}"))
    assert_equal(len(parts), 2)
    var doc = String(parts[0]) + String(
        '}],"layouts":[{"struct":"io_tlb_pool","field":"start",'
        '"bit_offset":0,"bit_size":64}]}'
    )
    var p = parse_profile_bytes(bytes_of(doc))
    assert_equal(len(p.layouts), 1)
    assert_equal(p.layouts[0].struct_name, String("io_tlb_pool"))
    assert_equal(p.layouts[0].field_name, String("start"))
    assert_equal(p.layouts[0].bit_offset, 0)
    assert_equal(p.layouts[0].bit_size, 64)


def test_parse_layouts_negative_rejects() raises:
    var parts = minimal_doc().split(String("}]}"))
    assert_equal(len(parts), 2)
    var doc = String(parts[0]) + String(
        '}],"layouts":[{"struct":"s","field":"f",'
        '"bit_offset":-1,"bit_size":64}]}'
    )
    expect_reject(doc)


def test_parse_layouts_too_many_rejects() raises:
    var parts = minimal_doc().split(String("}]}"))
    assert_equal(len(parts), 2)
    var items = String("")
    for i in range(17):
        if i > 0:
            items += String(",")
        items += String('{"struct":"s","field":"f')
        items += String(i)
        items += String('","bit_offset":0,"bit_size":8}')
    var doc = (
        String(parts[0])
        + String('}],"layouts":[')
        + items
        + String("]}")
    )
    expect_reject(doc)


def _v012_doc(layouts_json: String) -> String:
    """live_ref_doc as 0.1.2 plus a layouts array from caller JSON."""
    return _live_doc_with_layouts(layouts_json).replace(
        String('"schema_version":"0.1.1"'),
        String('"schema_version":"0.1.2"'),
    )


def test_parse_v012_layouts_ok() raises:
    var doc = _v012_doc(
        String(
            '{"capability":"copy-actual","target":"field",'
            '"struct":"io_tlb_pool","field":"start",'
            '"type_kind":"int","bit_size":64,"optional":false},'
            '{"capability":"mapping-lifecycle","target":"type",'
            '"struct":"mvt_dev",'
            '"type_kind":"struct","bit_size":6144,"optional":true},'
            '{"capability":"attempt-trace","target":"enumerator",'
            '"struct":"mvt_e64","field":"MVT_BIG",'
            '"type_kind":"enum","bit_size":64,"optional":false}'
        )
    )
    var p = parse_profile_bytes(bytes_of(doc))
    assert_equal(len(p.layouts), 3)
    assert_equal(p.schema_version, String("0.1.2"))
    assert_equal(p.layouts[0].capability, String("copy-actual"))
    assert_equal(p.layouts[0].target, String("field"))
    assert_equal(p.layouts[0].type_kind, String("int"))
    assert_equal(p.layouts[0].bit_size, 64)
    assert_true(not p.layouts[0].optional)
    assert_true(p.layouts[0].v012)
    assert_equal(p.layouts[1].target, String("type"))
    assert_equal(p.layouts[1].field_name, String(""))
    assert_true(p.layouts[1].optional)
    assert_true(p.layouts[1].v012)
    assert_equal(p.layouts[2].target, String("enumerator"))
    assert_equal(p.layouts[2].field_name, String("MVT_BIG"))
    assert_true(p.layouts[2].v012)


def test_parse_v012_rejects() raises:
    # bit_offset is not a 0.1.2 layout key.
    expect_reject(
        _v012_doc(
            String(
                '{"capability":"copy-actual","target":"field",'
                '"struct":"s","field":"f","type_kind":"int",'
                '"bit_size":8,"bit_offset":0,"optional":false}'
            )
        )
    )
    # type_kind is required.
    expect_reject(
        _v012_doc(
            String(
                '{"capability":"copy-actual","target":"field",'
                '"struct":"s","field":"f",'
                '"bit_size":8,"optional":false}'
            )
        )
    )
    # At most 64 items.
    var items = String("")
    for i in range(65):
        if i > 0:
            items += String(",")
        items += String(
            '{"capability":"copy-actual","target":"field",'
            '"struct":"s","field":"f'
        )
        items += String(i)
        items += String(
            '","type_kind":"int","bit_size":8,"optional":false}'
        )
    expect_reject(_v012_doc(items))
    # The 0.1.1 item shape is not a 0.1.2 item.
    expect_reject(
        _v012_doc(
            String(
                '{"struct":"s","field":"f",'
                '"bit_offset":0,"bit_size":64}'
            )
        )
    )
    # A type target omits field.
    expect_reject(
        _v012_doc(
            String(
                '{"capability":"copy-actual","target":"type",'
                '"struct":"s","field":"f","type_kind":"struct",'
                '"bit_size":64,"optional":false}'
            )
        )
    )
    # bit_size starts at 1.
    expect_reject(
        _v012_doc(
            String(
                '{"capability":"copy-actual","target":"field",'
                '"struct":"s","field":"f","type_kind":"int",'
                '"bit_size":0,"optional":false}'
            )
        )
    )
    # Duplicates name layouts and duplicate.
    var raised = False
    try:
        _ = parse_profile_bytes(
            bytes_of(
                _v012_doc(
                    String(
                        '{"capability":"copy-actual","target":"field",'
                        '"struct":"s","field":"f","type_kind":"int",'
                        '"bit_size":8,"optional":false},'
                        '{"capability":"copy-actual","target":"field",'
                        '"struct":"s","field":"f","type_kind":"int",'
                        '"bit_size":8,"optional":true}'
                    )
                )
            )
        )
    except e:
        raised = True
        assert_true(contains(String(e), String("layouts")))
        assert_true(contains(String(e), String("duplicate")))
    assert_true(raised)


def _v012_field(
    cap: String,
    sname: String,
    fname: String,
    kind: String,
    size: Int,
    optional: Bool,
) -> String:
    """One 0.1.2 field-target layout item as JSON."""
    var flag = String("false")
    if optional:
        flag = String("true")
    return (
        String('{"capability":"')
        + cap
        + String('","target":"field","struct":"')
        + sname
        + String('","field":"')
        + fname
        + String('","type_kind":"')
        + kind
        + String('","bit_size":')
        + String(size)
        + String(',"optional":')
        + flag
        + String("}")
    )


def _v012_btf() raises -> List[UInt8]:
    """kernel-38 vmlinux BTF bytes."""
    return read_host_file(
        fx("kernel-38") + String("/sys/kernel/btf/vmlinux"),
        String("fixture"),
        67108864,
    )


def test_core_layout_live_ok() raises:
    var raw = _v012_btf()
    var doc = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                _v012_field(
                    String("copy-actual"),
                    String("io_tlb_pool"),
                    String("start"),
                    String("int"),
                    64,
                    False,
                )
                + String(",")
                + _v012_field(
                    String("copy-actual"),
                    String("io_tlb_pool"),
                    String("slots"),
                    String("ptr"),
                    64,
                    False,
                )
                + String(",")
                + _v012_field(
                    String("copy-actual"),
                    String("device_dma_parameters"),
                    String("min_align_mask"),
                    String("int"),
                    32,
                    False,
                )
            )
        )
    )
    var lines = List[String]()
    var v = verify_core_layouts(
        Span(raw), doc.layouts, String("copy-actual"), lines
    )
    assert_true(v.ok)
    assert_equal(v.reason, String(""))
    assert_equal(len(lines), 3)
    assert_equal(
        lines[0],
        String("io_tlb_pool.start: offset 0 bits, size 64 bits"),
    )


def test_core_layout_live_refusals() raises:
    var raw = _v012_btf()
    # An absent member refuses with its layout code.
    var doc = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                _v012_field(
                    String("copy-actual"),
                    String("io_tlb_pool"),
                    String("cc_shared"),
                    String("int"),
                    8,
                    False,
                )
            )
        )
    )
    var lines = List[String]()
    var v = verify_core_layouts(
        Span(raw), doc.layouts, String("copy-actual"), lines
    )
    assert_true(not v.ok)
    assert_true(not v.unknown)
    assert_equal(v.code, String("layout-missing"))
    assert_equal(
        v.reason,
        String("layout: io_tlb_pool.cc_shared absent from kernel BTF"),
    )
    # The same member, optional, passes with an absent note.
    var doc_opt = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                _v012_field(
                    String("copy-actual"),
                    String("io_tlb_pool"),
                    String("cc_shared"),
                    String("int"),
                    8,
                    True,
                )
            )
        )
    )
    var lines_opt = List[String]()
    var v_opt = verify_core_layouts(
        Span(raw), doc_opt.layouts, String("copy-actual"), lines_opt
    )
    assert_true(v_opt.ok)
    assert_equal(len(lines_opt), 1)
    assert_equal(
        lines_opt[0],
        String("io_tlb_pool.cc_shared: absent (optional)"),
    )
    # A drifted size refuses with both widths quoted.
    var doc_size = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                _v012_field(
                    String("copy-actual"),
                    String("io_tlb_pool"),
                    String("start"),
                    String("int"),
                    32,
                    False,
                )
            )
        )
    )
    var lines_size = List[String]()
    var v_size = verify_core_layouts(
        Span(raw), doc_size.layouts, String("copy-actual"), lines_size
    )
    assert_true(not v_size.ok)
    assert_equal(v_size.code, String("layout-size"))
    assert_equal(
        v_size.reason,
        String(
            "layout: io_tlb_pool.start size 64 bits"
            " differs from object size 32 bits"
        ),
    )
    # A drifted kind refuses with both kinds quoted.
    var doc_kind = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                _v012_field(
                    String("copy-actual"),
                    String("io_tlb_pool"),
                    String("start"),
                    String("ptr"),
                    64,
                    False,
                )
            )
        )
    )
    var lines_kind = List[String]()
    var v_kind = verify_core_layouts(
        Span(raw), doc_kind.layouts, String("copy-actual"), lines_kind
    )
    assert_true(not v_kind.ok)
    assert_equal(v_kind.code, String("layout-kind"))
    assert_equal(
        v_kind.reason,
        String(
            "layout: io_tlb_pool.start kind int"
            " differs from object kind ptr"
        ),
    )
    # A lifecycle item refuses the lifecycle cap, not copy-actual.
    var doc_lc = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                _v012_field(
                    String("mapping-lifecycle"),
                    String("io_tlb_pool"),
                    String("cc_shared"),
                    String("int"),
                    8,
                    False,
                )
            )
        )
    )
    var lines_lc = List[String]()
    var v_lc = verify_core_layouts(
        Span(raw), doc_lc.layouts, String("mapping-lifecycle"), lines_lc
    )
    assert_true(not v_lc.ok)
    assert_equal(v_lc.code, String("layout-missing"))
    var lines_cp = List[String]()
    var v_cp = verify_core_layouts(
        Span(raw), doc_lc.layouts, String("copy-actual"), lines_cp
    )
    assert_true(v_cp.ok)
    assert_equal(len(lines_cp), 0)


def test_core_layout_live_type_enum() raises:
    var raw = read_host_file(
        String("tests/fixtures/btf/members.bin"),
        String("fixture"),
        67108864,
    )
    # A recorded struct matches kind and size; no offset prints.
    var doc = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                String(
                    '{"capability":"copy-actual","target":"type",'
                    '"struct":"mvt_dev","type_kind":"struct",'
                    '"bit_size":6144,"optional":false}'
                )
            )
        )
    )
    var lines = List[String]()
    var v = verify_core_layouts(
        Span(raw), doc.layouts, String("copy-actual"), lines
    )
    assert_true(v.ok)
    assert_equal(len(lines), 1)
    assert_equal(lines[0], String("mvt_dev: size 6144 bits"))
    # A typedef resolves through to its terminal kind.
    var doc_td = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                String(
                    '{"capability":"copy-actual","target":"type",'
                    '"struct":"mvt_phys_t","type_kind":"int",'
                    '"bit_size":64,"optional":false}'
                )
            )
        )
    )
    var lines_td = List[String]()
    var v_td = verify_core_layouts(
        Span(raw), doc_td.layouts, String("copy-actual"), lines_td
    )
    assert_true(v_td.ok)
    assert_equal(len(lines_td), 1)
    assert_equal(lines_td[0], String("mvt_phys_t: size 64 bits"))
    # A recorded enumerator matches the enum width.
    var doc_enum = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                String(
                    '{"capability":"copy-actual","target":"enumerator",'
                    '"struct":"mvt_e64","field":"MVT_BIG",'
                    '"type_kind":"enum","bit_size":64,"optional":false}'
                )
            )
        )
    )
    var lines_enum = List[String]()
    var v_enum = verify_core_layouts(
        Span(raw), doc_enum.layouts, String("copy-actual"), lines_enum
    )
    assert_true(v_enum.ok)
    assert_equal(len(lines_enum), 1)
    assert_equal(lines_enum[0], String("mvt_e64.MVT_BIG: size 64 bits"))
    # A missing type refuses without a member suffix.
    var doc_absent = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                String(
                    '{"capability":"copy-actual","target":"type",'
                    '"struct":"mvt_none","type_kind":"struct",'
                    '"bit_size":8,"optional":false}'
                )
            )
        )
    )
    var lines_absent = List[String]()
    var v_absent = verify_core_layouts(
        Span(raw), doc_absent.layouts, String("copy-actual"), lines_absent
    )
    assert_true(not v_absent.ok)
    assert_equal(v_absent.code, String("layout-missing"))
    assert_equal(
        v_absent.reason,
        String("layout: mvt_none absent from kernel BTF"),
    )
    # A drifted type kind refuses with both kinds quoted.
    var doc_kind = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                String(
                    '{"capability":"copy-actual","target":"type",'
                    '"struct":"mvt_dev","type_kind":"union",'
                    '"bit_size":6144,"optional":false}'
                )
            )
        )
    )
    var lines_kind = List[String]()
    var v_kind = verify_core_layouts(
        Span(raw), doc_kind.layouts, String("copy-actual"), lines_kind
    )
    assert_true(not v_kind.ok)
    assert_equal(v_kind.code, String("layout-kind"))
    assert_equal(
        v_kind.reason,
        String(
            "layout: mvt_dev kind struct differs from object kind union"
        ),
    )


def test_core_layout_bitfield_ambiguous() raises:
    var raw = read_host_file(
        String("tests/fixtures/btf/members.bin"),
        String("fixture"),
        67108864,
    )
    # A bitfield member refuses even with a matching width.
    var doc_bf = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                _v012_field(
                    String("copy-actual"),
                    String("mvt_dev"),
                    String("offline_disabled"),
                    String("int"),
                    1,
                    False,
                )
            )
        )
    )
    var lines_bf = List[String]()
    var v_bf = verify_core_layouts(
        Span(raw), doc_bf.layouts, String("copy-actual"), lines_bf
    )
    assert_true(not v_bf.ok)
    assert_true(not v_bf.unknown)
    assert_equal(v_bf.code, String("layout-bitfield"))
    assert_equal(
        v_bf.reason,
        String(
            "layout: mvt_dev.offline_disabled is a bitfield (unsupported)"
        ),
    )
    # Disagreeing definitions refuse with the resolver message.
    var doc_amb = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                _v012_field(
                    String("copy-actual"),
                    String("mvt_dup"),
                    String("flags"),
                    String("int"),
                    32,
                    False,
                )
            )
        )
    )
    var lines_amb = List[String]()
    var v_amb = verify_core_layouts(
        Span(raw), doc_amb.layouts, String("copy-actual"), lines_amb
    )
    assert_true(not v_amb.ok)
    assert_equal(v_amb.code, String("layout-ambiguous"))
    assert_equal(
        v_amb.reason,
        String("struct mvt_dup: 2 definitions disagree on flags"),
    )


def test_core_layout_reader_failure() raises:
    # A truncated blob is unknown with the health code, never refused.
    var raw = List[UInt8]()
    raw.append(UInt8(0))
    raw.append(UInt8(1))
    var doc = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                _v012_field(
                    String("copy-actual"),
                    String("s"),
                    String("f"),
                    String("int"),
                    8,
                    False,
                )
            )
        )
    )
    var lines = List[String]()
    var v = verify_core_layouts(
        Span(raw), doc.layouts, String("copy-actual"), lines
    )
    assert_true(not v.ok)
    assert_true(v.unknown)
    assert_equal(v.code, String("btf-truncated"))


def test_verify_live_v012_evidence() raises:
    var doc = parse_profile_bytes(
        bytes_of(
            _v012_doc(
                _v012_field(
                    String("copy-actual"),
                    String("io_tlb_pool"),
                    String("start"),
                    String("int"),
                    64,
                    False,
                )
            )
        )
    )
    var caps = List[String]()
    caps.append(String("copy-actual"))
    var v = verify_live_interfaces(
        fx("kernel-38"), doc^, caps^
    )
    assert_true(v.ok)
    assert_equal(v.reason, String(""))
    assert_equal(len(v.evidence), 1)
    assert_equal(
        v.evidence[0],
        String("io_tlb_pool.start: offset 0 bits, size 64 bits"),
    )


def _mint_live() raises -> String:
    """Mint a local-auto receipt over live-measured bindings."""
    var r = open_evidence_reader(fx("kernel-38"))
    var env = detect_environment(r)
    var doc = parse_profile_bytes(bytes_of(live_ref_doc()))
    var sel = select_attempt_hook(doc)
    assert_true(sel.ok)
    var bind = NarrowBindings()
    var unmeasured = measure_live_bindings(
        fx("kernel-38"),
        env.kernel.release,
        String("libz.so.1"),
        sel.hook.format_path,
        bind,
    )
    assert_equal(unmeasured, String(""))
    var caps = List[CapQualification]()
    caps.append(
        CapQualification(String("attempt-trace"), String("smoke ok"))
    )
    caps.append(
        CapQualification(String("mapping-lifecycle"), String("smoke ok"))
    )
    return mint_qualification_receipt(
        String("t-live"),
        env.kernel,
        bind,
        UInt64(123456789),
        caps^,
        String("0.1.0"),
        String("sha256:") + String(_MINT_BRIDGE),
        String("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        String("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        String(""),
        UInt64(3),
        String("smoke: attach/poll/detach, no traffic required"),
    )


def test_live_receipt_roundtrip() raises:
    var r = open_evidence_reader(fx("kernel-38"))
    var env = detect_environment(r)
    var doc = parse_profile_bytes(bytes_of(live_ref_doc()))
    var js = _mint_live()
    # Object shas arrive bare (receipt parse strips the
    # prefix; record resolves bare hex the same way).
    var v = verify_live_receipt(
        js.as_bytes(),
        doc,
        env.kernel,
        String(_MINT_BRIDGE),
        fx("kernel-38"),
        String("libz.so.1"),
        String("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        String("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        String(""),
    )
    assert_true(v.ok)
    assert_equal(len(v.caps), 2)


def test_live_receipt_drift_refuses() raises:
    # kernel-38-73 matches kernel-38 everywhere except
    # the BTF bytes, so the kernel-38 receipt fails there
    # with the live (not note) wording.
    var r = open_evidence_reader(fx("kernel-38"))
    var env = detect_environment(r)
    var doc = parse_profile_bytes(bytes_of(live_ref_doc()))
    var js = _mint_live()
    var v = verify_live_receipt(
        js.as_bytes(),
        doc,
        env.kernel,
        String(_MINT_BRIDGE),
        fx("kernel-38-73"),
        String("libz.so.1"),
        String(""),
        String(""),
        String(""),
    )
    assert_true(not v.ok)
    assert_equal(
        v.message, String("receipt bindings differ from live")
    )


def test_live_receipt_object_drift_refuses() raises:
    var r = open_evidence_reader(fx("kernel-38"))
    var env = detect_environment(r)
    var doc = parse_profile_bytes(bytes_of(live_ref_doc()))
    var js = _mint_live()
    var v = verify_live_receipt(
        js.as_bytes(),
        doc,
        env.kernel,
        String(_MINT_BRIDGE),
        fx("kernel-38"),
        String("libz.so.1"),
        String("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        String(""),
        String(""),
    )
    assert_true(not v.ok)
    assert_equal(
        v.message, String("receipt artifacts differ from objects")
    )




def test_select_bound_receipt_grade_caps() raises:
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var ps = load_profiles(fx("profiles-bound-ref"))
    var d = select_profile_bound(
        env.kernel,
        ps^,
        fx("bound-host"),
        String("libz.so.1"),
        fx("profiles-bound-ref"),
        String(_MINT_BRIDGE),
    )
    assert_true(d.matched)
    assert_equal(d.grade, String("local-auto"))
    assert_equal(len(d.receipt_caps), 1)
    assert_equal(d.receipt_caps[0], String("attempt-trace"))


def test_default_receipts_dir() raises:
    assert_equal(
        default_receipts_dir(
            String("/usr/share/memveil/profiles")
        ),
        String("/var/lib/memveil/receipts"),
    )
    assert_equal(
        default_receipts_dir(
            String("/usr/share/memveil/profiles/")
        ),
        String("/var/lib/memveil/receipts"),
    )
    assert_equal(
        default_receipts_dir(
            String("/usr/share/memveil/profiles//")
        ),
        String("/var/lib/memveil/receipts"),
    )
    assert_equal(
        default_receipts_dir(
            String("/usr/share/memveil/profiles/.")
        ),
        String("/var/lib/memveil/receipts"),
    )
    assert_equal(
        default_receipts_dir(
            String("/usr/share/memveil/profiles/./")
        ),
        String("/var/lib/memveil/receipts"),
    )
    assert_equal(
        default_receipts_dir(
            String("/usr/share/memveil/./profiles")
        ),
        String("/var/lib/memveil/receipts"),
    )
    assert_equal(
        default_receipts_dir(
            String("/usr/share//memveil/profiles")
        ),
        String("/var/lib/memveil/receipts"),
    )
    assert_equal(
        default_receipts_dir(
            String("/usr/share/memveil/./profiles/")
        ),
        String("/var/lib/memveil/receipts"),
    )
    assert_equal(
        default_receipts_dir(
            String("/usr/share/memveil/profiles/..")
        ),
        String("/usr/share/memveil/profiles/../receipts"),
    )
    # Interior-.. spellings that the kernel would fold
    # to the installed dir keep the byte-identical
    # fallback (rationale in _installed_profiles_key):
    # lexical .. resolution is symlink-unsafe.
    assert_equal(
        default_receipts_dir(
            String("/usr/share/memveil/profiles/../profiles")
        ),
        String(
            "/usr/share/memveil/profiles/../profiles/receipts"
        ),
    )
    assert_equal(
        default_receipts_dir(
            String("/usr/share/memveil/other/../profiles")
        ),
        String(
            "/usr/share/memveil/other/../profiles/receipts"
        ),
    )
    assert_equal(
        default_receipts_dir(String("build/../profiles")),
        String("build/../profiles/receipts"),
    )
    assert_equal(
        default_receipts_dir(String("/opt/mv/profiles")),
        String("/opt/mv/profiles/receipts"),
    )


def test_select_bound_validated_grade_caps() raises:
    var r = open_evidence_reader(fx("bound-host"))
    var env = detect_environment(r)
    var ps = load_profiles(fx("profiles-bound"))
    var d = select_profile_bound(
        env.kernel, ps^, fx("bound-host"), String("libz.so.1"),
        fx("profiles-bound"),
        String(""),
    )
    assert_true(d.matched)
    assert_equal(d.grade, String("validated"))
    assert_equal(len(d.receipt_caps), 0)




def _sig_doc(hooks_json: String, cap_hooks_json: String) -> String:
    """One minimal 0.1.1 document with caller-supplied hooks."""
    return (
        '{"schema_version":"0.1.1","profile_id":"s",'
        '"status":"reference-unvalidated","identity":{"arch":"x86_64",'
        '"min_kernel":"7.0","source":{"origin":"o","revision":"r"}},'
        '"hooks":[' + hooks_json + '],'
        '"capabilities":[{"id":"mapping-lifecycle",'
        '"status":"candidate","hooks":[' + cap_hooks_json + '],'
        '"reason":"r"}]}'
    )


def _tracing_hook(function: String, signature: String) -> String:
    """One tracing hook JSON fragment for function/signature."""
    return (
        '{"name":"fentry:' + function + '","kind":"tracing",'
        '"function":"' + function + '","attach":"fentry",'
        '"signature":"' + signature + '"}'
    )


def _sig_btf() raises -> List[UInt8]:
    """Raw BTF bytes holding FUNC test_fn from funcproto.bin."""
    return read_host_file(
        String("tests/fixtures/btf/funcproto.bin"),
        String("fixture"),
        67108864,
    )


def test_sig_match() raises:
    var doc = _sig_doc(
        _tracing_hook(
            String("test_fn"),
            String("int test_fn(struct device *dev, size_t size)"),
        ),
        String('"fentry:test_fn"'),
    )
    var p = parse_profile_bytes(bytes_of(doc))
    var raw = _sig_btf()
    var vs = verify_hook_signatures(p, Span(raw))
    assert_equal(len(vs), 1)
    assert_equal(vs[0].hook, String("fentry:test_fn"))
    assert_true(vs[0].ok)
    assert_equal(vs[0].reason, String(""))
    assert_equal(
        vs[0].live, String("int (struct device *dev, size_t size)")
    )


def test_sig_mismatch() raises:
    # Type spellings compare, never parameter names: a
    # differing return type still mismatches loudly.
    var doc = _sig_doc(
        _tracing_hook(
            String("test_fn"),
            String("long test_fn(struct device *dev, size_t size)"),
        ),
        String('"fentry:test_fn"'),
    )
    var p = parse_profile_bytes(bytes_of(doc))
    var raw = _sig_btf()
    var vs = verify_hook_signatures(p, Span(raw))
    assert_equal(len(vs), 1)
    assert_true(not vs[0].ok)
    assert_true(contains(vs[0].reason, String("signature mismatch")))
    assert_equal(
        vs[0].live, String("int (struct device *dev, size_t size)")
    )


def test_sig_missing_function() raises:
    var doc = _sig_doc(
        _tracing_hook(String("nope"), String("int nope(int x)")),
        String('"fentry:nope"'),
    )
    var p = parse_profile_bytes(bytes_of(doc))
    var raw = _sig_btf()
    var vs = verify_hook_signatures(p, Span(raw))
    assert_equal(len(vs), 1)
    assert_true(not vs[0].ok)
    assert_true(
        contains(vs[0].reason, String("function nope not found"))
    )
    assert_equal(vs[0].live, String(""))


def test_sig_malformed_frozen() raises:
    var doc = _sig_doc(
        _tracing_hook(String("test_fn"), String("int test_fn")),
        String('"fentry:test_fn"'),
    )
    var p = parse_profile_bytes(bytes_of(doc))
    var raw = _sig_btf()
    var vs = verify_hook_signatures(p, Span(raw))
    assert_equal(len(vs), 1)
    assert_true(not vs[0].ok)
    assert_true(
        contains(vs[0].reason, String("frozen signature malformed"))
    )


def test_sig_names_ignored() raises:
    var doc = _sig_doc(
        _tracing_hook(
            String("test_fn"),
            String("int test_fn(struct device *d, size_t length)"),
        ),
        String('"fentry:test_fn"'),
    )
    var p = parse_profile_bytes(bytes_of(doc))
    var raw = _sig_btf()
    var vs = verify_hook_signatures(p, Span(raw))
    assert_equal(len(vs), 1)
    assert_true(vs[0].ok)
    assert_equal(vs[0].reason, String(""))


def test_sig_typedef_swap() raises:
    var doc = _sig_doc(
        _tracing_hook(
            String("test_fn"),
            String("int test_fn(struct device *dev, phys_addr_t size)"),
        ),
        String('"fentry:test_fn"'),
    )
    var p = parse_profile_bytes(bytes_of(doc))
    var raw = _sig_btf()
    var vs = verify_hook_signatures(p, Span(raw))
    assert_equal(len(vs), 1)
    assert_true(not vs[0].ok)
    assert_true(contains(vs[0].reason, String("signature mismatch")))


def test_sig_param_count() raises:
    var doc = _sig_doc(
        _tracing_hook(
            String("test_fn"),
            String(
                "int test_fn(struct device *dev, size_t size, int extra)"
            ),
        ),
        String('"fentry:test_fn"'),
    )
    var p = parse_profile_bytes(bytes_of(doc))
    var raw = _sig_btf()
    var vs = verify_hook_signatures(p, Span(raw))
    assert_equal(len(vs), 1)
    assert_true(not vs[0].ok)
    assert_true(contains(vs[0].reason, String("signature mismatch")))


def test_sig_width() raises:
    var doc = _sig_doc(
        _tracing_hook(
            String("test_fn"),
            String("int test_fn(struct device *dev, size_t size)"),
        ),
        String('"fentry:test_fn"'),
    )
    var p = parse_profile_bytes(bytes_of(doc))
    var raw = read_host_file(
        String("tests/fixtures/btf/sig-width.bin"),
        String("fixture"),
        67108864,
    )
    var vs = verify_hook_signatures(p, Span(raw))
    assert_equal(len(vs), 1)
    assert_true(not vs[0].ok)
    assert_equal(
        vs[0].reason,
        String("fentry:test_fn: size_t width 32 bits (want 64)"),
    )


def test_sig_skips_tracepoint() raises:
    var doc = _sig_doc(
        '{"name":"swiotlb:x","kind":"tracepoint",'
        '"id_path":"/i","format_path":"/f"},'
        + _tracing_hook(
            String("test_fn"),
            String("int test_fn(struct device *dev, size_t size)"),
        ),
        String('"swiotlb:x","fentry:test_fn"'),
    )
    var p = parse_profile_bytes(bytes_of(doc))
    var raw = _sig_btf()
    var vs = verify_hook_signatures(p, Span(raw))
    assert_equal(len(vs), 1)
    assert_equal(vs[0].hook, String("fentry:test_fn"))
    assert_true(vs[0].ok)


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
    suite.test[test_floor_68_pass]()
    suite.test[test_floor_515_fail]()
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
    suite.test[test_parse_source_note_700_ok]()
    suite.test[test_parse_source_note_1025_rejects]()
    suite.test[test_parse_reference_file]()
    suite.test[test_gate_doc_tracing_caps_supported]()
    suite.test[test_parse_validated_file]()
    suite.test[test_parse_bad_status]()
    suite.test[test_parse_bad_version]()
    suite.test[test_parse_unknown_key]()
    suite.test[test_parse_dup_key]()
    suite.test[test_parse_bad_profile_id]()
    suite.test[test_parse_bad_min_kernel]()
    suite.test[test_parse_short_min_kernel]()
    suite.test[test_parse_bad_kind]()
    suite.test[test_parse_tracing_hook_ok]()
    suite.test[test_parse_tracing_missing_signature_rejects]()
    suite.test[test_parse_tracing_bad_attach_rejects]()
    suite.test[test_parse_tracing_with_format_path_rejects]()
    suite.test[test_parse_tracepoint_with_function_rejects]()
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
    suite.test[test_select_bound_prefers_validated]()
    suite.test[test_select_bound_multi_hook]()
    suite.test[test_select_bound_receipt_beats_first_covering]()
    suite.test[test_select_bound_receipt_match]()
    suite.test[test_select_bound_receipt_stale]()
    suite.test[test_select_bound_receipt_bridge_mismatch]()
    suite.test[test_select_bound_receipt_bridge_unchecked]()
    suite.test[test_select_bound_falls_back_with_reason]()
    suite.test[test_receipt_roundtrip]()
    suite.test[test_receipt_verdict_caps]()
    suite.test[test_receipt_verdict_caps_multi]()
    suite.test[test_receipt_lifecycle_missing_hash_refuses]()
    suite.test[test_receipt_verdict_caps_empty_on_refusal]()
    suite.test[test_receipt_artifacts_null]()
    suite.test[test_receipt_workload_false]()
    suite.test[test_receipt_trailing_data]()
    suite.test[test_receipt_trailing_data_beats_bridge_mismatch]()
    suite.test[test_receipt_bridge_shape]()
    suite.test[test_receipt_bridge_mismatch_refuses]()
    suite.test[test_receipt_workload_kind]()
    suite.test[test_receipt_traffic_true]()
    suite.test[test_receipt_duration_shape]()
    suite.test[test_receipt_u64_max]()
    suite.test[test_receipt_created_ns_range]()
    suite.test[test_receipt_created_ns_huge]()
    suite.test[test_receipt_duration_range]()
    suite.test[test_receipt_duration_huge]()
    suite.test[test_receipt_note_empty]()
    suite.test[test_receipt_memveil_empty]()
    suite.test[test_receipt_objects_unknown_field]()
    suite.test[test_receipt_objects_empty]()
    suite.test[test_receipt_artifacts_unknown_field]()
    suite.test[test_receipt_artifact_mismatch]()
    suite.test[test_receipt_revision_mismatch]()
    suite.test[test_receipt_wrong_kernel]()
    suite.test[test_receipt_wrong_binding]()
    suite.test[test_receipt_wrong_profile]()
    suite.test[test_receipt_bad_json]()
    suite.test[test_receipt_empty_capabilities]()
    suite.test[test_receipt_wrong_grade]()
    suite.test[test_select_arch_mismatch]()
    suite.test[test_select_68_covers_6plus_reference]()
    suite.test[test_select_empty]()
    suite.test[test_select_unparseable]()
    suite.test[test_decide_oversized_format_judges]()
    suite.test[test_decide_hookless_refuses]()
    suite.test[test_verify_live_ok]()
    suite.test[test_verify_live_sig_mismatch]()
    suite.test[test_verify_live_unattachable]()
    suite.test[test_verify_live_btf_absent]()
    suite.test[test_verify_live_btf_corrupt]()
    suite.test[test_verify_live_btf_corrupt_unknown]()
    suite.test[test_verify_live_btf_split_unknown]()
    suite.test[test_verify_live_signame_accepted]()
    suite.test[test_verify_live_sigswap_mismatch]()
    suite.test[test_verify_live_sigwidth_refused]()
    suite.test[test_frozen_sig_unnamed_params]()
    suite.test[test_verify_live_73_sig_mismatch]()
    suite.test[test_verify_live_73_alt_ok]()
    suite.test[test_verify_live_alt_malformed]()
    suite.test[test_verify_live_layout_ok]()
    suite.test[test_verify_live_layout_mismatch]()
    suite.test[test_verify_live_layout_skipped_for_lifecycle]()
    suite.test[test_parse_signature_alt_ok]()
    suite.test[test_parse_signature_alt_empty_rejects]()
    suite.test[test_parse_signature_alt_too_many_rejects]()
    suite.test[test_parse_signature_alt_on_tracepoint_rejects]()
    suite.test[test_parse_layouts_ok]()
    suite.test[test_parse_layouts_negative_rejects]()
    suite.test[test_parse_layouts_too_many_rejects]()
    suite.test[test_parse_v012_layouts_ok]()
    suite.test[test_parse_v012_rejects]()
    suite.test[test_core_layout_live_ok]()
    suite.test[test_core_layout_live_refusals]()
    suite.test[test_core_layout_live_type_enum]()
    suite.test[test_core_layout_bitfield_ambiguous]()
    suite.test[test_core_layout_reader_failure]()
    suite.test[test_verify_live_v012_evidence]()
    suite.test[test_live_receipt_roundtrip]()
    suite.test[test_live_receipt_drift_refuses]()
    suite.test[test_live_receipt_object_drift_refuses]()
    suite.test[test_select_bound_receipt_grade_caps]()
    suite.test[test_select_bound_validated_grade_caps]()
    suite.test[test_sig_match]()
    suite.test[test_sig_mismatch]()
    suite.test[test_sig_names_ignored]()
    suite.test[test_sig_typedef_swap]()
    suite.test[test_sig_param_count]()
    suite.test[test_sig_width]()
    suite.test[test_sig_missing_function]()
    suite.test[test_sig_malformed_frozen]()
    suite.test[test_sig_skips_tracepoint]()
    suite.test[test_default_receipts_dir]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
