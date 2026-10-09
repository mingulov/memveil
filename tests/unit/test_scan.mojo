# SPDX-License-Identifier: GPL-3.0-or-later

"""Admission-scan decisions over fixture roots and bound docs."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.cli.record import (
    RecordOptions,
    ScanDecision,
    decide_record,
    render_provenance,
    run_record_with,
)
from memveil.platform.evidence import KernelInfo
from memveil.platform.narrow import LiveValue
from memveil.platform.profiles import (
    Profile,
    load_profiles,
    parse_profile_bytes,
)
from memveil.platform.reader import fs_type_name, read_host_file

comptime _OK = "tests/fixtures/scan/ok"
comptime _SKEW = "tests/fixtures/scan/skew"
comptime _NOCONFIG = "tests/fixtures/scan/noconfig"
comptime _DIFFCONFIG = "tests/fixtures/scan/diffconfig"
comptime _PROFILES = "tests/fixtures/scan/profiles"
comptime _ELF_OK = "tests/fixtures/elf/ok.o"
comptime _ELF_RING = "tests/fixtures/elf/badring.o"
comptime _ELF_LC = "tests/fixtures/elf/lc-ok.o"
comptime _ELF_CP = "tests/fixtures/elf/cp-ok.o"
comptime _ELF_LC_BAD = "tests/fixtures/elf/lc-wrongsec.o"


def _kernel() -> KernelInfo:
    return KernelInfo(
        String("7.0.0-test"), String("x86_64"), True, String("")
    )


def _doc(name: String) raises -> Profile:
    var raw = read_host_file(
        String(_PROFILES) + String("/") + name,
        String("profile"),
        1048576,
    )
    return parse_profile_bytes(raw^)


def _profiles() raises -> List[Profile]:
    return load_profiles(String(_PROFILES))


def _opts(output: String) -> RecordOptions:
    var opts = RecordOptions()
    opts.output = output
    opts.object = String(_ELF_OK)
    opts.bridge = String("test-bridge")
    opts.has_bridge = True
    return opts^


def test_scan_validated_wins() raises:
    var d = decide_record(
        String(_OK), _kernel(), _profiles(), String(""), False,
        String(_ELF_OK),
        String(""),
        String(""),
        String(""),
    )
    assert_true(d.ok)
    assert_equal(d.kind, String("validated"))
    assert_equal(d.profile.profile_id, String("scan-valid"))
    assert_equal(d.reason, String("validated scan-valid: bindings hold"))
    assert_equal(d.ring_bytes, 8388608)
    assert_equal(d.tp_system, String("swiotlb"))
    assert_equal(d.tp_event, String("swiotlb_bounced"))


def test_scan_bound_measurements() raises:
    # A bound decision carries every measured narrow
    # identity for capture provenance.
    var d = decide_record(
        String(_OK), _kernel(), _profiles(), String(""), False,
        String(_ELF_OK),
        String(""),
        String(""),
        String(""),
    )
    assert_true(d.ok)
    assert_equal(d.measured_config.state, String("value"))
    assert_equal(d.measured_config.value.byte_length(), 64)
    assert_true(d.measured_config_src != String(""))
    assert_equal(d.measured_btf.state, String("value"))
    assert_equal(d.measured_btf.value.byte_length(), 64)
    assert_equal(d.measured_format.state, String("value"))
    assert_equal(d.measured_format.value.byte_length(), 64)
    assert_equal(d.measured_image.state, String("value"))
    assert_equal(d.measured_image.value.byte_length(), 64)
    assert_equal(d.measured_image_bid.state, String("value"))
    assert_true(d.measured_image_bid.value.byte_length() > 0)


def test_scan_partial_unmeasured() raises:
    # A partial decision ran no binding: every measured
    # identity stays empty so the capture marks it
    # unavailable.
    var d = decide_record(
        String(_NOCONFIG),
        _kernel(),
        _profiles(),
        String(""),
        False,
        String(_ELF_OK),
        String(""),
        String(""),
        String(""),
    )
    assert_true(d.ok)
    assert_equal(d.measured_config.state, String(""))
    assert_equal(d.measured_config_src, String(""))
    assert_equal(d.measured_btf.state, String(""))
    assert_equal(d.measured_format.state, String(""))
    assert_equal(d.measured_image.state, String(""))
    assert_equal(d.measured_image_bid.state, String(""))


def test_render_provenance() raises:
    var v = LiveValue()
    v.state = String("value")
    v.value = String("ab12")
    var valued = render_provenance(String("config.sha256"), v)
    assert_equal(valued.item_type, String("provenance"))
    assert_equal(valued.source, String("config.sha256"))
    assert_equal(valued.interpretation, String("ab12"))
    var e = LiveValue()
    var empty = render_provenance(String("btf.sha256"), e)
    assert_equal(
        empty.interpretation,
        String("unavailable: narrow identity unverified"),
    )
    var u = LiveValue()
    u.state = String("uncheckable")
    u.detail = String("btf unreadable")
    var failed = render_provenance(String("btf.sha256"), u)
    assert_equal(
        failed.interpretation,
        String("unavailable: uncheckable: btf unreadable"),
    )
    var n = LiveValue()
    n.state = String("uncheckable")
    var bare = render_provenance(String("btf.sha256"), n)
    assert_equal(
        bare.interpretation, String("unavailable: uncheckable")
    )


def test_fs_type_live() raises:
    # /tmp exists on every test host: the answer is a
    # known name or an explicit unknown-magic marker.
    var got = fs_type_name(String("/tmp"))
    assert_true(got != String(""))
    assert_true(got != String("unavailable: statfs failed"))
    var known = (
        got == String("tmpfs")
        or got == String("ext2/ext3/ext4")
        or got == String("overlay")
        or got == String("xfs")
        or got == String("btrfs")
        or got == String("nfs")
        or got == String("9p")
        or got == String("fuse")
    )
    var hexed = False
    var pre = String("unknown:0x")
    if got.byte_length() > pre.byte_length():
        var same = True
        var gb = got.as_bytes()
        var pb = pre.as_bytes()
        for i in range(len(pb)):
            if gb[i] != pb[i]:
                same = False
        hexed = same
    assert_true(known or hexed)


def test_fs_type_missing() raises:
    assert_equal(
        fs_type_name(String("/nonexistent-dir-xyz-123")),
        String("unavailable: statfs failed"),
    )


def test_scan_skips_mismatched() raises:
    var ps = List[Profile]()
    ps.append(_doc(String("badbind.json")))
    ps.append(_doc(String("valid.json")))
    var d = decide_record(
        String(_OK), _kernel(), ps^, String(""), False, String(_ELF_OK),
        String(""),
        String(""),
        String(""),
    )
    assert_true(d.ok)
    assert_equal(d.kind, String("validated"))
    assert_equal(d.profile.profile_id, String("scan-valid"))


def test_scan_uncheckable_partial() raises:
    var d = decide_record(
        String(_NOCONFIG),
        _kernel(),
        _profiles(),
        String(""),
        False,
        String(_ELF_OK),
        String(""),
        String(""),
        String(""),
    )
    assert_true(d.ok)
    assert_equal(d.kind, String("partial"))
    assert_equal(
        d.reason,
        String("partial scan-valid: narrow identity unverified"),
    )


def test_scan_diffconfig_partial() raises:
    var d = decide_record(
        String(_DIFFCONFIG),
        _kernel(),
        _profiles(),
        String(""),
        False,
        String(_ELF_OK),
        String(""),
        String(""),
        String(""),
    )
    assert_true(d.ok)
    assert_equal(d.kind, String("partial"))


def test_scan_skew_partial() raises:
    var d = decide_record(
        String(_SKEW),
        _kernel(),
        _profiles(),
        String(""),
        False,
        String(_ELF_OK),
        String(""),
        String(""),
        String(""),
    )
    assert_true(d.ok)
    assert_equal(d.kind, String("partial"))


def test_scan_explicit_candidate() raises:
    var d = decide_record(
        String(_OK),
        _kernel(),
        List[Profile](),
        String(_PROFILES) + String("/ref.json"),
        True,
        String(_ELF_OK),
        String(""),
        String(""),
        String(""),
    )
    assert_true(d.ok)
    assert_equal(d.kind, String("candidate"))
    assert_equal(
        d.reason,
        String("candidate scan-ref: bindings hold (profile unvalidated)"),
    )


def test_scan_explicit_mismatch_refuses() raises:
    var opts = _opts(String("build/scan-refused-7"))
    opts.profile = String(_PROFILES) + String("/valid.json")
    opts.has_profile = True
    var code = run_record_with(
        String(_SKEW), String(_PROFILES), opts^
    )
    assert_equal(code, 3)
    var absent = False
    try:
        _ = read_host_file(
            String("build/scan-refused-7/session.json"),
            String("probe"),
            16,
        )
    except:
        absent = True
    assert_true(absent)


def test_scan_saturation_mechanism() raises:
    # The smaller-ring object is a shape-valid stand-in: the
    # matching candidate doc admits it, the production doc
    # refuses it at the object hash.
    var adm = decide_record(
        String(_OK),
        _kernel(),
        List[Profile](),
        String(_PROFILES) + String("/sat.json"),
        True,
        String(_ELF_RING),
        String(""),
        String(""),
        String(""),
    )
    assert_true(adm.ok)
    assert_equal(adm.kind, String("candidate"))
    assert_equal(adm.ring_bytes, 4194304)
    var rej = decide_record(
        String(_OK),
        _kernel(),
        List[Profile](),
        String(_PROFILES) + String("/valid.json"),
        True,
        String(_ELF_RING),
        String(""),
        String(""),
        String(""),
    )
    assert_true(not rej.ok)
    assert_equal(rej.refusal, String("binding failed: mismatch object"))


def test_scan_no_coverage() raises:
    var d = decide_record(
        String(_OK),
        _kernel(),
        List[Profile](),
        String(""),
        False,
        String(_ELF_OK),
        String(""),
        String(""),
        String(""),
    )
    assert_true(not d.ok)
    assert_equal(d.refusal, String("no profile covers this kernel"))


def test_scan_explicit_unbound_reference() raises:
    var d = decide_record(
        String(_OK),
        _kernel(),
        List[Profile](),
        String(_PROFILES) + String("/unbound.json"),
        True,
        String(_ELF_OK),
        String(""),
        String(""),
        String(""),
    )
    assert_true(d.ok)
    assert_equal(d.kind, String("partial"))
    assert_equal(
        d.reason, String("explicit scan-unbound (reference, no bindings)")
    )


def test_scan_explicit_validated_unbound() raises:
    var d = decide_record(
        String(_OK),
        _kernel(),
        List[Profile](),
        String(_PROFILES) + String("/valid-unbound.json"),
        True,
        String(_ELF_OK),
        String(""),
        String(""),
        String(""),
    )
    assert_true(d.ok)
    assert_equal(d.kind, String("partial"))
    assert_equal(
        d.reason,
        String("explicit scan-valid-unbound (unbound, no bindings)"),
    )


def test_scan_explicit_nohook() raises:
    var d = decide_record(
        String(_OK),
        _kernel(),
        List[Profile](),
        String(_PROFILES) + String("/nohook.json"),
        True,
        String(_ELF_OK),
        String(""),
        String(""),
        String(""),
    )
    assert_true(not d.ok)
    assert_equal(d.refusal, String("no tracepoint hook"))


def test_scan_explicit_notext() raises:
    var d = decide_record(
        String(_OK),
        _kernel(),
        List[Profile](),
        String(_PROFILES) + String("/notext.json"),
        True,
        String(_ELF_OK),
        String(""),
        String(""),
        String(""),
    )
    assert_true(not d.ok)
    assert_equal(
        d.refusal, String("binding failed: uncheckable format_text")
    )


comptime _CAPS3 = "attempt-trace,mapping-lifecycle,copy-actual"
comptime _LC_SHA = "b705ba5013c3f8b1add8f4228575fd0606d566a26864dc1162d99d055e2e5ed4"
comptime _CP_SHA = "b7853c92a677a74ac18facffac1728f71322f056f3b1a4c5c99794d52a3b1bf3"


def _decide_lc(
    root: String,
    explicit: String,
    has_explicit: Bool,
    object_path: String,
    lc_object: String,
    cp_object: String,
    caps: String,
) raises -> ScanDecision:
    var profiles = List[Profile]()
    if not has_explicit:
        profiles = _profiles()
    return decide_record(
        root,
        _kernel(),
        profiles^,
        explicit,
        has_explicit,
        object_path,
        lc_object,
        cp_object,
        caps,
    )


def test_scan_valid_lc_record() raises:
    """Requested lifecycle/copy caps select both extra channels."""
    var d = _decide_lc(
        String(_OK),
        String(_PROFILES) + String("/valid-lc.json"),
        True,
        String(_ELF_OK),
        String(_ELF_LC),
        String(_ELF_CP),
        String(_CAPS3),
    )
    assert_true(d.ok)
    assert_equal(d.kind, String("validated"))
    assert_equal(d.selected_caps, String(_CAPS3))
    assert_true(d.has_lifecycle)
    assert_true(d.has_copy)
    assert_equal(d.lc_object_sha, String(_LC_SHA))
    assert_equal(d.cp_object_sha, String(_CP_SHA))
    assert_equal(d.lc_ring_bytes, 8388608)
    assert_equal(d.cp_ring_bytes, 8388608)
    assert_true(len(d.lc_elf) > 0)
    assert_true(len(d.cp_elf) > 0)


def test_scan_valid_lc_no_tracing() raises:
    """A no-fentry lifecycle object cannot satisfy the request."""
    var d = _decide_lc(
        String(_OK),
        String(_PROFILES) + String("/valid-lc.json"),
        True,
        String(_ELF_OK),
        String(_ELF_LC_BAD),
        String(_ELF_CP),
        String(_CAPS3),
    )
    assert_true(not d.ok)
    assert_equal(
        d.refusal, String("lc object refused: no fentry section")
    )


def test_scan_skew_lc_refuses() raises:
    """A skewed lc_object binding refuses the requested channel."""
    var d = _decide_lc(
        String(_OK),
        String(_PROFILES) + String("/lc-skew.json"),
        True,
        String(_ELF_OK),
        String(_ELF_LC),
        String(_ELF_CP),
        String(_CAPS3),
    )
    assert_true(not d.ok)
    assert_equal(
        d.refusal, String("binding failed: mismatch lc_object")
    )


def test_scan_lc_unsupported_refuses() raises:
    """Requesting an unsupported cap names the cap and the doc."""
    var d = _decide_lc(
        String(_OK),
        String(_PROFILES) + String("/valid.json"),
        True,
        String(_ELF_OK),
        String(_ELF_LC),
        String(_ELF_CP),
        String(_CAPS3),
    )
    assert_true(not d.ok)
    assert_equal(
        d.refusal,
        String(
            "capability mapping-lifecycle unsupported by scan-valid"
        ),
    )


def test_scan_unknown_capability_refuses() raises:
    var d = _decide_lc(
        String(_OK),
        String(_PROFILES) + String("/valid-lc.json"),
        True,
        String(_ELF_OK),
        String(_ELF_LC),
        String(_ELF_CP),
        String("attempt-trace,nope"),
    )
    assert_true(not d.ok)
    assert_equal(d.refusal, String("unknown capability: nope"))


def test_scan_lc_needs_object() raises:
    var d = _decide_lc(
        String(_OK),
        String(_PROFILES) + String("/valid-lc.json"),
        True,
        String(_ELF_OK),
        String(""),
        String(_ELF_CP),
        String(_CAPS3),
    )
    assert_true(not d.ok)
    assert_equal(
        d.refusal,
        String("capability mapping-lifecycle needs --lc-object"),
    )


def test_scan_convert_capability_refuses() raises:
    var d = _decide_lc(
        String(_OK),
        String(_PROFILES) + String("/valid.json"),
        True,
        String(_ELF_OK),
        String(_ELF_LC),
        String(_ELF_CP),
        String("attempt-trace,conversion-observe"),
    )
    assert_true(not d.ok)
    assert_equal(
        d.refusal,
        String("capability conversion-observe has no record channel"),
    )


def test_scan_mode_lc_refuses() raises:
    """Scan mode refuses when no doc satisfies the request."""
    var d = _decide_lc(
        String(_OK),
        String(""),
        False,
        String(_ELF_OK),
        String(_ELF_LC),
        String(_ELF_CP),
        String(_CAPS3),
    )
    assert_true(not d.ok)
    assert_equal(
        d.refusal,
        String(
            "capability mapping-lifecycle unsupported by scan-valid"
        ),
    )


def _decide_variant(name: String) raises -> ScanDecision:
    """Decide the full request against one lc-variant doc."""
    return _decide_lc(
        String(_OK),
        String(_PROFILES) + String("/") + name,
        True,
        String(_ELF_OK),
        String(_ELF_LC),
        String(_ELF_CP),
        String(_CAPS3),
    )


def test_scan_lc_wrongfunc_refuses() raises:
    """A hook binding an unknown function refuses admission."""
    var d = _decide_variant(String("lc-wrongfunc.json"))
    assert_true(not d.ok)
    assert_equal(
        d.refusal,
        String(
            "capability mapping-lifecycle hook "
            "fentry:__swiotlb_tbl_unmap_single "
            "binds no frozen mapping-lifecycle hook"
        ),
    )


def test_scan_lc_wrongattach_refuses() raises:
    """A hook bound at the wrong attach point refuses."""
    var d = _decide_variant(String("lc-wrongattach.json"))
    assert_true(not d.ok)
    assert_equal(
        d.refusal,
        String(
            "capability mapping-lifecycle hook "
            "fexit:swiotlb_tbl_map_single "
            "binds no frozen mapping-lifecycle hook"
        ),
    )


def test_scan_lc_missing_refuses() raises:
    """A cap missing one frozen hook refuses (no vacuous bind)."""
    var d = _decide_variant(String("lc-missing.json"))
    assert_true(not d.ok)
    assert_equal(
        d.refusal,
        String(
            "capability mapping-lifecycle missing frozen hook "
            "fentry:__swiotlb_tbl_unmap_single"
        ),
    )


def test_scan_lc_extra_refuses() raises:
    """A non-tracing hook named by the cap refuses."""
    var d = _decide_variant(String("lc-extra.json"))
    assert_true(not d.ok)
    assert_equal(
        d.refusal,
        String(
            "capability mapping-lifecycle hook "
            "swiotlb:swiotlb_bounced is not a tracing hook"
        ),
    )


def test_scan_lc_badsig_refuses() raises:
    """A corrupted signature text refuses admission."""
    var d = _decide_variant(String("lc-badsig.json"))
    assert_true(not d.ok)
    assert_equal(
        d.refusal,
        String(
            "capability mapping-lifecycle hook "
            "fexit:swiotlb_tbl_map_single signature mismatch"
        ),
    )


def test_scan_lc_unknown_kernel_refuses() raises:
    """An unparseable release covers nothing, even bound docs."""
    var kernel = KernelInfo(
        String("bogus"), String("x86_64"), True, String("")
    )
    var profiles = List[Profile]()
    var d = decide_record(
        String(_OK),
        kernel,
        profiles^,
        String(_PROFILES) + String("/valid-lc.json"),
        True,
        String(_ELF_OK),
        String(_ELF_LC),
        String(_ELF_CP),
        String(_CAPS3),
    )
    assert_true(not d.ok)
    assert_equal(
        d.refusal, String("profile does not cover this kernel")
    )


def test_scan_lc_skew_root_refuses() raises:
    """Tracing caps still need the whole-identity binding."""
    var d = _decide_lc(
        String(_SKEW),
        String(_PROFILES) + String("/valid-lc.json"),
        True,
        String(_ELF_OK),
        String(_ELF_LC),
        String(_ELF_CP),
        String(_CAPS3),
    )
    assert_true(not d.ok)
    assert_equal(
        d.refusal, String("binding failed: mismatch image")
    )

def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_scan_valid_lc_record]()
    suite.test[test_scan_valid_lc_no_tracing]()
    suite.test[test_scan_skew_lc_refuses]()
    suite.test[test_scan_lc_unsupported_refuses]()
    suite.test[test_scan_unknown_capability_refuses]()
    suite.test[test_scan_convert_capability_refuses]()
    suite.test[test_scan_lc_needs_object]()
    suite.test[test_scan_mode_lc_refuses]()
    suite.test[test_scan_lc_wrongfunc_refuses]()
    suite.test[test_scan_lc_wrongattach_refuses]()
    suite.test[test_scan_lc_missing_refuses]()
    suite.test[test_scan_lc_extra_refuses]()
    suite.test[test_scan_lc_badsig_refuses]()
    suite.test[test_scan_lc_unknown_kernel_refuses]()
    suite.test[test_scan_lc_skew_root_refuses]()
    suite.test[test_scan_validated_wins]()
    suite.test[test_scan_bound_measurements]()
    suite.test[test_scan_partial_unmeasured]()
    suite.test[test_render_provenance]()
    suite.test[test_fs_type_live]()
    suite.test[test_fs_type_missing]()
    suite.test[test_scan_skips_mismatched]()
    suite.test[test_scan_uncheckable_partial]()
    suite.test[test_scan_diffconfig_partial]()
    suite.test[test_scan_skew_partial]()
    suite.test[test_scan_explicit_candidate]()
    suite.test[test_scan_explicit_mismatch_refuses]()
    suite.test[test_scan_saturation_mechanism]()
    suite.test[test_scan_no_coverage]()
    suite.test[test_scan_explicit_unbound_reference]()
    suite.test[test_scan_explicit_validated_unbound]()
    suite.test[test_scan_explicit_nohook]()
    suite.test[test_scan_explicit_notext]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
