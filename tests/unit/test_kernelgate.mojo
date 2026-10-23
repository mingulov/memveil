# SPDX-License-Identifier: GPL-3.0-or-later

"""Kernel gate unit tests: tracefs probing, hook identity, ftrace state."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.run import attempt_loss_evidence
from memveil.platform.capabilities import attempt_loss_exact
from memveil.platform.evidence import detect_environment
from memveil.platform.kernelgate import (
    GateVerdict,
    LockdownState,
    count_filter_function,
    kernel_gate,
    probe_tracefs,
    read_ftrace_enabled,
    read_lockdown,
    remedy_for,
    tracefs_translate,
)
from memveil.platform.profiles import (
    Profile,
    parse_profile_bytes,
    verify_live_interfaces,
)
from memveil.platform.reader import open_evidence_reader, read_host_file


def gate(name: String) -> String:
    """Fixture directory path for one gate fixture name."""
    return "tests/fixtures/gate/" + name


def live_ref() raises -> Profile:
    """The scan-live-ref profile document for gate tests."""
    var raw = read_host_file(
        String("tests/fixtures/scan/profiles-live/live-ref.json"),
        String("profile"),
        1048576,
    )
    return parse_profile_bytes(raw^)


def one_cap(cap_id: String) -> List[String]:
    """One-element capability list for live verification."""
    var caps = List[String]()
    caps.append(cap_id)
    return caps^


def contains(hay: String, needle: String) -> Bool:
    """True when needle occurs in hay at least once."""
    return len(hay.split(String(needle))) > 1


def lockdown_of(name: String) raises -> LockdownState:
    """Read the lockdown state of one gate fixture tree."""
    var r = open_evidence_reader(gate(name))
    return read_lockdown(r, r.release.copy(), String("libz.so.1"))


def caps2(a: String, b: String) -> List[String]:
    """Two-element capability list in order."""
    var caps = List[String]()
    caps.append(a)
    caps.append(b)
    return caps^


def caps3(a: String, b: String, c: String) -> List[String]:
    """Three-element capability list in order."""
    var caps = List[String]()
    caps.append(a)
    caps.append(b)
    caps.append(c)
    return caps^


def gate_of(name: String, caps: List[String]) raises -> GateVerdict:
    """Run the kernel gate on one fixture tree and cap set."""
    var r = open_evidence_reader(gate(name))
    return kernel_gate(r, r.release.copy(), String("libz.so.1"), caps)


def attempt_only() -> List[String]:
    """The attempt-trace-only capability list."""
    return one_cap(String("attempt-trace"))


def all_caps() -> List[String]:
    """All three record capabilities in channel order."""
    return caps3(
        String("attempt-trace"),
        String("mapping-lifecycle"),
        String("copy-actual"),
    )


def test_tracefs_root_order() raises:
    var base = open_evidence_reader(gate(String("base")))
    var pb = probe_tracefs(base)
    assert_equal(pb.root, String("/sys/kernel/tracing"))
    var dbg = open_evidence_reader(gate(String("debugfs-root")))
    var pd = probe_tracefs(dbg)
    assert_equal(pd.root, String("/sys/kernel/debug/tracing"))
    var den = open_evidence_reader(gate(String("debug-denied")))
    var pn = probe_tracefs(den)
    assert_equal(pn.root, String("/sys/kernel/tracing"))
    assert_equal(
        tracefs_translate(
            pd,
            String(
                "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"
            ),
        ),
        String(
            "/sys/kernel/debug/tracing"
            "/events/swiotlb/swiotlb_bounced/format"
        ),
    )


def test_hook_identity_shapes() raises:
    var dup = open_evidence_reader(gate(String("aff-dup")))
    var hd = count_filter_function(
        dup, probe_tracefs(dup), String("swiotlb_tbl_map_single")
    )
    assert_equal(hd.count, 2)
    var mod = open_evidence_reader(gate(String("aff-module")))
    var hm = count_filter_function(
        mod, probe_tracefs(mod), String("swiotlb_tbl_map_single")
    )
    assert_equal(hm.count, 1)
    var clo = open_evidence_reader(gate(String("aff-clone")))
    var hc = count_filter_function(
        clo, probe_tracefs(clo), String("swiotlb_tbl_map_single")
    )
    assert_equal(hc.count, 0)
    assert_equal(hc.clones, 1)
    var pre = open_evidence_reader(gate(String("aff-prefix")))
    var hp = count_filter_function(
        pre, probe_tracefs(pre), String("swiotlb_tbl_map_single")
    )
    assert_equal(hp.count, 1)


def test_live_hook_ambiguous() raises:
    var v = verify_live_interfaces(
        gate(String("aff-dup")),
        live_ref(),
        one_cap(String("mapping-lifecycle")),
    )
    assert_true(not v.ok)
    assert_true(not v.unknown)
    assert_equal(v.code, String("hook-ambiguous"))
    assert_equal(
        v.reason,
        String(
            "fexit:swiotlb_tbl_map_single: hook swiotlb_tbl_map_single"
            " ambiguous (2 available_filter_functions lines)"
        ),
    )


def test_live_ftrace() raises:
    var off = verify_live_interfaces(
        gate(String("ftrace-off")),
        live_ref(),
        one_cap(String("mapping-lifecycle")),
    )
    assert_true(not off.ok)
    assert_true(not off.unknown)
    assert_equal(off.code, String("ftrace-disabled"))
    assert_equal(
        off.reason,
        String("kernel.ftrace_enabled is 0 (function tracing disabled)"),
    )
    var den = verify_live_interfaces(
        gate(String("ftrace-denied")),
        live_ref(),
        one_cap(String("mapping-lifecycle")),
    )
    assert_true(not den.ok)
    assert_true(den.unknown)
    assert_equal(den.code, String("ftrace-unknown"))
    var mal = verify_live_interfaces(
        gate(String("ftrace-malformed")),
        live_ref(),
        one_cap(String("mapping-lifecycle")),
    )
    assert_true(not mal.ok)
    assert_true(mal.unknown)
    assert_equal(mal.code, String("ftrace-unknown"))
    var base = verify_live_interfaces(
        gate(String("base")),
        live_ref(),
        one_cap(String("mapping-lifecycle")),
    )
    assert_true(base.ok)
    var dbg = verify_live_interfaces(
        gate(String("debugfs-root")),
        live_ref(),
        one_cap(String("mapping-lifecycle")),
    )
    assert_true(dbg.ok)


def test_live_debugfs_attempt() raises:
    # Tracepoint format and id paths resolve under the
    # debugfs root too, so attempt-trace verifies there.
    var base = verify_live_interfaces(
        gate(String("base")),
        live_ref(),
        one_cap(String("attempt-trace")),
    )
    assert_true(base.ok)
    var dbg = verify_live_interfaces(
        gate(String("debugfs-root")),
        live_ref(),
        one_cap(String("attempt-trace")),
    )
    assert_true(dbg.ok)


def test_lockdown_sources() raises:
    var b = lockdown_of(String("base"))
    assert_equal(b.mode, String("none"))
    assert_equal(b.src, String("securityfs"))
    var c = lockdown_of(String("lockdown-conf"))
    assert_equal(c.mode, String("confidentiality"))
    assert_equal(c.src, String("securityfs"))
    var i = lockdown_of(String("lockdown-integrity"))
    assert_equal(i.mode, String("integrity"))
    assert_equal(i.src, String("securityfs"))
    var n = lockdown_of(String("lockdown-nosecfs"))
    assert_equal(n.mode, String("confidentiality"))
    assert_equal(n.src, String("cmdline"))
    var g = lockdown_of(String("lockdown-config"))
    assert_equal(g.mode, String("confidentiality"))
    assert_equal(g.src, String("config"))
    var l = lockdown_of(String("lockdown-nolsm"))
    assert_equal(l.mode, String("none"))
    assert_equal(l.src, String("config"))


def test_lockdown_malformed() raises:
    var d = lockdown_of(String("lockdown-dashdash"))
    assert_equal(d.mode, String("unknown"))
    assert_equal(d.src, String("none"))
    var t = lockdown_of(String("lockdown-twobrackets"))
    assert_equal(t.mode, String("unknown"))
    assert_equal(t.detail, String("lockdown file malformed"))
    var o = lockdown_of(String("lockdown-bogus"))
    assert_equal(o.mode, String("unknown"))
    assert_equal(o.src, String("none"))
    assert_true(contains(o.detail, String("lockdown=bogus ignored")))
    var x = lockdown_of(String("lockdown-denied"))
    assert_equal(x.mode, String("unknown"))


def test_lockdown_forcenone_unknown() raises:
    # FORCE_NONE without securityfs cannot settle the
    # runtime level: root may have raised it since boot.
    var f = lockdown_of(String("lockdown-forcenone"))
    assert_equal(f.mode, String("unknown"))
    assert_equal(f.src, String("config"))


def test_gate_order() raises:
    var lc = gate_of(String("lockdown-conf"), attempt_only())
    assert_true(not lc.ok)
    assert_true(not lc.unknown)
    assert_equal(lc.code, String("lockdown-confidentiality"))
    var nc = gate_of(String("notracing-config"), attempt_only())
    assert_true(not nc.ok)
    assert_equal(nc.code, String("no-bpf-tracing"))
    var nb = gate_of(String("notracing-bpfevents"), attempt_only())
    assert_true(not nb.ok)
    assert_equal(nb.code, String("no-bpf-tracing"))
    var ne = gate_of(String("tracefs-noevents"), attempt_only())
    assert_true(not ne.ok)
    assert_equal(ne.code, String("no-bpf-tracing"))
    assert_equal(
        ne.reason,
        String(
            "kernel has no BPF tracing support (tracefs mounted at"
            " /sys/kernel/tracing but has no events/)"
        ),
    )
    var tu = gate_of(String("tracefs-unmounted"), attempt_only())
    assert_true(not tu.ok)
    assert_equal(tu.code, String("tracefs-not-mounted"))
    var tg = gate_of(String("tracefs-gone"), attempt_only())
    assert_true(not tg.ok)
    assert_equal(tg.code, String("tracefs-not-mounted"))
    var th = gate_of(String("tracefs-hidden"), attempt_only())
    assert_true(not th.ok)
    assert_true(th.unknown)
    assert_equal(
        th.reason,
        String(
            "tracepoint absent or tracefs hidden by lockdown"
            " (lockdown state unknown)"
        ),
    )
    var ed = gate_of(String("events-denied"), attempt_only())
    assert_true(not ed.ok)
    assert_true(ed.unknown)
    assert_equal(ed.code, String("tracefs-denied"))
    var b = gate_of(String("base"), all_caps())
    assert_true(b.ok)


def test_gate_noevents_unknown_lockdown_hidden() raises:
    # Mounted tracefs without events/ is only a definite
    # no-bpf-tracing verdict when lockdown is known;
    # otherwise lockdown may be hiding the mount.
    var g = gate_of(String("tracefs-noevents-nolock"), attempt_only())
    assert_true(not g.ok)
    assert_true(g.unknown)
    assert_equal(g.code, String("tracefs-hidden"))


def test_gate_btf_codes() raises:
    var lc = caps2(String("attempt-trace"), String("mapping-lifecycle"))
    var c = gate_of(String("btf-absent-config"), lc.copy())
    assert_true(not c.ok)
    assert_true(not c.unknown)
    assert_equal(c.code, String("btf-absent-config"))
    assert_equal(c.reason, String("BTF absent (kernel built without BTF)"))
    var u = gate_of(String("btf-absent-unknown"), lc.copy())
    assert_true(not u.ok)
    assert_equal(u.code, String("btf-absent-unknown"))
    assert_equal(
        u.reason,
        String(
            "BTF absent (not exposed: kernel built without BTF,"
            " or /sys/kernel/btf hidden)"
        ),
    )
    var n = gate_of(String("btf-not-visible"), lc.copy())
    assert_true(not n.ok)
    assert_true(n.unknown)
    assert_equal(n.code, String("btf-not-visible"))
    var d = gate_of(String("btf-denied"), lc.copy())
    assert_true(not d.ok)
    assert_true(d.unknown)
    assert_equal(d.code, String("btf-denied"))
    assert_true(gate_of(String("btf-absent-config"), attempt_only()).ok)
    assert_true(gate_of(String("btf-absent-unknown"), attempt_only()).ok)
    assert_true(gate_of(String("btf-not-visible"), attempt_only()).ok)
    assert_true(gate_of(String("btf-denied"), attempt_only()).ok)


def test_gate_hook_kallsyms() raises:
    var doc = live_ref()
    var lc = one_cap(String("mapping-lifecycle"))
    var a = verify_live_interfaces(
        gate(String("hook-absent")), doc.copy(), lc.copy()
    )
    assert_true(not a.ok)
    assert_equal(a.code, String("btf-hook-absent"))
    assert_equal(
        a.reason,
        String(
            "fexit:swiotlb_tbl_map_single: function"
            " swiotlb_tbl_map_single absent from this kernel"
        ),
    )
    var p = verify_live_interfaces(
        gate(String("hook-not-in-btf")), doc.copy(), lc.copy()
    )
    assert_true(not p.ok)
    assert_equal(p.code, String("btf-hook-not-in-btf"))
    var k = verify_live_interfaces(
        gate(String("hook-clone")), doc.copy(), lc.copy()
    )
    assert_true(not k.ok)
    assert_equal(k.code, String("btf-hook-not-in-btf"))
    assert_true(
        contains(k.reason, String("swiotlb_tbl_map_single.isra.0"))
    )
    # No kallsyms file cannot arbitrate: the BTF verdict
    # stands with a missing code.
    var m = verify_live_interfaces(
        gate(String("hook-nokallsyms")), doc.copy(), lc.copy()
    )
    assert_true(not m.ok)
    assert_equal(m.code, String("btf-hook-missing"))
    assert_equal(
        m.reason,
        String(
            "fexit:swiotlb_tbl_map_single: function"
            " swiotlb_tbl_map_single not found"
        ),
    )


def test_gate_denied_never_absent() raises:
    var g = gate_of(String("denied-all"), all_caps())
    assert_true(g.ok or g.unknown)
    assert_true(g.code != String("btf-absent-config"))
    assert_true(g.code != String("btf-absent-unknown"))
    assert_true(g.code != String("tracefs-not-mounted"))
    assert_true(g.code != String("ftrace-disabled"))
    assert_true(g.code != String("no-bpf-tracing"))
    assert_equal(g.lockdown.mode, String("unknown"))
    assert_equal(
        read_ftrace_enabled(
            open_evidence_reader(gate(String("denied-all")))
        ).value,
        String("denied"),
    )


def test_gate_container_views() raises:
    var caps = caps2(String("attempt-trace"), String("copy-actual"))
    var v = gate_of(String("container-view"), caps)
    assert_true(not v.ok)
    assert_true(v.unknown)
    assert_equal(v.tracefs.root, String("/sys/kernel/debug/tracing"))
    assert_equal(v.code, String("btf-not-visible"))
    assert_equal(
        v.remedy,
        String("run with the host /sys: this view hides /sys/kernel/btf/vmlinux"),
    )


def test_remedy_per_code() raises:
    var codes = List[String]()
    var wants = List[String]()
    codes.append(String("lockdown-confidentiality"))
    wants.append(
        String(
            "boot without lockdown=confidentiality or use a kernel"
            " without CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY;"
            " integrity mode is fine"
        )
    )
    codes.append(String("no-bpf-tracing"))
    wants.append(
        String(
            "kernel has no BPF tracing support: use a kernel built"
            " with CONFIG_FTRACE=y and CONFIG_BPF_EVENTS=y"
        )
    )
    codes.append(String("tracefs-not-mounted"))
    wants.append(
        String("mount tracefs: mount -t tracefs nodev /sys/kernel/tracing")
    )
    codes.append(String("tracefs-hidden"))
    wants.append(
        String(
            "check the lockdown state"
            " (cat /sys/kernel/security/lockdown) and that tracefs"
            " is mounted"
        )
    )
    var priv = String(
        "run as root, or grant CAP_BPF and CAP_PERFMON (or CAP_SYS_ADMIN)"
        " and read access to tracefs and /sys/kernel/btf/vmlinux"
    )
    codes.append(String("tracefs-denied"))
    wants.append(priv.copy())
    codes.append(String("btf-denied"))
    wants.append(priv.copy())
    codes.append(String("no-bpf-privilege"))
    wants.append(priv.copy())
    codes.append(String("load-eperm"))
    wants.append(priv.copy())
    var btfbuild = String(
        "use a kernel built with CONFIG_DEBUG_INFO_BTF=y;"
        " memveil qualify cannot help"
    )
    codes.append(String("btf-absent-config"))
    wants.append(btfbuild.copy())
    codes.append(String("btf-absent-unknown"))
    wants.append(btfbuild.copy())
    codes.append(String("btf-malformed"))
    wants.append(btfbuild.copy())
    codes.append(String("btf-truncated"))
    wants.append(btfbuild.copy())
    codes.append(String("btf-too-large"))
    wants.append(btfbuild.copy())
    codes.append(String("btf-split"))
    wants.append(btfbuild.copy())
    codes.append(String("btf-unreadable"))
    wants.append(btfbuild.copy())
    codes.append(String("btf-hook-not-in-btf"))
    wants.append(btfbuild.copy())
    codes.append(String("btf-hook-missing"))
    wants.append(btfbuild.copy())
    codes.append(String("btf-not-visible"))
    wants.append(
        String(
            "run with the host /sys: this view hides"
            " /sys/kernel/btf/vmlinux"
        )
    )
    var nohook = String(
        "this kernel does not expose the hook function for tracing;"
        " this capability cannot run here"
    )
    codes.append(String("btf-hook-absent"))
    wants.append(nohook.copy())
    codes.append(String("hook-ambiguous"))
    wants.append(nohook.copy())
    codes.append(String("hook-not-traceable"))
    wants.append(nohook.copy())
    codes.append(String("ftrace-disabled"))
    wants.append(String("enable function tracing: sysctl kernel.ftrace_enabled=1"))
    codes.append(String("ftrace-unknown"))
    wants.append(
        String(
            "check that /proc/sys/kernel/ftrace_enabled is readable"
            " and holds 1"
        )
    )
    var layout = String(
        "this kernel's struct layout differs from what the objects"
        " were built for; this capability cannot run here"
    )
    codes.append(String("layout-missing"))
    wants.append(layout.copy())
    codes.append(String("layout-kind"))
    wants.append(layout.copy())
    codes.append(String("layout-size"))
    wants.append(layout.copy())
    codes.append(String("layout-bitfield"))
    wants.append(layout.copy())
    codes.append(String("layout-ambiguous"))
    wants.append(layout.copy())
    var sig = String(
        "refresh the profile's recorded signatures from this kernel,"
        " then re-prove with memveil qualify"
        " (see memveil qualify --help)"
    )
    codes.append(String("signature-mismatch"))
    wants.append(sig.copy())
    codes.append(String("signature-width"))
    wants.append(sig.copy())
    var mem = String(
        "raise the cgroup memory limit (memory.max) or RLIMIT_MEMLOCK"
    )
    codes.append(String("memcg-headroom"))
    wants.append(mem.copy())
    codes.append(String("load-enomem"))
    wants.append(mem.copy())
    codes.append(String("object-missing"))
    wants.append(
        String(
            "install the memveil BPF objects or pass --object,"
            " --lc-object, --cp-object"
        )
    )
    codes.append(String("bridge-unchecked"))
    wants.append(
        String(
            "run memveil doctor --load-check or memveil record"
            " to check the bridge"
        )
    )
    codes.append(String("verifier-rejected"))
    wants.append(
        String(
            "the kernel verifier rejected the object;"
            " see the verifier lines above"
        )
    )
    for i in range(len(codes)):
        assert_equal(remedy_for(codes[i].copy()), wants[i].copy())
    assert_equal(remedy_for(String("profile")), String(""))
    assert_equal(remedy_for(String("no-such-code")), String(""))
    var shared = 0
    for i in range(len(codes)):
        if remedy_for(codes[i].copy()) == sig:
            shared += 1
    assert_equal(shared, 2)


def test_ftrace_states() raises:
    assert_equal(
        read_ftrace_enabled(
            open_evidence_reader(gate(String("base")))
        ).value,
        String("1"),
    )
    assert_equal(
        read_ftrace_enabled(
            open_evidence_reader(gate(String("ftrace-off")))
        ).value,
        String("0"),
    )
    assert_equal(
        read_ftrace_enabled(
            open_evidence_reader(gate(String("ftrace-denied")))
        ).value,
        String("denied"),
    )
    assert_equal(
        read_ftrace_enabled(
            open_evidence_reader(gate(String("ftrace-malformed")))
        ).value,
        String("malformed"),
    )


def test_cc_flags_without_node() raises:
    var snp = detect_environment(
        open_evidence_reader(gate(String("cc-flags-nonode")))
    )
    assert_equal(snp.guest.tech, String("unknown"))
    assert_equal(
        snp.guest.conflict,
        String(
            "cpu flag sev_snp without guest node: confidential guest"
            " with attestation device absent, or flags spoofed"
        ),
    )
    var found_snp = False
    for i in range(len(snp.guest.signals)):
        if snp.guest.signals[i] == String(
            "cc-flags:without-node:sev_snp"
        ):
            found_snp = True
    assert_true(found_snp)
    var tdx = detect_environment(
        open_evidence_reader(gate(String("cc-tdx-nonode")))
    )
    assert_equal(tdx.guest.tech, String("unknown"))
    assert_equal(
        tdx.guest.conflict,
        String(
            "cpu flag tdx_guest without guest node: confidential guest"
            " with attestation device absent, or flags spoofed"
        ),
    )
    var host = detect_environment(
        open_evidence_reader(gate(String("cc-flags-host")))
    )
    assert_equal(host.guest.tech, String("ordinary"))
    assert_equal(host.guest.conflict, String(""))
    var tsm = detect_environment(
        open_evidence_reader(gate(String("cc-tsm")))
    )
    var found_tsm = False
    for i in range(len(tsm.guest.signals)):
        if tsm.guest.signals[i] == String("tsm:present"):
            found_tsm = True
    assert_true(found_tsm)


def test_attempt_loss_exact() raises:
    assert_true(not attempt_loss_exact(String("6.6.160")))
    assert_true(attempt_loss_exact(String("6.7.0")))
    assert_true(attempt_loss_exact(String("7.0.0-38-generic")))
    assert_true(not attempt_loss_exact(String("6.0.19")))
    assert_true(not attempt_loss_exact(String("bogus")))


def test_attempt_loss_evidence() raises:
    var bound = attempt_loss_evidence(String("6.6.160"))
    assert_equal(len(bound), 1)
    assert_equal(bound[0].item_type, String("attempt-loss-bound"))
    assert_equal(bound[0].source, String("kernel 6.6.160"))
    assert_equal(
        bound[0].interpretation,
        String(
            "attempt loss counts are a lower bound before 6.7:"
            " trace_call_bpf skipped programs without counting them"
        ),
    )
    var exact = attempt_loss_evidence(String("7.0.0-38-generic"))
    assert_equal(len(exact), 0)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_tracefs_root_order]()
    suite.test[test_hook_identity_shapes]()
    suite.test[test_live_hook_ambiguous]()
    suite.test[test_live_ftrace]()
    suite.test[test_live_debugfs_attempt]()
    suite.test[test_ftrace_states]()
    suite.test[test_lockdown_sources]()
    suite.test[test_lockdown_malformed]()
    suite.test[test_lockdown_forcenone_unknown]()
    suite.test[test_gate_order]()
    suite.test[test_gate_noevents_unknown_lockdown_hidden]()
    suite.test[test_gate_btf_codes]()
    suite.test[test_gate_hook_kallsyms]()
    suite.test[test_gate_denied_never_absent]()
    suite.test[test_gate_container_views]()
    suite.test[test_remedy_per_code]()
    suite.test[test_cc_flags_without_node]()
    suite.test[test_attempt_loss_exact]()
    suite.test[test_attempt_loss_evidence]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
