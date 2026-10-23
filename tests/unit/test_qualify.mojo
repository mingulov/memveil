# SPDX-License-Identifier: GPL-3.0-or-later

"""Qualify CLI parsing, smoke planning, and receipt publication."""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from scripted import (
    ScriptClock,
    ScriptKernel,
    ScriptSignal,
    ScriptWriter,
    _stop_mkdtemp,
    _stop_timeout,
    _stop_zeros,
)
from memveil.capture.collector import Collector, CollectorConfig
from memveil.cli.qualify import (
    QualifyOptions,
    _smoke_bridge_hash,
    _smoke_object_hash,
    parse_qualify_args,
    plan_qualification,
    publish_receipt,
    qualify_usage,
    smoke_shutdown_ok,
)
from memveil.capture.run import decide_record
from memveil.platform.artifact_files import (
    open_bridge_snapshot,
    open_object_snapshot,
)
from memveil.platform.evidence import KernelInfo
from memveil.platform.hash import sha256_hex
from memveil.platform.profiles import Profile, load_profiles
from memveil.platform.outcome import OpOut
from memveil.platform.reader import bytes_to_text, read_host_file

comptime _HOST = "tests/fixtures/qualify/host"
comptime _PDIR = "tests/fixtures/qualify/profiles"
comptime _SCAN_OK = "tests/fixtures/scan/ok"
comptime _SCAN_PROFILES = "tests/fixtures/scan/profiles"
comptime _ELF_OK = "tests/fixtures/elf/ok.o"


def contains(hay: String, needle: String) -> Bool:
    """True when needle occurs in hay at least once."""
    return len(hay.split(String(needle))) > 1


def _args() -> List[String]:
    var out = List[String]()
    out.append(String("--output"))
    out.append(String("out"))
    out.append(String("--object"))
    out.append(String("obj.o"))
    return out^


def _opts() -> QualifyOptions:
    var opts = QualifyOptions()
    opts.output = String("out")
    opts.object = String("obj.o")
    return opts^


def test_qualify_args_defaults() raises:
    var opts = parse_qualify_args(_args())
    assert_equal(opts.output, String("out"))
    assert_equal(opts.object, String("obj.o"))
    assert_equal(opts.bridge, String(""))
    assert_true(not opts.has_bridge)
    assert_equal(opts.profile, String(""))
    assert_true(not opts.has_profile)
    assert_equal(opts.profiles_dir, String(""))
    assert_true(not opts.has_profiles_dir)
    assert_equal(opts.lc_object, String(""))
    assert_equal(opts.cp_object, String(""))
    assert_equal(opts.capabilities, String(""))


def test_qualify_args_full() raises:
    var args = _args()
    args.append(String("--bridge"))
    args.append(String("br.so"))
    args.append(String("--profile"))
    args.append(String("p1"))
    args.append(String("--profiles-dir"))
    args.append(String("qd"))
    args.append(String("--lc-object"))
    args.append(String("lc.o"))
    args.append(String("--cp-object"))
    args.append(String("cp.o"))
    args.append(String("--capability"))
    args.append(String("attempt-trace,mapping-lifecycle"))
    var opts = parse_qualify_args(args^)
    assert_equal(opts.bridge, String("br.so"))
    assert_true(opts.has_bridge)
    assert_equal(opts.profile, String("p1"))
    assert_true(opts.has_profile)
    assert_equal(opts.profiles_dir, String("qd"))
    assert_true(opts.has_profiles_dir)
    assert_equal(opts.lc_object, String("lc.o"))
    assert_equal(opts.cp_object, String("cp.o"))
    assert_equal(
        opts.capabilities, String("attempt-trace,mapping-lifecycle")
    )


def test_qualify_args_output_needs_value() raises:
    var raised = False
    try:
        var args = List[String]()
        args.append(String("--output"))
        _ = parse_qualify_args(args^)
    except e:
        raised = True
        assert_equal(e.message, String("--output needs a value"))
    assert_true(raised)


def test_qualify_args_object_needs_value() raises:
    var raised = False
    try:
        var args = List[String]()
        args.append(String("--object"))
        _ = parse_qualify_args(args^)
    except e:
        raised = True
        assert_equal(e.message, String("--object needs a value"))
    assert_true(raised)


def test_qualify_args_unknown_option() raises:
    var raised = False
    try:
        var args = _args()
        args.append(String("--bogus"))
        _ = parse_qualify_args(args^)
    except e:
        raised = True
        assert_true(
            contains(e.message, String("unknown option: --bogus"))
        )
    assert_true(raised)


def test_qualify_usage() raises:
    var text = qualify_usage()
    assert_true(contains(text, String("qualify --output")))
    assert_true(contains(text, String("[--object PATH]")))
    assert_true(contains(text, String("discover")))
    assert_true(
        contains(text, String("/var/lib/memveil/receipts"))
    )


def test_plan_ok() raises:
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), _opts()
    )
    assert_true(plan.ok)
    assert_equal(plan.refusal, String(""))
    assert_equal(plan.doc.profile_id, String("qual-ref"))
    assert_equal(plan.kernel.release, String("7.0.0-test"))
    assert_equal(len(plan.caps), 1)
    assert_equal(plan.caps[0], String("attempt-trace"))
    assert_true(plan.bindings.config != String(""))
    assert_equal(len(plan.signatures), 1)
    assert_true(plan.signatures[0].ok)
    assert_equal(
        plan.signatures[0].live,
        String("int (struct device *dev, size_t size)"),
    )


def test_plan_caps() raises:
    var opts = _opts()
    opts.capabilities = String("attempt-trace,mapping-lifecycle")
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), opts^
    )
    assert_true(plan.ok)
    assert_equal(len(plan.caps), 2)
    assert_equal(plan.caps[1], String("mapping-lifecycle"))


def test_plan_live_reference() raises:
    var opts = _opts()
    opts.capabilities = String("attempt-trace,mapping-lifecycle")
    var plan = plan_qualification(
        String("tests/fixtures/qualify/host-live38"),
        String("tests/fixtures/qualify/profiles-live"),
        opts^,
    )
    assert_true(plan.ok)
    assert_equal(plan.doc.profile_id, String("scan-live-ref"))
    assert_equal(len(plan.caps), 2)
    assert_equal(plan.caps[1], String("mapping-lifecycle"))


def test_plan_bad_caps() raises:
    var opts = _opts()
    opts.capabilities = String("bogus")
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), opts^
    )
    assert_true(not plan.ok)
    assert_equal(plan.refusal, String("unknown capability: bogus"))


def test_qualify_args_missing_output() raises:
    var raised = False
    try:
        var args = List[String]()
        args.append(String("--object"))
        args.append(String("obj.o"))
        _ = parse_qualify_args(args^)
    except e:
        raised = True
        assert_equal(e.message, String("missing --output"))
    assert_true(raised)


def test_qualify_args_object_optional() raises:
    # --object is discovered when absent, so parsing
    # without it succeeds and leaves the path empty.
    var args = List[String]()
    args.append(String("--output"))
    args.append(String("out"))
    var opts = parse_qualify_args(args^)
    assert_equal(opts.output, String("out"))
    assert_equal(opts.object, String(""))


def test_plan_convert_refuses() raises:
    var opts = _opts()
    opts.capabilities = String("attempt-trace,conversion-observe")
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), opts^
    )
    assert_true(not plan.ok)
    assert_equal(
        plan.refusal,
        String("capability conversion-observe has no record channel"),
    )


def test_plan_doc_source_automatic() raises:
    # Automatic selection records the planned manifest path
    # so the smoke cannot be redirected by a same-named
    # working-directory file through record's file-first
    # resolver.
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), _opts()
    )
    assert_true(plan.ok)
    assert_equal(
        plan.doc_source,
        String(_PDIR) + String("/qual-ref.json"),
    )


def test_plan_doc_source_explicit_id() raises:
    var opts = _opts()
    opts.profile = String("qual-ref")
    opts.has_profile = True
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), opts^
    )
    assert_true(plan.ok)
    assert_equal(
        plan.doc_source,
        String(_PDIR) + String("/qual-ref.json"),
    )


def test_plan_doc_source_explicit_file() raises:
    var opts = _opts()
    opts.profile = String(_PDIR) + String("/qual-ref.json")
    opts.has_profile = True
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), opts^
    )
    assert_true(plan.ok)
    assert_equal(
        plan.doc_source,
        String(_PDIR) + String("/qual-ref.json"),
    )


def test_plan_no_hook() raises:
    var opts = _opts()
    opts.profile = String(_PDIR) + String("/qual-nohook.json")
    opts.has_profile = True
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), opts^
    )
    assert_true(not plan.ok)
    assert_equal(plan.refusal, String("no tracepoint hook"))


def test_plan_unknown_profile() raises:
    var opts = _opts()
    opts.profile = String("nonexistent")
    opts.has_profile = True
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), opts^
    )
    assert_true(not plan.ok)
    assert_equal(
        plan.refusal, String("unknown --profile: nonexistent")
    )


def test_plan_unbound_note() raises:
    # A prose note is outside the narrow grammar, so the
    # doc is unbound and plans from live interfaces like a
    # noteless reference instead of refusing on bindings.
    var opts = _opts()
    opts.profile = String(_PDIR) + String("/qual-unbound.json")
    opts.has_profile = True
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), opts^
    )
    assert_true(plan.ok)
    assert_equal(plan.doc.profile_id, String("qual-unbound"))
    assert_equal(len(plan.caps), 1)
    assert_equal(plan.caps[0], String("attempt-trace"))


def test_plan_bad_signature() raises:
    var opts = _opts()
    opts.profile = String(_PDIR) + String("/qual-badsig.json")
    opts.has_profile = True
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), opts^
    )
    assert_true(not plan.ok)
    assert_equal(
        plan.refusal,
        String("fentry:test_fn: signature mismatch"),
    )


def test_plan_name_only_signature_accepted() raises:
    # Parameter names never compare: the frozen size_t
    # length matches the live size_t size.
    var opts = _opts()
    opts.profile = String(_PDIR) + String("/qual-namesig.json")
    opts.has_profile = True
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), opts^
    )
    assert_true(plan.ok)


def test_plan_missing_function() raises:
    var opts = _opts()
    opts.profile = String(_PDIR) + String("/qual-nofunc.json")
    opts.has_profile = True
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), opts^
    )
    assert_true(not plan.ok)
    assert_true(
        contains(plan.refusal, String("function nope not found"))
    )


def test_plan_binding_mismatch() raises:
    var plan = plan_qualification(
        String(_SCAN_OK), String(_PDIR), _opts()
    )
    assert_true(not plan.ok)
    assert_equal(
        plan.refusal, String("binding failed: btf mismatch")
    )


def test_plan_no_cover() raises:
    var plan = plan_qualification(
        String("tests/fixtures/qualify/host-arm"),
        String(_PDIR),
        _opts(),
    )
    assert_true(not plan.ok)
    assert_equal(
        plan.refusal, String("no profile covers this kernel")
    )


def test_plan_below_floor_refuses() raises:
    # The floor gate precedes profile loading, so CLI
    # cases past it are host-gated; the refusal itself
    # is pinned here against a fixture root.
    var plan = plan_qualification(
        String("tests/fixtures/qualify/host-old"),
        String(_PDIR),
        _opts(),
    )
    assert_true(not plan.ok)
    assert_equal(
        plan.refusal, String("kernel 5.15.0-test below floor 6.0")
    )


def test_plan_lc_below_611_refuses() raises:
    var opts = _opts()
    opts.capabilities = String("attempt-trace,mapping-lifecycle")
    var plan = plan_qualification(
        String("tests/fixtures/qualify/host-68"),
        String(_PDIR),
        opts^,
    )
    assert_true(not plan.ok)
    assert_equal(
        plan.refusal,
        String(
            "capability mapping-lifecycle needs kernel 6.11+"
            " (this kernel: 6.8.0-test)"
        ),
    )


def test_plan_source_survives_cwd_shadow() raises:
    # The shadow is unlinked even when the body fails, so a
    # failing run cannot poison later file-first tests with
    # ./qual-ref debris.
    _unlink_local(String("./qual-ref"))
    var failure = String("")
    try:
        _shadow_body()
    except e:
        failure = String(e)
    _unlink_local(String("./qual-ref"))
    assert_equal(failure, String(""))


def _shadow_body() raises:
    # Regression: the smoke resolves plan.doc_source (never a
    # bare id), so a working-directory file named like the
    # profile id cannot substitute the planned document
    # through record's file-first resolver. The negative
    # control shows the shadow does bite a bare id.
    _unlink_local(String("./qual-ref"))
    var opts = _opts()
    opts.profile = String("qual-ref")
    opts.has_profile = True
    var plan = plan_qualification(
        String(_HOST), String(_PDIR), opts^
    )
    assert_true(plan.ok)
    assert_equal(plan.doc.profile_id, String("qual-ref"))
    # The shadow appears after planning, modeling a
    # working-directory file arriving between plan and
    # smoke.
    publish_receipt(String("./qual-ref"), String("shadow-bytes\n"))
    var empty = List[Profile]()
    var shadowed = decide_record(
        String(_HOST),
        plan.kernel,
        empty^,
        String("qual-ref"),
        True,
        String("nonexistent.o"),
        String(""),
        String(""),
        String(""),
        String(""),
        String(""),
    )
    assert_true(not shadowed.ok)
    assert_true(
        contains(shadowed.refusal, String("cannot parse --profile"))
    )
    var surfaces = List[Profile]()
    var sourced = decide_record(
        String(_HOST),
        plan.kernel,
        surfaces^,
        plan.doc_source,
        True,
        String("nonexistent.o"),
        String(""),
        String(""),
        String(""),
        String(""),
        String(""),
    )
    assert_true(not sourced.ok)
    assert_equal(sourced.refusal, String("object unreadable"))
    _unlink_local(String("./qual-ref"))


def test_plan_bad_root() raises:
    var plan = plan_qualification(
        String("tests/fixtures/qualify/nonexistent"), String(_PDIR), _opts()
    )
    assert_true(not plan.ok)
    assert_true(contains(plan.refusal, String("cannot open evidence")))


def test_plan_bad_pdir() raises:
    var plan = plan_qualification(
        String(_HOST), String("tests/fixtures/qualify/nonexistent"), _opts()
    )
    assert_true(not plan.ok)
    assert_true(contains(plan.refusal, String("cannot load profiles")))


def test_publish_roundtrip() raises:
    var path = String("build/qpub/r.json")
    publish_receipt(path, String('{"grade":"local-auto"}\n'))
    var back = read_host_file(path, String("receipt"), 1048576)
    assert_equal(
        bytes_to_text(back^), String('{"grade":"local-auto"}\n')
    )


def test_publish_overwrite() raises:
    var path = String("build/qpub/w.json")
    publish_receipt(path, String("first\n"))
    publish_receipt(path, String("second\n"))
    var back = read_host_file(path, String("receipt"), 1048576)
    assert_equal(bytes_to_text(back^), String("second\n"))


def _smoke_config(output: String) -> CollectorConfig:
    var cfg = CollectorConfig()
    cfg.duration_s = UInt64(0)
    cfg.max_events_bytes = 134217728
    cfg.output = output
    cfg.profile_id = String("qualify-smoke-probe")
    cfg.pid = 4242
    return cfg^


def test_smoke_shutdown_closed() raises:
    var tmp = _stop_mkdtemp()
    var out = tmp + String("/cap")
    var kernel = ScriptKernel()
    kernel.add_poll(_stop_timeout(), 300)
    _stop_zeros(kernel, 8, 4)
    var clock = ScriptClock()
    clock.add(UInt64(1000000000))
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    var collector = Collector(_smoke_config(out))
    var result = collector.run(kernel, clock, signal, writer)
    assert_equal(result.exit_code, 4)
    assert_true(smoke_shutdown_ok(out))


def test_smoke_shutdown_detach_failed() raises:
    var tmp = _stop_mkdtemp()
    var out = tmp + String("/cap")
    var kernel = ScriptKernel()
    kernel.detach_out = OpOut(False, String("boom"))
    kernel.add_poll(_stop_timeout(), 300)
    _stop_zeros(kernel, 8, 4)
    var clock = ScriptClock()
    clock.add(UInt64(1000000000))
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    var collector = Collector(_smoke_config(out))
    var result = collector.run(kernel, clock, signal, writer)
    assert_equal(result.exit_code, 4)
    assert_equal(result.end_reason, String("duration"))
    assert_true(not smoke_shutdown_ok(out))


def test_smoke_shutdown_missing() raises:
    assert_true(
        not smoke_shutdown_ok(
            String("tests/fixtures/qualify/nonexistent-xyz")
        )
    )


def test_publish_bad_dir() raises:
    var raised = False
    try:
        publish_receipt(
            String("build/qualify-noexist-xyz/receipts/r.json"),
            String("x\n"),
        )
    except:
        raised = True
    assert_true(raised)


def _cstr_local(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


def _symlink(target: String, link: String):
    var t = _cstr_local(target)
    var l = _cstr_local(link)
    _ = external_call["symlink", Int32](
        Span(t).unsafe_ptr(), Span(l).unsafe_ptr()
    )


def _unlink_local(path: String):
    var cstr = _cstr_local(path)
    _ = external_call["unlinkat", Int32](
        Int32(-100), Span(cstr).unsafe_ptr(), Int32(0)
    )


def test_publish_parent_symlink_refuses() raises:
    _symlink(String("."), String("build/qlink"))
    var raised = False
    try:
        publish_receipt(
            String("build/qlink/refused.json"), String("x\n")
        )
    except:
        raised = True
    assert_true(raised)
    var absent = False
    try:
        _ = read_host_file(
            String("build/refused.json"), String("probe"), 16
        )
    except:
        absent = True
    assert_true(absent)


def test_publish_tmp_symlink_never_truncates() raises:
    publish_receipt(String("build/qx/victim"), String("precious\n"))
    var pid = Int(external_call["getpid", Int32]())
    var tmp = (
        String("build/qx/r.json.tmp.") + String(pid)
    )
    _unlink_local(tmp)
    _symlink(String("victim"), tmp)
    publish_receipt(String("build/qx/r.json"), String("new\n"))
    var back = read_host_file(
        String("build/qx/victim"), String("victim"), 1048576
    )
    assert_equal(bytes_to_text(back^), String("precious\n"))
    var fin = read_host_file(
        String("build/qx/r.json"), String("receipt"), 1048576
    )
    assert_equal(bytes_to_text(fin^), String("new\n"))


def test_publish_final_symlink_replaced() raises:
    publish_receipt(String("build/qf/victim"), String("precious\n"))
    _unlink_local(String("build/qf/r.json"))
    _symlink(String("victim"), String("build/qf/r.json"))
    publish_receipt(String("build/qf/r.json"), String("new\n"))
    var back = read_host_file(
        String("build/qf/victim"), String("victim"), 1048576
    )
    assert_equal(bytes_to_text(back^), String("precious\n"))
    var fin = read_host_file(
        String("build/qf/r.json"), String("receipt"), 1048576
    )
    assert_equal(bytes_to_text(fin^), String("new\n"))


def test_publish_trailing_slash_refuses() raises:
    var raised = False
    try:
        publish_receipt(String("build/qx/"), String("x\n"))
    except:
        raised = True
    assert_true(raised)


def _wait_child(pid: Int32) raises -> Int:
    """Reap one forked test child; return its exit code."""
    var status = List[Int32]()
    status.append(Int32(0))
    var got = external_call["waitpid", Int32](
        pid, Span(status).unsafe_ptr(), Int32(0)
    )
    if Int(got) < 0:
        raise Error("waitpid failed")
    var st = Int(status[0])
    if (st & Int(0x7F)) != 0:
        raise Error("test child did not exit")
    return (st >> 8) & Int(0xFF)


def _child_exit(code: Int):
    external_call["_exit", NoneType](Int32(code))


def _assert_tmp_absent(cand: String) raises:
    # Exclusive-create probe: success means no
    # publisher left this tmp name behind (the probe
    # file is removed again); any failure fails
    # the test with the offending name.
    var c = _cstr_local(cand)
    var fd = external_call["open", Int32](
        Span(c).unsafe_ptr(), Int32(0o301), UInt32(0o644)
    )
    if Int(fd) < 0:
        raise Error(String("stale tmp left: ") + cand)
    _ = external_call["close", Int32](fd)
    _unlink_local(cand)


def _assert_no_tmp_left(
    dir: String, final: String, pids: List[Int32]
) raises:
    for i in range(len(pids)):
        var cand = (
            dir
            + String("/")
            + final
            + String(".tmp.")
            + String(Int(pids[i]))
        )
        _assert_tmp_absent(cand)


def test_publish_concurrent_last_writer_wins() raises:
    # Eight processes publish distinct bodies at one
    # path: every publish succeeds and the final file
    # byte-equals exactly one whole body (atomic
    # last-writer-wins), with no tmp names left.
    var dir = _stop_mkdtemp()
    var path = dir + String("/r.json")
    var want = List[String]()
    for i in range(8):
        want.append(
            String("publisher-") + String(i) + String("\n")
        )
    var pids = List[Int32]()
    for i in range(8):
        var pid = external_call["fork", Int32]()
        if Int(pid) < 0:
            raise Error("fork failed")
        if pid == Int32(0):
            try:
                publish_receipt(path, want[i])
            except:
                _child_exit(1)
            _child_exit(0)
        pids.append(pid)
    for i in range(len(pids)):
        assert_equal(_wait_child(pids[i]), 0)
    var back = read_host_file(path, String("receipt"), 1048576)
    var text = bytes_to_text(back^)
    var found = False
    for i in range(8):
        if text == want[i]:
            found = True
    assert_true(found)
    pids.append(Int32(Int(external_call["getpid", Int32]())))
    _assert_no_tmp_left(dir, String("r.json"), pids^)


def test_publish_reader_sees_whole_files() raises:
    # One publisher alternates two large bodies while
    # the parent reads the final path: every read sees
    # A whole, B whole, or nothing (absent before the
    # first rename) -- never a torn mix.
    var dir = _stop_mkdtemp()
    var path = dir + String("/live.json")
    var chunk_a = String("")
    var chunk_b = String("")
    for _ in range(1000):
        chunk_a += String("A")
        chunk_b += String("B")
    var body_a = String("")
    var body_b = String("")
    for _ in range(64):
        body_a += chunk_a
        body_b += chunk_b
    var pid = external_call["fork", Int32]()
    if Int(pid) < 0:
        raise Error("fork failed")
    if pid == Int32(0):
        var code = 0
        for i in range(1000):
            try:
                if i % 2 == 0:
                    publish_receipt(path, body_a)
                else:
                    publish_receipt(path, body_b)
            except:
                code = 1
                break
        _child_exit(code)
    # Gate the burst on the first publication:
    # without this the reads below can all finish
    # before the first rename, leaving every
    # whole-file assertion unfired.
    var ready = False
    for _ in range(100000):
        var probe_ok = False
        try:
            var probe = read_host_file(
                path, String("receipt"), 1048576
            )
            _ = bytes_to_text(probe^)
            probe_ok = True
        except:
            probe_ok = False
        if probe_ok:
            ready = True
            break
    assert_true(ready)
    var observed = 0
    for _ in range(1000):
        var seen = String("")
        var have = False
        try:
            var back = read_host_file(
                path, String("receipt"), 1048576
            )
            seen = bytes_to_text(back^)
            have = True
        except:
            have = False
        if have:
            assert_true(seen == body_a or seen == body_b)
            observed += 1
    assert_equal(_wait_child(pid), 0)
    # Non-vacuity: at least one read must observe a
    # published body, else the whole-file assertions
    # above never fired and the test proves nothing.
    assert_true(observed > 0)
    var pids = List[Int32]()
    pids.append(pid)
    pids.append(Int32(Int(external_call["getpid", Int32]())))
    _assert_no_tmp_left(dir, String("live.json"), pids^)


def test_publish_stale_tmp_recycled() raises:
    # A stale tmp file squatting on this process's own
    # tmp name is unlinked once and the publish still
    # succeeds, leaving no tmp names behind.
    var dir = _stop_mkdtemp()
    var path = dir + String("/r.json")
    var self_pid = Int(external_call["getpid", Int32]())
    var stale = path + String(".tmp.") + String(self_pid)
    _q_write(stale, String("stale-junk\n"))
    publish_receipt(path, String("fresh\n"))
    var back = read_host_file(path, String("receipt"), 1048576)
    assert_equal(bytes_to_text(back^), String("fresh\n"))
    var pids = List[Int32]()
    pids.append(Int32(self_pid))
    _assert_no_tmp_left(dir, String("r.json"), pids^)


def _q_cstr(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


def _q_write(path: String, text: String) raises:
    var cpath = _q_cstr(path)
    var mode = _q_cstr("w")
    var fp = external_call["fopen", UInt64](
        Span(cpath).unsafe_ptr(), Span(mode).unsafe_ptr()
    )
    if fp == UInt64(0):
        raise Error("fopen failed for " + path)
    var raw = text.as_bytes()
    var n = external_call["fwrite", Int64](
        Span(raw).unsafe_ptr(), Int64(1), Int64(len(raw)), fp
    )
    _ = external_call["fclose", Int32](fp)
    if Int(n) != len(raw):
        raise Error("short write for " + path)


def test_smoke_bridge_binds_exercised_bytes() raises:
    # Snapshot the bridge, then swap the pathname: the
    # receipt input must name the exercised bytes, never
    # the swapped pathname bytes.
    var exercised = String("EXERCISED-BRIDGE-BYTES\n")
    var base = _stop_mkdtemp()
    var path = base + String("/bridge.so")
    var repl = base + String("/replacement.so")
    _q_write(path, exercised)
    _q_write(repl, String("SWAPPED-BRIDGE-BYTES\n"))
    var snap = open_bridge_snapshot(path)
    var cr = _q_cstr(repl)
    var cp = _q_cstr(path)
    var r = external_call["rename", Int32](
        Span(cr).unsafe_ptr(), Span(cp).unsafe_ptr()
    )
    assert_equal(Int(r), 0)
    assert_equal(
        _smoke_bridge_hash(snap),
        String("sha256:") + sha256_hex(exercised.as_bytes()),
    )


def test_smoke_bridge_unbound_refuses() raises:
    # No bound bridge bytes, no receipt: minting must
    # fail closed instead of hashing a pathname.
    var snap = open_bridge_snapshot(
        String("/nonexistent/memveil-bridge.so.1")
    )
    var raised = False
    try:
        _ = _smoke_bridge_hash(snap)
    except:
        raised = True
    assert_true(raised)


def _q_write_bytes(path: String, var data: List[UInt8]) raises:
    var cpath = _q_cstr(path)
    var mode = _q_cstr("wb")
    var fp = external_call["fopen", UInt64](
        Span(cpath).unsafe_ptr(), Span(mode).unsafe_ptr()
    )
    if fp == UInt64(0):
        raise Error("fopen failed for " + path)
    var n = external_call["fwrite", Int64](
        Span(data).unsafe_ptr(), Int64(1), Int64(len(data)), fp
    )
    _ = external_call["fclose", Int32](fp)
    if Int(n) != len(data):
        raise Error("short write for " + path)


def _q_scan_kernel() -> KernelInfo:
    return KernelInfo(
        String("7.0.0-test"), String("x86_64"), True, String("")
    )


def test_smoke_object_binds_exercised_bytes() raises:
    # Swap the object pathname between the smoke's read
    # and receipt minting: the minted identity must name
    # the exercised bytes, never the swapped bytes.
    var exercised = read_host_file(
        String(_ELF_OK), String("object"), 1048576
    )
    var base = _stop_mkdtemp()
    var path = base + String("/obj.o")
    var evil = base + String("/evil.o")
    _q_write_bytes(path, exercised.copy())
    _q_write(evil, String("SWAPPED-OBJECT-BYTES\n"))
    var snap = open_object_snapshot(path)
    var profiles = load_profiles(String(_SCAN_PROFILES))
    var smoked = decide_record(
        String(_SCAN_OK),
        _q_scan_kernel(),
        profiles^,
        String(""),
        False,
        snap.load_path,
        String(""),
        String(""),
        String(""),
        String(""),
        String(""),
    )
    assert_true(smoked.ok)
    assert_equal(smoked.object_sha, snap.sha)
    var ce = _q_cstr(evil)
    var cp = _q_cstr(path)
    var r = external_call["rename", Int32](
        Span(ce).unsafe_ptr(), Span(cp).unsafe_ptr()
    )
    assert_equal(Int(r), 0)
    var swapped = read_host_file(path, String("object"), 1048576)
    assert_equal(
        String(from_utf8=Span(swapped)),
        String("SWAPPED-OBJECT-BYTES\n"),
    )
    var minted = _smoke_object_hash(snap)
    assert_equal(minted, String("sha256:") + smoked.object_sha)
    assert_equal(
        minted, String("sha256:") + sha256_hex(Span(exercised))
    )


def test_smoke_object_unbound_refuses() raises:
    # No bound object bytes, no receipt: minting must
    # fail closed instead of hashing a pathname.
    var snap = open_object_snapshot(
        String("/nonexistent/memveil-obj.o")
    )
    var raised = False
    try:
        _ = _smoke_object_hash(snap)
    except:
        raised = True
    assert_true(raised)


def test_smoke_pins_survive_through_inner_opens() raises:
    # Qualify outer pins must stay alive through the
    # smoke's inner opens/reads on every return path:
    # the smoke re-snapshots the bridge alias and reads
    # the object aliases, so dangling outer fds would
    # degrade the inner snapshot and refuse admission.
    # The keep-alive touches below mirror
    # run_qualify_with's identical fix.
    var exercised = read_host_file(
        String(_ELF_OK), String("object"), 1048576
    )
    var base = _stop_mkdtemp()
    var opath = base + String("/obj.o")
    var bpath = base + String("/bridge.so")
    _q_write_bytes(opath, exercised.copy())
    _q_write(bpath, String("OUTER-BRIDGE-BYTES\n"))
    var snap = open_bridge_snapshot(bpath)
    var obj_snap = open_object_snapshot(opath)
    assert_true(snap.sha != String(""))
    assert_true(obj_snap.sha != String(""))
    var want_bridge = snap.sha.copy()
    var want_object = obj_snap.sha.copy()
    var bridge_alias = snap.load_path.copy()
    var object_alias = obj_snap.load_path.copy()
    # Smoke's inner opens, through production calls.
    var inner = open_bridge_snapshot(bridge_alias)
    var profiles = load_profiles(String(_SCAN_PROFILES))
    var smoked = decide_record(
        String(_SCAN_OK),
        _q_scan_kernel(),
        profiles^,
        String(""),
        False,
        object_alias,
        String(""),
        String(""),
        String(""),
        String(""),
        String(""),
    )
    # Keep-alive: outer pins through inner opens above;
    # the asserts below use only the pre-copied wants,
    # so these touches are the sole post-open uses.
    _ = snap.fd
    _ = obj_snap.fd
    assert_true(inner.sha != String(""))
    assert_equal(inner.sha, want_bridge)
    assert_true(smoked.ok)
    assert_equal(smoked.object_sha, want_object)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_qualify_args_defaults]()
    suite.test[test_qualify_args_full]()
    suite.test[test_qualify_args_output_needs_value]()
    suite.test[test_qualify_args_object_needs_value]()
    suite.test[test_qualify_args_unknown_option]()
    suite.test[test_qualify_args_missing_output]()
    suite.test[test_qualify_args_object_optional]()
    suite.test[test_qualify_usage]()
    suite.test[test_plan_ok]()
    suite.test[test_plan_caps]()
    suite.test[test_plan_live_reference]()
    suite.test[test_plan_bad_caps]()
    suite.test[test_plan_source_survives_cwd_shadow]()
    suite.test[test_plan_convert_refuses]()
    suite.test[test_plan_doc_source_automatic]()
    suite.test[test_plan_doc_source_explicit_id]()
    suite.test[test_plan_doc_source_explicit_file]()
    suite.test[test_plan_no_hook]()
    suite.test[test_plan_unknown_profile]()
    suite.test[test_plan_unbound_note]()
    suite.test[test_plan_bad_signature]()
    suite.test[test_plan_name_only_signature_accepted]()
    suite.test[test_plan_missing_function]()
    suite.test[test_plan_binding_mismatch]()
    suite.test[test_plan_no_cover]()
    suite.test[test_plan_bad_root]()
    suite.test[test_plan_bad_pdir]()
    suite.test[test_publish_roundtrip]()
    suite.test[test_publish_overwrite]()
    suite.test[test_smoke_shutdown_closed]()
    suite.test[test_smoke_shutdown_detach_failed]()
    suite.test[test_smoke_shutdown_missing]()
    suite.test[test_publish_bad_dir]()
    suite.test[test_publish_parent_symlink_refuses]()
    suite.test[test_publish_tmp_symlink_never_truncates]()
    suite.test[test_publish_final_symlink_replaced]()
    suite.test[test_publish_trailing_slash_refuses]()
    suite.test[test_publish_concurrent_last_writer_wins]()
    suite.test[test_publish_reader_sees_whole_files]()
    suite.test[test_publish_stale_tmp_recycled]()
    suite.test[test_plan_below_floor_refuses]()
    suite.test[test_plan_lc_below_611_refuses]()
    suite.test[test_smoke_bridge_binds_exercised_bytes]()
    suite.test[test_smoke_bridge_unbound_refuses]()
    suite.test[test_smoke_object_binds_exercised_bytes]()
    suite.test[test_smoke_object_unbound_refuses]()
    suite.test[test_smoke_pins_survive_through_inner_opens]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
