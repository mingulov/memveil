#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""F2-6: the extracted shipping bundle through three phases.

Extracts dist/memveil-0.1.0.tar.gz in the guest, verifies every
file against MANIFEST.json, and runs the extracted record with
all three channels through oracle-exact, outer-failure, and
block+vnet phases in one capture, rendered by the extracted
report. Oracle slices compare exactly (attempts, bytes,
allocations, releases, paired lifetimes); the fail slice proves
the internal/final boundary (failed outer, surviving copies, no
outer release); the I/O slice proves liveness under real traffic;
effective-copy totals admit paired sources only.
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import parse_oracle_log
from lifecycle_env import (BRIDGE, COPY_PROBE, LIFECYCLE_PROBE,
                           ensure_oracle_module,
                           require_lifecycle_env)
from test_record3 import (ATTEMPT_PROBE, SPEC, _events,
                          _mint_profile, check_capture_session,
                          check_lifetimes, check_oracle_slice)
from vm_boot import cleanup, run_guest, verify_exports

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TARBALL = os.path.join(REPO, "dist", "memveil-0.1.0.tar.gz")
MANIFEST = os.path.join(REPO, "dist", "memveil-0.1.0",
                        "MANIFEST.json")


def _sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _slice(events, window):
    return [e for e in events
            if window[0] <= int(e["ts_ns"]) <= window[1]]


def check_fail_slice(events, tag):
    """Frozen f-window at shipped-event level.

    Five maps (fail map plus healthy retry), five paired
    releases, eight request-only syncs, eight executed copies
    split by direction, five bounce attempts. The failed outer
    mapping itself never appears: no outer map, no outer sync,
    no outer release.
    """
    bad = []
    kinds = {}
    for event in events:
        kinds.setdefault(event["kind"], []).append(event)
    maps = kinds.get("map_result", [])
    unmaps = kinds.get("unmap", [])
    syncs = kinds.get("sync_request", [])
    copies = kinds.get("copy", [])
    attempts = kinds.get("bounce_attempt", [])
    if len(maps) != 5:
        bad.append("%s: want 5 map_result, got %d"
                   % (tag, len(maps)))
    if len(unmaps) != 5:
        bad.append("%s: want 5 unmap, got %d"
                   % (tag, len(unmaps)))
    if len(syncs) != 8:
        bad.append("%s: want 8 sync_request, got %d"
                   % (tag, len(syncs)))
    if len(copies) != 8:
        bad.append("%s: want 8 copy, got %d"
                   % (tag, len(copies)))
    if len(attempts) != 5:
        bad.append("%s: want 5 bounce_attempt, got %d"
                   % (tag, len(attempts)))
    if sorted(e["data"]["mapped_bytes"] for e in maps
              ) != ["1024", "2048", "2048", "4096", "512"]:
        bad.append("%s: map sizes %r" % (tag, maps))
    if [e["data"]["success"] for e in maps] != [True] * 5:
        bad.append("%s: map success %r" % (tag, maps))
    gens = [e["data"]["wire_generation"] for e in maps]
    if any(g in (None, "0") for g in gens):
        bad.append("%s: map gen unassigned %r" % (tag, gens))
    if len(set(gens)) != 5:
        bad.append("%s: maps share gen %r" % (tag, gens))
    bad += check_lifetimes(maps, unmaps, tag, True)
    if sorted(e["data"]["length"] for e in syncs
              ) != ["1024", "1024", "1024", "2048", "4096",
                    "4096", "512", "512"]:
        bad.append("%s: sync lengths %r" % (tag, syncs))
    for e in syncs:
        if (e["data"]["offset_known"],
                e["data"]["offset"]) != (False, None):
            bad.append("%s: sync offset %r" % (tag, e))
    todev = sorted(e["data"]["bytes"] for e in copies
                   if e["data"]["direction"]
                   == "original_to_bounce")
    tocpu = sorted(e["data"]["bytes"] for e in copies
                   if e["data"]["direction"]
                   == "bounce_to_original")
    if todev != ["1024", "2048", "2048", "4096", "512", "512"]:
        bad.append("%s: to-device copies %r" % (tag, todev))
    if tocpu != ["1024", "4096"]:
        bad.append("%s: to-cpu copies %r" % (tag, tocpu))
    if sorted(e["data"]["requested_bytes"] for e in attempts
              ) != ["1024", "2048", "2048", "4096", "512"]:
        bad.append("%s: attempt bytes %r" % (tag, attempts))
    return bad


def check_io_slice(events, tag):
    """Liveness plus pairing sanity under real block/vnet I/O."""
    bad = []
    kinds = {}
    for event in events:
        kinds.setdefault(event["kind"], []).append(event)
    maps = kinds.get("map_result", [])
    unmaps = kinds.get("unmap", [])
    syncs = kinds.get("sync_request", [])
    copies = kinds.get("copy", [])
    attempts = kinds.get("bounce_attempt", [])
    if not maps:
        bad.append("%s: no lifecycle maps under I/O" % tag)
    if not any(int(e["data"]["bytes"]) > 0 for e in copies):
        bad.append("%s: no executed-copy bytes under I/O" % tag)
    if not attempts:
        bad.append("%s: no attempts under I/O" % tag)
    bad += check_lifetimes(maps, unmaps, tag, False)
    for e in syncs:
        if (e["data"]["offset_known"],
                e["data"]["offset"]) != (False, None):
            bad.append("%s: sync offset %r" % (tag, e))
    for e in copies:
        if e["data"]["direction"] not in (
                "original_to_bounce", "bounce_to_original"):
            bad.append("%s: copy dir %r" % (tag, e))
    return bad


def _metric(report, name, scope=None):
    found = [m for m in report["metrics"] if m["name"] == name]
    if scope is not None:
        found = [m for m in found if scope in m["scope"]]
    assert len(found) == 1, (name, len(found))
    return found[0]


def _metric_all(report, name):
    return _metric(report, name, "all devices")


def check_report(report, events, bundle, tag, drained=True):
    """Extracted report consistency against the capture.

    drained=True demands the pool return to its own baseline
    (idle tail); signal-cut captures pass drained=False and
    only require the report to match the latest sample.
    """
    bad = []
    if bundle["report_exit"] != 4:
        bad.append("%s: report exit %r != 4 (partial)" % (
            tag, bundle["report_exit"]))
    kinds = {}
    for event in events:
        kinds.setdefault(event["kind"], []).append(event)
    attempts = kinds.get("bounce_attempt", [])
    maps = kinds.get("map_result", [])
    unmaps = kinds.get("unmap", [])
    syncs = kinds.get("sync_request", [])
    copies = kinds.get("copy", [])
    ok = [e for e in maps if e["data"]["success"]]
    if _metric_all(report, "bounce_attempts")["value"] != str(
            len(attempts)):
        bad.append("%s: report attempts drift" % tag)
    want_bytes = sum(int(e["data"]["requested_bytes"])
                     for e in attempts)
    if _metric_all(report, "requested_bounce_bytes")["value"] != str(
            want_bytes):
        bad.append("%s: report requested-bytes drift" % tag)
    if _metric(report, "successful_allocations")["value"] != str(
            len(ok)):
        bad.append("%s: report allocations drift" % tag)
    want_mapped = sum(int(e["data"]["mapped_bytes"]) for e in ok)
    if _metric(report, "mapped_bytes_total")["value"] != str(
            want_mapped):
        bad.append("%s: report mapped-bytes drift" % tag)
    for name in ("copy_original_to_bounce_bytes",
                 "copy_bounce_to_original_bytes"):
        metric = _metric(report, name)
        if metric["value"] != "0":
            bad.append("%s: report %s counts unpaired %r" % (
                tag, name, metric["value"]))
        if metric["coverage"] != "partial":
            bad.append("%s: report %s coverage %r" % (
                tag, name, metric["coverage"]))
    unpaired = sum(
        1 for e in maps + copies + syncs + unmaps
        if e["source"]["correlation"] == "unpaired")
    if _metric(report, "unpaired_lifecycle_events")["value"] != str(
            unpaired):
        bad.append("%s: report unpaired drift" % tag)
    if _metric(report, "sync_requests")["value"] != str(
            len(syncs)):
        bad.append("%s: report sync drift" % tag)
    born = {e["data"]["wire_generation"] for e in maps
            if e["data"]["wire_generation"] not in (None, "0")}
    paired = [e for e in unmaps
              if e["data"]["wire_generation"] in born]
    if _metric(report, "completed_lifetime_count")["value"] != str(
            len(paired)):
        bad.append("%s: report lifetime-count drift" % tag)
    samples = kinds.get("pool_sample", [])
    if not samples:
        bad.append("%s: report lacks pool samples" % tag)
    else:
        want = samples[0 if drained else -1]["data"][
            "used_bytes"]
        if _metric(report, "pool_used_bytes")["value"] != want:
            bad.append("%s: report pool %r != sample %r"
                       % (tag, _metric(
                           report, "pool_used_bytes")["value"],
                           want))
    codes = [f["code"] for f in report["findings"]]
    if "UNPAIRED_LIFECYCLE" not in codes:
        bad.append("%s: report lacks unpaired finding" % tag)
    return sorted(bad)


def test_bundle_three_phase_capture():
    require_lifecycle_env(LIFECYCLE_PROBE, COPY_PROBE,
                          ATTEMPT_PROBE, BRIDGE)
    assert os.path.isfile(TARBALL), "missing %s" % TARBALL
    assert os.path.isfile(MANIFEST), "missing %s" % MANIFEST
    ensure_oracle_module()
    _mint_profile()
    with open(SPEC) as handle:
        frozen = json.load(handle)
    assert frozen["frozen_for_module"] == "0.4.0", frozen
    with open(os.path.join(
            REPO, "tests", "vm", "fixtures",
            "witness-expectations.json")) as handle:
        witness = json.load(handle)
    assert witness["frozen_for_module"] == "0.4.0", witness
    tmp, proc = run_guest("bundle", timeout=900, network=True)
    try:
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        got = verify_exports(
            tmp, "bundle",
            ["identity.json", "record.json",
             "cap-session.json", "cap-events.ndjson",
             "o-oracle.log", "f-oracle.log",
             "workload.json", "bundle.json", "report.json"])
        ident = json.loads(got["identity.json"].read_text())
        assert ident["release"] == "7.0.0-34-generic", ident
        bundle = json.loads(got["bundle.json"].read_text())
        assert bundle["tarball_sha"] == _sha(TARBALL), bundle
        manifest = json.load(open(MANIFEST))
        assert bundle["files_verified"] == len(
            manifest["files"]), bundle
        assert bundle["manifest_sha"] == _sha(MANIFEST), bundle
        for key, rel in (("bin_sha", "bin/memveil"),
                         ("attempt_sha",
                          "bpf/swiotlb_attempt.bpf.o"),
                         ("lc_sha", "bpf/swiotlb_lifecycle.bpf.o"),
                         ("cp_sha", "bpf/swiotlb_copy.bpf.o"),
                         ("bridge_sha", "lib/libbpf_mojo.so.1")):
            assert bundle[key] == manifest["files"][rel], key
        workload = json.loads(got["workload.json"].read_text())
        assert workload["ping_tx"] == 200, workload
        assert workload["ping_rx"] == 200, workload
        assert workload["disk_bytes"] == 2 * 8 * 65536, \
            workload
        assert workload["end_ns"] < workload["detach_ns"], \
            workload
        record = json.loads(got["record.json"].read_text())
        session = json.loads(
            got["cap-session.json"].read_text())
        events = _events(got["cap-events.ndjson"])
        report = json.loads(got["report.json"].read_text())
        o_ops, _, o_complete = parse_oracle_log(
            str(got["o-oracle.log"]))
        assert o_complete, "oracle phase incomplete"
        assert len(o_ops) == 2, o_ops
        assert sorted(e["requested"] for e in o_ops.values()
                      ) == [1024, 4096], o_ops
        f_ops, f_rel, f_complete = parse_oracle_log(
            str(got["f-oracle.log"]))
        assert f_complete, "fail phase incomplete"
        assert len(f_ops) == 4, f_ops
        assert f_ops[2].get("success") is False, f_ops
        assert not f_ops[2].get("syncs"), f_ops
        assert f_ops[2].get("inner", {}).get(
            "health") == "healthy", f_ops
        assert 2 not in f_rel, "fail op released a mapping"
        phases = bundle["phases"]
        o_slice = _slice(events, phases["oracle"])
        f_slice = _slice(events, phases["fail"])
        io_slice = _slice(events, phases["io"])
        detail_kinds = ("bounce_attempt", "map_result", "unmap",
                        "sync_request", "copy")
        detail = [e for e in events
                  if e["kind"] in detail_kinds]
        in_any = lambda t: any(w[0] <= t <= w[1] for w in (
            phases["oracle"], phases["fail"], phases["io"]))
        ambient = [e for e in detail
                   if not in_any(int(e["ts_ns"]))]
        bad = check_capture_session(
            events, session, record, "b",
            130_000_000_000, 180_000_000_000,
            "record3-ephemeral")
        bad += check_oracle_slice(o_slice, "b-o")
        bad += check_fail_slice(f_slice, "b-f")
        bad += check_io_slice(io_slice, "b-io")
        bad += check_report(report, events, bundle, "b-r")
        all_maps = [e for e in events
                    if e["kind"] == "map_result"]
        bad += check_lifetimes(
            all_maps,
            [e for e in ambient if e["kind"] == "unmap"],
            "b-amb", False)
        for e in ambient:
            if e["kind"] == "sync_request" and (
                    e["data"]["offset_known"],
                    e["data"]["offset"]) != (False, None):
                bad.append("b-amb: sync offset %r" % (e,))
        assert not bad, "\n".join(bad)
        o_eff = sum(int(e["data"]["bytes"]) for e in o_slice
                    if e["kind"] == "copy")
        assert o_eff == frozen["n"]["witnessed_total"], o_eff
        f_todev = sum(int(e["data"]["bytes"]) for e in f_slice
                      if e["kind"] == "copy" and e["data"][
                          "direction"] == "original_to_bounce")
        f_tocpu = sum(int(e["data"]["bytes"]) for e in f_slice
                      if e["kind"] == "copy" and e["data"][
                          "direction"] == "bounce_to_original")
        assert f_todev == witness["f"]["witnessed"][
            "original_to_bounce"] + witness["f"][
            "unwitnessed_gap"], (f_todev, witness["f"])
        assert f_tocpu == witness["f"]["witnessed"][
            "bounce_to_original"], (f_tocpu, witness["f"])
        print("b: oracle %d + fail %d + io %d + ambient %d "
              "events, report exit 4 ok"
              % (len(o_slice), len(f_slice), len(io_slice),
                 len(ambient)))
    except Exception:
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp)
