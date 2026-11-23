#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""F2-6: the extracted shipping bundle through three phases.

Extracts dist/memveil-0.2.0.tar.gz in the guest, verifies every
file against MANIFEST.json, and runs the extracted record with
all three channels through oracle-exact, outer-failure, and
block+vnet phases in one capture, rendered by the extracted
report. Oracle slices compare exactly (attempts, bytes,
allocations, releases, paired lifetimes); the fail slice proves
the internal/final boundary (failed outer, surviving copies, no
outer release); the I/O slice proves liveness under real traffic;
effective-copy totals sum every executed copy event per
direction, paired or not; attribution stays a separate scope.
"""

import builtins
import hashlib
import inspect
import io
import json
import os
import pytest
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import parse_oracle_log
import gate_kernel  # noqa: E402
import guest_lifecycle  # noqa: E402
from lifecycle_env import (BRIDGE, COPY_PROBE, LIFECYCLE_PROBE,
                           ensure_oracle_module,
                           require_lifecycle_env,
                           sealed_profiles_dir)
from test_record3 import (ATTEMPT_PROBE, SPEC, _events,
                          _mint_profile, check_capture_session,
                          check_lifetimes, check_oracle_slice)
from evidence_retention import (expected_from_verified,
                                retain_failure)
from vm_boot import (cleanup, guest_artifact_paths, run_guest,
                     verify_exports)

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUNDLE_VERSION = "0.2.0"
TARBALL = os.path.join(REPO, "dist",
                       "memveil-%s.tar.gz" % BUNDLE_VERSION)
MANIFEST = os.path.join(REPO, "dist",
                        "memveil-%s" % BUNDLE_VERSION,
                        "MANIFEST.json")

BUNDLE_CLOSURE = ("bin/memveil",
                  "bpf/swiotlb_attempt.bpf.o",
                  "bpf/swiotlb_lifecycle.bpf.o",
                  "bpf/swiotlb_copy.bpf.o",
                  "lib/memveil/libgcc_s.so.1")


def _require_closure(files, where):
    missing = [rel for rel in BUNDLE_CLOSURE
               if rel not in files]
    if missing:
        raise ValueError("bundle closure lacks %s (%s)"
                         % (", ".join(missing), where))


def host_bundle_inputs(env=None):
    """(tarball, files, manifest_sha, selected) for the leg.

    Sealed inputs (MV_BUNDLE_TARBALL/MV_CANDIDATE_MANIFEST)
    resolve the verified candidate tarball and closure;
    without them the dev dist/ bundle resolves. Both modes
    require the full closure; nothing falls back to dev
    objects.
    """
    sys.path.insert(0, os.path.join(REPO, "tests"))
    from support.candidate_input import load
    selected = load(env)
    if selected is None:
        with open(MANIFEST) as handle:
            files = json.load(handle)["files"]
        _require_closure(files, "dev " + MANIFEST)
        return (TARBALL, files, _sha(MANIFEST), None)
    try:
        files = dict(selected.manifest["files"])
        _require_closure(
            files, "sealed " + str(selected.manifest_path))
    except BaseException:
        if env is not None:
            selected.close()
        raise
    return (str(selected.bundle), files,
            selected.manifest["bundle_manifest_sha256"],
            selected)


def _sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


UNARMED_SKIP = ("lifecycle VM gates need MEMVEIL_VM_LIFECYCLE=1 "
                "with qualified probes")


def _sealed_inputs_requested(env=None):
    sys.path.insert(0, os.path.join(REPO, "tests"))
    from support.candidate_input import requested
    return requested(env)


def require_bundle_env(selected):
    """Arming, harness, and gate kernel for the bundle leg.

    The caller resolves and validates the candidate first;
    the sealed leg then preflights against the candidate
    engine, objects, and profiles only, while the dev leg
    keeps the dev probes. The sealed run carries no
    saturation test object, so the saturation input names
    the sealed attempt bytes; the minted candidate binds
    them with their parsed ring and stays unvalidated. Unarmed
    runs skip here, from this file, so the offline selection
    accounts the skip to this leg.
    """
    if os.environ.get("MEMVEIL_VM_LIFECYCLE") != "1":
        pytest.skip(UNARMED_SKIP)
    if selected is None:
        require_lifecycle_env(LIFECYCLE_PROBE, COPY_PROBE,
                              ATTEMPT_PROBE, BRIDGE)
        return
    attempt = str(selected.path("bpf/swiotlb_attempt.bpf.o"))
    lc_obj = str(selected.path(
        "bpf/swiotlb_lifecycle.bpf.o"))
    cp_obj = str(selected.path("bpf/swiotlb_copy.bpf.o"))
    engine = str(selected.path("bin/memveil"))
    require_lifecycle_env(attempt, lc_obj, cp_obj, engine,
                          memveil=engine,
                          objects={"object": attempt,
                                   "lc_object": lc_obj,
                                   "cp_object": cp_obj},
                          profiles=sealed_profiles_dir(selected),
                          sat_object=attempt)


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
    if bundle["report_exit"] != 0:
        bad.append("%s: report exit %r != 0 (rendered)" % (
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
    for name, direction in (
            ("copy_original_to_bounce_bytes", "original_to_bounce"),
            ("copy_bounce_to_original_bytes", "bounce_to_original")):
        metric = _metric(report, name)
        want = sum(int(e["data"]["bytes"]) for e in copies
                   if e["data"]["direction"] == direction)
        if metric["value"] != str(want):
            bad.append("%s: report %s bytes %r != oracle %d" % (
                tag, name, metric["value"], want))
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
        # The report always shows the latest sample; drained
        # additionally demands the final match the
        # baseline-held closing sample (periodic samples lead
        # the closing baseline/final pair).
        want = samples[-1]["data"]["used_bytes"]
        if _metric(report, "pool_used_bytes")["value"] != want:
            bad.append("%s: report pool %r != sample %r"
                       % (tag, _metric(
                           report, "pool_used_bytes")["value"],
                           want))
        if drained and (len(samples) < 2 or samples[-1][
                "data"]["used_bytes"] != samples[-2][
                "data"]["used_bytes"]):
            bad.append("%s: pool not drained to baseline" % tag)
    codes = [f["code"] for f in report["findings"]]
    if "UNPAIRED_LIFECYCLE" not in codes:
        bad.append("%s: report lacks unpaired finding" % tag)
    return sorted(bad)


def test_bundle_three_phase_capture():
    if os.environ.get("MEMVEIL_VM_LIFECYCLE") != "1" \
            and not _sealed_inputs_requested():
        # Nothing armed and nothing offered: skip without
        # resolving any bundle inputs (the unarmed offline
        # run carries no dev bundle).
        pytest.skip(UNARMED_SKIP)
    tarball, files, manifest_sha, selected = \
        host_bundle_inputs()
    require_bundle_env(selected)
    assert os.path.isfile(tarball), "missing %s" % tarball
    if selected is None:
        ensure_oracle_module()
    else:
        ensure_oracle_module(
            profiles=sealed_profiles_dir(selected))
    if selected is None:
        _mint_profile()
    else:
        _mint_profile(
            selected.path("bpf/swiotlb_lifecycle.bpf.o"),
            selected.path("bpf/swiotlb_copy.bpf.o"))
    with open(SPEC) as handle:
        frozen = json.load(handle)
    assert frozen["frozen_for_module"] == "0.4.0", frozen
    with open(os.path.join(
            REPO, "tests", "vm", "fixtures",
            "witness-expectations.json")) as handle:
        witness = json.load(handle)
    assert witness["frozen_for_module"] == "0.4.0", witness
    tmp = None
    try:
        tmp, proc = run_guest("bundle", timeout=900, network=True)
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        got = verify_exports(
            tmp, "bundle",
            ["identity.json", "record.json",
             "cap-session.json", "cap-events.ndjson",
             "o-oracle.log", "f-oracle.log",
             "workload.json", "bundle.json", "report.json"])
        expected = expected_from_verified(got, "bundle")
        ident = json.loads(got["identity.json"].read_text())
        assert ident["release"] == gate_kernel.selected().release, ident
        bundle = json.loads(got["bundle.json"].read_text())
        assert bundle["tarball"] == os.path.basename(
            tarball), bundle
        assert bundle["tarball_sha"] == _sha(tarball), bundle
        assert bundle["files_verified"] == len(files), bundle
        assert bundle["manifest_sha"] == manifest_sha, bundle
        for key, rel in (("bin_sha", "bin/memveil"),
                         ("attempt_sha",
                          "bpf/swiotlb_attempt.bpf.o"),
                         ("lc_sha", "bpf/swiotlb_lifecycle.bpf.o"),
                         ("cp_sha", "bpf/swiotlb_copy.bpf.o"),
                         ("libgcc_sha",
                          "lib/memveil/libgcc_s.so.1")):
            assert bundle[key] == files[rel], key
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
              "events, report exit 0 ok"
              % (len(o_slice), len(f_slice), len(io_slice),
                 len(ambient)))
    except Exception:
        retain_failure(tmp, "bundle")
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp, "bundle",
                detail=dict(report_exit=bundle["report_exit"],
                            files_verified=bundle[
                                "files_verified"]),
                expected=expected)


def _seal_wire_bundle(tmp_path, name, libgcc=True):
    """Seal a synthetic bundle through the real candidate protocol.

    libgcc=True upgrades the fixture through the shaped seal
    (real packaging scripts, lib/memveil/libgcc_s.so.1 member)
    and binds it as the memveil-0.2.0 artifact the freeze
    serves; libgcc=False keeps the minimal seal (a differently
    named runtime lib) for the refusal leg. Names, bytes, and
    bindings are synthetic; only the protocol is real.
    """
    package_dir = os.path.join(REPO, "tests", "package")
    sys.path.insert(0, package_dir)
    sys.path.insert(0, os.path.join(REPO, "tools"))
    import sealed_fixture as fixture
    from test_candidate import deterministic_tar_gz
    import candidate as protocol
    shop = fixture.workshop()
    fix = shop.fresh(tmp_path / name)
    if libgcc:
        # The stock shaped seal agrees on the freeze version
        # (spec, manifest, and stub binaries); no overrides.
        manifest_path = fix["bundle_dir"] / "MANIFEST.json"
        fixture._shape_bundle(
            fix, tmp_path / (name + "-shape"))
        manifest = json.loads(manifest_path.read_text())
        manifest["bundle"] = "memveil-" + BUNDLE_VERSION
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True)
            + "\n")
        old_tarball, _arc = fixture._bundle_tarball(
            fix["artifacts"])
        engine = fix["bundle_dir"] / "bin" / "memveil"
        engine.chmod(0o755)
        new_tarball = fix["artifacts"] / (
            "memveil-" + BUNDLE_VERSION + ".tar.gz")
        deterministic_tar_gz(fix["bundle_dir"],
                             "memveil-" + BUNDLE_VERSION,
                             new_tarball)
        old_tarball.unlink()
    else:
        fixture._make_executable_bundle(fix)
    fixture._regenerate_seal_bindings(fix, shop.harness_bin())
    manifest = protocol.create_manifest(
        fix["bundle_dir"], fix["artifacts"], fix["policy"],
        {"root": str(fix["root"]),
         "harness_bin": shop.harness_bin()})
    out = fix["artifacts"] / "candidate.json"
    protocol.seal_manifest(manifest, out)
    roles = {entry["role"]: fix["artifacts"] / entry["name"]
             for entry in manifest["artifacts"]}
    assert roles["deb"].is_file() and roles["rpm"].is_file()
    assert roles["bundle"].is_file()
    return {"manifest_path": out, "manifest": manifest,
            "bundle": roles["bundle"], "deb": roles["deb"],
            "rpm": roles["rpm"],
            "bundle_dir": fix["bundle_dir"],
            "root": fix["root"]}


def _wire_env(sealed):
    return {"MV_BUNDLE_TARBALL": str(sealed["bundle"]),
            "MV_CANDIDATE_MANIFEST":
            str(sealed["manifest_path"])}


AYA_DIR = os.path.join(REPO, "tests", "vm", "fixtures", "aya")


def seal_bundle_with_members(tmp_path, name, members):
    """Seal a synthetic bundle with replaced member bytes.

    members maps bundle-relative paths to bytes; the BPF
    copies and the profiles typically take caller bytes
    while the rest stays workshop synthetic. Manifest pins
    are rebound and the install pair rebuilt before the
    seal, so the result verifies through the real candidate
    protocol. Selection tests share this helper.
    """
    package_dir = os.path.join(REPO, "tests", "package")
    sys.path.insert(0, package_dir)
    sys.path.insert(0, os.path.join(REPO, "tools"))
    import sealed_fixture as fixture
    from test_candidate import deterministic_tar_gz
    import candidate as protocol
    shop = fixture.workshop()
    fix = shop.fresh(tmp_path / name)
    bundle = fix["bundle_dir"]
    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    files = dict(manifest["files"])
    for rel, data in members.items():
        path = bundle / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        files[rel] = hashlib.sha256(data).hexdigest()
    manifest["files"] = files
    bpf = {short: files["bpf/" + short] for short in (
        "swiotlb_attempt.bpf.o", "swiotlb_lifecycle.bpf.o",
        "swiotlb_copy.bpf.o")}
    manifest["build_receipt"]["outputs"]["bpf"] = bpf
    manifest["embedded_bpf"] = dict(bpf)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    if members:
        # Changed payload bytes need a rebuilt install pair;
        # the seal compares its closure against the bundle.
        fixture._shape_bundle(fix, tmp_path / (name + "-shape"))
    else:
        # The loader requires an executable engine; re-tar so
        # the bundle artifact matches the rebound manifest
        # before the seal binds the bytes.
        engine = bundle / "bin" / "memveil"
        engine.chmod(0o755)
        tarball, arcname = fixture._bundle_tarball(
            fix["artifacts"])
        deterministic_tar_gz(bundle, arcname, tarball)
    fixture._regenerate_seal_bindings(fix, shop.harness_bin())
    sealed_manifest = protocol.create_manifest(
        bundle, fix["artifacts"], fix["policy"],
        {"root": str(fix["root"]),
         "harness_bin": shop.harness_bin()})
    out = fix["artifacts"] / "candidate.json"
    protocol.seal_manifest(sealed_manifest, out)
    roles = {entry["role"]: fix["artifacts"] / entry["name"]
             for entry in sealed_manifest["artifacts"]}
    assert roles["bundle"].is_file()
    return {"manifest_path": out, "manifest": sealed_manifest,
            "bundle": roles["bundle"]}


def _aya_member(short):
    with open(os.path.join(AYA_DIR, short), "rb") as handle:
        return handle.read()


def _sealed_select_bundle(tmp_path, name, profile_docs):
    """Sealed candidate with real BPF bytes and given profiles.

    profile_docs maps a profile filename to its doc; the
    manifest lists exactly those names. Returns the loaded
    selection, which the caller closes.
    """
    members = {
        "bpf/swiotlb_attempt.bpf.o":
        _aya_member("swiotlb_attempt.bpf.o"),
        "bpf/swiotlb_lifecycle.bpf.o":
        _aya_member("swiotlb_lifecycle.bpf.o"),
        "bpf/swiotlb_copy.bpf.o":
        _aya_member("swiotlb_copy.bpf.o"),
        "profiles/manifest.txt":
        ("\n".join(sorted(profile_docs)) + "\n").encode(),
    }
    for filename, doc in profile_docs.items():
        members["profiles/" + filename] = (
            json.dumps(doc, indent=2, sort_keys=True) + "\n"
        ).encode()
    sealed = seal_bundle_with_members(tmp_path, name, members)
    sys.path.insert(0, os.path.join(REPO, "tests"))
    from support.candidate_input import load
    return load(env=_wire_env(sealed), required=True)


def _sealed_select_objects(selected):
    """(bindings, saturation input) under the verified root."""
    attempt = str(selected.path("bpf/swiotlb_attempt.bpf.o"))
    return ({"object": attempt,
             "lc_object": str(selected.path(
                 "bpf/swiotlb_lifecycle.bpf.o")),
             "cp_object": str(selected.path(
                 "bpf/swiotlb_copy.bpf.o"))},
            attempt)


def _sealed_bundle_with_minted_profile(
        tmp_path, name, profile_id, ident, fmt, adjust=None):
    """Sealed candidate with a profile minted over sealed bytes.

    Two-phase: a probe bundle seals and loads first, so the
    emitter inputs resolve under a verified root (validated
    first; a missing member fails closed through the
    candidate loader instead of falling back to the dev
    tree); the minted doc is then sealed into the returned
    bundle. adjust(doc) tweaks the minted doc before the
    second seal. Returns the loaded selection, which the
    caller closes.
    """
    probe = _sealed_select_bundle(
        tmp_path, name + "-probe", {"probe.json": {}})
    try:
        objects, sat_object = _sealed_select_objects(probe)
        emit = {"attempt": objects["object"],
                "saturation": sat_object,
                "lc": objects["lc_object"],
                "cp": objects["cp_object"]}
        doc, _sat = gate_kernel.emitter().gate_docs(
            ident, fmt, profile_id, emit)
    finally:
        probe.close()
    doc["status"] = "validated"
    if adjust is not None:
        adjust(doc)
    return _sealed_select_bundle(
        tmp_path, name, {profile_id + ".json": doc})


@pytest.mark.dev_fixture
def test_bundle_sealed_inputs_wiring(tmp_path):
    """Sealed inputs resolve the sealed memveil-0.2.0 bundle both sides.

    Host and guest resolvers agree on the sealed tarball
    identity; the guest record line carries no --bridge and no
    dev-tree path, every resolved byte matches its sealed pin,
    the guest bridge slot and the host identity table agree
    on the sealed runtime member, and the dev defaults name
    memveil-0.2.0 on both sides. Pure resolution: no VM boots.
    """
    assert os.path.basename(TARBALL) == \
        "memveil-0.2.0.tar.gz", TARBALL
    assert os.path.basename(os.path.dirname(MANIFEST)) == \
        "memveil-0.2.0", MANIFEST
    dev = guest_lifecycle.bundle_run_inputs(REPO, None)
    assert dev["mode"] == "dev", dev
    assert os.path.basename(dev["tarball"]) == \
        "memveil-0.2.0.tar.gz", dev
    assert dev["root_name"] == "memveil-0.2.0", dev
    sealed = _seal_wire_bundle(tmp_path, "bundlewire",
                               libgcc=True)
    assert sealed["bundle"].name == \
        "memveil-0.2.0.tar.gz", sealed["bundle"]
    sys.path.insert(0, os.path.join(REPO, "tests"))
    from support.candidate_input import load
    env = _wire_env(sealed)
    selected = load(env=env, required=True)
    tarball, files, manifest_sha, host_selected = \
        host_bundle_inputs(env)
    try:
        assert tarball == str(sealed["bundle"]), tarball
        assert files == selected.manifest["files"], files
        assert manifest_sha == selected.manifest[
            "bundle_manifest_sha256"], manifest_sha
        run = guest_lifecycle.bundle_run_inputs(
            "/nonexistent-repo", selected)
        assert run["mode"] == "sealed", run
        assert run["tarball_name"] == \
            "memveil-0.2.0.tar.gz", run
        assert run["tarball"] == str(sealed["bundle"]), run
        assert run["root"] == str(selected.root), run
        for key, rel in (("bin", "bin/memveil"),
                         ("attempt",
                          "bpf/swiotlb_attempt.bpf.o"),
                         ("lc",
                          "bpf/swiotlb_lifecycle.bpf.o"),
                         ("cp", "bpf/swiotlb_copy.bpf.o"),
                         ("libgcc",
                          "lib/memveil/libgcc_s.so.1")):
            assert run[key] == str(selected.path(rel)), \
                (key, run[key])
            assert _sha(run[key]) == files[rel], key
            assert run[key].startswith(
                str(selected.root)), (key, run[key])
        argv = guest_lifecycle.bundle_record_argv(
            run["bin"],
            {"attempt": run["attempt"], "lc": run["lc"],
             "cp": run["cp"]},
            "/nonexistent-repo/build/vm/record3-profile.json",
            "/tmp/vmgate-work/cap")
        assert "--bridge" not in argv, argv
        assert all("libbpf_mojo" not in arg
                   for arg in argv), argv
        assert all("libbpf_mojo" not in value
                   for value in run.values()
                   if isinstance(value, str)), run
        assert run["tarball_sha"] == _sha(tarball), run
        assert run["manifest_sha"] == manifest_sha, run
        assert run["files_verified"] == len(files), run
        bridge = guest_lifecycle.guest_bridge_input(
            "/nonexistent-repo", "bundle", selected)
        assert bridge == run["libgcc"], bridge
        assert _sha(bridge) == files[
            "lib/memveil/libgcc_s.so.1"], bridge
        table = guest_artifact_paths(
            "bundle", "/nonexistent-repo", selected)
        assert table["bridge_sha"] == bridge, table
        assert table["lc_sha"] == run["lc"], table
        assert table["cp_sha"] == run["cp"], table
    finally:
        selected.close()
        host_selected.close()


@pytest.mark.dev_fixture
def test_bundle_sealed_inputs_refuse_dev_fallback(tmp_path):
    """A sealed closure without libgcc refuses outright.

    The bundle runner never falls back to dev-tree objects:
    sealed resolution raises instead of serving build/ bytes.
    """
    sealed = _seal_wire_bundle(tmp_path, "bundlerefuse",
                               libgcc=False)
    sys.path.insert(0, os.path.join(REPO, "tests"))
    from support.candidate_input import load
    env = _wire_env(sealed)
    selected = load(env=env, required=True)
    try:
        assert "lib/memveil/libgcc_s.so.1" not in \
            selected.manifest["files"]
        with pytest.raises(ValueError):
            guest_lifecycle.bundle_run_inputs(REPO, selected)
        with pytest.raises(ValueError):
            host_bundle_inputs(env)
    finally:
        selected.close()


@pytest.mark.dev_fixture
def test_bundle_armed_leg_resolves_inputs_first():
    """The armed leg resolves inputs before any preflight call."""
    source = inspect.getsource(test_bundle_three_phase_capture)
    assert source.index("host_bundle_inputs()") < \
        source.index("require_bundle_env(")


@pytest.mark.dev_fixture
def test_bundle_unarmed_skip_matches_shared_preflight(
        monkeypatch):
    """This leg's unarmed skip stays worded like the shared one.

    The leg skips from this file so the offline selection
    accounts the skip here; the wording still matches the
    shared preflight every other leg raises.
    """
    monkeypatch.delenv("MEMVEIL_VM_LIFECYCLE", raising=False)
    with pytest.raises(pytest.skip.Exception) as shared:
        require_lifecycle_env("/nonexistent-probe")
    with pytest.raises(pytest.skip.Exception) as leg:
        require_bundle_env(None)
    assert leg.value.msg == shared.value.msg == UNARMED_SKIP


@pytest.mark.dev_fixture
def test_bundle_unarmed_skips_without_bundle_inputs(
        monkeypatch):
    """Unarmed with no sealed inputs, the leg skips cleanly.

    Nothing armed and nothing offered: the leg skips from
    this file without resolving any bundle inputs (even a
    missing dev bundle cannot fail the skip).
    """
    monkeypatch.delenv("MEMVEIL_VM_LIFECYCLE", raising=False)
    monkeypatch.delenv("MV_BUNDLE_TARBALL", raising=False)
    monkeypatch.delenv("MV_CANDIDATE_MANIFEST", raising=False)
    monkeypatch.delenv("MV_CANDIDATE_DIGEST", raising=False)
    this = sys.modules[__name__]
    monkeypatch.setattr(this, "MANIFEST",
                        "/nonexistent-manifest.json")
    monkeypatch.setattr(this, "TARBALL",
                        "/nonexistent-bundle.tar.gz")
    with pytest.raises(pytest.skip.Exception) as skipped:
        test_bundle_three_phase_capture()
    assert skipped.value.msg == UNARMED_SKIP


@pytest.mark.dev_fixture
def test_bundle_validates_candidate_before_preflight(
        tmp_path, monkeypatch):
    """A bad candidate fails validation before any preflight skip.

    Unarmed runs skip, but candidate validation runs first:
    sealed inputs that fail verification raise instead of
    skipping quietly.
    """
    monkeypatch.delenv("MEMVEIL_VM_LIFECYCLE", raising=False)
    sealed = _seal_wire_bundle(tmp_path, "bundleorder",
                               libgcc=True)
    bad = dict(_wire_env(sealed), MV_CANDIDATE_DIGEST="f" * 64)
    with pytest.raises(ValueError):
        host_bundle_inputs(bad)


DEV_INPUT_DIRS = tuple(os.path.join(REPO, name) + os.sep
                       for name in ("build", "dist"))
CHECKOUT_PROFILES = (os.path.join(REPO, "profiles") + os.sep,)


def _refuse_dev_consult(monkeypatch, real, target,
                        dirs=DEV_INPUT_DIRS):
    """Fail the test if sealed work consults dev inputs."""
    def guard(path, *args, **kwargs):
        if isinstance(path, (str, os.PathLike)):
            text = os.fspath(path)
            if text.startswith(dirs):
                raise AssertionError(
                    "sealed leg consulted dev input: %s"
                    % text)
        return real(path, *args, **kwargs)
    monkeypatch.setattr(target[0], target[1], guard)


SEALED_FOREIGN_RELEASE = "9.9.9-sealed-foreign"


def _sealed_foreign_profile(pin):
    """Validated sealed profile naming the foreign release."""
    return {
        "status": "validated",
        "profile_id": "sealed-foreign",
        "identity": {
            "source": {
                "revision": SEALED_FOREIGN_RELEASE,
                "note": ("config=sha256:%s config_src=file "
                         "btf=sha256:%s format=sha256:%s"
                         % ("c" * 64, pin, "f" * 64)),
            },
        },
    }


@pytest.mark.dev_fixture
def test_bundle_sealed_path_consults_no_dev_tree(
        tmp_path, monkeypatch):
    """Sealed resolve-plus-preflight never consults dev inputs.

    With guards refusing any build/ or dist/ file consult,
    the sealed inputs resolve, the guest and host resolvers
    agree under the verified root, and the unarmed leg
    skips from this file. Pure resolution: no VM boots.
    """
    monkeypatch.delenv("MEMVEIL_VM_LIFECYCLE", raising=False)
    sealed = _seal_wire_bundle(tmp_path, "bundledevfree",
                               libgcc=True)
    env = _wire_env(sealed)
    _refuse_dev_consult(monkeypatch, os.path.isfile,
                        (os.path, "isfile"))
    _refuse_dev_consult(monkeypatch, os.path.exists,
                        (os.path, "exists"))
    _refuse_dev_consult(monkeypatch, builtins.open,
                        (builtins, "open"))
    _refuse_dev_consult(monkeypatch, io.open, (io, "open"))
    _refuse_dev_consult(monkeypatch, os.stat, (os, "stat"))
    tarball, files, manifest_sha, selected = \
        host_bundle_inputs(env)
    try:
        assert tarball == str(sealed["bundle"]), tarball
        assert not tarball.startswith(DEV_INPUT_DIRS), \
            tarball
        run = guest_lifecycle.bundle_run_inputs(
            "/nonexistent-repo", selected)
        assert run["tarball"] == tarball, run
        for key in ("bin", "attempt", "lc", "cp", "libgcc"):
            assert run[key].startswith(
                str(selected.root)), (key, run[key])
        bridge = guest_lifecycle.guest_bridge_input(
            "/nonexistent-repo", "bundle", selected)
        assert bridge == run["libgcc"], bridge
        table = guest_artifact_paths(
            "bundle", "/nonexistent-repo", selected)
        assert table["bridge_sha"] == bridge, table
        with pytest.raises(pytest.skip.Exception) as skipped:
            require_bundle_env(selected)
        assert skipped.value.msg == UNARMED_SKIP
    finally:
        selected.close()


@pytest.mark.dev_fixture
def test_bundle_sealed_preflight_names_candidate_inputs(
        tmp_path, monkeypatch):
    """Armed sealed preflight checks candidate inputs only.

    The harness and gate-kernel selection are stubbed; the
    test records every probed path plus the engine and
    objects handed to selection, and refuses any dev-tree
    entry. No VM boots and no doctor runs.
    """
    sealed = _seal_wire_bundle(tmp_path, "bundlepreflight",
                               libgcc=True)
    env = _wire_env(sealed)
    sys.path.insert(0, os.path.join(REPO, "tests"))
    from support.candidate_input import load
    import lifecycle_env as preflight
    selected = load(env=env, required=True)
    try:
        monkeypatch.setenv("MEMVEIL_VM_LIFECYCLE", "1")
        seen = []
        real_isfile = os.path.isfile

        def record_isfile(path):
            seen.append(os.fspath(path))
            return real_isfile(path)

        monkeypatch.setattr(os.path, "isfile", record_isfile)
        real_exists = os.path.exists
        monkeypatch.setattr(
            os.path, "exists",
            lambda p: True if p == "/dev/kvm"
            else real_exists(p))
        monkeypatch.setattr(
            shutil, "which", lambda name: "/fake/" + name)
        monkeypatch.setattr(
            subprocess, "run",
            lambda *args, **kwargs: subprocess.CompletedProcess(
                args[0] if args else [], 0))
        recorded = {}

        def record_prepare(**kwargs):
            recorded.update(kwargs)

        monkeypatch.setattr(preflight, "prepare_gate_kernel",
                            record_prepare)
        require_bundle_env(selected)
        engine = str(selected.path("bin/memveil"))
        assert recorded["memveil"] == engine, recorded
        attempt = str(selected.path(
            "bpf/swiotlb_attempt.bpf.o"))
        assert recorded["objects"] == {
            "object": attempt,
            "lc_object": str(selected.path(
                "bpf/swiotlb_lifecycle.bpf.o")),
            "cp_object": str(selected.path(
                "bpf/swiotlb_copy.bpf.o"))}, recorded
        assert recorded["profiles"] == selected.root / \
            "profiles", recorded
        assert recorded["sat_object"] == attempt, recorded
        assert seen, "sealed preflight probed no inputs"
        for path in seen:
            assert path.startswith(str(selected.root)), path
    finally:
        selected.close()


@pytest.mark.dev_fixture
def test_bundle_sealed_selection_uses_candidate_profiles(
        tmp_path):
    """A sealed selection serves the candidate profile as is.

    The sealed bundle carries real BPF bytes and one
    validated profile minted for the fixture kernel over
    those same bytes; selection serves that doc from under
    the verified root with no drift, and the saturation
    candidate binds the sealed attempt bytes with their
    parsed ring. No VM boots.
    """
    from test_gate_kernel import REL, kernel_tree
    root = kernel_tree(tmp_path)
    ident, fmt = gate_kernel.measure_identity(REL, str(root))
    emit = {
        "attempt": os.path.join(AYA_DIR,
                                "swiotlb_attempt.bpf.o"),
        "saturation": os.path.join(AYA_DIR,
                                   "swiotlb_attempt.bpf.o"),
        "lc": os.path.join(AYA_DIR,
                           "swiotlb_lifecycle.bpf.o"),
        "cp": os.path.join(AYA_DIR, "swiotlb_copy.bpf.o"),
    }
    gate, _sat = gate_kernel.emitter().gate_docs(
        ident, fmt, "sealed-shipped", emit)
    gate["status"] = "validated"
    selected = _sealed_select_bundle(
        tmp_path, "selectshipped",
        {"sealed-shipped.json": gate})
    try:
        profiles = sealed_profiles_dir(selected)
        assert profiles == selected.root / "profiles"
        objects, sat_object = _sealed_select_objects(selected)
        sel = gate_kernel.select(
            REL, str(root), tmp_path / "out", objects=objects,
            profiles=profiles, host_release=REL,
            require_shipped=True, sat_object=sat_object)
        assert sel.mode == "shipped"
        assert sel.gate_doc == profiles / "sealed-shipped.json"
        assert str(sel.gate_doc).startswith(
            str(selected.root)), sel.gate_doc
        sat = json.loads(sel.sat_doc.read_text())
        note = dict(part.split("=", 1) for part in
                    sat["identity"]["source"]["note"].split())
        files = selected.manifest["files"]
        assert note["object"] == "sha256:" + files[
            "bpf/swiotlb_attempt.bpf.o"]
        assert note["ring_bytes"] == "8388608"
    finally:
        selected.close()


@pytest.mark.dev_fixture
def test_bundle_sealed_selection_mints_without_dev_tree(
        tmp_path, monkeypatch, capsys):
    """A sealed mint consults no build-tree profiles or objects.

    The sealed profiles name only another release, so
    selection mints; with guards refusing any build/ or
    dist/ consult, the mint binds the sealed bytes
    throughout. No VM boots.
    """
    from test_gate_kernel import REL, kernel_tree
    root = kernel_tree(tmp_path)
    ident, fmt = gate_kernel.measure_identity(REL, str(root))

    def name_other(doc):
        doc["identity"]["source"]["revision"] = "9.9.1-other"

    selected = _sealed_bundle_with_minted_profile(
        tmp_path, "selectmint", "sealed-other", ident, fmt,
        name_other)
    try:
        profiles = sealed_profiles_dir(selected)
        objects, sat_object = _sealed_select_objects(selected)
        _refuse_dev_consult(monkeypatch, os.path.isfile,
                            (os.path, "isfile"))
        _refuse_dev_consult(monkeypatch, os.path.exists,
                            (os.path, "exists"))
        _refuse_dev_consult(monkeypatch, builtins.open,
                            (builtins, "open"))
        _refuse_dev_consult(monkeypatch, io.open, (io, "open"))
        _refuse_dev_consult(monkeypatch, os.stat, (os, "stat"))
        sel = gate_kernel.select(
            REL, str(root), tmp_path / "out", objects=objects,
            profiles=profiles, host_release=REL,
            require_shipped=False, sat_object=sat_object)
        assert sel.mode == "minted"
        assert "no validated shipped profile names" in \
            capsys.readouterr().out
        gate = json.loads(sel.gate_doc.read_text())
        note = dict(part.split("=", 1) for part in
                    gate["identity"]["source"]["note"].split())
        files = selected.manifest["files"]
        for key, rel in (("object", "bpf/swiotlb_attempt.bpf.o"),
                         ("lc_object",
                          "bpf/swiotlb_lifecycle.bpf.o"),
                         ("cp_object",
                          "bpf/swiotlb_copy.bpf.o")):
            assert note[key] == "sha256:" + files[rel], key
        assert note["ring_bytes"] == "8388608"
        assert note["lc_ring_bytes"] == "33554432"
        assert note["cp_ring_bytes"] == "33554432"
        sat = json.loads(sel.sat_doc.read_text())
        sat_note = dict(part.split("=", 1) for part in
                        sat["identity"]["source"]["note"].split())
        assert sat_note["object"] == "sha256:" + files[
            "bpf/swiotlb_attempt.bpf.o"]
        assert sat_note["ring_bytes"] == "8388608"
        # The fixture doc itself binds the sealed bytes: the
        # setup mint resolved the verified inputs, not the
        # dev tree.
        other_doc = json.loads(
            (profiles / "sealed-other.json").read_text())
        other_note = dict(
            part.split("=", 1) for part in
            other_doc["identity"]["source"]["note"].split())
        for key, rel in (("object", "bpf/swiotlb_attempt.bpf.o"),
                         ("lc_object",
                          "bpf/swiotlb_lifecycle.bpf.o"),
                         ("cp_object",
                          "bpf/swiotlb_copy.bpf.o")):
            assert other_note[key] == "sha256:" + files[rel], key
    finally:
        selected.close()


@pytest.mark.dev_fixture
def test_bundle_sealed_selection_reports_sealed_drift(
        tmp_path):
    """Sealed drift names the sealed doc, not the build tree.

    A validated sealed profile with foreign bindings mints
    with a drift reason naming that sealed doc, proving
    selection consulted the candidate profiles.
    """
    from test_gate_kernel import REL, kernel_tree
    root = kernel_tree(tmp_path)
    ident, fmt = gate_kernel.measure_identity(REL, str(root))

    def zero_object(doc):
        fields = []
        for part in doc["identity"]["source"]["note"].split():
            if part.startswith("object="):
                part = "object=sha256:" + "0" * 64
            fields.append(part)
        doc["identity"]["source"]["note"] = " ".join(fields)

    selected = _sealed_bundle_with_minted_profile(
        tmp_path, "selectdrift", "sealed-drifted", ident, fmt,
        zero_object)
    try:
        profiles = sealed_profiles_dir(selected)
        objects, sat_object = _sealed_select_objects(selected)
        with pytest.raises(gate_kernel.GateKernelError,
                           match="sealed-drifted.json.*drift"):
            gate_kernel.select(
                REL, str(root), tmp_path / "out",
                objects=objects, profiles=profiles,
                host_release=REL, require_shipped=True,
                sat_object=sat_object)
    finally:
        selected.close()


@pytest.mark.dev_fixture
def test_bundle_sealed_oracle_pin_resolves_verified_profiles(
        tmp_path, monkeypatch):
    """A sealed foreign-kernel oracle pins the sealed BTF root.

    The sealed bundle carries a validated profile for the
    foreign guest release; with the guest kernel override
    naming that release, the oracle identity takes the BTF
    pin from the verified root while the checkout profiles
    stay untouched. No VM boots.
    """
    from test_oracle_kver import make_kernel_tree, refuse_subprocess
    import lifecycle_env as preflight
    pin = "e" * 64
    selected = _sealed_select_bundle(
        tmp_path, "oraclepin",
        {"sealed-foreign.json": _sealed_foreign_profile(pin)})
    try:
        profiles = sealed_profiles_dir(selected)
        assert profiles == selected.root / "profiles"
        tree = make_kernel_tree(tmp_path / "kernels",
                                SEALED_FOREIGN_RELEASE)
        assert tree["btf_sha"] != pin
        monkeypatch.setenv("MEMVEIL_ORACLE_KVER",
                           SEALED_FOREIGN_RELEASE)
        refuse_subprocess(monkeypatch)
        _refuse_dev_consult(monkeypatch, os.path.isfile,
                            (os.path, "isfile"),
                            CHECKOUT_PROFILES)
        _refuse_dev_consult(monkeypatch, os.path.exists,
                            (os.path, "exists"),
                            CHECKOUT_PROFILES)
        _refuse_dev_consult(monkeypatch, builtins.open,
                            (builtins, "open"),
                            CHECKOUT_PROFILES)
        _refuse_dev_consult(monkeypatch, io.open, (io, "open"),
                            CHECKOUT_PROFILES)
        _refuse_dev_consult(monkeypatch, os.stat, (os, "stat"),
                            CHECKOUT_PROFILES)
        ident = preflight.module_build_identity(
            host_release="9.9.1-host",
            modules_root=tree["modules_root"],
            boot_root=tree["boot_root"], btf_path=tree["btf_path"],
            profiles_dir=profiles)
        assert ident["release"] == SEALED_FOREIGN_RELEASE
        assert ident["btf_sha"] == pin
        assert ident["btf_provenance"] == "profile-pinned"
    finally:
        selected.close()


@pytest.mark.dev_fixture
def test_bundle_sealed_oracle_refuses_unpinned_foreign_kernel(
        tmp_path, monkeypatch):
    """A sealed foreign kernel without a sealed pin fails closed.

    The sealed profiles name only another release, so the
    oracle identity for the foreign guest release refuses
    instead of falling back to the checkout. No VM boots.
    """
    from test_oracle_kver import make_kernel_tree, refuse_subprocess
    import lifecycle_env as preflight
    doc = _sealed_foreign_profile("e" * 64)
    doc["identity"]["source"]["revision"] = "9.9.1-other"
    selected = _sealed_select_bundle(
        tmp_path, "oraclerefuse", {"sealed-other.json": doc})
    try:
        profiles = sealed_profiles_dir(selected)
        tree = make_kernel_tree(tmp_path / "kernels",
                                SEALED_FOREIGN_RELEASE)
        monkeypatch.setenv("MEMVEIL_ORACLE_KVER",
                           SEALED_FOREIGN_RELEASE)
        refuse_subprocess(monkeypatch)
        _refuse_dev_consult(monkeypatch, os.path.isfile,
                            (os.path, "isfile"),
                            CHECKOUT_PROFILES)
        _refuse_dev_consult(monkeypatch, os.path.exists,
                            (os.path, "exists"),
                            CHECKOUT_PROFILES)
        _refuse_dev_consult(monkeypatch, builtins.open,
                            (builtins, "open"),
                            CHECKOUT_PROFILES)
        _refuse_dev_consult(monkeypatch, io.open, (io, "open"),
                            CHECKOUT_PROFILES)
        _refuse_dev_consult(monkeypatch, os.stat, (os, "stat"),
                            CHECKOUT_PROFILES)
        with pytest.raises(pytest.fail.Exception,
                           match="no validated shipped profile"):
            preflight.module_build_identity(
                host_release="9.9.1-host",
                modules_root=tree["modules_root"],
                boot_root=tree["boot_root"],
                btf_path=tree["btf_path"],
                profiles_dir=profiles)
    finally:
        selected.close()


@pytest.mark.dev_fixture
def test_bundle_sealed_export_resolves_verified_profiles(
        tmp_path, monkeypatch):
    """Sealed export checks pin the kernel identity to the sealed root.

    The export verifier hands the verified profile root to
    the identity builder; the recorded profiles dir is the
    sealed one, the artifact table resolves under the
    verified root, and the checkout profiles stay untouched.
    No VM boots.
    """
    import vm_boot
    import lifecycle_env as preflight
    sys.path.insert(0, os.path.join(REPO, "tests"))
    import support.candidate_input as candidate_input
    sealed = _seal_wire_bundle(tmp_path, "exportsealed",
                               libgcc=True)
    selected = candidate_input.load(
        env=_wire_env(sealed), required=True)
    try:
        monkeypatch.setattr(candidate_input, "load",
                            lambda *args, **kwargs: selected)
        recorded = {}

        def fake_identity(**kwargs):
            recorded.update(kwargs)
            return dict(release="9.9.9-sealed-foreign",
                        config_sha="c" * 64, btf_sha="d" * 64)

        monkeypatch.setattr(preflight, "module_build_identity",
                            fake_identity)
        ko = tmp_path / "oracle.ko"
        ko.write_bytes(b"fake-ko")
        monkeypatch.setattr(preflight, "ORACLE_KO", str(ko))
        identity = dict(
            release="9.9.9-sealed-foreign", swiotlb_force=True,
            config_sha="c" * 64, btf_sha="d" * 64,
            lc_sha=_sha(str(selected.path(
                "bpf/swiotlb_lifecycle.bpf.o"))),
            cp_sha=_sha(str(selected.path(
                "bpf/swiotlb_copy.bpf.o"))),
            bridge_sha=_sha(str(selected.path(
                "lib/memveil/libgcc_s.so.1"))),
            ko_sha=_sha(str(ko)))
        run = tmp_path / "run"
        export = run / "export"
        export.mkdir(parents=True)
        target = export / "bundle-identity.json"
        target.write_text(json.dumps(identity))
        (export / "bundle-identity.json.sha256").write_text(
            _sha(str(target)) + "\n")
        _refuse_dev_consult(monkeypatch, os.path.isfile,
                            (os.path, "isfile"),
                            CHECKOUT_PROFILES)
        _refuse_dev_consult(monkeypatch, os.path.exists,
                            (os.path, "exists"),
                            CHECKOUT_PROFILES)
        _refuse_dev_consult(monkeypatch, builtins.open,
                            (builtins, "open"),
                            CHECKOUT_PROFILES)
        _refuse_dev_consult(monkeypatch, io.open, (io, "open"),
                            CHECKOUT_PROFILES)
        _refuse_dev_consult(monkeypatch, os.stat, (os, "stat"),
                            CHECKOUT_PROFILES)
        vm_boot.verify_exports(run, "bundle", ["identity.json"])
        assert recorded == {"profiles_dir": selected.root
                            / "profiles"}, recorded
    finally:
        selected.close()


@pytest.mark.dev_fixture
def test_bundle_sealed_profiles_reject_tampering(tmp_path):
    """Sealed profile reads fail closed on tampered bytes.

    The member check and the manifest check each refuse
    bytes that changed after verification.
    """
    sealed = seal_bundle_with_members(tmp_path, "profiletamper",
                                      {})
    sys.path.insert(0, os.path.join(REPO, "tests"))
    from support.candidate_input import load
    env = _wire_env(sealed)
    selected = load(env=env, required=True)
    try:
        member = selected.root / "profiles" / "p.json"
        member.write_bytes(b'{"tampered": true}\n')
        with pytest.raises(ValueError,
                           match="candidate input changed"):
            sealed_profiles_dir(selected)
    finally:
        selected.close()
    selected = load(env=env, required=True)
    try:
        manifest = selected.root / "profiles" / "manifest.txt"
        manifest.write_bytes(b"p.json\ntampered.json\n")
        with pytest.raises(ValueError,
                           match="candidate input changed"):
            sealed_profiles_dir(selected)
    finally:
        selected.close()


@pytest.mark.dev_fixture
def test_bundle_sealed_profiles_reject_unlisted_member(
        tmp_path):
    """A sealed manifest cannot smuggle an unlisted profile."""
    sealed = seal_bundle_with_members(
        tmp_path, "profileghost",
        {"profiles/manifest.txt": b"p.json\nghost.json\n"})
    sys.path.insert(0, os.path.join(REPO, "tests"))
    from support.candidate_input import load
    selected = load(env=_wire_env(sealed), required=True)
    try:
        with pytest.raises(ValueError,
                           match="outside candidate closure"):
            sealed_profiles_dir(selected)
    finally:
        selected.close()


@pytest.mark.dev_fixture
def test_bundle_identity_carries_no_consumer(
        tmp_path, monkeypatch):
    """The bundle leg neither maps nor reports the consumer.

    The host identity table omits the consumer entry for
    the bundle leg in both modes, and the guest identity
    omits the consumer hash for the bundle leg while
    keeping it for consumer legs.
    """
    from vm_boot import guest_artifact_paths
    table = guest_artifact_paths("bundle", "/nonexistent-repo")
    assert "consume_sha" not in table
    assert set(table) == {"lc_sha", "cp_sha", "bridge_sha"}
    assert "consume_sha" in guest_artifact_paths(
        "copy", "/nonexistent-repo")
    work = tmp_path / "gate"
    work.mkdir()
    files = {}
    for key in ("bridge", "lc", "cp", "ko"):
        path = work / key
        path.write_bytes(key.encode())
        files[key] = str(path)
    gate = guest_lifecycle.Gate.__new__(guest_lifecycle.Gate)
    gate.sub = "bundle"
    gate.consume = None
    gate.bridge = files["bridge"]
    gate.lc_obj = files["lc"]
    gate.cp_obj = files["cp"]
    gate.lc_test_obj = files["lc"]
    gate.cp_test_obj = files["cp"]
    gate.ko = files["ko"]
    import lifecycle_env as preflight
    monkeypatch.setattr(
        preflight, "module_build_identity",
        lambda: {"config_sha": "c" * 64, "btf_sha": "d" * 64})
    doc = gate.identity()
    assert "consume_sha" not in doc
    assert set(doc) == {"release", "swiotlb_force", "config_sha",
                        "btf_sha", "bridge_sha", "lc_sha",
                        "cp_sha", "ko_sha"}
    gate.sub = "copy"
    gate.consume = files["bridge"]
    assert "consume_sha" in gate.identity()
