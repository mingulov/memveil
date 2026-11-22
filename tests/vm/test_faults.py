#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""F2-7: multi-channel faults through the sealed record.

Seven scenarios in one pinned guest: truncated lc/cp objects
refuse with exit 3 and zero BPF residue; SIGTERM mid-capture
(1ch f3a and 3ch f3b) stops bounded with a signal end reason;
a full output filesystem publishes an honest error
session; paced 300-op floods compare 1ch against
3ch capture exactly; a burst flood reconciles recorded plus
omitted against the scripted prediction; background flood
during attach leaves no pre-window records. Helper tests do
not substitute: every scenario drives the real binary, real
attach, and real rings.

The guest runs the verified record binary directly with the
guest-matched profile and no bridge; it never invokes the
dev consumer. The host binds the retained seal (binary plus
three channel objects plus profile), the locked guest
kernel, and the pinned-guest oracle fixture before boot,
and the guest re-verifies the bytes it actually uses.
"""

import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "stress-consumer"))

import candidate_pins as pins  # noqa: E402
from consume import parse_oracle_log, scripted_expectation
from evidence_retention import (VerifiedExports, expected_from_verified,
                                retain_failure, snapshot_exports)
from export_validation import validate_lifecycle_exports
import guest_oracle  # noqa: E402
from test_attempt_capture import evidence
from test_bundle import check_report
from test_record3 import (_events, check_capture_session,
                          check_lifetimes, check_oracle_slice)
from vm_boot import cleanup, guest_exec_command

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TESTS = os.path.join(REPO, "tests")
ARM_ENV = "MEMVEIL_VM_LIFECYCLE"
FAULTS_TIMEOUT = 1500

# Retained seal this gate binds: every digest is re-checked
# against the named files before boot; drift refuses. The
# expected values live in candidate_pins (the single pin
# file for the repeat runners); the object and profile
# pins also match the committed fixtures, cross-checked
# by the unarmed suite.

# Locked guest kernel, mirrored from the frozen
# tests/vm/kernels.lock.json row "7.0": the vng version tag
# boots it, the vmlinuz sha and the modules manifest sha
# verify its cache before any boot.
EXPECT_RELEASE = "7.0.14-070014-generic"
VNG_TAG = "v7.0.14"
VMLINUZ_SHA256 = "3d3d50d77364ff616ddeae0508c68f74501afdee9" \
    "679682ce3bf59edba5b4aca"
MODULES_MANIFEST_SHA256 = "921ffc5864bff7d52b128f907d8f439" \
    "9e422f773f4f66e7798297b6f9bf5ffdb"

# Guest-matched profile for the record legs: the shipped
# 7.0-reference doc, digest-pinned. Record admits all three
# channels under it through live-interface verification on
# the pinned guest; the decision string below is what the
# faults judge expects.
PROFILE_REL = os.path.join(
    "profiles", "linux-x86_64-7.0-reference.json")
PROFILE_ID = "linux-x86_64-7.0-reference"
# Reviewed profile doc pin (checkout bytes, seal-independent
# owner like the battery's): must equal the seal's profile
# member, enforced by the pin cross-check test.
PROFILE_SHA256 = "9cce54cd23d6310bf617cc3689045f134" \
    "748e9806d9c397cad5c5cc0a2523a27"
PROFILE_DECISION = ("candidate linux-x86_64-7.0-reference: "
                    "live interfaces verified "
                    "(profile unvalidated)")

CAPTURES = ("f3a", "f3b", "f5a", "f5b", "f5c", "f6")
FLOOD_OPS = 300


def sha_file(path):
    """SHA-256 of a file, streamed."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def seal_pins():
    """The retained seal this gate binds, as a pins dict."""
    return pins.seal_pins()


def verify_seal(candidate_path, bundle_path, pins=None):
    """Verify one retained seal from explicit paths, fully.

    Checks the manifest digest, schema, source and tree,
    the bundle size and hash, then opens the tarball and
    checks the inner manifest plus the five member hashes
    this gate runs (binary, three channel objects, bound
    profile). Returns the binding dict the run carries. Any
    absence, drift, or mix refuses with a precise reason.
    """
    pins = pins or seal_pins()
    if not candidate_path or not os.path.isfile(candidate_path):
        raise ValueError("candidate manifest missing: %r"
                         % (candidate_path,))
    if sha_file(candidate_path) != pins["candidate_sha256"]:
        raise ValueError("candidate manifest digest drift: %s"
                         % candidate_path)
    try:
        with open(candidate_path) as handle:
            manifest = json.load(handle)
    except ValueError as exc:
        raise ValueError("candidate manifest unparsable: %s (%s)"
                         % (candidate_path, exc))
    if manifest.get("schema") != pins["schema"]:
        raise ValueError("candidate schema drift: %r"
                         % manifest.get("schema"))
    source = manifest.get("source", {})
    if source.get("commit") != pins["source_commit"] \
            or source.get("tree") != pins["source_tree"]:
        raise ValueError("candidate source drift: %r" % (source,))
    if manifest.get("bundle_manifest_sha256") \
            != pins["bundle_manifest_sha256"]:
        raise ValueError("candidate bundle manifest drift")
    files = manifest.get("files", {})
    for name, want in pins["files"].items():
        if files.get(name) != want:
            raise ValueError("candidate file drift: %s" % name)
    bundle = None
    for entry in manifest.get("artifacts", []):
        if entry.get("name") == "bundle.tar.gz":
            bundle = entry
    if bundle is None:
        raise ValueError("candidate bundle entry missing")
    if bundle.get("sha256") != pins["bundle_sha256"] \
            or str(bundle.get("size")) != str(pins["bundle_size"]):
        raise ValueError("candidate bundle entry drift")
    if not bundle_path or not os.path.isfile(bundle_path):
        raise ValueError("candidate bundle missing: %r" % (bundle_path,))
    if sha_file(bundle_path) != pins["bundle_sha256"]:
        raise ValueError("candidate bundle bytes drift")
    if os.path.getsize(bundle_path) != pins["bundle_size"]:
        raise ValueError("candidate bundle size drift")
    try:
        archive = tarfile.open(bundle_path, "r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("candidate bundle unreadable: %s" % exc)
    try:
        members = {m.name: m for m in archive.getmembers()
                   if m.isfile()}
        inner = members.get("bundle/MANIFEST.json")
        if inner is None:
            raise ValueError("candidate bundle lacks inner manifest")
        got = hashlib.sha256(
            archive.extractfile(inner).read()).hexdigest()
        if got != pins["bundle_manifest_sha256"]:
            raise ValueError("candidate inner manifest drift")
        for name, want in pins["files"].items():
            member = members.get("bundle/" + name)
            if member is None:
                raise ValueError("candidate bundle lacks %s" % name)
            got = hashlib.sha256(
                archive.extractfile(member).read()).hexdigest()
            if got != want:
                raise ValueError("candidate bundle member drift: %s"
                                 % name)
    except (tarfile.TarError, OSError, KeyError) as exc:
        raise ValueError("candidate bundle member unreadable: %s" % exc)
    finally:
        archive.close()
    return {
        "manifest_sha256": pins["candidate_sha256"],
        "schema": manifest["schema"],
        "source": {"commit": pins["source_commit"],
                   "tree": pins["source_tree"]},
        "bundle_manifest_sha256": pins["bundle_manifest_sha256"],
        "files": dict(pins["files"]),
        "bundle": {"sha256": pins["bundle_sha256"],
                   "size": pins["bundle_size"]},
    }


def pinned_lock_entry(repo):
    """The frozen kernel-lock row this gate boots."""
    path = os.path.join(repo, "tests", "vm", "kernels.lock.json")
    try:
        with open(path) as handle:
            lock = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("kernel lock unreadable: %s" % exc)
    for entry in lock.get("kernels", []):
        if entry.get("id") == "7.0":
            return entry
    raise ValueError("kernel lock lacks row 7.0")


def verify_kernel_lock(repo):
    """Guest-kernel binding cross-checked against the lock."""
    entry = pinned_lock_entry(repo)
    source = entry.get("source", {})
    binding = {
        "row": "7.0",
        "vng_tag": source.get("vng_version"),
        "release": entry.get("release"),
        "vmlinuz_sha256": source.get("vmlinuz_sha256"),
        "modules_manifest_sha256": source.get(
            "modules_manifest_sha256"),
    }
    if binding["vng_tag"] != VNG_TAG:
        raise ValueError("guest vng tag drift: %r"
                         % binding["vng_tag"])
    if binding["release"] != EXPECT_RELEASE:
        raise ValueError("guest release drift: %r"
                         % binding["release"])
    if binding["vmlinuz_sha256"] != VMLINUZ_SHA256:
        raise ValueError("guest vmlinuz pin drift")
    if binding["modules_manifest_sha256"] \
            != MODULES_MANIFEST_SHA256:
        raise ValueError("guest modules pin drift")
    return binding


def verify_oracle(ko_path=None, provenance_path=None):
    """Verify the pinned-guest oracle fixture; return its binding.

    Re-verifies the fixture bytes (digest, size, receipt,
    exact vermagic parsed from the bytes) and stamps the
    digest, the vermagic, and the live-BTF identity pin. The
    guest enforces the digest before a normal load, never
    forced; drift refuses before boot.
    """
    guest_oracle.verify_fixture(ko_path, provenance_path)
    return {
        "ko": ko_path or guest_oracle.FIXTURE_KO,
        "ko_sha256": guest_oracle.KO_SHA256,
        "ko_vermagic": guest_oracle.GUEST_VERMAGIC,
        "btf_sha256": guest_oracle.GUEST_BTF_SHA256,
        "guest_release": guest_oracle.GUEST_RELEASE,
        "ko_provenance_sha256": sha_file(
            provenance_path or guest_oracle.FIXTURE_PROVENANCE),
    }


def verify_profile(repo, bundle_path):
    """Verify the bound profile member plus its reviewed doc.

    The seal member must parse and name the bound profile
    id, and its bytes must equal the reviewed checkout doc
    byte for byte; the doc itself must carry the pinned id
    and digest. Returns the profile binding.
    """
    doc_path = os.path.join(repo, PROFILE_REL)
    try:
        with open(doc_path) as handle:
            doc = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("bound profile unreadable: %s" % exc)
    if doc.get("profile_id") != PROFILE_ID:
        raise ValueError("bound profile id drift: %r"
                         % doc.get("profile_id"))
    if sha_file(doc_path) != PROFILE_SHA256:
        raise ValueError("bound profile digest drift")
    try:
        archive = tarfile.open(bundle_path, "r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("candidate bundle unreadable: %s" % exc)
    try:
        member = archive.getmember(
            "bundle/profiles/linux-x86_64-7.0-reference.json")
        if not member.isfile():
            raise ValueError("bound profile member not a file")
        member_bytes = archive.extractfile(member).read()
    except (KeyError, tarfile.TarError, OSError) as exc:
        raise ValueError("bound profile member unreadable: %s" % exc)
    finally:
        archive.close()
    try:
        member_doc = json.loads(member_bytes.decode("utf-8"))
    except ValueError as exc:
        raise ValueError("bound profile member unparsable: %s" % exc)
    if member_doc.get("profile_id") != PROFILE_ID:
        raise ValueError("bound profile member id drift: %r"
                         % member_doc.get("profile_id"))
    with open(doc_path, "rb") as handle:
        if handle.read() != member_bytes:
            raise ValueError("bound profile member differs from "
                             "the reviewed profile doc")
    return {"sha256": PROFILE_SHA256, "profile_id": PROFILE_ID}


def verify_faults_inputs(repo, candidate_path, bundle_path):
    """Verify every sealed faults input; return the binding.

    The retained seal (binary, three channel objects, bound
    profile), the locked guest kernel, and the pinned-guest
    oracle fixture are each re-hashed against their pins;
    any drift refuses before boot.
    """
    seal = verify_seal(candidate_path, bundle_path)
    files = seal["files"]
    return {
        "candidate": seal,
        "objects": {
            "lc": {"sha256": files[
                "bpf/swiotlb_lifecycle.bpf.o"]},
            "cp": {"sha256": files[
                "bpf/swiotlb_copy.bpf.o"]},
            "attempt": {"sha256": files[
                "bpf/swiotlb_attempt.bpf.o"]},
        },
        "binary": {"sha256": files["bin/memveil"]},
        "profile": verify_profile(repo, bundle_path),
        "oracle": verify_oracle(),
        "guest": verify_kernel_lock(repo),
    }


def check_faults_identity(ident, binding, files):
    """Recheck the exported guest identity host-side.

    Returns a reason list (empty ok): the booted release
    and the live BTF bytes must equal the pinned
    expectations, every measured input digest must equal
    the manifest-bound bytes, and the exported profile must
    name the bound id with the bound bytes. Independent of
    the guest's own gate.
    """
    bad = []
    if ident.get("release") != binding["guest"]["release"]:
        bad.append("guest booted release %r, expected %r"
                   % (ident.get("release"),
                      binding["guest"]["release"]))
    if ident.get("btf_sha256") != \
            binding["oracle"]["btf_sha256"]:
        bad.append("guest live BTF differs from the pinned bytes")
    digests = ident.get("digests", {})
    oracle = binding.get("oracle", {})
    if digests.get("ko") != oracle.get("ko_sha256"):
        bad.append("guest measured oracle bytes differ from "
                   "the pinned fixture")
    objects = binding.get("objects", {})
    for channel in ("lc", "cp", "attempt"):
        if digests.get(channel) != objects.get(
                channel, {}).get("sha256"):
            bad.append("guest measured %s bytes differ from "
                       "the seal" % channel)
    if digests.get("binary") != binding.get(
            "binary", {}).get("sha256"):
        bad.append("guest measured binary bytes differ from "
                   "the seal")
    profile = binding.get("profile", {})
    if digests.get("profile") != profile.get("sha256"):
        bad.append("guest measured profile bytes differ from "
                   "the bound profile")
    try:
        exported = json.loads(
            files["profile.json"].read_text())
    except (KeyError, ValueError, OSError) as exc:
        return bad + ["profile export unreadable: %s" % exc]
    if exported.get("profile_id") != profile.get("profile_id"):
        bad.append("exported profile id %r"
                   % exported.get("profile_id"))
    try:
        if sha_file(str(files["profile.json"])) != \
                profile.get("sha256"):
            bad.append("exported profile bytes differ from "
                       "the bound profile")
    except OSError as exc:
        bad.append("exported profile unreadable: %s" % exc)
    return bad


def snapshot_faults_exports(tmp, names):
    """Snapshot the exact export inventory with sidecar hashes."""
    export = Path(tmp) / "export"
    try:
        have = {p.name for p in export.iterdir()}
    except OSError as exc:
        raise ValueError("export unreadable: %s" % exc)
    want = {"faults-%s" % n for n in names}
    want |= {"faults-%s.sha256" % n for n in names}
    assert have == want, \
        "export inventory drift: %s" % sorted(have ^ want)
    return snapshot_exports(tmp, "faults", names)


def verify_faults_exports(tmp, names, binding):
    """Check the exact exports plus schemas plus identity."""
    got, verified = snapshot_faults_exports(tmp, names)
    # Identity and the exported profile carry
    # faults-specific binding checks below; retention
    # owns their shared shape, the gate their pins.
    validate_lifecycle_exports(
        {name: path for name, path in got.items()
         if name not in ("identity.json", "profile.json")},
        "faults")
    ident = json.loads(got["identity.json"].read_text())
    bad = check_faults_identity(ident, binding, got)
    assert not bad, "; ".join(bad)
    return VerifiedExports(got, verified)


def boot_faults_guest(binding, candidate_path, bundle_path):
    """Boot the pinned guest once for the sealed faults flow."""
    from test_attempt_capture import gate_prefix
    from harness_env import check_harness_versions
    from kernel_matrix import verify_entry_cache
    from vm_process import run_owned_guest
    sys.path.insert(0, TESTS)
    from support.candidate_input import load
    prefix, env = gate_prefix()
    harness = check_harness_versions(prefix[-1])
    lock_dir = Path(REPO) / "build" / "vm"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lease = (lock_dir / "suite.lock").open("a+")
    try:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lease.close()
        raise ValueError("VM suite lease already owned")
    try:
        entry = pinned_lock_entry(REPO)
        live = verify_kernel_lock(REPO)
        if live != binding["guest"]:
            raise ValueError("kernel lock changed after binding")
        home = os.path.expanduser("~")
        ok, why, ref = verify_entry_cache(home, entry)
        if not ok:
            raise ValueError("pinned guest cache not ready: %s" % why)
        selected = load()
        if selected is None:
            raise ValueError("candidate env missing for the guest")
        if selected.manifest_path \
                != Path(candidate_path).absolute() \
                or selected.bundle \
                != Path(bundle_path).absolute():
            raise ValueError("candidate env names files outside "
                             "the verified binding")
    except BaseException:
        lease.close()
        raise
    tmp = Path(tempfile.mkdtemp(prefix="vmgate-faults-"))
    work = "/tmp/vmgate-work"
    export = tmp / "export"
    export.mkdir()
    from capture_durability import check_shell_inert_path
    # The export reaches the launcher command raw, so its
    # spelling is gated before the boot is assembled.
    check_shell_inert_path(export, "export path")
    cmd = prefix + ["--run", VNG_TAG, "-m", "6G",
                    "--append", "swiotlb=force",
                    "--disable-microvm", "--network", "user",
                    "--qemu-opts=-cpu host",
                    "--qemu-opts=-device pcnet,netdev=pcnet0"
                    " -netdev user,id=pcnet0,net=10.0.3.0/24",
                    "--rwdir=/tmp/export=%s" % (export,),
                    "--exec",
                    guest_exec_command("faults", work, REPO,
                                       selected)]
    try:
        proc = run_owned_guest(cmd, timeout=FAULTS_TIMEOUT)
        (tmp / "harness.json").write_text(json.dumps(
            harness, sort_keys=True) + "\n")
    except subprocess.TimeoutExpired as exc:
        (tmp / "timeout.json").write_text(json.dumps(
            dict(timeout=FAULTS_TIMEOUT, status="FAIL")) + "\n")
        print("timed-out gate artifacts kept at %s" % tmp)
        raise
    finally:
        lease.close()
    return tmp, proc


def _slice(events, window):
    return [e for e in events
            if window[0] <= int(e["ts_ns"]) <= window[1]]


def _detail(events):
    return [e for e in events if e["kind"] in (
        "bounce_attempt", "map_result", "unmap",
        "sync_request", "copy")]


def check_flood_slice(events, want, tag):
    """Exact scripted-flood multisets plus generation pairing."""
    bad = []
    kinds = {}
    for event in events:
        kinds.setdefault(event["kind"], []).append(event)
    maps = kinds.get("map_result", [])
    unmaps = kinds.get("unmap", [])
    syncs = kinds.get("sync_request", [])
    copies = kinds.get("copy", [])
    attempts = kinds.get("bounce_attempt", [])
    if len(maps) != len(want["maps"]):
        bad.append("%s: want %d maps, got %d"
                   % (tag, len(want["maps"]), len(maps)))
    if len(unmaps) != len(want["unmaps"]):
        bad.append("%s: want %d unmaps, got %d"
                   % (tag, len(want["unmaps"]), len(unmaps)))
    want_syncs = want["syncs_dev"] + want["syncs_cpu"]
    if len(syncs) != len(want_syncs):
        bad.append("%s: want %d syncs, got %d"
                   % (tag, len(want_syncs), len(syncs)))
    if len(copies) != len(want["bounces"]):
        bad.append("%s: want %d copies, got %d"
                   % (tag, len(want["bounces"]), len(copies)))
    if len(attempts) != len(want["maps"]):
        bad.append("%s: want %d attempts, got %d"
                   % (tag, len(want["maps"]), len(attempts)))
    if sorted(int(e["data"]["mapped_bytes"]) for e in maps
              ) != sorted(s for s, _, _ in want["maps"]):
        bad.append("%s: map sizes drift" % tag)
    if any(not e["data"]["success"] for e in maps):
        bad.append("%s: map failure in flood" % tag)
    gens = [e["data"]["wire_generation"] for e in maps]
    if any(g in (None, "0") for g in gens):
        bad.append("%s: map gen unassigned" % tag)
    if len(set(gens)) != len(maps):
        bad.append("%s: maps share gen" % tag)
    bad += check_lifetimes(maps, unmaps, tag, True)
    if sorted(int(e["data"]["length"]) for e in syncs
              ) != sorted(req for req, _ in want_syncs):
        bad.append("%s: sync lengths drift" % tag)
    for e in syncs:
        if (e["data"]["offset_known"],
                e["data"]["offset"]) != (False, None):
            bad.append("%s: sync offset %r" % (tag, e))
            break
    want_todev = sorted(req for todev, req, _ in
                        want["bounces"] if todev == 1)
    want_tocpu = sorted(req for todev, req, _ in
                        want["bounces"] if todev == 0)
    got_todev = sorted(int(e["data"]["bytes"]) for e in copies
                       if e["data"]["direction"]
                       == "original_to_bounce")
    got_tocpu = sorted(int(e["data"]["bytes"]) for e in copies
                       if e["data"]["direction"]
                       == "bounce_to_original")
    if got_todev != want_todev:
        bad.append("%s: to-device copies drift" % tag)
    if got_tocpu != want_tocpu:
        bad.append("%s: to-cpu copies drift" % tag)
    if sorted(int(e["data"]["requested_bytes"])
              for e in attempts
              ) != sorted(s for s, _, _ in want["maps"]):
        bad.append("%s: attempt bytes drift" % tag)
    return bad


def check_cut_slice(events, ops_logged, tag):
    """Signal-cut prefix: strict subset, sane pairing."""
    bad = []
    kinds = {}
    for event in events:
        kinds.setdefault(event["kind"], []).append(event)
    attempts = kinds.get("bounce_attempt", [])
    if not 0 < len(attempts) <= ops_logged:
        bad.append("%s: attempts %d vs %d logged"
                   % (tag, len(attempts), ops_logged))
    maps = kinds.get("map_result", [])
    unmaps = kinds.get("unmap", [])
    if maps and not 0 < len(maps) <= ops_logged:
        bad.append("%s: maps %d vs %d logged"
                   % (tag, len(maps), ops_logged))
    bad += check_lifetimes(maps, unmaps, tag, False)
    for e in kinds.get("sync_request", []):
        if (e["data"]["offset_known"],
                e["data"]["offset"]) != (False, None):
            bad.append("%s: sync offset %r" % (tag, e))
            break
    return bad


def check_error_session(events, raw, session, tag,
                      expect_decision=None):
    """Honest error session: claims verified, not echoed.

    The session must be finalized with the error end
    reason under the admitted profile decision, and its
    committed accounting (bytes, line count, digest,
    sequence bounds) must match the kept events byte for
    byte; the kept events must be a nonzero 0-based
    prefix of the session's own id.
    """
    bad = []
    capture = session["capture"]
    if capture["finalized"] is not True:
        bad.append("%s: capture not finalized" % tag)
    if capture.get("end_reason") != "error":
        bad.append("%s: end_reason %r want 'error'"
                   % (tag, capture.get("end_reason")))
    decision = evidence(session, "profile.decision")
    want_decision = ("candidate record3-ephemeral: "
                     "bindings hold (profile unvalidated)") \
        if expect_decision is None else expect_decision
    if decision != want_decision:
        bad.append("%s: profile decision %r" % (tag, decision))
    integrity = capture["integrity"]
    if integrity.get("algorithm") != "sha256":
        bad.append("%s: integrity algorithm %r"
                   % (tag, integrity.get("algorithm")))
    if len(raw) != int(integrity["events_bytes"]):
        bad.append("%s: events bytes %d != integrity %s"
                   % (tag, len(raw),
                      integrity["events_bytes"]))
    if hashlib.sha256(raw).hexdigest() != \
            integrity["events_sha256"]:
        bad.append("%s: events digest mismatch" % tag)
    if len(events) != int(integrity["line_count"]):
        bad.append("%s: event lines %d != integrity %s"
                   % (tag, len(events),
                      integrity["line_count"]))
    if not events:
        bad.append("%s: no events kept" % tag)
        return bad
    seqs = [int(event["seq"]) for event in events]
    if seqs != list(range(len(events))):
        bad.append("%s: event seq not a 0-based prefix"
                   % tag)
    if str(integrity["first_seq"]) != "0":
        bad.append("%s: integrity first_seq %r"
                   % (tag, integrity["first_seq"]))
    if str(integrity["last_seq"]) != str(len(events) - 1):
        bad.append("%s: integrity last_seq %r"
                   % (tag, integrity["last_seq"]))
    sids = {event["session_id"] for event in events}
    if sids != {session["session_id"]}:
        bad.append("%s: session ids %r" % (tag, sids))
    return bad


def judge_faults_capture(got, expect_decision=None):
    """Judge one multi-channel faults boot.

    Shared by the retired consumer entry below and the
    battery runner: truncated-object refusals, signal
    cuts, full-filesystem honesty, paced and burst
    floods, and the attach race. expect_decision
    overrides the admitted profile decision for
    rebound legs. Shape violations raise
    AssertionError (as before); returns the sorted
    reason list.
    """
    want = scripted_expectation(FLOOD_OPS, -1)
    ledger = {row["scenario"]: row for row in
              json.loads(got["faults.json"].read_text())}
    for tag, row in sorted(ledger.items()):
        assert row["settle_s"] < 30, (tag, row)
        if tag == "f3b-report":
            continue
        assert row["progs_after"] == row["progs_before"], \
            (tag, row)
        assert row["maps_after"] == row["maps_before"], \
            (tag, row)
    for tag in ("f1", "f2"):
        row = ledger[tag]
        assert row["exit"] == 3, row
        assert row["cap"] is False, row
        assert row["stderr"], row
        print("ft-%s refused: %s" % (tag, row["stderr"]))
    # f4: mid-capture fullness publishes the honest
    # error session through the released finalization
    # reserve (exit 1, finalized, outcome error). The
    # session must exist, and its error claim must
    # verify against the kept events, never merely echo
    # the ledger.
    row = ledger["f4"]
    assert row["exit"] == 1, row
    assert row["cap"] is True, row
    assert row["events_kept"] is True, row
    assert row["stderr"], row
    assert row["ready"], row
    assert row["done"] == "record: end=error outcome=error " \
        "exit=1", row
    f4_session = json.loads(
        got["f4-session.json"].read_text())
    f4_raw = got["f4-events.ndjson"].read_bytes()
    f4_events = [json.loads(line) for line in
                 f4_raw.decode("utf-8").splitlines()
                 if line.strip()]
    bad = []
    bad += check_error_session(
        f4_events, f4_raw, f4_session, "ft-f4",
        expect_decision)
    f4_ops, _, _ = parse_oracle_log(
        str(got["f4-oracle.log"]))
    assert len(f4_ops) == 2, f4_ops
    caps = {}
    for tag in CAPTURES:
        record = json.loads(
            got[f"{tag}-record.json"].read_text())
        session = json.loads(
            got[f"{tag}-session.json"].read_text())
        events = _events(got[f"{tag}-events.ndjson"])
        ops, _, _ = parse_oracle_log(
            str(got[f"{tag}-oracle.log"]))
        caps[tag] = (record, session, events, ops)
    for tag in ("f3a", "f3b"):
        record, session, events, ops = caps[tag]
        window = ledger[tag]["window"]
        rest = "3ch" if tag == "f3b" else "1ch"
        cut, _, _ = parse_oracle_log(
            str(got[f"{tag}-cut-oracle.log"]))
        assert len(ops) == FLOOD_OPS, (tag, len(ops))
        assert 0 < len(cut) < FLOOD_OPS, \
            (tag, len(cut))
        bad += check_capture_session(
            events, session, record, "ft-" + tag,
            5_000_000_000, 30_000_000_000,
            "record3-ephemeral", tag == "f3b", "signal",
            False, expect_decision=expect_decision)
        bad += check_cut_slice(_slice(events, window),
                               len(cut), "ft-" + tag)
        print("ft-%s (%s signal cut): %d/%d ops at cut" % (
            tag, rest, len(cut), len(ops)))
    report = json.loads(got["f3b-report.json"].read_text())
    # Rendered reports exit 0 on finalized captures
    # whatever the verdict (the report carries verdict
    # complete/partial instead); the pre-cutover exit-4
    # expectation never held on this product and
    # contradicts check_report's rendered-exit demand.
    assert ledger["f3b-report"]["exit"] == 0, ledger
    bad += check_report(
        report, caps["f3b"][2],
        {"report_exit": ledger["f3b-report"]["exit"]},
        "ft-f3b-r", False)
    for tag in ("f5a", "f5b"):
        record, session, events, ops = caps[tag]
        window = ledger[tag]["window"]
        assert len(ops) == FLOOD_OPS, (tag, len(ops))
        bad += check_capture_session(
            events, session, record, "ft-" + tag,
            100_000_000_000, 150_000_000_000,
            "record3-ephemeral", tag == "f5b",
            expect_decision=expect_decision)
        sl = _slice(events, window)
        kinds = {e["kind"] for e in sl}
        if tag == "f5a":
            assert not (kinds & {"map_result", "unmap",
                                 "sync_request", "copy"}), \
                (tag, kinds)
            got_sizes = sorted(
                int(e["data"]["requested_bytes"]) for e in sl
                if e["kind"] == "bounce_attempt")
            assert got_sizes == sorted(
                s for s, _, _ in want["maps"]), tag
        else:
            bad += check_flood_slice(sl, want, "ft-" + tag)
    a_sizes = sorted(
        int(e["data"]["requested_bytes"]) for e in _slice(
            caps["f5a"][2], ledger["f5a"]["window"])
        if e["kind"] == "bounce_attempt")
    b_sizes = sorted(
        int(e["data"]["requested_bytes"]) for e in _slice(
            caps["f5b"][2], ledger["f5b"]["window"])
        if e["kind"] == "bounce_attempt")
    assert a_sizes == b_sizes, "1ch/3ch attempt drift"
    print("ft-f5: 1ch/3ch attempt streams identical, "
          "%d floods exact" % len(a_sizes))
    record, session, events, ops = caps["f5c"]
    window = ledger["f5c"]["window"]
    assert len(ops) == FLOOD_OPS, len(ops)
    bad += check_capture_session(
        events, session, record, "ft-f5c",
        100_000_000_000, 150_000_000_000,
        "record3-ephemeral", True, "duration", False,
        expect_decision=expect_decision)
    sl = _slice(events, window)
    kinds = {}
    for event in sl:
        kinds.setdefault(event["kind"], []).append(event)
    predicted = (len(want["maps"]) + len(want["unmaps"])
                 + len(want["syncs_dev"])
                 + len(want["syncs_cpu"])
                 + len(want["bounces"])
                 + len(want["maps"]))
    loss = int(session["quality"]["detail"]["loss_count"])
    buckets = dict(re.findall(
        r"([a-z_]+)=\((\d+)\)",
        session["quality"]["detail"]["reason"]))
    assert buckets, session["quality"]["detail"]["reason"]
    for key, value in buckets.items():
        if key != "duration_omitted":
            assert value == "0", (key, buckets)
    assert buckets.get("duration_omitted", "0") == str(
        loss), buckets
    ambient = [e for e in _detail(events)
               if not window[0] <= int(e["ts_ns"])
               <= window[1]]
    total = len(_detail(events)) + loss
    assert total == predicted + len(ambient), (
        len(_detail(events)), loss, predicted,
        len(ambient))
    if len(kinds.get("map_result", [])) > len(want["maps"]):
        bad.append("ft-f5c: maps exceed prediction")
    if len(kinds.get("copy", [])) > len(want["bounces"]):
        bad.append("ft-f5c: copies exceed prediction")
    bad += check_lifetimes(kinds.get("map_result", []),
                           kinds.get("unmap", []),
                           "ft-f5c", False)
    print("ft-f5c: burst %d recorded + %d omitted == "
          "predicted + ambient" % (
              len(_detail(events)), loss))
    record, session, events, ops = caps["f6"]
    window = ledger["f6"]["window"]
    assert len(ops) == 2, ops
    assert sorted(e["requested"] for e in ops.values()
                  ) == [1024, 4096], ops
    bad += check_capture_session(
        events, session, record, "ft-f6",
        40_000_000_000, 90_000_000_000,
        "record3-ephemeral",
        expect_decision=expect_decision)
    start = int(session["capture"]["window"]["start_ns"])
    early = [e for e in _detail(events)
             if int(e["ts_ns"]) < start]
    assert not early, "pre-window records: %r" % early[:3]
    bad += check_oracle_slice(_slice(events, window),
                              "ft-f6")
    ambient = [e for e in _detail(events)
               if not window[0] <= int(e["ts_ns"])
               <= window[1]]
    bad += check_lifetimes(
        [e for e in events if e["kind"] == "map_result"],
        [e for e in ambient if e["kind"] == "unmap"],
        "ft-f6-amb", False)
    print("ft-f6: attach race clean, oracle slice exact, "
          "%d ambient" % len(ambient))
    return sorted(bad)


def _faults_boot_seams(monkeypatch, selected):
    monkeypatch.syspath_prepend(TESTS)
    monkeypatch.setattr('test_attempt_capture.gate_prefix',
                        lambda: (['vng'], {}))
    monkeypatch.setattr('harness_env.check_harness_versions',
                        lambda vng: {})
    monkeypatch.setattr('kernel_matrix.verify_entry_cache',
                        lambda home, entry: (True, 'cached',
                                             '/fake/ref'))
    monkeypatch.setattr('support.candidate_input.load',
                        lambda: selected)


def test_boot_faults_guest_rewritten_tmpdir_refused(tmp_path,
                                                    monkeypatch):
    import tempfile
    from types import SimpleNamespace
    from unittest import mock
    manifest = tmp_path / 'candidate.json'
    manifest.write_text('{}')
    bundle = tmp_path / 'bundle.tar.gz'
    bundle.write_bytes(b'fake')
    selected = SimpleNamespace(
        manifest_path=manifest.absolute(),
        bundle=bundle.absolute(), digest='f' * 64)
    _faults_boot_seams(monkeypatch, selected)
    hostile = tmp_path / 't"mp'
    hostile.mkdir()
    monkeypatch.setenv('TMPDIR', str(hostile))
    monkeypatch.setattr(tempfile, 'tempdir', None)
    binding = {'guest': verify_kernel_lock(REPO)}
    with mock.patch('vm_process.run_owned_guest') as spawned:
        with pytest.raises(ValueError, match='launcher shell'):
            boot_faults_guest(binding, str(manifest), str(bundle))
    assert spawned.call_count == 0


def test_boot_faults_guest_honest_tmpdir_reaches_boot(tmp_path,
                                                      monkeypatch):
    from types import SimpleNamespace
    from unittest import mock
    manifest = tmp_path / 'candidate.json'
    manifest.write_text('{}')
    bundle = tmp_path / 'bundle.tar.gz'
    bundle.write_bytes(b'fake')
    selected = SimpleNamespace(
        manifest_path=manifest.absolute(),
        bundle=bundle.absolute(), digest='f' * 64)
    _faults_boot_seams(monkeypatch, selected)
    binding = {'guest': verify_kernel_lock(REPO)}
    with mock.patch('vm_process.run_owned_guest') as spawned:
        spawned.side_effect = ValueError('sentinel-reached-boot')
        with pytest.raises(ValueError,
                           match='sentinel-reached-boot'):
            boot_faults_guest(binding, str(manifest), str(bundle))
    assert spawned.call_count == 1


def test_faults_multi_channel():
    if os.environ.get(ARM_ENV) != "1":
        pytest.skip(
            "sealed faults gate needs %s=1 with the retained "
            "seal named" % ARM_ENV)
    candidate_path = os.environ.get("MV_CANDIDATE_MANIFEST", "")
    bundle_path = os.environ.get("MV_BUNDLE_TARBALL", "")
    if not candidate_path or not bundle_path:
        pytest.fail("armed but the retained seal is unnamed: set "
                    "MV_CANDIDATE_MANIFEST and MV_BUNDLE_TARBALL")
    try:
        binding = verify_faults_inputs(
            REPO, candidate_path, bundle_path)
    except (ValueError, OSError) as exc:
        pytest.fail("armed but %s" % exc)
    tmp = None
    try:
        tmp, proc = boot_faults_guest(
            binding, candidate_path, bundle_path)
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        names = ["identity.json", "profile.json", "faults.json",
                 "f4-oracle.log", "f4-session.json",
                 "f4-events.ndjson", "f3b-report.json",
                 "f3a-cut-oracle.log", "f3b-cut-oracle.log"]
        for tag in CAPTURES:
            names += [f"{tag}-record.json", f"{tag}-session.json",
                      f"{tag}-events.ndjson", f"{tag}-oracle.log"]
        got = verify_faults_exports(tmp, names, binding)
        expected = expected_from_verified(got, "faults")
        bad = judge_faults_capture(
            got, expect_decision=PROFILE_DECISION)
        assert not bad, "\n".join(bad)
    except Exception:
        retain_failure(tmp, "faults")
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp, "faults", expected=expected)
