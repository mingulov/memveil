#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Durable swap check for the candidate seal pins.

After the pin-file swap (the candidate_pins constants
replaced with the new seal's values and the Aya fixtures
refreshed), this check verifies the swap against the new
seal files through the DEFAULT guards: the stress
candidate binding, the faults seal gate, the bound-profile
match (sealed member versus the checkout doc, the same
match the faults preflight enforces, bound by digest on
the staged bytes after materialization), and battery
materialization. Both seal paths are REQUIRED: a missing
manifest or bundle is a hard failure, never a skip.
Standalone, from the repo root:
`python3 tests/vm/test_seal_swap.py [manifest bundle]`
(defaults to the checkout's dist/ seal; exit 0 iff the
default pins verify it). The pytest legs below prove the
check itself against a committed synthetic seal fixture,
hermetically (no dist/, no boot): swapped pins accept the
fixture through all four default guards, unswapped pins
refuse it, tampered copies refuse under swapped pins,
stale checkout profiles refuse under swapped pins,
tampered staging refuses under swapped pins, absent
paths fail instead of skipping, and unwritable scratch
fails clean with no traceback.
"""

import gzip
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "stress-consumer"))

import battery_core as core  # noqa: E402
import candidate_pins as pins  # noqa: E402
import stress_core as score  # noqa: E402
import test_faults as faults  # noqa: E402

REPO = faults.REPO
DIST_MANIFEST = os.path.join(REPO, "dist", "candidate.json")
DIST_BUNDLE = pins.dist_bundle_tarball(REPO)
FIXTURE_MANIFEST = os.path.join(
    REPO, "tests", "vm", "fixtures", "swap-proof", "candidate.json")
FIXTURE_BUNDLE = os.path.join(
    REPO, "tests", "vm", "fixtures", "swap-proof", "bundle.tar.gz")
# The one manifest entry the pins bind. The real seal
# carries three profiles/* entries plus a docs page; only
# this member is pinned, so the swap reads exactly it.
PROFILE_MEMBER = "profiles/linux-x86_64-7.0-reference.json"
FIXTURE_MEMBERS = ("bin/memveil", "bpf/swiotlb_attempt.bpf.o",
                   "bpf/swiotlb_copy.bpf.o",
                   "bpf/swiotlb_lifecycle.bpf.o", PROFILE_MEMBER)


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sealed_profile_member(bundle_path):
    """The bound profile member bytes from one seal bundle.

    Reads the pinned member straight out of the tarball.
    The checker no longer re-reads the bundle after
    staging (disk bytes re-read that late were never
    verified); the isolated-profile legs below use this
    to stage a repo whose doc equals the seal member.
    Any unreadable bundle or member raises ValueError;
    nothing here skips.
    """
    try:
        archive = tarfile.open(bundle_path, "r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("candidate bundle unreadable: %s" % exc)
    try:
        entries = archive.getmembers()
        tops = {m.name.rstrip("/").split("/")[0]
                for m in entries}
        if len(tops) != 1:
            raise ValueError(
                "candidate bundle has no single top dir")
        member = archive.getmember(
            tops.pop() + "/" + PROFILE_MEMBER)
        if not member.isfile():
            raise ValueError("bound profile member not a file")
        return archive.extractfile(member).read()
    except (KeyError, tarfile.TarError, OSError) as exc:
        raise ValueError("bound profile member unreadable: %s"
                         % exc)
    finally:
        archive.close()


def verify_swapped_seal(manifest_path, bundle_path, repo, work):
    """Verify one seal through the default guards, fully.

    Requires both seal paths, then runs the stress
    candidate binding (three sealed objects), the faults
    seal gate (all five sealed members), the faults
    profile gate (sealed member versus the checkout doc,
    before anything stages), and battery materialization
    (extract plus fixture cross-check), and finally binds
    the staged battery profile to the already-verified
    seal by hashing the staged bytes against the seal
    binding's profile digest (no bundle re-read: disk
    bytes re-read after staging were never verified),
    with default pins throughout. Returns the four
    bindings. Any absence, drift, or mix raises
    ValueError with a precise reason; nothing here
    skips.
    """
    if not manifest_path or not os.path.isfile(manifest_path):
        raise ValueError("swap seal manifest missing: %r"
                         % (manifest_path,))
    if not bundle_path or not os.path.isfile(bundle_path):
        raise ValueError("swap seal bundle missing: %r"
                         % (bundle_path,))
    stress_binding = score.verify_candidate_binding(
        manifest_path, bundle_path)
    seal_binding = faults.verify_seal(manifest_path, bundle_path)
    profile_binding = faults.verify_profile(repo, bundle_path)
    inputs = core.materialize(repo, work, manifest_path,
                              bundle_path)
    with open(inputs["profile"]["path"], "rb") as handle:
        staged_bytes = handle.read()
    staged_sha = hashlib.sha256(staged_bytes).hexdigest()
    if staged_sha != seal_binding["files"][PROFILE_MEMBER]:
        raise ValueError("staged battery profile differs from "
                         "the sealed profile member")
    return {"stress": stress_binding, "faults": seal_binding,
            "profile": profile_binding, "inputs": inputs}


def main(argv, repo=None):
    """CLI entry: verify the named seal, exit 0 iff bound.

    The repo defaults to this checkout; the
    isolated-profile legs pass a staged overlay so the
    accept leg pins fixture behavior without coupling
    to the live checkout profile state.
    """
    if len(argv) > 2:
        print("FAIL seal-swap: usage: "
              "test_seal_swap.py [manifest bundle]")
        return 1
    manifest_path = argv[0] if len(argv) > 0 else DIST_MANIFEST
    bundle_path = argv[1] if len(argv) > 1 else DIST_BUNDLE
    if repo is None:
        repo = REPO
    try:
        work = tempfile.mkdtemp(prefix="seal-swap-")
        try:
            result = verify_swapped_seal(
                manifest_path, bundle_path, repo, work)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    except (ValueError, OSError) as exc:
        print("FAIL seal-swap: %s" % exc)
        return 1
    binding = result["faults"]
    print("PASS seal-swap: %s %s source %s bundle %s/%d "
          "files %d" % (
              manifest_path, bundle_path,
              binding["source"]["commit"],
              binding["bundle"]["sha256"],
              binding["bundle"]["size"],
              len(binding["files"])))
    return 0


# -- Swap-proof fixture -------------------------------------

def pins_from_manifest(manifest_path):
    """Pin values read from one seal manifest, as a dict.

    Mirrors the pin-file swap step: every constant the
    swap replaces, sourced from the seal files. The bundle
    size entry is a JSON string in the real seal format,
    so it converts to int here (the pins carry a number).
    """
    with open(manifest_path) as handle:
        manifest = json.load(handle)
    # Real seals tag the bundle entry by role; the frozen
    # swap-proof fixture predates roles and keeps its
    # legacy name. Either identifies the bundle entry.
    entry = None
    for candidate in manifest["artifacts"]:
        if candidate.get("role") == "bundle":
            entry = candidate
    if entry is None:
        for candidate in manifest["artifacts"]:
            if candidate.get("name") == "bundle.tar.gz":
                entry = candidate
    if entry is None:
        raise ValueError("swap fixture lacks bundle entry")
    files = manifest["files"]
    return {
        "CANDIDATE_SHA256": sha_file(manifest_path),
        "CANDIDATE_SCHEMA": manifest["schema"],
        "SOURCE_COMMIT": manifest["source"]["commit"],
        "SOURCE_TREE": manifest["source"]["tree"],
        "BUNDLE_MANIFEST_SHA256":
            manifest["bundle_manifest_sha256"],
        "BUNDLE_SHA256": entry["sha256"],
        "BUNDLE_SIZE": int(entry["size"]),
        "LC_SHA256": files["bpf/swiotlb_lifecycle.bpf.o"],
        "CP_SHA256": files["bpf/swiotlb_copy.bpf.o"],
        "ATTEMPT_SHA256": files["bpf/swiotlb_attempt.bpf.o"],
        "BINARY_SHA256": files["bin/memveil"],
        "PROFILE_SHA256": files[PROFILE_MEMBER],
    }


def apply_swap(monkeypatch, values):
    """Point the default pins at the given values in place.

    The stand-in for the pin-file edit: same module
    attributes the swap rewrites, no cached copies (the
    builders read the module on every call). The
    monkeypatch fixture restores every constant after.
    """
    for attr, value in values.items():
        monkeypatch.setattr(pins, attr, value)


def committed_fixtures_match(manifest_path):
    """True when the checkout fixtures equal the seal bytes.

    Battery materialization cross-checks the sealed
    objects byte-equal with the committed Aya fixtures,
    so a refreshed checkout holds a stale fixture at that
    gate instead of passing fully. This predicate names
    which outcome the materialize legs must see.
    """
    with open(manifest_path) as handle:
        manifest = json.load(handle)
    files = manifest["files"]
    for member, fixture in (
            ("bpf/swiotlb_lifecycle.bpf.o",
             "swiotlb_lifecycle.bpf.o"),
            ("bpf/swiotlb_copy.bpf.o", "swiotlb_copy.bpf.o"),
            ("bpf/swiotlb_attempt.bpf.o",
             "swiotlb_attempt.bpf.o")):
        path = os.path.join(REPO, "tests", "vm", "fixtures",
                            "aya", fixture)
        if sha_file(path) != files[member]:
            return False
    return True


def stage_profile_repo(tmp_dir, profile_bytes):
    """A minimal repo overlay pinning the profile to given bytes.

    Carries the profile doc plus mirrors of the checkout's
    Aya fixtures and kernel lock (every repo-relative read
    below the seal paths the check performs), so the
    isolated legs pin seal behavior without coupling to
    the live checkout profile state: a profile-only swap
    leaves the accept leg's outcome to the BPF predicate
    alone.
    """
    assert core.PROFILE_REL == faults.PROFILE_REL
    assert core.PROFILE_ID == faults.PROFILE_ID
    repo = os.path.join(tmp_dir, "profile-repo")
    doc_path = os.path.join(repo, core.PROFILE_REL)
    os.makedirs(os.path.dirname(doc_path), exist_ok=True)
    with open(doc_path, "wb") as handle:
        handle.write(profile_bytes)
    for fixture in ("swiotlb_lifecycle.bpf.o",
                    "swiotlb_copy.bpf.o",
                    "swiotlb_attempt.bpf.o"):
        src = os.path.join(REPO, "tests", "vm", "fixtures",
                           "aya", fixture)
        dst = os.path.join(repo, "tests", "vm", "fixtures",
                           "aya", fixture)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)
    lock_src = os.path.join(REPO, "tests", "vm",
                            "kernels.lock.json")
    lock_dst = os.path.join(repo, "tests", "vm",
                            "kernels.lock.json")
    shutil.copyfile(lock_src, lock_dst)
    return repo


def apply_profile_companions(monkeypatch, profile_bytes):
    """Point the profile companion pins at the given bytes.

    The staged overlay's doc is verified against the
    faults and battery companion pins (seal-independent
    owners); pointing both at the staged bytes keeps the
    isolated legs green in every profile world.
    """
    digest = hashlib.sha256(profile_bytes).hexdigest()
    monkeypatch.setattr(faults, "PROFILE_SHA256", digest)
    monkeypatch.setattr(core, "PROFILE_SHA256", digest)


def build_stale_profile_seal(tmp_dir, profile_bytes, tag):
    """A self-consistent seal whose profile member is stale.

    Copies the swap-proof fixture members, swaps in the
    given profile bytes, and rebuilds the inner manifest,
    tarball, and manifest digests to match (deterministic
    bytes: PAX tar, sorted members, zeroed metadata, gzip
    mtime=0, size stored as a JSON string like the real
    seal). Source identity is minted fresh from the tag
    at runtime, so the helper carries no digests. Only
    the member-versus-doc match can refuse its output.
    """
    with tarfile.open(FIXTURE_BUNDLE, "r:gz") as archive:
        blobs = {}
        for info in archive.getmembers():
            if not info.isfile():
                continue
            assert info.name.startswith("bundle/")
            name = info.name[len("bundle/"):]
            if name == "MANIFEST.json":
                continue
            blobs[name] = archive.extractfile(info).read()
    assert sorted(blobs) == sorted(FIXTURE_MEMBERS)
    blobs[PROFILE_MEMBER] = profile_bytes
    inner = (json.dumps(
        {"files": {name: hashlib.sha256(blobs[name]).hexdigest()
                   for name in sorted(blobs)},
         "tag": tag}, sort_keys=True) + "\n").encode()
    files = dict(blobs)
    files["MANIFEST.json"] = inner
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w",
                      format=tarfile.PAX_FORMAT,
                      pax_headers={}) as archive:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo("bundle/" + name)
            info.size = len(data)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    tarball = gzip.compress(buf.getvalue(), mtime=0)
    manifest = {
        "artifacts": [{"name": "bundle.tar.gz",
                       "sha256": hashlib.sha256(
                           tarball).hexdigest(),
                       "size": str(len(tarball))}],
        "bundle_manifest_sha256": hashlib.sha256(inner).hexdigest(),
        "files": {name: hashlib.sha256(blobs[name]).hexdigest()
                  for name in sorted(blobs)},
        "schema": "memveil-candidate/2",
        "source": {
            "commit": hashlib.sha256(
                b"stale-seal:commit:" + tag.encode()
            ).hexdigest()[:40],
            "tree": hashlib.sha256(
                b"stale-seal:tree:" + tag.encode()
            ).hexdigest()[:40],
        },
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    manifest_path = os.path.join(tmp_dir, "candidate.json")
    bundle_path = os.path.join(tmp_dir, "bundle.tar.gz")
    with open(manifest_path, "wb") as handle:
        handle.write(manifest_bytes)
    with open(bundle_path, "wb") as handle:
        handle.write(tarball)
    return manifest_path, bundle_path


def test_fixture_manifest_shape():
    with open(FIXTURE_MANIFEST) as handle:
        manifest = json.load(handle)
    assert manifest["schema"] == "memveil-candidate/2"
    assert sorted(manifest["source"]) == ["commit", "tree"]
    assert len(manifest["source"]["commit"]) == 40
    assert len(manifest["source"]["tree"]) == 40
    assert sorted(manifest["files"]) == sorted(FIXTURE_MEMBERS)
    assert len(manifest["artifacts"]) == 1
    entry = manifest["artifacts"][0]
    assert entry["name"] == "bundle.tar.gz"
    assert isinstance(entry["size"], str)
    assert int(entry["size"]) == os.path.getsize(FIXTURE_BUNDLE)
    assert pins.PROFILE_MEMBER == PROFILE_MEMBER
    values = pins_from_manifest(FIXTURE_MANIFEST)
    assert type(values["BUNDLE_SIZE"]) is int
    assert values["BUNDLE_SIZE"] == os.path.getsize(
        FIXTURE_BUNDLE)


def test_swapped_pins_accept_fixture_binding(monkeypatch):
    apply_swap(monkeypatch,
               pins_from_manifest(FIXTURE_MANIFEST))
    stress_binding = score.verify_candidate_binding(
        FIXTURE_MANIFEST, FIXTURE_BUNDLE)
    assert stress_binding["source"]["commit"] == \
        pins.SOURCE_COMMIT
    assert stress_binding["bundle"]["sha256"] == \
        pins.BUNDLE_SHA256
    assert stress_binding["bundle"]["size"] == pins.BUNDLE_SIZE
    assert sorted(stress_binding["files"]) == sorted(
        pins.bpf_files())
    seal_binding = faults.verify_seal(
        FIXTURE_MANIFEST, FIXTURE_BUNDLE)
    assert seal_binding["files"] == pins.seal_files()
    assert seal_binding["bundle"]["size"] == pins.BUNDLE_SIZE


def test_swapped_pins_materialize_fixture(tmp_path,
                                          monkeypatch):
    apply_swap(monkeypatch,
               pins_from_manifest(FIXTURE_MANIFEST))
    work = str(tmp_path / "inputs")
    if not committed_fixtures_match(FIXTURE_MANIFEST):
        with pytest.raises(ValueError,
                           match="^aya fixture drift: "):
            core.materialize(REPO, work, FIXTURE_MANIFEST,
                             FIXTURE_BUNDLE)
        return
    inputs = core.materialize(REPO, work, FIXTURE_MANIFEST,
                              FIXTURE_BUNDLE)
    assert inputs["binary"]["sha256"] == pins.BINARY_SHA256
    assert inputs["lc"]["sha256"] == pins.LC_SHA256
    assert inputs["cp"]["sha256"] == pins.CP_SHA256
    assert inputs["attempt"]["sha256"] == pins.ATTEMPT_SHA256
    for key in ("binary", "lc", "cp", "attempt"):
        assert os.path.isfile(inputs[key]["path"])
    assert inputs["candidate"]["files"][
        "bin/memveil"] == pins.BINARY_SHA256


def test_swapped_pins_materialize_versioned_seal(tmp_path,
                                                  monkeypatch):
    tmp = str(tmp_path)
    blobs = {}
    for member, fixture in (
            ("bpf/swiotlb_lifecycle.bpf.o",
             "swiotlb_lifecycle.bpf.o"),
            ("bpf/swiotlb_copy.bpf.o", "swiotlb_copy.bpf.o"),
            ("bpf/swiotlb_attempt.bpf.o",
             "swiotlb_attempt.bpf.o")):
        with open(os.path.join(REPO, "tests", "vm", "fixtures",
                               "aya", fixture), "rb") as handle:
            blobs[member] = handle.read()
    blobs["bin/memveil"] = b"synthetic-versioned-binary"
    with open(os.path.join(REPO, core.PROFILE_REL),
              "rb") as handle:
        blobs[PROFILE_MEMBER] = handle.read()
    inner = (json.dumps(
        {"files": {name: hashlib.sha256(blobs[name]).hexdigest()
                   for name in sorted(blobs)}},
        sort_keys=True) + "\n").encode()
    top = "memveil-0.2.0"
    bundle_path = os.path.join(
        tmp, "memveil-0.2.0.tar.gz")
    with tarfile.open(bundle_path, "w:gz") as archive:
        files = dict(blobs)
        files["MANIFEST.json"] = inner
        for name in sorted(files):
            info = tarfile.TarInfo(top + "/" + name)
            info.size = len(files[name])
            archive.addfile(info, io.BytesIO(files[name]))
    with open(bundle_path, "rb") as handle:
        tarball = handle.read()
    manifest = {
        "artifacts": [{"role": "bundle",
                       "name": "memveil-0.2.0.tar.gz",
                       "sha256": hashlib.sha256(
                           tarball).hexdigest(),
                       "size": str(len(tarball))}],
        "bundle_manifest_sha256": hashlib.sha256(
            inner).hexdigest(),
        "files": {name: hashlib.sha256(blobs[name]).hexdigest()
                  for name in sorted(blobs)},
        "schema": "memveil-candidate/2",
        "source": {"commit": "c" * 40, "tree": "t" * 40},
    }
    manifest_path = os.path.join(tmp, "candidate.json")
    with open(manifest_path, "w") as handle:
        json.dump(manifest, handle, sort_keys=True)
    values = pins_from_manifest(manifest_path)
    assert type(values["BUNDLE_SIZE"]) is int
    assert values["BUNDLE_SIZE"] == len(tarball)
    apply_swap(monkeypatch, values)
    inputs = core.materialize(
        REPO, os.path.join(tmp, "inputs"),
        manifest_path, bundle_path)
    for member, key in (
            ("bpf/swiotlb_lifecycle.bpf.o", "lc"),
            ("bpf/swiotlb_copy.bpf.o", "cp"),
            ("bpf/swiotlb_attempt.bpf.o", "attempt"),
            ("bin/memveil", "binary")):
        assert inputs[key]["sha256"] == hashlib.sha256(
            blobs[member]).hexdigest()
        assert os.path.isfile(inputs[key]["path"])


def test_default_pins_refuse_fixture():
    with pytest.raises(ValueError,
                       match="manifest digest drift"):
        score.verify_candidate_binding(
            FIXTURE_MANIFEST, FIXTURE_BUNDLE)
    with pytest.raises(ValueError,
                       match="manifest digest drift"):
        faults.verify_seal(FIXTURE_MANIFEST, FIXTURE_BUNDLE)


def test_swapped_pins_refuse_tampered_copies(tmp_path,
                                             monkeypatch):
    apply_swap(monkeypatch,
               pins_from_manifest(FIXTURE_MANIFEST))
    tmp = str(tmp_path)
    bad_bundle = os.path.join(tmp, "tampered.tar.gz")
    shutil.copyfile(FIXTURE_BUNDLE, bad_bundle)
    with open(bad_bundle, "r+b") as handle:
        handle.seek(60)
        byte = handle.read(1)
        handle.seek(60)
        handle.write(bytes([byte[0] ^ 0xff]))
    with pytest.raises(ValueError,
                       match="bundle bytes drift"):
        score.verify_candidate_binding(
            FIXTURE_MANIFEST, bad_bundle)
    with pytest.raises(ValueError,
                       match="bundle bytes drift"):
        faults.verify_seal(FIXTURE_MANIFEST, bad_bundle)
    bad_manifest = os.path.join(tmp, "tampered.json")
    shutil.copyfile(FIXTURE_MANIFEST, bad_manifest)
    with open(bad_manifest, "r+b") as handle:
        handle.seek(60)
        byte = handle.read(1)
        handle.seek(60)
        handle.write(bytes([byte[0] ^ 0xff]))
    with pytest.raises(ValueError,
                       match="manifest digest drift"):
        score.verify_candidate_binding(
            bad_manifest, FIXTURE_BUNDLE)


def test_swapped_pins_refuse_stale_checkout_profile(tmp_path,
                                                     monkeypatch):
    doc_path = os.path.join(REPO, core.PROFILE_REL)
    with open(doc_path, "rb") as handle:
        doc = handle.read()
    member = doc + b"\n"
    assert json.loads(member.decode("utf-8"))[
        "profile_id"] == faults.PROFILE_ID
    manifest_path, bundle_path = build_stale_profile_seal(
        str(tmp_path), member, "stale-checkout-doc-0")
    apply_swap(monkeypatch,
               pins_from_manifest(manifest_path))
    reason = ("bound profile member differs from "
              "the reviewed profile doc")
    with pytest.raises(ValueError, match=reason):
        verify_swapped_seal(manifest_path, bundle_path, REPO,
                            str(tmp_path / "work"))
    with pytest.raises(ValueError, match=reason):
        faults.verify_profile(REPO, bundle_path)


def test_cli_refuses_stale_checkout_profile(tmp_path, monkeypatch,
                                            capsys):
    doc_path = os.path.join(REPO, core.PROFILE_REL)
    with open(doc_path, "rb") as handle:
        doc = handle.read()
    manifest_path, bundle_path = build_stale_profile_seal(
        str(tmp_path), doc + b"\n", "stale-checkout-doc-1")
    apply_swap(monkeypatch,
               pins_from_manifest(manifest_path))
    assert main([manifest_path, bundle_path]) == 1
    out = capsys.readouterr().out
    assert ("FAIL seal-swap: bound profile member differs "
            "from the reviewed profile doc") in out


def test_swapped_pins_refuse_tampered_staging(tmp_path,
                                              monkeypatch):
    apply_swap(monkeypatch,
               pins_from_manifest(FIXTURE_MANIFEST))
    member = sealed_profile_member(FIXTURE_BUNDLE)
    repo = stage_profile_repo(str(tmp_path), member)
    apply_profile_companions(monkeypatch, member)
    real_materialize = core.materialize

    def sabotaged(repo_arg, work, manifest_path, bundle_path):
        inputs = real_materialize(repo_arg, work, manifest_path,
                                  bundle_path)
        with open(inputs["profile"]["path"], "wb") as handle:
            handle.write(b'{"tampered": true}\n')
        return inputs

    monkeypatch.setattr(core, "materialize", sabotaged)
    if not committed_fixtures_match(FIXTURE_MANIFEST):
        # Drifted fixtures refuse mid-materialization,
        # before the sabotage runs: same per-world branch
        # as the materialize and accept legs.
        reason = "^aya fixture drift: "
    else:
        reason = ("staged battery profile differs from "
                  "the sealed profile member")
    with pytest.raises(ValueError, match=reason):
        verify_swapped_seal(FIXTURE_MANIFEST, FIXTURE_BUNDLE,
                            repo, str(tmp_path / "work"))


def test_absent_seal_hard_fails(tmp_path):
    tmp = str(tmp_path)
    gone_manifest = os.path.join(tmp, "absent.json")
    gone_bundle = os.path.join(tmp, "absent.tar.gz")
    with pytest.raises(ValueError, match="manifest missing"):
        verify_swapped_seal(gone_manifest, gone_bundle,
                            REPO, tmp)
    with pytest.raises(ValueError, match="bundle missing"):
        verify_swapped_seal(FIXTURE_MANIFEST, gone_bundle,
                            REPO, tmp)


def test_cli_absent_seal_exits_nonzero(tmp_path, capsys):
    tmp = str(tmp_path)
    gone_manifest = os.path.join(tmp, "absent.json")
    gone_bundle = os.path.join(tmp, "absent.tar.gz")
    assert main([gone_manifest, gone_bundle]) == 1
    assert "FAIL seal-swap" in capsys.readouterr().out
    assert main([FIXTURE_MANIFEST, gone_bundle]) == 1
    assert "FAIL seal-swap" in capsys.readouterr().out
    assert main([gone_manifest]) == 1
    assert "FAIL seal-swap" in capsys.readouterr().out


def test_cli_unwritable_tmpdir_fails_clean(tmp_path, monkeypatch,
                                             capsys):
    def no_tmp(*args, **kwargs):
        raise OSError("simulated unwritable scratch")
    monkeypatch.setattr(tempfile, "mkdtemp", no_tmp)
    assert main([FIXTURE_MANIFEST, FIXTURE_BUNDLE]) == 1
    out = capsys.readouterr()
    assert "FAIL seal-swap" in out.out
    assert "Traceback" not in out.err
    gone = os.path.join(str(tmp_path), "absent.json")
    assert main([gone, gone]) == 1
    out = capsys.readouterr()
    assert "FAIL seal-swap" in out.out
    assert "Traceback" not in out.err


def test_cli_usage_refuses_extra_argv(capsys):
    assert main(["a", "b", "c"]) == 1
    assert "FAIL seal-swap: usage" in capsys.readouterr().out


def test_cli_accepts_fixture_under_swapped_pins(
        tmp_path, monkeypatch, capsys):
    apply_swap(monkeypatch,
               pins_from_manifest(FIXTURE_MANIFEST))
    member = sealed_profile_member(FIXTURE_BUNDLE)
    repo = stage_profile_repo(str(tmp_path), member)
    apply_profile_companions(monkeypatch, member)
    want = 0 if committed_fixtures_match(
        FIXTURE_MANIFEST) else 1
    assert main([FIXTURE_MANIFEST, FIXTURE_BUNDLE],
                repo=repo) == want
    out = capsys.readouterr().out
    assert ("PASS seal-swap" in out) == (want == 0)
    assert ("FAIL seal-swap" in out) == (want == 1)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
