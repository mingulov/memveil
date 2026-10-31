# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline gate-kernel selection: shipped, minted, drift, refusals.

Fixture kernel trees carry controlled bytes, so every mode is
pinned without booting: a new release mints, a holding shipped
profile is used as is, drift and REQUIRE_SHIPPED are explicit,
and a foreign guest release with no shipped claim fails closed.
"""
import gzip
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate_kernel  # noqa: E402
from test_fixture_generation import generated  # noqa: F401

REPO = gate_kernel.REPO
FMT = ("name: swiotlb_bounced\nID: 382\nformat:\n"
       "\tfield:size_t size;\toffset:32;\tsize:8;\tsigned:0;\n")
REL = "9.9.0-test"


def _notes(bid):
    return (b"\x04\x00\x00\x00\x14\x00\x00\x00\x03\x00\x00\x00GNU\x00"
            + bytes.fromhex(bid))


def kernel_tree(tmp, rel=REL, btf=b"btf-bytes", bid="ab" * 20):
    root = tmp / "root"
    for path, data in {
        "proc/config.gz": gzip.compress(b"CONFIG_SWIOTLB=y\n"),
        "sys/kernel/btf/vmlinux": btf,
        gate_kernel.FMT_PATH.lstrip("/"): FMT.encode(),
        "sys/kernel/notes": _notes(bid),
        "boot/vmlinuz-" + rel: b"image-bytes",
    }.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_bytes(data)
    return root


def objects(tmp):
    out = {}
    for key in ("object", "lc_object", "cp_object"):
        p = tmp / (key + ".o")
        p.write_bytes(key.encode())
        out[key] = p
    return out


needs_build = pytest.mark.skipif(
    not all(p.is_file() for p in (gate_kernel.PROD_OBJ, gate_kernel.LC_OBJ,
                                  gate_kernel.CP_OBJ)),
    reason="needs build/bpf objects")


def test_gnu_bid_parses_kernel_notes():
    assert gate_kernel.gnu_bid(_notes("cd" * 20)) == "cd" * 20
    assert gate_kernel.gnu_bid(b"") is None


def test_measure_identity_uses_guest_rules(tmp_path):
    root = kernel_tree(tmp_path)
    ident, fmt = gate_kernel.measure_identity(REL, str(root))
    assert ident["release"] == REL
    assert ident["config_src"] == "gz"
    assert ident["config_sha"] == hashlib.sha256(
        b"CONFIG_SWIOTLB=y\n").hexdigest()
    assert ident["format_sha"] == hashlib.sha256(FMT.encode()).hexdigest()
    assert ident["image_bid"] == "ab" * 20
    assert fmt == FMT


def test_measure_identity_falls_back_to_boot_config(tmp_path):
    root = kernel_tree(tmp_path)
    (root / "proc/config.gz").unlink()
    (root / ("boot/config-" + REL)).write_bytes(b"CONFIG_X=y\n")
    ident, _ = gate_kernel.measure_identity(REL, str(root))
    assert ident["config_src"] == "file"


def _profiles(tmp, docs):
    d = tmp / "profiles"
    d.mkdir()
    names = []
    for name, doc in docs.items():
        (d / name).write_text(json.dumps(doc))
        names.append(name)
    (d / "manifest.txt").write_text("\n".join(names) + "\n")
    return d


@needs_build
def test_new_release_mints_bound_gate_profile(tmp_path):
    root = kernel_tree(tmp_path)
    sel = gate_kernel.select(REL, str(root), tmp_path / "out",
                             profiles=_profiles(tmp_path, {}),
                             host_release=REL, require_shipped=False)
    assert sel.mode == "minted"
    doc = json.loads(sel.gate_doc.read_text())
    assert doc["profile_id"] == "gate-" + REL
    assert doc["status"] == "reference-unvalidated"
    assert doc["identity"]["source"]["revision"] == REL
    ident, _ = gate_kernel.measure_identity(REL, str(root))
    assert gate_kernel.binding_drift(doc, ident, {
        "object": gate_kernel.PROD_OBJ, "lc_object": gate_kernel.LC_OBJ,
        "cp_object": gate_kernel.CP_OBJ}) == []
    assert sel.decision(sel.gate_doc) == (
        "candidate gate-%s: bindings hold (profile unvalidated)" % REL)
    sat = json.loads(sel.sat_doc.read_text())
    assert sat["profile_id"] == "saturation-candidate"
    assert sat["identity"]["source"]["revision"] == REL


@needs_build
def test_minted_profiles_pass_the_schema_validator(tmp_path):
    root = kernel_tree(tmp_path)
    sel = gate_kernel.select(REL, str(root), tmp_path / "out",
                             profiles=_profiles(tmp_path, {}),
                             host_release=REL, require_shipped=False)
    for doc in (sel.gate_doc, sel.sat_doc):
        r = subprocess.run([sys.executable, str(REPO / "tools" /
                                                "validate-schemas"),
                            "--check-profile", str(doc)],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr


@needs_build
def test_holding_shipped_profile_is_used(tmp_path):
    root = kernel_tree(tmp_path)
    ident, fmt = gate_kernel.measure_identity(REL, str(root))
    gate, _ = gate_kernel.emitter().gate_docs(ident, fmt, "linux-shipped")
    gate["status"] = "validated"
    profiles = _profiles(tmp_path, {"linux-shipped.json": gate})
    sel = gate_kernel.select(REL, str(root), tmp_path / "out",
                             profiles=profiles, host_release=REL,
                             require_shipped=True)
    assert sel.mode == "shipped"
    assert sel.gate_doc == profiles / "linux-shipped.json"
    assert sel.decision(sel.gate_doc) == (
        "validated linux-shipped: bindings hold")


@needs_build
def test_drifted_shipped_profile_mints_or_refuses(tmp_path):
    root = kernel_tree(tmp_path)
    ident, fmt = gate_kernel.measure_identity(REL, str(root))
    gate, _ = gate_kernel.emitter().gate_docs(ident, fmt, "linux-shipped")
    gate["status"] = "validated"
    profiles = _profiles(tmp_path, {"linux-shipped.json": gate})
    (root / "sys/kernel/btf/vmlinux").write_bytes(b"other btf")
    with pytest.raises(gate_kernel.GateKernelError,
                       match="REQUIRE_SHIPPED.*drift: btf"):
        gate_kernel.select(REL, str(root), tmp_path / "out",
                           profiles=profiles, host_release=REL,
                           require_shipped=True)
    sel = gate_kernel.select(REL, str(root), tmp_path / "out",
                             profiles=profiles, host_release=REL,
                             require_shipped=False)
    assert sel.mode == "minted"


@needs_build
def test_foreign_release_uses_shipped_claim_and_mints_saturation(tmp_path):
    root = kernel_tree(tmp_path)
    ident, fmt = gate_kernel.measure_identity(REL, str(root))
    gate, _ = gate_kernel.emitter().gate_docs(ident, fmt, "linux-shipped")
    gate["status"] = "validated"
    profiles = _profiles(tmp_path, {"linux-shipped.json": gate})
    sel = gate_kernel.select(REL, str(tmp_path / "absent"), tmp_path / "out",
                             profiles=profiles, host_release="9.9.1-host")
    assert sel.mode == "shipped"
    assert sel.gate_doc == profiles / "linux-shipped.json"
    sat = json.loads(sel.sat_doc.read_text())
    assert sat["profile_id"] == "saturation-candidate"
    assert sat["identity"]["source"]["revision"] == REL
    assert gate_kernel.shipped_identity(gate) == ident


@needs_build
def test_foreign_release_refuses_object_drift(tmp_path):
    root = kernel_tree(tmp_path)
    ident, fmt = gate_kernel.measure_identity(REL, str(root))
    gate, _ = gate_kernel.emitter().gate_docs(ident, fmt, "linux-shipped")
    gate["status"] = "validated"
    profiles = _profiles(tmp_path, {"linux-shipped.json": gate})
    with pytest.raises(gate_kernel.GateKernelError,
                       match="drift: object, lc_object, cp_object"):
        gate_kernel.select(REL, str(tmp_path / "absent"), tmp_path / "out",
                           objects=objects(tmp_path), profiles=profiles,
                           host_release="9.9.1-host")


def test_foreign_release_without_shipped_profile_fails_closed(tmp_path):
    with pytest.raises(gate_kernel.GateKernelError,
                       match="guest kernel 9.9.1-other"):
        gate_kernel.select("9.9.1-other", str(tmp_path), tmp_path / "out",
                           profiles=_profiles(tmp_path, {}),
                           host_release=REL)


def test_binding_drift_names_each_field(tmp_path):
    objs = objects(tmp_path)
    ident = {"release": REL, "config_src": "gz", "config_sha": "1" * 64,
             "btf_sha": "2" * 64, "format_sha": "3" * 64,
             "image_sha": "4" * 64, "image_bid": "5" * 40}
    sha = {k: hashlib.sha256(p.read_bytes()).hexdigest()
           for k, p in objs.items()}
    note = ("config=sha256:%s config_src=gz btf=sha256:%s format=sha256:%s"
            " object=sha256:%s image=sha256:%s image_bid=%s ring_bytes=1"
            " lc_object=sha256:%s lc_ring_bytes=1 cp_object=sha256:%s"
            " cp_ring_bytes=1" % ("1" * 64, "2" * 64, "3" * 64,
                                  sha["object"], "4" * 64, "5" * 40,
                                  sha["lc_object"], sha["cp_object"]))
    doc = {"identity": {"source": {"revision": REL, "note": note}}}
    assert gate_kernel.binding_drift(doc, ident, objs) == []
    objs["lc_object"].write_bytes(b"rebuilt")
    assert gate_kernel.binding_drift(doc, ident, objs) == ["lc_object"]
    doc["identity"]["source"]["revision"] = "other"
    assert gate_kernel.binding_drift(doc, ident, objs)[0] == "revision"


@needs_build
def test_narrow_test_profile_regenerates_from_its_own_bindings(generated):
    # Preserve every historical semantic field. Only the three object
    # identities vary with the independently permitted compiler build.
    path = (REPO / "tests/fixtures/capabilities/profiles-narrow-test"
            / "test-narrow-validated.json")
    checked = json.loads(path.read_text())
    assert checked["profile_id"] == "test-narrow-validated"
    assert checked["status"] == "validated"
    gate = json.loads((generated / "profile.json").read_text())
    assert gate["status"] == "reference-unvalidated"
    assert gate["profile_id"] == "test-narrow-provisional"
    assert gate["notes"].pop() == "Synthetic offline fixture; no live kernel qualification."
    gate["profile_id"] = checked["profile_id"]
    gate["status"] = checked["status"]
    historical = dict(p.split("=", 1)
                      for p in checked["identity"]["source"]["note"].split())
    parts = []
    for part in gate["identity"]["source"]["note"].split():
        key, value = part.split("=", 1)
        if key in ("object", "lc_object", "cp_object"):
            value = historical[key]
        parts.append(key + "=" + value)
    gate["identity"]["source"]["note"] = " ".join(parts)
    assert gate == checked


def comp_dirs(obj):
    """DW_AT_comp_dir values of one object via readelf (binutils)."""
    proc = subprocess.run(
        ["readelf", "--debug-dump=info", str(obj)],
        capture_output=True, text=True)
    assert proc.returncode == 0, obj
    out = []
    for line in proc.stdout.splitlines():
        if "DW_AT_comp_dir" in line:
            out.append(line.rsplit(": ", 1)[-1].strip())
    return out


@needs_build
def test_built_objects_contain_no_checkout_path():
    # Prefix-mapped objects reproduce across checkouts.
    root = str(REPO).encode()
    names = (
        "swiotlb_attempt.bpf.o", "swiotlb_attempt-test.bpf.o",
        "swiotlb_lifecycle.bpf.o", "swiotlb_lifecycle-test.bpf.o",
        "swiotlb_copy.bpf.o", "swiotlb_copy-test.bpf.o",
    )
    for name in names:
        data = (REPO / "build" / "bpf" / name).read_bytes()
        assert root not in data, name
        dirs = comp_dirs(REPO / "build" / "bpf" / name)
        assert dirs, name
        for value in dirs:
            assert value == ".", (name, value)


@needs_build
def test_built_objects_match_narrow_test_bindings(generated):
    # Current build bytes must equal separately compiled provisional
    # bindings; this does not change the historical qualified identities.
    doc = json.loads((generated / "profile.json").read_text())
    note = dict(part.split("=", 1)
                for part in doc["identity"]["source"]["note"].split())
    objs = (("object", gate_kernel.PROD_OBJ),
            ("lc_object", gate_kernel.LC_OBJ),
            ("cp_object", gate_kernel.CP_OBJ))
    for key, path in objs:
        want = note[key]
        assert want.startswith("sha256:")
        got = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        assert got == want, key


def test_doctor_doc_refuses_error_exit():
    good = '{"capabilities": []}'
    for code in (0, 3):
        proc = subprocess.CompletedProcess([], code, good, "")
        assert gate_kernel.doctor_doc(proc) == {"capabilities": []}
    with pytest.raises(gate_kernel.GateKernelError, match="exit 2"):
        gate_kernel.doctor_doc(subprocess.CompletedProcess([], 2, good, "x"))


def test_live_gaps_require_available_and_live_verified():
    ok = {"id": "copy-actual", "status": "available",
          "reason": "live-verified under reference profile x"}
    doc = {"capabilities": [
        ok,
        {"id": "mapping-lifecycle", "status": "available",
         "reason": "profile claims support"},
        {"id": "attempt-trace", "status": "unavailable",
         "reason": "live-verified earlier"}]}
    assert gate_kernel.live_gaps(doc, ["copy-actual"]) == []
    assert gate_kernel.live_gaps(
        doc, ["attempt-trace", "mapping-lifecycle", "absent-cap"]) == [
        "attempt-trace (live-verified earlier)",
        "mapping-lifecycle (profile claims support)",
        "absent-cap (absent)"]


def test_emit_gate_profiles_requires_explicit_out(monkeypatch):
    import importlib.util
    from importlib.machinery import SourceFileLoader
    path = REPO / "tools" / "emit-gate-profiles"
    loader = SourceFileLoader("emit_gate_profiles_cli", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    monkeypatch.setattr(sys, "argv", ["emit-gate-profiles",
                                      "ident.json",
                                      "format.txt"])
    assert module.main() == 2


def test_changed_provisional_binding_is_rejected(generated):
    doc = json.loads((generated / 'profile.json').read_text())
    ident = gate_kernel.shipped_identity(doc)
    objs = {'object': generated / 'swiotlb_attempt.bpf.o',
            'lc_object': generated / 'swiotlb_lifecycle.bpf.o',
            'cp_object': generated / 'swiotlb_copy.bpf.o'}
    assert gate_kernel.binding_drift(doc, ident, objs) == []
    note = doc['identity']['source']['note']
    parts = []
    for part in note.split():
        if part.startswith('lc_object='):
            part = 'lc_object=sha256:' + '0' * 64
        parts.append(part)
    doc['identity']['source']['note'] = ' '.join(parts)
    assert gate_kernel.binding_drift(doc, ident, objs) == ['lc_object']
