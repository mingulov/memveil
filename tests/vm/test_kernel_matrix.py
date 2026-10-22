#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Kernel matrix offline tests: lock, verdicts, oracle bracketing.

No boot, no network, no privileged reads. Every case runs from
controlled fixture bytes.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kernel_matrix as km


def _lock_entry(verdicts=None, omitted=None, vng="v6.6.160",
                release="6.6.160-0606160-generic", source=None):
    if verdicts is None:
        verdicts = {
            "attempt-trace": {"verdict": "admitted",
                              "reason_class": "live-verified"},
            "mapping-lifecycle": {"verdict": "admitted",
                                  "reason_class": "live-verified"},
            "copy-actual": {"verdict": "admitted",
                            "reason_class": "live-verified"},
        }
    if omitted is None:
        omitted = []
    if source is None:
        source = {
            "kind": "archive",
            "vng_version": vng,
            "archive_date": "2026-10-21 11:32",
            "vmlinuz_sha256": "a" * 64,
            "modules_manifest_sha256": "b" * 64,
        }
    return {
        "id": "6.6",
        "upstream": vng[1:],
        "release": release,
        "expected": verdicts,
        "oracle": {"omitted": omitted},
        "source": source,
    }


def _built_source():
    frags = ["tests/vm/kconfig/base.fragment",
             "tests/vm/kconfig/nobtf.fragment"]
    return {
        "kind": "built",
        "tarball_url": "https://cdn.kernel.org/pub/linux/kernel/"
                       "v6.x/linux-6.12.114.tar.xz",
        "tarball_sha256": "c" * 64,
        "fragments": frags,
        "fragments_sha256": {frag: "d" * 64 for frag in frags},
        "toolchain": {"gcc": "gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0",
                      "ld": "GNU ld (GNU Binutils for Ubuntu) 2.46",
                      "pahole": "v1.31"},
        "config_sha256": "e" * 64,
        "bzimage_sha256": "f" * 64,
        "modules_manifest_sha256": "1" * 64,
    }


def _built_entry():
    entry = _lock_entry()
    entry["id"] = "6.12.114-btf"
    entry["release"] = "6.12.114-mv-6.12.114-btf"
    entry["upstream"] = "6.12.114"
    entry["source"] = _built_source()
    return entry


def _distro_source():
    return {
        "kind": "distro",
        "packages": [{"url": "https://snapshot.debian.org/debian/"
                             "pool/main/l/linux/linux-image-6.12.57"
                             "-amd64-unsigned_6.12.57-1_amd64.deb",
                      "sha256": "2" * 64}],
        "vmlinuz_member": "./boot/vmlinuz-6.12.57-amd64",
        "vmlinuz_sha256": "3" * 64,
        "modules_manifest_sha256": "4" * 64,
        "config_sha256": "5" * 64,
        "banner": "Linux version 6.12.57-amd64 (debian-kernel@"
                  "lists.debian.org) (gcc-14 14.2.0) #1 SMP "
                  "Debian 6.12.57-1 (2026-01-01)",
    }


def _distro_entry():
    entry = _lock_entry()
    entry["id"] = "debian13"
    entry["release"] = "6.12.57-amd64"
    entry["upstream"] = "6.12.57"
    entry["source"] = _distro_source()
    return entry


def _lock_doc(entries=None):
    if entries is None:
        entries = [_lock_entry()]
    return {
        "schema": "memveil-kernel-matrix/2",
        "recorded_on": "2026-10-22",
        "archive": "https://kernel.ubuntu.com/mainline",
        "archive_queried": "2026-10-22",
        "tools": {"bpftrace": "bpftrace v0.25.0",
                  "bpftool": "bpftool v7.7.0"},
        "kernels": entries,
    }


def test_parse_valid_lock(tmp_path):
    doc = _lock_doc()
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(doc))
    got = km.parse_lock(str(path))
    assert len(got["kernels"]) == 1
    assert got["kernels"][0]["id"] == "6.6"


def test_parse_rejects_bad_schema(tmp_path):
    doc = _lock_doc()
    doc["schema"] = "memveil-kernel-matrix/1"
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(km.LockError):
        km.parse_lock(str(path))


def test_parse_rejects_bad_sha(tmp_path):
    entry = _lock_entry()
    entry["source"]["vmlinuz_sha256"] = "xyz"
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(_lock_doc([entry])))
    with pytest.raises(km.LockError):
        km.parse_lock(str(path))


def test_parse_rejects_bad_verdict(tmp_path):
    verdicts = {
        "attempt-trace": {"verdict": "maybe",
                          "reason_class": "live-verified"},
        "mapping-lifecycle": {"verdict": "admitted",
                              "reason_class": "live-verified"},
        "copy-actual": {"verdict": "admitted",
                        "reason_class": "live-verified"},
    }
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(_lock_doc([_lock_entry(verdicts)])))
    with pytest.raises(km.LockError):
        km.parse_lock(str(path))


def test_parse_rejects_bad_reason_class(tmp_path):
    verdicts = {
        "attempt-trace": {"verdict": "refused",
                          "reason_class": "no-such-class"},
        "mapping-lifecycle": {"verdict": "admitted",
                              "reason_class": "live-verified"},
        "copy-actual": {"verdict": "admitted",
                        "reason_class": "live-verified"},
    }
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(_lock_doc([_lock_entry(verdicts)])))
    with pytest.raises(km.LockError):
        km.parse_lock(str(path))


def test_parse_rejects_duplicate_id(tmp_path):
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(_lock_doc([_lock_entry(), _lock_entry()])))
    with pytest.raises(km.LockError):
        km.parse_lock(str(path))


def test_parse_rejects_bad_omitted_probe(tmp_path):
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(_lock_doc([_lock_entry(omitted=["nope"])])))
    with pytest.raises(km.LockError):
        km.parse_lock(str(path))


def _doctor(caps):
    return {"capabilities": [
        {"id": cap, "status": status, "reason": reason}
        for cap, status, reason in caps]}


def test_verdict_admitted_matches_available():
    expected = _lock_entry()["expected"]
    doctor = _doctor([
        ("attempt-trace", "available",
         "live-verified under reference profile x"),
        ("mapping-lifecycle", "available",
         "live-verified under reference profile x"),
        ("copy-actual", "available",
         "live-verified under reference profile x"),
    ])
    ok, detail = km.compare_doctor(expected, doctor)
    assert ok, detail


def test_verdict_admitted_rejects_unavailable():
    expected = _lock_entry()["expected"]
    doctor = _doctor([
        ("attempt-trace", "unavailable", "kernel 1.0 below the 6.0 floor"),
        ("mapping-lifecycle", "available",
         "live-verified under reference profile x"),
        ("copy-actual", "available",
         "live-verified under reference profile x"),
    ])
    ok, _ = km.compare_doctor(expected, doctor)
    assert not ok


def test_verdict_floor_60_matches():
    expected = {
        "attempt-trace": {"verdict": "refused",
                          "reason_class": "floor-6.0"},
        "mapping-lifecycle": {"verdict": "refused",
                              "reason_class": "no-cover"},
        "copy-actual": {"verdict": "refused",
                        "reason_class": "no-cover"},
    }
    doctor = _doctor([
        ("attempt-trace", "unavailable",
         "kernel 5.15.0-test is below the 6.0 floor"),
        ("mapping-lifecycle", "unknown",
         "no profile covers this identity"),
        ("copy-actual", "unknown",
         "no profile covers this identity"),
    ])
    ok, detail = km.compare_doctor(expected, doctor)
    assert ok, detail


def test_verdict_floor_611_matches():
    expected = {
        "attempt-trace": {"verdict": "admitted",
                          "reason_class": "live-verified"},
        "mapping-lifecycle": {"verdict": "refused",
                              "reason_class": "floor-6.11"},
        "copy-actual": {"verdict": "refused",
                        "reason_class": "floor-6.11"},
    }
    doctor = _doctor([
        ("attempt-trace", "available",
         "live-verified under reference profile x"),
        ("mapping-lifecycle", "unavailable",
         "kernel 6.6.0-test is below the 6.11 floor"),
        ("copy-actual", "unavailable",
         "kernel 6.6.0-test is below the 6.11 floor"),
    ])
    ok, detail = km.compare_doctor(expected, doctor)
    assert ok, detail


def test_verdict_refused_rejects_available():
    expected = {
        "attempt-trace": {"verdict": "admitted",
                          "reason_class": "live-verified"},
        "mapping-lifecycle": {"verdict": "refused",
                              "reason_class": "floor-6.11"},
        "copy-actual": {"verdict": "refused",
                        "reason_class": "floor-6.11"},
    }
    doctor = _doctor([
        ("attempt-trace", "available",
         "live-verified under reference profile x"),
        ("mapping-lifecycle", "available",
         "live-verified under reference profile x"),
        ("copy-actual", "available",
         "live-verified under reference profile x"),
    ])
    ok, _ = km.compare_doctor(expected, doctor)
    assert not ok


def test_verdict_wrong_reason_class_fails():
    expected = {
        "attempt-trace": {"verdict": "admitted",
                          "reason_class": "live-verified"},
        "mapping-lifecycle": {"verdict": "refused",
                              "reason_class": "floor-6.11"},
        "copy-actual": {"verdict": "refused",
                        "reason_class": "floor-6.11"},
    }
    doctor = _doctor([
        ("attempt-trace", "available",
         "live-verified under reference profile x"),
        ("mapping-lifecycle", "unavailable",
         "kernel 6.6.0-test is below the 6.0 floor"),
        ("copy-actual", "unavailable",
         "kernel 6.6.0-test is below the 6.11 floor"),
    ])
    ok, _ = km.compare_doctor(expected, doctor)
    assert not ok


def test_oracle_samples_parse():
    lines = [
        "T 100 tp=10 map=9 unmap=8 copy=7 syncc=3 syncd=2\n",
        "noise\n",
        "T 200 tp=20 map=19 unmap=18 copy=17 syncc=13 syncd=12\n",
    ]
    samples = km.parse_oracle_samples(lines)
    assert len(samples) == 2
    assert samples[0][0] == 100
    assert samples[0][1]["tp"] == 10
    assert samples[1][1]["syncd"] == 12


def test_bracket_requires_coverage():
    samples = [(100, {"tp": 10}), (200, {"tp": 20})]
    with pytest.raises(km.OracleError):
        km.bracket_oracle(samples, 50, 150)
    with pytest.raises(km.OracleError):
        km.bracket_oracle(samples, 100, 300)


def test_bracket_exact_window():
    samples = [(100, {"tp": 10, "map": 9}),
               (200, {"tp": 20, "map": 19}),
               (300, {"tp": 30, "map": 29})]
    lo, hi = km.oracle_interval(samples, 100, 300, "tp")
    assert (lo, hi) == (20, 20)
    lo, hi = km.oracle_interval(samples, 150, 250, "tp")
    assert lo == 0
    assert hi == 20


def test_oracle_program_omits_missing():
    prog = km.build_oracle_program(omitted=["map", "syncd"])
    assert "swiotlb_tbl_map_single" not in prog
    assert "__swiotlb_sync_single_for_device" not in prog
    assert "swiotlb_bounced" in prog
    for key in ("tp", "unmap", "copy", "syncc"):
        assert "@%s = count()" % key in prog
    assert "@map = count()" not in prog
    assert "@syncd = count()" not in prog


def test_oracle_program_dropped_copy_detectable():
    prog = km.build_oracle_program(omitted=["copy"])
    assert "swiotlb_bounced" in prog
    assert "swiotlb_bounce" in prog
    assert "@copy = count()" not in prog
    assert "fentry:vmlinux:swiotlb_bounce" not in prog


def test_oracle_program_counts_bounced_bytes():
    prog = km.build_oracle_program()
    assert "@tpb = sum(args.size)" in prog
    assert "tpb=%llu" in prog


def test_oracle_program_omitted_tp_drops_byte_counter():
    prog = km.build_oracle_program(omitted=["tp"])
    assert "tpb" not in prog


def test_manifest_stable_and_sensitive(tmp_path):
    root = tmp_path / "mods"
    (root / "a").mkdir(parents=True)
    (root / "a" / "x.ko").write_bytes(b"one")
    (root / "b.ko").write_bytes(b"two")
    sha1, n1 = km.modules_manifest_sha(str(root))
    assert n1 == 2
    sha2, n2 = km.modules_manifest_sha(str(root))
    assert sha1 == sha2
    (root / "b.ko").write_bytes(b"changed")
    sha3, _ = km.modules_manifest_sha(str(root))
    assert sha3 != sha1


def test_manifest_ignores_depmod_output(tmp_path):
    root = tmp_path / "mods"
    (root / "kernel").mkdir(parents=True)
    (root / "kernel" / "x.ko").write_bytes(b"one")
    (root / "modules.builtin").write_bytes(b"stable")
    sha1, n1 = km.modules_manifest_sha(str(root))
    assert n1 == 2
    (root / "modules.dep").write_bytes(b"generated")
    (root / "modules.alias.bin").write_bytes(b"generated")
    sha2, n2 = km.modules_manifest_sha(str(root))
    assert sha2 == sha1
    assert n2 == 2


def test_find_modules_root_prefers_lib(tmp_path):
    lib = tmp_path / "c" / "lib" / "modules" / "r"
    usr = tmp_path / "c" / "usr" / "lib" / "modules" / "r"
    lib.mkdir(parents=True)
    usr.mkdir(parents=True)
    got = km.find_modules_root(str(tmp_path / "c"), "r")
    assert got.endswith("lib/modules/r")


def test_find_modules_root_falls_back_to_usr(tmp_path):
    usr = tmp_path / "c" / "usr" / "lib" / "modules" / "r"
    usr.mkdir(parents=True)
    got = km.find_modules_root(str(tmp_path / "c"), "r")
    assert "usr/lib/modules/r" in got


def test_find_modules_root_missing(tmp_path):
    assert km.find_modules_root(str(tmp_path), "nope") is None


def test_misses_sums_matching_programs():
    progs = [
        {"name": "tracepoint_swiotlb_swiotlb_bounced_1",
         "recursion_misses": 3},
        {"name": "tracepoint_swiotlb_swiotlb_bounced_2",
         "recursion_misses": 4},
        {"name": "other_prog", "recursion_misses": 100},
    ]
    assert km.prog_misses(progs, ["tracepoint_swiotlb_swiotlb_bounced"]) == 7
    assert km.prog_misses(progs, ["other_prog"]) == 100
    assert km.prog_misses(progs, ["missing"]) == 0


def test_misses_missing_field_zero():
    assert km.prog_misses([{"name": "x"}], ["x"]) == 0


def test_no_uncalled_compare_channel():
    assert not hasattr(km, "compare_channel")


def test_parse_committed_lock():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "kernels.lock.json")
    doc = km.parse_lock(path)
    assert len(doc["kernels"]) == 20
    assert doc["tools"]["bpftrace"].startswith("bpftrace v")
    assert doc["tools"]["bpftool"].startswith("bpftool v")
    by_id = {e["id"]: e for e in doc["kernels"]}
    for ident in ("5.15", "6.0", "6.6", "6.10"):
        assert by_id[ident]["oracle"]["omitted"] == [
            "unmap", "syncc", "syncd"]
    for ident in ("6.11", "6.12", "6.12.114-btf", "6.12.114-nobtf",
                  "6.12.114-rt", "6.12.114-debug", "6.12.0",
                  "6.18", "6.18.0", "7.0", "7.1", "7.2",
                  "7.3-rc3", "7.3", "debian13"):
        assert by_id[ident]["oracle"]["omitted"] == []
    assert sorted(
        by_id["7.0.14-lockdown"]["oracle"]["omitted"]) == [
            "copy", "map", "syncc", "syncd", "tp", "unmap"]


def test_lock_has_every_k3a_row():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "kernels.lock.json")
    doc = km.parse_lock(path)
    ids = {e["id"] for e in doc["kernels"]}
    assert ids == {
        "5.15", "6.0", "6.6", "6.10", "6.11", "6.12",
        "6.12.114-btf", "6.12.114-nobtf", "6.12.114-rt",
        "6.12.114-debug", "6.12.0", "6.18", "6.18.0", "7.0",
        "7.0.14-lockdown", "7.1", "7.2", "7.3-rc3", "7.3",
        "debian13",
    }


def test_parse_rejects_vng_tag_with_suffix(tmp_path):
    entry = _lock_entry(vng="v6.6.160-amd64",
                        release="6.6.160-0606160-generic")
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(_lock_doc([entry])))
    with pytest.raises(km.LockError):
        km.parse_lock(str(path))


def test_parse_rejects_release_upstream_mismatch(tmp_path):
    entry = _lock_entry()
    entry["release"] = "6.6.161-0606161-generic"
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(_lock_doc([entry])))
    with pytest.raises(km.LockError):
        km.parse_lock(str(path))


def test_parse_rejects_rc_release_without_rc(tmp_path):
    entry = _lock_entry(vng="v7.3-rc3",
                        release="7.3.0-070300-generic")
    entry["upstream"] = "7.3-rc3"
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(_lock_doc([entry])))
    with pytest.raises(km.LockError):
        km.parse_lock(str(path))


def test_parse_accepts_rc_release(tmp_path):
    assert km.release_agrees_with_upstream(
        "7.3.0-070300rc3-generic", "7.3-rc3")
    entry = _lock_entry(vng="v7.3-rc3",
                        release="7.3.0-070300rc3-generic")
    entry["upstream"] = "7.3-rc3"
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(_lock_doc([entry])))
    got = km.parse_lock(str(path))
    assert got["kernels"][0]["upstream"] == "7.3-rc3"


def test_parse_rejects_missing_tools(tmp_path):
    doc = _lock_doc()
    del doc["tools"]
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(km.LockError):
        km.parse_lock(str(path))


def test_parse_rejects_bad_tools(tmp_path):
    doc = _lock_doc()
    doc["tools"] = {"bpftrace": "bpftrace v0.25.0"}
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(km.LockError):
        km.parse_lock(str(path))


def test_release_agrees_with_upstream():
    assert km.release_agrees_with_upstream(
        "6.6.160-0606160-generic", "6.6.160")
    assert km.release_agrees_with_upstream(
        "7.3.0-070300rc3-generic", "7.3-rc3")
    assert not km.release_agrees_with_upstream(
        "6.6.161-0606161-generic", "6.6.160")
    assert not km.release_agrees_with_upstream(
        "7.3.0-070300-generic", "7.3-rc3")
    assert not km.release_agrees_with_upstream("bogus", "6.6.160")


def _write_lock(tmp_path, doc):
    path = tmp_path / "kernels.lock.json"
    path.write_text(json.dumps(doc))
    return str(path)


def test_lock_v2_archive_row_roundtrip(tmp_path):
    got = km.parse_lock(_write_lock(tmp_path, _lock_doc()))
    src = got["kernels"][0]["source"]
    assert src["kind"] == "archive"
    assert src["vng_version"] == "v6.6.160"
    assert got["kernels"][0]["release"] == "6.6.160-0606160-generic"


def test_lock_v2_built_row_requires_every_hash(tmp_path):
    km.parse_lock(_write_lock(tmp_path, _lock_doc([_built_entry()])))
    for field in ("tarball_sha256", "config_sha256",
                  "bzimage_sha256", "modules_manifest_sha256"):
        entry = _built_entry()
        del entry["source"][field]
        with pytest.raises(km.LockError):
            km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))
    entry = _built_entry()
    entry["source"]["fragments_sha256"] = {}
    with pytest.raises(km.LockError):
        km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))
    entry = _built_entry()
    frag = entry["source"]["fragments"][0]
    entry["source"]["fragments_sha256"][frag] = "xyz"
    with pytest.raises(km.LockError):
        km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))


def test_lock_v2_distro_row_requires_banner_and_packages(tmp_path):
    km.parse_lock(_write_lock(tmp_path, _lock_doc([_distro_entry()])))
    entry = _distro_entry()
    del entry["source"]["banner"]
    with pytest.raises(km.LockError):
        km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))
    entry = _distro_entry()
    entry["source"]["banner"] = "not a banner"
    with pytest.raises(km.LockError):
        km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))
    entry = _distro_entry()
    entry["source"]["packages"] = []
    with pytest.raises(km.LockError):
        km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))
    entry = _distro_entry()
    entry["source"]["packages"][0]["sha256"] = "xyz"
    with pytest.raises(km.LockError):
        km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))


def test_lock_v2_unknown_key_fails(tmp_path):
    km.parse_lock(_write_lock(tmp_path, _lock_doc()))
    doc = _lock_doc()
    doc["surprise"] = 1
    with pytest.raises(km.LockError):
        km.parse_lock(_write_lock(tmp_path, doc))
    entry = _lock_entry()
    entry["surprise"] = 1
    with pytest.raises(km.LockError):
        km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))
    entry = _lock_entry()
    entry["source"]["surprise"] = 1
    with pytest.raises(km.LockError):
        km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))


def test_lock_v2_boot_append_allow_list(tmp_path):
    entry = _lock_entry()
    entry["boot_append"] = ["lockdown=confidentiality"]
    km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))
    entry = _lock_entry()
    entry["boot_append"] = ["quiet"]
    with pytest.raises(km.LockError):
        km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))
    entry = _lock_entry()
    entry["boot_append"] = "lockdown=confidentiality"
    with pytest.raises(km.LockError):
        km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))


def test_release_dot_zero_mapping(tmp_path):
    assert km.release_agrees_with_upstream(
        "6.12.0-061200-generic", "6.12.0")
    assert km.release_agrees_with_upstream(
        "6.12.0-061200-generic", "6.12")
    assert km.release_agrees_with_upstream(
        "6.12-061200-generic", "6.12.0")
    assert not km.release_agrees_with_upstream(
        "6.12.1-061200-generic", "6.12")
    assert not km.release_agrees_with_upstream(
        "6.12-061200-generic", "6.12.1")
    entry = _lock_entry(vng="v6.12",
                        release="6.12.0-061200-generic")
    entry["upstream"] = "6.12.0"
    km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))
    entry["upstream"] = "6.12.1"
    with pytest.raises(km.LockError):
        km.parse_lock(_write_lock(tmp_path, _lock_doc([entry])))


def test_release_agrees_debian_local_suffix():
    assert km.release_agrees_with_upstream(
        "6.12.107+deb13-amd64", "6.12.107")
    assert not km.release_agrees_with_upstream(
        "6.12.108+deb13-amd64", "6.12.107")


def _valid_built_cache(tmp_path, monkeypatch):
    entry = _built_entry()
    monkeypatch.setenv("MV_KCACHE", str(tmp_path / "kcache"))
    rowdir = tmp_path / "kcache" / entry["id"]
    boot = rowdir / "boot"
    mods = rowdir / "lib" / "modules" / entry["release"] / "kernel"
    mods.mkdir(parents=True)
    boot.mkdir(parents=True)
    vmlinuz = boot / ("vmlinuz-" + entry["release"])
    vmlinuz.write_bytes(b"fake-bzimage")
    (mods / "nvme.ko").write_bytes(b"fake-module")
    (rowdir / "config").write_text("CONFIG_X=y\n")
    src = entry["source"]
    src["bzimage_sha256"] = km.sha_file(str(vmlinuz))
    mods_root = rowdir / "lib" / "modules" / entry["release"]
    src["modules_manifest_sha256"], _ = km.modules_manifest_sha(
        str(mods_root))
    src["config_sha256"] = km.sha_file(str(rowdir / "config"))
    return entry, str(vmlinuz)


def test_verify_entry_cache_config_drift_fails(tmp_path, monkeypatch):
    entry, kernel = _valid_built_cache(tmp_path, monkeypatch)
    ok, why, got = km.verify_entry_cache("/nonexistent", entry)
    assert ok, why
    assert got == kernel
    rowdir = os.path.join(os.environ["MV_KCACHE"], entry["id"])
    with open(os.path.join(rowdir, "config"), "w") as handle:
        handle.write("CONFIG_Y=n\n")
    ok, why, got = km.verify_entry_cache("/nonexistent", entry)
    assert not ok
    assert "config" in why
    assert not got


def test_verify_entry_cache_modules_drift_fails(tmp_path, monkeypatch):
    entry, _ = _valid_built_cache(tmp_path, monkeypatch)
    ok, why, _ = km.verify_entry_cache("/nonexistent", entry)
    assert ok, why
    rowdir = os.path.join(os.environ["MV_KCACHE"], entry["id"])
    mod = os.path.join(rowdir, "lib", "modules", entry["release"],
                       "kernel", "nvme.ko")
    with open(mod, "wb") as handle:
        handle.write(b"tampered")
    ok, why, got = km.verify_entry_cache("/nonexistent", entry)
    assert not ok
    assert "modules" in why
    assert not got


def test_verify_entry_cache_missing_says_build(tmp_path, monkeypatch):
    monkeypatch.setenv("MV_KCACHE", str(tmp_path / "kcache"))
    ok, why, got = km.verify_entry_cache(
        "/nonexistent", _built_entry())
    assert not ok
    assert "tools/kernel-build" in why
    assert not got
    ok, why, got = km.verify_entry_cache(
        "/nonexistent", _distro_entry())
    assert not ok
    assert "tools/kernel-fetch" in why
    assert not got


def test_verify_entry_cache_archive_checks_hashes(tmp_path, monkeypatch):
    monkeypatch.delenv("MV_KCACHE", raising=False)
    home = tmp_path / "home"
    entry = _lock_entry()
    base = home / ".cache" / "virtme-ng" / "v6.6.160" / "amd64"
    boot = base / "boot"
    mods = base / "lib" / "modules" / entry["release"] / "kernel"
    mods.mkdir(parents=True)
    boot.mkdir(parents=True)
    vmlinuz = boot / ("vmlinuz-" + entry["release"])
    vmlinuz.write_bytes(b"fake-vmlinuz")
    (mods / "nvme.ko").write_bytes(b"fake-module")
    src = entry["source"]
    src["vmlinuz_sha256"] = km.sha_file(str(vmlinuz))
    mods_root = base / "lib" / "modules" / entry["release"]
    src["modules_manifest_sha256"], _ = km.modules_manifest_sha(
        str(mods_root))
    ok, why, target = km.verify_entry_cache(str(home), entry)
    assert ok, why
    assert target == "v6.6.160"
    vmlinuz.write_bytes(b"tampered")
    ok, why, target = km.verify_entry_cache(str(home), entry)
    assert not ok
    assert "vmlinuz" in why
    assert not target


def test_omitted_mismatch_fails():
    fails = km.check_omitted([], ["copy"], ["attempt-trace"])
    assert fails


def test_needed_probe_missing_fails_despite_lock_match():
    fails = km.check_omitted(["copy"], ["copy"], ["copy-actual"])
    assert any("needed" in f for f in fails)


def test_needed_attempt_probe_missing_fails():
    fails = km.check_omitted(["tp"], ["tp"], ["attempt-trace"])
    assert fails


def test_omitted_match_needed_present_passes():
    assert km.check_omitted(
        ["unmap", "syncc", "syncd"], ["unmap", "syncc", "syncd"],
        ["attempt-trace"]) == []
    assert km.check_omitted([], [], [
        "attempt-trace", "mapping-lifecycle", "copy-actual"]) == []


def test_needed_probes_per_capability():
    assert km.needed_probes(["attempt-trace"]) == ["tp"]
    assert km.needed_probes(["mapping-lifecycle"]) == ["map", "unmap"]
    assert km.needed_probes(["copy-actual"]) == ["copy", "syncc", "syncd"]
    assert km.needed_probes([]) == []


def _workload(first=1100, last=1900):
    lines = ["dd1 start %d" % first, "dd1 end %d rc=0" % (first + 10),
             "dd2 start %d" % (first + 20),
             "dd2 end %d rc=0" % (first + 30)]
    for i in range(4):
        lines.append("par%d start %d" % (i, first + 40 + i))
        lines.append("par%d end %d rc=%d" % (i, last, 0))
    return "\n".join(lines) + "\n"


def test_workload_inside_window_passes():
    parsed = km.parse_workload(_workload(1100, 1900))
    ok, detail = km.check_workload_window(parsed, 1000, 2000)
    assert ok, detail
    assert parsed["first_start"] == 1100
    assert parsed["last_end"] == 1900


def test_workload_starting_before_window_fails():
    parsed = km.parse_workload(_workload(900, 1900))
    ok, _ = km.check_workload_window(parsed, 1000, 2000)
    assert not ok


def test_workload_ending_after_window_fails():
    parsed = km.parse_workload(_workload(1100, 2100))
    ok, _ = km.check_workload_window(parsed, 1000, 2000)
    assert not ok


def test_workload_missing_parallel_timestamps_fails():
    text = ("dd1 start 1100\ndd1 end 1110 rc=0\n"
            "dd2 start 1120\ndd2 end 1130 rc=0\n"
            "par0 rc=0\npar1 rc=0\npar2 rc=0\npar3 rc=0\n")
    with pytest.raises(ValueError):
        km.parse_workload(text)


def test_workload_nonzero_rc_fails():
    text = _workload().replace("par2 end 1900 rc=0",
                               "par2 end 1900 rc=1")
    with pytest.raises(ValueError):
        km.parse_workload(text)


def test_workload_garbage_fails():
    with pytest.raises(ValueError):
        km.parse_workload("nothing here\n")


def test_zero_traffic_floor_fails():
    bounds = {"attempt": (0, 0)}
    fails = km.check_channel_floors(bounds, ["attempt"],
                                    km.count_floor(_BYTES768))
    assert fails


def test_floor_below_bound_passes():
    bounds = {"attempt": (13000, 13100), "map": (12900, 13100)}
    assert km.check_channel_floors(bounds, ["attempt", "map"],
                                   km.count_floor(_BYTES768)) == []


def test_floor_above_bound_fails_one_channel():
    bounds = {"attempt": (13000, 13100), "map": (100, 200)}
    fails = km.check_channel_floors(bounds, ["attempt", "map"],
                                    km.count_floor(_BYTES768))
    assert len(fails) == 1 and "map" in fails[0]


_BYTES768 = 805306368


def test_count_floor_from_block_bytes():
    assert km.count_floor(_BYTES768) == 3072
    assert km.count_floor(1) == 1
    assert km.count_floor(262144) == 1
    assert km.count_floor(262145) == 2


def test_count_ceiling_from_block_bytes():
    assert km.count_ceiling(_BYTES768) == 1572864
    assert km.count_ceiling(511) == 0
    assert km.count_ceiling(512) == 1


def test_ceiling_below_bound_passes():
    bounds = {"attempt": (13000, 13100), "map": (12900, 13100),
              "copy": (25900, 26200)}
    assert km.check_channel_ceiling(
        bounds, ["attempt", "map", "copy"], 1572864) == []


def test_ceiling_above_bound_fails_one_channel():
    bounds = {"attempt": (13000, 13100), "map": (2000000, 2000100)}
    fails = km.check_channel_ceiling(
        bounds, ["attempt", "map"], 1572864)
    assert len(fails) == 1 and "map" in fails[0]


def test_ceiling_doubles_for_copy():
    bounds = {"copy": (3000000, 3100000)}
    assert km.check_channel_ceiling(
        bounds, ["copy"], 1572864) == []
    bounds = {"copy": (3000000, 3200000)}
    assert km.check_channel_ceiling(
        bounds, ["copy"], 1572864)


def _byte_sums(req=_BYTES768, mapped=_BYTES768, sync=_BYTES768,
               cob=_BYTES768, cbo=_BYTES768):
    return {"requested": req, "mapped": mapped, "sync": sync,
            "copy": {"original_to_bounce": cob,
                     "bounce_to_original": cbo}}


def test_memveil_bytes_exact_passes():
    assert km.check_memveil_bytes(
        _byte_sums(), _BYTES768, 0, _CHANNELS5) == []


def test_memveil_bytes_over_fails():
    sums = _byte_sums(req=_BYTES768 + 512)
    fails = km.check_memveil_bytes(
        sums, _BYTES768, 10 * 262144, _CHANNELS5)
    assert len(fails) == 1 and "requested" in fails[0]


def test_memveil_bytes_short_within_allowance_passes():
    sums = _byte_sums(mapped=_BYTES768 - 262144)
    assert km.check_memveil_bytes(
        sums, _BYTES768, 262144, _CHANNELS5) == []


def test_memveil_bytes_short_beyond_allowance_fails():
    sums = _byte_sums(mapped=_BYTES768 - 262144 - 1)
    fails = km.check_memveil_bytes(
        sums, _BYTES768, 262144, _CHANNELS5)
    assert len(fails) == 1 and "mapped" in fails[0]


def test_memveil_bytes_copy_direction_short_fails():
    sums = _byte_sums(cbo=_BYTES768 - 512)
    fails = km.check_memveil_bytes(
        sums, _BYTES768, 0, _CHANNELS5)
    assert len(fails) == 1 and "bounce_to_original" in fails[0]


def test_memveil_bytes_absent_channel_skipped():
    sums = _byte_sums(req=0, mapped=0, sync=0, cob=0, cbo=0)
    assert km.check_memveil_bytes(
        sums, _BYTES768, 0, ["unmap"]) == []


def _tpb_samples(final):
    return [(900, {"tpb": 0}), (1000, {"tpb": 0}),
            (2000, {"tpb": final}), (2100, {"tpb": final})]


def _no_miss():
    return km.parse_miss_samples(
        [(500, []), (1200, []), (1800, []), (2200, [])])


def test_oracle_bytes_exact_passes():
    assert km.check_oracle_bytes(
        _tpb_samples(_BYTES768), _no_miss(), 1000, 2000,
        _BYTES768) == []


def test_oracle_bytes_over_fails():
    fails = km.check_oracle_bytes(
        _tpb_samples(_BYTES768 + 512), _no_miss(), 1000, 2000,
        _BYTES768)
    assert fails


def test_oracle_bytes_short_within_miss_allowance_passes():
    miss = km.parse_miss_samples([
        (500, []), (1200, []),
        (1800, [{"name": "tracepoint_swiotlb_swiotlb_bounced_1",
                 "recursion_misses": 2}]),
        (2200, []),
    ])
    assert km.check_oracle_bytes(
        _tpb_samples(_BYTES768 - 2 * 262144), miss, 1000,
        2000, _BYTES768) == []


def test_oracle_bytes_short_beyond_miss_allowance_fails():
    assert km.check_oracle_bytes(
        _tpb_samples(_BYTES768 - 1), _no_miss(), 1000, 2000,
        _BYTES768)


def test_oracle_bytes_missing_key_fails():
    samples = [(900, {"tp": 0}), (1000, {"tp": 0}),
               (2000, {"tp": 100}), (2100, {"tp": 100})]
    assert km.check_oracle_bytes(
        samples, _no_miss(), 1000, 2000, _BYTES768)


_LOSS7 = ("detail loss 6 (submit_fail=(0) malformed=(0) dropped=(0) "
          "recursion_missed=(6) size_omitted=(0) duration_omitted=(0) "
          "signal_omitted=(0) rejected=(0) write_failed=(0))")

_LOSS_KEYS = ("submit_fail", "malformed", "dropped",
              "recursion_missed", "size_omitted",
              "duration_omitted", "signal_omitted", "rejected",
              "write_failed")


def _loss_text(**over):
    vals = {key: over.get(key, 0) for key in _LOSS_KEYS}
    total = sum(vals.values())
    parts = " ".join("%s=(%d)" % (key, vals[key])
                     for key in _LOSS_KEYS)
    return "detail loss %d (%s)" % (total, parts)


def _set_session_loss(ev, **over):
    session = json.loads(ev["session_text"])
    vals = {key: over.get(key, 0) for key in _LOSS_KEYS}
    session["quality"]["detail"]["reason"] = _loss_text(**over)
    session["quality"]["detail"]["loss_count"] = str(
        sum(vals.values()))
    ev["session_text"] = json.dumps(session)


def _add_snap_misses(ev, idx, name, n):
    snaps = list(ev["miss_snaps"])
    stamp, text = snaps[idx]
    progs = json.loads(text)
    for prog in progs:
        if prog.get("name") == name:
            prog["recursion_misses"] = \
                prog.get("recursion_misses", 0) + n
            break
    else:
        progs.append({"name": name, "recursion_misses": n})
    snaps[idx] = (stamp, json.dumps(progs))
    ev["miss_snaps"] = snaps


def test_parse_detail_loss_real_shape():
    parsed = km.parse_detail_loss(_LOSS7)
    assert parsed["recursion_missed"] == 6
    assert parsed["total"] == 6
    assert km.transport_loss(parsed) == 0


def test_parse_detail_loss_transport_sum():
    reason = ("detail loss 9 (submit_fail=(4) malformed=(1) dropped=(2) "
              "recursion_missed=(1) size_omitted=(0) duration_omitted=(0) "
              "signal_omitted=(0) rejected=(1) write_failed=(0))")
    parsed = km.parse_detail_loss(reason)
    assert parsed["total"] == 9
    assert km.transport_loss(parsed) == 8


def test_parse_detail_loss_rejects_total_mismatch():
    reason = _LOSS7.replace("detail loss 6", "detail loss 7")
    with pytest.raises(ValueError):
        km.parse_detail_loss(reason)


def test_parse_detail_loss_rejects_garbage():
    with pytest.raises(ValueError):
        km.parse_detail_loss("loss unknown")


def test_recovered_from_session():
    session = {"environment": {"evidence": [
        {"type": "provenance", "source": "copy.recovered",
         "interpretation": "12398"}]}}
    assert km.recovered_from_session(session) == 12398


def test_recovered_missing_fails():
    with pytest.raises(ValueError):
        km.recovered_from_session({"environment": {"evidence": []}})


def _miss_snaps():
    return km.parse_miss_samples([
        (500, []),
        (1200, [{"name": "fentry_vmlinux_swiotlb_bounce_4",
                 "recursion_misses": 2},
                {"name": "mv_map_result", "recursion_misses": 1},
                {"name": "mv_bounce", "recursion_misses": 3}]),
        (1800, [{"name": "fentry_vmlinux_swiotlb_bounce_4",
                 "recursion_misses": 8},
                {"name": "mv_map_result", "recursion_misses": 5},
                {"name": "mv_bounce", "recursion_misses": 8}]),
        (2200, [{"name": "fentry_vmlinux_swiotlb_bounce_4",
                 "recursion_misses": 10},
                {"name": "mv_map_result", "recursion_misses": 6},
                {"name": "mv_bounce", "recursion_misses": 10},
                {"name": "mv_bounce_exit", "recursion_misses": 4}]),
    ])


def _count_samples():
    full = {"tp": 13000, "map": 13000, "unmap": 13000, "copy": 25990,
            "syncc": 13000, "syncd": 0}
    zero = {key: 0 for key in full}
    return [(900, dict(zero)), (1000, dict(zero)),
            (2000, dict(full)), (2100, dict(full))]


def _loss(**over):
    base = {"submit_fail": 0, "malformed": 0, "dropped": 0,
            "recursion_missed": 0, "size_omitted": 0,
            "duration_omitted": 0, "signal_omitted": 0,
            "rejected": 0, "write_failed": 0}
    base.update(over)
    base["total"] = sum(base[key] for key in km.TRANSPORT_KEYS) \
        + base["recursion_missed"] + sum(base[key] for key in
                                         km.POST_LATCH_KEYS)
    return base


def _persisted7():
    return {"bounce_attempt": 13000, "map_result": 12994,
            "unmap": 13000, "copy": 26000, "sync_request": 13000}


_CHANNELS5 = ["attempt", "map", "unmap", "copy", "sync"]


def test_miss_interval_matches_count_math():
    miss = _miss_snaps()
    assert km.miss_interval(
        miss, 1000, 2000, ["mv_map_result"]) == (4, 6)
    assert km.miss_interval(
        miss, 1000, 2000,
        ["fentry_vmlinux_swiotlb_bounce"]) == (6, 10)


def test_miss_interval_missing_program_is_zero():
    miss = _miss_snaps()
    assert km.miss_interval(miss, 1000, 2000, ["mv_unmap"]) == (0, 0)


def test_miss_interval_survives_unload():
    miss = km.parse_miss_samples([
        (500, []),
        (1200, [{"name": "mv_map_result",
                 "recursion_misses": 1}]),
        (1800, [{"name": "mv_map_result",
                 "recursion_misses": 5}]),
        (2200, []),
    ])
    assert km.miss_interval(miss, 1000, 2000,
                            ["mv_map_result"]) == (4, 5)


def test_miss_interval_backwards_counters_fail():
    miss = km.parse_miss_samples([
        (500, [{"name": "mv_map_result",
                "recursion_misses": 9}]),
        (1200, [{"name": "mv_map_result",
                 "recursion_misses": 1}]),
        (1800, [{"name": "mv_map_result",
                 "recursion_misses": 9}]),
        (2200, []),
    ])
    with pytest.raises(km.OracleError):
        km.miss_interval(miss, 1000, 2000, ["mv_map_result"])


def test_prewindow_misses_excluded():
    miss = km.parse_miss_samples([
        (500, [{"name": "mv_map_result",
                "recursion_misses": 100}]),
        (1200, [{"name": "mv_map_result",
                 "recursion_misses": 100}]),
        (1800, [{"name": "mv_map_result",
                 "recursion_misses": 100}]),
        (2200, [{"name": "mv_map_result",
                 "recursion_misses": 100}]),
    ])
    assert km.miss_interval(miss, 1000, 2000,
                            ["mv_map_result"]) == (0, 0)


def test_channel_bounds_add_bracketed_misses():
    lo, hi = km.channel_bounds(_count_samples(), _miss_snaps(),
                               1000, 2000, "copy")
    assert (lo, hi) == (25996, 26000)
    lo, hi = km.channel_bounds(_count_samples(), _miss_snaps(),
                               1000, 2000, "map")
    assert (lo, hi) == (13000, 13000)


def test_copy_allowance_subtracts_recovered():
    assert km.channel_allowance(_miss_snaps(), 1000, 2000, "copy",
                                0, 10) == 0
    assert km.channel_allowance(_miss_snaps(), 1000, 2000, "copy",
                                0, 4) == 6


def test_map_allowance_is_bpftool_plus_transport():
    assert km.channel_allowance(_miss_snaps(), 1000, 2000, "map",
                                0, 0) == 6
    assert km.channel_allowance(_miss_snaps(), 1000, 2000, "map",
                                3, 0) == 9


def test_exit_misses_grant_no_allowance():
    miss = km.parse_miss_samples([
        (500, []), (1200, []), (1800, []),
        (2200, [{"name": "mv_bounce_exit",
                 "recursion_misses": 1687}]),
    ])
    assert km.channel_allowance(miss, 1000, 2000, "copy",
                                0, 0) == 0


def test_decide_full_row_short_covered():
    loss = _loss(recursion_missed=6)
    per, overall, failed, info = km.decide_channels(
        _persisted7(), _count_samples(), _miss_snaps(), 1000, 2000,
        _CHANNELS5, loss, 6, 10)
    assert not failed, per
    assert overall == "SHORT-COVERED"
    assert per["map"].startswith("SHORT-COVERED")
    assert per["attempt"].startswith("EXACT")
    assert per["copy"].startswith("EXACT")
    assert info["shortfalls"]["map"] == 6


def test_decide_exact_row_passes():
    persisted = {"bounce_attempt": 13000, "map_result": 13000,
                 "unmap": 13000, "copy": 26000,
                 "sync_request": 13000}
    loss = _loss()
    per, overall, failed, _ = km.decide_channels(
        persisted, _count_samples(), _miss_snaps(), 1000, 2000,
        _CHANNELS5, loss, 0, 10)
    assert not failed, per
    assert overall == "EXACT"


def test_decide_huge_reported_loss_does_not_cover():
    loss = _loss(recursion_missed=10 ** 9)
    per, overall, failed, _ = km.decide_channels(
        {}, _count_samples(), _miss_snaps(), 1000, 2000,
        ["attempt"], loss, 10 ** 9, 0)
    assert failed
    assert overall == "SHORT-UNCOVERED"


def test_decide_cross_channel_cover_fails():
    persisted = {"unmap": 12994}
    loss = _loss(recursion_missed=6)
    per, overall, failed, _ = km.decide_channels(
        persisted, _count_samples(), _miss_snaps(), 1000, 2000,
        ["unmap"], loss, 6, 0)
    assert failed, per
    assert per["unmap"].startswith("SHORT-UNCOVERED")


def test_decide_overreported_loss_fails():
    persisted = {"bounce_attempt": 13000, "map_result": 13000,
                 "unmap": 13000, "copy": 26000,
                 "sync_request": 13000}
    loss = _loss(recursion_missed=12404)
    per, overall, failed, _ = km.decide_channels(
        persisted, _count_samples(), _miss_snaps(), 1000, 2000,
        _CHANNELS5, loss, 12404, 10)
    assert failed, per


def test_decide_post_latch_loss_does_not_cover():
    persisted = {"bounce_attempt": 12994}
    loss = _loss(size_omitted=6)
    per, overall, failed, _ = km.decide_channels(
        persisted, _count_samples(), _miss_snaps(), 1000, 2000,
        ["attempt"], loss, 6, 0)
    assert failed, per


def test_decide_total_shortfall_bounded_by_reported():
    persisted = {"bounce_attempt": 12990, "map_result": 12990}
    loss = _loss(recursion_missed=6)
    miss = km.parse_miss_samples([
        (500, []), (1200, []), (1800, []),
        (2200, [{"name": "mv_swiotlb_attempt",
                 "recursion_misses": 10},
                {"name": "mv_map_result",
                 "recursion_misses": 10}]),
    ])
    per, overall, failed, _ = km.decide_channels(
        persisted, _count_samples(), miss, 1000, 2000,
        ["attempt", "map"], loss, 6, 0)
    assert failed, per


def test_decide_total_shortfall_ignores_size_omit_padding():
    samples = [(900, {"copy": 0}), (1000, {"copy": 0}),
               (2000, {"copy": 1000}), (2100, {"copy": 1000})]
    miss = km.parse_miss_samples([
        (500, []), (1200, []),
        (1800, [{"name": "mv_bounce",
                 "recursion_misses": 100}]),
        (2200, []),
    ])
    loss = _loss(size_omitted=100)
    per, overall, failed, _ = km.decide_channels(
        {"copy": 900}, samples, miss, 1000, 2000,
        ["copy"], loss, 100, 0)
    assert failed, per


def test_decide_total_shortfall_sums_split_program_misses():
    samples = [(900, {"map": 0, "unmap": 0}),
               (1000, {"map": 0, "unmap": 0}),
               (2000, {"map": 100, "unmap": 100}),
               (2100, {"map": 100, "unmap": 100})]
    miss = km.parse_miss_samples([
        (500, []), (1200, []),
        (1800, [{"name": "mv_map_result",
                 "recursion_misses": 5},
                {"name": "mv_unmap",
                 "recursion_misses": 5}]),
        (2200, []),
    ])
    loss = _loss(recursion_missed=5, size_omitted=5)
    per, overall, failed, _ = km.decide_channels(
        {"map_result": 95, "unmap": 95}, samples, miss, 1000,
        2000, ["map", "unmap"], loss, 10, 0)
    assert failed, per


def test_decide_more_than_oracle_fails():
    persisted = {"bounce_attempt": 13001}
    loss = _loss()
    per, overall, failed, _ = km.decide_channels(
        persisted, _count_samples(), _miss_snaps(), 1000, 2000,
        ["attempt"], loss, 0, 0)
    assert failed
    assert per["attempt"].startswith("MORE THAN ORACLE")


def test_decide_missing_oracle_key_fails():
    samples = [(900, {"tp": 0}), (1000, {"tp": 0}),
               (2000, {"tp": 100}), (2100, {"tp": 100})]
    loss = _loss()
    per, overall, failed, _ = km.decide_channels(
        {"map_result": 100}, samples, _miss_snaps(), 1000, 2000,
        ["map"], loss, 0, 0)
    assert failed
    assert overall is None


def _split_miss():
    return km.parse_miss_samples([
        (500, []), (1200, []),
        (1800, [{"name": "mv_map_result",
                 "recursion_misses": 5},
                {"name": "mv_unmap",
                 "recursion_misses": 5},
                {"name": "mv_bounce",
                 "recursion_misses": 100}]),
        (2200, []),
    ])


def test_recursion_reported_exact_sum_passes():
    assert km.check_recursion_reported(
        _split_miss(), 1000, 2000, 10, 0, 100) == []


def test_recursion_reported_split_underreport_fails():
    fails = km.check_recursion_reported(
        _split_miss(), 1000, 2000, 9, 0, 100)
    assert len(fails) == 1 and "9" in fails[0] and "10" in fails[0]


def test_recursion_reported_copy_term_counts_unrecovered():
    fails = km.check_recursion_reported(
        _split_miss(), 1000, 2000, 54, 5, 60)
    assert fails and "55" in fails[0]
    assert km.check_recursion_reported(
        _split_miss(), 1000, 2000, 55, 5, 60) == []


def test_recursion_reported_copy_term_floors_at_zero():
    assert km.check_recursion_reported(
        _split_miss(), 1000, 2000, 10, 0, 5000) == []


def test_deferred_from_session():
    session = {"environment": {"evidence": [
        {"type": "provenance", "source": "copy.deferred",
         "interpretation": "7"}]}}
    assert km.deferred_from_session(session) == 7


def test_deferred_missing_fails():
    with pytest.raises(ValueError):
        km.deferred_from_session(
            {"environment": {"evidence": []}})


def test_bracket_gap_at_start_fails():
    samples = [(0, {"tp": 0}), (5 * 10 ** 9, {"tp": 100}),
               (6 * 10 ** 9, {"tp": 100})]
    with pytest.raises(km.OracleError):
        km.bracket_oracle(samples, 3 * 10 ** 9, 6 * 10 ** 9)


def test_bracket_gap_at_end_fails():
    samples = [(0, {"tp": 0}), (10 ** 9, {"tp": 100}),
               (6 * 10 ** 9, {"tp": 100})]
    with pytest.raises(km.OracleError):
        km.bracket_oracle(samples, 0, 3 * 10 ** 9)


def test_bracket_half_second_gaps_pass():
    assert km.MAX_EDGE_GAP_NS == 10 ** 9
    samples = [(0, {"tp": 0}), (5 * 10 ** 8, {"tp": 10}),
               (15 * 10 ** 8, {"tp": 90}),
               (2 * 10 ** 9, {"tp": 100})]
    before, _, _, _ = km.bracket_oracle(samples, 10 ** 9,
                                         15 * 10 ** 8)
    assert before["tp"] == 10


def test_oracle_interval_clamps_negative_lo():
    samples = [(0, {"tp": 1000}), (10 ** 9, {"tp": 0}),
               (2 * 10 ** 9, {"tp": 0})]
    lo, _ = km.oracle_interval(samples, 0, 2 * 10 ** 9, "tp")
    assert lo == 0


def test_persisted_invariants_nominal_pass():
    attributed = {"attempt": 0, "map": 6, "unmap": 0, "copy": 0,
                  "sync": 0}
    assert km.check_persisted_invariants(_persisted7(),
                                         attributed) == []


def test_persisted_invariants_skew_fails():
    persisted = dict(_persisted7())
    persisted["unmap"] = 12000
    attributed = {"attempt": 0, "map": 6, "unmap": 0, "copy": 0,
                  "sync": 0}
    assert km.check_persisted_invariants(persisted, attributed)


def test_persisted_copy_ratio_fails():
    persisted = dict(_persisted7())
    persisted["copy"] = 25000
    attributed = {"attempt": 0, "map": 6, "unmap": 0, "copy": 0,
                  "sync": 0}
    assert km.check_persisted_invariants(persisted, attributed)


def test_oracle_invariants_overlap_pass():
    bounds = {"attempt": (12800, 13000), "map": (12900, 13100),
              "unmap": (12800, 13000), "copy": (25900, 26100),
              "sync": (12800, 13000)}
    assert km.check_oracle_invariants(bounds) == []


def test_oracle_invariants_disjoint_fails():
    bounds = {"attempt": (12800, 13000), "map": (100, 200),
              "unmap": (12800, 13000), "copy": (25900, 26100),
              "sync": (12800, 13000)}
    assert km.check_oracle_invariants(bounds)


def test_oracle_copy_ratio_fails():
    bounds = {"attempt": (12800, 13000), "map": (12800, 13000),
              "unmap": (12800, 13000), "copy": (100, 200),
              "sync": (12800, 13000)}
    assert km.check_oracle_invariants(bounds)


def test_parse_blockstat_sectors():
    text = "2592 0 20736 120 0 0 0 0 0 0 0 0 0 0 0\n"
    assert km.parse_blockstat(text) == 20736


def test_sectors_nominal_pass():
    before, after = 1000000, 1000000 + 6 * 128 * 2048
    ok, detail = km.check_sectors(before, after, 128)
    assert ok, detail


def test_sectors_no_progress_fails():
    ok, _ = km.check_sectors(1000000, 1000000, 128)
    assert not ok


def test_sectors_far_over_expected_fails():
    ok, _ = km.check_sectors(0, 6 * 128 * 2048 * 4, 128)
    assert not ok


def test_expected_record_refusal_global_floor():
    release = "5.15.223-0515223-generic"
    for cap, cls in (("attempt-trace", "floor-6.0"),
                     ("mapping-lifecycle", "no-cover"),
                     ("copy-actual", "no-cover")):
        assert km.expected_record_refusal(release, cap, cls) == \
            "below floor 6.0"


def test_expected_record_refusal_per_cap():
    release = "6.6.160-0606160-generic"
    assert km.expected_record_refusal(
        release, "mapping-lifecycle", "floor-6.11") == \
        "capability mapping-lifecycle needs kernel 6.11+"
    assert km.expected_record_refusal(
        release, "copy-actual", "no-cover") == \
        "no profile covers this kernel"
    assert km.expected_record_refusal(
        release, "copy-actual", "live-refused") == \
        "live check failed"


def test_expected_record_refusal_floor_611_names_capability():
    assert km.expected_record_refusal(
        "6.6.160-0606160-generic", "copy-actual",
        "floor-6.11") == \
        "capability copy-actual needs kernel 6.11+"


def test_expected_record_refusal_unparseable_fails():
    with pytest.raises(ValueError):
        km.expected_record_refusal("bogus", "attempt-trace",
                                   "floor-6.0")


def test_refusal_probe_caps_pair_with_attempt():
    assert km.refusal_probe_caps("attempt-trace") == "attempt-trace"
    assert km.refusal_probe_caps("mapping-lifecycle") == \
        "attempt-trace,mapping-lifecycle"
    assert km.refusal_probe_caps("copy-actual") == \
        "attempt-trace,copy-actual"


def test_expected_combined_refusal():
    assert km.expected_combined_refusal(
        "5.15.223-0515223-generic",
        [("attempt-trace", "floor-6.0")]) == "below floor 6.0"
    assert km.expected_combined_refusal(
        "6.6.160-0606160-generic",
        [("mapping-lifecycle", "floor-6.11"),
         ("copy-actual", "floor-6.11")]) == \
        "capability mapping-lifecycle needs kernel 6.11+"


def test_check_refusal_pass_and_fail_modes():
    out = "memveil record: kernel 6.6.160-0606160-generic needs kernel 6.11+"
    ok, _ = km.check_refusal("3", out, "no", "needs kernel 6.11+")
    assert ok
    ok, _ = km.check_refusal("4", out, "no", "needs kernel 6.11+")
    assert not ok
    ok, _ = km.check_refusal("3", "other reason", "no",
                             "needs kernel 6.11+")
    assert not ok
    ok, _ = km.check_refusal("3", out, "yes", "needs kernel 6.11+")
    assert not ok


def test_expected_doctor_exit():
    admitted = {"attempt-trace": {"verdict": "admitted",
                                 "reason_class": "live-verified"}}
    refused = {"attempt-trace": {"verdict": "refused",
                                "reason_class": "floor-6.0"}}
    assert km.expected_doctor_exit({"expected": admitted}) == "0"
    assert km.expected_doctor_exit({"expected": refused}) == "3"


def test_boot_identity_match_passes():
    ok, detail = km.check_boot_identity(
        _uname7(), _mods7(), "7.0.14-070014-generic", _CACHE7)
    assert ok, detail


def test_boot_identity_uname_mismatch_fails():
    uname = "7.0.13-070013-generic\nquiet swiotlb=131072,force " \
        "virtme_link_mods=%s\n" % _MODS7
    ok, _ = km.check_boot_identity(
        uname, _mods7(), "7.0.14-070014-generic", _CACHE7)
    assert not ok


def test_boot_identity_mods_path_mismatch_fails():
    other = _CACHE7 + "/usr/lib/modules/7.0.13-070013-generic"
    uname = "7.0.14-070014-generic\nquiet swiotlb=131072,force " \
        "virtme_link_mods=%s\n" % other
    mods = "7.0.14-070014-generic\n%s\n" % other
    ok, _ = km.check_boot_identity(
        uname, mods, "7.0.14-070014-generic", _CACHE7)
    assert not ok


def test_boot_identity_missing_swiotlb_fails():
    uname = "7.0.14-070014-generic\nquiet virtme_link_mods=%s\n" \
        % _MODS7
    ok, _ = km.check_boot_identity(
        uname, _mods7(), "7.0.14-070014-generic", _CACHE7)
    assert not ok


_CACHE7 = "/home/u/.cache/virtme-ng/v7.0.14/amd64"
_MODS7 = _CACHE7 + "/usr/lib/modules/7.0.14-070014-generic"


def _uname7(cmdline="quiet swiotlb=131072,force"):
    return "7.0.14-070014-generic\n%s virtme_link_mods=%s\n" % (
        cmdline, _MODS7)


def _mods7(path=None):
    return "7.0.14-070014-generic\n%s\n" % (path or _MODS7)


def test_boot_identity_verified_cache_passes():
    ok, detail = km.check_boot_identity(
        _uname7(), _mods7(), "7.0.14-070014-generic", _CACHE7)
    assert ok, detail


def test_boot_identity_lib_layout_passes():
    lib = _CACHE7 + "/lib/modules/7.0.14-070014-generic"
    uname = "7.0.14-070014-generic\nquiet swiotlb=131072,force " \
        "virtme_link_mods=%s\n" % lib
    ok, detail = km.check_boot_identity(
        uname, _mods7(lib), "7.0.14-070014-generic", _CACHE7)
    assert ok, detail


def test_boot_identity_outside_verified_cache_fails():
    for evil in (_CACHE7.replace("/home/u", "/root"),
                 "/tmp/evil/7.0.14-070014-generic"):
        if evil == "/tmp/evil/7.0.14-070014-generic":
            path = evil
        else:
            path = evil + "/usr/lib/modules/7.0.14-070014-generic"
        uname = "7.0.14-070014-generic\nquiet swiotlb=131072,force " \
            "virtme_link_mods=%s\n" % path
        ok, _ = km.check_boot_identity(
            uname, _mods7(path), "7.0.14-070014-generic", _CACHE7)
        assert not ok, path


def test_boot_identity_cmdline_token_must_match_mods():
    uname = "7.0.14-070014-generic\nquiet swiotlb=131072,force " \
        "virtme_link_mods=/tmp/evil/x\n"
    ok, _ = km.check_boot_identity(
        uname, _mods7(), "7.0.14-070014-generic", _CACHE7)
    assert not ok


def test_boot_identity_missing_link_token_fails():
    uname = "7.0.14-070014-generic\nquiet swiotlb=131072,force\n"
    ok, _ = km.check_boot_identity(
        uname, _mods7(), "7.0.14-070014-generic", _CACHE7)
    assert not ok


def test_boot_identity_missing_cache_dir_fails():
    ok, _ = km.check_boot_identity(
        _uname7(), _mods7(), "7.0.14-070014-generic", None)
    assert not ok


def test_boot_identity_substring_swiotlb_fails():
    uname = _uname7("swiotlb=131072 noforce")
    ok, _ = km.check_boot_identity(
        uname, _mods7(), "7.0.14-070014-generic", _CACHE7)
    assert not ok


def _built_eval_entry():
    entry = _admitted_entry()
    entry["source"] = {"kind": "built",
                       "config_sha256": "c" * 64}
    return entry


def _distro_eval_entry():
    entry = _admitted_entry()
    entry["source"] = {"kind": "distro",
                       "banner": "Linux version test"}
    return entry


def test_boot_identity_built_config_mismatch_fails():
    ev = _ev_pass()
    ev["entry"] = _built_eval_entry()
    ev["configid_text"] = "c" * 64 + "\n"
    rec = km.evaluate_row(ev)
    assert rec["ok"], json.dumps(rec["checks"], indent=1)
    ev["configid_text"] = "0" * 64 + "\n"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "boot_config")["ok"]


def test_boot_identity_built_no_config_fails():
    ev = _ev_pass()
    ev["entry"] = _built_eval_entry()
    ev["configid_text"] = "absent\n"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "boot_config")["ok"]
    ev["configid_text"] = None
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "boot_config")["ok"]


def test_boot_identity_distro_banner_mismatch_fails():
    ev = _ev_pass()
    ev["entry"] = _distro_eval_entry()
    ev["version_text"] = "Linux version test\n"
    rec = km.evaluate_row(ev)
    assert rec["ok"], json.dumps(rec["checks"], indent=1)
    ev["version_text"] = "Linux version other\n"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "boot_banner")["ok"]
    ev["version_text"] = None
    rec = km.evaluate_row(ev)
    assert not _check(rec, "boot_banner")["ok"]


def test_boot_append_not_in_cmdline_fails():
    ev = _ev_pass()
    entry = _admitted_entry()
    entry["boot_append"] = ["lockdown=confidentiality"]
    ev["entry"] = entry
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "boot_append")["ok"]
    ev["uname_text"] = _uname7("quiet swiotlb=131072,force "
                               "lockdown=confidentiality")
    ev["lockdown_text"] = "none integrity [confidentiality]\n"
    rec = km.evaluate_row(ev)
    assert rec["ok"], json.dumps(rec["checks"], indent=1)


def test_lockdown_not_effective_fails():
    ev = _ev_pass()
    entry = _admitted_entry()
    entry["boot_append"] = ["lockdown=confidentiality"]
    ev["entry"] = entry
    ev["uname_text"] = _uname7("quiet swiotlb=131072,force "
                               "lockdown=confidentiality")
    ev["lockdown_text"] = "none [integrity] confidentiality\n"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "lockdown_effective")["ok"]
    assert _check(rec, "boot_append")["ok"]
    ev["lockdown_text"] = None
    rec = km.evaluate_row(ev)
    assert not _check(rec, "lockdown_effective")["ok"]


def test_lockdown_is_global_class():
    ev = _ev_pass()
    entry = dict(_admitted_entry())
    entry["expected"] = {
        "attempt-trace": {"verdict": "refused",
                          "reason_class": "lockdown"},
        "mapping-lifecycle": {"verdict": "refused",
                              "reason_class": "lockdown"},
        "copy-actual": {"verdict": "refused",
                        "reason_class": "lockdown"},
    }
    ev["entry"] = entry
    rec = km.evaluate_row(ev)
    check = _check(rec, "refusals")
    assert not check["ok"]
    assert "pair cannot attribute" not in check["detail"]
    assert "unknown reason class lockdown" in check["detail"]


def test_record_finalized_accepts_zero_and_four():
    assert km.check_record_finalized("0")[0]
    assert km.check_record_finalized("4")[0]
    assert not km.check_record_finalized("3")[0]
    assert not km.check_record_finalized("1")[0]
    assert not km.check_record_finalized("")[0]


def test_report_consistent_with_record():
    assert km.check_report_consistent("4", ["4", "4"])[0]
    assert km.check_report_consistent("0", ["0", "0"])[0]
    assert not km.check_report_consistent("0", ["4", "0"])[0]
    assert not km.check_report_consistent("4", ["0", "4"])[0]
    assert not km.check_report_consistent("4", ["4", "1"])[0]
    assert not km.check_report_consistent("", ["", ""])[0]
    assert not km.check_report_consistent("4", ["4", ""])[0]


def test_oracle_stderr_lost_events_fails():
    ok, _ = km.check_oracle_stderr("WARNING: Lost 5 events\n")
    assert not ok
    ok, _ = km.check_oracle_stderr("Lost 12 events\n")
    assert not ok


def test_oracle_stderr_benign_passes():
    ok, _ = km.check_oracle_stderr("Lost 0 events\n")
    assert ok
    ok, _ = km.check_oracle_stderr(
        "stdin:7:101-104: WARNING: Success\n"
        "Additional Info - helper: map_lookup_percpu_elem\n")
    assert ok


def test_dmesg_scan_clean_passes():
    text = "[1.0] memveil-matrix-abc\n[2.0] nvme ready\n"
    present, count = km.scan_dmesg(text, "memveil-matrix-abc")
    assert present
    assert count == 0


def test_dmesg_scan_missing_marker_fails_present():
    present, _ = km.scan_dmesg("[1.0] nvme ready\n",
                               "memveil-matrix-abc")
    assert not present


def test_dmesg_scan_suspicious_counted():
    text = ("[1.0] memveil-matrix-abc\n[2.0] BUG: spinlock\n"
            "[3.0] mv-oracle: error flag set\n")
    present, count = km.scan_dmesg(text, "memveil-matrix-abc")
    assert present
    assert count == 1


def test_dmesg_scan_ignores_pre_marker():
    text = "[0.5] BUG: early boot\n[1.0] memveil-matrix-abc\n"
    present, count = km.scan_dmesg(text, "memveil-matrix-abc")
    assert present
    assert count == 0


def test_dmesg_scan_counts_kernel_failure_lines():
    lines = [
        "general protection fault, probably for non-canonical "
        "address 0xdead: 0000 [#1] SMP NOPTI",
        "rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:",
        "INFO: task dd:123 blocked for more than 120 seconds.",
        "BUG: soft lockup - CPU#1 stuck for 22s!",
        "Kernel panic - not syncing: Fatal exception",
        "nvme nvme0: I/O 12 QID 1 timeout, aborting",
        "swiotlb buffer is full (sz: 4096 bytes), total 65536 "
        "(slots), used 65536 (slots)",
    ]
    for line in lines:
        _, count = km.scan_dmesg(
            "[1.0] memveil-matrix-abc\n[2.0] " + line + "\n",
            "memveil-matrix-abc")
        assert count == 1, line


def test_dmesg_scan_ignores_debugfs_notice():
    text = "[1.0] memveil-matrix-abc\n[2.0] debugfs: Directory 'x' " \
        "with parent 'y' already present!\n"
    _, count = km.scan_dmesg(text, "memveil-matrix-abc")
    assert count == 0


def test_dmesg_scan_ignores_trace_automount_notice():
    text = "[1.0] memveil-matrix-abc\n[2.0] NOTICE: Automounting " \
        "of tracing to debugfs is deprecated and will be " \
        "removed in 2030\n"
    _, count = km.scan_dmesg(text, "memveil-matrix-abc")
    assert count == 0


def test_redact_dmesg_strips_addresses():
    text = ("[0.0] e820: [mem 0x00000000-0x0009ffff] usable\n"
            "swiotlb: mapped [mem 0x00000000f8000000-0x00000000fbffffff]\n"
            "BUG: soft lockup detected\n")
    redacted = km.redact_dmesg(text)
    assert "0x00000000" not in redacted
    assert "f8000000" not in redacted
    assert "BUG: soft lockup" in redacted
    km.assert_redacted(redacted)


def test_assert_redacted_rejects_raw_address():
    with pytest.raises(ValueError):
        km.assert_redacted("[mem 0x00000000f8000000-0xfbffffff]")


def test_build_vng_cmd_plain_with_cpus():
    cmd = km.build_vng_cmd(["vng"], "0-7", "/home/u",
                           ["--run", "v7.0.14"])
    assert cmd == ["taskset", "-c", "0-7", "vng",
                   "--run", "v7.0.14"]


def test_build_vng_cmd_plain_without_cpus():
    cmd = km.build_vng_cmd(["vng"], None, "/home/u",
                           ["--run", "v7.0.14"])
    assert cmd == ["vng", "--run", "v7.0.14"]


def test_build_vng_cmd_sudo_carries_home():
    prefix = ["sudo", "-n", "env", "PATH=/x", "vng"]
    cmd = km.build_vng_cmd(prefix, "0-3", "/home/u",
                           ["--run", "v7.0.14"])
    assert cmd == ["sudo", "-n", "taskset", "-c", "0-3", "env",
                   "PATH=/x", "HOME=/home/u", "vng",
                   "--run", "v7.0.14"]


def test_build_vng_cmd_sudo_without_cpus():
    prefix = ["sudo", "-n", "env", "PATH=/x", "vng"]
    cmd = km.build_vng_cmd(prefix, "", "/home/u",
                           ["--run", "v7.0.14"])
    assert cmd == ["sudo", "-n", "env", "PATH=/x",
                   "HOME=/home/u", "vng", "--run", "v7.0.14"]


def test_validate_shell_path_accepts_normal():
    km.validate_shell_path("build/vm/kernels/7.0", "out")
    km.validate_shell_path("/tmp/disk.img", "disk")
    km.validate_shell_path("/work/a-b_c:d,e+f%g", "disk")


def test_validate_shell_path_rejects_metachars():
    for bad in ("a b", "a;b", "a$b", "a`b", "a'b", 'a"b',
                "a\\b", "a\nb", "a*b", "a?b", "a|b", "a&b",
                "a(b", "a)b", "a<b", "a>b", "a#b", "a~b", ""):
        with pytest.raises(ValueError):
            km.validate_shell_path(bad, "out")


def test_qemu_drive_opt_doubles_commas():
    assert km.qemu_drive_opt("/tmp/disk.img") == \
        ("-drive file=/tmp/disk.img,if=none,id=d0,format=raw,"
         "cache=none,readonly=on"
         " -device nvme,serial=mv0,drive=d0")
    assert ",," in km.qemu_drive_opt("/tmp/a,b.img")


def test_persisted_counts_strict():
    lines = ['{"kind": "bounce_attempt"}\n', "\n",
             '{"kind": "map_result"}\n']
    assert km.persisted_counts(lines) == {"bounce_attempt": 1,
                                          "map_result": 1}
    with pytest.raises(ValueError):
        km.persisted_counts(['{"kind": "bounce_attempt"}\n',
                             "not json\n"])
    with pytest.raises(ValueError):
        km.persisted_counts(['{"nkind": 1}\n'])


def _event_line(kind, data):
    return json.dumps({"kind": kind, "data": data}) + "\n"


def _byte_lines():
    return [
        _event_line("bounce_attempt", {"requested_bytes": "4080"}),
        _event_line("bounce_attempt", {"requested_bytes": "4096"}),
        _event_line("map_result", {"mapped_bytes": "8176"}),
        _event_line("sync_request", {"length": "8176"}),
        _event_line("copy", {"direction": "original_to_bounce",
                             "bytes": "4080"}),
        _event_line("copy", {"direction": "original_to_bounce",
                             "bytes": "4096"}),
        _event_line("copy", {"direction": "bounce_to_original",
                             "bytes": "8176"}),
        _event_line("unmap", {"mapping_id": "gen-1"}),
        _event_line("pool_sample", {"used_bytes": "0"}),
        "\n",
    ]


def test_persisted_bytes_sums_per_kind_and_direction():
    sums = km.persisted_bytes(_byte_lines())
    assert sums["requested"] == 8176
    assert sums["mapped"] == 8176
    assert sums["sync"] == 8176
    assert sums["copy"] == {"original_to_bounce": 8176,
                            "bounce_to_original": 8176}


def test_persisted_bytes_rejects_malformed_line():
    with pytest.raises(ValueError):
        km.persisted_bytes(["not json\n"])


def test_persisted_bytes_rejects_missing_field():
    with pytest.raises(ValueError):
        km.persisted_bytes(
            [_event_line("bounce_attempt", {})])


def test_persisted_bytes_rejects_bad_direction():
    with pytest.raises(ValueError):
        km.persisted_bytes([_event_line(
            "copy", {"direction": "sideways", "bytes": "8"})])


def test_persisted_bytes_rejects_negative():
    with pytest.raises(ValueError):
        km.persisted_bytes([_event_line(
            "map_result", {"mapped_bytes": "-8"})])


def test_resolve_inputs():
    assert km.resolve_inputs("/tmp/m.deb", None) == ("deb",
                                                     "/tmp/m.deb")
    assert km.resolve_inputs(None, "/tmp/b") == ("bundle",
                                                 "/tmp/b")
    with pytest.raises(ValueError):
        km.resolve_inputs("/tmp/m.deb", "/tmp/b")
    with pytest.raises(ValueError):
        km.resolve_inputs(None, None)


def test_merge_summary_keys_by_id():
    old = [{"id": "6.0", "ok": False}, {"id": "7.0", "ok": True}]
    new = [{"id": "6.0", "ok": True}]
    merged = km.merge_summary(old, new)
    assert {r["id"]: r["ok"] for r in merged} == {"6.0": True,
                                                 "7.0": True}


def test_merge_summary_appends_new_ids():
    merged = km.merge_summary([{"id": "6.0", "ok": True}],
                              [{"id": "7.0", "ok": True}])
    assert [r["id"] for r in merged] == ["6.0", "7.0"]


def test_check_out_collisions(tmp_path):
    (tmp_path / "7.0").mkdir()
    assert km.check_out_collisions(str(tmp_path),
                                   ["6.0", "7.0"]) == ["7.0"]
    assert km.check_out_collisions(str(tmp_path), ["6.0"]) == []


def _artifacts():
    return {"mode": "deb", "binary": {"path": "/usr/bin/memveil",
                                      "sha256": "a" * 64},
            "dpkg_version": "0.1.0-1",
            "bpf": {"attempt": "b" * 64, "lifecycle": "c" * 64,
                    "copy": "d" * 64},
            "bpftrace": "bpftrace v0.25.0",
            "bpftool": "bpftool v7.7.0"}


def _tools():
    return {"bpftrace": "bpftrace v0.25.0",
            "bpftool": "bpftool v7.7.0"}


def test_check_artifacts_valid_passes():
    assert km.check_artifacts(_artifacts(), _tools()) == []


def test_check_artifacts_version_drift_fails():
    arts = _artifacts()
    arts["bpftrace"] = "bpftrace v0.24.0"
    assert km.check_artifacts(arts, _tools())


def test_check_artifacts_bad_sha_fails():
    arts = _artifacts()
    arts["bpf"]["copy"] = "xyz"
    assert km.check_artifacts(arts, _tools())


def test_check_artifacts_missing_bpf_fails():
    arts = _artifacts()
    del arts["bpf"]["copy"]
    assert km.check_artifacts(arts, _tools())


def test_cache_paths_by_name():
    base = km.cache_base("/home/u", "v7.0.14")
    assert base.endswith("virtme-ng/v7.0.14/amd64")
    assert km.vmlinuz_for_release(
        base, "7.0.14-070014-generic").endswith(
            "boot/vmlinuz-7.0.14-070014-generic")


def test_vng_download_cmd_no_hardcoded_home():
    cmd = km.vng_download_cmd("/home/u/.local/bin/vng", "v7.0.14")
    assert cmd == ["/home/u/.local/bin/vng", "--run", "v7.0.14",
                   "--dry-run"]
    assert "/home/owner" not in " ".join(cmd)


def _admitted_entry():
    return {
        "id": "7.0",
        "release": "7.0.14-070014-generic",
        "upstream": "7.0.14",
        "expected": {
            "attempt-trace": {"verdict": "admitted",
                              "reason_class": "live-verified"},
            "mapping-lifecycle": {"verdict": "admitted",
                                  "reason_class": "live-verified"},
            "copy-actual": {"verdict": "admitted",
                            "reason_class": "live-verified"},
        },
        "oracle": {"omitted": []},
        "source": {
            "kind": "archive",
            "vng_version": "v7.0.14",
            "archive_date": "2026-06-27 15:46",
            "vmlinuz_sha256": "a" * 64,
            "modules_manifest_sha256": "b" * 64,
        },
    }


def _doctor_all_available():
    return {"capabilities": [
        {"id": "attempt-trace", "status": "available",
         "reason": "live-verified under reference profile x"},
        {"id": "mapping-lifecycle", "status": "available",
         "reason": "live-verified under reference profile x"},
        {"id": "copy-actual", "status": "available",
         "reason": "live-verified under reference profile x"},
    ]}


def _oracle_text():
    lines = []
    for t, mult in ((900, 0), (1000, 0), (2000, 1), (2100, 1)):
        lines.append("T %d tp=%d map=%d unmap=%d copy=%d syncc=%d "
                     "syncd=%d tpb=%d" % (
                         t, 13000 * mult, 13000 * mult,
                         13000 * mult, 25990 * mult,
                         13000 * mult, 0, _BYTES768 * mult))
    return "\n".join(lines) + "\n"


def _miss_snaps_text():
    oracle = ["tracepoint_swiotlb_swiotlb_bounced_1",
              "fexit_vmlinux_swiotlb_tbl_map_single_2",
              "fentry_vmlinux___swiotlb_tbl_unmap_single_3",
              "fentry_vmlinux_swiotlb_bounce_4",
              "fentry_vmlinux___swiotlb_sync_single_for_cpu_5",
              "fentry_vmlinux___swiotlb_sync_single_for_device_6",
              "interval_ms_500_7"]
    mv = ["mv_swiotlb_attempt", "mv_map_result", "mv_unmap",
          "mv_sync_cpu", "mv_sync_device", "mv_bounce",
          "mv_bounce_exit"]

    def progs(names, misses):
        out = []
        for name in names:
            prog = {"name": name}
            if name in misses:
                prog["recursion_misses"] = misses[name]
            out.append(prog)
        return out

    snaps = [
        (500, progs(oracle, {})),
        (1200, progs(oracle + mv, {
            "fentry_vmlinux_swiotlb_bounce_4": 2,
            "mv_map_result": 1,
            "mv_bounce": 3})),
        (1800, progs(oracle + mv, {
            "fentry_vmlinux_swiotlb_bounce_4": 8,
            "mv_map_result": 6,
            "mv_bounce": 10})),
        (2200, progs(oracle, {
            "fentry_vmlinux_swiotlb_bounce_4": 10})),
    ]
    return [(t, json.dumps(p)) for t, p in snaps]


def _session_text(recovered=10):
    return json.dumps({
        "product": {"name": "memveil", "version": "memveil-0.1.0"},
        "capture": {"window": {"start_ns": "1000",
                               "end_ns": "2000"}},
        "quality": {"detail": {"status": "partial",
                               "loss_count": "6",
                               "reason": _LOSS7},
                    "aggregate": {"status": "complete_for_scope",
                                  "loss_count": "0"}},
        "environment": {"evidence": [
            {"type": "provenance", "source": "copy.deferred",
             "interpretation": "0"},
            {"type": "provenance", "source": "copy.recovered",
             "interpretation": str(recovered)}]},
    })


def _ev_pass():
    return {
        "entry": _admitted_entry(),
        "tools": _tools(),
        "dd_count": 128,
        "vng_exit": "0",
        "fail_txt": None,
        "doctor_text": json.dumps(_doctor_all_available()),
        "doctor_exit": "0",
        "uname_text": _uname7(),
        "mods_text": _mods7(),
        "cache_dir": _CACHE7,
        "hooks_text": json.dumps({
            "present": {"tp": True, "map": True, "unmap": True,
                        "copy": True, "syncc": True,
                        "syncd": True},
            "omitted": []}),
        "artifacts_text": json.dumps(_artifacts()),
        "refusals": {},
        "record_exit": "4",
        "report_exit": "4",
        "report_json_exit": "4",
        "session_text": _session_text(),
        "workload_text": _workload(1100, 1900),
        "oracle_text": _oracle_text(),
        "oracle_stderr": "stdin:7: WARNING: Success\n",
        "miss_snaps": _miss_snaps_text(),
        "persisted": _persisted7(),
        "persisted_bytes": _byte_sums(),
        "events_error": None,
        "blockstat_text": json.dumps(
            {"dev": "nvme0n1", "before": 1000000,
             "after": 1000000 + 6 * 128 * 2048}),
        "dmesg_text": "[1.0] memveil-matrix-abc\n[2.0] nvme ready\n",
        "dmesg_scan_text": json.dumps(
            {"marker": "memveil-matrix-abc",
             "marker_present": True, "suspicious": 0}),
        "validate_rc": 0,
        "validate_out": "capture OK: 1 events\n",
    }


def _check(rec, name):
    for check in rec["checks"]:
        if check["name"] == name:
            return check
    raise AssertionError("missing check " + name)


def test_evaluate_full_row_passes():
    rec = km.evaluate_row(_ev_pass())
    assert rec["ok"], json.dumps(rec["checks"], indent=1)
    assert rec["oracle_overall"] == "SHORT-COVERED"
    assert _check(rec, "channels")["ok"]
    assert _check(rec, "recursion_reported")["ok"]
    assert _check(rec, "window")["ok"]
    assert _check(rec, "floors")["ok"]
    assert _check(rec, "invariants")["ok"]
    assert _check(rec, "capture_valid")["ok"]


def test_evaluate_fails_vng_exit():
    ev = _ev_pass()
    ev["vng_exit"] = "1"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "vng_exit")["ok"]


def test_evaluate_fails_on_fail_txt():
    ev = _ev_pass()
    ev["fail_txt"] = "record exited before ready\n"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "no_fail_txt")["ok"]


def test_evaluate_requires_progs_snapshots():
    ev = _ev_pass()
    ev["miss_snaps"] = [(500, "[]"), (2200, "[]")]
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "progs_complete")["ok"]


def test_evaluate_rejects_unparseable_progs():
    ev = _ev_pass()
    snaps = list(ev["miss_snaps"])
    snaps[2] = (1800, "bogus")
    ev["miss_snaps"] = snaps
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "progs_complete")["ok"]


def test_evaluate_fails_record_exit_three():
    ev = _ev_pass()
    ev["record_exit"] = "3"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "record_finalized")["ok"]
    assert "record.stderr" in rec["detail"]


def test_evaluate_fails_report_mismatch():
    ev = _ev_pass()
    ev["report_exit"] = "0"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "report_consistent")["ok"]


def test_evaluate_fails_lost_oracle_events():
    ev = _ev_pass()
    ev["oracle_stderr"] = "Lost 3 events\n"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "oracle_health")["ok"]


def test_evaluate_fails_dmesg_suspicious():
    ev = _ev_pass()
    ev["dmesg_scan_text"] = json.dumps(
        {"marker": "memveil-matrix-abc", "marker_present": True,
         "suspicious": 2})
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "dmesg")["ok"]


def test_evaluate_fails_unredacted_dmesg():
    ev = _ev_pass()
    ev["dmesg_text"] = "[mem 0x00000000f8000000-0xfbffffff]\n"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "dmesg")["ok"]


def test_evaluate_fails_validate_rc():
    ev = _ev_pass()
    ev["validate_rc"] = 1
    ev["validate_out"] = "invalid: bad count\n"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "capture_valid")["ok"]


def test_evaluate_fails_events_error():
    ev = _ev_pass()
    ev["persisted"] = None
    ev["events_error"] = "malformed events line 3"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "channels")["ok"]


def test_evaluate_fails_doctor_mismatch():
    ev = _ev_pass()
    doctor = _doctor_all_available()
    doctor["capabilities"][2] = {
        "id": "copy-actual", "status": "unavailable",
        "reason": "live layout differs"}
    ev["doctor_text"] = json.dumps(doctor)
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "doctor")["ok"]


def test_evaluate_fails_doctor_exit():
    ev = _ev_pass()
    ev["doctor_exit"] = "3"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "doctor_exit")["ok"]


def test_evaluate_fails_omitted_drift():
    ev = _ev_pass()
    ev["hooks_text"] = json.dumps(
        {"present": {"tp": True, "map": True, "unmap": False,
                     "copy": True, "syncc": False,
                     "syncd": False},
         "omitted": ["unmap", "syncc", "syncd"]})
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "omitted")["ok"]


def test_evaluate_fails_window_escape():
    ev = _ev_pass()
    ev["workload_text"] = _workload(100, 1900)
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "window")["ok"]


def test_evaluate_copy_shortfall_size_omit_padding_fails():
    ev = _ev_pass()
    ev["persisted"] = dict(ev["persisted"])
    ev["persisted"]["copy"] = 25900
    _add_snap_misses(ev, 2, "mv_bounce", 98)
    _set_session_loss(ev, recursion_missed=6, size_omitted=96)
    rec = km.evaluate_row(ev)
    assert not rec["ok"], json.dumps(rec["checks"], indent=1)


def test_evaluate_split_misses_size_omit_padding_fails():
    ev = _ev_pass()
    ev["persisted"] = dict(ev["persisted"])
    ev["persisted"]["unmap"] = 12995
    _add_snap_misses(ev, 2, "mv_unmap", 5)
    _set_session_loss(ev, recursion_missed=6, size_omitted=5)
    rec = km.evaluate_row(ev)
    assert not rec["ok"], json.dumps(rec["checks"], indent=1)


def test_evaluate_three_channel_misses_duration_padding_fails():
    ev = _ev_pass()
    ev["persisted"] = dict(ev["persisted"])
    ev["persisted"]["bounce_attempt"] = 12995
    ev["persisted"]["unmap"] = 12995
    _add_snap_misses(ev, 2, "mv_swiotlb_attempt", 5)
    _add_snap_misses(ev, 2, "mv_unmap", 5)
    _set_session_loss(ev, recursion_missed=6, duration_omitted=10)
    rec = km.evaluate_row(ev)
    assert not rec["ok"], json.dumps(rec["checks"], indent=1)


_MV_BY_CHANNEL = {
    "attempt": ["mv_swiotlb_attempt"],
    "map": ["mv_map_result"],
    "unmap": ["mv_unmap"],
    "sync": ["mv_sync_cpu", "mv_sync_device"],
    "copy": ["mv_bounce", "mv_bounce_exit"],
}

_MV7 = ["mv_swiotlb_attempt", "mv_map_result", "mv_unmap",
       "mv_sync_cpu", "mv_sync_device", "mv_bounce",
       "mv_bounce_exit"]

_ORACLE7 = ["tracepoint_swiotlb_swiotlb_bounced_7",
            "fexit_vmlinux_swiotlb_tbl_map_single_7",
            "fentry_vmlinux___swiotlb_tbl_unmap_single_7",
            "fentry_vmlinux_swiotlb_bounce_7",
            "fentry_vmlinux___swiotlb_sync_single_for_cpu_7",
            "fentry_vmlinux___swiotlb_sync_single_for_device_7",
            "interval_ms_500_7"]


def _raw_snaps(mv_here=(1, 2), oracle_here=(0, 1, 2, 3)):
    snaps = []
    for idx in range(4):
        progs = [{"name": name} for name in _ORACLE7
                 if idx in oracle_here]
        if idx in mv_here:
            progs += [{"name": name} for name in _MV7]
        snaps.append((idx * 100, progs))
    return snaps


def test_memveil_program_table_pins_expected_names():
    assert km.CHAN_MV_PROGS == _MV_BY_CHANNEL
    assert km.BOUNCE_PROG == "mv_bounce"


def test_prog_presence_bracketed_passes():
    snaps = _raw_snaps()
    assert km.check_prog_presence(
        snaps, _CHANNELS5,
        ["tp", "map", "unmap", "copy", "syncc", "syncd"]) == []


def test_prog_presence_missing_memveil_program_fails():
    snaps = _raw_snaps()
    _, progs = snaps[2]
    progs[:] = [prog for prog in progs
                if prog["name"] != "mv_unmap"]
    fails = km.check_prog_presence(
        snaps, _CHANNELS5,
        ["tp", "map", "unmap", "copy", "syncc", "syncd"])
    assert len(fails) == 1 and "mv_unmap" in fails[0]


def test_prog_presence_memveil_program_before_record_fails():
    snaps = _raw_snaps(mv_here=(0, 1, 2))
    fails = km.check_prog_presence(
        snaps, _CHANNELS5,
        ["tp", "map", "unmap", "copy", "syncc", "syncd"])
    assert any("mv_unmap" in fail for fail in fails)


def test_prog_presence_memveil_program_after_record_fails():
    snaps = _raw_snaps(mv_here=(1, 2, 3))
    fails = km.check_prog_presence(
        snaps, _CHANNELS5,
        ["tp", "map", "unmap", "copy", "syncc", "syncd"])
    assert any("mv_unmap" in fail for fail in fails)


def test_prog_presence_missing_oracle_program_fails():
    snaps = _raw_snaps(oracle_here=(0, 1, 2))
    fails = km.check_prog_presence(
        snaps, _CHANNELS5,
        ["tp", "map", "unmap", "copy", "syncc", "syncd"])
    assert fails and "snapshot 3" in fails[0]


def test_prog_presence_omitted_probe_not_required():
    snaps = []
    keep = ["tracepoint_swiotlb_swiotlb_bounced_7",
            "interval_ms_500_7"]
    for idx in range(4):
        progs = [{"name": name} for name in keep]
        if idx in (1, 2):
            progs.append({"name": "mv_swiotlb_attempt"})
        snaps.append((idx * 100, progs))
    assert km.check_prog_presence(
        snaps, ["attempt"], ["tp"]) == []


def test_kept_oracle_probes_subtracts_omitted():
    assert km.kept_oracle_probes(
        ["attempt-trace", "mapping-lifecycle", "copy-actual"],
        ["unmap", "syncc", "syncd"]) == ["tp", "map", "copy"]


def test_evaluate_renamed_memveil_program_fails():
    ev = _ev_pass()
    ev["persisted"] = dict(ev["persisted"])
    ev["persisted"]["unmap"] = 12995
    snaps = list(ev["miss_snaps"])
    stamp, text = snaps[2]
    progs = json.loads(text)
    for prog in progs:
        if prog.get("name") == "mv_unmap":
            prog["name"] = "mv_unmap_v2"
            prog["recursion_misses"] = 5
    snaps[2] = (stamp, json.dumps(progs))
    ev["miss_snaps"] = snaps
    _set_session_loss(ev, recursion_missed=6, dropped=5)
    rec = km.evaluate_row(ev)
    assert not rec["ok"], json.dumps(rec["checks"], indent=1)


def test_evaluate_missing_memveil_programs_fails():
    ev = _ev_pass()
    ev["persisted"] = dict(ev["persisted"])
    ev["persisted"]["map_result"] = 13000
    _set_session_loss(ev)
    snaps = []
    for stamp, text in ev["miss_snaps"]:
        progs = [prog for prog in json.loads(text)
                 if not prog["name"].startswith("mv_")]
        snaps.append((stamp, json.dumps(progs)))
    ev["miss_snaps"] = snaps
    rec = km.evaluate_row(ev)
    assert not rec["ok"], json.dumps(rec["checks"], indent=1)


def test_evaluate_lingering_memveil_programs_fail():
    ev = _ev_pass()
    snaps = list(ev["miss_snaps"])
    stamp3, text3 = snaps[3]
    progs3 = json.loads(text3)
    have = {prog["name"] for prog in progs3}
    for name in _MV7:
        if name not in have:
            progs3.append({"name": name, "recursion_misses": 0})
    snaps[3] = (stamp3, json.dumps(progs3))
    ev["miss_snaps"] = snaps
    rec = km.evaluate_row(ev)
    assert not rec["ok"], json.dumps(rec["checks"], indent=1)


def _zero_snap_misses(ev):
    snaps = []
    for stamp, text in ev["miss_snaps"]:
        progs = json.loads(text)
        for prog in progs:
            prog.pop("recursion_misses", None)
        snaps.append((stamp, json.dumps(progs)))
    ev["miss_snaps"] = snaps


def _scaled_oracle(maps, tpb):
    lines = []
    for stamp, mult in ((900, 0), (1000, 0), (2000, 1),
                        (2100, 1)):
        lines.append("T %d tp=%d map=%d unmap=%d copy=%d syncc=%d "
                     "syncd=%d tpb=%d" % (
                         stamp, maps * mult, maps * mult,
                         maps * mult, 2 * maps * mult,
                         maps * mult, 0, tpb * mult))
    return "\n".join(lines) + "\n"


def _scaled_persisted(maps):
    return {"bounce_attempt": maps, "map_result": maps,
            "unmap": maps, "copy": 2 * maps,
            "sync_request": maps}


def test_evaluate_low_traffic_row_fails_byte_checks():
    ev = _ev_pass()
    ev["oracle_text"] = _scaled_oracle(3100, 65022441)
    ev["persisted"] = _scaled_persisted(3100)
    ev["persisted_bytes"] = _byte_sums(
        req=65022441, mapped=65022441, sync=65022441,
        cob=65022441, cbo=65022441)
    _zero_snap_misses(ev)
    ev["session_text"] = _session_text(recovered=0)
    _set_session_loss(ev)
    rec = km.evaluate_row(ev)
    assert not rec["ok"], json.dumps(rec["checks"], indent=1)


def test_evaluate_oracle_bytes_mismatch_fails():
    ev = _ev_pass()
    lines = []
    for stamp, mult in ((900, 0), (1000, 0), (2000, 1),
                        (2100, 1)):
        lines.append("T %d tp=%d map=%d unmap=%d copy=%d syncc=%d "
                     "syncd=%d tpb=%d" % (
                         stamp, 13000 * mult, 13000 * mult,
                         13000 * mult, 25990 * mult,
                         13000 * mult, 0,
                         (_BYTES768 // 2) * mult))
    ev["oracle_text"] = "\n".join(lines) + "\n"
    ev["persisted_bytes"] = _byte_sums()
    rec = km.evaluate_row(ev)
    assert not rec["ok"], json.dumps(rec["checks"], indent=1)


def test_evaluate_counts_over_ceiling_fail():
    ev = _ev_pass()
    ev["oracle_text"] = _scaled_oracle(2600000, _BYTES768)
    ev["persisted"] = _scaled_persisted(2600000)
    ev["persisted_bytes"] = _byte_sums()
    _zero_snap_misses(ev)
    ev["session_text"] = _session_text(recovered=0)
    _set_session_loss(ev)
    rec = km.evaluate_row(ev)
    assert not rec["ok"], json.dumps(rec["checks"], indent=1)


def test_evaluate_byte_sums_over_block_fail():
    ev = _ev_pass()
    ev["persisted_bytes"] = _byte_sums(req=_BYTES768 + 512)
    rec = km.evaluate_row(ev)
    assert not rec["ok"], json.dumps(rec["checks"], indent=1)


def test_evaluate_byte_shortfall_within_loss_passes():
    ev = _ev_pass()
    ev["persisted_bytes"] = _byte_sums(
        mapped=_BYTES768 - 100000)
    rec = km.evaluate_row(ev)
    assert rec["ok"], json.dumps(rec["checks"], indent=1)


def test_evaluate_non_dict_doctor_fails_closed():
    ev = _ev_pass()
    ev["doctor_text"] = "[]"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "doctor")["ok"]


def test_evaluate_non_dict_hooks_fails_closed():
    ev = _ev_pass()
    ev["hooks_text"] = "[]"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "omitted")["ok"]


def test_evaluate_non_dict_dmesg_scan_fails_closed():
    ev = _ev_pass()
    ev["dmesg_scan_text"] = "[]"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "dmesg")["ok"]


def test_evaluate_non_dict_artifacts_fails_closed():
    ev = _ev_pass()
    ev["artifacts_text"] = "[1]"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "artifacts")["ok"]


def test_evaluate_non_dict_detail_quality_fails_closed():
    ev = _ev_pass()
    session = json.loads(ev["session_text"])
    session["quality"]["detail"] = "x"
    ev["session_text"] = json.dumps(session)
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "window")["ok"]


def _tool_module():
    import importlib.machinery
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "..", "tools", "kernel-matrix")
    loader = importlib.machinery.SourceFileLoader(
        "matrix_tool", path)
    spec = importlib.util.spec_from_loader("matrix_tool", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_collect_one_crash_fails_row_closed(tmp_path,
                                            monkeypatch):
    tool = _tool_module()
    entry = {
        "id": "5.15",
        "vng_version": "v5.15.223",
        "release": "5.15.223-0515223-generic",
        "expected": {
            "attempt-trace": {"verdict": "refused",
                              "reason_class": "floor-6.0"},
            "mapping-lifecycle": {"verdict": "refused",
                                  "reason_class": "no-cover"},
            "copy-actual": {"verdict": "refused",
                            "reason_class": "no-cover"},
        },
        "oracle": {"omitted": ["unmap", "syncc", "syncd"]},
    }

    def boom(ev):
        raise RuntimeError("synthetic decision crash")

    monkeypatch.setattr(tool.km, "evaluate_row", boom)
    rec = tool.collect_one(entry, str(tmp_path), _tools(), 128,
                           1.0, "run1", False, "/cache", 60)
    assert not rec["ok"]
    assert "crash" in rec["detail"]


def test_release_agrees_rejects_rc_mismatch():
    assert not km.release_agrees_with_upstream(
        "7.3.0-070300rc5-generic", "7.3-rc3")


def test_evaluate_paired_refusal_unattributable_fails():
    ev = _ev_pass()
    entry = dict(_admitted_entry())
    entry["expected"] = {
        "attempt-trace": {"verdict": "refused",
                          "reason_class": "live-refused"},
        "mapping-lifecycle": {"verdict": "refused",
                              "reason_class": "floor-6.11"},
        "copy-actual": {"verdict": "admitted",
                        "reason_class": "live-verified"},
    }
    ev["entry"] = entry
    ev["doctor_text"] = json.dumps({"capabilities": [
        {"id": "attempt-trace", "status": "unavailable",
         "reason": "live layout differs"},
        {"id": "mapping-lifecycle", "status": "unavailable",
         "reason": "release 7.0 is below the 6.11 floor"},
        {"id": "copy-actual", "status": "available",
         "reason": "live-verified under reference profile x"},
    ]})
    ev["doctor_exit"] = "3"
    ev["persisted"] = dict(ev["persisted"])
    ev["persisted"]["map_result"] = 13000
    ev["refusals"] = {
        "cap-attempt-trace": {"exit": "3",
                              "out": "memveil record: live check "
                                     "failed\n",
                              "exists": "no"},
        "cap-mapping-lifecycle": {
            "exit": "3",
            "out": "memveil record: capability mapping-lifecycle "
                   "needs kernel 6.11+\n",
            "exists": "no"},
        "combined": {"exit": "3",
                     "out": "memveil record: live check failed\n",
                     "exists": "no"},
    }
    snaps = []
    for stamp, text in ev["miss_snaps"]:
        progs = json.loads(text)
        for prog in progs:
            if prog["name"].startswith("mv_"):
                prog.pop("recursion_misses", None)
        snaps.append((stamp, json.dumps(progs)))
    ev["miss_snaps"] = snaps
    ev["session_text"] = _session_text(recovered=0)
    _set_session_loss(ev)
    rec = km.evaluate_row(ev)
    assert not rec["ok"], json.dumps(rec["checks"], indent=1)
    assert not _check(rec, "refusals")["ok"]


def _set_session_aggregate(ev, status, loss_count):
    session = json.loads(ev["session_text"])
    session["quality"]["aggregate"] = {
        "status": status, "loss_count": loss_count}
    ev["session_text"] = json.dumps(session)


def test_evaluate_aggregate_partial_fails():
    ev = _ev_pass()
    _set_session_aggregate(ev, "partial", "0")
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "aggregate_quality")["ok"]


def test_evaluate_aggregate_loss_fails():
    ev = _ev_pass()
    _set_session_aggregate(ev, "complete_for_scope", "1")
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "aggregate_quality")["ok"]


def test_evaluate_aggregate_missing_fails():
    ev = _ev_pass()
    session = json.loads(ev["session_text"])
    session["quality"].pop("aggregate", None)
    ev["session_text"] = json.dumps(session)
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "aggregate_quality")["ok"]


def test_repo_identity_reports_commit_and_clean(tmp_path):
    import subprocess
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "f.txt").write_text("one\n")
    subprocess.run(["git", "-C", str(root), "add", "f.txt"],
                   check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=t",
                    "-c", "user.email=t@t", "commit", "-qm",
                    "one"], check=True)
    commit, dirty = km.repo_identity(str(root))
    assert len(commit) == 40 and not dirty
    (root / "f.txt").write_text("two\n")
    _, dirty = km.repo_identity(str(root))
    assert dirty


def test_evaluate_records_workload_size():
    ev = _ev_pass()
    ev["duration"] = 60
    rec = km.evaluate_row(ev)
    assert rec["dd_count"] == 128
    assert rec["duration"] == 60


def test_scan_export_redaction_clean_passes(tmp_path):
    (tmp_path / "record.stderr").write_text("ready session=x\n")
    (tmp_path / "dmesg.txt").write_text("[0.0] ADDR ok\n")
    assert km.scan_export_redaction(str(tmp_path)) is None


def test_scan_export_redaction_names_leaking_file(tmp_path):
    (tmp_path / "record.stderr").write_text(
        "fault at 0x00000000f8000000\n")
    error = km.scan_export_redaction(str(tmp_path))
    assert error is not None and "record.stderr" in error


def test_scan_export_redaction_skips_digest_files(tmp_path):
    (tmp_path / "artifacts.json").write_text('{"a": "%s"}\n'
                                             % ("b" * 64))
    (tmp_path / "progs0.json").write_text(
        '[{"name": "x", "tag": "0612e9d9bb56f065"}]\n')
    (tmp_path / "report.json").write_text('{"a": "%s"}\n'
                                          % ("c" * 64))
    (tmp_path / "configid.txt").write_text("%s\n" % ("d" * 64))
    assert km.scan_export_redaction(str(tmp_path)) is None


def test_scan_export_redaction_skips_capture_dir(tmp_path):
    cap = tmp_path / "cap"
    cap.mkdir()
    (cap / "events.ndjson").write_text("raw 0x00000001\n")
    assert km.scan_export_redaction(str(tmp_path)) is None


def test_scan_export_redaction_rejects_undecodable(tmp_path):
    (tmp_path / "console.txt").write_bytes(b"\xff\xfe\x00bad")
    error = km.scan_export_redaction(str(tmp_path))
    assert error is not None and "console.txt" in error


def test_evaluate_export_redact_error_fails():
    ev = _ev_pass()
    ev["export_redact_error"] = "record.stderr: raw address"
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "export_redacted")["ok"]


def test_evaluate_export_redacted_passes():
    ev = _ev_pass()
    ev["export_redact_error"] = None
    rec = km.evaluate_row(ev)
    assert _check(rec, "export_redacted")["ok"]


def test_evaluate_refused_row_passes():
    entry = {
        "id": "5.15",
        "release": "5.15.223-0515223-generic",
        "upstream": "5.15.223",
        "expected": {
            "attempt-trace": {"verdict": "refused",
                              "reason_class": "floor-6.0"},
            "mapping-lifecycle": {"verdict": "refused",
                                  "reason_class": "no-cover"},
            "copy-actual": {"verdict": "refused",
                            "reason_class": "no-cover"},
        },
        "oracle": {"omitted": ["unmap", "syncc", "syncd"]},
        "source": {
            "kind": "archive",
            "vng_version": "v5.15.223",
            "archive_date": "2026-10-15 23:02",
            "vmlinuz_sha256": "a" * 64,
            "modules_manifest_sha256": "b" * 64,
        },
    }
    out = "memveil record: kernel 5.15.223-0515223-generic " \
        "below floor 6.0\n"
    ev = {
        "entry": entry,
        "tools": _tools(),
        "dd_count": 128,
        "vng_exit": "0",
        "fail_txt": None,
        "doctor_text": json.dumps({"capabilities": [
            {"id": "attempt-trace", "status": "unavailable",
             "reason": "release 5.15 is below the 6.0 floor"},
            {"id": "mapping-lifecycle", "status": "unknown",
             "reason": "no profile covers this identity"},
            {"id": "copy-actual", "status": "unknown",
             "reason": "no profile covers this identity"},
        ]}),
        "doctor_exit": "3",
        "uname_text": "5.15.223-0515223-generic\n"
                      "quiet swiotlb=131072,force "
                      "virtme_link_mods=/home/u/.cache/virtme-ng/"
                      "v5.15.223/amd64/lib/modules/"
                      "5.15.223-0515223-generic\n",
        "mods_text": "5.15.223-0515223-generic\n"
                     "/home/u/.cache/virtme-ng/v5.15.223/amd64/"
                     "lib/modules/5.15.223-0515223-generic\n",
        "cache_dir": "/home/u/.cache/virtme-ng/v5.15.223/amd64",
        "hooks_text": json.dumps({
            "present": {"tp": True, "map": True, "unmap": False,
                        "copy": True, "syncc": False,
                        "syncd": False},
            "omitted": ["unmap", "syncc", "syncd"]}),
        "artifacts_text": json.dumps(_artifacts()),
        "refusals": {
            "cap-attempt-trace": {"exit": "3", "out": out,
                                  "exists": "no"},
            "cap-mapping-lifecycle": {"exit": "3", "out": out,
                                      "exists": "no"},
            "cap-copy-actual": {"exit": "3", "out": out,
                                "exists": "no"},
            "combined": {"exit": "3", "out": out, "exists": "no"},
        },
        "record_exit": None,
        "report_exit": None,
        "report_json_exit": None,
        "session_text": None,
        "workload_text": None,
        "oracle_text": None,
        "oracle_stderr": None,
        "miss_snaps": None,
        "persisted": None,
        "events_error": None,
        "blockstat_text": None,
        "dmesg_text": "[1.0] memveil-matrix-abc\n",
        "dmesg_scan_text": json.dumps(
            {"marker": "memveil-matrix-abc",
             "marker_present": True, "suspicious": 0}),
        "validate_rc": None,
        "validate_out": None,
    }
    rec = km.evaluate_row(ev)
    assert rec["ok"], json.dumps(rec["checks"], indent=1)
    assert _check(rec, "refusals")["ok"]
    assert _check(rec, "channels")["skipped"]


def test_evaluate_attempt_row_wrong_refusal_reason_fails():
    ev = _ev_pass()
    entry = dict(_admitted_entry())
    entry["release"] = "6.6.160-0606160-generic"
    entry["expected"] = {
        "attempt-trace": {"verdict": "admitted",
                          "reason_class": "live-verified"},
        "mapping-lifecycle": {"verdict": "refused",
                              "reason_class": "floor-6.11"},
        "copy-actual": {"verdict": "refused",
                        "reason_class": "floor-6.11"},
    }
    entry["oracle"] = {"omitted": ["unmap", "syncc", "syncd"]}
    ev["entry"] = entry
    good = "memveil record: capability mapping-lifecycle " \
        "needs kernel 6.11+ (this kernel: 6.6.160-0606160-generic)\n"
    ev["refusals"] = {
        "cap-mapping-lifecycle": {"exit": "3", "out": good,
                                  "exists": "no"},
        "cap-copy-actual": {"exit": "3",
                            "out": "memveil record: exploded\n",
                            "exists": "no"},
        "combined": {"exit": "3", "out": good, "exists": "no"},
    }
    rec = km.evaluate_row(ev)
    assert not rec["ok"]
    assert not _check(rec, "refusals")["ok"]
