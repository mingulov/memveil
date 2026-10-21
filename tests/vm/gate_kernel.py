#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Gate kernel selection shared by every VM gate.

The gates boot the host kernel, or MEMVEIL_ORACLE_KVER through
the VNG path. A shipped validated profile whose revision names
that release and whose bindings hold against the measured
identity and the current objects is used as is ("shipped").
Otherwise, when the guest boots the host kernel, the host
measures the identity with the guest's own rules and mints an
unvalidated gate profile under build/vm/gate-profiles/<release>/
("minted"). The guest measures again and every exact assertion
compares against the selected profile, so minting never relaxes
a check: it only names the kernel actually under test. A
different guest release with no holding shipped profile fails
closed. MEMVEIL_VM_REQUIRE_SHIPPED=1 refuses minted mode for
runs that confirm a shipped claim. The saturation candidate is
always minted: it is unvalidated by design.

Lanes that load probes without record's admission (mv_consume)
also need the running kernel's hook signatures and layouts
verified; prepare() requires memveil doctor to report every
capability live-verified before a guest boots, and copies the
selection to build/vm/gate-profile.json for guest-side readers.
"""

import gzip
import hashlib
import importlib.util
import json
import os
import subprocess
from dataclasses import dataclass
from importlib.machinery import SourceFileLoader
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
PROFILES = REPO / "profiles"
EMITTER = REPO / "tools" / "emit-gate-profiles"
OUT_ROOT = REPO / "build" / "vm" / "gate-profiles"
SELECTED = REPO / "build" / "vm" / "gate-profile.json"
MEMVEIL = REPO / "build" / "memveil"
PROD_OBJ = REPO / "build" / "bpf" / "swiotlb_attempt.bpf.o"
LC_OBJ = REPO / "build" / "bpf" / "swiotlb_lifecycle.bpf.o"
CP_OBJ = REPO / "build" / "bpf" / "swiotlb_copy.bpf.o"
FMT_PATH = "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"


class GateKernelError(Exception):
    """The gate kernel cannot be selected; armed gates fail."""


@dataclass(frozen=True)
class GateKernel:
    mode: str
    release: str
    gate_doc: Path
    sat_doc: Path

    def decision(self, doc_path):
        """Admission decision record must print for doc_path."""
        doc = json.loads(Path(doc_path).read_text())
        if doc["status"] == "validated":
            return "validated %s: bindings hold" % doc["profile_id"]
        return ("candidate %s: bindings hold (profile unvalidated)"
                % doc["profile_id"])


def gate_release():
    """Release the guest boots: the override, else the host."""
    return os.environ.get("MEMVEIL_ORACLE_KVER") or os.uname().release


def read_root(path):
    """Bytes of a file, escalating to passwordless sudo when needed."""
    try:
        return Path(path).read_bytes()
    except OSError:
        pass
    proc = subprocess.run(["sudo", "-n", "cat", path],
                          capture_output=True, timeout=60)
    if proc.returncode != 0:
        raise GateKernelError("cannot read %s directly or via sudo -n"
                              % path)
    return proc.stdout


def gnu_bid(notes):
    """GNU build-id from /sys/kernel/notes bytes, or None."""
    pos = 0
    while pos + 12 <= len(notes):
        namesz, descsz, ntype = (int.from_bytes(notes[pos + i:pos + i + 4],
                                                "little")
                                 for i in (0, 4, 8))
        pos += 12
        is_gnu = (ntype == 3 and namesz == 4
                  and notes[pos:pos + 4] == b"GNU\x00")
        pos += ((namesz + 3) // 4) * 4
        if is_gnu and descsz == 20:
            return notes[pos:pos + 20].hex()
        pos += ((descsz + 3) // 4) * 4
    return None


def measure_identity(release, root="/"):
    """Host identity with the guest's rules (guest_flow.identity)."""
    def at(path):
        return os.path.join(root, path.lstrip("/"))
    try:
        raw = Path(at("/proc/config.gz")).read_bytes()
        src = "gz"
        cfg = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    except OSError:
        try:
            cfg = Path(at("/boot/config-" + release)).read_bytes()
            src = "file"
        except OSError:
            raise GateKernelError("no kernel config source for "
                                  + release)
    fmt = read_root(at(FMT_PATH))
    bid = gnu_bid(read_root(at("/sys/kernel/notes")))
    if not bid:
        raise GateKernelError("no GNU build-id in kernel notes")
    ident = {
        "release": release,
        "config_src": src,
        "config_sha": hashlib.sha256(cfg).hexdigest(),
        "btf_sha": hashlib.sha256(
            Path(at("/sys/kernel/btf/vmlinux")).read_bytes()).hexdigest(),
        "format_sha": hashlib.sha256(fmt).hexdigest(),
        "image_sha": hashlib.sha256(
            read_root(at("/boot/vmlinuz-" + release))).hexdigest(),
        "image_bid": bid,
    }
    return ident, fmt.decode()


def emitter():
    loader = SourceFileLoader("gate_profile_emitter", str(EMITTER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _note(doc):
    return dict(part.split("=", 1)
                for part in doc["identity"]["source"]["note"].split())


def binding_drift(doc, ident, objects):
    """Names of the shipped bindings that do not hold, in note order."""
    want = {
        "config": "sha256:" + ident["config_sha"],
        "config_src": ident["config_src"],
        "btf": "sha256:" + ident["btf_sha"],
        "format": "sha256:" + ident["format_sha"],
        "image": "sha256:" + ident["image_sha"],
        "image_bid": ident["image_bid"],
    }
    for key, path in objects.items():
        want[key] = "sha256:" + hashlib.sha256(
            Path(path).read_bytes()).hexdigest()
    note = _note(doc)
    drift = [k for k in note if k in want and note[k] != want[k]]
    drift += [k for k in want if k not in note
              and k not in ("lc_object", "cp_object")]
    if doc["identity"]["source"]["revision"] != ident["release"]:
        drift.insert(0, "revision")
    return drift


def shipped_identity(doc):
    """Identity a shipped profile binds, in measure_identity's shape."""
    note = _note(doc)
    return {"release": doc["identity"]["source"]["revision"],
            "config_src": note["config_src"],
            "config_sha": note["config"][7:], "btf_sha": note["btf"][7:],
            "format_sha": note["format"][7:], "image_sha": note["image"][7:],
            "image_bid": note["image_bid"]}


def shipped_profile(release, profiles=PROFILES):
    """Path of the validated shipped profile naming release, or None."""
    for name in (Path(profiles) / "manifest.txt").read_text().split():
        path = Path(profiles) / name
        try:
            doc = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if (doc.get("status") == "validated"
                and doc.get("identity", {}).get("source", {})
                .get("revision") == release):
            return path
    return None


def select(release=None, root="/", out_root=OUT_ROOT,
           objects=None, require_shipped=None, profiles=PROFILES,
           host_release=None):
    """Pick or mint the gate profiles for the kernel under test."""
    release = release or gate_release()
    if require_shipped is None:
        require_shipped = (
            os.environ.get("MEMVEIL_VM_REQUIRE_SHIPPED") == "1")
    objects = objects or {"object": PROD_OBJ, "lc_object": LC_OBJ,
                          "cp_object": CP_OBJ}
    host = host_release or os.uname().release
    if release != host:
        # Foreign guest kernel: only its shipped claim can admit it.
        path = shipped_profile(release, profiles)
        if path is None:
            raise GateKernelError(
                "no validated shipped profile names guest kernel "
                + release)
        # The host cannot measure a foreign kernel; its shipped claim names it.
        doc = json.loads(path.read_text())
        _, sat_doc = emitter().gate_docs(shipped_identity(doc),
                                         doc["hooks"][0]["format_text"],
                                         doc["profile_id"])
        out = Path(out_root) / release
        out.mkdir(parents=True, exist_ok=True)
        sat = out / "saturation-candidate.json"
        sat.write_text(json.dumps(sat_doc, indent=2) + "\n")
        return GateKernel("shipped", release, path, sat)
    ident, fmt_text = measure_identity(release, root)
    out = Path(out_root) / release
    out.mkdir(parents=True, exist_ok=True)
    gate_doc, sat_doc = emitter().gate_docs(
        ident, fmt_text, "gate-" + release)
    sat = out / "saturation-candidate.json"
    sat.write_text(json.dumps(sat_doc, indent=2) + "\n")
    path = shipped_profile(release, profiles)
    if path is not None:
        drift = binding_drift(json.loads(path.read_text()), ident,
                              objects)
        if not drift:
            return GateKernel("shipped", release, path, sat)
        reason = ("shipped %s bindings drift: %s"
                  % (path.name, ", ".join(drift)))
    else:
        reason = "no validated shipped profile names " + release
    if require_shipped:
        raise GateKernelError(
            "MEMVEIL_VM_REQUIRE_SHIPPED=1 but " + reason)
    gate = out / "gate.json"
    gate.write_text(json.dumps(gate_doc, indent=2) + "\n")
    print("gate kernel %s: minted (%s)" % (release, reason))
    return GateKernel("minted", release, gate, sat)


_SELECTED = None


def require_live_interfaces(caps, memveil=MEMVEIL):
    """Fail unless memveil doctor live-verifies every cap here."""
    proc = subprocess.run(["sudo", "-n", str(memveil), "doctor", "--json"],
                          capture_output=True, text=True, timeout=120)
    try:
        doc = json.loads(proc.stdout)
    except ValueError:
        raise GateKernelError("doctor --json unreadable (exit %d): %s"
                              % (proc.returncode, proc.stderr[-500:]))
    gaps = live_gaps(doc, caps)
    if gaps:
        raise GateKernelError("not live-verified on %s: %s"
                              % (os.uname().release, "; ".join(gaps)))


def live_gaps(doc, caps):
    """Caps doctor did not report available and live-verified."""
    got = {c.get("id"): c for c in doc.get("capabilities", [])}
    gaps = []
    for cap in caps:
        entry = got.get(cap) or {}
        if (entry.get("status") != "available"
                or not entry.get("reason", "").startswith("live-verified")):
            gaps.append("%s (%s)" % (cap, entry.get("reason", "absent")))
    return gaps


def prepare(caps=("attempt-trace", "mapping-lifecycle", "copy-actual")):
    """Select the gate kernel, verify its interfaces, publish it."""
    global _SELECTED
    sel = select()
    if sel.release == os.uname().release:
        require_live_interfaces(caps)
    SELECTED.parent.mkdir(parents=True, exist_ok=True)
    SELECTED.write_text(Path(sel.gate_doc).read_text())
    _SELECTED = sel
    return sel


def selected():
    """The selection prepare() made for this run."""
    if _SELECTED is None:
        raise GateKernelError("gate kernel not prepared")
    return _SELECTED


def selected_profile_id():
    return json.loads(Path(selected().gate_doc).read_text())["profile_id"]
