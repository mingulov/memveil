# SPDX-License-Identifier: GPL-3.0-or-later

"""A07 VM gate: live attempt capture with an ftrace oracle.

Two boots of the frozen harness (virtme-ng 1.41, qemu 10.2.1,
host kernel 7.0.0-34-generic, 6G, pcnet32 stimulus): a
correctness run demanding exact cross-equalities with zero
loss, and a SIGSTOP saturation run demanding exact loss
accounting. Both require narrow candidate admission; any
bound-hash drift fails until re-qualification.

Skips (pytest.skip; tools/vm-attempts maps to 77) when vng,
qemu, or kvm is unavailable. Every in-guest refusal aborts
FAIL, never skip.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
MEMVEIL = REPO / "build" / "memveil"
BRIDGE = REPO / "build" / "deps" / "lmb" / "lib" / "libbpf_mojo.so.1"
PROD_OBJ = REPO / "build" / "bpf" / "swiotlb_attempt.bpf.o"
SAT_OBJ = REPO / "build" / "bpf" / "swiotlb_attempt-test.bpf.o"
NARROW_DOC = REPO / "profiles" / "linux-x86_64-7.0.0-34-generic.json"
SAT_DOC = REPO / "tests" / "fixtures" / "profiles" / "saturation-candidate.json"
GUEST_FLOW = REPO / "tests" / "vm" / "guest_flow.py"

def find_vng():
    cand = os.environ.get("VNG")
    if cand:
        return cand
    found = shutil.which("vng")
    if found:
        return found
    home = Path.home() / ".venv" / "vng" / "bin" / "vng"
    if home.exists():
        return str(home)
    return None


def gate_prefix():
    """vng invocation prefix, or pytest.skip when unrunnable."""
    vng = find_vng()
    armed = any(v == "1" for k, v in os.environ.items()
                if k.startswith("MEMVEIL_VM_"))
    refuse = pytest.fail if armed else pytest.skip
    if not vng:
        refuse("vng not available")
    if not shutil.which("qemu-system-x86_64"):
        refuse("qemu-system-x86_64 not available")
    if not os.path.exists("/dev/kvm"):
        refuse("/dev/kvm not available")
    from harness_env import check_harness_versions
    check_harness_versions(vng)
    rel = os.uname().release
    vmlinuz = f"/boot/vmlinuz-{rel}"
    if os.access(vmlinuz, os.R_OK) and os.access("/dev/kvm", os.W_OK):
        return [vng], dict(os.environ)
    r = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    if r.returncode != 0:
        refuse("vng needs root and no passwordless sudo")
    env = dict(os.environ)
    env["PATH"] = (
        str(Path(vng).parent)
        + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    )
    return ["sudo", "-n", "env", f"PATH={env['PATH']}", vng], env


def run_guest(mode, profile, obj, duration):
    if os.environ.get("MEMVEIL_VM_ATTEMPTS") != "1":
        pytest.skip("attempt VM gates need MEMVEIL_VM_ATTEMPTS=1")
    prefix, env = gate_prefix()
    tmp = Path(tempfile.mkdtemp(prefix=f"vmgate-{mode}-"))
    # Guest /tmp is a private overlay: work files never reach the
    # host; only the rwdir export crosses. Work is guest-local.
    work = "/tmp/vmgate-work"
    export = tmp / "export"
    export.mkdir()
    cmd = prefix + [
        "--run", "-m", "6G", "--network", "user",
        "--qemu-opts=-cpu host",
        "--qemu-opts=-device pcnet,netdev=pcnet0"
        " -netdev user,id=pcnet0,net=10.0.3.0/24",
        f"--rwdir=/tmp/export={export}",
        "--exec",
        f"python3 {GUEST_FLOW} {mode} {work} /tmp/export {REPO}"
        f" {profile} {obj} {BRIDGE} {duration}",
    ]
    from vm_process import run_owned_guest
    proc = run_owned_guest(cmd, timeout=900)
    return tmp, proc


def cleanup(tmp):
    """Remove the run dir, escalating only for root-owned files."""
    if os.environ.get("MEMVEIL_VM_KEEP_EXPORTS") == "1":
        print(f"gate exports retained at {tmp}")
        return
    try:
        shutil.rmtree(tmp, ignore_errors=False)
        return
    except OSError:
        pass
    r = subprocess.run(["sudo", "-n", "rm", "-rf", str(tmp)])
    assert r.returncode == 0, f"cannot clean {tmp}"


def sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


EXPORT_NAMES = (
    "ledger.json", "oracle.json", "ping.txt", "record.stdout",
    "record.stderr", "session.json", "events.ndjson",
)


def verify_exports(tmp, mode):
    export = tmp / "export"
    got = {}
    for name in EXPORT_NAMES:
        f = export / f"{mode}-{name}"
        s = Path(str(f) + ".sha256")
        assert f.is_file(), f"missing export {mode}-{name}"
        assert s.is_file(), f"missing sidecar {mode}-{name}.sha256"
        want = s.read_text().split()[0]
        assert sha_file(f) == want, f"hash mismatch {mode}-{name}"
        got[name] = f
    # Exact inventory: no more, no fewer (the raw ftrace pipe
    # must never cross), and no raw DMA addresses anywhere.
    want_files = {f"{mode}-{n}" for n in EXPORT_NAMES}
    want_files |= {f"{mode}-{n}.sha256" for n in EXPORT_NAMES}
    have = {p.name for p in export.iterdir()}
    assert have == want_files, f"export inventory drift: {have ^ want_files}"
    from export_validation import validate_attempt_exports
    validate_attempt_exports(got)
    return got


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def parse_oracle(path):
    """(events, lost_lines) from the guest oracle (strict schema)."""
    doc = json.loads(path.read_text())
    assert set(doc) == {
        "schema", "lost_lines", "pipe_bytes", "pipe_lines", "header_lines", "blank_lines", "events",
    }, set(doc)
    assert doc["schema"] == "memveil-vm-oracle/1", doc["schema"]
    assert _is_int(doc["lost_lines"]), doc["lost_lines"]
    assert _is_int(doc["pipe_bytes"]), doc["pipe_bytes"]
    assert _is_int(doc["pipe_lines"]), doc["pipe_lines"]
    for key in ("lost_lines", "pipe_bytes", "pipe_lines", "header_lines", "blank_lines"):
        assert _is_int(doc[key]) and doc[key] >= 0, key
    assert doc["pipe_lines"] == len(doc["events"]) + doc["lost_lines"] + doc["header_lines"] + doc["blank_lines"]
    events = []
    assert isinstance(doc["events"], list), type(doc["events"])
    for e in doc["events"]:
        assert set(e) == {"ts_ns", "size", "forced"}, set(e)
        assert _is_int(e["ts_ns"]), e
        assert _is_int(e["size"]), e
        assert isinstance(e["forced"], bool), e
        events.append(
            {"ts_ns": e["ts_ns"], "size": e["size"], "forced": e["forced"]}
        )
    return events, doc["lost_lines"]


def parse_attempts(path):
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            if ev.get("kind") != "bounce_attempt":
                continue
            out.append(
                {
                    "ts_ns": int(ev["ts_ns"]),
                    "size": int(ev["data"]["requested_bytes"]),
                    "forced": bool(ev["data"]["forced"]),
                    "device": ev["data"]["device_id"],
                }
            )
    return out


def evidence(session, source):
    for item in session.get("environment", {}).get("evidence", []):
        if item.get("source") == source:
            return item.get("interpretation")
    for item in session.get("evidence", []):
        if item.get("source") == source:
            return item.get("interpretation")
    return None


def check_provenance(session, release):
    """R4D9: bound captures carry the full measured identity."""
    assert evidence(session, "kernel.release") == release
    bid = evidence(session, "kernel.build_id")
    assert re.fullmatch(r"[0-9a-f]+", bid or ""), bid
    assert len(bid) >= 16, bid
    for key in (
        "object.sha256", "config.sha256", "btf.sha256",
        "format.sha256", "image.sha256", "bridge.sha256",
    ):
        val = evidence(session, key)
        assert re.fullmatch(r"[0-9a-f]{64}", val or ""), (key, val)
    assert evidence(session, "config.src") in ("gz", "file")
    assert evidence(session, "bridge.abi") == "abi-v1 (required)"
    fstype = evidence(session, "output.fs")
    assert fstype and not fstype.startswith("unavailable"), fstype
    ring = evidence(session, "ring.bytes")
    assert ring and int(ring) > 0, ring


def doc_bindings(doc_path):
    doc = json.loads(Path(doc_path).read_text())
    note = doc["identity"]["source"]["note"]
    bind = {}
    for part in note.split(" "):
        k, v = part.split("=", 1)
        bind[k] = v
    return doc, bind


def check_identity_against_doc(ledger, doc_path):
    doc, bind = doc_bindings(doc_path)
    ident = ledger["identity"]
    assert ident["release"] == doc["identity"]["source"]["revision"]
    assert ident["config_src"] == bind["config_src"]
    assert ident["config_sha"] == bind["config"].removeprefix("sha256:")
    assert ident["btf_sha"] == bind["btf"].removeprefix("sha256:")
    assert ident["format_sha"] == bind["format"].removeprefix("sha256:")
    assert ident["image_sha"] == bind["image"].removeprefix("sha256:")
    assert ident["image_bid"] == bind["image_bid"]
    embedded = doc["hooks"][0]["format_text"]
    assert (
        hashlib.sha256(embedded.encode()).hexdigest() == ident["format_sha"]
    ), "live vs embedded format text differ"
    return doc, bind


def run_report(cap_dir):
    proc = subprocess.run(
        [str(MEMVEIL), "report", "--format", "json", str(cap_dir)],
        capture_output=True, text=True, timeout=300,
    )
    return proc


def global_metric(report, name):
    for m in report.get("metrics", []):
        dims = m.get("dimensions", {})
        if (
            m.get("name") == name
            and dims.get("device_id") is None
            and dims.get("pool_id") is None
        ):
            return m
    return None


def test_correctness():
    tmp, proc = run_guest("correctness", NARROW_DOC, PROD_OBJ, 40)
    try:
        assert proc.returncode == 0, f"guest failed: {proc.stderr[-2000:]}"
        check_correctness(tmp)
    except Exception:
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp)


def check_correctness(tmp):
    got = verify_exports(tmp, "correctness")
    ledger = json.loads(got["ledger.json"].read_text())
    session = json.loads(got["session.json"].read_text())
    assert ledger["record_exit"] == 4
    assert session["capture"]["end_reason"] == "duration"
    assert (
        evidence(session, "profile.decision")
        == "validated linux-x86_64-7.0.0-34-generic: bindings hold"
    )
    check_identity_against_doc(ledger, NARROW_DOC)
    check_provenance(session, "7.0.0-34-generic")
    assert ledger["ping_transmitted"] == 5000, ledger["ping_transmitted"]
    assert ledger["lost_markers"] == 0
    for cpu, stats in sorted(ledger["percpu"].items()):
        vals = stats["values"]
        assert vals["overrun"] == 0, (cpu, vals)
        assert vals["commit overrun"] == 0, (cpu, vals)
        assert vals["dropped events"] == 0, (cpu, vals)
    oracle, lost_lines = parse_oracle(got["oracle.json"])
    assert lost_lines == 0
    assert len(oracle) > 0, "oracle saw no events"
    assert not any(e["forced"] for e in oracle), "forced bounce live"
    start, end = ledger["workload_start_ns"], ledger["workload_end_ns"]
    attach = int(evidence(session, "attach_ns"))
    detach = int(evidence(session, "detach_ns"))
    assert attach < start < end < detach
    o_in = [e for e in oracle if start <= e["ts_ns"] <= end]
    o_out = [
        e for e in oracle if attach < e["ts_ns"] < detach
        and not (start <= e["ts_ns"] <= end)
    ]
    assert o_out == [], f"oracle activity outside workload: {len(o_out)}"
    assert len(o_in) > 0
    attempts = parse_attempts(got["events.ndjson"])
    assert len(attempts) > 0, "no persisted attempts"
    assert not any(a["forced"] for a in attempts), "forced persisted"
    p_in = [a for a in attempts if start <= a["ts_ns"] <= end]
    p_out = [
        a for a in attempts if attach < a["ts_ns"] < detach
        and not (start <= a["ts_ns"] <= end)
    ]
    assert p_out == [], f"persisted outside workload: {len(p_out)}"
    detail = session["quality"]["detail"]
    assert detail["status"] == "complete_for_scope", detail
    loss = int(detail.get("loss_count") or 0)
    assert loss == 0, detail
    assert len(o_in) == len(p_in) + loss, (len(o_in), len(p_in), loss)
    from collections import Counter
    assert not (Counter((e["size"], e["forced"]) for e in p_in) - Counter((e["size"], e["forced"]) for e in o_in))
    from collections import Counter
    assert Counter((e["size"], e["forced"]) for e in o_in) == Counter((e["size"], e["forced"]) for e in p_in)
    o_bytes = sum(e["size"] for e in o_in)
    p_bytes = sum(a["size"] for a in p_in)
    assert o_bytes == p_bytes, (o_bytes, p_bytes)
    assert o_bytes > 0
    cap_dir = tmp / "cap-report"
    cap_dir.mkdir()
    shutil.copy(got["session.json"], cap_dir / "session.json")
    shutil.copy(got["events.ndjson"], cap_dir / "events.ndjson")
    rep = run_report(cap_dir)
    assert rep.returncode == 4, rep.stderr[-1000:]
    report = json.loads(rep.stdout)
    assert report["quality"]["detail"]["status"] == "complete_for_scope"
    assert report["quality"]["detail"]["loss_count"] == "0"
    bounce = global_metric(report, "bounce_attempts")
    counter = global_metric(report, "counter_bounce_attempts")
    req = global_metric(report, "requested_bounce_bytes")
    counter_req = global_metric(report, "counter_requested_bounce_bytes")
    assert bounce and counter and req and counter_req
    assert int(bounce["value"]) == len(o_in)
    assert int(counter["value"]) == len(o_in)
    assert int(req["value"]) == o_bytes
    assert int(counter_req["value"]) == o_bytes
    print(f"correctness: oracle={len(o_in)} bytes={o_bytes} exact")


def test_saturation():
    tmp, proc = run_guest("saturation", SAT_DOC, SAT_OBJ, 60)
    try:
        assert proc.returncode == 0, f"guest failed: {proc.stderr[-2000:]}"
        check_saturation(tmp)
    except Exception:
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp)


def check_saturation(tmp):
    got = verify_exports(tmp, "saturation")
    ledger = json.loads(got["ledger.json"].read_text())
    session = json.loads(got["session.json"].read_text())
    assert ledger["record_exit"] == 4
    assert session["capture"]["end_reason"] == "signal"
    assert (
        evidence(session, "profile.decision")
        == "candidate saturation-candidate:"
        " bindings hold (profile unvalidated)"
    )
    check_identity_against_doc(ledger, SAT_DOC)
    check_provenance(session, "7.0.0-34-generic")
    assert ledger["ping_transmitted"] == 5000, ledger["ping_transmitted"]
    assert ledger["lost_markers"] == 0, "oracle unreliable under flood"
    for cpu, stats in sorted(ledger["percpu"].items()):
        vals = stats["values"]
        assert vals["overrun"] == 0, (cpu, vals)
        assert vals["commit overrun"] == 0, (cpu, vals)
        assert vals["dropped events"] == 0, (cpu, vals)
    oracle, lost_lines = parse_oracle(got["oracle.json"])
    assert lost_lines == 0
    assert len(oracle) > 0
    start, end = ledger["workload_start_ns"], ledger["workload_end_ns"]
    attach = int(evidence(session, "attach_ns"))
    detach = int(evidence(session, "detach_ns"))
    assert attach < start < end < detach
    o_in = [e for e in oracle if start <= e["ts_ns"] <= end]
    o_out = [
        e for e in oracle if attach < e["ts_ns"] < detach
        and not (start <= e["ts_ns"] <= end)
    ]
    assert o_out == [], f"oracle activity outside workload: {len(o_out)}"
    assert len(o_in) > 0
    attempts = parse_attempts(got["events.ndjson"])
    p_in = [a for a in attempts if start <= a["ts_ns"] <= end]
    p_out = [
        a for a in attempts if attach < a["ts_ns"] < detach
        and not (start <= a["ts_ns"] <= end)
    ]
    assert p_out == [], f"persisted outside workload: {len(p_out)}"
    detail = session["quality"]["detail"]
    assert detail["status"] == "partial", detail
    loss = int(detail.get("loss_count") or 0)
    assert loss > 0, detail
    assert len(o_in) == len(p_in) + loss, (len(o_in), len(p_in), loss)
    from collections import Counter
    assert not (Counter((e["size"], e["forced"]) for e in p_in) - Counter((e["size"], e["forced"]) for e in o_in))
    m = re.search(r"submit_fail=\((\d+)\)", detail.get("reason", ""))
    assert m and int(m.group(1)) > 0, detail.get("reason")
    cap_dir = tmp / "cap-report"
    cap_dir.mkdir()
    shutil.copy(got["session.json"], cap_dir / "session.json")
    shutil.copy(got["events.ndjson"], cap_dir / "events.ndjson")
    rep = run_report(cap_dir)
    assert rep.returncode == 4, rep.stderr[-1000:]
    report = json.loads(rep.stdout)
    assert report["quality"]["detail"]["status"] == "partial"
    assert int(report["quality"]["detail"]["loss_count"]) == loss
    bounce = global_metric(report, "bounce_attempts")
    counter = global_metric(report, "counter_bounce_attempts")
    assert bounce and counter
    assert int(bounce["value"]) + loss == int(counter["value"])
    assert int(counter["value"]) == len(o_in)
    req = global_metric(report, "requested_bounce_bytes")
    counter_req = global_metric(report, "counter_requested_bounce_bytes")
    assert req and counter_req
    assert int(req["value"]) == sum(e["size"] for e in p_in)
    assert int(counter_req["value"]) == sum(e["size"] for e in o_in)
    print(
        f"saturation: oracle={len(o_in)} persisted={len(p_in)}"
        f" loss={loss} exact"
    )
