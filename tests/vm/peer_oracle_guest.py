#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Peer-leg guest flow: owned NIC, tracefs oracle, sealed-candidate
capture, export.

Runs as root inside the virtme-ng guest (one boot for the
peer case). Brings up the owned off-loopback pcnet NIC,
runs a tracefs outer-DMA-API oracle window around peer
traffic while the product ``record`` captures the same
window, brackets NIC teardown/re-up, pairs maps to releases
in-guest with the shared oracle library, and exports opaque
rows plus counts with hash sidecars. Raw trace bytes (DMA
addresses) never cross to the host: only opaque key ids,
counts, hashes, and timestamps leave the guest.

Every setup, workload, oracle-parse, or capture refusal
aborts FAIL (exit 1), never skip. Semantic attribution
(orphans, still-open, agreement) is exported as data; the
host judges it. The product record logs (stdout/stderr)
are exported to the rwdir on every path, so a capture
refusal stays diagnosable after the guest is gone.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import peer_oracle as oracle


def fail(msg):
    print("peer_oracle_guest: FAIL: %s" % (msg,), file=sys.stderr)
    sys.exit(1)


def sh(args, timeout=180):
    return subprocess.run(args, capture_output=True, text=True,
                          timeout=timeout)


def read_text(path):
    with open(path, "rb") as handle:
        return handle.read().decode("utf-8", "replace")


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def mono_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def export_file(export_dir, name, data):
    if not isinstance(data, str):
        data = json.dumps(data, indent=1, sort_keys=True) + "\n"
    raw = data.encode("utf-8")
    with open(os.path.join(export_dir, "peer-" + name), "wb") as fh:
        fh.write(raw)
    with open(os.path.join(export_dir,
                           "peer-" + name + ".sha256"),
              "w") as fh:
        fh.write("%s  %s\n" % (sha_bytes(raw), "peer-" + name))


def export_record_logs(work, export_dir):
    """Best-effort copy of the record logs to the rwdir.

    Copies ``record.out``/``record.stderr`` from the
    guest-local work dir to ``peer-``-prefixed exports
    with hash sidecars. Missing sources, a missing work
    dir, or an unwritable export dir skip quietly: this
    runs on failure paths where raising would mask the
    real error, and the host reports absent logs
    explicitly. Never raises.
    """
    if not work or not export_dir:
        return
    try:
        os.makedirs(export_dir, exist_ok=True)
    except OSError:
        return
    for name in oracle.RECORD_LOGS:
        try:
            with open(os.path.join(work, name), "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        try:
            export_file(export_dir, name,
                        data.decode("utf-8", "replace"))
        except OSError:
            continue


def record_argv(memveil, args, dest):
    """Exact product record argv for the window capture."""
    return [memveil, "record", "--output", dest,
            "--duration", str(args.duration),
            "--capability", args.caps]


def find_pcnet():
    for iface in sorted(os.listdir("/sys/class/net")):
        drv = os.path.join("/sys/class/net", iface, "device",
                           "driver")
        try:
            if os.readlink(drv).endswith("pcnet32"):
                return iface
        except OSError:
            continue
    return None


def nic_pci(iface):
    try:
        link = os.readlink("/sys/class/net/%s/device" % (iface,))
        return link.split("/")[-1]
    except OSError:
        return ""


def nic_stat(iface, name):
    try:
        return int(read_text("/sys/class/net/%s/statistics/%s"
                             % (iface, name)).strip())
    except (OSError, ValueError):
        return None


def trace_root():
    for cand in ("/sys/kernel/tracing",
                 "/sys/kernel/debug/tracing"):
        if os.path.isdir(os.path.join(cand, "events")):
            return cand
    return None


def trace_write(root, rel, text):
    with open(os.path.join(root, rel), "w") as handle:
        handle.write(text)


def cpu_drops(root):
    drops = {}
    try:
        cpus = sorted(os.listdir(os.path.join(root, "per_cpu")))
    except OSError:
        fail("per-cpu trace stats unreadable")
    for cpu in cpus:
        try:
            text = read_text(os.path.join(root, "per_cpu", cpu,
                                          "stats"))
        except OSError:
            fail("trace stats unreadable for %s" % (cpu,))
        match = re.search(r"dropped events\s*:\s*(\d+)", text)
        if match is None:
            fail("no dropped-events counter for %s" % (cpu,))
        drops[cpu] = int(match.group(1))
    if not drops:
        fail("empty per-cpu trace inventory")
    return drops


def setup_nic(args):
    """Bring up the owned NIC and prove the traffic path."""
    release = os.uname()[2]
    if release != args.release:
        fail("guest release %r, want pinned %r"
             % (release, args.release))
    try:
        cmdline = read_text("/proc/cmdline")
    except OSError:
        fail("/proc/cmdline unreadable")
    if "swiotlb=force" not in cmdline.split():
        fail("swiotlb=force missing from guest cmdline")
    btf_path = "/sys/kernel/btf/vmlinux"
    if not os.path.isfile(btf_path):
        fail("guest BTF missing (BTF required)")
    btf_sha = oracle.sha_file(btf_path)
    iface = find_pcnet()
    if iface is None:
        fail("no pcnet32 NIC found")
    pci = nic_pci(iface)
    if pci.lower() != args.pci.lower():
        fail("owned NIC pci %r, want oracle device %r"
             % (pci, args.pci))
    try:
        mask = read_text("/sys/class/net/%s/device/dma_mask_bits"
                         % (iface,)).strip()
    except OSError:
        fail("dma_mask_bits unreadable")
    if mask != "32":
        fail("pcnet dma_mask_bits is %r, want 32" % (mask,))
    proc = sh(["sysctl", "-w",
               "net.ipv6.conf.%s.disable_ipv6=1" % (iface,)])
    if proc.returncode != 0:
        fail("ipv6 disable failed: %s" % (proc.stderr.strip(),))
    proc = sh(["ip", "link", "set", iface, "up"])
    if proc.returncode != 0:
        fail("ip link up failed: %s" % (proc.stderr.strip(),))
    proc = sh(["ip", "addr", "add", args.addr, "dev", iface])
    if proc.returncode != 0 and "exists" not in proc.stderr:
        fail("ip addr failed: %s" % (proc.stderr.strip(),))
    addr = sh(["ip", "-o", "addr", "show", iface])
    if args.addr not in addr.stdout:
        fail("owned address %s missing: %s"
             % (args.addr, addr.stdout.strip()))
    proc = sh(["ping", "-c", "1", "-W", "3", args.gateway])
    if proc.returncode != 0:
        fail("gateway ping failed: %s" % (proc.stdout.strip(),))
    print("peer_oracle_guest: nic %s %s up, path ok"
          % (iface, pci), flush=True)
    return {"release": release, "btf_sha": btf_sha,
            "iface": iface, "pci": pci.lower()}


def setup_tracefs(args):
    """Bind the oracle event set, formats, and buffer."""
    root = trace_root()
    if root is None:
        fail("no tracefs events dir")
    dma_dir = os.path.join(root, "events", "dma")
    try:
        dma_events = sorted(os.listdir(dma_dir))
    except OSError:
        fail("events/dma unreadable")
    for event in oracle.ORACLE_EVENTS:
        if event not in dma_events:
            fail("missing outer-DMA-API event %s" % (event,))
    # Siblings stay off: prove every dma enable reads back 0
    # before this leg enables exactly its two events.
    for event in dma_events:
        enable = os.path.join(dma_dir, event, "enable")
        if not os.path.isfile(enable):
            continue
        try:
            state = read_text(enable).strip()
        except OSError:
            continue
        if state != "0":
            fail("dma event %s already enabled" % (event,))
    ids = {}
    formats = {}
    for event in oracle.ORACLE_EVENTS:
        try:
            ids[event] = int(read_text(
                os.path.join(dma_dir, event, "id")).strip())
            fmt = read_text(os.path.join(dma_dir, event,
                                         "format"))
        except (OSError, ValueError):
            fail("event %s id/format unreadable" % (event,))
        formats[event] = sha_bytes(fmt.encode("utf-8"))
    try:
        map_fmt = read_text(os.path.join(
            dma_dir, "dma_map_phys", "format"))
        unmap_fmt = read_text(os.path.join(
            dma_dir, "dma_unmap_phys", "format"))
    except OSError:
        fail("event formats unreadable")
    tokens_ok = all(token in map_fmt for token in
                    ("dma_addr=", "dir=", "size=", "phys_addr="))
    tokens_ok = tokens_ok and all(token in unmap_fmt
                                  for token in
                                  ("dma_addr=", "dir=", "size="))
    if not tokens_ok:
        fail("oracle print format lacks bound tokens")
    trace_write(root, "current_tracer", "nop\n")
    trace_write(root, "buffer_size_kb", "%d\n" % (args.buffer_kb,))
    try:
        actual_kb = int(read_text(
            os.path.join(root, "buffer_size_kb")).strip())
    except (OSError, ValueError):
        fail("buffer_size_kb unreadable")
    try:
        clock = read_text(
            os.path.join(root, "trace_clock")).strip()
    except OSError:
        clock = ""
    if not clock:
        fail("trace_clock unreadable")
    print("peer_oracle_guest: tracefs %s buffer %d events %s"
          % (root, actual_kb, ",".join(oracle.ORACLE_EVENTS)),
          flush=True)
    return {"root": root, "event_ids": ids,
            "format_sha": formats, "format_tokens_ok": True,
            "buffer_kb": actual_kb, "trace_clock": clock}


def sealed_record_binary():
    """Resolve the sealed record binary in-guest.

    The host passes MV_CANDIDATE_MANIFEST/MV_BUNDLE_TARBALL/
    MV_CANDIDATE_DIGEST; the guest re-verifies the same
    candidate and resolves bin/memveil under the verified
    root, exactly like the host. No dev fallback: the leg
    only ever measures sealed bytes.
    """
    repo = os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))
    sys.path.insert(0, os.path.join(repo, "tests"))
    try:
        from support.candidate_input import load
        selected = load(required=True)
        binary = str(selected.path("bin/memveil"))
    except ValueError as exc:
        fail("the sealed candidate unusable in-guest: %s" % (exc,))
    if not os.access(binary, os.X_OK):
        fail("sealed record binary not executable")
    return binary


def start_record(args, work):
    """Start the product capture spanning the oracle window."""
    memveil = sealed_record_binary()
    binary_sha = oracle.sha_file(memveil)
    dest = os.path.join(work, "cap")
    argv = record_argv(memveil, args, dest)
    out_path = os.path.join(work, "record.out")
    err_path = os.path.join(work, "record.stderr")
    with open(out_path, "w") as out:
        with open(err_path, "w") as err:
            try:
                proc = subprocess.Popen(
                    argv, stdout=out, stderr=err,
                    start_new_session=True)
            except OSError as exc:
                fail("record spawn failed: %s" % (exc,))
    ready = None
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            text = read_text(out_path)
        except OSError:
            text = ""
        for line in text.splitlines():
            match = oracle.READY_RE.fullmatch(line.strip())
            if match:
                ready = (match.group(1), int(match.group(2)))
                break
        if ready is not None:
            break
        if proc.poll() is not None:
            fail("record exited %d before ready; see "
                 "peer-record.stderr" % (proc.returncode,))
        time.sleep(0.2)
    if ready is None:
        proc.kill()
        fail("record not ready in 120s; see "
             "peer-record.stderr")
    print("peer_oracle_guest: record ready session=%s"
          % (ready[0],), flush=True)
    export_record_logs(work, args.export)
    return {"proc": proc, "dest": dest, "work": work,
            "binary_sha": binary_sha,
            "ready_session": ready[0],
            "ready_start_ns": ready[1]}


def stop_record(handle, args):
    """Wait out the capture and bind its outputs."""
    proc = handle["proc"]
    try:
        proc.wait(timeout=args.duration + 120)
    except subprocess.TimeoutExpired:
        proc.kill()
        fail("record did not stop after its duration")
    if proc.returncode != 0:
        fail("record exited %d; see peer-record.stderr"
             % (proc.returncode,))
    session_path = os.path.join(handle["dest"], "session.json")
    events_path = os.path.join(handle["dest"], "events.ndjson")
    if not os.path.isfile(session_path) \
            or not os.path.isfile(events_path):
        fail("record outputs missing")
    try:
        session = json.loads(read_text(session_path))
    except ValueError:
        fail("record session.json unparseable")
    if session.get("session_id") != handle["ready_session"]:
        fail("record session %r does not bind ready %r"
             % (session.get("session_id"),
                handle["ready_session"]))
    try:
        first = read_text(events_path).splitlines()[0]
        profile = json.loads(first)["source"]["profile_id"]
    except (ValueError, KeyError, IndexError):
        fail("record events carry no profile")
    print("peer_oracle_guest: record done profile=%s"
          % (profile,), flush=True)
    export_record_logs(handle["work"], args.export)
    return {"session_path": session_path,
            "events_path": events_path, "profile": profile}


def ping_workload(gateway, count):
    """Flood-ping the peer; return (tx, rx)."""
    proc = sh(["timeout", "180", "ping", "-A", "-c", str(count),
               "-q", gateway], timeout=200)
    if proc.returncode != 0:
        fail("ping workload failed rc=%d: %s"
             % (proc.returncode, proc.stderr.strip()[-300:]))
    sent = re.search(r"(\d+) packets transmitted", proc.stdout)
    rcvd = re.search(r"(\d+) received", proc.stdout)
    tx = int(sent.group(1)) if sent else 0
    rx = int(rcvd.group(1)) if rcvd else 0
    if tx <= 0 or rx <= 0:
        fail("no peer traffic (tx=%d rx=%d)" % (tx, rx))
    return tx, rx


def open_window(trace):
    root = trace["root"]
    trace_write(root, "tracing_on", "0\n")
    trace_write(root, "trace", "\n")
    drops = cpu_drops(root)
    for event in oracle.ORACLE_EVENTS:
        trace_write(root, "events/dma/%s/enable" % (event,),
                    "1\n")
    for event in oracle.ORACLE_EVENTS:
        state = read_text(os.path.join(
            root, "events", "dma", event, "enable")).strip()
        if state != "1":
            fail("event %s did not enable" % (event,))
    trace_write(root, "tracing_on", "1\n")
    return drops


def close_window(trace):
    root = trace["root"]
    trace_write(root, "tracing_on", "0\n")
    for event in oracle.ORACLE_EVENTS:
        trace_write(root, "events/dma/%s/enable" % (event,),
                    "0\n")
    drops = cpu_drops(root)
    return read_text(os.path.join(root, "trace")), drops


def marker(trace, text):
    trace_write(trace["root"], "trace_marker", text + "\n")


def parse_window(text, device, what):
    try:
        window = oracle.read_trace_window(text, device)
    except oracle.OracleError as exc:
        fail("%s oracle parse: %s" % (what, exc))
    if window["header"] is None:
        fail("%s dump lacks the entries header" % (what,))
    pairing = oracle.pair_fifo(window["records"])
    order = oracle.check_ordering(window["records"])
    markers = sum(len(hit) for hit in window["markers"].values())
    header = window["header"]
    other = (window["other_device"]["map"]
             + window["other_device"]["unmap"]
             + len(window["other_events"]))
    return {"entries_in_buffer": header["in_buffer"],
            "entries_written": header["written"],
            "markers": markers,
            "maps": pairing["counts"]["maps"],
            "unmaps": pairing["counts"]["unmaps"],
            "pairs": pairing["counts"]["pairs"],
            "orphans": pairing["counts"]["orphans"],
            "still_open": pairing["counts"]["still_open"],
            "mismatches": pairing["counts"]["mismatches"],
            "order_violations": len(order),
            "other_device": other,
            "events": oracle.export_rows(window["records"])}, \
        window, pairing


def run_traffic(args, nic, trace):
    """Oracle window around peer traffic (the sealed candidate spans it)."""
    iface = nic["iface"]
    drops_before = open_window(trace)
    mono_open = mono_ns()
    marker(trace, oracle.TRAFFIC_BEGIN)
    tx0, rx0 = nic_stat(iface, "tx_packets"), \
        nic_stat(iface, "rx_packets")
    tx, rx = ping_workload(args.gateway, args.pings)
    tx1, rx1 = nic_stat(iface, "tx_packets"), \
        nic_stat(iface, "rx_packets")
    marker(trace, oracle.TRAFFIC_END)
    mono_close = mono_ns()
    text, drops_after = close_window(trace)
    if None in (tx0, rx0, tx1, rx1):
        fail("NIC counters unreadable")
    doc, window, _ = parse_window(text, nic["pci"], "traffic")
    for mark in (oracle.TRAFFIC_BEGIN, oracle.TRAFFIC_END):
        if len(window["markers"].get(mark, [])) != 1:
            fail("traffic marker %s broken" % (mark,))
    doc["drops_before"] = drops_before
    doc["drops_after"] = drops_after
    print("peer_oracle_guest: traffic tx=%d rx=%d maps=%d "
          "pairs=%d" % (tx, rx, doc["maps"], doc["pairs"]),
          flush=True)
    workload = {"ping_tx": tx, "ping_rx": rx,
                "nic_tx_before": tx0, "nic_tx_after": tx1,
                "nic_rx_before": rx0, "nic_rx_after": rx1}
    return doc, workload, mono_open, mono_close


def run_bracket(args, nic, trace):
    """Down/up bracket separating pre-existing from new."""
    iface = nic["iface"]
    drops_before = open_window(trace)
    marker(trace, oracle.MARKERS["pre"])
    proc = sh(["timeout", "120", "ping", "-c", "20", "-q",
               args.gateway], timeout=150)
    if proc.returncode != 0:
        fail("pre-bracket ping failed")
    marker(trace, oracle.MARKERS["down"])
    down = sh(["ip", "link", "set", iface, "down"])
    if down.returncode != 0:
        fail("ip link down failed")
    time.sleep(2)
    marker(trace, oracle.MARKERS["up"])
    up = sh(["ip", "link", "set", iface, "up"])
    if up.returncode != 0:
        fail("ip link up failed")
    time.sleep(2)
    addr = sh(["ip", "-o", "addr", "show", iface])
    link = sh(["ip", "-o", "link", "show", iface])
    link_up = args.addr in addr.stdout and (
        ",UP" in link.stdout or " UP " in link.stdout
        or link.stdout.strip().endswith(",UP>")
        or "state UP" in link.stdout)
    marker(trace, oracle.MARKERS["post"])
    proc = sh(["timeout", "120", "ping", "-c", "20", "-q",
               args.gateway], timeout=150)
    if proc.returncode != 0:
        fail("post-bracket ping failed")
    marker(trace, oracle.MARKERS["end"])
    text, drops_after = close_window(trace)
    doc, window, pairing = parse_window(text, nic["pci"],
                                       "bracket")
    doc["drops_before"] = drops_before
    doc["drops_after"] = drops_after
    bad, phases = oracle.split_bracket(window["records"],
                                      window["markers"])
    if bad:
        fail("bracket markers broken: %s" % ("; ".join(bad),))
    doc["marker_lines"] = {
        name: window["markers"][text][0]
        for name, text in oracle.MARKERS.items()}
    _, classified = oracle.classify_bracket(
        pairing, phases, drops_before == drops_after, link_up)
    doc["pre_existing"] = classified["pre_existing"]
    doc["held_open"] = classified["held_open"]
    print("peer_oracle_guest: bracket maps=%d unmaps=%d "
          "pre_existing=%d held=%d link_up=%s"
          % (doc["maps"], doc["unmaps"], doc["pre_existing"],
             doc["held_open"], link_up), flush=True)
    return doc, link_up


def parse_argv(argv):
    parser = argparse.ArgumentParser(
        description="peer-leg guest flow")
    parser.add_argument("work", help="guest-local work dir")
    parser.add_argument("export", help="rwdir export dir")
    parser.add_argument("--release", required=True,
                        help="pinned guest release (exact)")
    parser.add_argument("--pci", required=True,
                        help="owned NIC PCI BDF (exact)")
    parser.add_argument("--addr", default="10.0.3.15/24",
                        help="owned NIC address")
    parser.add_argument("--gateway", default="10.0.3.2",
                        help="peer gateway address")
    parser.add_argument("--pings", type=int, default=500,
                        help="traffic ping count")
    parser.add_argument("--buffer-kb", type=int, default=4096,
                        help="per-CPU trace buffer KiB")
    parser.add_argument("--caps",
                        default="attempt-trace,mapping-lifecycle,"
                                "copy-actual",
                        help="record capabilities")
    parser.add_argument("--duration", type=int, default=60,
                        help="record duration seconds")
    args = parser.parse_args(argv)
    if not oracle.BDF_RE.fullmatch(args.pci):
        fail("bad --pci %r" % (args.pci,))
    if args.pings <= 0 or args.buffer_kb <= 0 \
            or args.duration <= 0:
        fail("non-positive workload parameter")
    return args


def run(args):
    """Guest flow body; main() exports record logs around it."""
    os.makedirs(args.work, exist_ok=True)
    os.makedirs(args.export, exist_ok=True)
    nic = setup_nic(args)
    trace = setup_tracefs(args)
    handle = start_record(args, args.work)
    traffic, workload, opened, closed = run_traffic(
        args, nic, trace)
    finished = stop_record(handle, args)
    bracket, link_up = run_bracket(args, nic, trace)
    peer = {
        "schema": oracle.PEER_SCHEMA,
        "case": oracle.CASE_ID,
        "guest": {"release": nic["release"],
                  "swiotlb_force": True,
                  "btf_sha": nic["btf_sha"],
                  "iface": nic["iface"], "pci": nic["pci"],
                  "dma_mask_bits": 32, "addr": args.addr,
                  "link_up_at_end": bool(link_up),
                  "trace_root": trace["root"],
                  "trace_clock": trace["trace_clock"]},
        "oracle": {"events": list(oracle.ORACLE_EVENTS),
                   "event_ids": trace["event_ids"],
                   "format_sha": trace["format_sha"],
                   "format_tokens_ok":
                       trace["format_tokens_ok"],
                   "buffer_kb": trace["buffer_kb"]},
        "c9": {"binary_sha": handle["binary_sha"],
               "profile": finished["profile"],
               "caps": args.caps,
               "duration_s": args.duration,
               "record_exit": 0,
               "ready_session": handle["ready_session"],
               "ready_start_ns": handle["ready_start_ns"],
               "window_clock": oracle.MONO_CLOCK,
               "mono_open_ns": opened,
               "mono_close_ns": closed},
        "workload": workload,
        "traffic": traffic,
        "bracket": bracket,
    }
    try:
        oracle.validate_peer_doc(peer)
    except ValueError as exc:
        fail("guest export invalid: %s" % (exc,))
    export_file(args.export, "peer.json", peer)
    with open(finished["session_path"], "rb") as handle:
        export_file(args.export, "cap-session.json",
                    handle.read().decode("utf-8"))
    with open(finished["events_path"], "rb") as handle:
        export_file(args.export, "cap-events.ndjson",
                    handle.read().decode("utf-8"))
    print("peer_oracle_guest: exported peer PASS-ready",
          flush=True)
    return 0


def main(argv):
    args = parse_argv(argv)
    try:
        return run(args)
    finally:
        export_record_logs(args.work, args.export)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
