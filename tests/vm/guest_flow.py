#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""VM-gate guest flow: stimulate, capture, ledger, export.

Runs as root inside the virtme-ng guest (one boot per mode).
Modes: correctness | saturation. Every refusal aborts FAIL
(exit 1), never skip: the gate requires narrow candidate
admission and exact cross-checks.

Exports (with .sha256 sidecars): ledger.json, oracle.json,
ping.txt, record.stdout, record.stderr, session.json,
events.ndjson. The raw ftrace pipe (pipe.ram) never crosses
to the host: it holds DMA addresses (dev_addr). The guest
parses it into oracle.json, an allowlisted representation
(timestamps, sizes, force flags, loss evidence) with a fixed
schema, and only the oracle is exported.
"""
import ctypes
import ctypes.util
import gzip
import hashlib
import json
import os
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time

TR = "/sys/kernel/tracing"
EVT = TR + "/events/swiotlb/swiotlb_bounced"
FMT_PATH = EVT + "/format"

FTRACE_RE = re.compile(
    r"^\s*\S+\s+\[(\d+)\]\s+\S+\s+(\d+)\.(\d+):\s+swiotlb_bounced:\s+(.*)$"
)
SIZE_RE = re.compile(r"\bsize=(\d+)")
FLAG_RE = re.compile(r"\b(FORCE|NORMAL)\s*$")


def parse_ftrace(blob):
    """Every line has one category; unknown or truncated evidence refuses."""
    if blob and not blob.endswith(b"\n"):
        raise ValueError("truncated ftrace final line")
    events = []
    headers = blanks = lost = 0
    for raw in blob.splitlines():
        line = raw.decode("utf-8", "strict")
        if not line.strip():
            blanks += 1
        elif line.lstrip().startswith("#"):
            headers += 1
        elif re.fullmatch(r"\s*CPU:\d+ \[LOST \d+ EVENTS\]\s*", line):
            lost += 1
        else:
            m = FTRACE_RE.fullmatch(line)
            if not m:
                raise ValueError("malformed/unexpected ftrace line")
            sm = SIZE_RE.search(m.group(4))
            fm = FLAG_RE.search(m.group(4))
            if not sm or not fm or len(re.findall(r"\bsize=", m.group(4))) != 1:
                raise ValueError("malformed ftrace payload")
            fraction = m.group(3)
            if len(fraction) != 6:
                raise ValueError("unexpected ftrace timestamp precision")
            events.append(dict(ts_ns=int(m.group(2))*1000000000+int(fraction)*1000,
                               size=int(sm.group(1)), forced=fm.group(1)=="FORCE"))
    return dict(schema="memveil-vm-oracle/1", lost_lines=lost, pipe_bytes=len(blob),
                pipe_lines=blob.count(b"\n"), header_lines=headers,
                blank_lines=blanks, events=events)


def fail(msg):
    print(f"guest_flow: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


class PipeStreamer:
    """Owned splice-free trace_pipe streamer (not GNU cat).

    GNU cat's kernel-copy fast path tears concurrently
    appended trace_pipe pages under bursty multi-CPU tracing
    (proven by isolated A/B on block-burst traffic); a plain
    os.read/os.write loop streams the identical workload
    clean. Unbuffered: every chunk read is fully written
    before the next read, so stopping loses nothing the
    post-stop drain cannot re-read from the ring.
    """

    def __init__(self, pipe, out_path):
        self._pipe = pipe
        self._out_path = out_path
        self._stop = threading.Event()
        self._error = None
        self._thread = threading.Thread(target=self._run,
                                        daemon=True)

    def start(self):
        self._thread.start()

    def stop(self, timeout=15):
        self._stop.set()
        self._thread.join(timeout)
        if self._thread.is_alive():
            fail("pipe streamer did not stop")
        if self._error is not None:
            fail("pipe streamer failed: %r" % (self._error,))

    def _run(self):
        try:
            infd = os.open(self._pipe, os.O_RDONLY)
            try:
                outfd = os.open(
                    self._out_path,
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
                try:
                    while not self._stop.is_set():
                        ready, _, _ = select.select(
                            [infd], [], [], 0.5)
                        if not ready:
                            continue
                        chunk = os.read(infd, 65536)
                        if not chunk:
                            break
                        view = memoryview(chunk)
                        while view:
                            done = os.write(outfd, view)
                            view = view[done:]
                finally:
                    os.close(outfd)
            finally:
                os.close(infd)
        except Exception as exc:
            self._error = exc


def sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def preflight_fs(work):
    """Trial the capture op family on the work fs; return fstype."""
    trial = os.path.join(work, "preflight")
    os.makedirs(trial, exist_ok=True)
    f1 = os.path.join(trial, "a.tmp")
    f2 = os.path.join(trial, "b.tmp")
    fd = os.open(f1, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        os.write(fd, b"0123456789abcdef")
        os.pwrite(fd, b"XY", 4)
        os.fsync(fd)
    finally:
        os.close(fd)
    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        fail("no libc for renameat2 preflight")
    libc = ctypes.CDLL(libc_name, use_errno=True)
    AT_FDCWD = -100
    RENAME_NOREPLACE = 1
    b1, b2 = f1.encode(), f2.encode()
    rc = libc.renameat2(AT_FDCWD, b1, AT_FDCWD, b2, RENAME_NOREPLACE)
    if rc != 0:
        fail(f"renameat2 noreplace failed: errno {ctypes.get_errno()}")
    dfd = os.open(trial, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    st = sh(["stat", "-f", trial])
    fstype = "unknown"
    m = re.search(r"Type:\s*(\S+)", st.stdout)
    if m:
        fstype = m.group(1)
    shutil.rmtree(trial, ignore_errors=True)
    return fstype


def gnu_bid():
    data = read_bytes("/sys/kernel/notes")
    pos = 0
    while pos + 12 <= len(data):
        namesz, descsz, ntype = struct.unpack_from("<III", data, pos)
        pos += 12
        name_end = pos + ((namesz + 3) // 4) * 4
        is_gnu = (
            ntype == 3
            and namesz == 4
            and data[pos : pos + 4] == b"GNU\x00"
        )
        pos = name_end
        desc_end = pos + ((descsz + 3) // 4) * 4
        if is_gnu and descsz == 20:
            return data[pos : pos + 20].hex()
        pos = desc_end
    return None


def identity():
    release = os.uname().release
    cfg, src = None, None
    try:
        raw = read_bytes("/proc/config.gz")
        src = "gz"
        cfg = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    except OSError:
        try:
            cfg = read_bytes("/boot/config-" + release)
            src = "file"
        except OSError:
            pass
    if cfg is None:
        fail("no kernel config source")
    try:
        image = read_bytes("/boot/vmlinuz-" + release)
    except OSError:
        fail("vmlinuz unreadable")
    bid = gnu_bid()
    if not bid:
        fail("no GNU build-id in notes")
    return {
        "release": release,
        "config_src": src,
        "config_sha": hashlib.sha256(cfg).hexdigest(),
        "btf_sha": sha_file("/sys/kernel/btf/vmlinux"),
        "format_sha": sha_file(FMT_PATH),
        "image_sha": hashlib.sha256(image).hexdigest(),
        "image_bid": bid,
    }


def find_pcnet():
    for iface in sorted(os.listdir("/sys/class/net")):
        drv = os.path.join("/sys/class/net", iface, "device", "driver")
        try:
            if os.readlink(drv).endswith("pcnet32"):
                mb = read_bytes(
                    os.path.join(
                        "/sys/class/net", iface, "device", "dma_mask_bits"
                    )
                ).decode().strip()
                return iface, mb
        except OSError:
            continue
    return None, None


def configure_net(iface):
    # Silence IPv6 link-local chatter before link-up: the
    # gate requires zero ambient bounces in the margins.
    r = sh(
        [
            "sysctl",
            "-w",
            f"net.ipv6.conf.{iface}.disable_ipv6=1",
        ]
    )
    if r.returncode != 0:
        fail(f"ipv6 disable failed: {r.stderr.strip()}")
    r = sh(["ip", "link", "set", iface, "up"])
    if r.returncode != 0:
        fail(f"ip link up failed: {r.stderr.strip()}")
    r = sh(["ip", "addr", "add", "10.0.3.15/24", "dev", iface])
    if r.returncode != 0 and "exists" not in r.stderr:
        fail(f"ip addr failed: {r.stderr.strip()}")
    r = sh(["ping", "-c", "1", "-W", "3", "10.0.3.2"])
    if r.returncode != 0:
        fail(f"gateway ping failed: {r.stdout.strip()} {r.stderr.strip()}")


def hiwater():
    try:
        return read_bytes(
            "/sys/kernel/debug/swiotlb/io_tlb_used_hiwater"
        ).decode().strip()
    except OSError:
        return None


def percpu_stats():
    out = {}
    base = TR + "/per_cpu"
    try:
        cpus = sorted(os.listdir(base))
    except OSError:
        fail("no per_cpu trace stats")
    for cpu in cpus:
        try:
            raw = read_bytes(os.path.join(base, cpu, "stats")).decode()
        except OSError:
            fail(f"unreadable stats for {cpu}")
        vals = {}
        for key in ("overrun", "commit overrun", "dropped events"):
            m = re.search(rf"^{re.escape(key)}:\s*(\d+)", raw, re.M)
            vals[key] = int(m.group(1)) if m else None
        out[cpu] = {"values": vals}
    return out


def main():
    if len(sys.argv) not in (9, 10):
        print(
            "usage: guest_flow.py MODE WORK EXPORT REPO PROFILE OBJECT BRIDGE DURATION [PINGS]",
            file=sys.stderr,
        )
        return 2
    mode, work, export, repo, profile, obj, bridge, dur = sys.argv[1:9]
    duration = int(dur)
    # Optional workload size for small example captures; the gate
    # omits it and keeps 5000.
    pings = sys.argv[9] if len(sys.argv) == 10 else "5000"
    if not pings.isdigit() or int(pings) < 1:
        fail(f"bad PINGS {pings}")
    if mode not in ("correctness", "saturation"):
        fail(f"bad mode {mode}")
    if os.geteuid() != 0:
        fail("guest flow requires root")
    os.makedirs(work, exist_ok=True)
    os.makedirs(export, exist_ok=True)
    ledger = {"mode": mode}
    ledger["fs_type"] = preflight_fs(work)
    ledger["identity"] = identity()
    ledger["hiwater_before"] = hiwater()
    iface, mb = find_pcnet()
    if not iface:
        fail("no pcnet32 NIC found")
    if mb != "32":
        fail(f"pcnet dma_mask_bits is {mb}, want 32")
    ledger["iface"] = iface
    ledger["dma_mask_bits"] = int(mb)
    configure_net(iface)
    ledger["link_ok"] = True
    with open(TR + "/trace_clock", "w") as fh:
        fh.write("mono")
    with open(TR + "/trace_clock") as fh:
        ledger["trace_clock"] = fh.read().strip()
    if "[mono]" not in ledger["trace_clock"]:
        fail(f"trace clock is {ledger['trace_clock']}")
    with open(EVT + "/enable", "w") as fh:
        fh.write("1")
    pipe_path = os.path.join(work, "pipe.ram")
    streamer = PipeStreamer(TR + "/trace_pipe", pipe_path)
    streamer.start()
    cap = os.path.join(work, "cap")
    memveil = os.path.join(repo, "build", "memveil")
    rec = subprocess.Popen(
        [
            memveil, "record",
            "--duration", str(duration),
            "--output", cap,
            "--object", obj,
            "--bridge", bridge,
            "--profile", profile,
        ],
        stdout=subprocess.PIPE,
        stderr=open(os.path.join(work, "record.stderr"), "wb"),
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    ready = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        r, _, _ = select.select([rec.stdout], [], [], 1.0)
        if r:
            line = rec.stdout.readline()
            if line:
                if "ready session=" in line:
                    ready = line.strip()
                    break
        if rec.poll() is not None:
            break
    if ready is None:
        try:
            rec.kill()
        except OSError:
            pass
        fail("record never reached readiness")
    ledger["ready"] = ready
    out_path = os.path.join(work, "record.stdout")
    with open(out_path, "w") as fh:
        fh.write(ready + "\n")
    time.sleep(2)
    if mode == "saturation":
        os.kill(rec.pid, signal.SIGSTOP)
        time.sleep(1)
    start_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    ping = sh(["timeout", "20", "ping", "-A", "-c", pings, "-q", "10.0.3.2"])
    if ping.returncode != 0:
        fail(f"ping workload failed exit {ping.returncode}")
    end_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    ledger["workload_start_ns"] = start_ns
    ledger["workload_end_ns"] = end_ns
    with open(os.path.join(work, "ping.txt"), "w") as fh:
        fh.write(ping.stdout)
        fh.write(ping.stderr)
    m = re.search(r"(\d+) packets transmitted", ping.stdout)
    ledger["ping_transmitted"] = int(m.group(1)) if m else None
    m2 = re.search(r"(\d+) received", ping.stdout)
    ledger["ping_received"] = int(m2.group(1)) if m2 else None
    if mode == "saturation":
        os.kill(rec.pid, signal.SIGCONT)
        time.sleep(2)
        os.kill(rec.pid, signal.SIGTERM)
    else:
        time.sleep(2)
    try:
        rc = rec.wait(timeout=120)
    except subprocess.TimeoutExpired:
        rec.kill()
        rec.wait()
        fail("record did not exit")
    ledger["record_exit"] = rc
    try:
        rest = rec.stdout.read() or ""
    except OSError:
        rest = ""
    with open(out_path, "a") as fh:
        fh.write(rest)
    # Oracle shutdown protocol.
    with open(TR + "/tracing_on", "w") as fh:
        fh.write("0")
    streamer.stop()
    # Drain stragglers appended after the streaming reader stopped.
    drained = 0
    end_drain = time.monotonic() + 10
    pfd = os.open(TR + "/trace_pipe", os.O_RDONLY | os.O_NONBLOCK)
    try:
        with open(pipe_path, "ab") as fh:
            while time.monotonic() < end_drain:
                try:
                    chunk = os.read(pfd, 1048576)
                except OSError:
                    break
                if not chunk:
                    break
                drained += len(chunk)
                fh.write(chunk)
    finally:
        os.close(pfd)
    ledger["drained_bytes"] = drained
    with open(EVT + "/enable", "w") as fh:
        fh.write("0")
    ledger["percpu"] = percpu_stats()
    ledger["hiwater_after"] = hiwater()
    with open(pipe_path, "rb") as fh:
        blob = fh.read()
    ledger["pipe_bytes"] = len(blob)
    ledger["pipe_lines"] = blob.count(b"\n")
    ledger["lost_markers"] = len(
        re.findall(rb"lost", blob, flags=re.IGNORECASE)
    )
    # Allowlisted oracle: keep only timestamps, sizes, force
    # flags, and loss evidence. Raw lines (dev_addr and friends)
    # stay guest-local and are never exported.
    oracle = parse_ftrace(blob)
    oracle_src = os.path.join(work, "oracle.json")
    with open(oracle_src, "w") as fh:
        json.dump(oracle, fh, indent=1, sort_keys=True)
        fh.write("\n")
    for name in (
        "ledger.json",
        "oracle.json",
        "ping.txt",
        "record.stdout",
        "record.stderr",
        "session.json",
        "events.ndjson",
    ):
        if name in ("session.json", "events.ndjson"):
            src = os.path.join(cap, name)
        elif name == "ledger.json":
            src = os.path.join(work, name)
            with open(src, "w") as fh:
                json.dump(ledger, fh, indent=1, sort_keys=True)
                fh.write("\n")
        else:
            src = os.path.join(work, name)
        if not os.path.isfile(src):
            fail(f"missing export {name}")
        dst = os.path.join(export, f"{mode}-{name}")
        shutil.copyfile(src, dst)
        with open(dst + ".sha256", "w") as fh:
            fh.write(f"{sha_file(dst)}  {mode}-{name}\n")
    print(f"guest_flow: {mode} exported record_exit={rc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
