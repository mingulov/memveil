#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Matrix load generator: exact O_DIRECT phases for one capture.

read and write move --count x 1 MiB with the buffer at
--offset inside its page and print one phase line plus
the measured buffer alignment. busy loops concurrent
offset-0 readers until SIGTERM. Any IO error or short
transfer exits nonzero; nothing here retries or falls
back to buffered IO. Stdlib only: this runs in guests.
"""

import argparse
import ctypes
import mmap
import os
import signal
import sys
import threading
import time

IO_BYTES = 1048576
PAGE = 4096


def now_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def aligned_buffer(offset):
    """1 MiB view at offset inside a page, measured mod."""
    if offset not in (0, 512):
        raise ValueError("bad offset %r" % offset)
    size = IO_BYTES + PAGE
    mem = mmap.mmap(-1, size)
    base = ctypes.addressof(
        ctypes.c_char.from_buffer(mem))
    start = -base % PAGE
    view = memoryview(mem)[start + offset:
                           start + offset + IO_BYTES]
    mod = (base + start + offset) % PAGE
    return mem, view, mod


def fail(msg):
    sys.stderr.write("matrix-load: %s\n" % msg)
    return 1


def run_reads(dev, count, tag, mem, view, mod,
              out):
    try:
        fd = os.open(dev, os.O_RDONLY | os.O_DIRECT)
    except OSError as exc:
        return fail("open %s: %s" % (dev, exc))
    start = now_ns()
    try:
        for i in range(count):
            try:
                got = os.preadv(fd, [view], i * IO_BYTES)
            except OSError as exc:
                return fail("read %d: %s" % (i, exc))
            if got != IO_BYTES:
                return fail("short read %d: %d" % (i,
                                                  got))
    finally:
        end = now_ns()
        os.close(fd)
    out.write("phase %s start_ns %d end_ns %d bytes %d "
              "ios %d\n" % (tag, start, end,
                            count * IO_BYTES, count))
    out.write("buf %s mod4096=%d\n" % (tag, mod))
    out.flush()
    return 0


def run_writes(dev, count, tag, mem, view, mod,
               out):
    try:
        fd = os.open(dev, os.O_WRONLY | os.O_DIRECT)
    except OSError as exc:
        return fail("open %s: %s" % (dev, exc))
    start = now_ns()
    try:
        for i in range(count):
            try:
                got = os.pwritev(fd, [view],
                                 i * IO_BYTES)
            except OSError as exc:
                return fail("write %d: %s" % (i, exc))
            if got != IO_BYTES:
                return fail("short write %d: %d" % (i,
                                                   got))
        try:
            os.fsync(fd)
        except OSError as exc:
            return fail("fsync: %s" % exc)
    finally:
        end = now_ns()
        os.close(fd)
    out.write("phase %s start_ns %d end_ns %d bytes %d "
              "ios %d\n" % (tag, start, end,
                            count * IO_BYTES, count))
    out.write("buf %s mod4096=%d\n" % (tag, mod))
    out.flush()
    return 0


def run_busy(dev, readers, tag, out):
    try:
        fd = os.open(dev, os.O_RDONLY | os.O_DIRECT)
    except OSError as exc:
        return fail("open %s: %s" % (dev, exc))
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
    except OSError as exc:
        os.close(fd)
        return fail("size %s: %s" % (dev, exc))
    span = max(IO_BYTES, size - IO_BYTES)
    stop = threading.Event()

    def on_term(signum, frame):
        stop.set()

    signal.signal(signal.SIGTERM, on_term)
    errors = []
    counts = [0] * readers
    bufs = []
    for _ in range(readers):
        # Fault each buffer serially before the workers
        # start so first-touch pages stay contiguous;
        # interleaved faults scatter into ~100 segments
        # per read and set pressure by accident.
        mem, view, _ = aligned_buffer(0)
        view[:] = b"\x00" * IO_BYTES
        bufs.append((mem, view))
    start = now_ns()

    def worker(num):
        mem, view = bufs[num]
        i = 0
        try:
            while not stop.is_set():
                try:
                    got = os.preadv(
                        fd, [view],
                        (i * IO_BYTES) % span)
                except OSError as exc:
                    errors.append(str(exc))
                    stop.set()
                    return
                if got != IO_BYTES:
                    errors.append("short read")
                    stop.set()
                    return
                i += 1
        finally:
            counts[num] = i
            view.release()
            mem.close()

    threads = [threading.Thread(target=worker, args=(n,))
               for n in range(readers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    end = now_ns()
    os.close(fd)
    if errors:
        return fail("busy: %s" % errors[0])
    ios = sum(counts)
    out.write("phase %s start_ns %d end_ns %d bytes %d "
              "ios %d\n" % (tag, start, end,
                            ios * IO_BYTES, ios))
    out.write("buf %s mod4096=0\n" % tag)
    out.flush()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Exact O_DIRECT load phases.")
    sub = parser.add_subparsers(dest="mode", required=True)
    for name in ("read", "write"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--phase", required=True)
        cmd.add_argument("--dev", required=True)
        cmd.add_argument("--count", required=True,
                         type=int)
        cmd.add_argument("--offset", required=True,
                         type=int)
    busy = sub.add_parser("busy")
    busy.add_argument("--phase", required=True)
    busy.add_argument("--dev", required=True)
    busy.add_argument("--readers", required=True,
                      type=int)
    args = parser.parse_args(argv)
    if args.mode in ("read", "write"):
        if args.count <= 0:
            return fail("count must be positive")
        try:
            mem, view, mod = aligned_buffer(args.offset)
        except ValueError as exc:
            return fail(str(exc))
        if mod != args.offset:
            return fail("buffer at %d, want %d"
                        % (mod, args.offset))
        if args.mode == "read":
            return run_reads(args.dev, args.count,
                             args.phase, mem, view, mod,
                             sys.stdout)
        return run_writes(args.dev, args.count,
                          args.phase, mem, view, mod,
                          sys.stdout)
    if args.readers <= 0:
        return fail("readers must be positive")
    return run_busy(args.dev, args.readers, args.phase,
                    sys.stdout)


if __name__ == "__main__":
    sys.exit(main())
