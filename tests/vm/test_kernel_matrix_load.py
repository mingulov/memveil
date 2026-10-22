#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Matrix load generator tests: offsets, phases, hard IO errors.

No device IO: preadv/pwritev are stubbed, the buffer math
runs for real.
"""

import os
import signal
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kernel_matrix_load as kml


def _run(capsys, *argv):
    code = kml.main(list(argv))
    return code, capsys.readouterr().out


def test_read_einval_fails_not_buffered(tmp_path, capsys,
                                        monkeypatch):
    target = tmp_path / "disk.img"
    target.write_bytes(b"0" * 1048576)
    calls = []

    def fake_preadv(fd, buffers, offset, flags=0):
        calls.append(offset)
        raise OSError(22, "Invalid argument")

    monkeypatch.setattr(kml.os, "preadv", fake_preadv)
    code, _ = _run(capsys, "read", "--phase", "read0",
                   "--dev", str(target), "--count", "1",
                   "--offset", "0")
    assert code != 0
    assert len(calls) == 1


def test_short_read_fails(tmp_path, capsys, monkeypatch):
    target = tmp_path / "disk.img"
    target.write_bytes(b"0" * 1048576)

    def fake_preadv(fd, buffers, offset, flags=0):
        return 512

    monkeypatch.setattr(kml.os, "preadv", fake_preadv)
    code, _ = _run(capsys, "read", "--phase", "read0",
                   "--dev", str(target), "--count", "1",
                   "--offset", "0")
    assert code != 0


def test_phase_line_printed(tmp_path, capsys, monkeypatch):
    target = tmp_path / "disk.img"
    target.write_bytes(b"0" * 2097152)
    monkeypatch.setattr(kml.os, "preadv",
                        lambda fd, bufs, off, flags=0:
                        1048576)
    code, out = _run(capsys, "read", "--phase", "read0",
                     "--dev", str(target), "--count", "2",
                     "--offset", "0")
    assert code == 0
    assert "phase read0 start_ns " in out
    assert "bytes 2097152 ios 2" in out
    assert "buf read0 mod4096=0" in out


def test_buf_offset_measured(tmp_path, capsys, monkeypatch):
    target = tmp_path / "disk.img"
    target.write_bytes(b"0" * 1048576)
    monkeypatch.setattr(kml.os, "preadv",
                        lambda fd, bufs, off, flags=0:
                        1048576)
    code, out = _run(capsys, "read", "--phase", "read512",
                     "--dev", str(target), "--count", "1",
                     "--offset", "512")
    assert code == 0
    assert "buf read512 mod4096=512" in out


def test_busy_releases_buffers_quietly(tmp_path, capsys,
                                       monkeypatch):
    target = tmp_path / "disk.img"
    target.write_bytes(b"0" * 2097152)
    monkeypatch.setattr(kml.os, "preadv",
                        lambda fd, bufs, off, flags=0:
                        1048576)
    timer = threading.Timer(
        0.3, lambda: os.kill(os.getpid(),
                             signal.SIGTERM))
    timer.start()
    failures = []
    old_hook = threading.excepthook
    threading.excepthook = failures.append
    try:
        code, out = _run(capsys, "busy", "--phase",
                         "busy", "--dev", str(target),
                         "--readers", "2")
    finally:
        timer.cancel()
        threading.excepthook = old_hook
        signal.signal(signal.SIGTERM,
                      signal.SIG_DFL)
    assert code == 0
    assert "phase busy start_ns " in out
    assert failures == []
