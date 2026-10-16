#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Guest scsi_debug teardown: polled delete plus retried unload.

sysfs device deletion completes asynchronously in the guest,
so deleting the owned scsi_debug disk and immediately
unloading the module races teardown ("in use" rmmod
failures). The shared helper polls for the block node to
disappear (bounded) and retries the unload a few times; a
device that never leaves or an unload that never succeeds
still fails loudly instead of hanging the gate. These tests
drive the helper against a fake sysfs tree with a scripted
command runner: no guest, no modules, no sleeps.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import guest_lifecycle as guest


class Script:
    def __init__(self, returns):
        self.returns = list(returns)
        self.calls = []

    def __call__(self, args, **kw):
        self.calls.append(list(args))
        if len(self.returns) > 1:
            rc = self.returns.pop(0)
        else:
            rc = self.returns[0]
        return type("Result", (), dict(returncode=rc,
                                       stdout="", stderr="in use"))()


def make_node(root):
    node = Path(root) / "block" / "sdz"
    (node / "device").mkdir(parents=True)
    (node / "device" / "delete").write_text("")
    return node


def test_unload_retry_succeeds(tmp_path, monkeypatch):
    node = make_node(tmp_path)
    script = Script([1, 1, 0])
    monkeypatch.setattr(guest, "sh", script)
    real_exists = os.path.exists
    seen = []

    def vanishing(path):
        if str(path) == str(node):
            seen.append(1)
            return len(seen) == 1
        return real_exists(path)

    monkeypatch.setattr(guest.os.path, "exists", vanishing)
    guest.remove_scsi_debug("sdz", sysfs=str(tmp_path), poll_gap=0,
                            unload_gap=0)
    assert [c[:2] for c in script.calls] == [
        ["rmmod", "scsi_debug"]] * 3


def test_unload_persistent_failure(tmp_path, monkeypatch):
    node = make_node(tmp_path)
    script = Script([1])
    monkeypatch.setattr(guest, "sh", script)
    real_exists = os.path.exists

    def gone(path):
        if str(path) == str(node):
            return False
        return real_exists(path)

    monkeypatch.setattr(guest.os.path, "exists", gone)
    with pytest.raises(SystemExit):
        guest.remove_scsi_debug("sdz", sysfs=str(tmp_path),
                                poll_gap=0, unload_rounds=3,
                                unload_gap=0)
    assert len(script.calls) == 3


def test_delete_never_completes(tmp_path, monkeypatch):
    make_node(tmp_path)
    script = Script([0])
    monkeypatch.setattr(guest, "sh", script)
    with pytest.raises(SystemExit):
        guest.remove_scsi_debug("sdz", sysfs=str(tmp_path),
                                poll_rounds=3, poll_gap=0)
    assert script.calls == []


def test_delete_write_failure(tmp_path, monkeypatch):
    script = Script([0])
    monkeypatch.setattr(guest, "sh", script)
    with pytest.raises(SystemExit):
        guest.remove_scsi_debug("sdz", sysfs=str(tmp_path))
    assert script.calls == []
