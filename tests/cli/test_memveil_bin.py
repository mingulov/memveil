#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""MEMVEIL_BIN contract: the blessed binary is the executed binary.

The runner blesses one binary and every CLI driver resolves the
same selector (memveil_bin.resolve_memveil_bin), so the knob
binary provably equals the executed binary:

- set+usable resolves: a slash path verbatim, a bare name via
  PATH to an absolute path; unset resolves the build/memveil
  default; bogus (missing, not-a-file, non-executable, empty,
  unresolvable-on-PATH) refuses before dispatch.
- identity: every CLI driver resolves the knob to the identical
  string, and wrapper-knob end-to-end runs prove the executed
  binary is the knob binary (marker checks, both for slash
  paths and for bare names found on PATH).
- refusal: a bogus knob fails the runner (exit 1, before dispatch)
  and a directly-invoked driver (nonzero, names MEMVEIL_BIN).
"""

import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "tests" / "cli"
sys.path.insert(0, str(CLI))
from memveil_bin import DEFAULT_BIN, resolve_memveil_bin

# Every tests/cli module that executes the binary under test
# (test_capture_failures inherits BIN from test_checkpoint_writer;
# test_uncertainty exposes the module BIN its helpers run).
DRIVERS = (
    "test_adversarial_cli",
    "test_record_failures",
    "test_stdout_errors",
    "test_top",
    "test_output_paths",
    "test_checkpoint_writer",
    "test_checkpoint_recovery",
    "test_capture_integrity",
    "test_report_context",
    "test_dangling_unmap",
    "test_uncertainty",
    "test_capture_failures",
)


def driver_bin(driver, knob):
    """Import a driver with MEMVEIL_BIN=knob (None unsets) and print BIN."""
    env = dict(os.environ)
    if knob is None:
        env.pop("MEMVEIL_BIN", None)
    else:
        env["MEMVEIL_BIN"] = knob
    code = ("import sys; sys.path.insert(0, %r); "
            "import %s as driver; print(driver.BIN, flush=True)"
            % (str(CLI), driver))
    return subprocess.run([sys.executable, "-c", code], env=env,
                          capture_output=True, text=True)


def make_executable(path):
    Path(path).write_text("#!/bin/sh\nexit 0\n")
    os.chmod(path, 0o755)
    return str(path)


class KnobContract(unittest.TestCase):
    def test_default_is_build_memveil(self):
        old = os.environ.pop("MEMVEIL_BIN", None)
        try:
            self.assertEqual(DEFAULT_BIN, str(ROOT / "build" / "memveil"))
            self.assertEqual(resolve_memveil_bin(), DEFAULT_BIN)
        finally:
            if old is not None:
                os.environ["MEMVEIL_BIN"] = old

    def test_verbatim_when_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = make_executable(os.path.join(tmp, "sentinel"))
            link = os.path.join(tmp, "link")
            os.symlink(sentinel, link)
            old = os.environ.get("MEMVEIL_BIN")
            try:
                # Verbatim, not normalized: even a slash-path
                # symlink resolves to the knob string itself,
                # like tools/test.
                for knob in (sentinel, link):
                    os.environ["MEMVEIL_BIN"] = knob
                    self.assertEqual(resolve_memveil_bin(), knob)
            finally:
                if old is None:
                    os.environ.pop("MEMVEIL_BIN", None)
                else:
                    os.environ["MEMVEIL_BIN"] = old

    def test_bogus_refuses_before_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = os.path.join(tmp, "plain")
            Path(plain).write_text("not executable\n")
            cases = {
                "missing": os.path.join(tmp, "missing"),
                "directory": tmp,
                "non-executable": plain,
                "empty": "",
            }
            old = os.environ.get("MEMVEIL_BIN")
            try:
                for name, knob in cases.items():
                    with self.subTest(name):
                        os.environ["MEMVEIL_BIN"] = knob
                        err = io.StringIO()
                        with contextlib.redirect_stderr(err):
                            with self.assertRaises(SystemExit) as raised:
                                resolve_memveil_bin()
                        self.assertEqual(raised.exception.code, 1)
                        self.assertIn("MEMVEIL_BIN", err.getvalue())
            finally:
                if old is None:
                    os.environ.pop("MEMVEIL_BIN", None)
                else:
                    os.environ["MEMVEIL_BIN"] = old

    def test_bare_name_resolves_via_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = os.path.join(tmp, "first")
            second = os.path.join(tmp, "second")
            linkdir = os.path.join(tmp, "linkdir")
            os.mkdir(first)
            os.mkdir(second)
            os.mkdir(linkdir)
            hit = make_executable(os.path.join(first, "mv-bare-probe"))
            make_executable(os.path.join(second, "mv-bare-probe"))
            target = make_executable(os.path.join(tmp, "mv-real-probe"))
            os.symlink(target, os.path.join(linkdir, "mv-link-probe"))
            old_path = os.environ.get("PATH", "")
            old_knob = os.environ.get("MEMVEIL_BIN")
            try:
                # First hit on PATH wins, as an absolute path.
                os.environ["PATH"] = first + os.pathsep + second
                os.environ["MEMVEIL_BIN"] = "mv-bare-probe"
                self.assertEqual(resolve_memveil_bin(),
                                 os.path.realpath(hit))
                # A symlink on PATH resolves to its target.
                os.environ["PATH"] = linkdir
                os.environ["MEMVEIL_BIN"] = "mv-link-probe"
                self.assertEqual(resolve_memveil_bin(),
                                 os.path.realpath(target))
                # An empty PATH refuses every bare name.
                os.environ["PATH"] = ""
                os.environ["MEMVEIL_BIN"] = "mv-bare-probe"
                with self.assertRaises(SystemExit) as raised:
                    with contextlib.redirect_stderr(io.StringIO()):
                        resolve_memveil_bin()
                self.assertEqual(raised.exception.code, 1)
            finally:
                os.environ["PATH"] = old_path
                if old_knob is None:
                    os.environ.pop("MEMVEIL_BIN", None)
                else:
                    os.environ["MEMVEIL_BIN"] = old_knob

    def test_bare_name_unresolvable_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_path = os.environ.get("PATH", "")
            old_knob = os.environ.get("MEMVEIL_BIN")
            try:
                # The bare name resolves nowhere on PATH (the
                # empty tmp dir leads, the system entries stay
                # so the runner below can still exec).
                os.environ["PATH"] = tmp + os.pathsep + old_path
                os.environ["MEMVEIL_BIN"] = "mv-no-such-bare-probe"
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    with self.assertRaises(SystemExit) as raised:
                        resolve_memveil_bin()
                self.assertEqual(raised.exception.code, 1)
                self.assertIn("MEMVEIL_BIN", err.getvalue())
                # The runner refuses before dispatch, like any
                # other bogus knob (no recursion: bogus knobs
                # exit in rust_bin_setup).
                env = dict(os.environ)
                proc = subprocess.run(
                    [str(ROOT / "tools/test"), "reader-adversarial"],
                    env=env, capture_output=True, text=True)
                self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
                self.assertIn("MEMVEIL_BIN", proc.stderr)
                self.assertIn("missing or not executable", proc.stderr)
            finally:
                os.environ["PATH"] = old_path
                if old_knob is None:
                    os.environ.pop("MEMVEIL_BIN", None)
                else:
                    os.environ["MEMVEIL_BIN"] = old_knob

    def test_bare_knob_dispatched_via_runner(self):
        # End to end through the real runner: a bare knob found
        # on PATH must dispatch the found file, proving the
        # shell selector resolves bare names identically. Runs
        # from a directory without the wrapper, so a
        # current-directory check would refuse instead. Uses
        # the top suite (never reader-adversarial: that leg
        # runs this contract file, so a usable knob there
        # would recurse).
        real = resolve_memveil_bin()
        if not (os.path.isfile(real) and os.access(real, os.X_OK)):
            self.skipTest("no usable binary under test: %s" % real)
        with tempfile.TemporaryDirectory() as tmp:
            bindir = os.path.join(tmp, "bindir")
            os.mkdir(bindir)
            marker = os.path.join(tmp, "bare-executed")
            wrapper = os.path.join(bindir, "mv-bare-wrapper")
            Path(wrapper).write_text(
                "#!/bin/sh\ntouch %s\nexec %s \"$@\"\n" % (marker, real))
            os.chmod(wrapper, 0o755)
            env = dict(os.environ)
            env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
            env["MEMVEIL_BIN"] = "mv-bare-wrapper"
            proc = subprocess.run(
                [str(ROOT / "tools/test"), "top"],
                env=env, capture_output=True, text=True, cwd=tmp)
            self.assertEqual(proc.returncode, 0,
                             proc.stdout[-2000:] + proc.stderr[-2000:])
            self.assertTrue(os.path.isfile(marker),
                            "PATH-resolved bare knob was not executed")

    def test_all_drivers_resolve_knob_verbatim(self):
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = make_executable(os.path.join(tmp, "sentinel"))
            for driver in DRIVERS:
                with self.subTest(driver):
                    proc = driver_bin(driver, sentinel)
                    self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
                    self.assertEqual(proc.stdout.strip(), sentinel)

    def test_all_drivers_default_unchanged(self):
        for driver in DRIVERS:
            with self.subTest(driver):
                proc = driver_bin(driver, None)
                self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
                self.assertEqual(proc.stdout.strip(), DEFAULT_BIN)

    def test_wrapper_knob_is_executed(self):
        # End to end: drive one report through a reader driver's own
        # helper with MEMVEIL_BIN set to a wrapper. The wrapper marks
        # its execution, then execs the outer-resolved binary, so the
        # marker proves the executed binary is the knob binary. The
        # outer resolution keeps this green both by default and in
        # the sanitizer lane (knob set to the lane binary).
        real = resolve_memveil_bin()
        if not (os.path.isfile(real) and os.access(real, os.X_OK)):
            self.skipTest("no usable binary under test: %s" % real)
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "executed")
            wrapper = os.path.join(tmp, "knob-wrapper")
            Path(wrapper).write_text(
                "#!/bin/sh\ntouch %s\nexec %s \"$@\"\n" % (marker, real))
            os.chmod(wrapper, 0o755)
            env = dict(os.environ)
            env["MEMVEIL_BIN"] = wrapper
            code = ("import sys; sys.path.insert(0, %r); "
                    "from test_checkpoint_recovery import run, FIXTURE; "
                    "run(FIXTURE); print('driver-ran')"
                    % str(CLI))
            proc = subprocess.run([sys.executable, "-c", code], env=env,
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            self.assertIn("driver-ran", proc.stdout)
            self.assertTrue(os.path.isfile(marker),
                            "knob wrapper was not executed")

    def test_bogus_knob_refuses_runner_before_dispatch(self):
        # tools/test must fail closed (exit 1) before any suite runs.
        # Bogus knobs exit in rust_bin_setup, so this never recurses
        # into the contract test wired into reader-adversarial; never
        # invoke tools/test here with a usable knob.
        with tempfile.TemporaryDirectory() as tmp:
            plain = os.path.join(tmp, "plain")
            Path(plain).write_text("not executable\n")
            cases = {
                "missing": os.path.join(tmp, "missing"),
                "non-executable": plain,
                "empty": "",
            }
            for name, knob in cases.items():
                with self.subTest(name):
                    env = dict(os.environ)
                    env["MEMVEIL_BIN"] = knob
                    proc = subprocess.run(
                        [str(ROOT / "tools/test"), "reader-adversarial"],
                        env=env, capture_output=True, text=True)
                    self.assertEqual(proc.returncode, 1, proc.stderr[-2000:])
                    self.assertIn("MEMVEIL_BIN", proc.stderr)
                    self.assertIn("missing or not executable", proc.stderr)

    def test_bogus_knob_refuses_direct_driver(self):
        # A driver invoked directly (outside tools/test) refuses at
        # import, before dispatching anything: nonzero, names the
        # knob, and runs no checks.
        env = dict(os.environ)
        env["MEMVEIL_BIN"] = "/nonexistent/memveil-bin-knob"
        proc = subprocess.run(
            [sys.executable, str(CLI / "test_adversarial_cli.py")],
            env=env, capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("MEMVEIL_BIN", proc.stderr)
        self.assertNotIn("ok ", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
