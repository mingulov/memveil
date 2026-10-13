#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Top CLI harness: replay summaries over fixture captures.

Drives the built memveil binary: usage errors, refresh blocks,
device display filtering, the long-lived policy, replay-prefix
equivalence with report, hostile-name escaping, SIGINT
handling, and live-mode failure behavior. Exits nonzero on
the first failure.
"""

import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(ROOT)
BIN = os.path.join(REPO, "build", "memveil")
NESTED = os.path.join(REPO, "tests", "fixtures", "lifecycle",
                      "lifecycle-nested")
LONG = os.path.join(REPO, "tests", "fixtures", "lifecycle",
                    "long-window")
OPEN = os.path.join(REPO, "tests", "fixtures", "lifecycle",
                    "open-at-end")
ESCAPE = os.path.join(REPO, "tests", "fixtures", "reader", "escape")


def run(args, **kw):
    return subprocess.run([BIN] + args, capture_output=True, text=True,
                          **kw)


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def main():
    if not os.path.isfile(BIN):
        print("FAIL top: missing %s (run tools/build first)" % BIN)
        sys.exit(1)

    p = run(["top", "--help"])
    check("help-exit", p.returncode == 0, "exit %d" % p.returncode)
    check("help-text", "memveil top" in p.stdout)

    p = run(["top"])
    check("no-dir", p.returncode == 2, "exit %d" % p.returncode)
    p = run(["top", "--interval", "nope", NESTED])
    check("bad-interval", p.returncode == 2, "exit %d" % p.returncode)
    p = run(["top", "--nope", NESTED])
    check("unknown-flag", p.returncode == 2, "exit %d" % p.returncode)
    p = run(["top", "--long-lived-after", "0s", NESTED])
    check("zero-long-lived", p.returncode == 2, "exit %d" % p.returncode)

    p = run(["top", "--interval", "1s", NESTED])
    check("nested-exit", p.returncode == 0, "exit %d: %s"
          % (p.returncode, p.stderr))
    blocks = [b for b in p.stdout.split("--- refresh ") if b.strip()]
    # Window [1e9, 2.5e9) with 1s interval: boundary 2e9 + final.
    check("nested-blocks", len(blocks) == 2, "%d blocks" % len(blocks))
    check("nested-final", "successful_allocations = 1" in blocks[-1])
    # The 2.0s refresh must exclude the unmap at 2.3s: the mapping
    # is still open at the first boundary.
    check("nested-interim-open", "open_mappings = 1" in blocks[0])
    check("nested-interim-live",
          "live_observed_allocation_bytes = 4096" in blocks[0])
    check("nested-interim-no-close",
          "completed_lifetime_count = 1" not in blocks[0])

    rep = run(["report", NESTED])
    check("report-exit", rep.returncode == 0)
    final_body = blocks[-1].split("\n", 1)[1]
    check("replay-equivalence", final_body == rep.stdout,
          "final top block differs from report output")

    p = run(["top", "--interval", "1s", "--device", "dev-1", NESTED])
    check("device-exit", p.returncode == 0)
    check("device-shown", "{device=dev-1}" in p.stdout)
    p = run(["top", "--interval", "1s", "--device", "testdev0", NESTED])
    check("device-name-exit", p.returncode == 0)
    check("device-name-shown", "{device=dev-1}" in p.stdout)
    p = run(["top", "--interval", "1s", "--device", "nope", NESTED])
    check("device-none", "{device=" not in p.stdout)
    check("device-global", "bounce_attempts = 1" in p.stdout)

    p = run(["top", "--interval", "1s", OPEN])
    check("open-exit", p.returncode == 0)
    check("open-no-long-lived", "LONG_LIVED_ALLOCATION" not in p.stdout)
    p = run(["top", "--interval", "1s", "--long-lived-after", "1s",
             OPEN])
    check("long-lived-exit", p.returncode == 0, "exit %d" % p.returncode)
    check("long-lived-found", "LONG_LIVED_ALLOCATION" in p.stdout)
    check("long-lived-note", "not a leak" in p.stdout)

    p = run(["top", "--interval", "1s", ESCAPE])
    check("escape-exit", p.returncode == 0, "exit %d: %s"
          % (p.returncode, p.stderr))
    check("escape-clean", "\x1b" not in p.stdout)

    # One boundary refresh sleeps a full interval before the final,
    # so the process is guaranteed to be sleeping at 0.5s.
    proc = subprocess.Popen(
        [BIN, "top", "--interval", "1s", NESTED],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.5)
    if proc.poll() is not None:
        out, err = proc.communicate(timeout=8)
        print("FAIL sigint: top exited before the signal (exit %d)"
              % proc.returncode)
        sys.exit(1)
    proc.send_signal(signal.SIGINT)
    try:
        out, err = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate(timeout=8)
        print("FAIL sigint: top ignored SIGINT")
        sys.exit(1)
    check("sigint-exit", proc.returncode == 0,
          "exit %s: %s" % (proc.returncode, err))
    check("sigint-final", "successful_allocations = 1" in out)

    # A stop during a long refresh sleep lands promptly: the
    # wait polls first and sleeps in slices, so an hour-long
    # interval still exits within seconds of SIGTERM.
    proc = subprocess.Popen(
        [BIN, "top", "--interval", "1h", LONG],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.5)
    if proc.poll() is not None:
        out, err = proc.communicate(timeout=8)
        print("FAIL sigterm-long: top exited before the signal (exit %d)"
              % proc.returncode)
        sys.exit(1)
    proc.send_signal(signal.SIGTERM)
    try:
        out, err = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate(timeout=8)
        print("FAIL sigterm-long: top ignored SIGTERM during long sleep")
        sys.exit(1)
    check("sigterm-long-exit", proc.returncode == 0,
          "exit %s: %s" % (proc.returncode, err))
    check("sigterm-long-final", "successful_allocations = 1" in out)

    # Live-mode failures: no collection starts.
    live_env = dict(os.environ)
    live_env.pop("LMB_NATIVE_LIB", None)
    live_out = os.path.join(
        tempfile.mkdtemp(prefix="mvtoplive"), "cap")

    p = run(["top", NESTED, "--output", live_out],
            env=live_env)
    check("live-mode-conflict", p.returncode == 2,
          "exit %d" % p.returncode)
    check("live-mode-conflict-msg",
          "replay" in p.stderr and "live" in p.stderr,
          repr(p.stderr[:160]))

    dummy = os.path.join(REPO, "build", "dummy.o")
    p = run(["top", "--output", live_out, "--object", dummy],
            env=live_env)
    check("live-unavailable", p.returncode == 3,
          "exit %d" % p.returncode)
    check("live-unavailable-msg", "memveil top:" in p.stderr,
          repr(p.stderr[:160]))
    check("live-unavailable-clean",
          not os.path.exists(live_out), live_out)
    check("live-unavailable-tty",
          "\x1b" not in p.stdout and "\x1b" not in p.stderr)

    p = run(["top", "--output", live_out, "--duration", "nope"],
            env=live_env)
    check("live-bad-duration", p.returncode == 2,
          "exit %d" % p.returncode)
    check("live-bad-duration-msg", "bad decimal: nope" in p.stderr,
          repr(p.stderr[:160]))

    p = run(["top", NESTED, "--profiles-dir", "/alt/profiles"])
    check("replay-profiles-refused", p.returncode == 2,
          "exit %d" % p.returncode)
    check("replay-profiles-refused-msg",
          "live options need --output" in p.stderr,
          repr(p.stderr[:160]))

    # Profile resolution runs past the kernel-floor gate, so
    # the admission checks below need x86_64 kernel >= 7,
    # mirroring the record/qualify lanes; parser, replay, and
    # no-bridge checks stay unconditional. The floor refusal
    # itself is pinned fixture-backed in test_qualify.mojo
    # (test_plan_below_floor_refuses).
    eligible = False
    major = platform.release().split(".")[0]
    if (platform.machine() == "x86_64" and len(major) > 0
            and all(c in "0123456789" for c in major)):
        eligible = int(major) >= 7
    if not eligible:
        print("skip live-profiles-* (needs x86_64 kernel >= 7)")
    else:
        # The selected cache, not the default, reaches
        # admission: a missing override refuses at profile
        # load, while the default profiles proceed past it.
        missing = os.path.join(
            tempfile.mkdtemp(prefix="mvtopprof"), "no-such-dir")
        p = run(["top", "--output", live_out, "--object", dummy,
                 "--bridge", dummy, "--profiles-dir", missing],
                env=live_env)
        check("live-profiles-missing", p.returncode == 3,
              "exit %d" % p.returncode)
        check("live-profiles-missing-msg",
              "cannot load profiles" in p.stderr,
              repr(p.stderr[:160]))
        check("live-profiles-missing-clean",
              not os.path.exists(live_out), live_out)

        # A malformed manifest in the override refuses the
        # same way: the manifest half of the cache is read
        # from the selected directory.
        bad = os.path.join(tempfile.mkdtemp(prefix="mvtopbad"),
                           "profiles")
        os.makedirs(bad)
        with open(os.path.join(bad, "manifest.txt"), "w") as fh:
            fh.write("linux-x86_64-7.0-reference.json\n\n")
        p = run(["top", "--output", live_out, "--object", dummy,
                 "--bridge", dummy, "--profiles-dir", bad],
                env=live_env)
        check("live-profiles-bad-manifest", p.returncode == 3,
              "exit %d" % p.returncode)
        check("live-profiles-bad-manifest-msg",
              "cannot load profiles" in p.stderr,
              repr(p.stderr[:160]))

        # Receipt-sensitive routing oracle: mint an alternate
        # cache whose reference profile covers the live kernel,
        # with a receipt verifying for this host (live release
        # plus the resolved bridge hash). A verifying receipt
        # admits the profile, so the unsupported extra
        # capability names it; a missing or stale receipt
        # admits nothing. Both verbs must agree on every
        # diagnostic: top consults the selected receipts with
        # the shared checks, never weaker ones.
        live = platform.release()
        ok_obj = os.path.join(REPO, "tests", "fixtures", "elf", "ok.o")
        lc_obj = os.path.join(REPO, "tests", "fixtures", "elf", "lc-ok.o")
        with open(ok_obj, "rb") as fh:
            bridge_sha = hashlib.sha256(fh.read()).hexdigest()

        def sha(c):
            return "sha256:" + c * 64

        doc = json.load(open(os.path.join(
            REPO, "profiles", "linux-x86_64-7.0-reference.json")))
        doc["profile_id"] = "live-synth"
        doc["identity"]["source"]["revision"] = live
        doc["identity"]["source"]["note"] = (
            "config=%s config_src=file btf=%s format=%s object=%s "
            "image=%s image_bid=%s ring_bytes=131072 "
            "lc_object=%s lc_ring_bytes=131072 "
            "cp_object=%s cp_ring_bytes=131072"
            % (sha("a"), sha("b"), sha("c"), sha("d"), sha("e"),
               "f" * 40, sha("1"), sha("2")))

        def receipt_for(release):
            return {
                "schema_version": "0.1.0",
                "kind": "memveil-qualification-receipt",
                "profile_id": "live-synth", "grade": "local-auto",
                "created_ns": "123456789",
                "kernel": {"arch": "x86_64", "release": release},
                "bindings": {
                    "config": sha("a"), "config_src": "file",
                    "btf": sha("b"), "format": sha("c"),
                    "image": sha("e"), "image_bid": "f" * 40},
                "capabilities": {
                    "attempt-trace": {
                        "status": "qualified",
                        "detail": "synthetic test smoke"},
                    "mapping-lifecycle": {
                        "status": "qualified",
                        "detail": "synthetic test smoke"}},
                "artifacts": {
                    "memveil": "0.1.0",
                    "bridge": "sha256:" + bridge_sha,
                    "objects": {"attempt": sha("d"),
                                "lifecycle": sha("1")}},
                "workload": {
                    "kind": "smoke", "duration_s": "3",
                    "traffic_required": False,
                    "note": "synthetic test receipt"},
            }

        def cache_with(receipt):
            alt = os.path.join(
                tempfile.mkdtemp(prefix="mvtopalt"), "profiles")
            os.makedirs(alt)
            with open(os.path.join(alt, "live-synth.json"), "w") as fh:
                json.dump(doc, fh)
            with open(os.path.join(alt, "manifest.txt"), "w") as fh:
                fh.write("live-synth.json\n")
            if receipt is not None:
                os.makedirs(os.path.join(alt, "receipts"))
                with open(os.path.join(
                        alt, "receipts", "live-synth.json"), "w") as fh:
                    json.dump(receipt, fh)
            return alt

        receipt_cases = [
            ("live-receipt", cache_with(receipt_for(live)),
             "capability mapping-lifecycle unsupported by live-synth"),
            ("live-no-receipt", cache_with(None),
             "no profile satisfies requested capabilities"),
            ("live-stale-receipt",
             cache_with(receipt_for("0.0.0-test")),
             "no profile satisfies requested capabilities"),
        ]
        for tag, alt, want in receipt_cases:
            rec_out = os.path.join(
                tempfile.mkdtemp(prefix="mvtoprec"), "cap")
            top_out = os.path.join(
                tempfile.mkdtemp(prefix="mvtoptop"), "cap")
            rec = run(["record", "--output", rec_out,
                       "--object", ok_obj, "--lc-object", lc_obj,
                       "--bridge", ok_obj, "--profiles-dir", alt,
                       "--capability", "attempt-trace,mapping-lifecycle"],
                      env=live_env)
            top = run(["top", "--output", top_out,
                       "--object", ok_obj, "--lc-object", lc_obj,
                       "--bridge", ok_obj, "--profiles-dir", alt,
                       "--capability", "attempt-trace,mapping-lifecycle"],
                      env=live_env)
            check(tag + "-record-exit", rec.returncode == 3,
                  "exit %d" % rec.returncode)
            check(tag + "-top-exit", top.returncode == 3,
                  "exit %d" % top.returncode)
            rec_diag = rec.stderr.replace("memveil record: ", "").strip()
            top_diag = top.stderr.replace("memveil top: ", "").strip()
            check(tag + "-record-want", rec_diag == want, rec_diag[:160])
            check(tag + "-top-want", top_diag == want, top_diag[:160])
            check(tag + "-same-refusal", rec_diag == top_diag,
                  "record %r top %r"
                  % (rec.stderr[:160], top.stderr[:160]))
            check(tag + "-record-clean",
                  not os.path.exists(rec_out), rec_out)
            check(tag + "-top-clean",
                  not os.path.exists(top_out), top_out)

    # Refusal precedes any write: an occupied dir stays
    # untouched when admission refuses first. The exact
    # exists-refusal needs a bridge, so the VM walkthrough
    # pins exit 3 naming the clash there.
    busy = tempfile.mkdtemp(prefix="mvtopbusy")
    with open(os.path.join(busy, "session.json"), "w") as fh:
        fh.write("{}")
    before = sorted(os.listdir(busy))
    p = run(["top", "--output", busy, "--object", dummy],
            env=live_env)
    check("live-refusal-no-write", p.returncode == 3,
          "exit %d" % p.returncode)
    check("live-refusal-untouched",
          sorted(os.listdir(busy)) == before, busy)

    print("top: CLI harness passed")


if __name__ == "__main__":
    main()
