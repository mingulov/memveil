#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared core for the lifecycle/copy stress runner.

Binds the two object pairs (pre-change baseline from history,
current candidate from the retained manifest), verifies exact
bytes on the host, stamps every output, and judges stress legs
with the identity-races gate's assertion shapes plus the
baseline-vs-candidate miss comparison. All judging is pure and
unit-tested on synthetic logs; live boots stay in the runner.
"""

import hashlib
import json
import os
import selectors
import subprocess
import sys
import tarfile
import time
from fractions import Fraction

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import check_conservation, check_identity_closure  # noqa: E402
import guest_oracle  # noqa: E402
from stress_guest import EXPECT_RELEASE  # noqa: E402,E401

SCHEMA = "memveil-stress-inputs/1"

# Pre-change baseline: the parent of the cutover commit, by full
# hash, with the two blob paths, blob ids, and byte hashes.
BASELINE_COMMIT = "6f850aba88162c4e987b5afb42ecf59d326c7849"
BASELINE_CUTOVER = "22f1efa1298b5033e7a7229fefb3b05334fd4077"
BASELINE_LC_BLOB = "tests/fixtures/elf/lc-ok.o"
BASELINE_CP_BLOB = "tests/fixtures/elf/cp-ok.o"
BASELINE_LC_BLOB_ID = "a54cffd0624e434b7630705a862a6d991f589c52"
BASELINE_CP_BLOB_ID = "467ba8235d1ae0e0478946ab056beb57e6891e15"
BASELINE_LC_SHA = "3eec845b8e47fc34f031bfbb24cb209f06b3bece55ace67765648c570ea575c2"
BASELINE_CP_SHA = "ae91c9f35676b54ef8b0c5561ebb33bcdd7f6e7c22bc76584c26605b42361154"

# Current candidate objects, manifest-exact (dist/candidate.json
# wins over any remembered prefix).
C9_CANDIDATE_SHA = "ac2503a3ef4269826ae3f9512ca2402d45e767be2601c289" \
    "3e812ebb6df929a7"
C9_LC_SHA = "32f6a353779778981e727f311fe5d1b2c21fc92ae9918765f86bc4f81f58df34"
C9_CP_SHA = "526a6726e24f7725a0e88e28d6994f0475a1589c3de10c7ebef703a03dfa73e8"
C9_ATTEMPT_SHA = "ded931289c83713f62cdb5479fbf8aab03fe344d91a91bdeeee7e76f106979eb"
C9_SOURCE_COMMIT = "1af6cc9a912a38c8b2cb61da14749fbf1f628659"
C9_SOURCE_TREE = "ac316ebc57a7b9d1aaf91bfcac8b1de410a6f614"
C9_BUNDLE_MANIFEST_SHA = "b2ba73f2d2ad02c8957171c08e4fbf4a9e6895bec0a7d3074ad5c687e07ad820"
C9_BUNDLE_SHA = "389f1d358e9eb8896c6033ec9ce18f74a1adda10d2502f4a9e2d7f2943cb05ea"
C9_BUNDLE_SIZE = 1797674

# Gate constants mirrored from the identity-races gate
# (tests/vm/test_identity_races.py) and the guest workload
# (tests/vm/guest_lifecycle.py). The runner cross-checks every
# value against its source; drift fails the self-test.
P1_OPS = 200
P2_OPS = 2000
COUNT_SLACK = 64
MISS_CEILING = 0.5
LC_SITES = ("mv_map_result:swiotlb_tbl_map_single,"
            "mv_unmap:__swiotlb_tbl_unmap_single")
CP_SITES = ("mv_sync_device:__swiotlb_sync_single_for_device,"
            "mv_sync_cpu:__swiotlb_sync_single_for_cpu,"
            "mv_bounce:swiotlb_bounce,"
            "mv_bounce_exit:swiotlb_bounce")
LC_RING = "mv_lifecycle"
CP_RING = "mv_copies"

# Wire constants mirrored from crates/ebpf-common/src/lib.rs
# (magic/version/lengths only; decoding stays with the shared
# decoders inside the consumer).
LC_LEN = 44
LC_MAGIC = 0x434C564D
LC_VERSION = 2
LC_KIND_MAP = 1
LC_KIND_UNMAP = 2
LC_FLAG_OK = 0x1
LC_FLAG_SKIP_SYNC = 0x2
LC_FLAG_GEN_MISS = 0x4
LC_FLAG_GEN_UNASSIGNED = 0x8
CP_LEN = 48
CP_MAGIC = 0x5043564D
CP_VERSION = 1
CP_KIND_SYNC = 1
CP_KIND_COPY = 2
CP_FLAG_TO_DEVICE = 0x1
CP_FLAG_KNOWN = 0x2
CP_FLAG_CLAMPED = 0x4
CP_FLAG_EARLY_ZERO = 0x8

CONSUMER_DIR = os.path.dirname(os.path.abspath(__file__))
CONSUMER_CARGO = os.path.join(CONSUMER_DIR, "Cargo.toml")
CONSUMER_RELEASE = os.path.join(CONSUMER_DIR, "target", "release",
                                "stress-consume")


def sha_file(path):
    """SHA-256 of a file, streamed."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


# Post-kill reap, then the pipe drain, for the shared
# host runner below. Same bound shape as the guest
# command helper: the verdict never waits on a child
# unconditionally.
RUN_REAP_TIMEOUT = 5
RUN_DRAIN_TIMEOUT = 5


def _run_text(blob, binary):
    """Decode runner bytes, lossy-but-total for text."""
    if binary:
        return b"" if blob is None else blob
    if blob is None:
        blob = b""
    return blob.decode("utf-8", "replace").replace(
        "\r\n", "\n").replace("\r", "\n")


def _unavailable_note(key, reason):
    """Bytes marking one unregistered stream lost.

    Names the stream and the registration error,
    so a collection missing a stream carries its
    reason instead of reporting clean success.
    """
    name = {"out": "stdout", "err": "stderr"}[key]
    return ("\n[stress-core: %s unavailable: "
            "selector registration failed "
            "(%s)]\n" % (name, reason)).encode("utf-8")


def _collect(proc, timeout):
    """Drain both pipes with a deadline, then reap.

    Returns (out_bytes, err_bytes, done): done means
    both pipes hit EOF and the child reaped. Partial
    bytes survive either deadline: unlike
    Popen.communicate, a child that outlives its
    closed pipes costs the reap only, never the bytes
    already read (communicate raises its final wait
    timeout with empty output fields, discarding
    them). EOF'd streams are closed, as with
    communicate. Readiness waits use the default
    selector, which has no fd-number ceiling
    (unlike select()'s 1024 fd_set). A stream the
    selector refuses stays visible: its bytes carry
    an unavailable-with-reason note, and done is
    False, so a collection missing a stream never
    reports clean success. No stdin pipe: every
    caller here leaves stdin inherited.
    """
    want = {}
    for key, name in (("out", "stdout"),
                      ("err", "stderr")):
        stream = getattr(proc, name, None)
        if stream is not None and not stream.closed:
            want[stream] = key
    chunks = {"out": [], "err": []}
    for stream in want:
        try:
            os.set_blocking(stream.fileno(), False)
        except (OSError, ValueError):
            pass
    open_streams = list(want)
    end = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    lost = {}
    try:
        for stream in open_streams:
            try:
                selector.register(stream,
                                  selectors.EVENT_READ)
            except (OSError, ValueError) as exc:
                # Refused is unavailable, not EOF:
                # the sibling still drains, and the
                # note below keeps the loss visible.
                lost[stream] = "%s: %s" % (
                    type(exc).__name__, exc)
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
        open_streams = [stream for stream in open_streams
                        if not stream.closed]
        while open_streams:
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            try:
                events = selector.select(
                    min(remaining, 0.5))
            except (OSError, ValueError):
                break
            for key, _mask in events:
                stream = key.fileobj
                try:
                    data = os.read(stream.fileno(),
                                   65536)
                except BlockingIOError:
                    continue
                except (OSError, ValueError):
                    data = b""
                if data:
                    chunks[want[stream]].append(data)
                    continue
                try:
                    selector.unregister(stream)
                except (OSError, ValueError, KeyError):
                    pass
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
                open_streams.remove(stream)
    finally:
        selector.close()
        for stream in open_streams:
            try:
                os.set_blocking(stream.fileno(), True)
            except (OSError, ValueError):
                pass
    for stream, reason in lost.items():
        chunks[want[stream]].append(
            _unavailable_note(want[stream], reason))
    try:
        proc.wait(timeout=max(end - time.monotonic(),
                              0))
    except subprocess.TimeoutExpired:
        return (b"".join(chunks["out"]),
                b"".join(chunks["err"]), False)
    return (b"".join(chunks["out"]),
            b"".join(chunks["err"]),
            not open_streams and not lost)


def run(cmd, cwd=None, timeout=600, env=None, text=True):
    """Run a command, returning the completed process.

    Bounded end to end: the command gets `timeout`, then
    SIGKILL plus a bounded reap, then a bounded output
    collection. Nothing here waits on the child
    unconditionally (contrast subprocess.run, which reaps
    with wait(None) after the kill). A timeout still
    raises TimeoutExpired, carrying whatever partials
    were readable; text decoding never raises. Bytes
    read before either deadline survive it, even when
    the child outlives its closed pipes.
    """
    # Binary pipes throughout: decoding happens once,
    # below, so undecodable bytes can never raise out of
    # either the success or the timeout path.
    proc = subprocess.Popen(cmd, cwd=cwd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env)
    binary = not text
    first_out, first_err, done = _collect(proc, timeout)
    if done:
        return subprocess.CompletedProcess(
            cmd, proc.returncode, _run_text(first_out,
                                            binary),
            _run_text(first_err, binary))
    try:
        proc.kill()
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=RUN_REAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        pass
    second_out, second_err, _drained = _collect(
        proc, RUN_DRAIN_TIMEOUT)
    raise subprocess.TimeoutExpired(
        cmd, timeout,
        output=_run_text(first_out + second_out,
                         binary),
        stderr=_run_text(first_err + second_err,
                         binary))


def git_head(repo):
    """Full commit of the checkout, or refusal text."""
    proc = run(["git", "-C", repo, "rev-parse", "HEAD"])
    if proc.returncode != 0:
        raise ValueError("cannot read runner commit: %s" % proc.stderr.strip())
    return proc.stdout.strip()


def materialize(repo, work):
    """Write both pinned pairs to files under work, verified.

    The candidate pair copies from the committed Aya fixtures;
    the baseline pair extracts from history by full commit hash
    (never from a fingerprint). Every byte is hash-checked on
    write. Returns {name: {"lc": path, "cp": path}} plus shas.
    """
    os.makedirs(work, exist_ok=True)
    pairs = {}
    c9 = {
        "lc": ("tests/vm/fixtures/aya/swiotlb_lifecycle.bpf.o", C9_LC_SHA),
        "cp": ("tests/vm/fixtures/aya/swiotlb_copy.bpf.o", C9_CP_SHA),
    }
    for channel, (rel, want) in c9.items():
        src = os.path.join(repo, rel)
        with open(src, "rb") as handle:
            blob = handle.read()
        got = hashlib.sha256(blob).hexdigest()
        if got != want:
            raise ValueError("candidate %s digest drift: %s" % (rel, got))
        dst = os.path.join(work, "c9-%s.o" % channel)
        with open(dst, "wb") as handle:
            handle.write(blob)
        pairs.setdefault("c9", {})[channel] = {"path": dst, "sha256": got}
    base = {
        "lc": (BASELINE_LC_BLOB, BASELINE_LC_BLOB_ID, BASELINE_LC_SHA),
        "cp": (BASELINE_CP_BLOB, BASELINE_CP_BLOB_ID, BASELINE_CP_SHA),
    }
    for channel, (rel, blob_id, want) in base.items():
        # Byte-level extraction: blobs are raw object bytes, never
        # text, so the shared runner stays in binary mode.
        raw = run(["git", "-C", repo, "cat-file", "-p",
                   "%s:%s" % (BASELINE_COMMIT, rel)],
                  timeout=60, text=False)
        if raw.returncode != 0 or not raw.stdout:
            raise ValueError("cannot extract baseline %s" % rel)
        got = hashlib.sha256(raw.stdout).hexdigest()
        if got != want:
            raise ValueError("baseline %s digest drift: %s" % (rel, got))
        ident = run(["git", "-C", repo, "rev-parse",
                     "%s:%s" % (BASELINE_COMMIT, rel)], timeout=60)
        if ident.returncode != 0 or ident.stdout.strip() != blob_id:
            raise ValueError("baseline %s blob id drift" % rel)
        dst = os.path.join(work, "baseline-%s.o" % channel)
        with open(dst, "wb") as handle:
            handle.write(raw.stdout)
        pairs.setdefault("baseline", {})[channel] = {
            "path": dst, "sha256": got}
    # The baseline commit must be the cutover's parent exactly.
    parent = run(["git", "-C", repo, "rev-parse",
                  "%s^" % BASELINE_CUTOVER], timeout=60)
    if parent.returncode != 0 or parent.stdout.strip() != BASELINE_COMMIT:
        raise ValueError("baseline is not the cutover parent")
    return pairs


def candidate_pins():
    """The pinned seal this runner binds (explicit-path inputs)."""
    return {
        "candidate_sha256": C9_CANDIDATE_SHA,
        "schema": "memveil-candidate/2",
        "source_commit": C9_SOURCE_COMMIT,
        "source_tree": C9_SOURCE_TREE,
        "bundle_manifest_sha256": C9_BUNDLE_MANIFEST_SHA,
        "files": {
            "bpf/swiotlb_lifecycle.bpf.o": C9_LC_SHA,
            "bpf/swiotlb_copy.bpf.o": C9_CP_SHA,
            "bpf/swiotlb_attempt.bpf.o": C9_ATTEMPT_SHA,
        },
        "bundle_sha256": C9_BUNDLE_SHA,
        "bundle_size": C9_BUNDLE_SIZE,
    }


def verify_candidate_binding(candidate_path, bundle_path, pins=None):
    """Verify one candidate seal from explicit paths, fully.

    Checks the manifest digest, schema, source and tree,
    the bundle size and hash, then opens the tarball and
    checks the inner manifest plus all three BPF member
    hashes against the pinned seal. Returns the binding
    dict the input manifest carries. Any absence, drift,
    or mix refuses with a precise reason.
    """
    pins = pins or candidate_pins()
    if not candidate_path or not os.path.isfile(candidate_path):
        raise ValueError("candidate manifest missing: %r"
                         % (candidate_path,))
    if sha_file(candidate_path) != pins["candidate_sha256"]:
        raise ValueError("candidate manifest digest drift: %s"
                         % candidate_path)
    try:
        with open(candidate_path) as handle:
            manifest = json.load(handle)
    except ValueError as exc:
        raise ValueError("candidate manifest unparsable: %s (%s)"
                         % (candidate_path, exc))
    if manifest.get("schema") != pins["schema"]:
        raise ValueError("candidate schema drift: %r"
                         % manifest.get("schema"))
    source = manifest.get("source", {})
    if source.get("commit") != pins["source_commit"] \
            or source.get("tree") != pins["source_tree"]:
        raise ValueError("candidate source drift: %r" % (source,))
    if manifest.get("bundle_manifest_sha256") \
            != pins["bundle_manifest_sha256"]:
        raise ValueError("candidate bundle manifest drift")
    files = manifest.get("files", {})
    for name, want in pins["files"].items():
        if files.get(name) != want:
            raise ValueError("candidate file drift: %s" % name)
    bundle = None
    for entry in manifest.get("artifacts", []):
        if entry.get("name") == "bundle.tar.gz":
            bundle = entry
    if bundle is None:
        raise ValueError("candidate bundle entry missing")
    if bundle.get("sha256") != pins["bundle_sha256"] \
            or str(bundle.get("size")) != str(pins["bundle_size"]):
        raise ValueError("candidate bundle entry drift")
    if not bundle_path or not os.path.isfile(bundle_path):
        raise ValueError("candidate bundle missing: %r" % (bundle_path,))
    if sha_file(bundle_path) != pins["bundle_sha256"]:
        raise ValueError("candidate bundle bytes drift")
    if os.path.getsize(bundle_path) != pins["bundle_size"]:
        raise ValueError("candidate bundle size drift")
    try:
        archive = tarfile.open(bundle_path, "r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("candidate bundle unreadable: %s" % exc)
    try:
        members = {m.name: m for m in archive.getmembers()
                   if m.isfile()}
        inner = members.get("bundle/MANIFEST.json")
        if inner is None:
            raise ValueError("candidate bundle lacks inner manifest")
        got = hashlib.sha256(
            archive.extractfile(inner).read()).hexdigest()
        if got != pins["bundle_manifest_sha256"]:
            raise ValueError("candidate inner manifest drift")
        for name, want in pins["files"].items():
            member = members.get("bundle/" + name)
            if member is None:
                raise ValueError("candidate bundle lacks %s" % name)
            got = hashlib.sha256(
                archive.extractfile(member).read()).hexdigest()
            if got != want:
                raise ValueError("candidate bundle member drift: %s"
                                 % name)
    except (tarfile.TarError, OSError, KeyError) as exc:
        raise ValueError("candidate bundle member unreadable: %s" % exc)
    finally:
        archive.close()
    return {
        "schema": manifest["schema"],
        "source": {"commit": pins["source_commit"],
                   "tree": pins["source_tree"]},
        "bundle_manifest_sha256": pins["bundle_manifest_sha256"],
        "files": dict(pins["files"]),
        "bundle": {"sha256": pins["bundle_sha256"],
                   "size": pins["bundle_size"]},
    }


def load_candidate_binding(repo, candidate_path=None, bundle_path=None):
    """Verify the retained candidate manifest and bundle bytes.

    Explicit paths win; without them the checkout's dist/
    seal applies. Returns the binding dict the input
    manifest carries. Every digest is re-checked against
    the files; drift refuses.
    """
    manifest_path = candidate_path or os.path.join(
        repo, "dist", "candidate.json")
    tarball_path = bundle_path or os.path.join(
        repo, "dist", "bundle.tar.gz")
    return verify_candidate_binding(manifest_path, tarball_path)


def oracle_digest(repo):
    """Hash the owned oracle-module sources (ground-truth pin)."""
    kernel = os.path.join(repo, "tests", "kernel")
    out = {}
    for name in ("memveil_dma_oracle.c", "Makefile"):
        out[name] = sha_file(os.path.join(kernel, name))
    return out


def oracle_run_binding(repo):
    """Bind the guest oracle bytes plus the identity pins.

    Re-verifies the guest-targeted fixture (digest, size,
    receipt, exact vermagic) and stamps its digest, the
    vermagic, and the live-BTF identity pin next to the
    source hashes. The guest enforces the digest and the
    BTF pin before loading; drift refuses before boot.
    """
    binding = oracle_digest(repo)
    guest_oracle.verify_fixture()
    binding["ko_sha256"] = guest_oracle.KO_SHA256
    binding["ko_vermagic"] = guest_oracle.GUEST_VERMAGIC
    binding["btf_sha256"] = guest_oracle.GUEST_BTF_SHA256
    binding["ko_provenance_sha256"] = sha_file(
        guest_oracle.FIXTURE_PROVENANCE)
    binding["guest_release"] = guest_oracle.GUEST_RELEASE
    return binding


def cargo_env():
    """Build environment letting the checkout toolchain pin win."""
    env = dict(os.environ)
    # A session-wide RUSTUP_TOOLCHAIN override would ignore the
    # checkout's rust-toolchain.toml; the pin wins for stamps.
    env.pop("RUSTUP_TOOLCHAIN", None)
    return env


def build_consumer():
    """Build the release consumer, returning path plus stamp dict."""
    proc = run(["cargo", "build", "--locked", "--offline", "--release"],
               cwd=CONSUMER_DIR, timeout=900, env=cargo_env())
    if proc.returncode != 0:
        raise ValueError("consumer build failed: %s"
                         % (proc.stderr.strip()[-2000:]))
    if not os.path.isfile(CONSUMER_RELEASE):
        raise ValueError("consumer binary missing after build")
    rustc = run(["rustc", "--version"], timeout=30, env=cargo_env())
    cargo = run(["cargo", "--version"], timeout=30, env=cargo_env())
    lock = {}
    lock_path = os.path.join(CONSUMER_DIR, "Cargo.lock")
    if os.path.isfile(lock_path):
        text = open(lock_path).read()
        for name in ("aya", "aya-obj"):
            marker = 'name = "%s"' % name
            at = text.find(marker)
            if at >= 0:
                field = text[at:at + 200].split('version = "', 1)[1]
                version = field.split('"', 1)[0]
                lock[name] = version
    return {
        "path": CONSUMER_RELEASE,
        "sha256": sha_file(CONSUMER_RELEASE),
        "build": {
            "rustc": rustc.stdout.strip(),
            "cargo": cargo.stdout.strip(),
            "profile": "release",
            "package": "memveil-stress-consumer 0.0.0",
            "locked": lock,
        },
    }


def write_input_manifest(path, pairs, candidate, consumer, oracle,
                         argv, runner_commit):
    """Write the stress-only input manifest binding every byte."""
    manifest = {
        "schema": SCHEMA,
        "runner_commit": runner_commit,
        "runner_argv": list(argv),
        "consumer": {
            "binary_sha256": consumer["sha256"],
            "build": consumer["build"],
        },
        "oracle": oracle,
        "pairs": {
            "baseline": {
                "lc": {"path": pairs["baseline"]["lc"]["path"],
                       "sha256": pairs["baseline"]["lc"]["sha256"]},
                "cp": {"path": pairs["baseline"]["cp"]["path"],
                       "sha256": pairs["baseline"]["cp"]["sha256"]},
                "binding": {
                    "commit": BASELINE_COMMIT,
                    "cutover_child": BASELINE_CUTOVER,
                    "lc_blob": BASELINE_LC_BLOB,
                    "lc_blob_id": BASELINE_LC_BLOB_ID,
                    "cp_blob": BASELINE_CP_BLOB,
                    "cp_blob_id": BASELINE_CP_BLOB_ID,
                },
            },
            "c9": {
                "lc": {"path": pairs["c9"]["lc"]["path"],
                       "sha256": pairs["c9"]["lc"]["sha256"]},
                "cp": {"path": pairs["c9"]["cp"]["path"],
                       "sha256": pairs["c9"]["cp"]["sha256"]},
                "binding": {"candidate": candidate},
            },
        },
    }
    with open(path, "w") as handle:
        handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def verify_input_manifest(manifest, consumer_path=None):
    """Re-hash every bound byte; returns a reason list (empty ok).

    The host runs this before booting and the guest re-runs it
    before attaching: both ends verify the bytes they use.
    """
    bad = []
    if manifest.get("schema") != SCHEMA:
        return ["manifest schema %r" % (manifest.get("schema"),)]
    for field in ("runner_commit", "runner_argv", "consumer",
                  "oracle", "pairs"):
        if field not in manifest:
            bad.append("manifest lacks %s" % field)
    if bad:
        return sorted(bad)
    if consumer_path is not None:
        try:
            got = sha_file(consumer_path)
        except OSError as exc:
            return ["consumer unreadable: %s" % exc]
        if got != manifest["consumer"].get("binary_sha256"):
            bad.append("consumer digest mismatch")
    pairs = manifest["pairs"]
    if sorted(pairs.keys()) != ["baseline", "c9"]:
        return sorted(bad + ["manifest pairs %r" % sorted(pairs.keys())])
    want = {
        "baseline": {"lc": BASELINE_LC_SHA, "cp": BASELINE_CP_SHA},
        "c9": {"lc": C9_LC_SHA, "cp": C9_CP_SHA},
    }
    for name in ("baseline", "c9"):
        for channel in ("lc", "cp"):
            entry = pairs[name].get(channel, {})
            path = entry.get("path", "")
            try:
                got = sha_file(path)
            except OSError:
                bad.append("%s %s unreadable: %s" % (name, channel, path))
                continue
            if got != entry.get("sha256"):
                bad.append("%s %s bytes differ from manifest"
                           % (name, channel))
            if got != want[name][channel]:
                bad.append("%s %s is not the pinned pair bytes"
                           % (name, channel))
    base = pairs["baseline"].get("binding", {})
    if base.get("commit") != BASELINE_COMMIT:
        bad.append("baseline commit drift")
    if base.get("lc_blob_id") != BASELINE_LC_BLOB_ID:
        bad.append("baseline lc blob drift")
    if base.get("cp_blob_id") != BASELINE_CP_BLOB_ID:
        bad.append("baseline cp blob drift")
    candidate = pairs["c9"].get("binding", {}).get("candidate", {})
    if candidate.get("source", {}).get("commit") != C9_SOURCE_COMMIT:
        bad.append("candidate source drift")
    if candidate.get("bundle_manifest_sha256") != C9_BUNDLE_MANIFEST_SHA:
        bad.append("candidate bundle manifest drift")
    files = candidate.get("files", {})
    if files.get("bpf/swiotlb_lifecycle.bpf.o") != C9_LC_SHA:
        bad.append("candidate lc file drift")
    if files.get("bpf/swiotlb_copy.bpf.o") != C9_CP_SHA:
        bad.append("candidate cp file drift")
    oracle = manifest.get("oracle", {})
    if oracle.get("ko_sha256") != guest_oracle.KO_SHA256:
        bad.append("oracle ko digest drift")
    if oracle.get("ko_vermagic") != guest_oracle.GUEST_VERMAGIC:
        bad.append("oracle ko vermagic drift")
    if oracle.get("btf_sha256") != guest_oracle.GUEST_BTF_SHA256:
        bad.append("oracle btf pin drift")
    if oracle.get("guest_release") != guest_oracle.GUEST_RELEASE:
        bad.append("oracle guest release drift")
    return sorted(bad)


# -- Wire encoders (test vectors only) --------------------------
# The consumer decodes with the shared MemVeil wire decoders; these
# build the byte vectors that prove the round-trip. Layouts mirror
# crates/ebpf-common/src/lib.rs.

def encode_lc(kind, ok, skip, dirc, seq, ktime, size, gen,
              miss=False, unassigned=False):
    """Encode one 44-byte lifecycle record."""
    import struct
    flags = (LC_FLAG_OK if ok else 0) | (LC_FLAG_SKIP_SYNC if skip else 0)
    flags |= LC_FLAG_GEN_MISS if miss else 0
    flags |= LC_FLAG_GEN_UNASSIGNED if unassigned else 0
    return struct.pack("<IHHHHQQQQ", LC_MAGIC, LC_VERSION, kind,
                       flags, dirc, seq, ktime, size, gen)


def encode_cp(kind, todev, known, clamp, ezero, dirc, reason,
              seq, ktime, req, eff):
    """Encode one 48-byte copy record."""
    import struct
    flags = (CP_FLAG_TO_DEVICE if todev else 0)
    flags |= CP_FLAG_KNOWN if known else 0
    flags |= CP_FLAG_CLAMPED if clamp else 0
    flags |= CP_FLAG_EARLY_ZERO if ezero else 0
    return (struct.pack("<IHHHHQQQQ", CP_MAGIC, CP_VERSION, kind,
                        flags, dirc, seq, ktime, req, eff)
            + struct.pack("<H", reason) + b"\0\0")


# -- Judges (pure; assertion shapes of the identity-races gate) --

def miss_fraction(lc_events):
    """Fraction of retained lifecycle records with gen 0."""
    if not lc_events:
        return 0.0
    missed = sum(1 for e in lc_events if e["gen"] == 0)
    return missed / len(lc_events)


def retained_breakdown(lc_events):
    """Outcome mix over validated retained lifecycle records.

    M counts gen==0, D counts every retained map-result and unmap
    record; failed maps, unassigned successful maps, and missed
    unmaps are reported separately for the receipt.
    """
    out = {
        "D": 0, "M": 0,
        "maps_ok_assigned": 0, "maps_unassigned": 0,
        "maps_failed": 0, "unmaps_known": 0,
        "unmaps_missed": 0,
    }
    for e in lc_events:
        if e["kind"] not in (1, 2):
            continue
        out["D"] += 1
        if e["gen"] == 0:
            out["M"] += 1
        if e["kind"] == 1:
            if not e["ok"]:
                out["maps_failed"] += 1
            elif e["gen"] == 0:
                out["maps_unassigned"] += 1
            else:
                out["maps_ok_assigned"] += 1
        elif e["gen"] == 0:
            out["unmaps_missed"] += 1
        else:
            out["unmaps_known"] += 1
    return out


def judge_phase2(lc, lc_sum, cp, cp_sum, bpf, blockstats, tag):
    """Judge one stress leg, returning (reasons, metrics).

    Shapes mirror the identity-races gate's phase 2: exact
    conservation on both rings, exact identity closure, block
    reads proving the flood flowed, probe-vs-bpftrace agreement
    within quiet-guest slack, copy double-record/drop tripwires,
    and the total-breakage miss ceiling.
    """
    bad = []
    bad += check_conservation(lc, lc_sum, tag + "-lc")
    bad += check_conservation(cp, cp_sum, tag + "-cp")
    bad += check_identity_closure(lc, tag + "-lc")
    if blockstats["after"]["read_ios"] <= blockstats["before"]["read_ios"]:
        bad.append("%s: flood produced no block reads" % tag)
    lc_firings = bpf["maps"] + bpf["unmaps"]
    if abs(lc_sum["cnt_obs"] - lc_firings) > COUNT_SLACK:
        bad.append("%s: probe observed %d vs bpftrace %d "
                   "(maps %d + unmaps %d)" % (
                       tag, lc_sum["cnt_obs"], lc_firings,
                       bpf["maps"], bpf["unmaps"]))
    kind2 = sum(1 for e in cp if e["kind"] == 2)
    if kind2 > bpf["bounces"] + COUNT_SLACK:
        bad.append("%s: %d copy records vs %d bounce calls "
                   "(double-record?)" % (tag, kind2, bpf["bounces"]))
    if bpf["bounces"] > kind2 + cp_sum["cnt_fail"] + COUNT_SLACK:
        bad.append("%s: %d bounce calls vs %d records + %d "
                   "fail (silent drop?)" % (
                       tag, bpf["bounces"], kind2, cp_sum["cnt_fail"]))
    mix = retained_breakdown(lc)
    miss = miss_fraction(lc)
    if miss > MISS_CEILING:
        bad.append("%s: miss fraction %.4f over ceiling %.2f"
                   % (tag, miss, MISS_CEILING))
    metrics = {
        "M": mix["M"], "D": mix["D"], "miss": miss,
        "mix": mix, "lc_obs": lc_sum["cnt_obs"],
        "firings": lc_firings, "kind2": kind2,
        "bounces": bpf["bounces"],
        "block_reads": (blockstats["after"]["read_ios"]
                        - blockstats["before"]["read_ios"]),
    }
    return sorted(bad), metrics


def compare_pairs(base, c9, tag):
    """Compare one baseline leg against one candidate leg.

    Each side is {"M", "D", "complete"}. Requires D>0 and
    complete comparable coverage on both sides, else the pair is
    BLOCKED (never a pass, never a bare comparison). A higher
    candidate ratio is a regression even when both legs clear
    the ceiling. Returns (verdict, reasons, detail).
    """
    detail = {
        "base": dict(base), "c9": dict(c9),
        "base_ratio": None, "c9_ratio": None,
    }
    if base["D"] <= 0 or c9["D"] <= 0:
        return ("BLOCKED",
                ["%s: empty retained window (base D=%d, c9 D=%d)"
                 % (tag, base["D"], c9["D"])],
                detail)
    if not base["complete"] or not c9["complete"]:
        return ("BLOCKED",
                ["%s: incomplete coverage (base %s, c9 %s)"
                 % (tag, base["complete"], c9["complete"])],
                detail)
    base_ratio = Fraction(base["M"], base["D"])
    c9_ratio = Fraction(c9["M"], c9["D"])
    detail["base_ratio"] = "%s/%s" % (base["M"], base["D"])
    detail["c9_ratio"] = "%s/%s" % (c9["M"], c9["D"])
    if c9_ratio > base_ratio:
        return ("REGRESSION",
                ["%s: candidate %s/%s above baseline %s/%s"
                 % (tag, c9["M"], c9["D"], base["M"], base["D"])],
                detail)
    return ("PASS", [], detail)


def parse_verify_layout(text):
    """Parse consumer --verify-layout output into a dict."""
    out = {"maps": {}, "programs": {}, "family": None,
           "core_relocations": None, "sha256": None,
           "verdict": None}
    section = None
    for line in text.split("\n"):
        if line.startswith("sha256: "):
            out["sha256"] = line.split(": ", 1)[1].strip()
        elif line.startswith("core-relocations: "):
            out["core_relocations"] = line.split(": ", 1)[1].strip()
        elif line == "maps:":
            section = "maps"
        elif line == "programs:":
            section = "programs"
        elif line.startswith("gate: PASS "):
            out["verdict"] = "PASS"
            for token in line.split()[2:]:
                if token.startswith("family="):
                    out["family"] = token.split("=", 1)[1]
        elif line.startswith("gate: REFUSE "):
            out["verdict"] = "REFUSE"
            out["reason"] = line.split("gate: REFUSE ", 1)[1]
        elif line.startswith("  ") and section == "maps":
            parts = line.split()
            row = {}
            for token in parts[1:]:
                key, _, value = token.partition("=")
                row[key] = int(value)
            out["maps"][parts[0]] = row
        elif line.startswith("  ") and section == "programs":
            parts = line.split()
            out["programs"][parts[0]] = {
                "kind": parts[1],
                "sleepable": len(parts) > 2,
            }
    return out
