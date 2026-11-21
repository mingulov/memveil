#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assemble the MemVeil Rust owner bundle from pinned inputs.

Builds the distributable binary copy (``$ORIGIN``-relative
RUNPATH), ships the single-library Rust closure plus the Aya
BPF objects as inspection copies, and records every payload
hash in MANIFEST.json. The tree must be clean (the git
revision stays descriptive next to the input hashes) or the
run refuses; a git-free source export records revision
"export" instead. Every staged file is verified against the
exact source bytes it was copied from before the manifest is
written, and the tarball hashes before publication and again
after the rename, so bytes changed after verification fail
the package.

Layout of ``dist/memveil-<version>/``::

    bin/memveil            relocatable binary (RUNPATH $ORIGIN/../lib/memveil)
    lib/memveil/*.so*              Rust closure (the pinned Debian libgcc_s
                           only; the Aya loader links statically, no
                           bridge ships)
    bpf/*.bpf.o            Aya BPF objects (attempt, lifecycle,
                           copy) as inspection copies of the
                           bytes embedded in the binary
    profiles/              manifest plus shipped semantic profiles
    docs/                  the full manuals tree (every manual
                           quickstart/support reference ships)
    examples/real-capture/ sanitized real capture (worked example)
    examples/lifecycle-copy/ recorded three-channel capture
                           (worked example with oracle logs)
    LICENSE, LICENSES/   MemVeil's own license texts
    licenses/              GCC runtime texts for the shipped lib
    licenses/crates/       per-crate notice files staged from
                           the locked crates.io sources
    THIRD-PARTY-NOTICES.md generated attribution (Cargo closure
                           plus the shipped lib; no vendored deps)
    MANIFEST.json          file hashes, versions, source revisions,
                           and the build receipt bound at seal time

Usage: scripts/package-tarball.py [--out DIR] [--tag NAME]
    [--root DIR] [--binary PATH] [--bpf-dir DIR] [--build]
    [--candidate]
  --out DIR    stage directory (default: dist/)
  --tag NAME   bundle directory name (default: memveil-<version>)
  --root DIR   input tree (default: auto-detected checkout root)
  --binary PATH  release binary (default: <root>/target/
               release/memveil, honoring $CARGO_TARGET_DIR;
               forbidden with --build, which consumes
               cargo's own reported artifact paths)
  --bpf-dir DIR  build-script OUT_DIR holding memveil-ebpf-*
               (default: auto-detected under the target dir)
  --build      run `cargo build --release --locked --offline` first
               in a fresh per-build target dir (explicit
               --target-dir plus a pinned build.build-dir,
               scrubbed redirect environment, JSON artifact
               paths, dir removed after packaging), so only
               this invocation's bytes can be packaged
  --candidate  sealable bundle: requires --build from the root
               and forbids --binary/--bpf-dir; only this mode
               records a build receipt the seal accepts

Requires a release binary (use --build or build it first),
patchelf, strip, and readelf. Fails closed when the link
closure names anything outside the shipped lib/ set and the
system allowlist, when a BPF inspection input differs
from the binary's dumped embedded digest, carries another
channel's marker, or stages bytes that differ from the
dumped digest, and when the staged executable differs from
the validated --binary bytes or dumps a different embedded
manifest than validated. Every
cargo invocation strips RUSTUP_TOOLCHAIN so the repository pin
wins.
"""

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
RUN_ROOT_DIR = os.path.dirname(HERE)

# NEEDED entries the bundle binary and closure lib may name that
# must resolve to the host C library set. Anything else must
# ship in lib/ or the package refuses to assemble. The set is
# deliberately libc-only: libelf/libz/libzstd never appear in
# the Rust closure, so their appearance fails closed instead
# of silently resolving to the host.
SYSTEM_ALLOW = {
    "libc.so.6",
    "libm.so.6",
    "libdl.so.2",
    "libpthread.so.0",
    "ld-linux-x86-64.so.2",
}

# NEEDED names outside SYSTEM_ALLOW that the closure walk may
# ship. Any other name fails the build instead of guessing.
# The single entry resolves to the pinned vendored provider
# below (verified at every build), never to the host toolchain:
# the host libgcc requires GLIBC_ABI_GNU2_TLS (glibc 2.40 floor),
# while the payload needs only ancient unwinder symbols.
CLOSURE_PROVIDERS = {
    "libgcc_s.so.1": "vendored-deb",
}

# Pinned libgcc provider: Debian trixie libgcc-s1 14.2.0-19
# (amd64), vendored as the exact archive .deb under
# packaging/libgcc/. The .deb sha256 is verified before
# anything is read from it and the member sha256 again after
# extraction; any mismatch refuses the package. Provenance,
# adoption proofs, and the update procedure live in
# packaging/libgcc/PROVENANCE.txt.
LIBGCC_DIR = os.path.join("packaging", "libgcc")
LIBGCC_DEB_NAME = "libgcc-s1_14.2.0-19_amd64.deb"
LIBGCC_DEB_SHA256 = \
    "3c71917b490d1a17aed43196a2787a256ecf060526cdb20216a74bedc061b150"
LIBGCC_SO_MEMBER = "usr/lib/x86_64-linux-gnu/libgcc_s.so.1"
LIBGCC_SO_SHA256 = \
    "30c61ab012a4241bed033725a09b61f5fdd3bb7df95ee852d0b096520524c7af"
LIBGCC_PROVIDER = "debian-stable-libgcc-s1"
LIBGCC_PROVIDER_VERSION = "14.2.0-19"
# Vendored GPL-3 text staged next to the Debian binary (Debian's
# common-licenses grant; same FSF text as the Fedora host copy
# modulo FSF URL modernization, pinned so every build host
# stages identical bytes).
LIBGCC_GPL3_NAME = "GPL-3.txt"
LIBGCC_GPL3_SHA256 = \
    "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"

# (OUT_DIR channel, shipped BPF file name).
CHANNELS = (
    ("attempt", "swiotlb_attempt.bpf.o"),
    ("lifecycle", "swiotlb_lifecycle.bpf.o"),
    ("copy", "swiotlb_copy.bpf.o"),
)

# Channel identity marker: each Aya channel object carries a
# `memveil_channel` section holding `memveil-channel:<name>\0`
# (the MEMVEIL_CHANNEL statics in crates/ebpf/src/bin/).
# The packager requires marker == expected channel per
# --bpf-dir path after the occurrence check, so a renamed
# (swapped) input refuses instead of staging under the wrong
# channel; the expectation is identity (no frozen tables).
BPF_MARKER_SECTION = "memveil_channel"
BPF_MARKER_PREFIX = b"memveil-channel:"

# Channels the `--embedded-manifest` probe must report, in
# dump order.
MANIFEST_CHANNELS = ("attempt", "lifecycle", "copy")

# Host license texts for the shipped libgcc, as (staged rel,
# candidate host paths): the first readable candidate wins.
# Debian ships no standalone GCC exception text, so the
# exception entry falls back to the vendored copy below (last
# candidate, used only when no host text exists). The GPL-3
# text is vendored instead (VENDORED_LICENSES): it pairs with
# the vendored Debian binary and stays identical on every
# build host.
GCC_LICENSES = (
    ("licenses/RUNTIME.LIBRARY.EXCEPTION", (
        "/usr/share/licenses/libgcc/COPYING.RUNTIME",
    )),
)

# Vendored license texts, as (staged rel, repo-root rel,
# sha256): pinned bytes staged on every host, verified before
# staging. The GPL-3 grant pairs with the vendored Debian
# libgcc above.
VENDORED_LICENSES = (
    ("licenses/GPL-3.0.txt",
     os.path.join(LIBGCC_DIR, LIBGCC_GPL3_NAME),
     LIBGCC_GPL3_SHA256),
)

# Vendored fallback for the exception entry, root-relative: the
# FSF's immutable Version 3.1 grant, byte-identical to the Fedora
# host text. The tarball suite pins that equality wherever the
# host text exists, so Fedora builds keep staging host bytes
# while Debian builds stage these identical bytes. Never edit:
# any byte change breaks the verbatim grant (and the pin).
VENDORED_EXCEPTION = os.path.join(
    "packaging", "RUNTIME.LIBRARY.EXCEPTION")

BIN_RUNPATH = "$ORIGIN/../lib/memveil"


def validate_tag(tag):
    """Bundle directory name: a single safe path segment."""
    if not tag or tag in (".", ".."):
        raise ValueError("bad bundle tag %r" % tag)
    if "/" in tag or "\\" in tag or "\x00" in tag:
        raise ValueError("bad bundle tag %r" % tag)
    if tag.startswith("-"):
        raise ValueError("bad bundle tag %r" % tag)
    return tag


def validate_lib_name(name, requirer):
    """NEEDED name: a bare file name, never a path escape."""
    if not name or name in (".", ".."):
        raise ValueError("bad NEEDED %r from %s" % (name, requirer))
    if "/" in name or "\\" in name or "\x00" in name:
        raise ValueError("bad NEEDED %r from %s" % (name, requirer))
    if os.path.basename(name) != name:
        raise ValueError("bad NEEDED %r from %s" % (name, requirer))
    return name


def contained(path, directory):
    """True when path stays inside directory after normalization."""
    base = os.path.realpath(directory)
    full = os.path.realpath(path)
    return full == base or full.startswith(base + os.sep)


def read_elf_section(path, section):
    """Raw bytes of `section` in the ELF file at path, or None.

    Minimal 64-bit little-endian section reader: validates the
    ELF magic, class, and data encoding, then walks the section
    headers through the section-name table. Truncation or
    inconsistency fails closed; a well-formed file without the
    section (or without section names) returns None.
    """
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        fail("cannot read %s: %s" % (path, exc))
    if len(data) < 64 or data[:4] != b"\x7fELF":
        fail("not an ELF file: %s" % path)
    if data[4] != 2 or data[5] != 1:
        fail("want 64-bit little-endian ELF: %s" % path)
    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
        "<HHH", data, 0x3A)
    if e_shentsize < 64 or e_shnum == 0:
        fail("no section headers in %s" % path)
    if e_shoff + e_shentsize * e_shnum > len(data):
        fail("section headers overrun %s" % path)
    if e_shstrndx == 0:
        return None
    if e_shstrndx >= e_shnum:
        fail("no section-name table in %s" % path)
    base = e_shoff + e_shstrndx * e_shentsize
    (str_off, str_size) = struct.unpack_from("<QQ", data, base + 24)
    if str_off + str_size > len(data):
        fail("section names overrun %s" % path)
    names = data[str_off:str_off + str_size]
    for index in range(e_shnum):
        base = e_shoff + index * e_shentsize
        (sh_name,) = struct.unpack_from("<I", data, base)
        if sh_name >= len(names):
            fail("section name overruns %s" % path)
        name = names[sh_name:].split(b"\0", 1)[0] \
            .decode("ascii", "replace")
        if name != section:
            continue
        (sh_offset, sh_size) = struct.unpack_from(
            "<QQ", data, base + 24)
        if sh_offset + sh_size > len(data):
            fail("section %s overruns %s" % (section, path))
        return data[sh_offset:sh_offset + sh_size]
    return None


def check_bpf_markers(bpf_inputs):
    """Refuse --bpf-dir inputs whose channel marker mismatches.

    `bpf_inputs` maps shipped names to (source path, digest) as
    built in main(); the expected marker comes from the CHANNELS
    table (marker == channel name per path). A missing section or
    mistitled bytes refuses naming the file, so a renamed input
    can never stage under the wrong channel.
    """
    expect = dict((shipped, channel)
                  for channel, shipped in CHANNELS)
    for shipped, (source, _digest) in sorted(bpf_inputs.items()):
        channel = expect[shipped]
        want = BPF_MARKER_PREFIX + channel.encode("ascii") + b"\0"
        found = read_elf_section(source, BPF_MARKER_SECTION)
        if found is None:
            fail("BPF input %s lacks the %s section: --bpf-dir "
                 "is stale or mixed" % (source, BPF_MARKER_SECTION))
        if found != want:
            fail("BPF input %s carries channel %r, want %r: "
                 "--bpf-dir inputs are swapped or mixed"
                 % (source, found, want))


def parse_embedded_manifest(text, binary):
    """{channel: sha256} from `--embedded-manifest` output.

    Strict shape: exactly one `channel digest` line per known
    channel, in dump order, with a 64-character lowercase hex
    digest each. Anything else fails closed: a truncated or
    hand-edited dump must never bind inspection copies.
    """
    rows = text.splitlines()
    if len(rows) != len(MANIFEST_CHANNELS):
        fail("binary %s dumps %d manifest rows, want %d"
             % (binary, len(rows), len(MANIFEST_CHANNELS)))
    found = {}
    for row, channel in zip(rows, MANIFEST_CHANNELS):
        fields = row.split(" ")
        if len(fields) != 2 or fields[0] != channel:
            fail("binary %s dumps a bad manifest row %r, want "
                 "'%s <sha256>'" % (binary, row, channel))
        digest = fields[1]
        if len(digest) != 64 or any(
                byte not in "0123456789abcdef" for byte in digest):
            fail("binary %s dumps a bad %s digest %r: want 64 "
                 "lowercase hex" % (binary, channel, digest))
        found[channel] = digest
    return found


def embedded_manifest(binary):
    """{channel: sha256} the binary reports for its embedded objects.

    Runs the hidden `--embedded-manifest` probe, which prints
    the build-baked digest of the exact bytes `embedded_object`
    serves per channel. A binary that predates the flag (or
    otherwise fails the probe) refuses with a rebuild pointer
    instead of falling back to an occurrence search, which
    cannot tell planted bytes apart from the runtime bytes.
    """
    try:
        proc = subprocess.run(
            [binary, "--embedded-manifest"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=60,
        )
    except OSError as exc:
        fail("cannot run %s --embedded-manifest: %s" % (binary, exc))
    except subprocess.TimeoutExpired:
        fail("binary %s hangs on --embedded-manifest" % binary)
    if proc.returncode != 0:
        hint = ""
        for line in proc.stderr.splitlines():
            if line.strip():
                hint = ": %s" % line.strip()[:160]
                break
        fail("binary %s refuses --embedded-manifest (exit %d%s): "
             "it predates the embedded-digest binding; rebuild the "
             "release binary from this source before packaging"
             % (binary, proc.returncode, hint))
    return parse_embedded_manifest(proc.stdout, binary)


def manifest_source(root, source):
    """Stable manifest display for a license source path.

    Sources inside the input tree record repo-relative (stable
    across clones); host paths record verbatim.
    """
    base = os.path.realpath(root)
    if source == base or source.startswith(base + os.sep):
        return os.path.relpath(source, base)
    return source


def tar_member_mode(full, is_dir):
    """Portable tar member mode: dirs 0755, files 0644, +x kept."""
    if is_dir:
        return 0o755
    if os.stat(full).st_mode & 0o111:
        return 0o755
    return 0o644


def fail(message):
    print("package-tarball: %s" % message, file=sys.stderr)
    sys.exit(1)


def candidate_built_from_source(candidate, build, binary_opt,
                                bpf_opt):
    """Whether this run records a sealable build receipt.

    Only candidate mode (--candidate with --build from the
    input root and no --binary/--bpf-dir override) builds the
    engine and BPF objects from the sealed tree in-flow, so
    only it records built_from_source. Every other mode
    (development --binary runs included) records a receipt
    the seal refuses. Raises SystemExit on a candidate run
    that tries to mix --build with prebuilt overrides, or to
    skip the build.
    """
    if not candidate:
        return False
    if not build:
        fail("candidate mode requires --build from the root")
    if binary_opt is not None or bpf_opt is not None:
        fail("candidate mode forbids --binary and --bpf-dir "
             "overrides")
    return True


def run(argv, **kwargs):
    proc = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, **kwargs,
    )
    return proc


def needed(path):
    proc = run(["readelf", "-d", path])
    if proc.returncode != 0:
        fail("readelf failed on %s:\n%s" % (path, proc.stderr))
    names = []
    for line in proc.stdout.splitlines():
        if "(NEEDED)" in line and "[" in line:
            names.append(line.split("[")[1].split("]")[0])
    return names


def runpath_abspaths(dyn):
    """Non-$ORIGIN RUNPATH/RPATH entries in a dynamic section.

    Parses the bracketed `Library runpath:`/`Library rpath:`
    values and returns every colon-separated entry that is
    not $ORIGIN-relative: any absolute build-host path, not
    just known prefixes. [] means fully relocatable.
    """
    found = []
    for line in dyn.splitlines():
        match = re.search(r"Library (?:runpath|rpath): \[(.*)\]",
                          line)
        if not match:
            continue
        for entry in match.group(1).split(":"):
            if entry and not entry.startswith("$ORIGIN"):
                found.append(entry)
    return found


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _HashingWriter:
    """Fileobj wrapper hashing every byte written through it."""

    def __init__(self, raw):
        self._raw = raw
        self._digest = hashlib.sha256()

    def write(self, data):
        self._digest.update(data)
        return self._raw.write(data)

    def flush(self):
        self._raw.flush()

    def hexdigest(self):
        return self._digest.hexdigest()


def run_cargo(argv, cwd):
    """Run cargo with RUSTUP_TOOLCHAIN stripped (repo pin wins)."""
    env = dict(os.environ)
    env.pop("RUSTUP_TOOLCHAIN", None)
    proc = subprocess.run(
        ["cargo"] + argv, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, cwd=cwd, env=env,
    )
    return proc


def cargo_tool_versions(rust_dir):
    """(cargo version, rustc version) under the repository pin."""
    cargo = run_cargo(["--version"], rust_dir)
    if cargo.returncode != 0 or not cargo.stdout.split():
        fail("cargo --version failed")
    # rustc honors the same ambient override, so strip it too.
    env = dict(os.environ)
    env.pop("RUSTUP_TOOLCHAIN", None)
    rustc_proc = subprocess.run(
        ["rustc", "--version"], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env,
    )
    if rustc_proc.returncode != 0 or not rustc_proc.stdout.split():
        fail("rustc --version failed")
    return (cargo.stdout.split()[1], rustc_proc.stdout.split()[1])


def bpf_linker_version(rust_dir):
    """bpf-linker version under the repository pin.

    Mirrors the seal's toolchain probe: RUSTUP_TOOLCHAIN stripped
    so the checkout pin wins, parsed as the second `--version`
    token with a leading `v` dropped, refused unless it looks like
    a dotted version. Recorded in the build receipt, never guessed.
    """
    env = dict(os.environ)
    env.pop("RUSTUP_TOOLCHAIN", None)
    try:
        proc = subprocess.run(
            ["bpf-linker", "--version"], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, cwd=rust_dir, env=env,
        )
    except OSError as exc:
        fail("cannot probe bpf-linker: %s" % exc)
    if proc.returncode != 0 or len(proc.stdout.split()) < 2:
        fail("bpf-linker --version failed")
    token = proc.stdout.split()[1]
    if token.startswith("v"):
        token = token[1:]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+"
                        r"(?:[-+][0-9A-Za-z.+-]+)?", token) \
            or len(token) > 64:
        fail("bpf-linker reports a bad version %r" % token)
    return token


def git_tree_inventory(root, commit):
    """(entries, digest) for the git tree at commit.

    Same construction as the candidate seal's source inventory:
    entries come from `git ls-tree` plus batched blob reads, so the
    digest is purely commit-derived and immune to worktree strays.
    Files carry path/kind/mode/size/sha256, symlinks path/kind/mode/
    target, directories path/kind/mode, with raw git modes. The
    digest hashes one sorted-keys JSON line per path-sorted entry.
    Anything unexpected fails the package instead of recording a
    digest the seal cannot reproduce.
    """
    if not re.fullmatch(r"[0-9a-f]{40}", commit or ""):
        fail("build receipt needs a commit identity, want 40 hex")
    env = dict(os.environ)
    for key in [key for key in env if key.startswith("GIT_")]:
        env.pop(key)
    try:
        proc = subprocess.run(
            ["git", "-C", root, "ls-tree", "-r", "-t", "-z", commit],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )
    except OSError as exc:
        fail("cannot read the source tree: %s" % exc)
    if proc.returncode != 0:
        fail("unknown source commit %s" % commit)
    blobs, entries = [], []
    for record in proc.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw = record.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split()
            path = raw.decode("utf-8")
        except (ValueError, UnicodeError):
            fail("invalid git tree entry")
        if not path or "\\" in path \
                or any(part in ("", ".", "..")
                       for part in path.split("/")) \
                or any(ord(char) < 33 or ord(char) > 126
                       for char in path):
            fail("invalid source tree path")
        if kind == "tree":
            if mode != "040000":
                fail("unsupported tree mode")
            entries.append({"path": path, "kind": "dir",
                            "mode": mode})
        elif kind == "blob" and mode in ("100644", "100755"):
            entries.append({"path": path, "kind": "file",
                            "mode": mode, "oid": oid})
            blobs.append(oid)
        elif kind == "blob" and mode == "120000":
            entries.append({"path": path, "kind": "symlink",
                            "mode": mode, "oid": oid})
            blobs.append(oid)
        else:
            fail("unsupported source archive entry: " + path)
    content = _git_tree_blobs(root, blobs, env)
    resolved = []
    for entry in entries:
        oid = entry.pop("oid", None)
        if entry["kind"] == "dir":
            resolved.append(entry)
        elif entry["kind"] == "symlink":
            try:
                target = content[oid].decode("utf-8")
            except UnicodeError:
                fail("invalid symlink target")
            if not target:
                fail("empty symlink target")
            entry["target"] = target
            resolved.append(entry)
        else:
            entry["size"] = len(content[oid])
            entry["sha256"] = hashlib.sha256(content[oid]).hexdigest()
            resolved.append(entry)
    resolved.sort(key=lambda entry: entry["path"])
    found = hashlib.sha256()
    for entry in resolved:
        found.update(json.dumps(
            entry, sort_keys=True,
            separators=(",", ":")).encode("utf-8"))
        found.update(b"\n")
    return resolved, found.hexdigest()


def _git_tree_blobs(root, oids, env):
    """{oid: bytes} for every oid via one `git cat-file --batch`."""
    try:
        proc = subprocess.run(
            ["git", "-C", root, "cat-file", "--batch"],
            input=("".join(oid + "\n" for oid in oids)).encode(
                "ascii"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )
    except OSError as exc:
        fail("cannot read source blobs: %s" % exc)
    if proc.returncode != 0:
        fail("cannot read source blobs")
    content, rest = {}, proc.stdout
    for oid in oids:
        try:
            header, rest = rest.split(b"\n", 1)
            found, kind, size = header.decode("ascii").split()
            size = int(size)
            data = rest[:size]
            rest = rest[size:]
            if rest[:1] != b"\n":
                fail("cannot read source blobs")
            rest = rest[1:]
        except (ValueError, IndexError):
            fail("cannot read source blobs")
        if found != oid or kind != "blob" or len(data) != size:
            fail("cannot read source blobs")
        content[oid] = data
    return content


def root_markers_present(root):
    return (
        os.path.isfile(os.path.join(root, "profiles", "manifest.txt"))
        and os.path.isfile(os.path.join(root, "Cargo.lock"))
        and os.path.isfile(os.path.join(root, "LICENSE"))
    )


def resolve_root(explicit):
    """Input tree: explicit --root or the auto-detected checkout."""
    if explicit is not None:
        root = os.path.abspath(explicit)
        if not root_markers_present(root):
            fail("input root lacks profiles/, Cargo.lock, "
                 "LICENSE: %s" % explicit)
        return root
    if root_markers_present(RUN_ROOT_DIR):
        return os.path.abspath(RUN_ROOT_DIR)
    fail("cannot detect the input root from %s" % RUN_ROOT_DIR)


def resolve_target_dir(root):
    """Development lookup dir, honoring the ambient override.

    In-flow builds never use this: they build in a fresh
    per-build dir that beats every redirect mechanism.
    """
    override = os.environ.get("CARGO_TARGET_DIR")
    if override:
        return os.path.abspath(override)
    return os.path.join(root, "target")


# Environment redirects that steer cargo outputs away from the
# source root. Verified on cargo 1.100.0 (`cargo build --help`
# plus share/doc/rust/html/cargo/reference/config.html, and
# live precedence probes): the --target-dir CLI flag beats
# CARGO_TARGET_DIR/CARGO_BUILD_TARGET_DIR, which beat the
# build.target-dir config file; intermediates follow
# build.build-dir (CARGO_BUILD_BUILD_DIR or config) unless a
# CLI --config override pins them; CARGO_BUILD_TARGET selects
# a target-triple output subdir. In-flow builds pin the CLI
# side and scrub all four, so only this invocation's bytes
# can be packaged.
BUILD_REDIRECT_ENV = (
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_TARGET_DIR",
    "CARGO_BUILD_BUILD_DIR",
    "CARGO_BUILD_TARGET",
)


def fresh_target_dir():
    """Fresh per-build cargo target dir, immune to redirects.

    A new mkdtemp dir per in-flow build: no reusable dir
    means no cached-artifact staleness versus the probed
    linker, by construction. The caller removes it after
    packaging via drop_target_dir.
    """
    try:
        return tempfile.mkdtemp(prefix="memveil-cargo-target-")
    except OSError as exc:
        fail("cannot create a fresh target dir: %s" % exc)


def drop_target_dir(target_dir):
    """Remove a fresh target dir; never fail the packaging."""
    if target_dir is None:
        return
    try:
        if os.path.islink(target_dir):
            os.unlink(target_dir)
        else:
            shutil.rmtree(target_dir, ignore_errors=True)
    except OSError:
        pass


def select_built_binary(stdout, bin_name, target_dir):
    """Cargo's own release binary path from JSON build output.

    Requires exactly one built executable for the named bin
    target, an existing regular file under the pinned target
    dir. Anything else (no artifact, ambiguity, a path
    outside the pin) fails closed.
    """
    target_dir = os.path.abspath(target_dir)
    found = []
    for line in stdout.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if not isinstance(message, dict) \
                or message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target") or {}
        if target.get("name") != bin_name \
                or "bin" not in (target.get("kind") or []):
            continue
        executable = message.get("executable")
        if not executable or not isinstance(executable, str):
            continue
        found.append(executable)
    if len(set(found)) != 1:
        fail("cargo reported %d %s binaries, want exactly one"
             % (len(set(found)), bin_name))
    binary = os.path.abspath(found[0])
    if os.path.commonpath([target_dir, binary]) != target_dir:
        fail("cargo reported a binary outside the pinned "
             "target dir: %s" % found[0])
    if not os.path.isfile(binary) or os.path.islink(binary):
        fail("cargo-reported binary is not a regular file: %s"
             % found[0])
    return binary


def config_file_rustflags(path):
    """build.rustflags from one Cargo config file, else None.

    Returns the raw string or array: merging across files
    needs the type, since a nearer string replaces while
    arrays join. Fails closed on anything this reader cannot
    reproduce exactly: an include list, target-specific
    rustflags (those shadow build.rustflags), or a mistyped
    value.
    """
    try:
        with open(path, "rb") as handle:
            doc = tomllib.load(handle)
    except OSError as exc:
        fail("cannot read cargo config %s: %s" % (path, exc))
    except tomllib.TOMLDecodeError as exc:
        fail("cannot parse cargo config %s: %s" % (path, exc))
    if "include" in doc:
        fail("cargo config %s uses include: pass its flags "
             "through RUSTFLAGS instead" % path)
    target = doc.get("target")
    if target is not None:
        if not isinstance(target, dict):
            fail("cargo config %s has a non-table target"
                 % path)
        for table in target.values():
            if isinstance(table, dict) and "rustflags" in table:
                fail("cargo config %s sets target rustflags: "
                     "pass its flags through RUSTFLAGS instead"
                     % path)
    build = doc.get("build")
    if build is None:
        return None
    if not isinstance(build, dict):
        fail("cargo config %s has a non-table build" % path)
    if "rustflags" not in build:
        return None
    value = build["rustflags"]
    if isinstance(value, str):
        return value
    if isinstance(value, list) \
            and all(isinstance(item, str) for item in value):
        return list(value)
    fail("cargo config %s has a non-string build.rustflags"
         % path)


def config_layer_rustflags(build_dir, env):
    """Config-layer flags for a build with no channel set.

    Only consulted when neither CARGO_ENCODED_RUSTFLAGS nor
    RUSTFLAGS is set: Cargo checks the encoded spelling,
    then RUSTFLAGS, then the config layer, and a set-but-
    empty channel still shadows everything below it. Merges
    the home config first, then each ancestor config down
    to the build directory: a nearer string replaces,
    arrays join, and a string meeting an array across files
    refuses like Cargo does. The dotted environment
    spelling appends after the merged file flags, and an
    empty one leaves them standing. A home directory that
    overlaps an ancestor loads once at the ancestor; at one
    directory the extensionless config wins over config.toml
    wholesale. Fails closed rather than shadowing flags it
    cannot see.
    """
    for name in env:
        if name.startswith("CARGO_TARGET_") \
                and name.endswith("_RUSTFLAGS") \
                and len(name) > len("CARGO_TARGET__RUSTFLAGS"):
            fail("%s sets target rustflags: pass its flags "
                 "through RUSTFLAGS instead" % name)
    home = env.get("CARGO_HOME")
    if home is None:
        parent = env.get("HOME", "")
        home = os.path.join(parent, ".cargo") if parent else ""
    build_dir = os.path.abspath(build_dir)
    if home and not os.path.isabs(home):
        home = os.path.join(build_dir, home)
    chain = [build_dir]
    while True:
        parent = os.path.dirname(chain[-1])
        if parent == chain[-1]:
            break
        chain.append(parent)
    flag_dirs = [os.path.join(ancestor, ".cargo")
                 for ancestor in reversed(chain)]
    if home and os.path.realpath(home) not in set(
            os.path.realpath(flag) for flag in flag_dirs):
        flag_dirs.insert(0, home)
    merged = None
    for flag_dir in flag_dirs:
        plain = os.path.join(flag_dir, "config")
        dotted = os.path.join(flag_dir, "config.toml")
        if os.path.exists(plain):
            path = plain
        elif os.path.exists(dotted):
            path = dotted
        else:
            continue
        value = config_file_rustflags(path)
        if value is None:
            continue
        if merged is None:
            merged = value
        elif isinstance(merged, str) and isinstance(value, str):
            merged = value
        elif isinstance(merged, list) and isinstance(value, list):
            merged = merged + value
        else:
            fail("cargo config %s mixes string and array "
                 "build.rustflags across files: pass its flags "
                 "through RUSTFLAGS instead" % path)
    dotted = env.get("CARGO_BUILD_RUSTFLAGS")
    if dotted is not None:
        extra = dotted.split()
        if extra:
            if merged is None:
                merged = extra
            elif isinstance(merged, str):
                merged = merged.split() + extra
            else:
                merged = merged + extra
    if merged is None:
        return []
    if isinstance(merged, str):
        return merged.split()
    return merged


def split_rustflags(text):
    """Split a flag string the way Cargo splits RUSTFLAGS.

    Words break on the space character alone; every other
    byte stays literal, so quotes and backslashes reach the
    compiler untouched. Empty words never form: leading,
    trailing, and repeated spaces vanish.
    """
    return [word for word in text.split(" ") if word]


def remap_build_paths(env, rust_dir):
    """Append path remaps so shipped bytes name no build machine.

    Home directory first, then the checkout root last, so
    checkout paths land under /build-root (the BPF build
    script applies the same pair to the objects it compiles).
    Starts from the flag set Cargo itself would use: the
    encoded spelling when set, else RUSTFLAGS when set (a
    set-but-empty channel still shadows the rest), else the
    config layer carried forward so this export shadows
    nothing. The remap pair lands exactly once at the end
    and leaves through the encoded channel alone. A missing
    or empty HOME contributes no remap.
    """
    if "CARGO_ENCODED_RUSTFLAGS" in env:
        encoded = env["CARGO_ENCODED_RUSTFLAGS"]
        flags = encoded.split("\x1f") if encoded else []
    elif "RUSTFLAGS" in env:
        flags = split_rustflags(env["RUSTFLAGS"])
    else:
        flags = config_layer_rustflags(rust_dir, env)
    home = env.get("HOME", "")
    if home:
        flags.append("--remap-path-prefix=%s=/build-prefix" % home)
    flags.append("--remap-path-prefix=%s=/build-root"
                 % os.path.abspath(rust_dir))
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
    env.pop("RUSTFLAGS", None)


def build_release_binary(rust_dir, target_dir,
                         bin_name="memveil"):
    """Build release in-flow, return cargo's own binary path.

    The caller passes a fresh per-build target dir; the
    build pins --target-dir plus a CLI build.build-dir
    override (both beat environment and config files),
    scrubs every redirect variable, remaps build-machine
    paths out of the shipped bytes, and consumes only the
    JSON artifact paths, so exactly this invocation's bytes
    are packaged. Fails closed on any build error or path
    surprise.
    """
    target_dir = os.path.abspath(target_dir)
    if any(char in target_dir for char in "\"\\\n"):
        fail("refusing a target dir that needs config "
             "escaping: %s" % target_dir)
    env = dict(os.environ)
    env.pop("RUSTUP_TOOLCHAIN", None)
    for name in BUILD_REDIRECT_ENV:
        env.pop(name, None)
    remap_build_paths(env, rust_dir)
    try:
        proc = subprocess.run(
            ["cargo",
             "--config",
             'build.build-dir="%s"' % target_dir,
             "build", "--release", "--locked", "--offline",
             "--target-dir", target_dir,
             "--message-format=json"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=rust_dir, env=env)
    except OSError as exc:
        fail("cannot run cargo build: %s" % exc)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        fail("cargo build --release failed")
    print("package-tarball: in-flow cargo build pinned to %s "
          "(redirect environment scrubbed)" % target_dir)
    return select_built_binary(proc.stdout, bin_name,
                               target_dir)


def resolve_binary(root, explicit, build, fresh_target=None,
                   bin_name="memveil"):
    """Release binary: the in-flow build's own path, else lookup."""
    rust_dir = root
    if build:
        if explicit is not None:
            fail("--build forbids --binary: the fresh in-flow "
                 "binary is packaged")
        if fresh_target is None:
            fail("in-flow build needs a fresh target dir")
        return build_release_binary(rust_dir, fresh_target,
                                    bin_name=bin_name)
    if explicit is not None:
        binary = os.path.abspath(explicit)
    else:
        binary = os.path.join(
            resolve_target_dir(root), "release", "memveil")
    if not os.path.isfile(binary):
        fail("release binary missing: %s (run cargo build "
             "--release in %s, or pass --build)" % (binary, rust_dir))
    return binary


def bpf_candidates(release_dir):
    """Complete OUT_DIR sets holding all three channel artifacts.

    Rooted at the release dir cargo actually used (derived
    from the packaged binary's own path under --build), so a
    target-triple output subdir cannot desynchronize the
    search from the build.
    """
    base = os.path.join(release_dir, "build", "memveil")
    found = []
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return []
    for name in names:
        out = os.path.join(base, name, "out")
        if all(os.path.isfile(os.path.join(
                out, "memveil-ebpf-" + channel))
               for channel, _ in CHANNELS):
            found.append(out)
    return found


def resolve_bpf_dir(release_dir, explicit):
    """OUT_DIR for the BPF inspection copies.

    Several build-script output dirs can hold copies; every
    complete set must agree byte-for-byte, and the newest
    wins. Divergent sets fail closed.
    """
    if explicit is not None:
        out = os.path.abspath(explicit)
        missing = [channel for channel, _ in CHANNELS
                   if not os.path.isfile(os.path.join(
                       out, "memveil-ebpf-" + channel))]
        if missing:
            fail("--bpf-dir lacks channel artifacts: %s"
                 % ", ".join(missing))
        return out
    sets = bpf_candidates(release_dir)
    if not sets:
        fail("no BPF artifacts under %s (run cargo build "
             "--release, or pass --bpf-dir)" % release_dir)
    first = {channel: sha256_file(os.path.join(
        sets[0], "memveil-ebpf-" + channel))
        for channel, _ in CHANNELS}
    for other in sets[1:]:
        for channel, _ in CHANNELS:
            digest = sha256_file(os.path.join(
                other, "memveil-ebpf-" + channel))
            if digest != first[channel]:
                fail("divergent BPF sets: %s vs %s"
                     % (sets[0], other))
    return max(sets, key=lambda out: os.path.getmtime(
        os.path.join(out, "memveil-ebpf-attempt")))


def closure_provider(name, vendored):
    """Provider file for a shippable NEEDED name.

    `vendored` maps shippable names to their verified provider
    files (resolved once per run by `vendored_libgcc`). Unknown
    names return None so the caller fails instead of guessing.
    """
    if name not in CLOSURE_PROVIDERS:
        return None
    if CLOSURE_PROVIDERS[name] != "vendored-deb":
        fail("no resolver for shippable NEEDED %s" % name)
    path = vendored.get(name)
    if path is None or not os.path.isfile(path):
        fail("vendored provider missing for %s" % name)
    return path


def read_ar_member(archive_path, want_prefix):
    """Raw bytes of the first ar member starting with want_prefix.

    Minimal System V ar reader for the .deb container: global
    magic, 60-byte headers, even-byte padding, short names only
    (long-name references and the symbol/string tables never
    carry data). Anything malformed fails closed.
    """
    try:
        with open(archive_path, "rb") as handle:
            archive = handle.read()
    except OSError as exc:
        fail("cannot read %s: %s" % (archive_path, exc))
    if archive[:8] != b"!<arch>\n":
        fail("not an ar archive: %s" % archive_path)
    pos = 8
    while pos + 60 <= len(archive):
        header = archive[pos:pos + 60]
        name = header[:16].decode("ascii", "replace").rstrip().rstrip("/")
        try:
            size = int(header[48:58].decode("ascii").strip() or "0")
        except ValueError:
            fail("bad ar member size in %s" % archive_path)
        start = pos + 60
        end = start + size
        if size < 0 or end > len(archive):
            fail("ar member overruns %s" % archive_path)
        if name.startswith(want_prefix):
            return archive[start:end]
        pos = end + (end % 2)
    fail("no %s* member in %s" % (want_prefix, archive_path))


def extract_deb_file(deb_path, member):
    """Exact bytes of `member` from a .deb data archive.

    Verifies nothing itself (callers pin the .deb and the member
    hashes); refuses unknown data compressions, duplicate
    members, links, and anything but a regular file.
    """
    data = read_ar_member(deb_path, "data.tar")
    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        fail("cannot open data archive in %s: %s" % (deb_path, exc))
    with tar:
        hits = []
        for info in tar.getmembers():
            name = info.name
            if name.startswith("./"):
                name = name[2:]
            if name == member:
                hits.append(info)
        if len(hits) != 1:
            fail("want exactly one %s in %s, found %d"
                 % (member, deb_path, len(hits)))
        info = hits[0]
        if not info.isfile() or info.issym() or info.islnk():
            fail("not a regular file in %s: %s" % (deb_path, member))
        try:
            extracted = tar.extractfile(info)
            raw = extracted.read() if extracted is not None else None
        except (tarfile.TarError, OSError) as exc:
            fail("cannot extract %s from %s: %s"
                 % (member, deb_path, exc))
    if raw is None:
        fail("cannot extract %s from %s" % (member, deb_path))
    return raw


def vendored_libgcc(root, scratch):
    """Verified provider libgcc path, extracted under scratch.

    Verifies the vendored .deb sha256, extracts the single
    member, verifies the member sha256, and writes it under
    scratch (re-read after the write). Every mismatch refuses
    the package.
    """
    deb = os.path.join(root, LIBGCC_DIR, LIBGCC_DEB_NAME)
    if not os.path.isfile(deb) or os.path.islink(deb):
        fail("vendored libgcc .deb missing: %s"
             % os.path.join(LIBGCC_DIR, LIBGCC_DEB_NAME))
    if sha256_file(deb) != LIBGCC_DEB_SHA256:
        fail("vendored libgcc .deb differs from its pin: %s" % deb)
    raw = extract_deb_file(deb, LIBGCC_SO_MEMBER)
    if hashlib.sha256(raw).hexdigest() != LIBGCC_SO_SHA256:
        fail("vendored libgcc member differs from its pin: %s"
             % LIBGCC_SO_MEMBER)
    dest = os.path.join(scratch, "libgcc_s.so.1")
    if not contained(dest, scratch):
        fail("vendored libgcc staging escapes: %s" % dest)
    try:
        with open(dest, "wb") as handle:
            handle.write(raw)
    except OSError as exc:
        fail("vendored libgcc staging failed: %s" % exc)
    if sha256_file(dest) != LIBGCC_SO_SHA256:
        fail("vendored libgcc mis-staged under %s" % scratch)
    print("package-tarball: vendored libgcc %s verified (%s)"
          % (LIBGCC_PROVIDER_VERSION, LIBGCC_PROVIDER))
    return dest


def dynamic_symbol_versions(path):
    """(undefined, defined) versioned-symbol sets from readelf.

    Undefined entries are (name, version) pairs the file imports;
    defined entries are (name, version) pairs it exports. Both
    come from `readelf --dyn-syms -W`; any readelf failure or
    unparsable line fails closed.
    """
    proc = run(["readelf", "--dyn-syms", "-W", path])
    if proc.returncode != 0:
        fail("readelf --dyn-syms failed on %s:\n%s"
             % (path, proc.stderr))
    undefined = set()
    defined = set()
    for line in proc.stdout.splitlines():
        match = re.match(
            r"^\s*\d+:\s+[0-9a-f]+\s+\d+\s+\S+\s+\S+\s+\S+\s+"
            r"(\S+)\s+(\S+?)(?:\s+\(\d+\))?\s*$", line)
        if match is None:
            continue
        ndx, name = match.group(1), match.group(2)
        if "@@" in name:
            base, version = name.split("@@", 1)
            if ndx != "UND":
                defined.add((base, version))
        elif "@" in name:
            base, version = name.split("@", 1)
            if ndx == "UND" and version:
                undefined.add((base, version))
    if not undefined and not defined:
        fail("no dynamic symbols parsed from %s" % path)
    return undefined, defined


def check_libgcc_unwinder(binary, lib):
    """Refuse when the binary needs libgcc symbols the lib lacks.

    The payload's libgcc needs are its undefined (name, GCC_*
    version) pairs: every one must be defined by the shipped lib
    at that same version. A toolchain bump that widens the need
    refuses here instead of shipping an unsatisfiable pair.
    """
    needs, _defined = dynamic_symbol_versions(binary)
    _needs, provides = dynamic_symbol_versions(lib)
    missing = sorted((name, version) for name, version in needs
                     if version.startswith("GCC_")
                     and (name, version) not in provides)
    if missing:
        fail("shipped libgcc lacks %d symbol(s) the binary needs: %s"
             % (len(missing),
                ", ".join("%s@%s" % pair for pair in missing)))
    print("package-tarball: shipped libgcc satisfies the "
          "binary's unwinder needs")


def cargo_tree_closure(rust_dir, manifest, package):
    """(name, version) normal-edge closure from `cargo tree`.

    Offline and locked: resolution reads the lockfile and the
    local cargo cache only, never the network.
    """
    proc = run_cargo(
        ["tree", "--offline", "--locked", "--manifest-path",
         manifest, "-p", package, "--edges", "normal",
         "--prefix", "none"],
        rust_dir)
    if proc.returncode != 0:
        fail("cargo tree failed for %s:\n%s" % (package, proc.stderr))
    closure = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        tokens = line.split()
        if len(tokens) < 2 or not tokens[1].startswith("v"):
            fail("cannot parse cargo tree line: %r" % line)
        closure.append((tokens[0], tokens[1][1:]))
    if not closure:
        fail("cargo tree listed nothing for %s" % package)
    return closure


def cargo_metadata_map(rust_dir, manifest):
    """({(name, version): (license, source, root)}, {workspace names}).

    Offline and locked, like the tree query above. `root` is
    the crate source directory holding the manifest: the
    locked bytes license texts stage from.
    """
    proc = run_cargo(
        ["metadata", "--offline", "--locked", "--format-version",
         "1", "--manifest-path", manifest],
        rust_dir)
    if proc.returncode != 0:
        fail("cargo metadata failed for %s:\n%s"
             % (manifest, proc.stderr))
    try:
        data = json.loads(proc.stdout)
    except ValueError as exc:
        fail("cargo metadata is not JSON: %s" % exc)
    members = set()
    for ident in data.get("workspace_members", []):
        if "#" in ident:
            # Opaque `path+file:///...#name@version` form.
            members.add(ident.split("#", 1)[1].split("@")[0])
        else:
            # Legacy `name version (source)` form.
            members.add(ident.split(" ")[0])
    packages = {}
    for entry in data.get("packages", []):
        try:
            root = os.path.dirname(entry["manifest_path"])
        except KeyError:
            fail("cargo metadata lacks manifest_path for %s %s"
                 % (entry.get("name"), entry.get("version")))
        packages[(entry.get("name"), entry.get("version"))] = (
            entry.get("license") or "NOASSERTION",
            entry.get("source") or "",
            root,
        )
    return packages, members


# First-party crates: path dependencies owned by this tree. Any
# other path-sourced closure member is a vendored dependency
# and fails the build until the notices handle it.
FIRST_PARTY_CRATES = frozenset((
    "memveil",
    "memveil-ebpf",
    "memveil-ebpf-common",
))


def third_party_crates(rust_dir, manifest, package):
    """(sorted third-party records, {(name, version): crate root}).

    Records carry (name, version, license, source); the roots
    map carries the locked source directory of each record
    for license-text staging. Membership is source-based,
    not workspace-based: the eBPF workspace consumes
    memveil-ebpf-common as a path dependency without
    listing it as a member, and it is still first-party.
    Unknown path-sourced members fail closed (vendored
    dependencies need explicit notices handling).
    """
    closure = cargo_tree_closure(rust_dir, manifest, package)
    packages, members = cargo_metadata_map(rust_dir, manifest)
    records = {}
    roots = {}
    for name, version in closure:
        key = (name, version)
        if key not in packages:
            fail("cargo metadata lacks %s %s" % (name, version))
        license_text, source, root = packages[key]
        if not source or name in members:
            if name not in FIRST_PARTY_CRATES:
                fail("vendored path dependency needs notices "
                     "handling: %s %s" % (name, version))
            continue
        if not source.startswith("registry+"):
            fail("non-registry dependency needs notices "
                 "handling: %s %s (%s)" % (name, version, source))
        records[key] = {"name": name, "version": version,
                        "license": license_text, "source": source}
        roots[key] = root
    ordered = [records[key] for key in sorted(records)]
    return ordered, roots


# Crate source files that count as copyright/permission texts:
# the leading token of the upper-cased basename must be one of
# these (so LICENSE, LICENSE-MIT, LICENSE-MIT.txt, COPYING,
# and UNLICENSE all qualify; LICENSING-notes.md does not).
CRATE_TEXT_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE",
                       "COPYRIGHT", "UNLICENSE")

# Largest acceptable license text: the Apache-2.0 grant is ~11
# KiB, so anything past 256 KiB is not a notice file.
CRATE_TEXT_MAX_BYTES = 262144


def crate_text_files(root):
    """Sorted notice-file basenames in a locked crate directory."""
    try:
        names = sorted(os.listdir(root))
    except OSError as exc:
        fail("cannot list crate sources at %s: %s" % (root, exc))
    found = []
    for name in names:
        if not name.upper().startswith(CRATE_TEXT_PREFIXES):
            continue
        full = os.path.join(root, name)
        if os.path.islink(full):
            fail("crate notice is a symlink, refusing to follow: %s"
                 % full)
        if not os.path.isfile(full):
            continue
        found.append(name)
    return found


def apache_alternative(expr):
    """True when the SPDX expression offers Apache-2.0 as an option.

    Dual `A OR B` / `A/B` grants and a bare `Apache-2.0` qualify;
    `WITH`-exception grants do not (the plain grant text alone
    cannot satisfy them), and neither does an AND-only chain.
    """
    tokens = re.split(r"[()\s/]+", expr or "")
    if "WITH" in tokens:
        return False
    if "Apache-2.0" not in tokens:
        return False
    return "OR" in tokens or "/" in (expr or "") \
        or (expr or "").strip() == "Apache-2.0"


def stage_crate_texts(staged, crates, ebpf_crates, roots):
    """Stage locked crate texts under licenses/crates/.

    Fills each record's "texts" with its staged bundle rels
    (plus "fallback": True when the shared grant below
    applied) and returns {staged rel: crate source path} for
    byte verification. Every record must yield at least one
    text: crates whose locked sources carry notice files
    stage those bytes; a text-less crate with Apache-2.0 as
    a grant alternative stages the shared standard text
    (the most common locked LICENSE-APACHE bytes, with no
    unique winner failing the package); anything else fails
    the package.
    """
    dest_root = os.path.join(staged, "licenses", "crates")
    try:
        os.makedirs(dest_root)
    except OSError as exc:
        fail("crate text staging setup failed: %s" % exc)
    # Shared-grant donor pool: one LICENSE-APACHE per linked
    # crate that carries it. Copies differ across projects
    # (appendix trimming, whitespace, filled-in copyright
    # lines), so the shared text is the most common bytes --
    # the verbatim standard grant the ecosystem repeats --
    # and anything without a unique winner fails closed for
    # a human to resolve. The tarball suite pins the
    # winning hash, so a lock bump that moves the majority
    # cannot silently swap the staged grant.
    donors = []
    for record in crates + ebpf_crates:
        root = roots[(record["name"], record["version"])]
        if "LICENSE-APACHE" in crate_text_files(root):
            with open(os.path.join(root, "LICENSE-APACHE"),
                      "rb") as handle:
                donors.append(handle.read())
    shared = None
    if donors:
        by_hash = {}
        for data in donors:
            by_hash.setdefault(hashlib.sha256(data).hexdigest(),
                               []).append(data)
        winners = sorted(by_hash.values(), key=len, reverse=True)
        if len(winners) > 1 and len(winners[0]) == len(winners[1]):
            fail("no unique majority LICENSE-APACHE among %d "
                 "locked copies; refusing to pick a shared grant "
                 "text" % len(donors))
        shared = winners[0][0]
        if b"Apache License" not in shared \
                or b"Version 2.0" not in shared:
            fail("shared LICENSE-APACHE is not the Apache-2.0 "
                 "grant text")
        print("package-tarball: shared grant text wins %d of %d "
              "locked LICENSE-APACHE copies"
              % (len(winners[0]), len(donors)))
    sources = {}
    for record in crates + ebpf_crates:
        name, version = record["name"], record["version"]
        for field in (name, version):
            if not re.fullmatch(r"[A-Za-z0-9_.\-]+", field or ""):
                fail("unsafe crate identity for staging: %r %r"
                     % (name, version))
        root = roots[(name, version)]
        leaf = "%s-%s" % (name, version)
        dest_dir = os.path.join(dest_root, leaf)
        if not contained(dest_dir, dest_root):
            fail("crate text staging escapes: %s" % leaf)
        # Both closures can hold the same crate (same locked
        # root, verified at the merge): re-staging writes the
        # identical bytes the byte check below re-verifies.
        try:
            os.makedirs(dest_dir, exist_ok=True)
        except OSError as exc:
            fail("crate text staging setup failed: %s" % exc)
        texts = []
        for text in crate_text_files(root):
            if "/" in text or text in (".", ".."):
                fail("unsafe crate text name: %s" % text)
            source = os.path.join(root, text)
            try:
                with open(source, "rb") as handle:
                    data = handle.read()
            except OSError as exc:
                fail("cannot read crate text %s: %s" % (source, exc))
            if not data:
                fail("empty crate text: %s" % source)
            if len(data) > CRATE_TEXT_MAX_BYTES:
                fail("oversize crate text: %s" % source)
            staged_rel = "licenses/crates/%s/%s" % (leaf, text)
            dest = os.path.join(dest_dir, text)
            if not contained(dest, dest_root):
                fail("crate text staging escapes: %s" % staged_rel)
            with open(dest, "wb") as handle:
                handle.write(data)
            texts.append(staged_rel)
            sources[staged_rel] = os.path.realpath(source)
        record["fallback"] = False
        if not texts:
            if shared is None or not apache_alternative(
                    record["license"]):
                fail("crate %s %s ships no license text and "
                     "offers no Apache-2.0 alternative "
                     "(locked sources at %s)"
                     % (name, version, root))
            staged_rel = "licenses/crates/%s/LICENSE-APACHE" % leaf
            dest = os.path.join(dest_dir, "LICENSE-APACHE")
            if not contained(dest, dest_root):
                fail("crate text staging escapes: %s" % staged_rel)
            with open(dest, "wb") as handle:
                handle.write(shared)
            # No single source file to re-verify later: the
            # shared bytes are pinned here, and the staged-tree
            # walk plus archive-time re-read cover them after.
            if sha256_file(dest) != hashlib.sha256(shared) \
                    .hexdigest():
                fail("shared grant text mis-staged: %s" % staged_rel)
            texts.append(staged_rel)
            record["fallback"] = True
            print("package-tarball: %s %s has no locked notice "
                  "file; staged the shared Apache-2.0 grant "
                  "under its %s alternative"
                  % (name, version, record["license"]))
        record["texts"] = texts
    return sources


def notices_text(version, lock_sha, ebpf_lock_sha, crates,
                 ebpf_crates, lib_source, lib_provider_sha,
                 lib_staged_sha):
    """Generated THIRD-PARTY-NOTICES.md for the Rust bundle."""
    lines = [
        "<!-- SPDX-License-Identifier: GPL-3.0-or-later -->",
        "# Third-party notices (memveil %s, Rust userspace)" % version,
        "",
        "This bundle redistributes the following third-party",
        "components alongside MemVeil's own files (whose texts",
        "are `LICENSE` and `LICENSES/`). All paths below are",
        "bundle-relative.",
        "",
        "No vendored or patched Rust dependencies: every Rust",
        "crate below comes from the crates.io registry pinned by",
        "`Cargo.lock` (sha256 %s) and" % lock_sha,
        "`crates/ebpf/Cargo.lock` (sha256 %s)." % ebpf_lock_sha,
        "The Aya loader links statically and no bridge shared",
        "object ships.",
        "",
        "- `lib/memveil/libgcc_s.so.1` from the pinned Debian",
        "  provider (vendored %s %s, amd64; provenance and" % (
            "libgcc-s1", LIBGCC_PROVIDER_VERSION),
        "  adoption proofs in packaging/libgcc/PROVENANCE.txt):",
        "  %s" % lib_source,
        "  GPL-3.0-only WITH GCC-exception-3.1; full texts in",
        "  `licenses/GPL-3.0.txt` plus",
        "  `licenses/RUNTIME.LIBRARY.EXCEPTION`.",
        "  provider sha256: %s" % lib_provider_sha,
        "  staged sha256: %s" % lib_staged_sha,
        "",
        "Statically linked Rust crates (compiled into `bin/memveil`):",
        "",
    ]
    for record in crates:
        lines.append("- %s %s (%s)" % (
            record["name"], record["version"], record["license"]))
        lines.append("  source: %s" % (record["source"] or "NOASSERTION"))
        for text in record["texts"]:
            lines.append("  text: `%s`" % text)
        if record.get("fallback"):
            lines.append("  no notice file in the locked sources; "
                         "redistributed under the Apache-2.0 "
                         "alternative (shared standard grant text, "
                         "the most common locked LICENSE-APACHE "
                         "bytes, verified at package time)")
    lines += [
        "",
        "Statically linked eBPF crates (compiled into `bpf/*.bpf.o`):",
        "",
    ]
    for record in ebpf_crates:
        lines.append("- %s %s (%s)" % (
            record["name"], record["version"], record["license"]))
        lines.append("  source: %s" % (record["source"] or "NOASSERTION"))
        for text in record["texts"]:
            lines.append("  text: `%s`" % text)
        if record.get("fallback"):
            lines.append("  no notice file in the locked sources; "
                         "redistributed under the Apache-2.0 "
                         "alternative (shared standard grant text, "
                         "the most common locked LICENSE-APACHE "
                         "bytes, verified at package time)")
    lines += [
        "",
        "License texts: `LICENSE`, `LICENSES/` (MemVeil);",
        "`licenses/GPL-3.0.txt` plus",
        "`licenses/RUNTIME.LIBRARY.EXCEPTION` (GCC runtime);",
        "`licenses/crates/<name>-<version>/` holds each linked",
        "crate's notice files staged from the locked crates.io",
        "sources above (byte-verified at package time). The",
        "manifest's `cargo.crates` / `cargo.ebpf_crates` records",
        "bind each crate to its staged texts.",
        "",
    ]
    return "\n".join(lines)


def _drop_candidates(out_dir, tag):
    """Best-effort removal of a tag's bundle and tarball.

    A failed run leaves no apparently successful final
    candidate for its tag. Never raises and never escapes
    the output directory.
    """
    try:
        validate_tag(tag)
    except ValueError:
        return
    try:
        final = os.path.join(out_dir, tag)
        tarball = os.path.join(out_dir, tag + ".tar.gz")
        if not contained(final, out_dir) \
                or os.path.realpath(final) == \
                os.path.realpath(out_dir):
            return
        shutil.rmtree(final, ignore_errors=True)
        if os.path.isdir(tarball) and not os.path.islink(tarball):
            shutil.rmtree(tarball, ignore_errors=True)
        elif os.path.exists(tarball):
            os.remove(tarball)
    except OSError:
        pass


def owns_git_root(path):
    """Require the source root to equal Git's top-level."""
    try:
        proc = run(["git", "-C", path, "rev-parse",
                    "--show-toplevel"])
    except FileNotFoundError:
        return False
    return (proc.returncode == 0 and bool(proc.stdout.strip())
            and os.path.realpath(proc.stdout.strip())
            == os.path.realpath(path))


def git_rev_or_none(path):
    if not owns_git_root(path):
        return None
    proc = run(["git", "-C", path, "rev-parse", "HEAD"])
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def git_clean(path):
    if not owns_git_root(path):
        fail("cannot inspect owning Git tree at %s" % path)
    proc = run(["git", "-C", path, "status", "--porcelain"])
    if proc.returncode != 0:
        fail("cannot inspect %s" % path)
    return proc.stdout.strip() == ""


def main(argv):
    out_dir = None
    tag = None
    root_opt = None
    binary_opt = None
    bpf_opt = None
    build = False
    candidate = False
    args = list(argv)
    while args:
        opt = args.pop(0)
        if opt in ("--help", "-h"):
            print(__doc__)
            return 0
        if opt == "--out" and args:
            out_dir = args.pop(0)
            continue
        if opt == "--tag" and args:
            tag = args.pop(0)
            continue
        if opt == "--root" and args:
            root_opt = args.pop(0)
            continue
        if opt == "--binary" and args:
            binary_opt = args.pop(0)
            continue
        if opt == "--bpf-dir" and args:
            bpf_opt = args.pop(0)
            continue
        if opt == "--build":
            build = True
            continue
        if opt == "--candidate":
            candidate = True
            continue
        fail("unknown option: %s" % opt)
    built_from_source = candidate_built_from_source(
        candidate, build, binary_opt, bpf_opt)
    if tag is not None:
        try:
            validate_tag(tag)
        except ValueError as err:
            fail(str(err))
    root = resolve_root(root_opt)
    if out_dir is None:
        out_dir = os.path.join(root, "dist")
    packaging_tools = {}
    for name in ("patchelf", "strip", "readelf"):
        tool = shutil.which(name)
        if tool is None:
            fail("required packaging tool missing: " + name)
        result = run([tool, "--version"])
        if result.returncode != 0:
            fail("packaging tool version failed: " + name)
        packaging_tools[name] = {
            "version": result.stdout.splitlines()[0],
            "sha256": sha256_file(tool)}
    staged = None
    provider_work = None
    fresh_target = None
    # A failed run leaves no staging directory and no
    # apparently successful final candidate: every failure
    # below drops this run's tag candidates (once the tag
    # is known) and the staging directory.
    try:
        memveil_rev = git_rev_or_none(root)
        if memveil_rev is not None:
            if not git_clean(root):
                fail("worktree has uncommitted changes; commit first")
            clean_tree = True
        else:
            # Git-free source export: no commit identity to record
            # and no worktree state to enforce. The manifest says
            # "export" so nobody mistakes this for a commit-anchored
            # build, and tarball mtimes fall back to the youngest
            # staged file instead of the commit clock.
            memveil_rev = "export"
            # No receipt is recorded below, so the seal's
            # clean_tree requirement can never pass: the export
            # cleanliness value stays false by absence.
            clean_tree = False
            print("package-tarball: git-free export; "
                  "revision recorded as export")
        rust_dir = root
        cargo_version, rustc_version = cargo_tool_versions(rust_dir)
        print("package-tarball: cargo %s rustc %s (RUSTUP_TOOLCHAIN "
              "stripped)" % (cargo_version, rustc_version))
        if build:
            fresh_target = fresh_target_dir()
        binary_input = resolve_binary(root, binary_opt, build,
                                      fresh_target)
        binary_input_sha = sha256_file(binary_input)
        if build:
            release_dir = os.path.dirname(binary_input)
        else:
            release_dir = os.path.join(
                resolve_target_dir(root), "release")
        bpf_dir = resolve_bpf_dir(release_dir, bpf_opt)
        bpf_inputs = {}
        for channel, shipped in CHANNELS:
            source = os.path.join(
                bpf_dir, "memveil-ebpf-" + channel)
            bpf_inputs[shipped] = (source, sha256_file(source))

        # The bpf/ inspection copies must be the exact bytes the
        # binary runs: --binary and --bpf-dir resolve
        # independently, so a stale or mixed pair would
        # otherwise ship a consistent manifest for probes
        # zero-config `record` never executes. Identity first:
        # each path must carry its own channel marker, so a
        # renamed same-build input refuses naming the
        # mistitled channel. The marker travels with the
        # bytes, so requiring marker == expected channel per
        # path closes the swap.
        check_bpf_markers(bpf_inputs)
        print("package-tarball: BPF inputs carry their channel markers")

        # Then the binding: each inspection input's digest must
        # equal the build-baked digest the binary dumps for its
        # channel — the hash of the exact bytes `embedded_object`
        # serves. An occurrence search cannot make this
        # distinction: correctly marked bytes planted in an
        # unused loadable section occur inside the mapped
        # ranges while the executable keeps running its
        # original copy. Anything else refuses here, before
        # staging.
        embedded = embedded_manifest(binary_input)
        expect = dict((shipped, channel)
                      for channel, shipped in CHANNELS)
        for shipped, (source, digest) in sorted(bpf_inputs.items()):
            if digest != embedded[expect[shipped]]:
                fail("binary %s does not embed the %s input "
                     "(%s sha256 %s): --binary and --bpf-dir "
                     "come from different builds"
                     % (binary_input, shipped, source, digest))
        print("package-tarball: BPF inspection digests match "
              "the embedded manifest")

        # Pinned closure provider: verify and extract the vendored
        # libgcc before the closure walk consumes it, and prove it
        # satisfies the binary's unwinder needs (a toolchain bump
        # that widens the need refuses here).
        provider_work = os.path.join(out_dir, ".libgcc")
        shutil.rmtree(provider_work, ignore_errors=True)
        try:
            os.makedirs(provider_work)
        except OSError as exc:
            fail("provider staging setup failed: %s" % exc)
        provider_lib = vendored_libgcc(root, provider_work)
        check_libgcc_unwinder(binary_input, provider_lib)
        vendored = {"libgcc_s.so.1": provider_lib}

        # Cargo closure facts (offline, locked): the manifest and
        # the generated notices bind exactly these crates.
        lock_path = os.path.join(rust_dir, "Cargo.lock")
        ebpf_lock_path = os.path.join(
            rust_dir, "crates", "ebpf", "Cargo.lock")
        lock_sha = sha256_file(lock_path)
        ebpf_lock_sha = sha256_file(ebpf_lock_path)
        crates, crate_roots = third_party_crates(
            rust_dir, os.path.join(rust_dir, "Cargo.toml"),
            "memveil")
        ebpf_crates, ebpf_roots = third_party_crates(
            rust_dir,
            os.path.join(rust_dir, "crates", "ebpf", "Cargo.toml"),
            "memveil-ebpf")
        if not crates or not ebpf_crates:
            fail("empty Cargo closure; refusing a notice-less bundle")
        roots = dict(crate_roots)
        for key, ebpf_root in ebpf_roots.items():
            if key in roots and roots[key] != ebpf_root:
                fail("crate %s %s resolves to two source trees: "
                     "%s vs %s"
                     % (key[0], key[1], roots[key], ebpf_root))
            roots[key] = ebpf_root

        staged = os.path.join(out_dir, ".stage")
        bindir = os.path.join(staged, "bin")
        libdir = os.path.join(staged, "lib")
        shutil.rmtree(staged, ignore_errors=True)
        try:
            os.makedirs(bindir)
            os.makedirs(libdir)
        except OSError as exc:
            fail("staging setup failed: %s" % exc)
        binary = os.path.join(bindir, "memveil")
        shutil.copy2(binary_input, binary)
        if sha256_file(binary) != binary_input_sha:
            fail("staged executable differs from its input")

        # Transitive closure over the staged binary: every NEEDED
        # name outside the system allowlist must resolve to a
        # shippable provider file, and shipped libs must not
        # widen the closure. Unknown names fail instead of guessing.
        ship = {}
        queue = [binary]
        while queue:
            path = queue.pop(0)
            for name in needed(path):
                if name in SYSTEM_ALLOW or name in ship:
                    continue
                try:
                    validate_lib_name(name, os.path.basename(path))
                except ValueError as err:
                    fail(str(err))
                provider = closure_provider(name, vendored)
                if provider is None:
                    fail("no source for NEEDED %s (from %s)"
                         % (name, os.path.basename(path)))
                ship[name] = provider
                queue.append(provider)
        if not ship:
            fail("empty link closure; refusing a lib-less bundle")
        # The provider table admits exactly one shippable name, so
        # the closure holds exactly one lib; the notices and the
        # provenance record below attribute exactly that lib.
        if len(ship) != 1:
            fail("closure holds %d libs, want 1: %s"
                 % (len(ship), sorted(ship)))
        for name in sorted(ship):
            dest = os.path.join(libdir, name)
            if not contained(dest, libdir):
                fail("staging escapes lib/: %s" % name)
            shutil.copy2(ship[name], dest)
        for name in sorted(os.listdir(libdir)):
            for dep in needed(os.path.join(libdir, name)):
                if dep in SYSTEM_ALLOW or dep in ship:
                    continue
                fail("shipped %s needs %s: outside closure" % (name, dep))

        # Bundle version comes from the engine itself, never from
        # a duplicated string here. The staged libdir on the
        # loader path proves the staged lib loads; the rerun
        # after normalization (below) proves the RUNPATH.
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = libdir
        proc = run([binary, "version"], env=env)
        if proc.returncode != 0 or not proc.stdout.startswith("memveil-"):
            fail("bundle binary version check failed: %r" % proc.stdout)
        version = proc.stdout.strip().split("-", 1)[1]
        if tag is None:
            tag = "memveil-" + version
        try:
            validate_tag(tag)
        except ValueError as err:
            fail(str(err))

        # A failed run must leave no apparently successful final
        # candidate: drop any previous bundle and tarball for this
        # tag now, before staging produces a new one.
        final = os.path.join(out_dir, tag)
        tarball = os.path.join(out_dir, tag + ".tar.gz")
        if not contained(final, out_dir) \
                or os.path.realpath(final) == os.path.realpath(out_dir):
            fail("bundle target escapes output dir: %s" % tag)
        _drop_candidates(out_dir, tag)

        for sub in ("bpf", "profiles", "docs", "examples"):
            os.makedirs(os.path.join(staged, sub))
        for shipped, (source, _digest) in sorted(bpf_inputs.items()):
            shutil.copy2(source, os.path.join(staged, "bpf", shipped))
        for name in sorted(os.listdir(os.path.join(root, "profiles"))):
            if name == "manifest.txt" or name.endswith(".json"):
                shutil.copy2(os.path.join(root, "profiles", name),
                             os.path.join(staged, "profiles", name))
        # Ship the whole manuals tree: quickstart and support
        # reference troubleshooting, performance, resource-limits,
        # and permissions, so staging a subset would ship dangling
        # references. Every staged manual must resolve its local
        # links inside the bundle (pinned by the package lane).
        for base, dirs, files in os.walk(os.path.join(root, "docs")):
            dirs.sort()
            for name in sorted(files):
                if not name.endswith(".md"):
                    continue
                src = os.path.join(base, name)
                rel = os.path.relpath(src, os.path.join(root, "docs"))
                dest = os.path.join(staged, "docs", rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copy2(src, dest)
        for name in ("quickstart.md", "support.md", "privacy.md"):
            if not os.path.isfile(os.path.join(staged, "docs", name)):
                fail("missing docs/%s" % name)
        for leaf in ("real-capture", "lifecycle-copy"):
            example = os.path.join(root, "examples", leaf)
            for name in ("events.ndjson", "session.json"):
                src = os.path.join(example, name)
                if not os.path.isfile(src):
                    fail("missing %s" % src)
            shutil.copytree(example,
                            os.path.join(staged, "examples", leaf))

        # License texts: MemVeil's own plus the GCC runtime texts
        # for the shipped lib. A missing text fails the package.
        src = os.path.join(root, "LICENSE")
        if not os.path.isfile(src):
            fail("missing %s" % src)
        shutil.copy2(src, os.path.join(staged, "LICENSE"))
        own_licenses = os.path.join(root, "LICENSES")
        for name in ("GPL-2.0-only.txt", "GPL-2.0-or-later.txt",
                     "GPL-2.0.txt"):
            if not os.path.isfile(os.path.join(own_licenses, name)):
                fail("missing LICENSES/%s" % name)
        shutil.copytree(own_licenses, os.path.join(staged, "LICENSES"))
        staged_licenses = os.path.join(staged, "licenses")
        os.makedirs(staged_licenses)
        license_sources = {}
        for staged_rel, candidates in GCC_LICENSES:
            paths = list(candidates)
            if staged_rel == "licenses/RUNTIME.LIBRARY.EXCEPTION":
                paths.append(os.path.join(root, VENDORED_EXCEPTION))
            provider = next((path for path in paths
                             if os.path.isfile(path)), None)
            if provider is None:
                fail("missing host license text for %s (tried %s)"
                     % (staged_rel, ", ".join(paths)))
            shutil.copy2(provider, os.path.join(staged, staged_rel))
            license_sources[staged_rel] = os.path.realpath(provider)
        for staged_rel, root_rel, want_sha in VENDORED_LICENSES:
            source = os.path.join(root, root_rel)
            if not os.path.isfile(source) or os.path.islink(source):
                fail("vendored license text missing: %s" % root_rel)
            if sha256_file(source) != want_sha:
                fail("vendored license text differs from its pin: %s"
                     % root_rel)
            shutil.copy2(source, os.path.join(staged, staged_rel))
            license_sources[staged_rel] = os.path.realpath(source)
        # Linked-crate notice files from the locked sources (MIT
        # `bytes` et al.): every Cargo closure record stages its
        # texts here, before the staged-tree walk below binds
        # them into the manifest.
        crate_text_sources = stage_crate_texts(
            staged, crates, ebpf_crates, roots)
        print("package-tarball: license texts staged")

        # Every staged copy must match the exact source bytes it
        # was copied from; a torn copy or a source changed under
        # staging fails here, before the manifest is written.
        # Maps staged rels to the source paths they must equal.
        expect = {}
        for name in ship:
            expect["lib/" + name] = ship[name]
        for shipped, (source, _digest) in bpf_inputs.items():
            expect["bpf/" + shipped] = source
        problems = []
        observed = {}
        for base, _dirs, files in os.walk(staged):
            for name in sorted(files):
                full = os.path.join(base, name)
                rel = os.path.relpath(full, staged).replace(os.sep, "/")
                if os.path.islink(full):
                    problems.append("staged path is a symlink: %s" % rel)
                    continue
                digest = sha256_file(full)
                observed[rel] = digest
        for rel, source in sorted(expect.items()):
            full = os.path.join(staged, *rel.split("/"))
            if not os.path.isfile(full) or os.path.islink(full):
                problems.append("staged copy missing: %s" % rel)
            elif sha256_file(full) != sha256_file(source):
                problems.append("staged copy differs from source: %s"
                                % rel)
        # The staged executable must equal the exact --binary bytes
        # validated above: compare the STAGED digest against the
        # PINNED validation-time digest, never against a fresh
        # read of the mutable --binary path. A staged-vs-source
        # re-read passes a source swapped between validation and
        # staging (both sides read the replacement) while the
        # pinned digest records the validated original: the
        # pinned digest is the single source of truth, so a
        # staged copy that differs from it refuses here.
        staged_binary_ok = True
        if not os.path.isfile(binary) or os.path.islink(binary):
            problems.append("staged copy missing: bin/memveil")
            staged_binary_ok = False
        elif observed.get("bin/memveil") != binary_input_sha:
            problems.append("staged executable differs from the "
                            "validated binary: bin/memveil")
            staged_binary_ok = False
        # The staged BPF inspection copies must equal the exact
        # bytes the binary embeds: compare the STAGED digests
        # against the executable's dumped manifest, never against
        # a fresh read of the mutable --bpf-dir path. The
        # staged-vs-source check above passes a source swapped
        # between validation and staging (both sides read the
        # replacement) while `embedded_bpf` below would record
        # the validated original: the executable is the single
        # source of truth, so a staged copy that differs from
        # its dumped digest refuses here, before the seal.
        staged_channels = dict(
            (shipped, channel) for channel, shipped in CHANNELS)
        for shipped in sorted(staged_channels):
            rel = "bpf/" + shipped
            if observed.get(rel) != \
                    embedded[staged_channels[shipped]]:
                problems.append(
                    "staged BPF copy differs from the binary's "
                    "embedded manifest: %s" % rel)
        # The dumped manifest must describe the STAGED executable:
        # re-dump `--embedded-manifest` from the staged copy and
        # require the validation-time rows. The validation probe
        # executes the mutable --binary path while every other
        # validation read opens it, so a --binary replaced between
        # the validation hash and the probe (and restored before
        # staging) validates one binary's bytes against another's
        # manifest; only the staged executable re-dumping the same
        # rows proves the seal binds a single binary. Anything
        # else refuses here, before the seal. The re-dump runs
        # only a digest-verified staged binary: a mismatch or a
        # symlink recorded above already refuses below, and
        # probing it would execute bytes already deemed invalid.
        if staged_binary_ok:
            staged_embedded = embedded_manifest(binary)
            if staged_embedded != embedded:
                problems.append(
                    "staged executable dumps a different embedded "
                    "manifest than validated: bin/memveil")
        for rel, source in sorted(license_sources.items()):
            full = os.path.join(staged, *rel.split("/"))
            if sha256_file(full) != sha256_file(source):
                problems.append("staged license differs: %s" % rel)
        for rel, source in sorted(crate_text_sources.items()):
            full = os.path.join(staged, *rel.split("/"))
            if not os.path.isfile(full) or os.path.islink(full):
                problems.append("staged crate text missing: %s" % rel)
            elif sha256_file(full) != sha256_file(source):
                problems.append("staged crate text differs: %s" % rel)
        # Tree-derived copies must equal the input tree bytes and
        # cover the whole input selection (a deletion under
        # staging is otherwise invisible).
        for prefix in ("docs", "profiles", "examples", "LICENSES"):
            base = os.path.join(root, prefix)
            for current, _dirs, files in os.walk(base):
                for name in sorted(files):
                    if prefix == "docs" and not name.endswith(".md"):
                        continue
                    if prefix == "profiles" and not (
                            name == "manifest.txt"
                            or name.endswith(".json")):
                        continue
                    src = os.path.join(current, name)
                    rel = prefix + "/" + os.path.relpath(
                        src, base).replace(os.sep, "/")
                    full = os.path.join(staged, *rel.split("/"))
                    if not os.path.isfile(full) or os.path.islink(full):
                        problems.append(
                            "expected tree copy missing: %s" % rel)
                    elif sha256_file(full) != sha256_file(src):
                        problems.append(
                            "staged copy differs from tree: %s" % rel)
        if sha256_file(os.path.join(staged, "LICENSE")) != \
                sha256_file(os.path.join(root, "LICENSE")):
            problems.append("staged LICENSE differs from tree")
        if problems:
            for problem in problems[:10]:
                print("package-tarball: %s" % problem, file=sys.stderr)
            fail("staged tree differs from its sources")
        print("package-tarball: staged tree matches its sources")

        # Refuse path substitutions before any tool can mutate a staged input.
        if os.path.islink(staged):
            fail("staged root broke seal before normalization")
        for base, dirs, files in os.walk(staged):
            for name in dirs + files:
                path = os.path.join(base, name)
                mode = os.lstat(path).st_mode
                if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    fail("staged path broke seal before normalization: " +
                         os.path.relpath(path, staged))
        for relative, digest in observed.items():
            path = os.path.join(staged, relative)
            if not os.path.isfile(path) or sha256_file(path) != digest:
                fail("staged file broke seal before normalization: "
                     + relative)

        # Canonical normalization: the binary gains its relocatable
        # RUNPATH and the shipped lib loses unneeded sections.
        # Both sides of each transformation bind in the manifest.
        transformations = {}
        canonical_libdir = os.path.join(libdir, "memveil")
        os.makedirs(canonical_libdir)
        for name in sorted(ship):
            old = os.path.join(libdir, name)
            os.rename(old, os.path.join(canonical_libdir, name))
        lib_provider_sha = {}
        for relative in ["bin/memveil"] + [
                "lib/memveil/" + name for name in sorted(ship)]:
            path = os.path.join(staged, relative)
            original = sha256_file(path)
            source_relative = relative.replace(
                "lib/memveil/", "lib/", 1)
            if original != observed[source_relative]:
                fail("staged input changed before normalization: "
                     + relative)
            before = needed(path)
            if relative == "bin/memveil":
                operations = [["patchelf", "--set-rpath",
                               BIN_RUNPATH, relative]]
            else:
                operations = [["strip", "--strip-unneeded", relative]]
                lib_provider_sha[relative] = original
            for command in operations:
                result = run(command, cwd=staged)
                if result.returncode != 0:
                    fail("canonical normalization failed: %s\n%s"
                         % (relative, result.stderr))
            if needed(path) != before:
                fail("canonical normalization changed dependencies: "
                     + relative)
            # No source_path on the engine record: the in-flow
            # build compiles into a fresh temporary target dir,
            # so any path would name disposable build state.
            # The input digest plus the build receipt below
            # already bind the engine bytes and source commit.
            # Shipped libs keep their repo-relative provider
            # path, which names a pinned vendored input.
            record = {
                "source_sha256": original,
                "output_sha256": sha256_file(path),
                "operations": operations,
                "working_directory": "bundle-root",
                "source_root": "input-tree",
                "staged_input_path": source_relative,
            }
            if relative != "bin/memveil":
                record["source_path"] = os.path.join(
                    LIBGCC_DIR, LIBGCC_DEB_NAME)
            transformations[relative] = record
        for relative in list(observed):
            if relative.startswith("lib/"):
                observed["lib/memveil/" + relative[4:]] = \
                    observed.pop(relative)
        for relative, transformation in transformations.items():
            observed[relative] = transformation["output_sha256"]

        # The generated notices name the staged lib bytes, so they
        # are written after normalization and join the manifest.
        lib_rel = "lib/memveil/" + sorted(ship)[0]
        notices = notices_text(
            version, lock_sha, ebpf_lock_sha, crates, ebpf_crates,
            os.path.join(LIBGCC_DIR, LIBGCC_DEB_NAME) + " member "
            + LIBGCC_SO_MEMBER, lib_provider_sha[lib_rel],
            observed[lib_rel])
        with open(os.path.join(staged, "THIRD-PARTY-NOTICES.md"),
                  "w", encoding="utf-8") as handle:
            handle.write(notices)
        observed["THIRD-PARTY-NOTICES.md"] = sha256_file(
            os.path.join(staged, "THIRD-PARTY-NOTICES.md"))

        # The normalized binary must start with no loader help:
        # this rerun proves the RUNPATH resolves the staged lib.
        bare = dict(os.environ)
        bare.pop("LD_LIBRARY_PATH", None)
        rerun = run([binary, "version"], env=bare)
        if rerun.returncode != 0 or rerun.stdout.strip() != \
                "memveil-" + version:
            fail("canonical executable failed version check: "
                 + rerun.stderr)

        # Build-time receipt: source C plus the tree inventory, the
        # probed tool versions, the engine/BPF output digests, the
        # build-time worktree cleanliness, and whether this run
        # built the engine and BPF objects from the input root
        # in-flow, recorded from the verified staging reads above
        # (never re-walked). The provenance emitter and the seal
        # bind this recording: only candidate mode (--candidate
        # with --build and no prebuilt overrides) records a
        # receipt the seal accepts, so stale prebuilt bytes
        # repackaged at C with a fresh receipt still fail. Git-free
        # exports carry no commit identity, so they record no
        # receipt and cannot seal.
        build_receipt = None
        if memveil_rev != "export":
            _tree_entries, tree_digest = git_tree_inventory(
                root, memveil_rev)
            build_receipt = {
                "source_commit": memveil_rev,
                "inventory_sha256": tree_digest,
                "tools": {"cargo": cargo_version,
                          "rustc": rustc_version,
                          "bpf_linker": bpf_linker_version(rust_dir)},
                "outputs": {
                    "engine_sha256": observed["bin/memveil"],
                    "bpf": {shipped: observed["bpf/" + shipped]
                            for _channel, shipped in CHANNELS},
                },
                "clean_tree": clean_tree,
                "built_from_source": built_from_source,
            }

        # Known manifest gaps, intentionally unported (not
        # oversights): no `canonical_runtime` entry — the Rust
        # baseline (x86-64-v1) runs everywhere >= v1, so no
        # CPU-floor gate is needed (recorded performance
        # evidence decides if v3 codegen is warranted); and no
        # `source_inventory` entry — the port-vs-retire record
        # for sources lives in the parity notes instead.
        manifest = {
            "bundle": tag,
            "qualification": "unqualified-local-build",
            "normalization": transformations,
            "packaging_tools": packaging_tools,
            "engine_version": version,
            "memveil_revision": memveil_rev,
            "toolchain": {
                "cargo": {"version": cargo_version},
                "rustc": {"version": rustc_version},
            },
            "cargo": {
                "lock_sha256": lock_sha,
                "crates": crates,
                "ebpf_lock_sha256": ebpf_lock_sha,
                "ebpf_crates": ebpf_crates,
                "rustup_toolchain_env": "stripped",
            },
            "system_libraries": sorted(SYSTEM_ALLOW),
            "runtime_provenance": {
                lib_rel: {
                    "source_path": os.path.join(
                        LIBGCC_DIR, LIBGCC_DEB_NAME),
                    "provider": LIBGCC_PROVIDER,
                    "provider_version": LIBGCC_PROVIDER_VERSION,
                    "member": LIBGCC_SO_MEMBER,
                    "deb_sha256": LIBGCC_DEB_SHA256,
                    "member_sha256": lib_provider_sha[lib_rel],
                    "pre_normalization_sha256":
                        lib_provider_sha[lib_rel],
                    "staged_sha256": observed[lib_rel],
                    "license": "GPL-3.0-only WITH GCC-exception-3.1",
                },
            },
            "runtime_licenses": {
                rel: {"sha256": sha256_file(os.path.join(staged, rel)),
                      "source": manifest_source(root, source)}
                for rel, source in sorted(license_sources.items())
            },
            "first_party": {
                "license_default": "GPL-3.0-or-later",
                "licenses": {
                    "GPL-2.0-only": "LICENSES/GPL-2.0-only.txt",
                    "GPL-2.0-or-later": "LICENSES/GPL-2.0-or-later.txt",
                    "GPL-3.0-or-later": "LICENSE",
                },
                "paths": {
                    "bpf/swiotlb_attempt.bpf.o": "GPL-2.0-only",
                    "bpf/swiotlb_lifecycle.bpf.o": "GPL-2.0-only",
                    "bpf/swiotlb_copy.bpf.o": "GPL-2.0-only",
                },
            },
            # Inspection-copy digests the binary itself dumps
            # for the bytes it embeds: `bpf/<name>` in files[]
            # must equal this entry (proven against the staged
            # bytes just above), so a manifest for the wrong
            # probes cannot validate. The executable is the
            # single source of truth — never a re-read of the
            # mutable --bpf-dir path.
            "embedded_bpf": {
                shipped: embedded[channel]
                for channel, shipped in CHANNELS
            },
            "files": {},
        }
        # Payload hashes come from the verification reads, never
        # from a live re-walk: bytes changed after verification
        # fail at archive time instead of shipping self-consistent.
        manifest["files"] = dict(observed)
        if build_receipt is not None:
            manifest["build_receipt"] = build_receipt
        manifest_text = json.dumps(
            manifest, indent=2, sort_keys=True) + "\n"
        manifest_bytes = manifest_text.encode("utf-8")
        with open(os.path.join(staged, "MANIFEST.json"), "w") as handle:
            handle.write(manifest_text)

        # The archive publishes the bundle: write it from the
        # staging directory first, then rename into place only
        # after the bytes hash. An archive-write failure leaves
        # neither a final bundle nor a partial tarball.
        if memveil_rev == "export":
            mtime = 0
            for base, _, files in os.walk(staged):
                for name in files:
                    stamp = int(os.path.getmtime(
                        os.path.join(base, name)))
                    if stamp > mtime:
                        mtime = stamp
        else:
            mtime = int(run(["git", "-C", root, "log", "-1",
                             "--format=%ct"]).stdout.strip())
        # Zero-mtime gzip header: "w:gz" stamps the current time,
        # which would make identical revisions hash differently.
        # Explicit directory members plus normalized modes keep
        # extraction identical on any umask (dirs 0755, files
        # 0644, executable bit kept). Every archived file binds to
        # its verified bytes as consumed: a change after
        # verification fails here instead of shipping.
        archived = set()
        written_digest = None
        try:
            with open(tarball, "wb") as raw:
                wrapped = _HashingWriter(raw)
                gz = gzip.GzipFile(filename="", mode="wb",
                                   fileobj=wrapped, compresslevel=9,
                                   mtime=0)
                try:
                    with tarfile.open(fileobj=gz, mode="w") as tar:
                        for base, dirs, files in os.walk(staged):
                            dirs.sort()
                            rel = os.path.relpath(base, staged)
                            arcbase = tag if rel == "." else \
                                tag + "/" + rel.replace(os.sep, "/")
                            info = tar.gettarinfo(base, arcbase)
                            if not info.isdir():
                                fail("staged directory changed "
                                     "under archiving: %s" % arcbase)
                            info.mtime = mtime
                            info.uid = info.gid = 0
                            info.uname = info.gname = ""
                            info.mode = tar_member_mode(base, True)
                            tar.addfile(info)
                            for name in sorted(files):
                                full = os.path.join(base, name)
                                rel = os.path.relpath(
                                    full, staged).replace(
                                        os.sep, "/")
                                if os.path.islink(full):
                                    fail("staged file changed under "
                                         "archiving: %s" % rel)
                                try:
                                    with open(full, "rb") as handle:
                                        data = handle.read()
                                except OSError:
                                    fail("staged file vanished under "
                                         "archiving: %s" % rel)
                                if rel == "MANIFEST.json":
                                    match = data == manifest_bytes
                                else:
                                    want = observed.get(rel)
                                    match = want is not None and \
                                        hashlib.sha256(data) \
                                        .hexdigest() == want
                                if not match:
                                    fail("staged file changed under "
                                         "archiving: %s" % rel)
                                info = tar.gettarinfo(
                                    full, tag + "/" + rel)
                                if not info.isfile():
                                    fail("staged file changed under "
                                         "archiving: %s" % rel)
                                info.mtime = mtime
                                info.uid = info.gid = 0
                                info.uname = info.gname = ""
                                info.mode = tar_member_mode(
                                    full, False)
                                info.size = len(data)
                                tar.addfile(info, io.BytesIO(data))
                                archived.add(rel)
                finally:
                    gz.close()
                written_digest = wrapped.hexdigest()
        except OSError as exc:
            try:
                if os.path.exists(tarball):
                    os.remove(tarball)
            except OSError:
                pass
            fail("bundle archive failed: %s" % exc)
        expected = set(observed) | {"MANIFEST.json"}
        if archived != expected:
            fail("archived payload differs from verified "
                 "staging: missing=%s extra=%s"
                 % (sorted(expected - archived),
                    sorted(archived - expected)))
        # Hash before publication, rename, then re-hash, each
        # bound to the digest computed while writing the
        # verified archive: a swap at any point fails instead
        # of shipping, and any hashing or rename failure leaves
        # neither a final bundle nor a tarball.
        try:
            digest = sha256_file(tarball)
        except OSError as exc:
            _drop_candidates(out_dir, tag)
            fail("bundle archive unreadable before publication: %s"
                 % exc)
        if digest != written_digest:
            _drop_candidates(out_dir, tag)
            fail("tarball changed after archiving")
        try:
            os.rename(staged, final)
        except OSError as exc:
            _drop_candidates(out_dir, tag)
            fail("bundle publication failed: %s" % exc)
        try:
            published = sha256_file(tarball)
        except OSError as exc:
            _drop_candidates(out_dir, tag)
            fail("published tarball unreadable: %s" % exc)
        if published != written_digest:
            _drop_candidates(out_dir, tag)
            fail("published tarball changed during publication")
        print("package-tarball: %s" % tarball)
        print("package-tarball: sha256 %s" % digest)
        print("package-tarball: %d files, MANIFEST.json recorded" %
              len(manifest["files"]))
        return 0
    except BaseException:
        if tag is not None:
            _drop_candidates(out_dir, tag)
        raise
    finally:
        if staged is not None:
            if os.path.islink(staged):
                os.unlink(staged)
            else:
                shutil.rmtree(staged, ignore_errors=True)
        if provider_work is not None:
            if os.path.islink(provider_work):
                os.unlink(provider_work)
            else:
                shutil.rmtree(provider_work, ignore_errors=True)
        drop_target_dir(fresh_target)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
