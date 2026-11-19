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
    lib/memveil/*.so*              Rust closure (the toolchain libgcc_s only;
                           the Aya loader links statically, no bridge ships)
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
    THIRD-PARTY-NOTICES.md generated attribution (Cargo closure
                           plus the shipped lib; no vendored deps)
    MANIFEST.json          file hashes, versions, source revisions

Usage: rust/scripts/package-tarball.py [--out DIR] [--tag NAME]
    [--root DIR] [--binary PATH] [--bpf-dir DIR] [--build]
  --out DIR    stage directory (default: rust/dist/)
  --tag NAME   bundle directory name (default: memveil-<version>)
  --root DIR   input tree (default: auto-detected checkout root)
  --binary PATH  release binary (default: <root>/rust/target/
               release/memveil, honoring $CARGO_TARGET_DIR)
  --bpf-dir DIR  build-script OUT_DIR holding memveil-ebpf-*
               (default: auto-detected under the target dir)
  --build      run `cargo build --release --locked --offline` first

Requires a release binary (use --build or build it first),
patchelf, strip, and readelf. Fails closed when the link
closure names anything outside the shipped lib/ set and the
system allowlist. Every cargo invocation strips
RUSTUP_TOOLCHAIN so the repository pin wins.
"""

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
RUN_RUST_DIR = os.path.dirname(HERE)

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
# ship, with the tool that locates each provider file. Any
# other name fails the build instead of guessing.
CLOSURE_PROVIDERS = {
    "libgcc_s.so.1": ("gcc", "-print-file-name=libgcc_s.so.1"),
}

# (OUT_DIR channel, shipped BPF file name).
CHANNELS = (
    ("attempt", "swiotlb_attempt.bpf.o"),
    ("lifecycle", "swiotlb_lifecycle.bpf.o"),
    ("copy", "swiotlb_copy.bpf.o"),
)

# Host license texts for the shipped libgcc, as (staged rel,
# candidate host paths): the first readable candidate wins.
# Portability: the GPL-3 text resolves on Fedora (libgcc
# COPYING3) and Debian (common-licenses). Debian ships no
# standalone GCC exception text, so the exception entry falls
# back to the vendored copy below (last candidate, used only
# when no host text exists).
GCC_LICENSES = (
    ("licenses/GPL-3.0.txt", (
        "/usr/share/licenses/libgcc/COPYING3",
        "/usr/share/common-licenses/GPL-3",
    )),
    ("licenses/RUNTIME.LIBRARY.EXCEPTION", (
        "/usr/share/licenses/libgcc/COPYING.RUNTIME",
    )),
)

# Vendored fallback for the exception entry, root-relative: the
# FSF's immutable Version 3.1 grant, byte-identical to the Fedora
# host text. The tarball suite pins that equality wherever the
# host text exists, so Fedora builds keep staging host bytes
# while Debian builds stage these identical bytes. Never edit:
# any byte change breaks the verbatim grant (and the pin).
VENDORED_EXCEPTION = os.path.join(
    "rust", "packaging", "RUNTIME.LIBRARY.EXCEPTION")

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


def root_markers_present(root):
    return (
        os.path.isfile(os.path.join(root, "profiles", "manifest.txt"))
        and os.path.isfile(os.path.join(root, "rust", "Cargo.lock"))
        and os.path.isfile(os.path.join(root, "LICENSE"))
    )


def resolve_root(explicit):
    """Input tree: explicit --root or the auto-detected checkout."""
    if explicit is not None:
        root = os.path.abspath(explicit)
        if not root_markers_present(root):
            fail("input root lacks profiles/, rust/Cargo.lock, "
                 "LICENSE: %s" % explicit)
        return root
    autodetect = os.path.dirname(RUN_RUST_DIR)
    for candidate in (autodetect, RUN_RUST_DIR):
        if root_markers_present(candidate):
            return os.path.abspath(candidate)
    fail("cannot detect the input root from %s" % RUN_RUST_DIR)


def resolve_target_dir(root):
    override = os.environ.get("CARGO_TARGET_DIR")
    if override:
        return os.path.abspath(override)
    return os.path.join(root, "rust", "target")


def resolve_binary(root, explicit, build):
    """Release binary, building it first under --build."""
    rust_dir = os.path.join(root, "rust")
    if build:
        proc = run_cargo(
            ["build", "--release", "--locked", "--offline"],
            rust_dir)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr, file=sys.stderr)
            fail("cargo build --release failed")
    if explicit is not None:
        binary = os.path.abspath(explicit)
    else:
        binary = os.path.join(
            resolve_target_dir(root), "release", "memveil")
    if not os.path.isfile(binary):
        fail("release binary missing: %s (run cargo build "
             "--release in %s, or pass --build)" % (binary, rust_dir))
    return binary


def bpf_candidates(target_dir):
    """Complete OUT_DIR sets holding all three channel artifacts."""
    base = os.path.join(target_dir, "release", "build", "memveil")
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


def resolve_bpf_dir(target_dir, explicit):
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
    sets = bpf_candidates(target_dir)
    if not sets:
        fail("no BPF artifacts under %s (run cargo build "
             "--release, or pass --bpf-dir)" % target_dir)
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


def closure_provider(name):
    """Provider file for a shippable NEEDED name."""
    if name not in CLOSURE_PROVIDERS:
        return None
    tool, flag = CLOSURE_PROVIDERS[name][0], CLOSURE_PROVIDERS[name][1]
    if shutil.which(tool) is None:
        fail("cannot locate %s: %s is not installed" % (name, tool))
    proc = run([tool, flag])
    if proc.returncode != 0:
        fail("cannot locate %s: %s %s failed" % (name, tool, flag))
    candidate = os.path.realpath(proc.stdout.strip().splitlines()[0])
    if not os.path.isfile(candidate):
        fail("cannot locate %s: %s printed %r"
             % (name, tool, proc.stdout.strip()))
    return candidate


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
    """({(name, version): (license, source)}, {workspace names}).

    Offline and locked, like the tree query above.
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
        packages[(entry.get("name"), entry.get("version"))] = (
            entry.get("license") or "NOASSERTION",
            entry.get("source") or "",
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
    """Sorted third-party (name, version, license, source) records.

    Membership is source-based, not workspace-based: the eBPF
    workspace consumes memveil-ebpf-common as a path dependency
    without listing it as a member, and it is still
    first-party. Unknown path-sourced members fail closed
    (vendored dependencies need explicit notices handling).
    """
    closure = cargo_tree_closure(rust_dir, manifest, package)
    packages, members = cargo_metadata_map(rust_dir, manifest)
    records = {}
    for name, version in closure:
        key = (name, version)
        if key not in packages:
            fail("cargo metadata lacks %s %s" % (name, version))
        license_text, source = packages[key]
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
    return [records[key] for key in sorted(records)]


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
        "No vendored or patched dependencies: every Rust crate",
        "below comes from the crates.io registry pinned by",
        "`rust/Cargo.lock` (sha256 %s) and" % lock_sha,
        "`rust/crates/ebpf/Cargo.lock` (sha256 %s)." % ebpf_lock_sha,
        "The Aya loader links statically and no bridge shared",
        "object ships.",
        "",
        "- `lib/memveil/libgcc_s.so.1` from the build host toolchain:",
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
    lines += [
        "",
        "Statically linked eBPF crates (compiled into `bpf/*.bpf.o`):",
        "",
    ]
    for record in ebpf_crates:
        lines.append("- %s %s (%s)" % (
            record["name"], record["version"], record["license"]))
        lines.append("  source: %s" % (record["source"] or "NOASSERTION"))
    lines += [
        "",
        "License texts: `LICENSE`, `LICENSES/` (MemVeil);",
        "`licenses/GPL-3.0.txt` plus",
        "`licenses/RUNTIME.LIBRARY.EXCEPTION` (GCC runtime).",
        "Crate licenses name their SPDX expressions above; full",
        "crate texts ship with the crates.io sources, not in",
        "this bundle.",
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
    proc = run(["git", "-C", path, "status", "--short"])
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
        fail("unknown option: %s" % opt)
    if tag is not None:
        try:
            validate_tag(tag)
        except ValueError as err:
            fail(str(err))
    root = resolve_root(root_opt)
    if out_dir is None:
        out_dir = os.path.join(root, "rust", "dist")
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
    # A failed run leaves no staging directory and no
    # apparently successful final candidate: every failure
    # below drops this run's tag candidates (once the tag
    # is known) and the staging directory.
    try:
        memveil_rev = git_rev_or_none(root)
        if memveil_rev is not None:
            if not git_clean(root):
                fail("worktree has uncommitted changes; commit first")
        else:
            # Git-free source export: no commit identity to record
            # and no worktree state to enforce. The manifest says
            # "export" so nobody mistakes this for a commit-anchored
            # build, and tarball mtimes fall back to the youngest
            # staged file instead of the commit clock.
            memveil_rev = "export"
            print("package-tarball: git-free export; "
                  "revision recorded as export")
        rust_dir = os.path.join(root, "rust")
        cargo_version, rustc_version = cargo_tool_versions(rust_dir)
        print("package-tarball: cargo %s rustc %s (RUSTUP_TOOLCHAIN "
              "stripped)" % (cargo_version, rustc_version))
        target_dir = resolve_target_dir(root)
        binary_input = resolve_binary(root, binary_opt, build)
        binary_input_sha = sha256_file(binary_input)
        bpf_dir = resolve_bpf_dir(target_dir, bpf_opt)
        bpf_inputs = {}
        for channel, shipped in CHANNELS:
            source = os.path.join(
                bpf_dir, "memveil-ebpf-" + channel)
            bpf_inputs[shipped] = (source, sha256_file(source))

        # Cargo closure facts (offline, locked): the manifest and
        # the generated notices bind exactly these crates.
        lock_path = os.path.join(rust_dir, "Cargo.lock")
        ebpf_lock_path = os.path.join(
            rust_dir, "crates", "ebpf", "Cargo.lock")
        lock_sha = sha256_file(lock_path)
        ebpf_lock_sha = sha256_file(ebpf_lock_path)
        crates = third_party_crates(
            rust_dir, os.path.join(rust_dir, "Cargo.toml"),
            "memveil")
        ebpf_crates = third_party_crates(
            rust_dir,
            os.path.join(rust_dir, "crates", "ebpf", "Cargo.toml"),
            "memveil-ebpf")
        if not crates or not ebpf_crates:
            fail("empty Cargo closure; refusing a notice-less bundle")

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
                provider = closure_provider(name)
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
        print("package-tarball: license texts staged")

        # Every staged copy must match the exact source bytes it
        # was copied from; a torn copy or a source changed under
        # staging fails here, before the manifest is written.
        # Maps staged rels to the source paths they must equal.
        expect = {"bin/memveil": binary_input}
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
        for rel, source in sorted(license_sources.items()):
            full = os.path.join(staged, *rel.split("/"))
            if sha256_file(full) != sha256_file(source):
                problems.append("staged license differs: %s" % rel)
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
            transformations[relative] = {
                "source_sha256": original,
                "output_sha256": sha256_file(path),
                "operations": operations,
                "working_directory": "bundle-root",
                "source_root": "input-tree",
                "source_path": (os.path.abspath(binary_input)
                                if relative == "bin/memveil"
                                else "host-toolchain:"
                                + os.path.basename(relative)),
                "staged_input_path": source_relative,
            }
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
            ship[sorted(ship)[0]], lib_provider_sha[lib_rel],
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

        gcc_version = run(["gcc", "--version"]).stdout.splitlines()[0] \
            if shutil.which("gcc") else "unknown"
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
                    "source_path": ship[sorted(ship)[0]],
                    "provider": "host-toolchain-gcc",
                    "provider_version": gcc_version,
                    "member_sha256": lib_provider_sha[lib_rel],
                    "pre_normalization_sha256":
                        lib_provider_sha[lib_rel],
                    "staged_sha256": observed[lib_rel],
                    "license": "GPL-3.0-only WITH GCC-exception-3.1",
                },
            },
            "runtime_licenses": {
                rel: {"sha256": sha256_file(os.path.join(staged, rel)),
                      "source": source}
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
            "files": {},
        }
        # Payload hashes come from the verification reads, never
        # from a live re-walk: bytes changed after verification
        # fail at archive time instead of shipping self-consistent.
        manifest["files"] = dict(observed)
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


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
