#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build the third-party memveil .deb from the Rust owner bundle.

Runs rust/scripts/package-tarball.py (pinned Cargo closure,
checked lib set, license texts, MANIFEST.json) and rearranges
the staged tree into the installed FHS layout the discovery
code resolves with zero flags or environment::

    usr/bin/memveil                 binary (RUNPATH $ORIGIN/../lib/memveil),
                                    stripped
    usr/lib/memveil/*.so*           Rust closure (the toolchain libgcc_s
                                    only), stripped (--strip-unneeded)
    usr/lib/memveil/*.bpf.o         Aya BPF inspection objects (attempt,
                                    lifecycle, copy) beside the runtime:
                                    arch-dependent ELF under /usr/share
                                    is a packaging error
    usr/share/memveil/profiles/     manifest plus shipped profiles
    usr/share/memveil/docs/         the full manuals tree plus the worked
                                    examples (docs/examples/real-capture
                                    and docs/examples/lifecycle-copy)
    usr/share/doc/memveil/          copyright stub plus every license and
                                    notice text the bundle redistributes,
                                    plus the generated changelog.Debian.gz
                                    non-native packages must ship
    usr/share/man/man1/             memveil.1 plus one memveil-<verb>.1
                                    per verb, generated at build time
                                    from the --help texts
    usr/share/bash-completion/      static memveil completions from the
    completions/ + zsh              frozen verb/flag sets (bash plus
    vendor-completions/             zsh vendor dir)
    usr/share/lintian/overrides/    justified lintian overrides (BPF arch
    memveil                         false positive, uncompressed man)
    var/lib/memveil/receipts/       empty state dir (0755 root:root)

Control notes: manual ``Depends: libc6 (>= X.Y)`` (the libc6
floor is derived at build time from the staged ELF files,
never hardcoded; the private libgcc needs no system
counterpart); no maintainer scripts (the private lib needs no
ldconfig, no collection runs at install); DEBIAN/md5sums is
generated over the payload for dpkg --verify; no setuid bits
or file capabilities. X-Memveil-Revision records the exact
source, X-Memveil-Cargo-Lock the Cargo.lock bytes, and
X-Memveil-Build-Tools the assembly dpkg-deb version and the
canonical payload normalizer patchelf version.

Third-party origin: this package is built outside the archive
from the MemVeil sources with the pinned Rust toolchain.
Installed runs need no flags or environment: profiles resolve
from the installed share dir and qualify receipts land under
/var/lib/memveil/receipts. Man pages are generated at build
time from the --help texts (rust/scripts/gen-man.py) and
completions from the frozen verb/flag sets
(rust/scripts/gen-completions.py); the same generators feed
the .rpm, so both formats ship identical pages.

Usage: rust/scripts/package-deb.py [--out DIR] [--tag STEM] [--bundle DIR]
    [--root DIR] [--binary PATH] [--bpf-dir DIR] [--build]
  --bundle DIR  consume an existing verified bundle without building
  --out DIR   output directory (default: rust/dist/)
  --tag STEM  .deb file stem (default: memveil_<version>-1_amd64)
  --root/--binary/--bpf-dir/--build  bundle-build inputs, used only
      without --bundle (see package-tarball.py)

Requires a clean tree (enforced by the bundle build) when
--bundle is omitted. Consuming --bundle requires only Python,
readelf and dpkg-deb; no compiler or ELF rewrite runs.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
RUN_RUST_DIR = os.path.dirname(HERE)

PACKAGE = "memveil"
SECTION = "utils"
PRIORITY = "optional"
ARCH = "amd64"
MAINTAINER = "Denis Mingulov <denis@mingulov.com>"

BPF_OBJECTS = (
    "swiotlb_attempt.bpf.o",
    "swiotlb_lifecycle.bpf.o",
    "swiotlb_copy.bpf.o",
)

CLOSURE_LIB = "libgcc_s.so.1"


def fail(message):
    print("package-deb: %s" % message, file=sys.stderr)
    sys.exit(1)


def run(argv, **kwargs):
    proc = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, **kwargs,
    )
    return proc


def parse_glibc_floor(version_info):
    """Max GLIBC_x.y need in readelf -V output, as (x, y) or None.

    Pure parser over the `.gnu.version_r` listing: every
    `GLIBC_<major>.<minor>` token is a minimum libc the
    file must load against, so the max wins. Non-glibc
    tokens (ELFUTILS_, GCC_, GLIBC_PRIVATE) never match.
    """
    floor = None
    for major, minor in re.findall(r"GLIBC_(\d+)\.(\d+)",
                                   version_info):
        need = (int(major), int(minor))
        if floor is None or need > floor:
            floor = need
    return floor


def glibc_floor(paths):
    """Max GLIBC_x.y need across staged ELF files, as "X.Y".

    Runs readelf -V over the staged binary plus every
    shipped .so and takes the max, so the Depends libc6
    floor always matches the bytes being shipped, never a
    stale literal. Fails closed when readelf fails or no
    GLIBC need is found.
    """
    floor = None
    for path in sorted(paths):
        proc = run(["readelf", "-V", path])
        if proc.returncode != 0:
            fail("readelf -V failed on %s:\n%s"
                 % (path, proc.stderr))
        need = parse_glibc_floor(proc.stdout)
        if need is not None and (floor is None or need > floor):
            floor = need
    if floor is None:
        fail("no GLIBC version need in staged ELF: %s"
             % sorted(paths))
    return "%d.%d" % floor


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_stem(stem):
    """.deb file stem: a single safe path segment."""
    if not stem or stem in (".", ".."):
        raise ValueError("bad .deb stem %r" % stem)
    if "/" in stem or "\\" in stem or "\x00" in stem:
        raise ValueError("bad .deb stem %r" % stem)
    if stem.startswith("-"):
        raise ValueError("bad .deb stem %r" % stem)
    return stem


def validate_upstream(version):
    """Upstream version: Debian-safe dotted identifier."""
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+~]*", version):
        raise ValueError("bad upstream version %r" % version)
    return version


def contained(path, directory):
    """True when path stays inside directory after normalization."""
    base = os.path.realpath(directory)
    full = os.path.realpath(path)
    return full == base or full.startswith(base + os.sep)


def fix_modes(root):
    """Staging modes: dirs 0755, files 0644, binary 0755.

    Ownership is forced to root:root by dpkg-deb
    --root-owner-group at build time, so no chown (and no
    privilege) is needed here.
    """
    binary = os.path.join(root, "usr", "bin", "memveil")
    for base, dirs, files in os.walk(root):
        for name in dirs:
            os.chmod(os.path.join(base, name), 0o755)
        for name in files:
            full = os.path.join(base, name)
            if os.path.realpath(full) == os.path.realpath(binary):
                os.chmod(full, 0o755)
            else:
                os.chmod(full, 0o644)
    os.chmod(root, 0o755)


def write_md5sums(root):
    """DEBIAN/md5sums over every payload file (dpkg --verify).

    debhelper's dh_md5sums normally writes this; raw staging
    generates the same "<md5>  <path>" lines with root-relative
    paths, sorted, covering payload files only (never DEBIAN/).
    """
    entries = []
    for base, _, files in os.walk(root):
        for name in sorted(files):
            full = os.path.join(base, name)
            rel = os.path.relpath(full, root)
            if rel == "DEBIAN" or rel.startswith("DEBIAN/"):
                continue
            digest = hashlib.md5()
            with open(full, "rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
            entries.append("%s  %s\n" % (digest.hexdigest(), rel))
    entries.sort(key=lambda line: line.split("  ", 1)[1])
    with open(os.path.join(root, "DEBIAN", "md5sums"), "w") as handle:
        handle.writelines(entries)


def changelog_epoch():
    """Changelog clock: SOURCE_DATE_EPOCH or the current time.

    Honors the reproducible-builds epoch when set and
    falls back to now, so a pinned environment regenerates
    the same entry while ordinary builds stamp build time.
    """
    import time

    try:
        return int(os.environ.get("SOURCE_DATE_EPOCH") or time.time())
    except ValueError:
        return int(time.time())


def changelog_text(upstream, memveil_rev, epoch):
    """The Debian changelog entry for this third-party build.

    Non-native packages must ship changelog.Debian.gz
    (lintian no-changelog); the single entry names the
    engine version, the bundle revision, and the control
    maintainer.
    """
    import datetime
    import email.utils

    stamp = email.utils.format_datetime(
        datetime.datetime.fromtimestamp(
            epoch, tz=datetime.timezone.utc))
    lines = [
        "memveil (%s-1) unstable; urgency=medium" % upstream,
        "",
        "  * Third-party binary build from memveil revision:",
        "    %s" % memveil_rev,
        "",
        " -- %s  %s" % (MAINTAINER, stamp),
        "",
    ]
    return "\n".join(lines)


def write_changelog(licdir, upstream, memveil_rev):
    """Gzip the Debian changelog into the doc dir (mtime pinned).

    Policy wants changelog.Debian.gz; the gzip mtime is the
    changelog clock so SOURCE_DATE_EPOCH pins the bytes.
    """
    import gzip
    import io

    epoch = changelog_epoch()
    text = changelog_text(upstream, memveil_rev, epoch)
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", compresslevel=9,
                       mtime=epoch, fileobj=buffer) as handle:
        handle.write(text.encode("utf-8"))
    with open(os.path.join(licdir, "changelog.Debian.gz"),
              "wb") as handle:
        handle.write(buffer.getvalue())


def tool_line(argv):
    """First version line of a required packaging tool.

    Fails closed when the tool errors or prints no version:
    the .deb records the exact packager versions, never a
    blank.
    """
    proc = run(argv)
    if proc.returncode != 0:
        fail("%s --version failed" % argv[0])
    text = proc.stdout if proc.stdout.strip() else proc.stderr
    first = text.splitlines()[0].strip() if text.strip() else ""
    if not first:
        fail("%s printed no version" % argv[0])
    return first


def read_template(name):
    """rust/packaging/deb/<name> text, failing closed when absent."""
    path = os.path.join(RUN_RUST_DIR, "packaging", "deb", name)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        fail("packaging template unreadable: %s (%s)" % (name, exc))


def control_text(upstream, depends, memveil_rev, cargo_lock,
                 build_tools):
    """DEBIAN/control rendered from control.in (no tokens survive)."""
    text = read_template("control.in")
    for token, value in (
            ("@UPSTREAM@", upstream),
            ("@DEPENDS@", depends),
            ("@REVISION@", memveil_rev),
            ("@CARGO_LOCK@", cargo_lock),
            ("@BUILD_TOOLS@", build_tools)):
        text = text.replace(token, value)
    leftover = re.search(r"@[A-Z_]+@", text)
    if leftover:
        fail("control template has unsubstituted token %s"
             % leftover.group(0))
    if not text.endswith("\n"):
        text += "\n"
    return text


def verify_bundle(bundle):
    """Bundle MANIFEST re-verified; returns the manifest dict.

    Every MANIFEST files[] entry must exist with matching
    bytes: the .deb stages verified bundle bytes only.
    """
    manifest_path = os.path.join(bundle, "MANIFEST.json")
    try:
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, ValueError) as exc:
        fail("bundle MANIFEST unreadable: %s" % exc)
    if not manifest.get("engine_version") \
            or not manifest.get("memveil_revision") \
            or not manifest.get("files"):
        fail("bundle MANIFEST lacks identity")
    for rel, want in sorted(manifest["files"].items()):
        full = os.path.join(bundle, rel)
        if not os.path.isfile(full) or os.path.islink(full):
            fail("bundle payload missing: %s" % rel)
        if sha256_file(full) != want:
            fail("bundle payload differs from MANIFEST: %s" % rel)
    for key in ("cargo", "packaging_tools"):
        if key not in manifest:
            fail("bundle MANIFEST lacks %s" % key)
    try:
        patchelf = manifest["packaging_tools"]["patchelf"]["version"]
        lock = manifest["cargo"]["lock_sha256"]
    except (KeyError, TypeError):
        fail("bundle MANIFEST lacks tool/cargo identity")
    if not patchelf or not lock:
        fail("bundle MANIFEST lacks tool/cargo identity")
    return manifest


def main(argv):
    canonical_bundle = None
    out_dir = None
    stem = None
    passthrough = []
    args = list(argv)
    while args:
        opt = args.pop(0)
        if opt in ("--help", "-h"):
            print(__doc__)
            return 0
        if opt == "--bundle" and args:
            canonical_bundle = os.path.abspath(args.pop(0))
            continue
        if opt == "--out" and args:
            out_dir = args.pop(0)
            continue
        if opt == "--tag" and args:
            stem = args.pop(0)
            continue
        if opt in ("--root", "--binary", "--bpf-dir") and args:
            passthrough += [opt, args.pop(0)]
            continue
        if opt == "--build":
            passthrough.append(opt)
            continue
        fail("unknown option: %s" % opt)
    if canonical_bundle is not None and passthrough:
        fail("--bundle cannot combine with bundle-build options "
             "(--root/--binary/--bpf-dir/--build)")
    if shutil.which("dpkg-deb") is None:
        fail("dpkg-deb is required to assemble the .deb")
    if shutil.which("readelf") is None:
        fail("readelf is required to verify the FHS binary")
    build_tools = "dpkg-deb=%s" % tool_line(["dpkg-deb", "--version"])

    work = tempfile.mkdtemp(prefix="memveil-deb-")
    try:
        bundle = canonical_bundle
        if bundle is None:
            bundle_parent = os.path.join(work, "bundle-build")
            os.makedirs(bundle_parent)
            build = run([os.path.join(HERE, "package-tarball.py"),
                         "--out", bundle_parent, "--tag", "bundle"]
                        + passthrough)
            if build.returncode != 0:
                print(build.stdout)
                print(build.stderr, file=sys.stderr)
                fail("package-tarball.py failed")
            bundle = os.path.join(bundle_parent, "bundle")
        manifest = verify_bundle(bundle)
        try:
            upstream = validate_upstream(
                manifest["engine_version"])
        except ValueError as err:
            fail(str(err))
        build_tools += "; patchelf=" + manifest[
            "packaging_tools"]["patchelf"]["version"]
        memveil_rev = manifest["memveil_revision"]
        cargo_lock = manifest["cargo"]["lock_sha256"]
        if stem is None:
            stem = "%s_%s-1_%s" % (PACKAGE, upstream, ARCH)
        try:
            validate_stem(stem)
        except ValueError as err:
            fail(str(err))
        if out_dir is None:
            out_dir = os.path.join(RUN_RUST_DIR, "dist")

        root = os.path.join(work, "root")
        bindir = os.path.join(root, "usr", "bin")
        libdir = os.path.join(root, "usr", "lib", "memveil")
        profdir = os.path.join(root, "usr", "share", "memveil",
                               "profiles")
        docdir = os.path.join(root, "usr", "share", "memveil", "docs")
        licdir = os.path.join(root, "usr", "share", "doc", "memveil")
        receipts = os.path.join(root, "var", "lib", "memveil",
                                "receipts")
        debdir = os.path.join(root, "DEBIAN")
        for path in (bindir, libdir, profdir, docdir, licdir,
                     receipts, debdir):
            os.makedirs(path)

        for name in sorted(os.listdir(os.path.join(bundle, "lib", "memveil"))):
            shutil.copy2(os.path.join(bundle, "lib", "memveil", name),
                         os.path.join(libdir, name))
        if not os.path.isfile(os.path.join(libdir, CLOSURE_LIB)):
            fail("staged lib/ lacks the closure library")

        binary = os.path.join(bindir, "memveil")
        shutil.copy2(os.path.join(bundle, "bin", "memveil"), binary)

        for name in BPF_OBJECTS:
            src = os.path.join(bundle, "bpf", name)
            if not os.path.isfile(src):
                fail("bundle lacks BPF object %s" % name)
            shutil.copy2(src, os.path.join(libdir, name))
        for name in sorted(os.listdir(
                os.path.join(bundle, "profiles"))):
            shutil.copy2(os.path.join(bundle, "profiles", name),
                         os.path.join(profdir, name))
        if not os.path.isfile(os.path.join(profdir, "manifest.txt")):
            fail("staged profiles/ lacks manifest.txt")
        for base, dirs, files in os.walk(
                os.path.join(bundle, "docs")):
            dirs.sort()
            for name in sorted(files):
                src = os.path.join(base, name)
                rel = os.path.relpath(
                    src, os.path.join(bundle, "docs"))
                dest = os.path.join(docdir, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copy2(src, dest)
        for leaf in ("real-capture", "lifecycle-copy"):
            shutil.copytree(os.path.join(bundle, "examples", leaf),
                            os.path.join(docdir, "examples", leaf))
        with open(os.path.join(licdir, "copyright"), "w") as handle:
            handle.write(read_template("copyright"))
        for name in ("LICENSE", "THIRD-PARTY-NOTICES.md"):
            shutil.copy2(os.path.join(bundle, name),
                         os.path.join(licdir, name))
        for name in ("LICENSES", "licenses"):
            shutil.copytree(os.path.join(bundle, name),
                            os.path.join(licdir, name))
        rerun = run([binary, "version"])
        if rerun.returncode != 0 \
                or rerun.stdout.strip() != "memveil-" + upstream:
            fail("FHS binary fails to start after staging: %r"
                 % rerun.stdout)
        write_changelog(licdir, upstream, memveil_rev)

        mandir = os.path.join(root, "usr", "share", "man", "man1")
        os.makedirs(mandir)
        gen_man = run([os.path.join(HERE, "gen-man.py"),
                       "--binary", binary, "--out", mandir])
        if gen_man.returncode != 0:
            print(gen_man.stdout)
            print(gen_man.stderr, file=sys.stderr)
            fail("gen-man.py failed")
        comp_parent = os.path.join(work, "completions")
        os.makedirs(comp_parent)
        gen_comp = run([os.path.join(HERE, "gen-completions.py"),
                        "--out", comp_parent])
        if gen_comp.returncode != 0:
            print(gen_comp.stdout)
            print(gen_comp.stderr, file=sys.stderr)
            fail("gen-completions.py failed")
        bashcomp = os.path.join(root, "usr", "share",
                                "bash-completion", "completions")
        zshcomp = os.path.join(root, "usr", "share", "zsh",
                               "vendor-completions")
        os.makedirs(bashcomp)
        os.makedirs(zshcomp)
        shutil.copy2(os.path.join(comp_parent, "memveil"),
                     os.path.join(bashcomp, "memveil"))
        shutil.copy2(os.path.join(comp_parent, "_memveil"),
                     os.path.join(zshcomp, "_memveil"))
        overdir = os.path.join(root, "usr", "share", "lintian",
                               "overrides")
        os.makedirs(overdir)
        with open(os.path.join(overdir, "memveil"), "w") as handle:
            handle.write(read_template("lintian-overrides"))
        staged_elf = [binary]
        for name in sorted(os.listdir(libdir)):
            if re.fullmatch(r"[^/]+\.so(\..*)?", name) \
                    and os.path.isfile(
                        os.path.join(libdir, name)):
                staged_elf.append(os.path.join(libdir, name))
        depends = "libc6 (>= %s)" % glibc_floor(staged_elf)
        with open(os.path.join(debdir, "control"), "w") as handle:
            handle.write(control_text(upstream, depends,
                                      memveil_rev, cargo_lock,
                                      build_tools))

        write_md5sums(root)
        fix_modes(root)
        out = os.path.join(out_dir, stem + ".deb")
        if not contained(out, out_dir):
            fail(".deb target escapes output dir: %s" % stem)
        os.makedirs(out_dir, exist_ok=True)
        if os.path.exists(out):
            os.remove(out)
        deb = run(["dpkg-deb", "--root-owner-group", "--build",
                   root, out])
        if deb.returncode != 0:
            print(deb.stdout)
            print(deb.stderr, file=sys.stderr)
            fail("dpkg-deb --build failed")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print("package-deb: %s" % out)
    print("package-deb: sha256 %s" % sha256_file(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
