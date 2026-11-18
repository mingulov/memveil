# SPDX-License-Identifier: GPL-3.0-or-later
# memveil third-party system package: the same FHS layout the
# .deb ships, so the installed binary resolves its runtime,
# BPF inspection objects, and profiles with zero flags or
# environment. The Rust userspace embeds its eBPF objects and
# links the Aya loader statically: no bridge ships, and the
# only private library is the toolchain libgcc.
#
# Build (on an x86-64 host with cargo, rpmbuild, and the
# repository pin; this package is built outside the archive):
#
#   cargo build --release --locked --offline   # in rust/
#   rust/scripts/package-tarball.py --out dist
#   rust/scripts/package-rpm.py --work build/rpm --out dist \
#       --bundle "$PWD/dist/memveil-0.1.0"
#
# The Version tag tracks the engine version printed by
# `memveil version` (bump together; the package gate fails
# otherwise). A git-free source tree records revision "export"
# in the bundle MANIFEST the build verifies.
#
# Private bundled libraries (bundled() convention): the single
# libgcc_s.so.1 ships under /usr/lib/memveil for the FHS
# RUNPATH only. Auto-provides are off so it never satisfies
# other packages, auto-requires are off so the private SONAME
# never leaks into the dependency set, and the system dep stays
# manual exactly like the .deb (the versioned glibc floor the
# staged ELF files require). The floor uses the portable
# package-name form `glibc >= X.Y` rather than the
# generator-spelled virtual `libc.so.6(GLIBC_X.Y)(64bit)`
# provide; its value is the max GLIBC_x.y need across the
# staged binary and lib (see the .deb derivation and
# spec_no_scriptlets_or_privilege), kept in sync by hand
# because the spec is static text.
# The AutoReq/AutoProv tags are the effective switch on rpm
# >= 4.9 (the __find_* nil globals predate the fileattrs
# generators and no longer suppress anything on their own);
# the nils stay as belt and braces for old rpm.
# No maintainer scriptlets: the private lib needs no
# ldconfig and no collection runs at install. No file
# capabilities and no set-uid bits anywhere.
%global __find_provides %{nil}
%global __find_requires %{nil}
AutoProv: no
AutoReq: no
# brp-strip would strip the BPF objects' symbol tables (the
# .deb gate pins them unstripped) and there is no debuginfo
# to split from this manual staging, so post-processing is
# off entirely; man pages ship uncompressed.
%global __os_install_post %{nil}

Name: memveil
Version: 0.1.0
Release: 1%{?dist}
Summary: swiotlb bounce-attempt capture and offline replay on x86-64 Linux
# The two code licenses; every redistributed third-party text
# ships under /usr/share/doc/memveil (see the copyright file
# for the full attribution set).
License: GPL-3.0-or-later AND GPL-2.0-only
ExclusiveArch: x86_64
Source0: memveil-%{version}.tar.gz
BuildRequires: binutils
BuildRequires: python3
Requires: glibc >= 2.35

%description
Record swiotlb bounce activity, mapping lifetimes, and executed
copies into a self-describing capture directory, then replay it
offline as text, JSON, or Markdown. Counts are try-counts with
requested bytes; actual copies come from the copy channel.

Third-party binary package: built outside the archive from the
MemVeil sources with the pinned Rust toolchain. Installed
runs need no flags or environment: profiles resolve from the
installed share dir and qualify receipts land under
/var/lib/memveil/receipts.

%prep
%setup -q

%build
B="${MEMVEIL_CANONICAL_BUNDLE:?Supply a canonical bundle with package-rpm.py --bundle}"
python3 - "$B" <<'EOF'
import hashlib
import json
import os
import sys

bundle = sys.argv[1]
try:
    with open(os.path.join(bundle, "MANIFEST.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
except (OSError, ValueError) as exc:
    sys.exit("bundle MANIFEST unreadable: %s" % exc)
if not manifest.get("engine_version") or not manifest.get("files"):
    sys.exit("bundle MANIFEST lacks identity")
for rel, want in sorted(manifest["files"].items()):
    full = os.path.join(bundle, rel)
    digest = hashlib.sha256()
    try:
        with open(full, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError:
        sys.exit("bundle payload unreadable: %s" % rel)
    if digest.hexdigest() != want:
        sys.exit("bundle payload differs from MANIFEST: %s" % rel)
print("bundle %s verified (%d files)" % (manifest.get("bundle"), len(manifest["files"])))
EOF

%install
B="${MEMVEIL_CANONICAL_BUNDLE:?Canonical bundle directory is required}"
test -f "$B/bin/memveil" || exit 1
test -f "$B/lib/memveil/libgcc_s.so.1" || exit 1
test -f "$B/profiles/manifest.txt" || exit 1
install -D -m0755 "$B/bin/memveil" "%{buildroot}/usr/bin/memveil"
mkdir -p "%{buildroot}/usr/lib/memveil"
cp -rp "$B"/lib/memveil/*.so* "%{buildroot}/usr/lib/memveil/"
for obj in swiotlb_attempt.bpf.o swiotlb_lifecycle.bpf.o \
    swiotlb_copy.bpf.o; do
  test -f "$B/bpf/$obj" || exit 1
  install -m0644 "$B/bpf/$obj" "%{buildroot}/usr/lib/memveil/$obj"
done
mkdir -p "%{buildroot}/usr/share/memveil/profiles"
cp -rp "$B"/profiles/* "%{buildroot}/usr/share/memveil/profiles/"
mkdir -p "%{buildroot}/usr/share/memveil/docs"
cp -rp "$B"/docs/. "%{buildroot}/usr/share/memveil/docs/"
mkdir -p "%{buildroot}/usr/share/memveil/docs/examples"
cp -rp "$B/examples/real-capture" \
    "%{buildroot}/usr/share/memveil/docs/examples/real-capture"
cp -rp "$B/examples/lifecycle-copy" \
    "%{buildroot}/usr/share/memveil/docs/examples/lifecycle-copy"
mkdir -p "%{buildroot}/usr/share/doc/memveil"
cat > "%{buildroot}/usr/share/doc/memveil/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Source: third-party binary build; see the source RPM for the exact revision

Files: *
Copyright: See LICENSE and THIRD-PARTY-NOTICES.md in this directory.
License: GPL-3.0-or-later
 The MemVeil sources are available under GPL-3.0-or-later; the full
 license text is in LICENSE. On Debian systems the GPL-3 text is
 also in /usr/share/common-licenses/GPL-3. BPF objects are
 GPL-2.0-only (LICENSES/). The shipped libgcc runtime library is
 GPL-3.0-only WITH GCC-exception-3.1 (licenses/), with notices in
 THIRD-PARTY-NOTICES.md.
EOF
for text in LICENSE THIRD-PARTY-NOTICES.md; do
  install -m0644 "$B/$text" "%{buildroot}/usr/share/doc/memveil/$text"
done
cp -rp "$B/LICENSES" "$B/licenses" \
    "%{buildroot}/usr/share/doc/memveil/"
python3 rust/scripts/gen-man.py --binary "%{buildroot}/usr/bin/memveil" \
    --out man-pages
mkdir -p "%{buildroot}/usr/share/man/man1"
install -m0644 man-pages/*.1 "%{buildroot}/usr/share/man/man1/"
python3 rust/scripts/gen-completions.py --out completions
install -D -m0644 completions/memveil \
    "%{buildroot}/usr/share/bash-completion/completions/memveil"
install -D -m0644 completions/_memveil \
    "%{buildroot}/usr/share/zsh/vendor-completions/_memveil"
mkdir -p "%{buildroot}/var/lib/memveil/receipts"
# Five octal digits clear inherited directory setgid bits.
find "%{buildroot}" -type d -exec chmod 00755 {} +
find "%{buildroot}" -type f -exec chmod 0644 {} +
chmod 0755 "%{buildroot}/usr/bin/memveil"
# Every staged payload byte must still equal the verified
# bundle MANIFEST entry it was copied from (generated man
# pages, completions, copyright, and changelog have no
# bundle source and are excluded by the mapping).
python3 - "$B" "%{buildroot}" <<'EOF'
import hashlib
import json
import os
import sys

bundle, root = sys.argv[1], sys.argv[2]
with open(os.path.join(bundle, "MANIFEST.json"), encoding="utf-8") as handle:
    manifest = json.load(handle)
files = manifest["files"]


def source(installed):
    if installed == "usr/bin/memveil":
        return "bin/memveil"
    if installed.startswith("usr/lib/memveil/"):
        leaf = installed[len("usr/lib/memveil/"):]
        if leaf.endswith(".bpf.o"):
            return "bpf/" + leaf
        return "lib/memveil/" + leaf
    if installed.startswith("usr/share/memveil/profiles/"):
        return "profiles/" + installed[len("usr/share/memveil/profiles/"):]
    if installed.startswith("usr/share/memveil/docs/examples/"):
        return "examples/" + installed[len("usr/share/memveil/docs/examples/"):]
    if installed.startswith("usr/share/memveil/docs/"):
        return "docs/" + installed[len("usr/share/memveil/docs/"):]
    if installed.startswith("usr/share/doc/memveil/"):
        leaf = installed[len("usr/share/doc/memveil/"):]
        if leaf in ("copyright", "changelog.Debian.gz"):
            return None
        return leaf
    return None


checked = 0
for base, _, names in os.walk(root):
    for name in sorted(names):
        full = os.path.join(base, name)
        rel = os.path.relpath(full, root)
        origin = source(rel)
        if origin is None:
            continue
        want = files.get(origin)
        if want is None:
            sys.exit("staged file has no bundle origin: %s" % rel)
        digest = hashlib.sha256()
        with open(full, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        if digest.hexdigest() != want:
            sys.exit("staged file differs from bundle: %s" % rel)
        checked += 1
print("installed payload matches the bundle (%d files)" % checked)
EOF

%files
%defattr(-,root,root,-)
%dir /usr/lib/memveil
/usr/lib/memveil/*.so*
/usr/lib/memveil/*.bpf.o
/usr/bin/memveil
%dir /usr/share/memveil
/usr/share/memveil/profiles/
/usr/share/memveil/docs/
%dir /usr/share/doc/memveil
%dir /usr/share/doc/memveil/LICENSES
%dir /usr/share/doc/memveil/licenses
/usr/share/doc/memveil/copyright
/usr/share/doc/memveil/LICENSE
/usr/share/doc/memveil/THIRD-PARTY-NOTICES.md
/usr/share/doc/memveil/LICENSES/GPL-2.0-only.txt
/usr/share/doc/memveil/LICENSES/GPL-2.0-or-later.txt
/usr/share/doc/memveil/LICENSES/GPL-2.0.txt
/usr/share/doc/memveil/licenses/GPL-3.0.txt
/usr/share/doc/memveil/licenses/RUNTIME.LIBRARY.EXCEPTION
/usr/share/man/man1/memveil.1
/usr/share/man/man1/memveil-record.1
/usr/share/man/man1/memveil-report.1
/usr/share/man/man1/memveil-top.1
/usr/share/man/man1/memveil-doctor.1
/usr/share/man/man1/memveil-qualify.1
/usr/share/man/man1/memveil-bind-profile.1
/usr/share/bash-completion/completions/memveil
/usr/share/zsh/vendor-completions/_memveil
%dir /var/lib/memveil
%dir /var/lib/memveil/receipts

%changelog
* Wed Nov 18 2026 Denis Mingulov <denis@mingulov.com> - 0.1.0-1
- Third-party build: FHS layout matching the .deb, generated man pages and
  static shell completions (Rust userspace, statically linked Aya loader).
