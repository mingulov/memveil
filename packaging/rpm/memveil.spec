# SPDX-License-Identifier: GPL-3.0-or-later
# memveil third-party system package: the same FHS layout the
# .deb ships, so the installed binary resolves its bridge, BPF
# objects, and profiles with zero flags or environment.
#
# Build (on an x86-64 host with the contributor toolchain from
# docs/build.md; the conda/pixi Mojo toolchain cannot enter
# Fedora, so this package is built outside the archive):
#
#   git archive --prefix=memveil-0.1.0/ HEAD \
#       -o memveil-0.1.0.tar.gz   # Source0
#   # Source1: the libbpf-mojo tarball whose sha256 matches
#   # toolchain.lock.json (verified by tools/package at build).
#   rpmbuild -bb packaging/rpm/memveil.spec \
#       --define "_sourcedir $PWD" --define "_srcrpmdir $PWD"
#
# The Version tag tracks ENGINE_VERSION in
# src/memveil/model/report.mojo (bump together; the package
# gate fails otherwise). A git archive has no commit identity,
# so MANIFEST.json inside the build records revision "export".
#
# Private bundled libraries (bundled() convention): the Mojo
# runtime closure and libbpf_mojo.so.1 ship under
# /usr/lib/memveil for the FHS RUNPATH only. Auto-provides
# are off so they never satisfy other packages, auto-requires
# are off so the private SONAMEs never leak into the
# dependency set, and system deps stay manual exactly like the
# .deb (libelf, zlib, plus the versioned glibc floor the
# staged ELF files require). The floor uses the portable
# package-name form `glibc >= X.Y` (Fedora and SUSE share
# the glibc name with a comparable EVR) rather than the
# generator-spelled virtual `libc.so.6(GLIBC_X.Y)(64bit)`
# provide; its value is the max GLIBC_x.y need across the
# staged binary, bridge, and closure (see the .deb
# derivation and test_spec_glibc_floor_matches_payload),
# kept in sync by hand because the spec is static text.
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
# ships under /usr/share/doc/memveil (see the deb copyright
# file for the full attribution set).
License: GPL-3.0-or-later AND GPL-2.0-only
ExclusiveArch: x86_64
Source0: memveil-%{version}.tar.gz
Source1: libbpf-mojo-0.2.0.tar.gz
BuildRequires: binutils
BuildRequires: patchelf
BuildRequires: python3
Requires: libelf.so.1()(64bit), libz.so.1()(64bit), glibc >= 2.38

%description
Record swiotlb bounce activity, mapping lifetimes, and executed
copies into a self-describing capture directory, then replay it
offline as text, JSON, or Markdown. Counts are try-counts with
requested bytes; actual copies come from the copy channel.

Third-party binary package: the conda/pixi Mojo toolchain cannot
enter Fedora, so this .rpm is built outside the archive. Installed
runs need no flags or environment: profiles resolve from the
installed share dir and qualify receipts land under
/var/lib/memveil/receipts.

%prep
%setup -q

%build
export LMB_PACKAGE="%{SOURCE1}"
./tools/package --out %{_builddir}/bundle --tag bundle

%install
B="%{_builddir}/bundle/bundle"
test -f "$B/bin/memveil" || exit 1
test -f "$B/lib/libbpf_mojo.so.1" || exit 1
test -f "$B/profiles/manifest.txt" || exit 1
install -D -m0755 "$B/bin/memveil" "%{buildroot}/usr/bin/memveil"
patchelf --set-rpath '$ORIGIN/../lib/memveil' \
    "%{buildroot}/usr/bin/memveil"
mkdir -p "%{buildroot}/usr/lib/memveil"
cp -rp "$B"/lib/*.so* "%{buildroot}/usr/lib/memveil/"
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
 GPL-2.0-only (LICENSES/). Redistributed third-party texts,
 including the libbpf-mojo bridge license, live in licenses/,
 with notices in THIRD-PARTY-NOTICES.md
 and THIRD-PARTY-NOTICES.libbpf-mojo.md.
EOF
for text in LICENSE THIRD-PARTY-NOTICES.md \
    THIRD-PARTY-NOTICES.libbpf-mojo.md; do
  install -m0644 "$B/$text" "%{buildroot}/usr/share/doc/memveil/$text"
done
cp -rp "$B/LICENSES" "$B/licenses" \
    "%{buildroot}/usr/share/doc/memveil/"
./tools/gen-man --binary "%{buildroot}/usr/bin/memveil" \
    --out man-pages
mkdir -p "%{buildroot}/usr/share/man/man1"
install -m0644 man-pages/*.1 "%{buildroot}/usr/share/man/man1/"
./tools/gen-completions --out completions
install -D -m0644 completions/memveil \
    "%{buildroot}/usr/share/bash-completion/completions/memveil"
install -D -m0644 completions/_memveil \
    "%{buildroot}/usr/share/zsh/vendor-completions/_memveil"
mkdir -p "%{buildroot}/var/lib/memveil/receipts"
find "%{buildroot}" -type d -exec chmod 0755 {} +
find "%{buildroot}" -type f -exec chmod 0644 {} +
chmod 0755 "%{buildroot}/usr/bin/memveil"

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
%dir /usr/share/doc/memveil/licenses/libbpf-mojo-LICENSES
/usr/share/doc/memveil/copyright
/usr/share/doc/memveil/LICENSE
/usr/share/doc/memveil/THIRD-PARTY-NOTICES.md
/usr/share/doc/memveil/THIRD-PARTY-NOTICES.libbpf-mojo.md
/usr/share/doc/memveil/LICENSES/GPL-2.0-only.txt
/usr/share/doc/memveil/LICENSES/GPL-2.0-or-later.txt
/usr/share/doc/memveil/licenses/GPL-3.0.txt
/usr/share/doc/memveil/licenses/LICENSE.BSD-2-Clause.libbpf
/usr/share/doc/memveil/licenses/LICENSE.mojo-compiler
/usr/share/doc/memveil/licenses/LICENSE.zlib
/usr/share/doc/memveil/licenses/NOTICE.mojo-runtime.md
/usr/share/doc/memveil/licenses/RUNTIME.LIBRARY.EXCEPTION
/usr/share/doc/memveil/licenses/Third-Party-Notices.mojo-compiler
/usr/share/doc/memveil/licenses/libbpf-mojo-LICENSE
/usr/share/doc/memveil/licenses/libbpf-mojo-LICENSES/GPL-2.0-only.txt
/usr/share/doc/memveil/licenses/libbpf-mojo-LICENSES/LLVM-exception.txt
/usr/share/man/man1/memveil.1
/usr/share/man/man1/memveil-record.1
/usr/share/man/man1/memveil-report.1
/usr/share/man/man1/memveil-top.1
/usr/share/man/man1/memveil-doctor.1
/usr/share/man/man1/memveil-qualify.1
/usr/share/bash-completion/completions/memveil
/usr/share/zsh/vendor-completions/_memveil
%dir /var/lib/memveil
%dir /var/lib/memveil/receipts

%changelog
* Sun Oct 11 2026 Denis Mingulov <denis@mingulov.com> - 0.1.0-1
- Third-party build: FHS layout matching the .deb, generated man pages and
  static shell completions.
