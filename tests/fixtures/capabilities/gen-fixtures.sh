#!/usr/bin/env bash
# Generate the evidence and manifest files under
# tests/fixtures/capabilities/. Deterministic; rerunning reproduces
# those files byte for byte. The test profile JSON, this script, and
# the README are hand-maintained and preserved across runs. Tabs in
# cpuinfo/format files are real 0x09 bytes via printf.
set -euo pipefail
ROOT="${1:?usage: $0 <capabilities-dir>}"
mkdir -p "$ROOT"

TAB="$(printf '\t')"

write_cpuinfo() {
  # $1 = file, $2 = extra flag tokens (may be empty)
  local extra="$2"
  {
    printf 'processor\t: 0\n'
    printf 'vendor_id\t: GenuineIntel\n'
    printf 'cpu family\t: 6\n'
    printf 'model\t\t: 142\n'
    printf 'model name\t: Fixture CPU Model One\n'
    printf 'flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc arch_perfmon nopl xtopology tsc_reliable nonstop_tsc cpuid pni pclmulqdq ssse3 cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx rdrand hypervisor lahf_lm abm invpcid_single pti fsgsbase avx2 invpcid rdseed clflushopt md_clear flush_l1d arch_capabilities%s\n' "$extra"
    printf '\n'
  } > "$1"
}

write_cpuinfo_decoy() {
  # $1 = file: ordinary flags plus a second processor whose model
  # name carries token-lookalike words. Pins that verdicts read
  # flags lines only (exact lowercase whole tokens), never model
  # text, across multi-block cpuinfo.
  write_cpuinfo "$1" ""
  {
    printf 'processor\t: 1\n'
    printf 'vendor_id\t: GenuineIntel\n'
    printf 'cpu family\t: 6\n'
    printf 'model\t\t: 142\n'
    printf 'model name\t: Decoy SEV_SNP sev snoop tdx_guest CPU\n'
    printf 'flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic\n'
    printf '\n'
  } >> "$1"
}

write_os_release() {
  cat > "$1" <<'EOF'
NAME="Ubuntu"
VERSION="24.04.1 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04.1 LTS"
VERSION_ID="24.04"
EOF
}

write_format() {
  # $1 = file, $2 = size value (4 or 8)
  {
    printf 'name: swiotlb_bounced\n'
    printf 'ID: 1901\n'
    printf 'format:\n'
    printf '%sfield:unsigned int test_field;%soffset:0;%ssize:%s;%ssigned:0;\n' "$TAB" "$TAB" "$TAB" "$2" "$TAB"
    printf '\n'
    printf 'print fmt: "test_field=%%u", REC->test_field\n'
  } > "$1"
}

write_meta() {
  # $1 = file, $2 = arch, $3 = release, $4 = euid, rest extra lines
  {
    printf 'arch=%s\n' "$2"
    printf 'release=%s\n' "$3"
    printf 'euid=%s\n' "$4"
    shift 4
    for line in "$@"; do printf '%s\n' "$line"; done
  } > "$1"
}

base_fixture() {
  # $1 = name; ordinary-shaped 7.0 evidence, caller tweaks afterwards.
  local d="$ROOT/$1"
  mkdir -p "$d/proc" "$d/etc" "$d/sys/kernel/btf" \
    "$d/sys/kernel/tracing/events/swiotlb/swiotlb_bounced"
  write_cpuinfo "$d/proc/cpuinfo" ""
  write_os_release "$d/etc/os-release"
  printf '1901\n' > "$d/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/id"
  write_format "$d/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format" 4
  printf 'fixture-btf-stand-in-v1\n' > "$d/sys/kernel/btf/vmlinux"
  write_meta "$d/meta.txt" "x86_64" "7.0.0-34-generic" "1001"
}

# 1. ordinary baseline (with model-text decoy block)
base_fixture ordinary-7.0
write_cpuinfo_decoy "$ROOT/ordinary-7.0/proc/cpuinfo"

# 2-4. guest technologies
base_fixture snp-7.0
mkdir -p "$ROOT/snp-7.0/dev"
: > "$ROOT/snp-7.0/dev/sev-guest"
write_cpuinfo "$ROOT/snp-7.0/proc/cpuinfo" " sme sev sev_snp"

base_fixture tdx-7.0
mkdir -p "$ROOT/tdx-7.0/dev"
: > "$ROOT/tdx-7.0/dev/tdx_guest"
write_cpuinfo "$ROOT/tdx-7.0/proc/cpuinfo" " tdx_guest"

base_fixture sev-classic-7.0
mkdir -p "$ROOT/sev-classic-7.0/dev"
: > "$ROOT/sev-classic-7.0/dev/sev-guest"
write_cpuinfo "$ROOT/sev-classic-7.0/proc/cpuinfo" " sme sev"

# 5. unavailable evidence: no cpuinfo, no nodes
base_fixture unavailable-evidence
rm "$ROOT/unavailable-evidence/proc/cpuinfo"
rmdir "$ROOT/unavailable-evidence/proc"

# 6-7. conflicting evidence
base_fixture conflicting-evidence
mkdir -p "$ROOT/conflicting-evidence/dev"
: > "$ROOT/conflicting-evidence/dev/sev-guest"
: > "$ROOT/conflicting-evidence/dev/tdx_guest"
write_cpuinfo "$ROOT/conflicting-evidence/proc/cpuinfo" " sme sev"

base_fixture conflicting-flags
mkdir -p "$ROOT/conflicting-flags/dev"
: > "$ROOT/conflicting-flags/dev/sev-guest"
# flags lack sev: node/flag contradiction

# 8-10. user assertions
base_fixture user-asserted-snp
rm "$ROOT/user-asserted-snp/proc/cpuinfo"
rmdir "$ROOT/user-asserted-snp/proc"
write_meta "$ROOT/user-asserted-snp/meta.txt" "x86_64" "7.0.0-34-generic" \
  "1001" "asserted_guest_tech=snp"

base_fixture user-asserted-agree
mkdir -p "$ROOT/user-asserted-agree/dev"
: > "$ROOT/user-asserted-agree/dev/sev-guest"
write_cpuinfo "$ROOT/user-asserted-agree/proc/cpuinfo" " sme sev sev_snp"
write_meta "$ROOT/user-asserted-agree/meta.txt" "x86_64" "7.0.0-34-generic" \
  "1001" "asserted_guest_tech=snp"

base_fixture user-asserted-conflict
mkdir -p "$ROOT/user-asserted-conflict/dev"
: > "$ROOT/user-asserted-conflict/dev/sev-guest"
write_cpuinfo "$ROOT/user-asserted-conflict/proc/cpuinfo" " sme sev sev_snp"
write_meta "$ROOT/user-asserted-conflict/meta.txt" "x86_64" "7.0.0-34-generic" \
  "1001" "asserted_guest_tech=tdx"

# 11-12. missing evidence
base_fixture missing-btf
rm "$ROOT/missing-btf/sys/kernel/btf/vmlinux"
rmdir "$ROOT/missing-btf/sys/kernel/btf"

base_fixture missing-tracepoint
rm -rf "$ROOT/missing-tracepoint/sys/kernel/tracing"

# 13-14. denied evidence (content held to prove denied-wins)
base_fixture denied-tracepoint
write_meta "$ROOT/denied-tracepoint/meta.txt" "x86_64" "7.0.0-34-generic" \
  "1001" "denied=/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"

base_fixture denied-guest-node
mkdir -p "$ROOT/denied-guest-node/dev"
: > "$ROOT/denied-guest-node/dev/sev-guest"
write_cpuinfo "$ROOT/denied-guest-node/proc/cpuinfo" " sme sev"
write_meta "$ROOT/denied-guest-node/meta.txt" "x86_64" "7.0.0-34-generic" \
  "1001" "denied=/dev/sev-guest"

# 15-16. signature fixtures (consumed with profiles-test/)
base_fixture changed-signature
write_format "$ROOT/changed-signature/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format" 8

base_fixture oversized-format
head -c 131073 /dev/zero \
  > "$ROOT/oversized-format/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"

base_fixture denied-id-changed
write_format "$ROOT/denied-id-changed/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format" 8
write_meta "$ROOT/denied-id-changed/meta.txt" "x86_64" "7.0.0-34-generic" \
  "1001" "denied=/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/id"

base_fixture conflicting-flags-sev-tdx
mkdir -p "$ROOT/conflicting-flags-sev-tdx/dev"
: > "$ROOT/conflicting-flags-sev-tdx/dev/sev-guest"
write_cpuinfo "$ROOT/conflicting-flags-sev-tdx/proc/cpuinfo" \
  " sme sev sev_snp tdx_guest"

base_fixture conflicting-flags-tdx-sev
mkdir -p "$ROOT/conflicting-flags-tdx-sev/dev"
: > "$ROOT/conflicting-flags-tdx-sev/dev/tdx_guest"
write_cpuinfo "$ROOT/conflicting-flags-tdx-sev/proc/cpuinfo" \
  " sme sev tdx_guest"

base_fixture ready-validated

# 17-19. identity fixtures
base_fixture kernel-6.8
write_meta "$ROOT/kernel-6.8/meta.txt" "x86_64" "6.8.0-41-generic" "1001"

base_fixture arch-mismatch
write_meta "$ROOT/arch-mismatch/meta.txt" "aarch64" "7.0.0-test" "1001"

base_fixture malformed-release
write_meta "$ROOT/malformed-release/meta.txt" "x86_64" "not-a-kernel-release" \
  "1001"

# Shared validated profiles dir for signature/ready tests.
mkdir -p "$ROOT/profiles-test"
printf 'test-validated.json\n' > "$ROOT/profiles-test/manifest.txt"

# Empty manifest dir.
mkdir -p "$ROOT/profiles-empty"
: > "$ROOT/profiles-empty/manifest.txt"

# Bad manifests.
mkdir -p "$ROOT/profiles-bad-manifest-blank"
printf 'test-validated.json\n\n' > "$ROOT/profiles-bad-manifest-blank/manifest.txt"
mkdir -p "$ROOT/profiles-bad-manifest-dup"
printf 'a.json\na.json\n' > "$ROOT/profiles-bad-manifest-dup/manifest.txt"
mkdir -p "$ROOT/profiles-bad-manifest-escape"
printf '../profiles-test/test-validated.json\n' > "$ROOT/profiles-bad-manifest-escape/manifest.txt"

# Bad profile document.
mkdir -p "$ROOT/profiles-bad-doc"
printf 'bad.json\n' > "$ROOT/profiles-bad-doc/manifest.txt"
printf '{"schema_version": "0.1.0", "profile_id": ' > "$ROOT/profiles-bad-doc/bad.json"

# Bad meta headers (meta.txt only; the reader fails before anything else).
mkdir -p "$ROOT/meta-bad-dup"
printf 'arch=x86_64\nrelease=7.0.0\narch=x86_64\neuid=1001\n' \
  > "$ROOT/meta-bad-dup/meta.txt"
mkdir -p "$ROOT/meta-bad-unknown-key"
printf 'arch=x86_64\nrelease=7.0.0\neuid=1001\nfrobnicate=yes\n' \
  > "$ROOT/meta-bad-unknown-key/meta.txt"
mkdir -p "$ROOT/meta-bad-euid-alpha"
printf 'arch=x86_64\nrelease=7.0.0\neuid=root\n' \
  > "$ROOT/meta-bad-euid-alpha/meta.txt"
mkdir -p "$ROOT/meta-bad-euid-huge"
printf 'arch=x86_64\nrelease=7.0.0\neuid=9999999999\n' \
  > "$ROOT/meta-bad-euid-huge/meta.txt"
mkdir -p "$ROOT/meta-bad-denied-relative"
printf 'arch=x86_64\nrelease=7.0.0\neuid=1001\ndenied=relative/path\n' \
  > "$ROOT/meta-bad-denied-relative/meta.txt"
mkdir -p "$ROOT/meta-bad-tech"
printf 'arch=x86_64\nrelease=7.0.0\neuid=1001\nasserted_guest_tech=sme\n' \
  > "$ROOT/meta-bad-tech/meta.txt"
mkdir -p "$ROOT/meta-bad-arch-long"
printf 'arch=%33s\nrelease=7.0.0\neuid=1001\n' " " | tr ' ' 'a' \
  > "$ROOT/meta-bad-arch-long/meta.txt"
mkdir -p "$ROOT/meta-bad-release-long"
printf 'arch=x86_64\nrelease=%129s\neuid=1001\n' " " | tr ' ' 'r' \
  > "$ROOT/meta-bad-release-long/meta.txt"
mkdir -p "$ROOT/meta-bad-denied-long"
printf 'arch=x86_64\nrelease=7.0.0\neuid=1001\ndenied=/%256s\n' " " \
  | tr ' ' 'd' > "$ROOT/meta-bad-denied-long/meta.txt"
mkdir -p "$ROOT/meta-bad-nul"
printf 'arch=x86_64\nrelease=ab\x00cd\neuid=1001\n' \
  > "$ROOT/meta-bad-nul/meta.txt"
mkdir -p "$ROOT/meta-bad-utf8"
printf 'arch=x86_64\nrelease=7.0\xff-beta\neuid=1001\n' \
  > "$ROOT/meta-bad-utf8/meta.txt"

# Release that is unsafe to interpolate into paths and carries a
# control byte, for the boot-config skip plus sanitizer coverage.
mkdir -p "$ROOT/meta-release-hostile"
printf 'arch=x86_64\nrelease=7.0/evil\x1b[0m\neuid=1001\n' \
  > "$ROOT/meta-release-hostile/meta.txt"

echo "wrote $(find "$ROOT" -type f | wc -l) files in $ROOT"
