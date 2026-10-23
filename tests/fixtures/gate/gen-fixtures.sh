#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Generate the kernel-gate fixture trees under tests/fixtures/gate/.
# Deterministic; rerunning reproduces every tree byte for byte.
# This script and the README are hand-maintained and preserved.
# Run: tests/fixtures/gate/gen-fixtures.sh tests/fixtures/gate
set -euo pipefail
GATE="${1:?usage: $0 <gate-dir>}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$ROOT/tests/fixtures/scan/live38"
mkdir -p "$GATE"

# Every generated tree; later tasks extend this list alongside
# their variants. Only these directories are ever removed.
VARIANTS="base ftrace-off ftrace-denied ftrace-malformed aff-dup aff-module aff-clone aff-prefix debugfs-root debug-denied lockdown-conf lockdown-integrity lockdown-nosecfs lockdown-dashdash lockdown-config lockdown-nolsm lockdown-twobrackets lockdown-bogus lockdown-denied notracing-config notracing-bpfevents tracefs-noevents tracefs-unmounted tracefs-hidden tracefs-gone events-denied btf-absent-config btf-absent-unknown btf-not-visible btf-denied btf-split btf-truncated hook-absent hook-not-in-btf hook-clone hook-nokallsyms denied-all container-view format-denied id-absent cc-flags-nonode cc-tdx-nonode cc-flags-host cc-tsm caps-none caps-bpf-perfmon caps-sysadmin caps-malformed caps-short memcg-small memcg-ancestor memcg-malformed memcg-huge memcg-empty memcg-v1 unpriv-bpf swiotlb-noforce swiotlb-inactive"
for v in $VARIANTS; do
  rm -rf "$GATE/$v"
done

cp -R "$SRC" "$GATE/base"
mkdir -p "$GATE/base/proc/self" "$GATE/base/sys/fs/cgroup/mvt.slice" \
  "$GATE/base/sys/kernel/security"
printf '1\n' > "$GATE/base/proc/sys/kernel/ftrace_enabled"
{
  printf 'Name:\tmvt-probe\n'
  printf 'State:\tR (running)\n'
  printf 'CapEff:\t000001ffffffffff\n'
} > "$GATE/base/proc/self/status"
printf '0::/mvt.slice\n' > "$GATE/base/proc/self/cgroup"
printf 'max\n' > "$GATE/base/sys/fs/cgroup/mvt.slice/memory.max"
printf '0\n' > "$GATE/base/sys/fs/cgroup/mvt.slice/memory.current"
printf '[none] integrity confidentiality\n' \
  > "$GATE/base/sys/kernel/security/lockdown"
{
  printf 'tracefs /sys/kernel/tracing tracefs rw,nosuid,nodev,noexec,relatime 0 0\n'
  printf 'securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0\n'
} > "$GATE/base/proc/mounts"
printf 'BOOT_IMAGE=/vmlinuz root=/dev/vda1\n' > "$GATE/base/proc/cmdline"

mk() {
  cp -R "$GATE/base" "$GATE/$1"
}

write_gate_cpuinfo() {
  # $1 = file, $2 = extra flag tokens (with leading blank, may be empty).
  # Base flags carry no hypervisor/sev/tdx token; variants add them.
  local extra="$2"
  {
    printf 'processor\t: 0\n'
    printf 'vendor_id\t: GenuineIntel\n'
    printf 'model name\t: Fixture CPU Model One\n'
    printf 'flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc arch_perfmon nopl xtopology tsc_reliable nonstop_tsc cpuid pni pclmulqdq ssse3 cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx rdrand lahf_lm abm invpcid_single pti fsgsbase avx2 invpcid rdseed clflushopt md_clear flush_l1d arch_capabilities%s\n' "$extra"
    printf '\n'
  } > "$1"
}

mk ftrace-off
printf '0\n' > "$GATE/ftrace-off/proc/sys/kernel/ftrace_enabled"

mk ftrace-denied
printf 'denied=/proc/sys/kernel/ftrace_enabled\n' >> "$GATE/ftrace-denied/meta.txt"

mk ftrace-malformed
printf 'x\n' > "$GATE/ftrace-malformed/proc/sys/kernel/ftrace_enabled"

mk aff-dup
printf 'swiotlb_tbl_map_single\n' \
  >> "$GATE/aff-dup/sys/kernel/tracing/available_filter_functions"

mk aff-module
sed -i 's/^swiotlb_tbl_map_single$/swiotlb_tbl_map_single [swiotlb]/' \
  "$GATE/aff-module/sys/kernel/tracing/available_filter_functions"

mk aff-clone
sed -i 's/^swiotlb_tbl_map_single$/swiotlb_tbl_map_single.isra.0/' \
  "$GATE/aff-clone/sys/kernel/tracing/available_filter_functions"

mk aff-prefix
AFF="$GATE/aff-prefix/sys/kernel/tracing/available_filter_functions"
printf '%s\n%s' "$(cat "$AFF")" 'swiotlb_tbl_map_single_x' > "$AFF"

mk debugfs-root
mkdir -p "$GATE/debugfs-root/sys/kernel/debug"
mv "$GATE/debugfs-root/sys/kernel/tracing" \
  "$GATE/debugfs-root/sys/kernel/debug/tracing"
mkdir -p "$GATE/debugfs-root/sys/kernel/tracing"

mk debug-denied
mkdir -p "$GATE/debug-denied/sys/kernel/debug"
cp -R "$GATE/debug-denied/sys/kernel/tracing" \
  "$GATE/debug-denied/sys/kernel/debug/tracing"
printf 'denied=/sys/kernel/debug\n' >> "$GATE/debug-denied/meta.txt"

strip_securityfs() {
  # $1 = tree: remove the securityfs dir and its mounts line.
  rm -rf "$1/sys/kernel/security"
  printf 'tracefs /sys/kernel/tracing tracefs rw,nosuid,nodev,noexec,relatime 0 0\n' \
    > "$1/proc/mounts"
}

mk lockdown-conf
printf 'none integrity [confidentiality]\n' \
  > "$GATE/lockdown-conf/sys/kernel/security/lockdown"

mk lockdown-integrity
printf 'none [integrity] confidentiality\n' \
  > "$GATE/lockdown-integrity/sys/kernel/security/lockdown"

mk lockdown-nosecfs
strip_securityfs "$GATE/lockdown-nosecfs"
printf 'BOOT_IMAGE=/vmlinuz root=/dev/vda1 lockdown=confidentiality\n' \
  > "$GATE/lockdown-nosecfs/proc/cmdline"

mk lockdown-dashdash
strip_securityfs "$GATE/lockdown-dashdash"
printf 'root=/dev/vda1 -- lockdown=confidentiality\n' \
  > "$GATE/lockdown-dashdash/proc/cmdline"

mk lockdown-config
strip_securityfs "$GATE/lockdown-config"
rm "$GATE/lockdown-config/proc/config.gz"
printf 'CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y\n' \
  > "$GATE/lockdown-config/boot/config-7.0.0-38-generic"

mk lockdown-nolsm
strip_securityfs "$GATE/lockdown-nolsm"
rm "$GATE/lockdown-nolsm/proc/config.gz"
printf '# CONFIG_SECURITY_LOCKDOWN_LSM is not set\n' \
  > "$GATE/lockdown-nolsm/boot/config-7.0.0-38-generic"

mk lockdown-twobrackets
printf '[none] [integrity] confidentiality\n' \
  > "$GATE/lockdown-twobrackets/sys/kernel/security/lockdown"

mk lockdown-bogus
strip_securityfs "$GATE/lockdown-bogus"
printf 'BOOT_IMAGE=/vmlinuz root=/dev/vda1 lockdown=bogus\n' \
  > "$GATE/lockdown-bogus/proc/cmdline"

mk lockdown-denied
printf 'denied=/sys/kernel/security/lockdown\n' \
  >> "$GATE/lockdown-denied/meta.txt"

write_boot_config() {
  # $1 = tree, $2.. = config lines: release-named boot config
  # with proc/config.gz deleted so the boot file decides.
  local tree="$1"
  shift
  rm -f "$tree/proc/config.gz"
  : > "$tree/boot/config-7.0.0-38-generic"
  for line in "$@"; do
    printf '%s\n' "$line" >> "$tree/boot/config-7.0.0-38-generic"
  done
}

mk notracing-config
write_boot_config "$GATE/notracing-config" '# CONFIG_FTRACE is not set'

mk notracing-bpfevents
write_boot_config "$GATE/notracing-bpfevents" 'CONFIG_FTRACE=y'

mk tracefs-noevents
rm -rf "$GATE/tracefs-noevents/sys/kernel/tracing/events"

mk tracefs-unmounted
rm -rf "$GATE/tracefs-unmounted/sys/kernel/tracing"
mkdir -p "$GATE/tracefs-unmounted/sys/kernel/tracing"
printf 'securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0\n' \
  > "$GATE/tracefs-unmounted/proc/mounts"

mk tracefs-hidden
rm -rf "$GATE/tracefs-hidden/sys/kernel/tracing/events"
strip_securityfs "$GATE/tracefs-hidden"
# No mounts table at all: neither mounted nor unmounted is
# provable, so the hidden-tracefs unknown fires.
rm "$GATE/tracefs-hidden/proc/mounts"

mk tracefs-gone
rm -rf "$GATE/tracefs-gone/sys/kernel/tracing"
rm -rf "$GATE/tracefs-gone/sys/kernel/debug"

mk events-denied
printf 'denied=/sys/kernel/tracing/events\n' \
  >> "$GATE/events-denied/meta.txt"

mk btf-absent-config
rm "$GATE/btf-absent-config/sys/kernel/btf/vmlinux"
write_boot_config "$GATE/btf-absent-config" \
  '# CONFIG_DEBUG_INFO_BTF is not set'

mk btf-absent-unknown
rm "$GATE/btf-absent-unknown/sys/kernel/btf/vmlinux"
rm "$GATE/btf-absent-unknown/proc/config.gz"
rm -f "$GATE/btf-absent-unknown"/boot/config-*

mk btf-not-visible
rm "$GATE/btf-not-visible/sys/kernel/btf/vmlinux"
write_boot_config "$GATE/btf-not-visible" 'CONFIG_DEBUG_INFO_BTF=y'

mk btf-denied
printf 'denied=/sys/kernel/btf/vmlinux\n' >> "$GATE/btf-denied/meta.txt"

mk btf-split
cp "$ROOT/tests/fixtures/btf/split.bin" \
  "$GATE/btf-split/sys/kernel/btf/vmlinux"

mk btf-truncated
head -c 600 "$GATE/btf-truncated/sys/kernel/btf/vmlinux" \
  > "$GATE/btf-truncated/sys/kernel/btf/vmlinux.cut"
mv "$GATE/btf-truncated/sys/kernel/btf/vmlinux.cut" \
  "$GATE/btf-truncated/sys/kernel/btf/vmlinux"

NOMAP="$ROOT/tests/fixtures/btf/swiotlb-live-nomap.bin"

mk hook-absent
cp "$NOMAP" "$GATE/hook-absent/sys/kernel/btf/vmlinux"
{
  printf '0000000000000000 T noise_fn\n'
  printf '0000000000000000 t other_fn\n'
} > "$GATE/hook-absent/proc/kallsyms"

mk hook-not-in-btf
cp "$NOMAP" "$GATE/hook-not-in-btf/sys/kernel/btf/vmlinux"
{
  printf '0000000000000000 T noise_fn\n'
  printf '0000000000000000 T swiotlb_tbl_map_single\n'
} > "$GATE/hook-not-in-btf/proc/kallsyms"

mk hook-clone
cp "$NOMAP" "$GATE/hook-clone/sys/kernel/btf/vmlinux"
{
  printf '0000000000000000 T noise_fn\n'
  printf '0000000000000000 t swiotlb_tbl_map_single.isra.0\n'
} > "$GATE/hook-clone/proc/kallsyms"

mk hook-nokallsyms
cp "$NOMAP" "$GATE/hook-nokallsyms/sys/kernel/btf/vmlinux"
# No kallsyms file at all: the listing cannot arbitrate,
# so the BTF verdict stands with a missing code.

mk denied-all
printf '%s\n' \
  'denied=/sys/kernel/security/lockdown,/sys/kernel/debug,/boot/config-7.0.0-38-generic,/proc/config.gz,/proc/kallsyms,/proc/sys/kernel/ftrace_enabled,/sys/fs/cgroup/mvt.slice/memory.max,/proc/self/status' \
  >> "$GATE/denied-all/meta.txt"

mk container-view
rm "$GATE/container-view/sys/kernel/btf/vmlinux"
write_boot_config "$GATE/container-view" 'CONFIG_DEBUG_INFO_BTF=y'
strip_securityfs "$GATE/container-view"
mkdir -p "$GATE/container-view/sys/kernel/debug"
mv "$GATE/container-view/sys/kernel/tracing" \
  "$GATE/container-view/sys/kernel/debug/tracing"
mkdir -p "$GATE/container-view/sys/kernel/tracing"

mk format-denied
printf 'denied=/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format\n' \
  >> "$GATE/format-denied/meta.txt"

# Validated coverage without the tracepoint id file: copied from
# the ready-validated capabilities tree, never edited by hand.
cp -R "$ROOT/tests/fixtures/capabilities/ready-validated" "$GATE/id-absent"
rm "$GATE/id-absent/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/id"

mk cc-flags-nonode
write_gate_cpuinfo "$GATE/cc-flags-nonode/proc/cpuinfo" \
  " sev sev_es sev_snp hypervisor"

mk cc-tdx-nonode
write_gate_cpuinfo "$GATE/cc-tdx-nonode/proc/cpuinfo" \
  " tdx_guest hypervisor"

mk cc-flags-host
write_gate_cpuinfo "$GATE/cc-flags-host/proc/cpuinfo" \
  " sev sev_es sev_snp"

mk cc-tsm
write_gate_cpuinfo "$GATE/cc-tsm/proc/cpuinfo" \
  " sev sev_es sev_snp hypervisor"
mkdir -p "$GATE/cc-tsm/sys/kernel/config/tsm/report"

mk caps-none
sed -i 's/^CapEff:.*/CapEff:\t0000000000000000/' \
  "$GATE/caps-none/proc/self/status"

mk caps-bpf-perfmon
sed -i 's/^CapEff:.*/CapEff:\t000000c000000000/' \
  "$GATE/caps-bpf-perfmon/proc/self/status"

mk caps-sysadmin
sed -i 's/^CapEff:.*/CapEff:\t0000000000200000/' \
  "$GATE/caps-sysadmin/proc/self/status"

mk caps-malformed
sed -i 's/^CapEff:.*/CapEff:\tzz/' \
  "$GATE/caps-malformed/proc/self/status"

mk caps-short
sed -i 's/^CapEff:.*/CapEff:\t1ff/' \
  "$GATE/caps-short/proc/self/status"

mk memcg-small
printf '1048576\n' \
  > "$GATE/memcg-small/sys/fs/cgroup/mvt.slice/memory.max"

mk memcg-ancestor
printf '12:memory:/x\n0::/a/b\n' \
  > "$GATE/memcg-ancestor/proc/self/cgroup"
mkdir -p "$GATE/memcg-ancestor/sys/fs/cgroup/a/b"
printf '50000000\n' > "$GATE/memcg-ancestor/sys/fs/cgroup/a/memory.max"
printf '0\n' > "$GATE/memcg-ancestor/sys/fs/cgroup/a/memory.current"
printf 'max\n' > "$GATE/memcg-ancestor/sys/fs/cgroup/a/b/memory.max"
printf '0\n' > "$GATE/memcg-ancestor/sys/fs/cgroup/a/b/memory.current"

mk memcg-malformed
printf '12abc\n' \
  > "$GATE/memcg-malformed/sys/fs/cgroup/mvt.slice/memory.max"

mk memcg-huge
printf '123456789012345678901\n' \
  > "$GATE/memcg-huge/sys/fs/cgroup/mvt.slice/memory.max"

mk memcg-empty
: > "$GATE/memcg-empty/sys/fs/cgroup/mvt.slice/memory.max"

mk memcg-v1
printf '12:memory:/x\n' > "$GATE/memcg-v1/proc/self/cgroup"

mk unpriv-bpf
printf '2\n' \
  > "$GATE/unpriv-bpf/proc/sys/kernel/unprivileged_bpf_disabled"

mk swiotlb-noforce
printf 'BOOT_IMAGE=/vmlinuz root=/dev/vda1 swiotlb=noforce\n' \
  > "$GATE/swiotlb-noforce/proc/cmdline"

mk swiotlb-inactive
mkdir -p "$GATE/swiotlb-inactive/sys/kernel/debug"

echo "wrote $GATE (base plus 57 variants)"
