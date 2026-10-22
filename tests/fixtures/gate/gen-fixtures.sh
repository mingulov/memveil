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
VARIANTS="base ftrace-off ftrace-denied ftrace-malformed aff-dup aff-module aff-clone aff-prefix debugfs-root debug-denied"
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

echo "wrote $GATE (base plus 9 variants)"
