#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Target-filtered RUSTC_WRAPPER for the sanitizer lane (see
# docs/sanitizer-lane.md).
#
# Appends `-Zsanitizer=address` ONLY to rustc invocations for the
# lane target (x86_64-unknown-linux-gnu) and logs every invocation
# it sees to $ASAN_WRAPPER_LOG (one line each, flock-serialized).
# Everything else passes through untouched:
# - bpfel-unknown-none: the eBPF child must never see a sanitizer
#   flag. (The root build.rs additionally strips RUSTC_WRAPPER from
#   the child eBPF cargo entirely, so in a normal lane build the
#   child never reaches this wrapper at all; the log plus the
#   BPF-ELF symbol check in the lane doc prove that.)
# - host builds (no --target: build scripts, proc macros and their
#   deps): rustc rejects sanitizer flags for proc-macro crates, and
#   ASan-instrumented host rlibs break proc-macro loading, so host
#   tooling stays uninstrumented. All product code, tests, and the
#   rebuilt sysroot build for the lane target and are instrumented.
#
# Usage: RUSTC_WRAPPER=$PWD/tools/asan-rustc-wrapper.sh \
#        ASAN_WRAPPER_LOG=$PWD/target/asan/invocations.log \
#        <nightly cargo> build -Zbuild-std --target x86_64-unknown-linux-gnu
set -u

rustc=$1
shift

log=${ASAN_WRAPPER_LOG:?ASAN_WRAPPER_LOG must point at the invocation log}
lane_target=${ASAN_LANE_TARGET:-x86_64-unknown-linux-gnu}

target=host
crate_name=?
query=0
prev=
for arg in "$@"; do
    if [ "$prev" = "--target" ]; then
        target=$arg
    fi
    case $arg in
        --target=*)
            target=${arg#--target=}
            ;;
        -vV | --version | -h | --help | --print | --print=*)
            query=1
            ;;
    esac
    if [ "$prev" = "--crate-name" ]; then
        crate_name=$arg
    fi
    prev=$arg
done

added=no
if [ "$query" -eq 0 ] && [ "$target" = "$lane_target" ]; then
    added=yes
fi

# One line per invocation: target, whether the sanitizer flag was
# added, crate name, then the full argv for audit. flock-serialized:
# cargo runs rustc in parallel and one printf per line is not
# enough to keep parallel appends from interleaving.
line=$(printf 'target=%s added=%s crate=%s argv:' "$target" "$added" "$crate_name")
for arg in "$@"; do
    line="$line <$arg>"
done
{
    flock 9
    printf '%s\n' "$line" >&9
} 9>>"$log"

if [ "$added" = yes ]; then
    exec "$rustc" -Zsanitizer=address "$@"
else
    exec "$rustc" "$@"
fi
