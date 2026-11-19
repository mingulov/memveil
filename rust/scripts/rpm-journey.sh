#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# memveil rpm install journey (Rust-built .rpm): runs INSIDE a Fedora
# container as root.
#
# Usage: rpm-journey.sh /mnt/memveil.rpm
#
# Refuses retained receipts before installing (naming them;
# nothing installed, nothing deleted), installs the given
# .rpm with dnf (proving its Requires resolve on Fedora),
# then drives the installed tree: rpm verify, version,
# receipts-dir state, loader LOAD proof (ldd plus the private
# libgcc through the FHS RUNPATH -- there is no bridge dlopen
# in the Rust package, and no bridge ships), generalized
# RUNPATH check, BPF placement, zero-flag doctor, zero-env
# record probe, privileged qualify with explicit objects
# (receipt lands in /var/lib/memveil/receipts on a
# qualifying host, else a past-resolution refusal),
# uninstall, and residue check. Every step prints
# `journey-ok: <step>`; any failure prints `journey-FAIL: ...`
# and exits 1. Needs network (dnf).
set -u

RPM=${1:?usage: rpm-journey.sh /mnt/memveil.rpm}

ok() {
    echo "journey-ok: $1"
}

die() {
    echo "journey-FAIL: $1" >&2
    exit 1
}

# Pre-install fresh-state gate: a receipts dir that already
# holds files, or an already installed memveil package
# (rpm -q), refuses the run BEFORE anything is installed or
# deleted, naming the cause. MV_RECEIPTS_DIR restages the
# state dir for staged tests; the container journey leaves
# it unset.
RECEIPTS_DIR=${MV_RECEIPTS_DIR:-/var/lib/memveil/receipts}
if [ -d "$RECEIPTS_DIR" ]; then
    # Fail closed: an unreadable listing (empty output
    # plus nonzero status) must refuse, never read as
    # fresh state. The status is captured before the
    # name formatting, which would otherwise mask it.
    listed=$(ls -A "$RECEIPTS_DIR"); rc=$?
    [ "$rc" -eq 0 ] \
        || die "refusing install: cannot list $RECEIPTS_DIR (ls exit $rc); resolve the error, then rerun"
    kept=$(printf '%s\n' "$listed" | paste -sd, - | sed 's/,/, /g')
    [ -z "$kept" ] || die "refusing install: $RECEIPTS_DIR holds retained receipts ($kept); back them up or remove them, then rerun"
fi
if rpm -q memveil >/dev/null 2>&1; then
    die "refusing install: memveil package already installed (rpm -q memveil); remove it, then rerun"
fi

# Fedora container images set tsflags=nodocs, which would
# skip the man pages and license texts; real Fedora
# installs ship them, so the journey clears the flag to
# prove the full payload.
dnf install -y -q --setopt=tsflags= "$RPM" python3 binutils \
    >/tmp/journey-dnf.log 2>&1 \
    || die "dnf install failed: $(tail -n 5 /tmp/journey-dnf.log)"
ok "dnf-install"

verify=$(rpm -V memveil 2>&1) || die "rpm -V failed: $verify"
[ -z "$verify" ] || die "rpm -V noisy: $verify"
ok "rpm-verify"

want=$(rpm -q --queryformat '%{VERSION}' memveil 2>/dev/null) \
    || die "rpm -q version failed"
[ "$(memveil version)" = "memveil-$want" ] || die "version mismatch"
ok "version"

[ -d /var/lib/memveil/receipts ] || die "receipts dir missing"
[ "$(stat -c '%a %u %g' /var/lib/memveil/receipts)" = "755 0 0" ] \
    || die "receipts perms: $(stat -c '%a %u %g' /var/lib/memveil/receipts)"
[ -z "$(ls -A /var/lib/memveil/receipts)" ] \
    || die "fresh install ships receipts"
ok "receipts-dir"

# Loader LOAD proof: the binary's closure resolves, and the
# private libgcc resolves through the FHS RUNPATH. The Rust
# package ships no bridge: its presence is a failure.
[ -e /usr/lib/memveil/libbpf_mojo.so.1 ] \
    && die "bridge shipped in the bridgeless package"
[ -f /usr/lib/memveil/libgcc_s.so.1 ] \
    || die "missing /usr/lib/memveil/libgcc_s.so.1"
ldd /usr/bin/memveil >/tmp/journey-ldd-bin.log 2>&1 \
    || die "ldd binary failed"
grep -q "not found" /tmp/journey-ldd-bin.log \
    && die "binary closure broken: $(cat /tmp/journey-ldd-bin.log)"
grep -q "lib/memveil/libgcc_s.so.1" /tmp/journey-ldd-bin.log \
    || die "libgcc not RUNPATH-resolved: $(cat /tmp/journey-ldd-bin.log)"
ok "lib-load"

python3 - >/tmp/journey-runpath.log 2>&1 <<'EOF' || die "runpath check failed"
import re
import subprocess
dyn = subprocess.run(["readelf", "-d", "/usr/bin/memveil"],
                     capture_output=True, text=True)
assert dyn.returncode == 0, dyn.stderr
assert "$ORIGIN/../lib/memveil" in dyn.stdout, dyn.stdout
found = []
for line in dyn.stdout.splitlines():
    match = re.search(r"Library (?:runpath|rpath): \[(.*)\]", line)
    if match:
        found += [entry for entry in match.group(1).split(":")
                  if entry and not entry.startswith("$ORIGIN")]
assert found == [], found
print("runpath-ok")
EOF
grep -q "runpath-ok" /tmp/journey-runpath.log \
    || die "runpath generalized: $(cat /tmp/journey-runpath.log)"
ok "runpath"

for obj in swiotlb_attempt.bpf.o swiotlb_lifecycle.bpf.o \
    swiotlb_copy.bpf.o; do
    path="/usr/lib/memveil/$obj"
    [ -f "$path" ] || die "missing $path"
    readelf -h "$path" 2>/dev/null | grep -q "BPF" \
        || die "$obj is not EM_BPF"
    readelf -S "$path" 2>/dev/null | grep -q "] .symtab" \
        || die "$obj lost its symtab"
done
ok "bpf"

python3 - >/tmp/journey-elf.log 2>&1 <<'EOF' || die "ELF scan crashed"
import os
bad = []
for base, _, names in os.walk("/usr/share"):
    for name in names:
        full = os.path.join(base, name)
        with open(full, "rb") as handle:
            if handle.read(4) == b"\x7fELF":
                bad.append(full)
assert not bad, bad
print("no-elf-ok")
EOF
grep -q "no-elf-ok" /tmp/journey-elf.log \
    || die "ELF under /usr/share: $(cat /tmp/journey-elf.log)"
ok "no-elf-share"

for page in memveil.1 memveil-record.1 memveil-report.1 \
    memveil-top.1 memveil-doctor.1 memveil-qualify.1 \
    memveil-bind-profile.1; do
    [ -f "/usr/share/man/man1/$page" ] || die "missing man $page"
done
grep -q "Generated by rust/scripts/gen-man" /usr/share/man/man1/memveil.1 \
    || die "man page lacks generator marker"
[ -f /usr/share/bash-completion/completions/memveil ] \
    || die "missing bash completions"
[ -f /usr/share/zsh/vendor-completions/_memveil ] \
    || die "missing zsh completions"
for text in copyright LICENSE THIRD-PARTY-NOTICES.md; do
    [ -f "/usr/share/doc/memveil/$text" ] || die "missing $text"
done
[ -f /usr/share/memveil/profiles/manifest.txt ] \
    || die "missing profiles manifest"
[ -f /usr/share/memveil/docs/quickstart.md ] \
    || die "missing installed manuals tree"
ok "man-completions"

out=$(memveil doctor 2>/tmp/journey-doctor.err)
rc=$?
[ "$rc" -eq 0 ] || [ "$rc" -eq 3 ] \
    || die "doctor exit $rc: $(cat /tmp/journey-doctor.err)"
[ -n "$out" ] || die "doctor printed nothing"
ok "doctor"

rm -rf /tmp/journey-cap
out=$(cd /tmp && env -i /usr/bin/memveil record --output /tmp/journey-cap \
    --duration 1 2>/tmp/journey-record.err)
rc=$?
for missing in "no bridge" "no object" "missing --object" \
    "cannot load profiles" "cannot resolve profiles"; do
    grep -q "$missing" /tmp/journey-record.err \
        && die "record discovery failed: $missing"
done
[ "$rc" -eq 0 ] || [ "$rc" -eq 3 ] || [ "$rc" -eq 4 ] \
    || die "record exit $rc: $(cat /tmp/journey-record.err)"
if [ "$rc" -eq 3 ]; then
    [ ! -e /tmp/journey-cap ] || die "refused record left a capture dir"
else
    [ -e /tmp/journey-cap ] || die "exit $rc left no capture dir"
fi
ok "record-probe"

# Qualify takes explicit objects (it snapshots file bytes)
# plus a fixed-bytes bridge fixture: the fixture binds the
# exercised path exactly like a production --bridge artifact
# while letting the receipt leg pin the expected hash.
printf 'MEMVEIL-JOURNEY-BRIDGE-FIXTURE-v1\n' > /tmp/journey-bridge-fixture.so
rm -rf /tmp/journey-qcap
out=$(memveil qualify --output /tmp/journey-qcap \
    --object /usr/lib/memveil/swiotlb_attempt.bpf.o \
    --lc-object /usr/lib/memveil/swiotlb_lifecycle.bpf.o \
    --cp-object /usr/lib/memveil/swiotlb_copy.bpf.o \
    --bridge /tmp/journey-bridge-fixture.so \
    2>/tmp/journey-qualify.err)
rc=$?
if [ "$rc" -eq 0 ]; then
    echo "$out" | grep -q "receipt=/var/lib/memveil/receipts/" \
        || die "receipt path outside state dir: $out"
    [ -n "$(ls -A /var/lib/memveil/receipts)" ] \
        || die "exit 0 published no receipt"
    FIXTURE_SHA=$(sha256sum /tmp/journey-bridge-fixture.so | cut -d' ' -f1)
    export FIXTURE_SHA
    python3 - >/tmp/journey-receipt.log 2>&1 <<'EOF' \
        || die "receipt invalid: $(cat /tmp/journey-receipt.log)"
import hashlib
import json
import os


def sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


names = sorted(os.listdir("/var/lib/memveil/receipts"))
assert names == [n for n in names if n.endswith(".json")], names
assert len(names) == 1, names
doc = json.load(open("/var/lib/memveil/receipts/" + names[0]))
assert doc["schema_version"] == "0.1.0", doc
assert doc["kind"] == "memveil-qualification-receipt", doc
assert doc["grade"] == "local-auto", doc
assert doc["capabilities"]["attempt-trace"]["status"] == "qualified", doc
assert doc["workload"]["kind"] == "smoke", doc
art = doc["artifacts"]
assert art["bridge"] == "sha256:" + os.environ["FIXTURE_SHA"], art
objs = art["objects"]
assert objs["attempt"] == \
    "sha256:" + sha("/usr/lib/memveil/swiotlb_attempt.bpf.o"), objs
assert objs["lifecycle"] == \
    "sha256:" + sha("/usr/lib/memveil/swiotlb_lifecycle.bpf.o"), objs
assert objs["copy"] == \
    "sha256:" + sha("/usr/lib/memveil/swiotlb_copy.bpf.o"), objs
print("receipt-ok")
EOF
    grep -q "receipt-ok" /tmp/journey-receipt.log \
        || die "receipt invalid"
    echo "journey qualify receipt: $(echo "$out" | tail -n 1)"
    rm -f /var/lib/memveil/receipts/*.json || die "receipt cleanup failed"
    ok "qualify-receipt"
elif [ "$rc" -eq 3 ]; then
    for missing in "no bridge" "no object" "missing --object" \
        "cannot load profiles" "cannot resolve profiles"; do
        grep -q "$missing" /tmp/journey-qualify.err \
            && die "qualify resolution failed: $missing"
    done
    [ -s /tmp/journey-qualify.err ] || die "refusal needs a diagnostic"
    [ -z "$(ls -A /var/lib/memveil/receipts)" ] \
        || die "refused qualify left receipts"
    echo "journey qualify refusal: $(cat /tmp/journey-qualify.err)"
    ok "qualify-refusal"
else
    die "qualify exit $rc: $(cat /tmp/journey-qualify.err)"
fi
rm -rf /tmp/journey-qcap /tmp/journey-cap /tmp/journey-bridge-fixture.so

dnf remove -y -q memveil >/tmp/journey-remove.log 2>&1 \
    || die "dnf remove failed: $(tail -n 5 /tmp/journey-remove.log)"
rpm -q memveil >/dev/null 2>&1 && die "package still installed"
for path in /usr/lib/memveil /usr/share/memveil /usr/share/doc/memveil \
    /var/lib/memveil; do
    [ -e "$path" ] && die "residue: $path"
done
ok "uninstall-clean"

echo "journey: all steps passed"
