#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# memveil rpm install journey: runs INSIDE a Fedora container as root.
#
# Usage: rpm_journey.sh /mnt/memveil.rpm
#
# Refuses retained receipts before installing (naming them;
# nothing installed, nothing deleted), installs the given
# .rpm with dnf (proving its Requires resolve on Fedora),
# then drives the installed tree exactly like the
# .deb journey: rpm verify, version, receipts-dir state, bridge
# LOAD proof (ldd plus a real dlopen), generalized RUNPATH
# check, BPF placement, zero-flag doctor, zero-env record
# probe, privileged qualify (receipt lands in
# /var/lib/memveil/receipts on a qualifying host, else a
# past-resolution refusal), uninstall, and residue check.
# Every step prints `journey-ok: <step>`; any failure prints
# `journey-FAIL: ...` and exits 1. Needs network (dnf).
set -u

RPM=${1:?usage: rpm_journey.sh /mnt/memveil.rpm}

ok() {
    echo "journey-ok: $1"
}

die() {
    echo "journey-FAIL: $1" >&2
    exit 1
}

# Pre-install fresh-state gate (the .deb journey refuses
# retained receipts before dpkg -i; this is the rpm twin):
# a receipts dir that already holds files, or an already
# installed memveil package (rpm -q), refuses the run
# BEFORE anything is installed or deleted, naming the
# cause. MV_RECEIPTS_DIR restages the state dir for
# staged tests; the container journey leaves it unset.
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

ldd /usr/lib/memveil/libbpf_mojo.so.1 \
    >/tmp/journey-ldd-bridge.log 2>&1 || die "ldd bridge failed"
grep -q "not found" /tmp/journey-ldd-bridge.log \
    && die "bridge closure broken: $(cat /tmp/journey-ldd-bridge.log)"
[ "$(python3 -c 'import ctypes; lib = ctypes.CDLL("/usr/lib/memveil/libbpf_mojo.so.1"); lib.lmb_last_error; print("bridge-load-ok")' 2>/tmp/journey-dlopen.err)" = "bridge-load-ok" ] \
    || die "dlopen bridge failed: $(cat /tmp/journey-dlopen.err)"
ldd /usr/bin/memveil >/tmp/journey-ldd-bin.log 2>&1 \
    || die "ldd binary failed"
grep -q "not found" /tmp/journey-ldd-bin.log \
    && die "binary closure broken: $(cat /tmp/journey-ldd-bin.log)"
ok "bridge-load"

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
    memveil-top.1 memveil-doctor.1 memveil-qualify.1; do
    [ -f "/usr/share/man/man1/$page" ] || die "missing man $page"
done
grep -q "Generated by tools/gen-man" /usr/share/man/man1/memveil.1 \
    || die "man page lacks generator marker"
[ -f /usr/share/bash-completion/completions/memveil ] \
    || die "missing bash completions"
[ -f /usr/share/zsh/vendor-completions/_memveil ] \
    || die "missing zsh completions"
for text in copyright LICENSE THIRD-PARTY-NOTICES.md \
    THIRD-PARTY-NOTICES.libbpf-mojo.md; do
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

prof_id=$(python3 -c '
import json
import os
release = os.uname().release
for name in sorted(os.listdir("/usr/share/memveil/profiles")):
    if not name.endswith(".json"):
        continue
    try:
        doc = json.load(open("/usr/share/memveil/profiles/" + name))
    except (OSError, ValueError):
        continue
    source = doc.get("identity", {}).get("source", {})
    if doc.get("status") == "validated" \
            and source.get("revision") == release:
        print(doc.get("profile_id", ""))
        break
')
rm -rf /tmp/journey-qcap
if [ -n "$prof_id" ]; then
    out=$(memveil qualify --output /tmp/journey-qcap \
        --profile "$prof_id" 2>/tmp/journey-qualify.err)
    rc=$?
else
    out=$(memveil qualify --output /tmp/journey-qcap \
        2>/tmp/journey-qualify.err)
    rc=$?
fi
echo "journey qualify profile: ${prof_id:-default}"
if [ "$rc" -eq 0 ]; then
    echo "$out" | grep -q "receipt=/var/lib/memveil/receipts/" \
        || die "receipt path outside state dir: $out"
    [ -n "$(ls -A /var/lib/memveil/receipts)" ] \
        || die "exit 0 published no receipt"
    python3 - >/tmp/journey-receipt.log 2>&1 <<'EOF' \
        || die "receipt JSON invalid: $(cat /tmp/journey-receipt.log)"
import json
import os
names = sorted(os.listdir("/var/lib/memveil/receipts"))
assert names, "no receipt file"
for name in names:
    assert name.endswith(".json"), name
    doc = json.load(open("/var/lib/memveil/receipts/" + name))
    assert doc.get("profile_id"), name
print("receipt-json-ok")
EOF
    grep -q "receipt-json-ok" /tmp/journey-receipt.log \
        || die "receipt JSON invalid"
    echo "journey qualify receipt: $(echo "$out" | tail -n 1)"
    rm -f /var/lib/memveil/receipts/*.json || die "receipt cleanup failed"
    ok "qualify-receipt"
elif [ "$rc" -eq 3 ]; then
    for missing in "no bridge" "no object" \
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
rm -rf /tmp/journey-qcap /tmp/journey-cap

dnf remove -y -q memveil >/tmp/journey-remove.log 2>&1 \
    || die "dnf remove failed: $(tail -n 5 /tmp/journey-remove.log)"
rpm -q memveil >/dev/null 2>&1 && die "package still installed"
for path in /usr/lib/memveil /usr/share/memveil /usr/share/doc/memveil \
    /var/lib/memveil; do
    [ -e "$path" ] && die "residue: $path"
done
ok "uninstall-clean"

echo "journey: all steps passed"
