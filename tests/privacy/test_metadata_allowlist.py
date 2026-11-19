#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Metadata-allowlist audit: no payload channel exists to misuse.

Statically audits the product tree: schemas expose no
payload/key/address/cmdline/environment property; the eBPF
probes read only their frozen per-file kernel sites (checked
probe reads plus one map-slot volatile load) with no
user-memory, skb, debug, or perf-output helper; Rust reads
only allowlisted environment names (LMB_NATIVE_LIB read
then ignored for artifact selection, MEMVEIL_SIGBLK for the
signal guard, SUDO_UID and SUDO_GID ownership-only for sudo
capture hand-back, never persisted or attested, plus the
MEMVEIL_* test-child coordination namespace) and no /proc
cmdline or environ file; and the CLI flag set exactly
matches the frozen inventory (any new flag fails here until
reviewed). Exits nonzero on the first violation.
"""

import glob
import json
import contextlib
import io
import os
import re
import sys

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
RUST = REPO

FORBIDDEN_PROPS = {
    "payload", "payload_bytes", "key", "key_material", "private_key",
    "password", "pin", "content_hash", "sha256", "raw_address",
    "virtual_address", "dma_address", "phys_addr", "command_line",
    "cmdline", "environ", "env_dump", "environment_dump", "hostname",
    "username", "ip_address", "mac_address",
}

# --profiles-dir reviewed 2026-10-11: a profile/receipt
# directory selector (read by doctor/record, read and
# written by qualify). It adds no data source, no
# payload/cmdline/environ access, and no exfiltration
# channel; the invoking operator chooses which profile
# set to trust, exactly like --profile/--object.
# --compact: cli/top.rs parse_top_args selects presentation only.
# --strict: parse_report_args/parse_top_args/parse_record_args select partial-evidence exit policy.
# --profile-id: cli/bind.rs parse_bind_args names the profile being generated.
# These existing selectors add no collection, environment or payload source.
ALLOWED_FLAGS = {
    "--allow-partial", "--bridge", "--capability", "--cp-object",
    "--device", "--duration", "--format", "--help", "--interval",
    "--json", "--lc-object", "--load-check", "--long-lived-after",
    "--max-events-bytes", "--max-line-bytes", "--max-session-bytes",
    "--object", "--output", "--profile", "--profiles-dir",
    "--compact", "--strict", "--profile-id",
}

# SUDO_UID/SUDO_GID reviewed 2026-10-11: read once by
# record's sudo ownership hand-back to learn the invoking
# user's ids. They select no artifact, enter no capture,
# report, provenance, or receipt, and are never
# attested; any other use fails review here.
# LMB_NATIVE_LIB is read then ignored (the statically linked
# loader takes no environment-selected bridge); MEMVEIL_SIGBLK
# arms the signal guard; MEMVEIL_* is otherwise the
# test-child coordination namespace.
ALLOWED_ENV = {"LMB_NATIVE_LIB", "MEMVEIL_SIGBLK", "SUDO_UID", "SUDO_GID"}

FORBIDDEN_BPF = (
    "bpf_probe_read_user", "bpf_probe_read_compat",
    "bpf_probe_write_user", "bpf_printk", "bpf_trace_printk",
    "perf_event_output", "bpf_skb_", "bpf_xdp_",
    "bpf_get_current_comm", "get_current_comm", "virt_to_phys",
    "bpf_probe_read_kernel_str", "bpf_d_path",
)


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


VAR_LIT_RE = r'(?:std::env::|env::)var(?:_os)?\(\s*"([A-Z0-9_]+)"'
VAR_IDENT_RE = r'(?:std::env::|env::)var(?:_os)?\(\s*([A-Z][A-Z0-9_]*)\s*\)'
CONST_RE = r'const\s+([A-Z][A-Z0-9_]*)\s*:\s*&str\s*=\s*"([A-Z0-9_]+)"'


def env_names_in(code):
    """Environment names read by Rust code: direct literals plus
    const-indirected sentinels resolved from their definitions."""
    names = set(re.findall(VAR_LIT_RE, code))
    consts = dict(re.findall(CONST_RE, code))
    for ident in re.findall(VAR_IDENT_RE, code):
        if ident in consts:
            names.add(consts[ident])
    return names


def self_check_extractor():
    # Every read spelling must be audited: a forbidden name
    # in any form has to surface here otherwise env-frozen
    # below would pass it silently.
    direct = ('let a = std::env::var("LMB_NATIVE_LIB");\n'
              'let b = env::var("FORBIDDEN_DIRECT");\n'
              'let c = std::env::var_os("FORBIDDEN_OS");')
    check("env-pattern-direct",
          env_names_in(direct) == {"LMB_NATIVE_LIB", "FORBIDDEN_DIRECT",
                                   "FORBIDDEN_OS"},
          sorted(env_names_in(direct)))
    indirect = ('const SENTINEL: &str = "MEMVEIL_SIGBLK";\n'
                'if std::env::var(SENTINEL).is_ok() {}\n'
                'const OTHER: &str = "FORBIDDEN_INDIRECT";\n'
                'let _ = env::var(OTHER);')
    check("env-pattern-indirect",
          env_names_in(indirect) == {"MEMVEIL_SIGBLK",
                                     "FORBIDDEN_INDIRECT"},
          sorted(env_names_in(indirect)))


def schema_props(path):
    names = set()
    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "properties" and isinstance(v, dict):
                    names.update(v.keys())
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(json.load(open(path)))
    return names


def audit_flags(flags):
    check("flags-frozen", flags == ALLOWED_FLAGS,
          "extra %s missing %s"
          % (sorted(flags - ALLOWED_FLAGS), sorted(ALLOWED_FLAGS - flags)))


def self_check_flag_audit():
    for changed in (ALLOWED_FLAGS | {'--dump-payload'}, ALLOWED_FLAGS - {'--strict'}):
        rejected = False
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                audit_flags(changed)
            except SystemExit as exc:
                rejected = exc.code == 1
        check('flags-sensitivity', rejected, 'flag inventory mutation was accepted')


def strip_line_comments(text):
    return "\n".join(
        line for line in text.split("\n")
        if not re.match(r"\s*//", line))


def main():
    self_check_extractor()
    self_check_flag_audit()
    schemas = sorted(glob.glob(os.path.join(REPO, "schemas", "*.json")))
    check("schemas-present", len(schemas) >= 5, "%d files" % len(schemas))
    for path in schemas:
        props = schema_props(path)
        bad = sorted(props & FORBIDDEN_PROPS)
        check("schema-%s" % os.path.basename(path), not bad,
              "forbidden %s" % bad)

    progs = sorted(glob.glob(os.path.join(
        RUST, "crates", "ebpf", "src", "*.rs")) + glob.glob(os.path.join(
        RUST, "crates", "ebpf", "src", "bin", "*.rs")))
    check("bpf-present", len(progs) >= 1)
    # Frozen per-file audit: (bpf_probe_read_kernel_buf,
    # bpf_probe_read_kernel, read_volatile) call sites in code
    # (full-line comments stripped; string literals carry no
    # primitive names). Attempt reads the device name through
    # one checked buffer read; copy reads kernel words through
    # three checked width readers plus the trampoline frame
    # pointer from its own BPF stack (used only as a claim-map
    # key, never emitted); common carries one map-slot
    # volatile load (shared-map access, not a kernel read);
    # lifecycle reads nothing (fentry args only); channel
    # bins wire programs and maps without reads. A new probe
    # file, or a new read in an old file, fails here until
    # reviewed.
    read_sites = {
        "attempt.rs": (1, 0, 0),
        "copy.rs": (0, 4, 0),
        "lifecycle.rs": (0, 0, 0),
        "common.rs": (0, 0, 1),
        "bin/attempt.rs": (0, 0, 0),
        "bin/copy.rs": (0, 0, 0),
        "bin/lifecycle.rs": (0, 0, 0),
    }
    got_files = sorted(
        os.path.relpath(p, os.path.join(RUST, "crates", "ebpf", "src"))
        for p in progs)
    check("bpf-files-frozen", got_files == sorted(read_sites),
          got_files)
    for path in progs:
        base = os.path.relpath(
            path, os.path.join(RUST, "crates", "ebpf", "src"))
        text = open(path).read()
        for token in FORBIDDEN_BPF:
            check("bpf-no-%s" % token.replace("bpf_", ""),
                  token not in text, base)
        code = strip_line_comments(text)
        buf = len(re.findall(r"bpf_probe_read_kernel_buf\s*\(", code))
        krnl = len(re.findall(r"bpf_probe_read_kernel\s*\(", code))
        volat = len(re.findall(r"read_volatile\s*\(", code))
        check("bpf-read-sites",
              (buf, krnl, volat) == read_sites[base],
              "%s has %d+%d+%d sites" % (base, buf, krnl, volat))

    flags = set()
    for path in glob.glob(os.path.join(RUST, "src", "cli", "*.rs")):
        # Product code only: unit tests live inline below
        # `mod tests` and name bogus flags for refusal pins.
        # (Fail-closed: product code after a tests module
        # would drop real flags and trip flags-frozen.)
        product = open(path).read().split("\nmod tests {")[0]
        flags.update(re.findall(r'"(--[a-z0-9-]+)"', product))
    audit_flags(flags)

    env_names = set()
    proc_hits = []
    for path in glob.glob(os.path.join(RUST, "src", "**", "*.rs"),
                          recursive=True):
        text = open(path).read()
        # Code and string literals only: line comments may
        # name the paths they refuse to read.
        code = strip_line_comments(text)
        env_names.update(env_names_in(code))
        for token in ("/proc/self/cmdline", "/proc/self/environ",
                      "/proc/self/mem", "BEGIN PRIVATE", "getpass"):
            if token in code:
                proc_hits.append("%s:%s" % (path, token))
    foreign = sorted(n for n in env_names
                     if n not in ALLOWED_ENV
                     and not n.startswith("MEMVEIL_"))
    check("env-frozen", not foreign, "extra %s" % foreign)
    check("no-proc-mem", not proc_hits, "; ".join(proc_hits[:5]))


if __name__ == "__main__":
    main()
