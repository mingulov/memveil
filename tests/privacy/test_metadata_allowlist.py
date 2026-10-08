#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Metadata-allowlist audit: no payload channel exists to misuse.

Statically audits the product tree: schemas expose no
payload/key/address/cmdline/environment property; BPF reads
only its frozen per-file kernel sites (probe-read plus
CO-RE field reads) with no user-memory, skb, debug, or
perf-output helper; Mojo reads only two
allowlisted environment names and no /proc cmdline or
environ file; and the CLI flag set is exactly the frozen
eighteen (any new flag fails here until reviewed). Exits
nonzero on the first violation.
"""

import glob
import json
import os
import re
import sys

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)

FORBIDDEN_PROPS = {
    "payload", "payload_bytes", "key", "key_material", "private_key",
    "password", "pin", "content_hash", "sha256", "raw_address",
    "virtual_address", "dma_address", "phys_addr", "command_line",
    "cmdline", "environ", "env_dump", "environment_dump", "hostname",
    "username", "ip_address", "mac_address",
}

ALLOWED_FLAGS = {
    "--allow-partial", "--bridge", "--capability", "--cp-object",
    "--device", "--duration", "--format", "--help", "--interval",
    "--json", "--lc-object", "--long-lived-after",
    "--max-events-bytes", "--max-line-bytes", "--max-session-bytes",
    "--object", "--output", "--profile",
}

ALLOWED_ENV = {"LMB_NATIVE_LIB", "MEMVEIL_SIGBLK"}

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


ENV_RE = r'getenv\(\s*(?:String\s*\(\s*)?"([A-Z_]+)'


def env_names_in(code):
    return set(re.findall(ENV_RE, code))


def self_check_extractor():
    # Both getenv spellings must be audited: a forbidden name
    # in either form has to surface here otherwise env-frozen
    # below would pass it silently.
    direct = ('var p = getenv("LMB_NATIVE_LIB")\n'
              'var q = getenv("FORBIDDEN_DIRECT")')
    check("env-pattern-direct",
          env_names_in(direct) == {"LMB_NATIVE_LIB", "FORBIDDEN_DIRECT"},
          sorted(env_names_in(direct)))
    wrapped = ('var p = getenv(String("MEMVEIL_SIGBLK"))\n'
               'var q = getenv(String("FORBIDDEN_WRAPPED"))')
    check("env-pattern-wrapped",
          env_names_in(wrapped) == {"MEMVEIL_SIGBLK", "FORBIDDEN_WRAPPED"},
          sorted(env_names_in(wrapped)))


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


def main():
    self_check_extractor()
    schemas = sorted(glob.glob(os.path.join(REPO, "schemas", "*.json")))
    check("schemas-present", len(schemas) >= 5, "%d files" % len(schemas))
    for path in schemas:
        props = schema_props(path)
        bad = sorted(props & FORBIDDEN_PROPS)
        check("schema-%s" % os.path.basename(path), not bad,
              "forbidden %s" % bad)

    progs = sorted(glob.glob(os.path.join(REPO, "bpf", "programs", "*.c")))
    check("bpf-present", len(progs) >= 1)
    # Frozen per-file audit: (bpf_probe_read_kernel,
    # BPF_CORE_READ) counts. Attempt reads its fixed context
    # plus the device name; lifecycle reads nothing (fentry
    # args only); copy reads the pool header (start, nslabs,
    # slots) through three checked relocating reads, one pool
    # slot (bulk copy over a relocated pointer), plus the
    # device align mask through two checked relocating reads
    # to replicate the hook's clamp. Any checked-read failure
    # degrades to unknown-with-reason. Transient kernel reads
    # never reach a record: emitted bytes are sizes,
    # directions, and outcome flags only. A new probe file, or
    # a new read in an old file, fails here until reviewed.
    # Tuples are (bpf_probe_read_kernel, BPF_CORE_READ,
    # bpf_core_read) call sites.
    read_sites = {
        "swiotlb_attempt.bpf.c": (2, 0, 0),
        "swiotlb_copy.bpf.c": (1, 0, 5),
        "swiotlb_lifecycle.bpf.c": (0, 0, 0),
    }
    check("bpf-files-frozen",
          sorted(os.path.basename(p) for p in progs) ==
          sorted(read_sites),
          sorted(os.path.basename(p) for p in progs))
    for path in progs:
        base = os.path.basename(path)
        text = open(path).read()
        for token in FORBIDDEN_BPF:
            check("bpf-no-%s" % token.replace("bpf_", ""),
                  token not in text, base)
        sites = text.count("bpf_probe_read_kernel")
        core = text.count("BPF_CORE_READ")
        core_fn = len(re.findall(r"bpf_core_read\s*\(", text))
        check("bpf-read-sites",
              (sites, core, core_fn) == read_sites[base],
              "%s has %d+%d+%d sites" % (base, sites, core, core_fn))
    headers = sorted(glob.glob(os.path.join(REPO, "bpf", "include", "*.h")))
    for path in headers:
        text = open(path).read()
        check("hdr-no-read-%s" % os.path.basename(path),
              "bpf_probe_read" not in text)

    flags = set()
    for path in glob.glob(os.path.join(REPO, "src", "memveil", "cli", "*.mojo")):
        flags.update(re.findall(r'"(--[a-z0-9-]+)"', open(path).read()))
    check("flags-frozen", flags == ALLOWED_FLAGS,
          "extra %s missing %s"
          % (sorted(flags - ALLOWED_FLAGS), sorted(ALLOWED_FLAGS - flags)))

    env_names = set()
    proc_hits = []
    for path in glob.glob(os.path.join(REPO, "src", "memveil", "**", "*.mojo"),
                          recursive=True):
        text = open(path).read()
        # Code and string literals only: docstrings and line
        # comments may name the paths they refuse to read.
        code = re.sub(r'""".*?"""', "", text, flags=re.DOTALL)
        code = "\n".join(ln.split("#", 1)[0] for ln in code.split("\n"))
        env_names.update(env_names_in(code))
        for token in ("/proc/self/cmdline", "/proc/self/environ",
                      "/proc/self/mem", "BEGIN PRIVATE", "getpass"):
            if token in code:
                proc_hits.append("%s:%s" % (path, token))
    check("env-frozen", env_names <= ALLOWED_ENV,
          "extra %s" % sorted(env_names - ALLOWED_ENV))
    check("no-proc-mem", not proc_hits, "; ".join(proc_hits[:5]))


if __name__ == "__main__":
    main()
