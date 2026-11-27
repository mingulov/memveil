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
import copy
import io
import os
import re
import runpy
import sys

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
RUST = REPO

# Registered schema filenames, the single source of truth shared
# with the schema self-test (tools/validate-schemas pins each
# file's $id to its name). Schema identity below always verifies
# against this set; a document's own $id is never trusted.
VALIDATOR = runpy.run_path(os.path.join(REPO, "tools", "validate-schemas"))
# Reserved contract-review schemas (provenance gate's
# reserved pins): shipped for offline validation while
# current readers still refuse them. Registered here so
# their verified identity resolves; the observer
# exemption still covers event schemas alone.
RESERVED_SCHEMA_FILES = frozenset({
    "confidential-guest-manifest-v1.schema.json",
    "confidential-range-manifest-v1.schema.json",
    "event-v0.2.0.schema.json",
    "report-v0.2.0.schema.json",
    "session-v0.2.0.schema.json",
})
REGISTERED_SCHEMA_FILES = (frozenset(VALIDATOR["SCHEMA_FILES"])
                           | RESERVED_SCHEMA_FILES)
_REGISTERED_DOCS = {}


def _matches_registered(name, doc):
    """True when `doc` equals the registered file `name` on
    disk: an unattested identity claim verifies only as the
    genuine registered content, never by $id alone. Missing
    or unreadable files verify nothing (fail closed)."""
    if name not in REGISTERED_SCHEMA_FILES:
        return False
    if name not in _REGISTERED_DOCS:
        try:
            with open(os.path.join(REPO, "schemas", name)) as handle:
                _REGISTERED_DOCS[name] = json.load(handle)
        except (OSError, ValueError):
            return False
    return doc == _REGISTERED_DOCS[name]

FORBIDDEN_PROPS = {
    "payload", "payload_bytes", "key", "key_material", "private_key",
    "password", "pin", "content_hash", "sha256", "raw_address",
    "virtual_address", "dma_address", "phys_addr", "command_line",
    "cmdline", "environ", "env_dump", "environment_dump", "hostname",
    "username", "ip_address", "mac_address",
}

# comm/pid/tgid reviewed 2026-11-22: the event schema's
# reserved observer_context block names the observing
# execution context (cpu/pid/tgid/comm/cgroup_id under
# relation execution_context_only). The shipped collector
# never sets it, no renderer emits it (pinned by the canary
# suites), and foreign captures re-persist it verbatim, so
# these three names are allowed ONLY inside that block, in
# event schemas. Any new identity-shaped name, any of these
# names outside the block, any change to the block's frozen
# shape, or the block appearing in any non-event schema
# fails review here.
REVIEWED_ALLOWED_PROPS = {"comm", "pid", "tgid"}
OBSERVER_FROZEN_PROPS = {"cpu", "pid", "tgid", "comm", "cgroup_id", "relation"}

# The reviewed observer block lives at exactly these schema
# path segments: the walker compares segment vectors, never a
# joined string, so only equality exempts and a "/" inside a
# key cannot collide with the reviewed path.
OBSERVER_EXACT_PATH = ("properties", "observer_context")
OBSERVER_PARENT_PATH = ("properties",)


def event_schema(schema_id):
    """True for event schemas: the leak exemption covers the
    reviewed slot there only. `schema_id` is always a verified
    registered filename (or ""), never a document's own $id, so
    an unreviewed schema claiming an event- ID still fails. Any
    other schema gaining an observer_context block fails, even a
    byte-identical one, because that block was never reviewed
    for that schema. The exemption cannot smuggle new names:
    the unscoped freeze below still demands the byte-identical
    node."""
    return schema_id.startswith("event-")

# The frozen observer block, byte-identical in every event
# schema carrying it: property inventory, value bounds, and
# the relation const. Any drift fails review here.
OBSERVER_FROZEN = {
    "additionalProperties": False,
    "description": "Execution context only, unless a separate "
                   "adapter proves ownership.",
    "properties": {
        "cgroup_id": {"$ref": "#/$defs/opaque_id"},
        "comm": {"maxLength": 64, "type": "string"},
        "cpu": {"maximum": 1048575, "minimum": 0,
                "type": "integer"},
        "pid": {"maximum": 4194304, "minimum": 0,
                "type": "integer"},
        "relation": {"const": "execution_context_only"},
        "tgid": {"maximum": 4194304, "minimum": 0,
                 "type": "integer"},
    },
    "required": ["relation"],
    "type": "object",
}

# --profiles-dir reviewed 2026-10-11: a profile/receipt
# directory selector (read by doctor/record, read and
# written by qualify). It adds no data source, no
# payload/cmdline/environ access, and no exfiltration
# channel; the invoking operator chooses which profile
# set to trust, exactly like --profile/--object.
# --compact: cli/top.rs parse_top_args selects presentation only.
# --full: cli/top.rs parse_top_args selects full per-refresh
# reports instead of headlines. Both add no collection,
# environment or payload source.
# --strict: parse_report_args/parse_top_args/parse_record_args select partial-evidence exit policy.
# --profile-id: cli/bind.rs parse_bind_args names the profile being generated.
# These existing selectors add no collection, environment or payload source.
# --journal-object: cli/record.rs + cli/qualify.rs (+ top live
# forwarding) select the journal object override for an explicit
# path. --journal-callers: the same parsers enable bounded caller
# classification. Both require conversion-journal (parse-time
# refusal otherwise), add no data source beyond the journal
# channel, and never export addresses, frames, or task names.
ALLOWED_FLAGS = {
    "--allow-partial", "--bridge", "--capability", "--cp-object",
    "--device", "--duration", "--format", "--full", "--help",
    "--interval", "--json", "--lc-object", "--load-check",
    "--long-lived-after", "--max-events-bytes", "--max-line-bytes",
    "--max-session-bytes", "--object", "--output", "--profile",
    "--profiles-dir", "--compact", "--strict", "--profile-id",
    "--journal-object", "--journal-callers",
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


def schema_blocks(doc, origin=None):
    """Every (path segments, property-name set, object node,
    verified schema id) for object schemas carrying properties,
    so identity-shaped names can be contained to their reviewed
    block and the block's frozen shape (bounds and consts
    included) can be pinned, not just its key inventory. The
    reviewed slot is pinned even when shapeless, so a
    present-but-propertyless observer node fails the freeze
    loudly instead of passing vacuously by never entering the
    walk. `origin` is the registered filename the document was
    read from; without one the document's own $id verifies
    only when it names a registered file whose on-disk content
    the document equals, so an unreviewed schema claiming an
    event- ID — registered or not — is never exempt."""
    found = []
    if origin is None:
        claimed = doc.get("$id", "") if isinstance(doc, dict) else ""
        verified = claimed if _matches_registered(claimed, doc) else ""
    else:
        verified = origin if origin in REGISTERED_SCHEMA_FILES else ""
    def walk(o, path):
        if isinstance(o, dict):
            if isinstance(o.get("properties"), dict):
                found.append((path, set(o["properties"].keys()),
                              o, verified))
            if path == OBSERVER_PARENT_PATH and "observer_context" in o:
                child = o["observer_context"]
                if not (isinstance(child, dict)
                        and isinstance(child.get("properties"), dict)):
                    found.append((OBSERVER_EXACT_PATH, set(),
                                  child, verified))
            for k, v in o.items():
                walk(v, path + (k,))
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, path + (i,))
    walk(doc, ())
    return found


def observer_frozen_ok(blocks):
    return all(node == OBSERVER_FROZEN
               for where, props, node, schema in blocks
               if where == OBSERVER_EXACT_PATH)


def observer_leaked(blocks):
    return sorted({n for where, props, node, schema in blocks
                   if not (where == OBSERVER_EXACT_PATH
                           and event_schema(schema))
                   for n in props & REVIEWED_ALLOWED_PROPS})


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


def journal_inventory(code):
    helpers = set(re.findall(r"\b(bpf_[a-z0-9_]+)\s*\(", code))
    expected = {"bpf_get_current_task_btf", "bpf_probe_read_kernel",
                "bpf_ktime_get_ns", "bpf_get_stack",
                "bpf_get_smp_processor_id"}
    return (helpers == expected
            and code.count("bpf_probe_read_kernel(") == 1
            and code.count("bpf_get_stack(") == 1
            and "mv_jr_offs" in code
            and "reserve_bytes(" in code
            and ".submit(0)" in code
            and "NO_ADDRESSES" in code
            and "NO_FRAMES" in code
            and "NO_TASK_NAMES" in code)


def audit_journal_inventory(code):
    check("journal-helper-field-inventory", journal_inventory(code))
    for mutant in (code + "\nbpf_unknown_helper();",
                   code.replace("bpf_probe_read_kernel(",
                                "bpf_probe_read_user("),
                   code.replace("reserve_bytes(", "reserve_bytes_x("),
                   code + "\nbpf_probe_read_kernel(extra);"):
        check("journal-inventory-sensitivity", not journal_inventory(mutant))


def self_check_observer_audit():
    # Synthetic stand-ins declare their schema identity like
    # real files: the leak exemption covers registered event
    # schemas only, so the event-shaped controls carry a
    # registered event id.
    eid = "event-v0.1.2.schema.json"
    frozen = copy.deepcopy(OBSERVER_FROZEN)
    clean = {"$id": eid,
             "properties": {"observer_context": frozen,
                            "data": {"properties": {"device_id": {}}}}}
    check("observer-clean-accepted",
          observer_frozen_ok(schema_blocks(clean, origin=eid))
          and observer_leaked(schema_blocks(clean, origin=eid)) == [])
    check("observer-name-inventory",
          set(OBSERVER_FROZEN["properties"])
          == OBSERVER_FROZEN_PROPS)
    grown = {"$id": eid,
             "properties": {"observer_context":
                            dict(copy.deepcopy(OBSERVER_FROZEN),
                                 properties=dict(
                                     OBSERVER_FROZEN["properties"],
                                     uid={}))}}
    check("observer-growth-rejected",
          not observer_frozen_ok(schema_blocks(grown, origin=eid)))
    stray = {"$id": eid,
             "properties": {"observer_context": frozen,
                            "data": {"properties": {"comm": {}}}}}
    check("observer-stray-rejected",
          observer_leaked(schema_blocks(stray, origin=eid)) == ["comm"])
    # A same-named block in an unreviewed location is not
    # the reviewed block: its identity names leak.
    smuggled = {"$id": eid,
                "properties": {"extra": {"properties":
                                         {"observer_context":
                                          copy.deepcopy(
                                              OBSERVER_FROZEN)}}}}
    smuggled_blocks = schema_blocks(smuggled, origin=eid)
    check("observer-smuggled-path-rejected",
          observer_leaked(smuggled_blocks) != []
          and not (observer_frozen_ok(smuggled_blocks)
                   and not observer_leaked(smuggled_blocks)))
    # The freeze covers values, not just key names: a
    # retargeted relation const fails the frozen check.
    mutated = {"$id": eid,
               "properties": {"observer_context":
                              copy.deepcopy(OBSERVER_FROZEN)}}
    mutated["properties"]["observer_context"][
        "properties"]["relation"]["const"] = "origin"
    mutated_blocks = schema_blocks(mutated, origin=eid)
    check("observer-const-rejected",
          not observer_frozen_ok(mutated_blocks)
          and not (observer_frozen_ok(mutated_blocks)
                   and not observer_leaked(mutated_blocks)))
    # A present-but-shapeless observer node fails loudly
    # instead of passing vacuously: property-less objects
    # and non-objects alike never equal the frozen node.
    for slot in ({"type": "object"}, True):
        shapeless = {"$id": eid,
                     "properties": {"observer_context": slot}}
        shapeless_blocks = schema_blocks(shapeless, origin=eid)
        check("observer-shapeless-rejected",
              not observer_frozen_ok(shapeless_blocks)
              and not (observer_frozen_ok(shapeless_blocks)
                       and not observer_leaked(shapeless_blocks)))
    # The exemption covers event schemas only: a
    # byte-identical block in any other schema leaks its
    # reviewed names, because that block was never reviewed
    # for that schema.
    foreign = {"$id": "doctor-v0.1.1.schema.json",
               "properties": {"observer_context":
                              copy.deepcopy(OBSERVER_FROZEN)}}
    foreign_blocks = schema_blocks(foreign, origin="doctor-v0.1.1.schema.json")
    check("observer-foreign-schema-rejected",
          observer_leaked(foreign_blocks) != []
          and not (observer_frozen_ok(foreign_blocks)
                   and not observer_leaked(foreign_blocks)))
    # An unreviewed schema claiming an event- ID is never
    # exempt: identity verifies against registered filenames,
    # never the document's own $id.
    spoofed = {"$id": "event-selfcheck.schema.json",
               "properties": {"observer_context":
                              copy.deepcopy(OBSERVER_FROZEN)}}
    spoofed_blocks = schema_blocks(spoofed)
    check("observer-spoofed-id-rejected",
          observer_leaked(spoofed_blocks) != []
          and not (observer_frozen_ok(spoofed_blocks)
                   and not observer_leaked(spoofed_blocks)))
    # A copied registered $id verifies nothing without the
    # registered content: the claim must equal the file.
    copied = {"$id": eid,
              "properties": {"observer_context":
                             copy.deepcopy(OBSERVER_FROZEN)}}
    copied_blocks = schema_blocks(copied)
    check("observer-copied-id-rejected",
          observer_leaked(copied_blocks) != []
          and not (observer_frozen_ok(copied_blocks)
                   and not observer_leaked(copied_blocks)))
    # The genuine registered content verifies unattested: the
    # fallback admits the reviewed file itself.
    genuine = json.load(open(os.path.join(REPO, "schemas", eid)))
    genuine_blocks = schema_blocks(genuine)
    check("observer-genuine-registered-accepted",
          observer_frozen_ok(genuine_blocks)
          and not observer_leaked(genuine_blocks))
    # A key containing "/" cannot collide with the reviewed
    # path: segment vectors compare, never joined strings, so
    # the smuggled block's names leak even though the genuine
    # block beside it stays frozen and exempt.
    slashed = {"$id": eid,
               "properties": {"observer_context":
                              copy.deepcopy(OBSERVER_FROZEN)},
               "properties/observer_context":
                   copy.deepcopy(OBSERVER_FROZEN)}
    slashed_blocks = schema_blocks(slashed, origin=eid)
    check("observer-slashed-key-rejected",
          observer_leaked(slashed_blocks) != []
          and not (observer_frozen_ok(slashed_blocks)
                   and not observer_leaked(slashed_blocks)))


def strip_line_comments(text):
    return "\n".join(
        line for line in text.split("\n")
        if not re.match(r"\s*//", line))


def main():
    self_check_extractor()
    self_check_flag_audit()
    self_check_observer_audit()
    schemas = sorted(glob.glob(os.path.join(REPO, "schemas", "*.json")))
    check("schemas-present", len(schemas) >= 5, "%d files" % len(schemas))
    for path in schemas:
        props = schema_props(path)
        bad = sorted(props & FORBIDDEN_PROPS)
        check("schema-%s" % os.path.basename(path), not bad,
              "forbidden %s" % bad)
        blocks = schema_blocks(json.load(open(path)),
                              origin=os.path.basename(path))
        check("schema-observer-frozen-%s" % os.path.basename(path),
              observer_frozen_ok(blocks), "observer_context drifted")
        leaked = observer_leaked(blocks)
        check("schema-identity-contained-%s" % os.path.basename(path),
              not leaked, "reviewed names outside observer_context: %s" % leaked)

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
    # reviewed. The journal bin reads one u64 (task birth at
    # the host-resolved tabled offset) through one checked
    # width reader; pairing keys stay in kernel maps and no
    # address, frame, or task name reaches the ring (pinned
    # by the journal inventory audit below).
    read_sites = {
        "attempt.rs": (1, 0, 0),
        "copy.rs": (0, 4, 0),
        "lifecycle.rs": (0, 0, 0),
        "common.rs": (0, 0, 1),
        "bin/attempt.rs": (0, 0, 0),
        "bin/copy.rs": (0, 0, 0),
        "bin/lifecycle.rs": (0, 0, 0),
        "bin/conversion_journal.rs": (0, 1, 0),
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
        if base == "bin/conversion_journal.rs":
            audit_journal_inventory(text)
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
