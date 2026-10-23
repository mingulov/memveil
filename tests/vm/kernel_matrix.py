#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Kernel matrix helpers: lock, verdicts, oracle bracketing, row decision.

Pure offline logic for tools/kernel-matrix. No boot, no network,
no privileged reads. All pass/fail predicates live here so the
offline tests pin them; the tool only gathers evidence files
and the guest only produces them.
"""

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

SCHEMA = "memveil-kernel-matrix/2"
BOOT_APPEND_ALLOW = frozenset({"lockdown=confidentiality"})
CAPS = ("attempt-trace", "mapping-lifecycle", "copy-actual")
PROBES = ("tp", "map", "unmap", "copy", "syncc", "syncd")
ADMIT_CLASS = "live-verified"
REFUSE_CLASSES = ("floor-6.0", "floor-6.11", "no-cover", "live-refused",
                "btf-absent", "lockdown")
GLOBAL_REFUSE_CLASSES = ("floor-6.0", "lockdown")
CLASS_CODES = {
    "live-verified": ("available",),
    "btf-absent": ("btf-absent-config",),
    "lockdown": ("lockdown-confidentiality",),
    "floor-6.0": ("floor",),
    "floor-6.11": ("floor",),
    "live-refused": (
        "layout-missing", "layout-kind", "layout-size",
        "layout-bitfield", "layout-ambiguous",
        "signature-mismatch", "signature-width",
        "btf-hook-absent", "btf-hook-not-in-btf",
        "btf-hook-missing", "hook-ambiguous",
        "hook-not-traceable",
    ),
}
LIVE_CODES = frozenset(CLASS_CODES["live-refused"])
LOAD_CODES = frozenset(("load-eperm", "load-enomem",
                        "verifier-rejected", "load-failed"))
_VERIFIED_ROUTES = ("live interfaces verified", "bindings hold",
                    "receipt verified")

KINDS = {
    "attempt": ("bounce_attempt", ["tp"]),
    "map": ("map_result", ["map"]),
    "unmap": ("unmap", ["unmap"]),
    "copy": ("copy", ["copy"]),
    "sync": ("sync_request", ["syncc", "syncd"]),
}

CAP_CHANNELS = {
    "attempt-trace": ["attempt"],
    "mapping-lifecycle": ["map", "unmap"],
    "copy-actual": ["copy", "sync"],
}

CAP_PROBES = {
    "attempt-trace": ["tp"],
    "mapping-lifecycle": ["map", "unmap"],
    "copy-actual": ["copy", "syncc", "syncd"],
}

CHAN_MV_PROGS = {
    "attempt": ["mv_swiotlb_attempt"],
    "map": ["mv_map_result"],
    "unmap": ["mv_unmap"],
    "sync": ["mv_sync_cpu", "mv_sync_device"],
    "copy": ["mv_bounce", "mv_bounce_exit"],
}

NONCOPY_PROGS = CHAN_MV_PROGS["attempt"] \
    + CHAN_MV_PROGS["map"] + CHAN_MV_PROGS["unmap"] \
    + CHAN_MV_PROGS["sync"]

BOUNCE_PROG = CHAN_MV_PROGS["copy"][0]

TRANSPORT_KEYS = ("submit_fail", "malformed", "dropped",
                  "rejected", "write_failed")
POST_LATCH_KEYS = ("size_omitted", "duration_omitted",
                   "signal_omitted")
LOWER_BOUND_LABEL = \
    "attempt loss counts are a lower bound before 6.7"

MAX_EDGE_GAP_NS = 10 ** 9
BUSY_MAX_EDGE_GAP_NS = 2 * 10 ** 9
BUSY_SETTLE_NS = 2 * MAX_EDGE_GAP_NS
DMA_TO_DEVICE = 1
DMA_FROM_DEVICE = 2
DMESG_MARKER = "memveil-matrix-start"
DMESG_SUSPICIOUS = re.compile(
    r"warn|(?<!de)bug|oops|error|general protection fault|"
    r"(?<!in)stall|blocked for more than|panic|timed?\s?out|"
    r"swiotlb buffer is full", re.IGNORECASE)
WORKLOAD_GROUPS = 6
MAX_MAP_BYTES = 262144
SECTOR_BYTES = 512
COPY_DIRECTIONS = ("original_to_bounce", "bounce_to_original")
VNG_TAG = re.compile(r"^v\d+(\.\d+)*(-rc\d+)?$")

_PROBE_SNIPPET = {
    "tp": "tracepoint:swiotlb:swiotlb_bounced "
          "{ @tp = count(); @tpb = sum(args.size); }",
    "tp_countonly": "tracepoint:swiotlb:swiotlb_bounced "
                    "{ @tp = count(); }",
    "map": "fexit:vmlinux:swiotlb_tbl_map_single "
           "{ @map = count(); @mapd[args.dir] = count(); }",
    "unmap": ("fentry:vmlinux:__swiotlb_tbl_unmap_single"
              " { @unmap = count(); }"),
    "copy": "fentry:vmlinux:swiotlb_bounce "
            "{ @copy = count(); @copyd[args.dir] = count(); }",
    "syncc": ("fentry:vmlinux:__swiotlb_sync_single_for_cpu"
              " { @syncc = count(); }"),
    "syncd": ("fentry:vmlinux:__swiotlb_sync_single_for_device"
              " { @syncd = count(); }"),
}

_DIR_MAPS = {"map": "mapd", "copy": "copyd"}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class LockError(ValueError):
    """The lock file is malformed."""


class OracleError(ValueError):
    """Oracle samples do not bracket the capture window."""


class HostError(ValueError):
    """The build host or its recipe inputs are not usable."""


def _need(cond, msg):
    if not cond:
        raise LockError(msg)


def _strip_dot_zero(ver):
    if re.fullmatch(r"\d+\.\d+\.0", ver):
        return ver[:-2]
    return ver


def release_agrees_with_upstream(release, upstream):
    """Release carries its upstream version, rc mapped to .0."""
    if not isinstance(release, str) or not isinstance(upstream, str):
        return False
    release_ver = release.split("-", 1)[0].split("+", 1)[0]
    if "-rc" in upstream:
        base, want_rc = upstream.split("-rc", 1)
        if release_ver not in (base, base + ".0"):
            return False
        got = re.search(r"rc(\d+)", release)
        return got is not None and got.group(1) == want_rc
    return _strip_dot_zero(release_ver) == _strip_dot_zero(upstream)


UPSTREAM_RE = re.compile(r"^(?:\d+\.\d+\.\d+|\d+\.\d+-rc\d+)$")

_TOP_KEYS = frozenset({"schema", "recorded_on", "archive",
                      "archive_queried", "tools", "note",
                      "kernels"})
_ENTRY_KEYS = frozenset({"id", "release", "upstream",
                        "expected", "oracle", "boot_append",
                        "source"})
_ARCHIVE_KEYS = frozenset({"kind", "vng_version",
                          "archive_date", "vmlinuz_sha256",
                          "modules_manifest_sha256"})
_BUILT_KEYS = frozenset({"kind", "tarball_url",
                        "tarball_sha256", "fragments",
                        "fragments_sha256", "toolchain",
                        "config_sha256", "bzimage_sha256",
                        "modules_manifest_sha256"})
_TOOLCHAIN_KEYS = frozenset({"gcc", "ld", "pahole", "gzip",
                           "vng"})
TOOLCHAIN_NAMES = ("gcc", "ld", "pahole", "gzip", "vng")
_DISTRO_KEYS = frozenset({"kind", "packages",
                         "vmlinuz_member", "vmlinuz_sha256",
                         "modules_manifest_sha256",
                         "config_sha256", "banner"})
_PACKAGE_KEYS = frozenset({"url", "sha256"})
_VERDICT_KEYS = frozenset({"verdict", "reason_class"})


def _no_extra(doc, allowed, what):
    extra = set(doc) - allowed
    if extra:
        raise LockError("unknown %s key %s"
                        % (what, sorted(extra)[0]))


def _need_sha(val, what):
    _need(isinstance(val, str) and _HEX64.match(val),
          "bad %s" % what)


def _need_archive_source(source, upstream, ident):
    _no_extra(source, _ARCHIVE_KEYS, "source")
    vng = source.get("vng_version")
    _need(isinstance(vng, str) and VNG_TAG.match(vng),
          "bad vng_version for " + ident)
    stripped = vng[1:]
    plain_tag = re.fullmatch(r"v\d+\.\d+", vng) is not None
    _need(upstream == stripped or
          (plain_tag and upstream == stripped + ".0"),
          "upstream must strip v for " + ident)
    _need(isinstance(source.get("archive_date"), str)
          and source["archive_date"],
          "bad archive_date for " + ident)
    _need_sha(source.get("vmlinuz_sha256"),
              "vmlinuz_sha256 for " + ident)
    _need_sha(source.get("modules_manifest_sha256"),
              "modules_manifest_sha256 for " + ident)


def _need_built_source(source, ident):
    _no_extra(source, _BUILT_KEYS, "source")
    url = source.get("tarball_url")
    _need(isinstance(url, str) and
          url.startswith("https://") and url.endswith(".tar.xz"),
          "bad tarball_url for " + ident)
    _need_sha(source.get("tarball_sha256"),
              "tarball_sha256 for " + ident)
    frags = source.get("fragments")
    _need(isinstance(frags, list) and frags
          and all(isinstance(f, str) and f and
                  not f.startswith("/") and ".." not in
                  f.split("/") for f in frags),
          "bad fragments for " + ident)
    _need(len(set(frags)) == len(frags),
          "duplicate fragment for " + ident)
    fsha = source.get("fragments_sha256")
    _need(isinstance(fsha, dict) and
          set(fsha) == set(frags),
          "fragments_sha256 must cover fragments for " + ident)
    for frag in frags:
        _need_sha(fsha[frag],
                  "fragments_sha256 %s for %s" % (frag, ident))
    tool = source.get("toolchain")
    _need(isinstance(tool, dict), "bad toolchain for " + ident)
    _no_extra(tool, _TOOLCHAIN_KEYS, "toolchain")
    for name in TOOLCHAIN_NAMES:
        _need(isinstance(tool.get(name), str) and
              tool[name], "bad toolchain %s for %s"
              % (name, ident))
    _need_sha(source.get("config_sha256"),
              "config_sha256 for " + ident)
    _need_sha(source.get("bzimage_sha256"),
              "bzimage_sha256 for " + ident)
    _need_sha(source.get("modules_manifest_sha256"),
              "modules_manifest_sha256 for " + ident)


def _need_distro_source(source, ident):
    _no_extra(source, _DISTRO_KEYS, "source")
    packs = source.get("packages")
    _need(isinstance(packs, list) and packs,
          "bad packages for " + ident)
    for pack in packs:
        _need(isinstance(pack, dict), "bad package for " + ident)
        _no_extra(pack, _PACKAGE_KEYS, "package")
        url = pack.get("url")
        _need(isinstance(url, str) and
              url.startswith("https://") and url,
              "bad package url for " + ident)
        _need_sha(pack.get("sha256"),
                  "package sha256 for " + ident)
    _need(isinstance(source.get("vmlinuz_member"), str)
          and source["vmlinuz_member"],
          "bad vmlinuz_member for " + ident)
    _need_sha(source.get("vmlinuz_sha256"),
              "vmlinuz_sha256 for " + ident)
    _need_sha(source.get("modules_manifest_sha256"),
              "modules_manifest_sha256 for " + ident)
    _need_sha(source.get("config_sha256"),
              "config_sha256 for " + ident)
    banner = source.get("banner")
    _need(isinstance(banner, str) and
          banner.startswith("Linux version "),
          "bad banner for " + ident)


def _unique_object(pairs):
    obj = {}
    for key, val in pairs:
        if key in obj:
            raise LockError("duplicate key %r" % key)
        obj[key] = val
    return obj


def parse_lock(path):
    """Parse and validate one kernels.lock.json file."""
    try:
        doc = json.loads(Path(path).read_text(),
                         object_pairs_hook=_unique_object)
    except LockError:
        raise
    except (OSError, ValueError) as exc:
        raise LockError("unreadable lock: %s" % exc)
    _need(isinstance(doc, dict), "bad lock object")
    _no_extra(doc, _TOP_KEYS, "top level")
    _need(doc.get("schema") == SCHEMA, "bad schema")
    _need(isinstance(doc.get("recorded_on"), str)
          and doc["recorded_on"], "bad recorded_on")
    _need(doc.get("archive") == "https://kernel.ubuntu.com/mainline",
          "bad archive")
    _need(isinstance(doc.get("archive_queried"), str)
          and doc["archive_queried"], "bad archive_queried")
    tools = doc.get("tools")
    _need(isinstance(tools, dict), "bad tools")
    _no_extra(tools, frozenset({"bpftrace", "bpftool"}), "tools")
    for key in ("bpftrace", "bpftool"):
        _need(isinstance(tools.get(key), str)
              and tools[key].startswith(key + " v"),
              "bad tools %s" % key)
    kernels = doc.get("kernels")
    _need(isinstance(kernels, list) and kernels, "bad kernels")
    seen = set()
    for entry in kernels:
        _need(isinstance(entry, dict), "bad entry")
        _no_extra(entry, _ENTRY_KEYS, "entry")
        ident = entry.get("id")
        _need(isinstance(ident, str) and ident, "bad id")
        _need(ident not in seen, "duplicate id " + ident)
        seen.add(ident)
        upstream = entry.get("upstream")
        _need(isinstance(upstream, str)
              and UPSTREAM_RE.match(upstream),
              "bad upstream for " + ident)
        _need(isinstance(entry.get("release"), str)
              and entry["release"], "bad release for " + ident)
        _need(release_agrees_with_upstream(entry["release"],
                                           upstream),
              "release disagrees with upstream for " + ident)
        if "boot_append" in entry:
            extra = entry["boot_append"]
            _need(isinstance(extra, list) and extra
                  and all(arg in BOOT_APPEND_ALLOW
                          for arg in extra),
                  "bad boot_append for " + ident)
        source = entry.get("source")
        _need(isinstance(source, dict), "bad source for " + ident)
        kind = source.get("kind")
        if kind == "archive":
            _need_archive_source(source, upstream, ident)
        elif kind == "built":
            _need_built_source(source, ident)
        elif kind == "distro":
            _need_distro_source(source, ident)
        else:
            raise LockError("bad source kind for " + ident)
        expected = entry.get("expected")
        _need(isinstance(expected, dict), "bad expected for " + ident)
        _no_extra(expected, frozenset(CAPS), "expected")
        for cap in CAPS:
            _need(cap in expected, "missing %s for %s" % (cap, ident))
            want = expected[cap]
            _need(isinstance(want, dict), "bad %s for %s" % (cap, ident))
            _no_extra(want, _VERDICT_KEYS, "verdict")
            verdict = want.get("verdict")
            _need(verdict in ("admitted", "refused"),
                  "bad verdict for %s/%s" % (ident, cap))
            cls = want.get("reason_class")
            if verdict == "admitted":
                _need(cls == ADMIT_CLASS,
                      "bad reason_class for %s/%s" % (ident, cap))
            else:
                _need(cls in REFUSE_CLASSES,
                      "bad reason_class for %s/%s" % (ident, cap))
        oracle = entry.get("oracle")
        _need(isinstance(oracle, dict), "bad oracle for " + ident)
        _no_extra(oracle, frozenset({"omitted"}), "oracle")
        omitted = oracle.get("omitted")
        _need(isinstance(omitted, list), "bad omitted for " + ident)
        for probe in omitted:
            _need(probe in PROBES, "bad omitted probe for " + ident)
    return doc


def _below_floor(release):
    try:
        return _release_triple(release) < (6, 0)
    except ValueError:
        return False


def _reason_ok(reason_class, status, reason, code, release):
    """One capability matches its lock class by code and reason."""
    reason = reason or ""
    if reason_class == "live-verified":
        return status == "available" \
            and code in CLASS_CODES["live-verified"] \
            and not reason.startswith("partial ") \
            and any(route in reason
                    for route in _VERIFIED_ROUTES)
    if status not in ("unavailable", "unknown"):
        return False
    if reason_class == "no-cover":
        if code is None:
            return False
        if _below_floor(release):
            return code == "floor" and \
                "capability attempt-trace needs kernel 6.0+" \
                in reason
        return code != "available" \
            and "no profile covers" in reason
    if code not in CLASS_CODES.get(reason_class, ()):
        return False
    if reason_class == "floor-6.0":
        return "needs kernel 6.0+" in reason
    if reason_class == "floor-6.11":
        return "needs kernel 6.11+" in reason
    return True


def compare_doctor(expected, doctor, release):
    """Compare lock expectations with one load-check doctor document.

    Admitted needs load-check available with code available
    plus a verified-route reason. Refused needs a refused
    status plus its class code (and floor text for floors).
    Returns (ok, detail) with one line per capability.
    """
    got = {}
    for cap in doctor.get("capabilities", []):
        got[cap.get("id")] = (cap.get("status"),
                              cap.get("reason", ""),
                              cap.get("reason_code"))
    lines = []
    ok = True
    for cap in CAPS:
        want = expected.get(cap)
        if want is None:
            lines.append("%s: missing expectation" % cap)
            ok = False
            continue
        if cap not in got:
            lines.append("%s: missing from doctor" % cap)
            ok = False
            continue
        status, reason, code = got[cap]
        if _reason_ok(want["reason_class"], status, reason,
                      code, release):
            lines.append("%s: match (%s/%s)" % (cap, status, code))
        else:
            lines.append("%s: want %s/%s got %s/%s (%s)"
                         % (cap, want["verdict"],
                            want["reason_class"], status, code,
                            reason))
            ok = False
    return ok, "; ".join(lines)


def parse_oracle_samples(lines):
    """Parse interval T lines into [(nsecs, {key: count})]."""
    out = []
    for line in lines:
        if not line.startswith("T "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            nsecs = int(parts[1])
        except ValueError:
            continue
        counts = {}
        for item in parts[2:]:
            if "=" not in item:
                continue
            key, val = item.split("=", 1)
            try:
                counts[key] = int(val.split("/")[0])
            except ValueError:
                continue
        out.append((nsecs, counts))
    out.sort(key=lambda pair: pair[0])
    return out


def _bracket_core(samples, start_ns, end_ns):
    if not samples or samples[0][0] > start_ns \
            or samples[-1][0] < end_ns:
        raise OracleError("oracle does not bracket the capture window")
    before_start = max((s for s in samples if s[0] <= start_ns),
                       key=lambda s: s[0])
    after_start = min((s for s in samples if s[0] >= start_ns),
                      key=lambda s: s[0])
    before_end = max((s for s in samples if s[0] <= end_ns),
                     key=lambda s: s[0])
    after_end = min((s for s in samples if s[0] >= end_ns),
                    key=lambda s: s[0])
    return before_start, after_start, before_end, after_end


def bracket_oracle(samples, start_ns, end_ns,
                   max_gap_ns=MAX_EDGE_GAP_NS):
    """Find the four bracketing samples for [start, end).

    Raises OracleError when the first sample is after start,
    the last is before end, or either edge gap exceeds the
    limit. Returns (before_start, after_start, before_end,
    after_end) count dicts.
    """
    before_start, after_start, before_end, after_end = _bracket_core(
        samples, start_ns, end_ns)
    if after_start[0] - before_start[0] > max_gap_ns:
        raise OracleError("oracle gap over %dns at window start"
                          % max_gap_ns)
    if after_end[0] - before_end[0] > max_gap_ns:
        raise OracleError("oracle gap over %dns at window end"
                          % max_gap_ns)
    return (before_start[1], after_start[1],
            before_end[1], after_end[1])


def oracle_interval(samples, start_ns, end_ns, key,
                    max_gap_ns=MAX_EDGE_GAP_NS):
    """Conservative [lo, hi] oracle count for key over [start, end)."""
    before_start, after_start, before_end, after_end = bracket_oracle(
        samples, start_ns, end_ns, max_gap_ns)
    for name, snap in (("before_start", before_start),
                       ("after_start", after_start),
                       ("before_end", before_end),
                       ("after_end", after_end)):
        if key not in snap:
            raise OracleError("oracle key %s missing in %s"
                              % (key, name))
    lo = before_end[key] - after_start[key]
    hi = after_end[key] - before_start[key]
    return max(0, lo), hi


def _base_prog_name(name):
    return re.sub(r"_\d+$", "", name or "")


def parse_miss_samples(snaps):
    """Parse [(nsecs, progs)] into [(nsecs, {base: misses})]."""
    out = []
    for nsecs, progs in snaps:
        counts = {}
        for prog in progs or []:
            base = _base_prog_name(prog.get("name", ""))
            try:
                val = int(prog.get("recursion_misses", 0) or 0)
            except (TypeError, ValueError):
                continue
            counts[base] = counts.get(base, 0) + val
        out.append((int(nsecs), counts))
    out.sort(key=lambda pair: pair[0])
    return out


def miss_interval(miss_samples, start_ns, end_ns, names):
    """Bracketed [lo, hi] misses for programs over [start, end).

    Lo is the proven in-window portion; hi is the max over
    snapshots minus the pre-window value, which stays exact
    when memveil programs unload before the last snapshot.
    A program missing from a snapshot counts zero, and
    sparse snapshots carry no gap limit. Backwards counters
    are corrupt evidence and fail.
    """
    before_start, after_start, before_end, after_end = _bracket_core(
        miss_samples, start_ns, end_ns)
    del after_end
    lo = hi = 0
    for name in names:
        lo += before_end[1].get(name, 0) - after_start[1].get(name, 0)
        top = max(snap.get(name, 0) for _, snap in miss_samples)
        hi += top - miss_samples[0][1].get(name, 0)
    lo, hi = max(0, lo), max(0, hi)
    if lo > hi:
        raise OracleError("miss counters moved backwards")
    return lo, hi


def channel_bounds(samples, miss_samples, start_ns, end_ns, chan,
                   max_gap_ns=MAX_EDGE_GAP_NS):
    """Oracle [lo, hi] for one channel, misses bracketed in."""
    kind, keys = KINDS[chan]
    del kind
    lo = hi = 0
    for key in keys:
        klo, khi = oracle_interval(samples, start_ns, end_ns, key,
                                   max_gap_ns)
        mlo, mhi = miss_interval(miss_samples, start_ns, end_ns,
                                 ORACLE_PROGS[key])
        lo += klo + mlo
        hi += khi + mhi
    return lo, hi


def channel_allowance(miss_samples, start_ns, end_ns, chan,
                      transport, recovered):
    """In-window misses that may cover one channel shortfall.

    Copy counts only unrecovered entry misses: the exit probe
    observes returns without persisting events, so its misses
    grant no allowance. Transport loss is global and may cover
    any one channel; the total rule bounds the sum.
    """
    if chan == "copy":
        _, bounce_hi = miss_interval(miss_samples, start_ns,
                                     end_ns, [BOUNCE_PROG])
        return max(0, bounce_hi - recovered) + transport
    _, mhi = miss_interval(miss_samples, start_ns, end_ns,
                           CHAN_MV_PROGS[chan])
    return mhi + transport


_DETAIL_FIRST_NAMES = ("SLOT_READ", "MASK_READ", "BOUNDS",
                         "LAYOUT", "SHIFT")
_DETAIL_EQUATIONS = ("attempt->map", "map->copy", "copy->map",
                     "unmap->copy", "copy->unmap")
_DETAIL_SUFFIX_RE = (
    r"(?:; first unknown copy: (?P<first_name>"
    r"(?:SLOT_READ|MASK_READ|BOUNDS|LAYOUT|SHIFT)))?"
    r"(?P<live>(?:; hooks silent: "
    r"(?:attempt->map|map->copy|copy->map|unmap->copy|"
    r"copy->unmap) \(\d+ > \d+\)"
    r"|; (?:attempt->map|map->copy|copy->map|unmap->copy|"
    r"copy->unmap) liveness unverified \(\d+ vs \d+\)"
    r"|; copy liveness unverified: lifecycle not captured))?"
    r"(?P<lower>; attempt loss counts are a lower bound "
    r"before 6\.7)?"
)


def parse_detail_loss(reason):
    """Parse the strict detail loss grammar into counters.

    Accepts the collector suffixes only: an optional first
    unknown copy name plus at most one hook-liveness form
    (hooks silent, an equation unverified, or copy without
    lifecycle) plus the optional pre-6.7 lower-bound label.
    Anything else is a grammar mismatch. The result carries
    first_unknown_copy and liveness_suffix (each None when
    absent) and lower_bound beside the counters.
    """
    match = re.fullmatch(
        r"detail loss (\d+) \(submit_fail=\((\d+)\) "
        r"malformed=\((\d+)\) dropped=\((\d+)\) "
        r"recursion_missed=\((\d+)\) size_omitted=\((\d+)\) "
        r"duration_omitted=\((\d+)\) signal_omitted=\((\d+)\) "
        r"rejected=\((\d+)\) write_failed=\((\d+)\)\)"
        + _DETAIL_SUFFIX_RE,
        reason or "")
    if not match:
        raise ValueError("detail loss grammar mismatch")
    nums = [int(match.group(i)) for i in range(1, 11)]
    keys = ["total", "submit_fail", "malformed", "dropped",
            "recursion_missed", "size_omitted",
            "duration_omitted", "signal_omitted", "rejected",
            "write_failed"]
    parsed = dict(zip(keys, nums))
    parsed["first_unknown_copy"] = match.group("first_name")
    parsed["liveness_suffix"] = match.group("live")
    parsed["lower_bound"] = match.group("lower") is not None
    expect = sum(parsed[k] for k in TRANSPORT_KEYS) \
        + parsed["recursion_missed"] \
        + sum(parsed[k] for k in POST_LATCH_KEYS)
    if parsed["total"] != expect:
        raise ValueError("Detail loss total contradicts parts")
    return parsed


def transport_loss(parsed):
    """Attributable transport loss, post-latch omits excluded."""
    return sum(parsed[key] for key in TRANSPORT_KEYS)


def post_latch_loss(parsed):
    """Declared latch and drain omits, in-window by construction."""
    return sum(parsed[key] for key in POST_LATCH_KEYS)


def deferred_from_session(session):
    """Copy fallback deferrals memveil itself reports."""
    try:
        evidence = session["environment"]["evidence"]
    except (KeyError, TypeError):
        raise ValueError("session lacks environment evidence")
    for item in evidence:
        if isinstance(item, dict) \
                and item.get("source") == "copy.deferred":
            try:
                return int(item.get("interpretation"))
            except (TypeError, ValueError):
                raise ValueError("copy.deferred unparseable")
    raise ValueError("copy.deferred missing from session")


def recovered_from_session(session):
    """Copy fallback recoveries memveil itself reports."""
    try:
        evidence = session["environment"]["evidence"]
    except (KeyError, TypeError):
        raise ValueError("session lacks environment evidence")
    for item in evidence:
        if isinstance(item, dict) \
                and item.get("source") == "copy.recovered":
            try:
                return int(item.get("interpretation"))
            except (TypeError, ValueError):
                raise ValueError("copy.recovered unparseable")
    raise ValueError("copy.recovered missing from session")


def decide_channels(persisted, samples, miss_samples, start_ns,
                    end_ns, channels, loss, reported_total,
                    recovered, liveness_suffix=None):
    """Per-channel verdicts under the strict loss rules.

    Each shortfall must fit that channel memveil misses plus
    transport loss plus declared post-latch omits; the total
    shortfall must fit transport plus reported recursion
    misses plus declared omits; captured plus reported loss
    must stay inside the summed oracle bounds so
    over-reporting fails. A hooks-silent or
    liveness-unverified detail suffix voids every exact
    channel claim, since the hook cross-check is unproven;
    covered shortfalls still pass. Returns
    (per, overall, failed, info).
    """
    per = {}
    bounds = {}
    shortfalls = {}
    allowances = {}
    attributed = {}
    transport = transport_loss(loss)
    omits = post_latch_loss(loss)
    for chan in channels:
        kind, _ = KINDS[chan]
        try:
            lo, hi = channel_bounds(samples, miss_samples,
                                    start_ns, end_ns, chan)
            allowance = channel_allowance(
                miss_samples, start_ns, end_ns, chan,
                transport + omits,
                recovered if chan == "copy" else 0)
        except OracleError as exc:
            per[chan] = "ORACLE-FAIL (%s)" % exc
            return per, None, True, {"bounds": bounds,
                                     "shortfalls": shortfalls,
                                     "allowances": allowances,
                                     "attributed": attributed}
        bounds[chan] = (lo, hi)
        got = persisted.get(kind, 0)
        if got > hi:
            per[chan] = "MORE THAN ORACLE (%d > %d..%d)" % (got, lo, hi)
            shortfalls[chan] = 0
            allowances[chan] = allowance
            attributed[chan] = 0
            continue
        short = lo - got if got < lo else 0
        shortfalls[chan] = short
        allowances[chan] = allowance
        if short == 0:
            if liveness_suffix:
                per[chan] = "EXACT-UNPROVEN (%d in %d..%d; %s)" \
                    % (got, lo, hi, liveness_suffix[2:])
            else:
                per[chan] = "EXACT (%d in %d..%d)" % (got, lo, hi)
            attributed[chan] = 0
        elif short <= allowance:
            per[chan] = "SHORT-COVERED (%d < %d..%d)" % (got, lo, hi)
            attributed[chan] = short
        else:
            per[chan] = "SHORT-UNCOVERED (%d < %d..%d)" % (got, lo, hi)
            attributed[chan] = min(short, allowance)
    info = {"bounds": bounds, "shortfalls": shortfalls,
            "allowances": allowances, "attributed": attributed}
    if any(v.startswith("MORE THAN ORACLE") for v in per.values()):
        return per, None, True, info
    total_short = sum(shortfalls.values())
    sum_got = sum(persisted.get(KINDS[c][0], 0) for c in channels)
    sum_lo = sum(bounds[c][0] for c in channels)
    sum_hi = sum(bounds[c][1] for c in channels)
    allowed_total = transport + loss["recursion_missed"] + omits
    info.update({"sum_got": sum_got, "sum_lo": sum_lo,
                 "sum_hi": sum_hi, "total_short": total_short,
                 "allowed_total": allowed_total,
                 "over_reported": sum_got + reported_total > sum_hi})
    if any(v.startswith("SHORT-UNCOVERED") for v in per.values()):
        return per, "SHORT-UNCOVERED", True, info
    if any(v.startswith("EXACT-UNPROVEN")
           for v in per.values()):
        return per, "LIVENESS-UNPROVEN", True, info
    if total_short > allowed_total:
        return per, "SHORT-UNCOVERED", True, info
    if info["over_reported"]:
        return per, "OVER-REPORTED", True, info
    if sum_got + allowed_total < sum_lo:
        return per, None, True, info
    if total_short == 0:
        return per, "EXACT", False, info
    return per, "SHORT-COVERED", False, info


def check_recursion_reported(miss_samples, start_ns, end_ns,
                             recursion_reported, deferred,
                             recovered):
    """Hard check: reported misses cover the summed identity.

    The product reports recursion_missed as its non-copy
    program misses plus unrecovered copy entry misses, so
    the report must reach the summed non-copy bpftool high
    bounds plus max(0, bounce + deferred - recovered).
    """
    _, noncopy_hi = miss_interval(miss_samples, start_ns, end_ns,
                                  NONCOPY_PROGS)
    _, bounce_hi = miss_interval(miss_samples, start_ns, end_ns,
                                 [BOUNCE_PROG])
    want = noncopy_hi + max(0, bounce_hi + deferred - recovered)
    if recursion_reported < want:
        return ["reported recursion_missed %d below bpftool %d "
                "(non-copy %d, bounce %d, deferred %d, "
                "recovered %d)" % (recursion_reported, want,
                                   noncopy_hi, bounce_hi,
                                   deferred, recovered)]
    return []


LOAD_IO_BYTES = 1048576


def parse_workload_v2(text):
    """Parse phased workload lines into phases and byte totals.

    Requires read0, read512 and write512 once each plus
    one readers-N block per WORKLOAD_GROUPS reader, each
    with its buffer alignment line.
    """
    phases = []
    mods = {}
    for line in (text or "").splitlines():
        match = re.fullmatch(
            r"phase (\S+) start_ns (\d+) end_ns (\d+) "
            r"bytes (\d+) ios (\d+)", line.strip())
        if match:
            tag, start, end, nbytes, ios = match.groups()
            phases.append({"tag": tag,
                           "start": int(start),
                           "end": int(end),
                           "bytes": int(nbytes),
                           "ios": int(ios)})
            continue
        match = re.fullmatch(r"buf (\S+) mod4096=(\d+)",
                             line.strip())
        if match:
            mods[match.group(1)] = int(match.group(2))
    want = {"read0", "read512", "write512"}
    want |= {"readers-%d" % i
             for i in range(WORKLOAD_GROUPS)}
    seen = [phase["tag"] for phase in phases]
    if set(seen) != want or len(seen) != len(want):
        raise ValueError("workload lacks phases")
    for phase in phases:
        tag = phase["tag"]
        if tag not in mods:
            raise ValueError("workload lacks buf " + tag)
        phase["mod"] = mods[tag]
        if phase["end"] < phase["start"]:
            raise ValueError("workload phase ends early")
    read = sum(phase["bytes"] for phase in phases
               if phase["tag"] != "write512")
    write = sum(phase["bytes"] for phase in phases
                if phase["tag"] == "write512")
    return {"phases": phases,
            "first_start": min(phase["start"]
                               for phase in phases),
            "last_end": max(phase["end"]
                            for phase in phases),
            "read_bytes": read, "write_bytes": write}


def check_workload_phases(parsed):
    """Offsets and sizes of every workload phase."""
    fails = []
    for phase in parsed["phases"]:
        tag = phase["tag"]
        want_mod = 512 if tag in ("read512", "write512") \
            else 0
        if phase["mod"] != want_mod:
            fails.append("%s buffer at %d, want %d"
                         % (tag, phase["mod"], want_mod))
        if phase["bytes"] != phase["ios"] * LOAD_IO_BYTES:
            fails.append("%s bytes %d are not ios x 1 MiB"
                         % (tag, phase["bytes"]))
    return fails


def parse_workload(text):
    """Parse guest workload timestamps, every dd required."""
    want = ["dd1", "dd2", "par0", "par1", "par2", "par3"]
    starts = {}
    ends = {}
    for line in (text or "").splitlines():
        match = re.fullmatch(r"(dd[12]|par[0-3]) (start|end) (\d+)"
                             r"( rc=(\d+))?", line.strip())
        if not match:
            continue
        name, edge, stamp = match.group(1), match.group(2), \
            int(match.group(3))
        if edge == "start":
            if match.group(4) is not None:
                raise ValueError("workload start carries rc")
            starts[name] = stamp
        else:
            if match.group(5) is None:
                raise ValueError("workload end lacks rc")
            if int(match.group(5)) != 0:
                raise ValueError("workload %s rc=%s"
                                 % (name, match.group(5)))
            ends[name] = stamp
    for name in want:
        if name not in starts or name not in ends:
            raise ValueError("workload %s timestamps missing" % name)
        if ends[name] < starts[name]:
            raise ValueError("workload %s ends before it starts"
                             % name)
    return {"first_start": min(starts.values()),
            "last_end": max(ends.values())}


def check_workload_window(parsed, start_ns, end_ns):
    """Whole workload must sit inside the capture window."""
    if start_ns > parsed["first_start"]:
        return False, "first dd starts %d before window %d" % (
            parsed["first_start"], start_ns)
    if parsed["last_end"] > end_ns:
        return False, "last dd ends %d after window %d" % (
            parsed["last_end"], end_ns)
    return True, "workload %d..%d inside window %d..%d" % (
        parsed["first_start"], parsed["last_end"],
        start_ns, end_ns)


def count_floor(block_bytes):
    """Least maps a healthy row can show for these bytes.

    One swiotlb mapping spans at most 256 KiB, so block
    bytes need at least one map per 256 KiB. A fully
    bounced healthy row cannot fall below this; fewer
    maps mean missed traffic.
    """
    return -(-int(block_bytes) // MAX_MAP_BYTES)


def count_ceiling(block_bytes):
    """Most maps these block bytes can hold.

    Every map covers at least one 512-byte sector, so a
    map-like channel cannot exceed the sector count; the
    copy channel counts twice per map.
    """
    return int(block_bytes) // SECTOR_BYTES


def check_channel_floors(bounds, channels, floor):
    """Each admitted channel oracle must reach the floor."""
    fails = []
    for chan in channels:
        lo, _ = bounds[chan]
        if lo < floor:
            fails.append("%s oracle lower bound %d below floor %d"
                         % (chan, lo, floor))
    return fails


def check_channel_ceiling(bounds, channels, ceiling):
    """Each admitted channel oracle must fit the ceiling."""
    fails = []
    for chan in channels:
        _, hi = bounds[chan]
        limit = 2 * ceiling if chan == "copy" else ceiling
        if hi > limit:
            fails.append("%s oracle upper bound %d over ceiling %d"
                         % (chan, hi, limit))
    return fails


def _kind_channel(kind):
    for chan, (own, _) in KINDS.items():
        if own == kind:
            return chan
    return None


def check_persisted_invariants(persisted, attributed,
                               open_leak=0):
    """Fixed workload ratios within attributed loss.

    Each map carries one attempt, one unmap and one sync.
    Copy direction counts are checked exactly by
    check_copy_direction_counts, not here. Present
    channels only: a row with one channel has no ratio
    to check. Mappings the kernel never released keep
    map and attempt above unmap and sync by exactly the
    open count.
    """
    fails = []
    group = [k for k in ("bounce_attempt", "map_result", "unmap",
                         "sync_request") if k in persisted]
    upper = ("bounce_attempt", "map_result")
    lower = ("unmap", "sync_request")
    for i in range(len(group)):
        for j in range(i + 1, len(group)):
            first, second = group[i], group[j]
            allow = attributed.get(_kind_channel(first), 0) \
                + attributed.get(_kind_channel(second), 0)
            if first in upper and second in lower:
                gap = persisted[first] - persisted[second]
                if abs(gap - open_leak) > allow:
                    fails.append(
                        "%s=%d vs %s=%d beyond loss %d "
                        "and %d open" % (
                            first, persisted[first],
                            second, persisted[second],
                            allow, open_leak))
            elif abs(persisted[first] - persisted[second]) \
                    > allow:
                fails.append("%s=%d vs %s=%d beyond loss %d"
                             % (first, persisted[first],
                                second, persisted[second], allow))
    return fails


def oracle_counts_equal(bounds, persisted):
    """True when unmap and sync agree with the oracle."""
    for chan, kind in (("unmap", "unmap"),
                       ("sync", "sync_request")):
        if chan not in bounds or kind not in persisted:
            return False
        try:
            lo, hi = bounds[chan]
        except (TypeError, ValueError):
            return False
        if not lo <= persisted[kind] <= hi:
            return False
    return True


def check_copy_direction_counts(copy_dirs, copy_total, maps,
                                read_lo, read_hi, att_copy,
                                att_map, open_leak=0):
    """Exact per-direction copy counts within loss.

    Original-to-bounce equals maps (one map-path bounce
    each); bounce-to-original equals read maps (one
    bounce-back each). Shortfalls fit the copy plus map
    attribution; over always fails. Mappings the kernel
    never released miss their bounce-back, so the
    bounce-back shortfall may reach the open count.
    """
    try:
        o2b = int(copy_dirs["original_to_bounce"])
        b2o = int(copy_dirs["bounce_to_original"])
    except (KeyError, TypeError, ValueError):
        return ["copy direction counts unreadable"]
    fails = []
    if o2b + b2o != copy_total:
        fails.append("copy dirs %d + %d disagree with "
                     "total %d" % (o2b, b2o, copy_total))
    allow = att_copy + att_map
    if abs(o2b - maps) > allow:
        fails.append("original_to_bounce=%d vs maps=%d "
                     "beyond loss %d" % (o2b, maps, allow))
    if b2o > read_hi:
        fails.append("bounce_to_original=%d over read "
                     "maps %d" % (b2o, read_hi))
    elif b2o < read_lo - allow - open_leak:
        fails.append("bounce_to_original=%d under read "
                     "maps %d beyond loss %d and %d open"
                     % (b2o, read_lo, allow, open_leak))
    return fails


def check_oracle_invariants(bounds, open_leak=0):
    """Oracle intervals must share the workload ratios."""
    fails = []
    group = [c for c in ("attempt", "map", "unmap", "sync")
             if c in bounds]
    if len(group) >= 2:
        top = max(bounds[c][0] for c in group)
        bottom = min(bounds[c][1] for c in group)
        if top - bottom > open_leak:
            fails.append("oracle attempt/map/unmap/sync disjoint")
    return fails


def check_oracle_direction_formulas(map_iv, mapd, copy_iv,
                                    copyd, map_miss_hi,
                                    copy_miss_hi):
    """Exact oracle direction formulas with miss slack.

    TO_DEVICE bounces equal maps, FROM_DEVICE bounces
    equal read maps, and each direction split sums to
    its total; directions 0 and 3 must stay empty. True
    counts may exceed observed highs by that probe
    misses; anything else disjoint fails.
    """
    try:
        mlo, mhi = map_iv
        clo, chi = copy_iv
        mids = {d: tuple(mapd[d]) for d in range(4)}
        cids = {d: tuple(copyd[d]) for d in range(4)}
    except (KeyError, TypeError, ValueError):
        return ["oracle direction bounds unreadable"]
    fails = []
    for direction in (0, 3):
        if mids[direction][1] != 0:
            fails.append("oracle map dir %d not empty"
                         % direction)
        if cids[direction][1] != 0:
            fails.append("oracle copy dir %d not empty"
                         % direction)
    c1lo, c1hi = cids[DMA_TO_DEVICE]
    if c1lo > mhi + map_miss_hi \
            or mlo > c1hi + copy_miss_hi:
        fails.append("oracle TO_DEVICE copies disjoint "
                     "from maps")
    c2lo, c2hi = cids[DMA_FROM_DEVICE]
    m2lo, m2hi = mids[DMA_FROM_DEVICE]
    if c2lo > m2hi + map_miss_hi \
            or m2lo > c2hi + copy_miss_hi:
        fails.append("oracle FROM_DEVICE copies disjoint "
                     "from read maps")
    if mids[1][0] + mids[2][0] > mhi or mlo > mids[1][1] \
            + mids[2][1]:
        fails.append("oracle map dirs do not sum to maps")
    if cids[1][0] + cids[2][0] > chi or clo > cids[1][1] \
            + cids[2][1]:
        fails.append("oracle copy dirs do not sum to copies")
    return fails


def parse_detail_loss_unknown(reason):
    """Parse the strict detail-unknown grammar into counters.

    Takes the same collector suffixes as the exact form and
    returns the same first_unknown_copy and liveness_suffix
    keys beside cause and the known counters.
    """
    parts = " ".join("%s=\\((\\d+)\\)" % key
                     for key in ("submit_fail", "malformed",
                                 "dropped", "recursion_missed",
                                 "size_omitted",
                                 "duration_omitted",
                                 "signal_omitted", "rejected",
                                 "write_failed"))
    match = re.fullmatch(
        r"detail loss unknown \(([^;()]+); known: " + parts
        + r"\)" + _DETAIL_SUFFIX_RE, reason or "")
    if not match:
        raise ValueError("detail loss unknown grammar mismatch")
    cause = match.group(1)
    if not cause.strip():
        raise ValueError("detail loss unknown cause empty")
    nums = [int(match.group(i)) for i in range(2, 11)]
    keys = ["submit_fail", "malformed", "dropped",
            "recursion_missed", "size_omitted",
            "duration_omitted", "signal_omitted", "rejected",
            "write_failed"]
    parsed = dict(zip(keys, nums))
    parsed["cause"] = cause
    parsed["first_unknown_copy"] = match.group("first_name")
    parsed["liveness_suffix"] = match.group("live")
    parsed["lower_bound"] = match.group("lower") is not None
    return parsed


def parse_busy_span(text):
    """Busy loader phase line into start, end and ios."""
    for line in (text or "").splitlines():
        match = re.fullmatch(
            r"phase busy start_ns (\d+) end_ns (\d+) "
            r"bytes (\d+) ios (\d+)", line.strip())
        if match:
            start, end, _, ios = (int(v) for v in
                                  match.groups())
            return {"start": start, "end": end, "ios": ios}
    raise ValueError("busy phase line missing")


def check_busy_span(span, spawn_ns, exit_ns):
    """Busy load must span record spawn to exit with IO."""
    fails = []
    if span["start"] >= spawn_ns:
        fails.append("busy load starts %d at or after "
                     "spawn %d" % (span["start"], spawn_ns))
    if span["end"] <= exit_ns:
        fails.append("busy load ends %d at or before "
                     "exit %d" % (span["end"], exit_ns))
    if span["ios"] == 0:
        fails.append("busy load ran no IO")
    return fails


def _busy_known_loss(known):
    return transport_loss(known) + known["recursion_missed"]


def decide_busy(persisted, samples, miss_samples, start_ns,
                end_ns, channels, session, counters,
                loss_exact=True):
    """Busy capture verdicts from its own session evidence.

    An exact detail claim (complete_for_scope or a
    partial "Detail loss N" with a matching count) gets
    strict per-channel lower bounds with that channel
    transport loss plus declared post-latch omits plus
    bpftool misses, never pooled. An unknown
    partial, or a numeric partial whose aggregate says
    attempt loss is a lower bound, gets honesty only:
    not complete, each channel inside its oracle upper.
    Captured plus known loss must fit the summed oracle
    upper in both paths, since the loss claim is global.
    On an exact-loss kernel a carried aggregate loss
    count must match attempts plus loss against the
    oracle over the attached interval. A hooks-silent or
    liveness-unverified detail suffix voids every strict
    exact channel claim. Below 6.7 the claim must be
    partial with the lower-bound label in detail and
    aggregate; on 6.7 and later the label must be
    absent. Returns (per, overall, failed, info).
    """
    try:
        detail = session["quality"]["detail"]
        status = detail["status"]
        loss_count = detail.get("loss_count")
        reason = detail.get("reason")
        agg = session["quality"].get("aggregate", {})
    except (KeyError, TypeError, AttributeError):
        per = {c: "CLAIM-UNPROVEN (session unreadable)"
               for c in channels}
        return per, "CLAIM-UNPROVEN", True, {}
    agg_reason = (agg or {}).get("reason") or ""
    detail_lower = LOWER_BOUND_LABEL in (reason or "")
    agg_lower = LOWER_BOUND_LABEL in agg_reason
    if loss_exact:
        if detail_lower or agg_lower:
            per = {c: "CLAIM-UNPROVEN (lower-bound label on "
                      "exact-loss kernel)"
                   for c in channels}
            return per, "CLAIM-UNPROVEN", True, {}
    elif status != "partial" or not detail_lower \
            or not agg_lower:
        per = {c: "CLAIM-UNPROVEN (pre-6.7 needs partial "
                  "plus label in detail and aggregate)"
               for c in channels}
        return per, "CLAIM-UNPROVEN", True, {}
    numeric = unknown = None
    try:
        numeric = parse_detail_loss(reason)
    except ValueError:
        numeric = None
    try:
        unknown = parse_detail_loss_unknown(reason)
    except ValueError:
        unknown = None
    numeric_ok = numeric is not None \
        and loss_count is not None \
        and str(loss_count) == str(numeric["total"])
    unknown_ok = unknown is not None and loss_count is None
    lower_bound = agg_lower
    if numeric_ok and not lower_bound and status in (
            "complete_for_scope", "partial"):
        known = numeric
        strict = True
        honest_lower = False
    elif status == "partial" and unknown_ok \
            and not lower_bound:
        known = unknown
        strict = False
        honest_lower = False
    elif status == "partial" and lower_bound \
            and (numeric_ok or unknown_ok):
        known = numeric if numeric_ok else unknown
        strict = False
        honest_lower = True
    else:
        per = {c: "CLAIM-UNPROVEN (%s loss=%s)"
               % (status, loss_count) for c in channels}
        return per, "CLAIM-UNPROVEN", True, {}
    if "copy" in channels:
        try:
            recovered = recovered_from_session(session)
        except ValueError as exc:
            per = {c: "CLAIM-UNPROVEN (%s)" % exc
                   for c in channels}
            return per, "CLAIM-UNPROVEN", True, {}
    else:
        recovered = 0
    per = {}
    transport = transport_loss(known)
    omits = post_latch_loss(known)
    known_total = _busy_known_loss(known)
    liveness = known.get("liveness_suffix")
    for chan in channels:
        kind, _ = KINDS[chan]
        try:
            lo, hi = channel_bounds(samples, miss_samples,
                                    start_ns, end_ns, chan,
                                    BUSY_MAX_EDGE_GAP_NS)
            allowance = channel_allowance(
                miss_samples, start_ns, end_ns, chan,
                transport + omits,
                recovered if chan == "copy" else 0)
        except OracleError as exc:
            per[chan] = "ORACLE-FAIL (%s)" % exc
            return per, None, True, {}
        got = persisted.get(kind, 0)
        if got == 0:
            per[chan] = "EMPTY (empty in busy capture)"
            continue
        if got > hi:
            per[chan] = "MORE THAN ORACLE (%d > %d..%d)" \
                % (got, lo, hi)
            continue
        if strict:
            short = lo - got if got < lo else 0
            if short > allowance:
                per[chan] = "SHORT-UNCOVERED " \
                    "(%d < %d..%d)" % (got, lo, hi)
            elif short == 0:
                if liveness:
                    per[chan] = "EXACT-UNPROVEN " \
                        "(%d in %d..%d; %s)" \
                        % (got, lo, hi, liveness[2:])
                else:
                    per[chan] = "EXACT (%d in %d..%d)" \
                        % (got, lo, hi)
            else:
                per[chan] = "SHORT-COVERED (%d < %d..%d)" \
                    % (got, lo, hi)
        else:
            per[chan] = "HONEST (%d <= %d)" % (got, hi)
    if any(v.startswith("MORE THAN ORACLE")
           for v in per.values()):
        return per, "MORE THAN ORACLE", True, {}
    if any(v.startswith("EMPTY") for v in per.values()):
        return per, "EMPTY", True, {}
    if any(v.startswith("SHORT-UNCOVERED")
           for v in per.values()):
        return per, "SHORT-UNCOVERED", True, {}
    if any(v.startswith("EXACT-UNPROVEN")
           for v in per.values()):
        return per, "LIVENESS-UNPROVEN", True, {}
    sum_got = sum(persisted.get(KINDS[c][0], 0)
                  for c in channels)
    sum_hi = 0
    for chan in channels:
        _, hi = channel_bounds(samples, miss_samples,
                               start_ns, end_ns, chan,
                               BUSY_MAX_EDGE_GAP_NS)
        sum_hi += hi
    if sum_got + known_total > sum_hi:
        return per, "OVER-REPORTED", True, {}
    if loss_exact and (agg or {}).get("loss_count") is not None:
        try:
            loss_n = int(agg["loss_count"])
        except (TypeError, ValueError):
            return per, "AGGREGATE-MISMATCH", True, \
                {"aggregate": "aggregate loss count unparseable"}
        try:
            agg_start, agg_end = parse_attached_interval(
                (agg or {}).get("scope"))
        except ValueError as exc:
            return per, "AGGREGATE-MISMATCH", True, \
                {"aggregate": str(exc)}
        try:
            ok, detail = _check_aggregate(
                counters, loss_n, samples, miss_samples,
                agg_start, agg_end, BUSY_MAX_EDGE_GAP_NS)
        except OracleError as exc:
            failed_all = {
                c: "ORACLE-FAIL (%s)" % exc for c in channels}
            return failed_all, None, True, {}
        if not ok:
            return per, "AGGREGATE-MISMATCH", True, \
                {"aggregate": detail}
    if strict:
        if any(v.startswith("SHORT-COVERED")
               for v in per.values()):
            return per, "SHORT-COVERED", False, {}
        return per, "EXACT", False, {}
    if honest_lower:
        return per, "HONEST-LOWER-BOUND", False, {}
    return per, "HONEST", False, {}


def parse_attached_interval(scope):
    """D31 attached [start, end) claim from an aggregate scope."""
    match = re.search(r" attached \[(\d+),(\d+)\)$",
                      scope or "")
    if not match:
        raise ValueError(
            "aggregate scope lacks attached interval")
    start, end = int(match.group(1)), int(match.group(2))
    if not start < end:
        raise ValueError("attached interval not ordered")
    return start, end


def _check_aggregate(counters, loss_n, samples, miss_samples,
                     start_ns, end_ns, max_gap_ns):
    """Aggregate counter claim against oracle bounds.

    Attempts plus the declared loss must fall inside the
    oracle bounds over the attached interval; bytes bind
    the same way where the oracle sums them, with each
    lost run worth at most MAX_MAP_BYTES.
    """
    if not isinstance(counters, dict):
        return False, "aggregate claims complete with " \
            "no counters"
    try:
        attempts = int(counters["swiotlb.bounce_attempts"])
    except (KeyError, TypeError, ValueError):
        return False, "aggregate lacks attempt counters"
    lo, hi = channel_bounds(samples, miss_samples, start_ns,
                            end_ns, "attempt", max_gap_ns)
    total = attempts + loss_n
    if total < lo or total > hi:
        return False, "aggregate attempts %d + loss %d = " \
            "%d outside oracle %d..%d" % (
                attempts, loss_n, total, lo, hi)
    if "swiotlb.requested_bytes" in counters:
        if not any("tpb" in snap for _, snap in samples):
            return True, "aggregate counts match the oracle; " \
                "bytes unproven on a countonly oracle"
        try:
            nbytes = int(counters["swiotlb.requested_bytes"])
        except (TypeError, ValueError):
            return False, "aggregate byte counter unparseable"
        blo, bhi = oracle_interval(samples, start_ns, end_ns,
                                   "tpb", max_gap_ns)
        _, miss_hi = miss_interval(miss_samples, start_ns,
                                   end_ns, ORACLE_PROGS["tp"])
        if nbytes + loss_n * MAX_MAP_BYTES < blo \
                or nbytes > bhi + miss_hi * MAX_MAP_BYTES:
            return False, "aggregate bytes %d outside " \
                "oracle %d..%d" % (nbytes, blo, bhi)
    return True, "aggregate counters match the oracle"


def decide_main_aggregate(agg, counters, samples,
                          miss_samples, loss_exact,
                          max_gap_ns=MAX_EDGE_GAP_NS):
    """Main-path aggregate loss count against the oracle.

    Below 6.7 only honesty applies; otherwise a carried
    loss count binds attempts plus loss (and bytes where
    the oracle has them) over the attached interval.
    """
    if not loss_exact:
        return True, "aggregate honesty only below 6.7"
    if not isinstance(agg, dict):
        return False, "aggregate quality unreadable"
    if agg.get("loss_count") is None:
        return True, "aggregate loss unknown; honesty only"
    try:
        loss_n = int(agg["loss_count"])
    except (TypeError, ValueError):
        return False, "aggregate loss count unparseable"
    try:
        start_ns, end_ns = parse_attached_interval(
            agg.get("scope"))
    except ValueError as exc:
        return False, str(exc)
    try:
        return _check_aggregate(
            counters, loss_n, samples, miss_samples,
            start_ns, end_ns, max_gap_ns)
    except OracleError as exc:
        return False, "ORACLE-FAIL (%s)" % exc


def check_memveil_bytes(byte_sums, read_bytes, write_bytes,
                        allowance, channels,
                        unpaired_bytes=0):
    """Persisted byte sums must match the block layer totals.

    Requested, mapped, sync and original-to-bounce sums
    equal read plus write bytes; bounce-to-original
    equals read bytes only. Exact at zero loss, any
    shortfall must fit the loss allowance, over always
    fails. Present channels only. Mappings the kernel
    never released keep their bytes out of sync, so the
    sync shortfall must equal the unpaired map bytes;
    the bounce-back shortfall only reaches that high
    when the leaked maps are reads.
    """
    try:
        sums = {"requested": int(byte_sums["requested"]),
                "mapped": int(byte_sums["mapped"]),
                "sync": int(byte_sums["sync"])}
        copies = {direction: int(byte_sums["copy"][direction])
                  for direction in COPY_DIRECTIONS}
    except (KeyError, TypeError, ValueError):
        return ["byte sums unreadable"]
    total = read_bytes + write_bytes
    fails = []
    for chan, field in (("attempt", "requested"),
                        ("map", "mapped")):
        if chan not in channels:
            continue
        if sums[field] > total:
            fails.append("%s bytes %d over block %d"
                         % (field, sums[field], total))
        elif total - sums[field] > allowance:
            fails.append("%s bytes %d short of block %d beyond "
                         "loss %d" % (field, sums[field],
                                      total, allowance))
    if "sync" in channels:
        if sums["sync"] > total:
            fails.append("sync bytes %d over block %d"
                         % (sums["sync"], total))
        elif abs(total - sums["sync"] - unpaired_bytes) \
                > allowance:
            fails.append("sync bytes %d short of block %d "
                         "beyond loss %d and %d unpaired"
                         % (sums["sync"], total, allowance,
                            unpaired_bytes))
    if "copy" in channels:
        for direction, want in (
                ("original_to_bounce", total),
                ("bounce_to_original", read_bytes)):
            got = copies[direction]
            leak = 0
            if direction == "bounce_to_original":
                leak = unpaired_bytes
            if got > want:
                fails.append("copy %s bytes %d over block %d"
                             % (direction, got, want))
            elif want - got > allowance + leak:
                fails.append("copy %s bytes %d short of block "
                             "%d beyond loss %d and %d unpaired"
                             % (direction, got, want,
                                allowance, leak))
    return fails


def check_oracle_bytes(samples, miss_samples, start_ns, end_ns,
                       block_bytes):
    """The oracle byte counter must match the block total.

    tpb sums bounced sizes at the tracepoint; its bracket
    equals the sector bytes, short only by missed oracle
    events at 256 KiB each. Over always fails.
    """
    try:
        lo, hi = oracle_interval(samples, start_ns, end_ns,
                                 "tpb")
        _, miss_hi = miss_interval(miss_samples, start_ns,
                                   end_ns, ORACLE_PROGS["tp"])
    except OracleError as exc:
        return ["oracle bytes: %s" % exc]
    if lo > block_bytes or hi > block_bytes:
        return ["oracle bytes %d..%d over block %d"
                % (lo, hi, block_bytes)]
    if block_bytes - lo > miss_hi * MAX_MAP_BYTES:
        return ["oracle bytes %d..%d short of block %d beyond "
                "%d misses" % (lo, hi, block_bytes, miss_hi)]
    return []


_HIST_BUCKET = re.compile(
    r"\{\s*size:\s*(\d+)\s*\}\s*hitcount:\s*(\d+)")
_HIST_TOTAL = re.compile(r"(Hits|Entries|Dropped):\s*(\d+)")


def parse_hist_totals(text):
    """Tracefs hist file into (count, bytes) totals.

    Every bucket contributes its size times hitcount.
    Dropped must read 0 with its line present, and any
    line outside the Totals block, buckets and comments
    fails so format drift never parses silently.
    """
    dropped = None
    seen_totals = False
    count = nbytes = 0
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "Totals:":
            seen_totals = True
            continue
        match = _HIST_TOTAL.fullmatch(stripped)
        if match:
            if match.group(1) == "Dropped":
                dropped = int(match.group(2))
            continue
        match = _HIST_BUCKET.fullmatch(stripped)
        if match:
            size, hits = int(match.group(1)), \
                int(match.group(2))
            count += hits
            nbytes += size * hits
            continue
        raise ValueError("hist line unparseable: %r"
                         % stripped[:40])
    if not seen_totals or dropped is None:
        raise ValueError("hist totals missing")
    if dropped != 0:
        raise ValueError("hist dropped %d" % dropped)
    return count, nbytes


def check_hist_bytes(before_text, after_text, block_bytes,
                     tp_lo, tp_hi):
    """Hist byte delta must equal the block total exactly.

    Both snapshots bracket the workload like blockstat,
    so no oracle slack applies; the count delta must sit
    inside the tracepoint oracle bounds over the window.
    """
    try:
        before_count, before_bytes = parse_hist_totals(
            before_text)
        after_count, after_bytes = parse_hist_totals(
            after_text)
    except ValueError as exc:
        return ["hist: %s" % exc]
    if after_count < before_count \
            or after_bytes < before_bytes:
        return ["hist runs backwards"]
    count = after_count - before_count
    nbytes = after_bytes - before_bytes
    if count == 0:
        return ["hist counted nothing"]
    if nbytes != block_bytes:
        return ["hist bytes %d are not block %d"
                % (nbytes, block_bytes)]
    if count < tp_lo or count > tp_hi:
        return ["hist count %d outside oracle %d..%d"
                % (count, tp_lo, tp_hi)]
    return []


def parse_blockstat(text):
    """Sectors read from one /sys/block/*/stat line."""
    try:
        return int((text or "").split()[2])
    except (IndexError, ValueError):
        raise ValueError("block stat line unparseable")


def parse_blockstat_write(text):
    """Sectors written from one /sys/block/*/stat line."""
    try:
        return int((text or "").split()[6])
    except (IndexError, ValueError):
        raise ValueError("block stat line unparseable")


def _opt_sector(side, key):
    if key not in side:
        return None
    try:
        return int(side[key])
    except (TypeError, ValueError):
        raise ValueError("blockstat sides unreadable")


def parse_blockstat_v2(text):
    """Per-side sector counters from one blockstat.json.

    Returns data dev, data reads, scratch dev, scratch
    writes, then the idle sides (data writes, scratch
    reads), each None when the guest did not record it.
    """
    try:
        doc = json.loads(text or "")
        data = doc["data"]
        scratch = doc["scratch"]
        out = (data["dev"], int(data["read_before"]),
               int(data["read_after"]), scratch["dev"],
               int(scratch["write_before"]),
               int(scratch["write_after"]),
               _opt_sector(data, "write_before"),
               _opt_sector(data, "write_after"),
               _opt_sector(scratch, "read_before"),
               _opt_sector(scratch, "read_after"))
    except (KeyError, TypeError, ValueError):
        raise ValueError("blockstat sides unreadable")
    if not out[0] or not out[3]:
        raise ValueError("blockstat sides unreadable")
    if out[2] < out[1] or out[5] < out[4]:
        raise ValueError("blockstat runs backwards")
    for before, after in ((out[6], out[7]), (out[8], out[9])):
        if before is not None and after is not None \
                and after < before:
            raise ValueError("blockstat runs backwards")
    return out


def check_idle_sides(data_write_before, data_write_after,
                     scratch_read_before, scratch_read_after):
    """Idle sides stay silent: no data writes or scratch reads."""
    sides = (data_write_before, data_write_after,
             scratch_read_before, scratch_read_after)
    if any(val is None for val in sides):
        return ["idle sides unrecorded"]
    fails = []
    if data_write_after != data_write_before:
        fails.append("data disk wrote %d sectors"
                     % (data_write_after - data_write_before))
    if scratch_read_after != scratch_read_before:
        fails.append("scratch disk read %d sectors"
                     % (scratch_read_after
                        - scratch_read_before))
    return fails


def check_sectors(data_before, data_after,
                  scratch_before, scratch_after,
                  read_bytes, write_bytes):
    """Per-device sectors must equal the workload bytes exactly.

    Data disk read sectors track read bytes, scratch write
    sectors track write bytes; any deviation fails.
    """
    fails = []
    if read_bytes % 512 or write_bytes % 512:
        return False, "workload bytes not sector aligned"
    data = data_after - data_before
    if data != read_bytes // 512:
        fails.append("data sectors %d, want %d"
                     % (data, read_bytes // 512))
    scratch = scratch_after - scratch_before
    if scratch != write_bytes // 512:
        fails.append("scratch sectors %d, want %d"
                     % (scratch, write_bytes // 512))
    if fails:
        return False, "; ".join(fails)
    return True, "sectors exact: data %d, scratch %d" % (
        data, scratch)


def _release_triple(release):
    match = re.match(r"^(\d+)\.(\d+)", release or "")
    if not match:
        raise ValueError("release unparseable: %r" % release)
    return int(match.group(1)), int(match.group(2))


def expected_record_refusal(release, cap, reason_class):
    """Record refusal text for one refused capability.

    Below 6.0 the global floor fires before any per-cap
    check, so every cap refuses with the floor text.
    """
    if _release_triple(release) < (6, 0):
        return "below floor 6.0"
    if reason_class == "floor-6.11":
        return "capability %s needs kernel 6.11+" % cap
    if reason_class == "no-cover":
        return "no profile covers this kernel"
    if reason_class == "live-refused":
        return "live check failed"
    if reason_class == "btf-absent":
        return "BTF absent (kernel built without BTF)"
    if reason_class == "lockdown":
        return "kernel lockdown is confidentiality"
    if reason_class == "floor-6.0":
        return "below floor 6.0"
    raise ValueError("unknown reason class " + reason_class)


def refusal_probe_caps(cap):
    """Caps arg proving one refused cap refuses for its reason.

    Solo lifecycle/copy requests refuse with attempt-trace
    is required before any cap check, so pair the refused
    cap with attempt-trace; the pair refuses for the cap.
    """
    if cap == "attempt-trace":
        return "attempt-trace"
    return "attempt-trace," + cap


def expected_combined_refusal(release, refused):
    """Combined all-caps refusal follows the first refusal."""
    if not refused:
        raise ValueError("combined refusal needs a refused cap")
    if _release_triple(release) < (6, 0):
        return "below floor 6.0"
    cap, cls = refused[0]
    return expected_record_refusal(release, cap, cls)


_RECORD_CODE_PREFIX = "memveil record: code: "


def record_code(out_text):
    """Record code line value, None when absent.

    More than one code line is corrupt evidence and raises.
    """
    found = []
    for line in (out_text or "").splitlines():
        if line.startswith(_RECORD_CODE_PREFIX):
            found.append(line[len(_RECORD_CODE_PREFIX):].strip())
    if len(found) > 1:
        raise ValueError("more than one record code line")
    if not found:
        return None
    return found[0]


def expected_record_code(reason_class, cap, doctor_codes):
    """Record code line value for one refused cap, or None.

    Gate classes pin their code; live-refused agrees with
    the load-check doctor code of that capability; floors
    and no-cover print no code line.
    """
    if reason_class == "btf-absent":
        return "btf-absent-config"
    if reason_class == "lockdown":
        return "lockdown-confidentiality"
    if reason_class == "live-refused":
        if cap not in doctor_codes:
            raise ValueError("doctor has no %s code" % cap)
        return doctor_codes[cap]
    if reason_class in ("floor-6.0", "floor-6.11", "no-cover"):
        return None
    raise ValueError("unknown reason class " + reason_class)


def expected_combined_code(refused, doctor_codes):
    """Combined probe code follows the first refusal in record order."""
    if not refused:
        raise ValueError("combined code needs a refused cap")
    cap, cls = refused[0]
    return expected_record_code(cls, cap, doctor_codes)


def check_refusal(exit_text, out_text, exists_text, want_reason,
                  want_code):
    """One refusal probe: exit 3, reason, code, no output dir.

    A None want_code means no code line may appear.
    """
    if (exit_text or "").strip() != "3":
        return False, "exit %r want 3" % (exit_text or "")
    if want_reason not in (out_text or ""):
        return False, "reason lacks %r" % want_reason
    try:
        got_code = record_code(out_text)
    except ValueError as exc:
        return False, "record code: %s" % exc
    if got_code != want_code:
        if want_code is None:
            return False, "unexpected record code line %r" % (
                got_code,)
        return False, "record code %r want %r" % (got_code,
                                                 want_code)
    if (exists_text or "").strip() != "no":
        return False, "left partial capture"
    return True, "refused exit 3 (%s)" % want_reason


def expected_doctor_exit(entry):
    """Doctor exits 0 only when all three capabilities are admitted."""
    for cap in CAPS:
        if entry["expected"][cap]["verdict"] != "admitted":
            return "3"
    return "0"


def check_passive_doctor(passive, loadcheck):
    """Passive doctor agrees with the load-check document.

    Passive never reads available or ready; an admitted
    capability is available-load-unchecked there, and a
    refusal with a non-load code carries the same code.
    """
    if not isinstance(passive, dict) \
            or not isinstance(loadcheck, dict):
        return False, "a doctor document is not an object"
    if passive.get("mode") != "passive":
        return False, "passive mode %r" % (passive.get("mode"),)
    if passive.get("verdict") == "ready":
        return False, "passive verdict ready"
    got = {}
    for cap in passive.get("capabilities", []):
        if isinstance(cap, dict):
            if cap.get("status") == "available":
                return False, "%s passive available" % (
                    cap.get("id"),)
            got[cap.get("id")] = cap
    want = {}
    for cap in loadcheck.get("capabilities", []):
        if isinstance(cap, dict):
            want[cap.get("id")] = cap
    for cap in CAPS:
        pcap = got.get(cap)
        lcap = want.get(cap)
        if pcap is None or lcap is None:
            return False, "%s missing from a doctor document" % cap
        if lcap.get("status") == "available":
            if pcap.get("status") != "available-load-unchecked":
                return False, "%s passive %s want " \
                    "available-load-unchecked" % (
                        cap, pcap.get("status"))
        else:
            lcode = lcap.get("reason_code")
            if lcode not in LOAD_CODES \
                    and pcap.get("reason_code") != lcode:
                return False, "%s passive code %r differs " \
                    "from %r" % (cap, pcap.get("reason_code"),
                                 lcode)
    return True, "passive matches load-check"


def check_guest_ordinary(loadcheck, sev_sysfs_text):
    """Load-check guest reads ordinary with no SNP evidence."""
    if not isinstance(loadcheck, dict):
        return False, "load-check doctor is not an object"
    guest = loadcheck.get("guest")
    if not isinstance(guest, dict):
        return False, "guest block missing"
    if guest.get("tech") != "ordinary":
        return False, "guest tech %r" % (guest.get("tech"),)
    if guest.get("conflict") != "":
        return False, "guest conflict %r" % (
            guest.get("conflict"),)
    signals = guest.get("signals")
    if not isinstance(signals, list):
        return False, "guest signals missing"
    for sig in signals:
        if isinstance(sig, str) and sig.startswith("sev-vmpl:"):
            return False, "guest signal %s" % sig
    if (sev_sysfs_text or "") != "absent":
        return False, "sev sysfs present"
    return True, "guest ordinary, no sev sysfs"


def check_boot_identity(uname_text, mods_text, want_release,
                        cache_dir):
    """Guest uname, modules path and swiotlb flag match the lock.

    The modules path must equal the verified cache modules
    dir for the release in either layout, and the cmdline
    virtme_link_mods token must carry the same path.
    """
    uname = (uname_text or "").splitlines()
    if not uname or uname[0].strip() != want_release:
        return False, "uname %r is not %s" % (
            uname[0] if uname else "", want_release)
    tokens = (uname[1] if len(uname) > 1 else "").split()
    if "swiotlb=131072,force" not in tokens:
        return False, "cmdline lacks forced swiotlb"
    mods = (mods_text or "").splitlines()
    if len(mods) < 2 or mods[0].strip() != want_release:
        return False, "guest modules path is not %s" % want_release
    if not cache_dir:
        return False, "verified cache dir unknown"
    base = str(cache_dir)
    want_dirs = (os.path.join(base, "lib", "modules", want_release),
                 os.path.join(base, "usr", "lib", "modules",
                              want_release))
    mods_path = mods[1].strip()
    if mods_path not in want_dirs:
        return False, "guest modules %s outside verified cache" % (
            mods_path)
    link = [tok.split("=", 1)[1] for tok in tokens
            if tok.startswith("virtme_link_mods=")]
    if len(link) != 1 or link[0] != mods_path:
        return False, "cmdline virtme_link_mods does not match " \
            "modules path"
    return True, "booted %s" % want_release


def check_boot_config(configid_text, want_sha):
    """Guest config.gz sha matches the built row pin."""
    if configid_text is None:
        return False, "config id missing"
    got = configid_text.strip()
    if got == "absent":
        return False, "guest has no /proc/config.gz"
    if got != want_sha:
        return False, "config.gz sha %s is not %s" % (got,
                                                     want_sha)
    return True, "config.gz matches the pin"


def check_boot_banner(version_text, want_banner):
    """Guest /proc/version equals the distro row banner."""
    if version_text is None:
        return False, "version text missing"
    got = version_text.strip()
    if got != want_banner:
        return False, "/proc/version %r is not the banner" \
            % got[:60]
    return True, "banner matches the pin"


def check_boot_append(uname_text, boot_append):
    """Every boot_append argument shows in the cmdline."""
    lines = (uname_text or "").splitlines()
    tokens = lines[1].split() if len(lines) > 1 else []
    for arg in boot_append or []:
        if arg not in tokens:
            return False, "cmdline lacks %s" % arg
    return True, "cmdline carries %s" % ",".join(
        boot_append or [])


def check_lockdown_effective(lockdown_text):
    """Lockdown reads confidentiality in the guest."""
    if lockdown_text is None:
        return False, "lockdown state missing"
    if "[confidentiality]" not in lockdown_text:
        first = lockdown_text.strip().splitlines()
        return False, "lockdown not effective: %s" % (
            first[0][:60] if first else "empty")
    return True, "lockdown is confidentiality"


def needed_probes(admitted):
    """Oracle probes one admitted set cannot run without."""
    out = []
    for cap in CAPS:
        if cap in admitted:
            out.extend(CAP_PROBES[cap])
    return out


def kept_oracle_probes(admitted, actual_omitted):
    """Oracle probes the guest must have kept for one row."""
    return [probe for probe in needed_probes(admitted)
            if probe not in actual_omitted]


def check_prog_presence(parsed_snaps, channels, kept_probes):
    """Memveil programs bracket record; oracle programs persist.

    Each admitted channel memveil program must load in
    snapshots 1 and 2 and stay out of 0 and 3; each kept
    oracle program plus the interval printer must show in
    all four. bpftrace index suffixes are stripped.
    """
    if len(parsed_snaps) != 4:
        return ["want 4 snapshots, got %d" % len(parsed_snaps)]
    have = []
    for _, progs in parsed_snaps:
        names = set()
        for prog in progs or []:
            full = prog.get("name", "")
            names.add(full)
            names.add(_base_prog_name(full))
        have.append(names)
    fails = []
    for chan in channels:
        for prog in CHAN_MV_PROGS[chan]:
            if prog not in have[1] or prog not in have[2]:
                fails.append("%s missing while record runs" % prog)
            if prog in have[0] or prog in have[3]:
                fails.append("%s present outside record" % prog)
    want_oracle = [ORACLE_INTERVAL_PROG]
    for probe in kept_probes:
        want_oracle.extend(ORACLE_PROGS[probe])
    for prog in want_oracle:
        for idx in range(4):
            if prog not in have[idx]:
                fails.append("%s missing from snapshot %d"
                             % (prog, idx))
    return fails


def check_omitted(lock_omitted, actual_omitted, admitted):
    """Actual omitted probes must equal the lock exactly.

    A probe needed by an admitted capability must be
    present even when the lock already omits it: skipping
    the channel would pass without comparing it.
    """
    fails = []
    if actual_omitted is None:
        return ["hooks.json unreadable"]
    if set(actual_omitted) != set(lock_omitted or []):
        fails.append("oracle omitted drift: lock %s actual %s"
                     % (lock_omitted, actual_omitted))
    for probe in needed_probes(admitted):
        if probe in actual_omitted:
            fails.append("needed probe %s missing" % probe)
    return fails


def check_udev_quiesced(exit_text, out_text):
    """Guest udev settle plus exec-queue stop both exited 0."""
    if (exit_text or "").strip() == "0":
        return True, "udev quiesced"
    tail = (out_text or "").strip().splitlines()
    tail = tail[-1][:80] if tail else "no output"
    return False, "udev quiesce exit %r (%s)" % (
        (exit_text or "").strip() or "missing", tail)


def events_file_bytes(path):
    """Size of one events file, or None when unreadable."""
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def product_max_ops():
    """Attempt-record cap read from the product source."""
    root = os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))
    path = os.path.join(root, "src", "memveil", "capture",
                        "collector.mojo")
    try:
        with open(path) as handle:
            text = handle.read()
    except OSError as exc:
        raise ValueError("product MAX_OPS unreadable: %s" % exc)
    match = re.search(r"^comptime MAX_OPS = (\d+)\s*$", text,
                      re.M)
    if not match:
        raise ValueError("product MAX_OPS not found")
    return int(match.group(1))


def detail_op_count(persisted):
    """Bridge-delivered detail events behind the op cap."""
    return sum(int(persisted.get(kind, 0)) for kind in (
        "bounce_attempt", "map_result", "unmap", "copy",
        "sync_request"))


def check_busy_stop_reason(text, events_bytes=None, cap=None,
                           op_count=None, max_ops=None):
    """Busy record stopped on signal or filled its budget.

    A size_limit stop is accepted with the events bytes at
    the configured cap (within BUSY_SIZE_SLACK below it,
    never above it) or with the persisted operation count
    at exactly MAX_OPS (read from the product). Any other
    stop mismatch fails.
    """
    if cap is None:
        cap = BUSY_MAX_EVENTS_BYTES
    reason = (text or "").strip()
    if reason == "signal":
        return True, "busy stopped on signal"
    if reason != "size_limit":
        return False, "busy end reason %r, want signal" % (
            reason or "missing")
    if not isinstance(events_bytes, int):
        return False, "busy size_limit without events bytes"
    if events_bytes > cap:
        return False, "busy size_limit bytes %d over cap %d" % (
            events_bytes, cap)
    if events_bytes >= cap - BUSY_SIZE_SLACK:
        return True, "busy size_limit with %d/%d bytes" % (
            events_bytes, cap)
    if max_ops is None:
        try:
            max_ops = product_max_ops()
        except ValueError as exc:
            return False, "busy size_limit with %d/%d bytes, %s" % (
                events_bytes, cap, exc)
    if op_count == max_ops:
        return True, "busy size_limit with %d ops at the cap" % (
            op_count)
    return False, "busy size_limit with %d/%d bytes, " \
        "want bytes at the cap" % (events_bytes, cap)


def session_end_reason(text):
    """Capture end_reason from a session.json document."""
    try:
        doc = json.loads(text or "")
    except ValueError:
        raise ValueError("session is not JSON")
    if not isinstance(doc, dict):
        raise ValueError("session is not an object")
    try:
        reason = doc["capture"]["end_reason"]
    except (KeyError, TypeError):
        raise ValueError("session lacks capture end_reason")
    if not isinstance(reason, str) or not reason:
        raise ValueError("session end_reason not a string")
    return reason


def check_record_finalized(exit_text):
    """Finalized record exits 0 or 4 per the record contract."""
    if (exit_text or "").strip() in ("0", "4"):
        return True, "record exit %s" % (exit_text or "").strip()
    return False, "record exit %r not finalized (0/4)" % (
        exit_text or "")


def check_report_consistent(record_exit, exits):
    """Report exits must equal record, not pass alone."""
    want = (record_exit or "").strip()
    got = [(each or "").strip() for each in exits]
    if want and all(each == want for each in got):
        return True, "report exits match record %s" % want
    return False, "report exits %s differ from record %s" % (
        got, want)


def check_oracle_stderr(text):
    """bpftrace must not report lost perf events."""
    if text is None:
        return False, "missing oracle.stderr"
    for hit in re.findall(r"lost (\d+) events", text,
                           re.IGNORECASE):
        if int(hit) > 0:
            return False, "oracle lost %s events" % hit
    return True, "oracle lost no events"


def scan_dmesg(text, marker):
    """Suspicious count after the marker, like the VM gates."""
    lines = (text or "").splitlines()
    start = None
    for i, line in enumerate(lines):
        if marker and marker in line:
            start = i + 1
            break
    if start is None:
        return False, 0
    count = 0
    for line in lines[start:]:
        if "mv-oracle:" in line:
            continue
        if DMESG_SUSPICIOUS.search(line):
            count += 1
    return True, count


def redact_dmesg(text):
    """Strip raw addresses from guest dmesg before export."""
    redacted = re.sub(r"0x[0-9a-fA-F]+", "ADDR", text or "")
    return re.sub(r"\b[0-9a-fA-F]{8,}\b", "ADDR", redacted)


def assert_redacted(text):
    """Fail when a raw address survived redaction.

    A bare hex run counts only with a hex letter, so a
    long decimal integral is not mistaken for an
    address.
    """
    if re.search(r"0x[0-9a-fA-F]", text or ""):
        raise ValueError("redacted text keeps 0x address")
    if re.search(r"\b(?=[0-9]*[a-fA-F])[0-9a-fA-F]{16,}\b",
                 text or ""):
        raise ValueError("redacted text keeps long hex run")


REDACT_SKIP_FILES = ("artifacts.json", "progs0.json",
                     "progs1.json", "progs2.json",
                     "progs3.json", "report.json",
                     "configid.txt")


def scan_export_redaction(export):
    """Assert every guest text export is redacted.

    Skips exactly the capture dirs (product output,
    covered by the product privacy suites) and the files
    that carry hashes and bpftool tags by design. Returns
    None when clean, else the first offending file and
    reason.
    """
    root = str(export)
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        if rel == "." and "cap" in dirnames:
            dirnames.remove("cap")
        if rel == "busy" and "cap" in dirnames:
            dirnames.remove("cap")
        for name in sorted(filenames):
            if name in REDACT_SKIP_FILES:
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, "rb") as handle:
                    text = handle.read().decode("utf-8")
            except (OSError, UnicodeDecodeError):
                return "%s: unreadable as text" % os.path.relpath(
                    path, root)
            try:
                assert_redacted(text)
            except ValueError as exc:
                return "%s: %s" % (os.path.relpath(path, root),
                                   exc)
    return None


def shrink_busy_events(busy_dir):
    """Replace busy events with counts plus sha256, or an error.

    Writes events_summary.json beside the capture and only
    then unlinks the 1 GB events file; on any read or
    parse failure the file is kept and the error returned.
    """
    path = os.path.join(str(busy_dir), "cap", "events.ndjson")
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        return None, "busy events unreadable: %s" % exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return None, "busy events undecodable: %s" % exc
    try:
        counts = persisted_counts(text.splitlines(keepends=True))
    except ValueError as exc:
        return None, "busy events: %s" % exc
    summary = {"sha256": hashlib.sha256(raw).hexdigest(),
               "bytes": len(raw), "counts": counts}
    dest = os.path.join(str(busy_dir), "events_summary.json")
    try:
        with open(dest, "w") as handle:
            json.dump(summary, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError as exc:
        return None, "busy summary unwritable: %s" % exc
    try:
        os.unlink(path)
    except OSError as exc:
        return None, "busy events kept: %s" % exc
    return summary, None


def repo_identity(root):
    """Commit and dirty flag for one checkout.

    Mute git answers unknown and dirty so callers never
    mistake missing identity for a clean tree.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10)
        commit = proc.stdout.strip() if proc.returncode == 0 \
            else ""
        proc = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            return commit or "unknown", True
        return commit or "unknown", bool(proc.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return "unknown", True


BUSY_MAX_EVENTS_BYTES = 4294967296
# A genuine byte-budget stop lands within one 64 KiB
# closing reserve plus one max 64 KiB event line below
# the cap: the writer refuses the line that would cross
# the reserve, and committed bytes never exceed the cap.
BUSY_SIZE_SLACK = 131072


def record_argv(mv, dest, duration, caps, max_events_bytes=None):
    """memveil record argv, with an optional events-bytes cap.

    The busy capture runs 20 s under full read pressure and
    must not hit the default 1 GiB cap mid-window; pass
    BUSY_MAX_EVENTS_BYTES for it, None for the default.
    4 GiB is the product budget maximum and ~2.6x the
    observed saturation capture.
    """
    argv = [mv, "record", "--output", dest, "--duration",
           str(duration), "--capability", caps]
    if max_events_bytes is not None:
        argv += ["--max-events-bytes", str(max_events_bytes)]
    return argv


def build_vng_cmd(prefix, cpus, home, vng_args):
    """Guest command from the shared gate prefix.

    Splices the host CPU set from the environment after
    sudo and carries HOME through so root boots the
    verified user cache instead of a fresh download.
    """
    if not prefix:
        raise ValueError("empty vng prefix")
    task = []
    if cpus:
        validate_shell_path(cpus, "host CPU set")
        task = ["taskset", "-c", cpus]
    if prefix[0] != "sudo":
        return task + list(prefix) + list(vng_args)
    if len(prefix) < 2 or prefix[1] != "-n":
        raise ValueError("sudo prefix without -n")
    rest = list(prefix[2:])
    if "env" not in rest:
        raise ValueError("sudo prefix without env")
    idx = rest.index("env") + 1
    while idx < len(rest) and "=" in rest[idx]:
        idx += 1
    rest.insert(idx, "HOME=" + home)
    return ["sudo", "-n"] + task + rest + list(vng_args)


def validate_shell_path(value, what):
    """Reject paths the vng shell paste would split."""
    if not value or re.search(r"[\s'\"\\$`!;&|<>(){}\[\]*?#~]",
                              value):
        raise ValueError("%s unsafe for shell paste: %r"
                         % (what, value))


def qemu_drive_opt(disk_img, drive_id="d0", serial="mv0",
                   readonly=True):
    """NVMe drive options, commas doubled for QEMU."""
    mode = ",readonly=on" if readonly else ""
    return "-drive file=%s,if=none,id=%s,format=raw," \
        "cache=none%s -device nvme,serial=%s,drive=%s" \
        % (disk_img.replace(",", ",,"), drive_id, mode,
           serial, drive_id)


def scratch_img_path(disk_img, ident):
    """Fresh-per-run scratch image beside the data disk."""
    parent = os.path.dirname(os.path.abspath(disk_img))
    return os.path.join(parent, "scratch-" + ident + ".img")


def persisted_counts(lines):
    """Count persisted kinds, failing on malformed lines."""
    counts = {}
    for num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            kind = json.loads(line).get("kind")
        except ValueError:
            raise ValueError("malformed events line %d" % num)
        if not kind or not isinstance(kind, str):
            raise ValueError("events line %d lacks kind" % num)
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _byte_field(data, field, num):
    try:
        val = int(data[field])
    except (KeyError, TypeError, ValueError):
        raise ValueError("events line %d lacks %s" % (num, field))
    if val < 0 or val > 2 ** 64 - 1:
        raise ValueError("events line %d bad %s" % (num, field))
    return val


def persisted_bytes(lines):
    """Sum byte fields per kind, failing on malformed lines."""
    sums = {"requested": 0, "mapped": 0, "sync": 0,
            "copy": {direction: 0
                     for direction in COPY_DIRECTIONS}}
    for num, line in enumerate(lines, 1):
        text = line.strip()
        if not text:
            continue
        try:
            event = json.loads(text)
        except ValueError:
            raise ValueError("malformed events line %d" % num)
        if not isinstance(event, dict):
            raise ValueError("malformed events line %d" % num)
        kind = event.get("kind")
        if kind not in ("bounce_attempt", "map_result",
                        "sync_request", "copy"):
            continue
        data = event.get("data")
        if not isinstance(data, dict):
            raise ValueError("events line %d lacks data" % num)
        if kind == "bounce_attempt":
            sums["requested"] += _byte_field(
                data, "requested_bytes", num)
        elif kind == "map_result":
            sums["mapped"] += _byte_field(data, "mapped_bytes",
                                          num)
        elif kind == "sync_request":
            sums["sync"] += _byte_field(data, "length", num)
        else:
            direction = data.get("direction")
            if direction not in COPY_DIRECTIONS:
                raise ValueError("events line %d bad direction"
                                 % num)
            sums["copy"][direction] += _byte_field(
                data, "bytes", num)
    return sums


def persisted_copy_dirs(lines):
    """Count copy events per direction, failing on bad rows."""
    dirs = {direction: 0 for direction in COPY_DIRECTIONS}
    for num, line in enumerate(lines, 1):
        text = line.strip()
        if not text:
            continue
        try:
            event = json.loads(text)
        except ValueError:
            raise ValueError("malformed events line %d" % num)
        if not isinstance(event, dict):
            raise ValueError("malformed events line %d" % num)
        if event.get("kind") != "copy":
            continue
        data = event.get("data")
        if not isinstance(data, dict):
            raise ValueError("events line %d lacks data" % num)
        direction = data.get("direction")
        if direction not in COPY_DIRECTIONS:
            raise ValueError("events line %d bad direction"
                             % num)
        dirs[direction] += 1
    return dirs


def unpaired_maps(lines):
    """Successful maps without an unmap, count and bytes.

    Pairs by mapping_id; failed maps never open and
    unmaps without a map are ignored. Other kinds are
    skipped, malformed rows fail.
    """
    mapped = {}
    unmapped = set()
    for num, line in enumerate(lines, 1):
        text = line.strip()
        if not text:
            continue
        try:
            event = json.loads(text)
        except ValueError:
            raise ValueError("malformed events line %d" % num)
        if not isinstance(event, dict):
            raise ValueError("malformed events line %d" % num)
        kind = event.get("kind")
        if kind not in ("map_result", "unmap"):
            continue
        data = event.get("data")
        if not isinstance(data, dict):
            raise ValueError("events line %d lacks data" % num)
        if kind == "unmap":
            if data.get("mapping_id") is not None:
                unmapped.add(data["mapping_id"])
            continue
        if data.get("success") is not True:
            continue
        ident = data.get("mapping_id")
        if not isinstance(ident, str) or not ident:
            raise ValueError("events line %d lacks mapping_id"
                             % num)
        mapped[ident] = _byte_field(data, "mapped_bytes", num)
    count = 0
    nbytes = 0
    for ident, size in mapped.items():
        if ident not in unmapped:
            count += 1
            nbytes += size
    return count, nbytes


def counter_deltas(lines):
    """Attempt counter deltas per id, summed over epochs.

    Values must not move backwards inside an epoch;
    other kinds are skipped, malformed rows fail.
    """
    first = {}
    last = {}
    for num, line in enumerate(lines, 1):
        text = line.strip()
        if not text:
            continue
        try:
            event = json.loads(text)
        except ValueError:
            raise ValueError("malformed events line %d" % num)
        if not isinstance(event, dict):
            raise ValueError("malformed events line %d" % num)
        if event.get("kind") != "counter_snapshot":
            continue
        data = event.get("data")
        if not isinstance(data, dict):
            raise ValueError("events line %d lacks data" % num)
        try:
            ident = data["counter_id"]
            epoch = str(data["epoch"])
            value = int(data["value"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("events line %d bad counter"
                             % num)
        if not isinstance(ident, str) or not ident \
                or value < 0 or value > 2 ** 64 - 1:
            raise ValueError("events line %d bad counter"
                             % num)
        key = (ident, epoch)
        if key not in first:
            first[key] = value
        if value < last.get(key, value):
            raise ValueError("counter %s runs backwards"
                             % ident)
        last[key] = value
    out = {}
    for ident, epoch in first:
        out[ident] = out.get(ident, 0) + last[(ident, epoch)] \
            - first[(ident, epoch)]
    return out


def resolve_inputs(deb, bundle):
    """One binary source: deb and bundle conflict."""
    if deb and bundle:
        raise ValueError("pass one of --deb and --bundle")
    if deb:
        return "deb", deb
    if bundle:
        return "bundle", bundle
    raise ValueError("need --deb/MV_DEB or --bundle")


def merge_summary(old, new):
    """Merge per-run rows keyed by kernel id, new wins."""
    merged = [(row.get("id"), row) for row in old]
    index = {ident: pos for pos, (ident, _) in enumerate(merged)}
    for row in new:
        ident = row.get("id")
        if ident in index:
            merged[index[ident]] = (ident, row)
        else:
            index[ident] = len(merged)
            merged.append((ident, row))
    return [row for _, row in merged]


def check_out_collisions(out, ids):
    """Kernel dirs that already exist and refuse overwrite."""
    return [ident for ident in ids
            if os.path.exists(os.path.join(out, ident))]


def select_kernel_ids(entries, text):
    """Lock entries for a comma-separated id list, in order.

    Every id must exist in the lock exactly once; blank
    entries and repeats fail. Raises ValueError.
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("kernel ids list is empty")
    by_id = {}
    for entry in entries:
        ident = entry.get("id") if isinstance(entry, dict) \
            else None
        if isinstance(ident, str):
            by_id.setdefault(ident, entry)
    picked = []
    seen = set()
    for raw in text.split(","):
        ident = raw.strip()
        if not ident:
            raise ValueError("blank kernel id in %r" % text)
        if ident not in by_id:
            raise ValueError("unknown kernel id %r" % ident)
        if ident in seen:
            raise ValueError("repeated kernel id %r" % ident)
        seen.add(ident)
        picked.append(by_id[ident])
    return picked


def workflow_subset_ids(yml_text):
    """Kernel ids from the workflow MV_KERNELS_IDS line."""
    match = re.search(r"MV_KERNELS_IDS=([0-9A-Za-z.,\-]+)",
                      yml_text or "")
    if not match:
        raise ValueError("workflow subset line missing")
    return match.group(1).split(",")


def check_artifacts(artifacts, tools):
    """Binary, BPF and oracle tool identities match the pins."""
    fails = []
    if not isinstance(artifacts, dict):
        return ["artifacts.json unreadable"]
    binary = artifacts.get("binary") or {}
    if not binary.get("path"):
        fails.append("binary path missing")
    if not isinstance(binary.get("sha256"), str) \
            or not _HEX64.match(binary["sha256"]):
        fails.append("binary sha256 malformed")
    if artifacts.get("mode") == "deb" \
            and not artifacts.get("dpkg_version"):
        fails.append("dpkg version missing")
    bpf = artifacts.get("bpf") or {}
    for obj in ("attempt", "lifecycle", "copy"):
        if not isinstance(bpf.get(obj), str) \
                or not _HEX64.match(bpf[obj]):
            fails.append("bpf %s sha256 malformed" % obj)
    for key in ("bpftrace", "bpftool"):
        if artifacts.get(key) != (tools or {}).get(key):
            fails.append("%s %r drifts from %r"
                         % (key, artifacts.get(key),
                            (tools or {}).get(key)))
    return fails


def fragment_lines(text):
    """Parse kconfig lines into [(symbol, value)] pairs.

    Skips comments and blanks; a "# ... is not set"
    line parses as ("n").
    """
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        match = re.fullmatch(
            r"(CONFIG_[A-Za-z0-9_]+)=(.*)", line)
        if match:
            out.append((match.group(1),
                        match.group(2).strip()))
            continue
        match = re.fullmatch(
            r"#\s*(CONFIG_[A-Za-z0-9_]+)\s+is not set",
            line)
        if match:
            out.append((match.group(1), "n"))
    return out


def merge_fragments(texts):
    """Merge fragment texts, later files override earlier."""
    merged = {}
    for text in texts:
        for sym, val in fragment_lines(text):
            merged[sym] = val
    return merged


def dropped_fragment_lines(merged, final_config):
    """Fragment lines olddefconfig did not keep, named.

    An "=n" line is satisfied by "# ... is not set" or
    by absence; any other value must match exactly.
    Returns ["SYM=value", ...] for the unsatisfied ones.
    """
    final = {}
    for sym, val in fragment_lines(final_config):
        final[sym] = val
    dropped = []
    for sym in sorted(merged):
        want = merged[sym]
        if want == "n":
            if final.get(sym, "n") != "n":
                dropped.append("%s=n" % sym)
        elif final.get(sym) != want:
            dropped.append("%s=%s" % (sym, want))
    return dropped


def cache_base(home, vng):
    """virtme-ng cache dir for one version."""
    return os.path.join(home, ".cache", "virtme-ng", vng, "amd64")


def vmlinuz_for_release(base, release):
    """Verified kernel file by release name."""
    return os.path.join(base, "boot", "vmlinuz-" + release)


def vng_download_cmd(vng, ver):
    """Populate one cache entry through vng itself."""
    return [vng, "--run", ver, "--dry-run"]


def check_toolchain(want, got):
    """Refuse when a pinned toolchain line drifted, by name."""
    bad = []
    for name in TOOLCHAIN_NAMES:
        if want.get(name) != got.get(name):
            bad.append("%s lock=%r host=%r"
                       % (name, want.get(name),
                          got.get(name)))
    if bad:
        raise HostError("toolchain drift: "
                        + "; ".join(bad))


def check_free_space(path, need_gb=25, statvfs=os.statvfs):
    """Refuse when path holds less than need_gb free."""
    try:
        st = statvfs(path)
        free = st.f_bavail * st.f_frsize
    except OSError as exc:
        raise HostError("cannot stat %s: %s" % (path, exc))
    if free < need_gb * 1024 ** 3:
        raise HostError("only %.1f GB free on %s, need %d"
                        % (free / 1024 ** 3, path,
                           need_gb))


def remove_build_links(mods_root):
    """Drop the kbuild build/source links before hashing.

    Only symlinks are removed; a real file or dir at
    those names refuses instead of deleting user data.
    """
    for name in ("build", "source"):
        link = os.path.join(mods_root, name)
        if os.path.islink(link):
            os.unlink(link)
        elif os.path.exists(link):
            raise HostError("%s is not a symlink, refusing "
                            "to remove" % link)


def kcache_base(home):
    """Root holding one dir per built or distro row."""
    override = os.environ.get("MV_KCACHE")
    if override:
        return override
    return os.path.join(home, ".cache", "memveil-kernels")


def entry_cache_dir(home, entry):
    """Verified cache dir for one row, any source kind."""
    source = entry.get("source") or {}
    if source.get("kind") == "archive":
        return cache_base(home, source["vng_version"])
    return os.path.join(kcache_base(home), entry["id"])


def row_boot_label(entry):
    """Short boot artifact label for one row in reports."""
    source = entry.get("source") or {}
    if source.get("kind") == "archive":
        return source.get("vng_version", "")
    return entry.get("id", "")


def _verify_archive_cache(home, entry, source, release):
    vng = source["vng_version"]
    base = cache_base(home, vng)
    if not Path(base).is_dir():
        return False, "cache missing %s" % base, None
    vmlinuz = vmlinuz_for_release(base, release)
    if not os.path.isfile(vmlinuz):
        return False, "vmlinuz-%s missing in %s" % (release,
                                                   base), None
    if sha_file(vmlinuz) != source["vmlinuz_sha256"]:
        return False, "vmlinuz sha drift for %s" % vng, None
    mods = find_modules_root(base, release)
    if not mods:
        return False, "modules missing for %s" % release, None
    sha, _ = modules_manifest_sha(mods)
    if sha != source["modules_manifest_sha256"]:
        return False, "modules manifest drift for %s" % vng, None
    return True, "cache holds", vng


def verify_entry_cache(home, entry):
    """Verify one row cache against the lock hashes.

    Returns (ok, why, kernel_path): the vng tag for
    archive rows, the vmlinuz file for built and distro
    rows. A missing built or distro cache names the tool
    that fills it; nothing is fetched here.
    """
    source = entry.get("source") or {}
    kind = source.get("kind")
    release = entry.get("release")
    ident = entry.get("id")
    if kind == "archive":
        return _verify_archive_cache(home, entry, source,
                                     release)
    if kind == "built":
        want_img = source.get("bzimage_sha256")
        tool = "tools/kernel-build"
    elif kind == "distro":
        want_img = source.get("vmlinuz_sha256")
        tool = "tools/kernel-fetch"
    else:
        return False, "bad source kind for %s" % ident, None
    rowdir = os.path.join(kcache_base(home), ident)
    vmlinuz = os.path.join(rowdir, "boot",
                           "vmlinuz-" + release)
    if not os.path.isfile(vmlinuz):
        return False, "cache missing %s; run %s" % (vmlinuz,
                                                   tool), None
    if sha_file(vmlinuz) != want_img:
        return False, "vmlinuz sha drift for %s" % ident, None
    mods = find_modules_root(rowdir, release)
    if not mods:
        return False, "modules missing for %s; run %s" % (
            release, tool), None
    sha, _ = modules_manifest_sha(mods)
    if sha != source.get("modules_manifest_sha256"):
        return False, "modules manifest drift for %s" % ident, \
            None
    config = os.path.join(rowdir, "config")
    if not os.path.isfile(config):
        return False, "config missing for %s; run %s" % (ident,
                                                        tool), None
    if sha_file(config) != source.get("config_sha256"):
        return False, "config drift for %s" % ident, None
    return True, "cache holds", vmlinuz


def _add_hist_bytes(add, ev, samples, start, end,
                    block_bytes):
    if any("tpb" in snap for _, snap in samples):
        add("oracle_bytes", False,
            "countonly oracle carries tpb")
        return
    status = (ev.get("hist_status_text") or "").strip()
    if not status:
        add("oracle_bytes", False, "hist evidence missing")
        return
    if status.startswith("unsupported:"):
        if status[len("unsupported:"):].strip():
            add("oracle_bytes", True,
                "bytes unproven (%s)" % status, skipped=True)
        else:
            add("oracle_bytes", False,
                "hist status unreadable")
        return
    if status != "ok":
        add("oracle_bytes", False, "hist status unreadable")
        return
    before = ev.get("hist_before_text")
    after = ev.get("hist_after_text")
    if before is None or after is None:
        add("oracle_bytes", False, "hist snapshots missing")
        return
    try:
        tp_lo, tp_hi = oracle_interval(samples, start, end,
                                       "tp")
    except OracleError as exc:
        add("oracle_bytes", False, "hist tp bounds: %s" % exc)
        return
    fails = check_hist_bytes(before, after, block_bytes,
                             tp_lo, tp_hi)
    add("oracle_bytes", not fails,
        "; ".join(fails) or "hist bytes match block total")


def _direction_fails(ev, samples, miss_samples, start,
                     end, attributed, open_leak=0):
    if samples is None or miss_samples is None:
        return ["directions need oracle and progs"]
    if ev.get("persisted_copy_dirs") is None:
        return ["copy direction counts missing"]
    try:
        map_iv = oracle_interval(samples, start, end, "map")
        copy_iv = oracle_interval(samples, start, end, "copy")
        mapd = {d: oracle_interval(samples, start, end,
                                   "mapd%d" % d)
                for d in range(4)}
        copyd = {d: oracle_interval(samples, start, end,
                                    "copyd%d" % d)
                 for d in range(4)}
        _, map_miss_hi = miss_interval(
            miss_samples, start, end, ORACLE_PROGS["map"])
        _, copy_miss_hi = miss_interval(
            miss_samples, start, end, ORACLE_PROGS["copy"])
    except OracleError as exc:
        return ["direction oracle: %s" % exc]
    fails = check_copy_direction_counts(
        ev["persisted_copy_dirs"],
        ev["persisted"].get("copy", 0),
        ev["persisted"].get("map_result", 0),
        mapd[DMA_FROM_DEVICE][0],
        mapd[DMA_FROM_DEVICE][1] + map_miss_hi,
        attributed.get("copy", 0),
        attributed.get("map", 0),
        open_leak)
    fails.extend(check_oracle_direction_formulas(
        map_iv, mapd, copy_iv, copyd, map_miss_hi,
        copy_miss_hi))
    return fails


def _parse_blockstat_doc(text):
    try:
        doc = json.loads(text or "")
        before = int(doc["before"])
        after = int(doc["after"])
    except (ValueError, KeyError, TypeError):
        raise ValueError("blockstat.json unreadable")
    if not isinstance(doc.get("dev"), str) or not doc["dev"]:
        raise ValueError("blockstat device missing")
    return before, after


def evaluate_row(ev):
    """Decide one matrix row from gathered evidence texts.

    Every required check runs and lands in rec checks; the
    row passes only when all pass. Admitted-only checks on
    a refused row are marked skipped with their reason.
    """
    entry = ev["entry"]
    ident = entry["id"]
    release = entry["release"]
    try:
        loss_exact = _release_triple(release) >= (6, 7)
    except ValueError:
        loss_exact = False
    admitted = [cap for cap in CAPS
                if entry["expected"][cap]["verdict"] == "admitted"]
    refused = [(cap, entry["expected"][cap]["reason_class"])
               for cap in CAPS
               if entry["expected"][cap]["verdict"] == "refused"]
    channels = []
    for cap in admitted:
        channels.extend(CAP_CHANNELS[cap])
    rec = {"id": ident, "vng_version": row_boot_label(entry),
           "release": release, "checks": [],
           "dd_count": ev.get("dd_count"),
           "duration": ev.get("duration")}

    def add(name, ok, detail, skipped=False):
        rec["checks"].append({"name": name, "ok": bool(ok),
                              "detail": detail,
                              "skipped": bool(skipped)})

    rec["vng_exit"] = (ev.get("vng_exit") or "").strip()
    add("vng_exit", rec["vng_exit"] == "0",
        "vng exit %s" % rec["vng_exit"])
    fail_txt = ev.get("fail_txt")
    add("no_fail_txt", fail_txt in (None, ""),
        "guest FAIL: %s" % (fail_txt or "").strip()[:120]
        if fail_txt else "no guest FAIL.txt")
    try:
        doctor = json.loads(ev.get("doctor_text") or "")
        if not isinstance(doctor, dict):
            raise ValueError("doctor.json is not an object")
        doctor_ok, doctor_detail = compare_doctor(
            entry["expected"], doctor, release)
    except ValueError as exc:
        doctor = None
        doctor_ok, doctor_detail = False, "doctor.json bad: %s" % exc
    rec["doctor_ok"] = doctor_ok
    rec["doctor_detail"] = doctor_detail
    add("doctor", doctor_ok, doctor_detail)
    doctor_exit = (ev.get("doctor_exit") or "").strip()
    want_exit = expected_doctor_exit(entry)
    add("doctor_exit", doctor_exit == want_exit,
        "doctor exit %s want %s" % (doctor_exit, want_exit))
    try:
        passive = json.loads(ev.get("doctor_passive_text") or "")
        if not isinstance(passive, dict):
            raise ValueError("passive doctor is not an object")
        if doctor is None:
            passive_ok, passive_detail = \
                False, "no load-check doctor"
        else:
            passive_ok, passive_detail = check_passive_doctor(
                passive, doctor)
    except ValueError as exc:
        passive_ok, passive_detail = \
            False, "passive doctor.json bad: %s" % exc
    add("doctor_passive", passive_ok, passive_detail)
    passive_exit = (ev.get("doctor_passive_exit") or "").strip()
    add("doctor_passive_exit", passive_exit == want_exit,
        "passive doctor exit %s want %s" % (passive_exit,
                                            want_exit))
    if doctor is None:
        add("guest_ordinary", False, "no load-check doctor")
    else:
        ok, detail = check_guest_ordinary(
            doctor, ev.get("sev_sysfs_text"))
        add("guest_ordinary", ok, detail)
    ok, detail = check_boot_identity(ev.get("uname_text"),
                                     ev.get("mods_text"), release,
                                     ev.get("cache_dir"))
    add("boot_identity", ok, detail)
    kind = (entry.get("source") or {}).get("kind")
    if kind == "built":
        ok, detail = check_boot_config(
            ev.get("configid_text"),
            (entry["source"] or {}).get("config_sha256"))
        add("boot_config", ok, detail)
    else:
        add("boot_config", True, "no built kernel",
            skipped=True)
    if kind == "distro":
        ok, detail = check_boot_banner(
            ev.get("version_text"),
            (entry["source"] or {}).get("banner"))
        add("boot_banner", ok, detail)
    else:
        add("boot_banner", True, "no distro kernel",
            skipped=True)
    if entry.get("boot_append"):
        ok, detail = check_boot_append(ev.get("uname_text"),
                                       entry["boot_append"])
        add("boot_append", ok, detail)
        if "lockdown=confidentiality" in entry["boot_append"]:
            ok, detail = check_lockdown_effective(
                ev.get("lockdown_text"))
            add("lockdown_effective", ok, detail)
    else:
        add("boot_append", True, "no extra boot args",
            skipped=True)
        add("lockdown_effective", True, "no lockdown arg",
            skipped=True)
    try:
        hooks = json.loads(ev.get("hooks_text") or "")
        if not isinstance(hooks, dict):
            raise ValueError("hooks.json is not an object")
        actual_omitted = hooks.get("omitted")
        hooks_btf = hooks.get("btf")
    except ValueError:
        actual_omitted = None
        hooks_btf = None
    rec["omitted_lock"] = entry["oracle"]["omitted"]
    rec["omitted_actual"] = actual_omitted
    fails = check_omitted(entry["oracle"]["omitted"],
                          actual_omitted, admitted)
    add("omitted", not fails, "; ".join(fails) or "omitted match")
    try:
        artifacts = json.loads(ev.get("artifacts_text") or "")
    except ValueError:
        artifacts = None
    fails = check_artifacts(artifacts, ev.get("tools"))
    add("artifacts", not fails, "; ".join(fails) or "artifacts match")
    if isinstance(artifacts, dict) \
            and isinstance(artifacts.get("binary"), dict):
        rec["binary_sha256"] = artifacts["binary"].get("sha256")
    redact_error = ev.get("export_redact_error")
    if redact_error:
        add("export_redacted", False, "exports: %s" % redact_error)
    else:
        add("export_redacted", True, "exports redacted")
    if admitted:
        ok, detail = check_udev_quiesced(
            ev.get("udev_exit"), ev.get("udev_out"))
        add("udev_quiesced", ok, detail)
    else:
        add("udev_quiesced", True, "no admitted caps",
            skipped=True)
    if refused:
        fails = []
        attempt = entry["expected"].get("attempt-trace", {})
        pair_blind = attempt.get("verdict") == "refused" \
            and attempt.get("reason_class") \
            not in GLOBAL_REFUSE_CLASSES
        doctor_codes = {}
        if isinstance(doctor, dict):
            for cap in doctor.get("capabilities", []):
                if isinstance(cap, dict) and cap.get("id") in CAPS:
                    doctor_codes[cap["id"]] = cap.get(
                        "reason_code")
        for cap, cls in refused:
            if pair_blind and cap != "attempt-trace":
                fails.append("cap-%s: pair cannot attribute a "
                             "refusal while attempt-trace refuses "
                             "for %s" % (cap, attempt.get(
                                 "reason_class")))
                continue
            try:
                want = expected_record_refusal(release, cap, cls)
                want_code = expected_record_code(
                    cls, cap, doctor_codes)
            except ValueError as exc:
                fails.append("cap-%s: %s" % (cap, exc))
                continue
            probe = (ev.get("refusals") or {}).get("cap-" + cap, {})
            ok, detail = check_refusal(probe.get("exit"),
                                       probe.get("out"),
                                       probe.get("exists"), want,
                                       want_code)
            if not ok:
                fails.append("cap-%s: %s" % (cap, detail))
        try:
            want = expected_combined_refusal(release, refused)
            want_code = expected_combined_code(refused,
                                               doctor_codes)
            probe = (ev.get("refusals") or {}).get("combined", {})
            ok, detail = check_refusal(probe.get("exit"),
                                       probe.get("out"),
                                       probe.get("exists"), want,
                                       want_code)
            if not ok:
                fails.append("combined: %s" % detail)
        except ValueError as exc:
            fails.append("combined: %s" % exc)
        add("refusals", not fails,
            "; ".join(fails) or "all refusals exit 3")
    else:
        add("refusals", True, "no refused caps", skipped=True)
    try:
        scan = json.loads(ev.get("dmesg_scan_text") or "")
        if not isinstance(scan, dict):
            raise ValueError("dmesg scan is not an object")
        marker = scan.get("marker")
        scan_present = scan.get("marker_present") is True
        scan_count = scan.get("suspicious")
        if not marker or scan_present is not True \
                or not isinstance(scan_count, int):
            raise ValueError("dmesg scan shape bad")
        assert_redacted(ev.get("dmesg_text") or "")
        present, count = scan_dmesg(ev.get("dmesg_text"),
                                    marker)
        if not present or not scan_present:
            raise ValueError("dmesg marker missing")
        if count != scan_count:
            raise ValueError("dmesg rescan %d differs from %d"
                             % (count, scan_count))
        if count > 0:
            raise ValueError("dmesg holds %d suspicious lines"
                             % count)
        add("dmesg", True, "dmesg clean after marker")
    except ValueError as exc:
        add("dmesg", False, "dmesg: %s" % exc)
    if not admitted:
        for name in ("record_finalized", "report_consistent",
                     "progs_complete", "prog_presence", "window",
                     "workload", "aggregate_quality",
                     "aggregate_bounds", "floors",
                     "ceiling", "recursion_reported",
                     "channels", "invariants", "bytes",
                     "oracle_bytes", "sectors", "sectors_idle",
                     "oracle_health", "capture_valid",
                     "busy_finalized", "busy_stop_reason",
                     "busy_span", "busy_bounds", "busy_valid",
                     "busy_report"):
            add(name, True, "no admitted caps", skipped=True)
        rec["ok"] = all(c["ok"] for c in rec["checks"])
        rec["detail"] = "; ".join(c["detail"] for c in rec["checks"]
                                  if not c["ok"])
        return rec
    if not channels:
        add("channels", False, "admitted caps map to no channels")
        rec["ok"] = False
        rec["detail"] = "; ".join(c["detail"] for c in rec["checks"]
                                  if not c["ok"])
        return rec
    record_exit = (ev.get("record_exit") or "").strip()
    rec["record_exit"] = record_exit
    ok, detail = check_record_finalized(ev.get("record_exit"))
    if not ok:
        detail += "; see record.stderr"
    add("record_finalized", ok, detail)
    rec["report_exit"] = (ev.get("report_exit") or "").strip()
    rec["report_json_exit"] = (ev.get("report_json_exit")
                               or "").strip()
    ok, detail = check_report_consistent(
        ev.get("record_exit"),
        [ev.get("report_exit"), ev.get("report_json_exit")])
    add("report_consistent", ok, detail)
    miss_samples = None
    parsed_snaps = None
    try:
        snaps = ev.get("miss_snaps")
        if not isinstance(snaps, list) or len(snaps) != 4:
            raise ValueError("want 4 bpftool snapshots, got %s"
                             % (len(snaps) if isinstance(
                                 snaps, list) else snaps))
        parsed_snaps = []
        for idx, (nsecs, text) in enumerate(snaps):
            if nsecs is None or text is None:
                raise ValueError("snapshot %d unreadable" % idx)
            progs = json.loads(text or "")
            if not isinstance(progs, list):
                raise ValueError("snapshot is not a list")
            parsed_snaps.append((int(nsecs), progs))
        miss_samples = parse_miss_samples(parsed_snaps)
        add("progs_complete", True, "4 bpftool snapshots bracket")
    except (ValueError, TypeError) as exc:
        parsed_snaps = None
        add("progs_complete", False, "progs: %s" % exc)
    if parsed_snaps is None:
        add("prog_presence", False, "presence needs progs")
    elif actual_omitted is None:
        add("prog_presence", False, "presence needs hooks.json")
    else:
        kept = kept_oracle_probes(admitted, actual_omitted)
        fails = check_prog_presence(parsed_snaps, channels, kept)
        add("prog_presence", not fails,
            "; ".join(fails) or "programs bracket record")
    session = None
    start = end = None
    loss = None
    reported_total = None
    recovered = None
    try:
        session = json.loads(ev.get("session_text") or "")
        start = int(session["capture"]["window"]["start_ns"])
        end = int(session["capture"]["window"]["end_ns"])
        detail = session["quality"]["detail"]
        if not isinstance(detail, dict):
            raise ValueError("Detail quality is not an object")
        loss = parse_detail_loss(detail.get("reason"))
        reported_total = int(detail.get("loss_count"))
        if reported_total != loss["total"]:
            raise ValueError("loss_count differs from reason")
        rec["detail_quality"] = "%s loss=%s" % (
            detail.get("status"), detail.get("loss_count"))
        agg = session["quality"].get("aggregate", {})
        rec["aggregate_quality"] = "%s loss=%s" % (
            agg.get("status"), agg.get("loss_count"))
    except (ValueError, KeyError, TypeError) as exc:
        session = None
        add("window", False, "session.json unreadable (%s)" % exc)
        add("workload", False, "workload needs session")
    parsed_workload = None
    if session is not None:
        try:
            parsed_workload = parse_workload_v2(
                ev.get("workload_text"))
            ok, detail = check_workload_window(
                parsed_workload, start, end)
            add("window", ok, detail)
            fails = check_workload_phases(parsed_workload)
            add("workload", not fails,
                "; ".join(fails) or "phases exact")
        except ValueError as exc:
            parsed_workload = None
            add("window", False, "workload: %s" % exc)
            add("workload", False, "workload: %s" % exc)
    if session is None:
        add("aggregate_quality", False, "aggregate needs session")
    else:
        agg = session["quality"].get("aggregate")
        detail_q = session["quality"].get("detail", {})
        if not isinstance(agg, dict):
            add("aggregate_quality", False,
                "aggregate quality unreadable")
        elif not loss_exact:
            if agg.get("status") == "partial" \
                    and LOWER_BOUND_LABEL in (
                        agg.get("reason") or "") \
                    and detail_q.get("status") == "partial" \
                    and LOWER_BOUND_LABEL in (
                        detail_q.get("reason") or ""):
                add("aggregate_quality", True,
                    "aggregate partial lower bound")
            else:
                add("aggregate_quality", False,
                    "pre-6.7 needs partial plus label in "
                    "detail and aggregate")
        elif LOWER_BOUND_LABEL in (agg.get("reason") or "") \
                or LOWER_BOUND_LABEL in (
                    detail_q.get("reason") or ""):
            add("aggregate_quality", False,
                "lower-bound label on exact-loss kernel")
        elif agg.get("status") == "complete_for_scope" \
                and agg.get("loss_count") == "0":
            add("aggregate_quality", True, "aggregate complete")
        else:
            add("aggregate_quality", False,
                "aggregate %s loss=%s" % (agg.get("status"),
                                          agg.get("loss_count")))
    samples = None
    if session is not None:
        try:
            if ev.get("oracle_text") is None:
                raise ValueError("missing oracle.txt")
            samples = parse_oracle_samples(
                ev["oracle_text"].splitlines(keepends=True))
        except ValueError as exc:
            samples = None
            samples_error = str(exc)
        else:
            samples_error = ""
    else:
        samples_error = "no session window"
    sec_error = ""
    try:
        sec = parse_blockstat_v2(ev.get("blockstat_text"))
    except (ValueError, KeyError, TypeError) as exc:
        sec = None
        sec_error = str(exc)
    if sec is not None:
        read_bytes = (sec[2] - sec[1]) * SECTOR_BYTES
        write_bytes = (sec[5] - sec[4]) * SECTOR_BYTES
        block_bytes = read_bytes + write_bytes
    else:
        read_bytes = write_bytes = block_bytes = None
    bounds = None
    if samples is not None and miss_samples is not None \
            and block_bytes is not None:
        try:
            bounds = {chan: channel_bounds(samples, miss_samples,
                                           start, end, chan)
                      for chan in channels}
            fails = check_channel_floors(
                bounds, channels, count_floor(block_bytes))
            add("floors", not fails,
                "; ".join(fails) or "all channels reach floor")
            fails = check_channel_ceiling(
                bounds, channels, count_ceiling(block_bytes))
            add("ceiling", not fails,
                "; ".join(fails) or "all channels fit ceiling")
        except (OracleError, ValueError, KeyError) as exc:
            bounds = None
            add("floors", False, "floors: %s" % exc)
            add("ceiling", False, "ceiling: %s" % exc)
    else:
        add("floors", False, "floors need oracle, progs, blockstat")
        add("ceiling", False,
            "ceiling needs oracle, progs, blockstat")
    if miss_samples is not None and loss is not None:
        try:
            if "copy" in channels:
                copy_deferred = deferred_from_session(session)
                copy_recovered = recovered_from_session(session)
            else:
                copy_deferred = copy_recovered = 0
            fails = check_recursion_reported(
                miss_samples, start, end,
                loss["recursion_missed"], copy_deferred,
                copy_recovered)
            add("recursion_reported", not fails,
                "; ".join(fails) or "recursion misses reported")
        except (OracleError, ValueError) as exc:
            add("recursion_reported", False, "misses: %s" % exc)
    else:
        add("recursion_reported", False,
            "misses need progs/session")
    per = {}
    overall = None
    attributed = {}
    if ev.get("persisted") is None:
        add("channels", False, "persisted counts missing (%s)"
            % (ev.get("events_error") or "no events error"))
    elif samples is None or miss_samples is None or loss is None \
            or reported_total is None:
        add("channels", False,
            "channels need oracle/progs/session (%s)"
            % samples_error)
    else:
        if "copy" in channels:
            try:
                recovered = recovered_from_session(session)
            except ValueError as exc:
                recovered = None
                add("channels", False, "recovered: %s" % exc)
                per, overall = {}, None
        if recovered is not None or "copy" not in channels:
            if "copy" not in channels:
                recovered = 0
            per, overall, failed, info = decide_channels(
                ev["persisted"], samples, miss_samples, start,
                end, channels, loss, reported_total, recovered,
                liveness_suffix=loss["liveness_suffix"])
            attributed = info.get("attributed", {})
            rec["channels"] = per
            rec["oracle_overall"] = overall
            if failed:
                detail = "; ".join(
                    "%s %s" % pair for pair in sorted(per.items()))
                if info.get("over_reported"):
                    detail += "; captured+loss over oracle bounds"
                add("channels", False, detail or
                    "oracle comparison failed")
            else:
                add("channels", True, overall)
    if not loss_exact:
        add("aggregate_bounds", True,
            "aggregate honesty only below 6.7")
    elif session is None:
        add("aggregate_bounds", False,
            "aggregate bounds need session")
    elif samples is None or miss_samples is None:
        add("aggregate_bounds", False,
            "aggregate bounds need oracle/progs (%s)"
            % samples_error)
    elif ev.get("counters") is None:
        add("aggregate_bounds", False,
            "main counters missing (%s)"
            % (ev.get("counters_error") or "no events error"))
    else:
        agg = session["quality"].get("aggregate")
        ok, detail = decide_main_aggregate(
            agg, ev["counters"], samples, miss_samples,
            loss_exact)
        add("aggregate_bounds", ok, detail)
    leak_open = 0
    leak_bytes = 0
    leak_note = ""
    if session is not None and bounds is not None \
            and ev.get("persisted") is not None:
        try:
            stop_open = int(
                session["stop"]["open_mappings"])
        except (KeyError, TypeError, ValueError):
            stop_open = 0
        unpaired_n = ev.get("unpaired_count")
        unpaired_b = ev.get("unpaired_bytes")
        if stop_open > 0 and unpaired_n == stop_open \
                and isinstance(unpaired_b, int) \
                and oracle_counts_equal(bounds,
                                        ev["persisted"]):
            leak_open = stop_open
            leak_bytes = unpaired_b
            leak_note = "; kernel left %d mappings open" % (
                stop_open)
    if bounds is not None and attributed is not None \
            and ev.get("persisted") is not None:
        fails = check_persisted_invariants(ev["persisted"],
                                           attributed,
                                           leak_open)
        fails.extend(check_oracle_invariants(bounds,
                                             leak_open))
        if "copy" in channels:
            fails.extend(_direction_fails(
                ev, samples, miss_samples, start, end,
                attributed, leak_open))
        if leak_open and not fails:
            add("invariants", True,
                "workload ratios hold" + leak_note)
        else:
            add("invariants", not fails,
                "; ".join(fails) or "workload ratios hold")
    else:
        add("invariants", False, "invariants need channels")
    if block_bytes is not None and loss is not None \
            and ev.get("persisted_bytes") is not None:
        allowance = (transport_loss(loss)
                     + loss["recursion_missed"]
                     + post_latch_loss(loss)) * MAX_MAP_BYTES
        fails = check_memveil_bytes(ev["persisted_bytes"],
                                    read_bytes, write_bytes,
                                    allowance, channels,
                                    leak_bytes)
        if leak_open and not fails:
            add("bytes", True,
                "byte sums match block total" + leak_note)
        else:
            add("bytes", not fails,
                "; ".join(fails)
                or "byte sums match block total")
    else:
        add("bytes", False, "bytes need session, events, blockstat")
    if "attempt" not in channels:
        add("oracle_bytes", True, "no attempt channel",
            skipped=True)
    elif samples is None or miss_samples is None \
            or block_bytes is None:
        add("oracle_bytes", False,
            "oracle bytes need oracle, progs, blockstat")
    else:
        mode = ev.get("oracle_mode")
        if mode is None:
            if any("tpb" in snap for _, snap in samples):
                mode = "full"
            else:
                mode = "countonly"
        if mode == "full" and hooks_btf is False:
            add("oracle_bytes", False,
                "full oracle needs BTF")
        elif mode == "countonly" and hooks_btf is True:
            add("oracle_bytes", False,
                "countonly oracle with BTF present")
        elif mode == "full":
            fails = check_oracle_bytes(samples, miss_samples,
                                       start, end, block_bytes)
            add("oracle_bytes", not fails,
                "; ".join(fails)
                or "oracle bytes match block total")
        elif mode == "countonly":
            _add_hist_bytes(add, ev, samples, start, end,
                            block_bytes)
        else:
            add("oracle_bytes", False,
                "oracle mode unreadable")
    if sec is None:
        add("sectors", False, "sectors: %s" % sec_error)
        add("sectors_idle", False, "idle sides need blockstat")
    elif parsed_workload is None:
        add("sectors", False, "sectors need workload phases")
        add("sectors_idle", False, "idle sides need workload")
    else:
        ok, detail = check_sectors(sec[1], sec[2], sec[4],
                                   sec[5],
                                   parsed_workload[
                                       "read_bytes"],
                                   parsed_workload[
                                       "write_bytes"])
        add("sectors", ok, detail)
        fails = check_idle_sides(sec[6], sec[7], sec[8],
                                 sec[9])
        add("sectors_idle", not fails,
            "; ".join(fails) or "idle sides silent")
    ok, detail = check_oracle_stderr(ev.get("oracle_stderr"))
    add("oracle_health", ok, detail)
    if ev.get("validate_rc") == 0:
        add("capture_valid", True,
            (ev.get("validate_out") or "").strip()[:120])
    else:
        add("capture_valid", False, "validate-schemas rc=%s: %s"
            % (ev.get("validate_rc"),
               (ev.get("validate_out") or "").strip()[:200]))
    ok, detail = check_record_finalized(
        ev.get("busy_record_exit"))
    if not ok:
        detail += "; see busy/record.stderr"
    add("busy_finalized", ok, detail)
    busy_ops = None
    if isinstance(ev.get("busy_persisted"), dict):
        busy_ops = detail_op_count(ev["busy_persisted"])
    ok, detail = check_busy_stop_reason(
        ev.get("busy_end_reason"), ev.get("busy_events_bytes"),
        op_count=busy_ops)
    add("busy_stop_reason", ok, detail)
    try:
        times = json.loads(ev.get("busy_times_text") or "")
        spawn_ns = int(times["spawn_ns"])
        exit_ns = int(times["exit_ns"])
    except (ValueError, KeyError, TypeError):
        add("busy_span", False, "busy times unreadable")
    else:
        try:
            span = parse_busy_span(ev.get("busy_out_text"))
        except ValueError as exc:
            add("busy_span", False, "busy span: %s" % exc)
        else:
            fails = check_busy_span(span, spawn_ns, exit_ns)
            add("busy_span", not fails,
                "; ".join(fails)
                or "busy load spans the record")
    if ev.get("busy_persisted") is None:
        add("busy_bounds", False,
            "busy counts missing (%s)"
            % (ev.get("busy_events_error")
               or "no events error"))
    elif samples is None:
        add("busy_bounds", False,
            "busy bounds need oracle (%s)" % samples_error)
    elif ev.get("busy_miss_snaps") is None:
        add("busy_bounds", False,
            "busy bounds need bpftool snapshots")
    else:
        try:
            busy_session = json.loads(
                ev.get("busy_session_text") or "")
            if not isinstance(busy_session, dict):
                raise ValueError("busy session not an object")
            busy_start = int(busy_session["capture"]["window"]
                             ["start_ns"])
            busy_end = int(busy_session["capture"]["window"]
                           ["end_ns"])
            busy_snaps = ev["busy_miss_snaps"]
            if not isinstance(busy_snaps, list) \
                    or len(busy_snaps) != 3:
                raise ValueError("want 3 busy snapshots")
            parsed_busy = []
            for idx, (nsecs, text) in enumerate(busy_snaps):
                if nsecs is None or text is None:
                    raise ValueError("busy snapshot %d "
                                     "unreadable" % idx)
                progs = json.loads(text or "")
                if not isinstance(progs, list):
                    raise ValueError("busy snapshot not a list")
                parsed_busy.append((int(nsecs), progs))
            busy_miss = parse_miss_samples(parsed_busy)
            busy_ok = True
        except (ValueError, KeyError, TypeError) as exc:
            add("busy_bounds", False, "busy session: %s" % exc)
            busy_ok = False
        if not busy_ok:
            pass
        elif ev.get("busy_counters_error"):
            add("busy_bounds", False, "busy counters: %s"
                % ev["busy_counters_error"])
        else:
            per, overall, failed, info = decide_busy(
                ev["busy_persisted"], samples, busy_miss,
                busy_start, busy_end, channels,
                busy_session, ev.get("busy_counters"),
                loss_exact)
            rec["busy_channels"] = per
            rec["busy_overall"] = overall
            if failed:
                detail = "; ".join(
                    "%s %s" % pair for pair in sorted(per.items()))
                if overall in ("OVER-REPORTED",
                               "AGGREGATE-MISMATCH",
                               "CLAIM-UNPROVEN", "EMPTY"):
                    detail += "; busy %s" % overall.lower()
                if info.get("aggregate"):
                    detail += "; %s" % info["aggregate"]
                add("busy_bounds", False, detail or
                    "busy oracle comparison failed")
            else:
                add("busy_bounds", True, overall)
    if ev.get("busy_validate_rc") == 0:
        add("busy_valid", True,
            (ev.get("busy_validate_out") or "").strip()[:120])
    else:
        add("busy_valid", False, "busy validate-schemas rc=%s: %s"
            % (ev.get("busy_validate_rc"),
               (ev.get("busy_validate_out") or "").strip()[:200]))
    ok, detail = check_report_consistent(
        ev.get("busy_record_exit"),
        [ev.get("busy_report_exit"),
         ev.get("busy_report_json_exit")])
    add("busy_report", ok, detail)
    rec["ok"] = all(c["ok"] for c in rec["checks"])
    rec["detail"] = "; ".join(c["detail"] for c in rec["checks"]
                              if not c["ok"])
    return rec


def build_oracle_program(omitted=None, count_only=False):
    """Build the per-CPU count() oracle program text.

    Omitted probes (missing hooks) leave both the probe and
    their interval fields out so bpftrace still attaches.
    The tracepoint probe also sums bounced bytes into tpb,
    unless count_only drops args for a BTF-less kernel. Map
    and copy probes split counts by args.dir into mapd and
    copyd keys 0..3 for the direction formulas.
    """
    omitted = set(omitted or [])
    for probe in omitted:
        if probe not in PROBES:
            raise ValueError("bad omitted probe " + probe)
    keep = [key for key in PROBES if key not in omitted]
    if not keep:
        raise ValueError("oracle needs at least one probe")
    lines = []
    for key in keep:
        if key == "tp" and count_only:
            lines.append(_PROBE_SNIPPET["tp_countonly"])
        else:
            lines.append(_PROBE_SNIPPET[key])
    fields = []
    reads = []
    for key in keep:
        fields.append("%s=%%llu" % key)
        reads.append("(uint64)@%s" % key)
        if key == "tp" and not count_only:
            fields.append("tpb=%llu")
            reads.append("(uint64)@tpb")
        if key in _DIR_MAPS:
            for direction in range(4):
                fields.append("%s%d=%%llu"
                              % (_DIR_MAPS[key], direction))
                reads.append("(uint64)@%s[%d]"
                             % (_DIR_MAPS[key], direction))
    lines.append('interval:ms:500 { printf("T %%llu %s\\n", nsecs, %s); }'
                 % (" ".join(fields), ", ".join(reads)))
    return "\n".join(lines) + "\n"


def sha_file(path):
    """Hex sha256 of one file."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def modules_manifest_sha(modules_root):
    """Manifest sha over one modules tree plus its file count.

    The manifest lists "<sha>  <relpath>" per regular file
    and "symlink:<target>  <relpath>" per symlink, sorted,
    then hashes that text. Top-level depmod output
    (modules.* except builtin, builtin.modinfo, order) is
    skipped: booting regenerates it, so hashing it would make
    every boot look like a re-download drift. A re-download
    that differs in shipped bytes still changes the sha.
    """
    keep_top = {"modules.builtin", "modules.builtin.modinfo",
                "modules.order"}
    root = Path(modules_root)
    entries = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if len(rel.parts) == 1 and rel.name.startswith("modules.") \
                and rel.name not in keep_top:
            continue
        if path.is_symlink():
            try:
                target = os.readlink(path)
            except OSError:
                target = ""
            entries.append("symlink:%s  %s" % (target, rel))
        elif path.is_file():
            entries.append("%s  %s" % (sha_file(path), rel))
    text = "\n".join(entries) + "\n" if entries else "\n"
    return hashlib.sha256(text.encode()).hexdigest(), len(entries)


def find_modules_root(cache_dir, release):
    """Modules dir for one cached kernel, old or usrmerge layout."""
    lib = os.path.join(str(cache_dir), "lib", "modules", release)
    if os.path.isdir(lib):
        return lib
    usr = os.path.join(str(cache_dir), "usr", "lib", "modules", release)
    if os.path.isdir(usr):
        return usr
    return None


ORACLE_PROGS = {
    "tp": ["tracepoint_swiotlb_swiotlb_bounced"],
    "map": ["fexit_vmlinux_swiotlb_tbl_map_single"],
    "unmap": ["fentry_vmlinux___swiotlb_tbl_unmap_single"],
    "copy": ["fentry_vmlinux_swiotlb_bounce"],
    "syncc": ["fentry_vmlinux___swiotlb_sync_single_for_cpu"],
    "syncd": ["fentry_vmlinux___swiotlb_sync_single_for_device"],
}

ORACLE_INTERVAL_PROG = "interval_ms_500"

MEMVEIL_PROGS = {
    "tp": ["mv_swiotlb_attempt"],
    "map": ["mv_map_result"],
    "unmap": ["mv_unmap"],
    "copy": ["mv_bounce"],
    "sync": ["mv_sync_cpu", "mv_sync_device"],
}


def prog_misses(progs, names):
    """Sum recursion_misses for programs matching one name.

    bpftrace suffixes its program names with an index, so a
    trailing _<digits> is stripped before comparing.
    """
    total = 0
    for prog in progs or []:
        name = prog.get("name", "")
        base = _base_prog_name(name)
        if base in names or name in names:
            try:
                total += int(prog.get("recursion_misses", 0) or 0)
            except (TypeError, ValueError):
                continue
    return total
