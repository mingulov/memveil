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
REFUSE_CLASSES = ("floor-6.0", "floor-6.11", "no-cover", "live-refused")

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

MAX_EDGE_GAP_NS = 10 ** 9
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
    "map": "fexit:vmlinux:swiotlb_tbl_map_single { @map = count(); }",
    "unmap": ("fentry:vmlinux:__swiotlb_tbl_unmap_single"
              " { @unmap = count(); }"),
    "copy": "fentry:vmlinux:swiotlb_bounce { @copy = count(); }",
    "syncc": ("fentry:vmlinux:__swiotlb_sync_single_for_cpu"
              " { @syncc = count(); }"),
    "syncd": ("fentry:vmlinux:__swiotlb_sync_single_for_device"
              " { @syncd = count(); }"),
}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class LockError(ValueError):
    """The lock file is malformed."""


class OracleError(ValueError):
    """Oracle samples do not bracket the capture window."""


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
    release_ver = release.split("-", 1)[0]
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
_TOOLCHAIN_KEYS = frozenset({"gcc", "ld", "pahole"})
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
    for name in ("gcc", "ld", "pahole"):
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


def parse_lock(path):
    """Parse and validate one kernels.lock.json file."""
    try:
        doc = json.loads(Path(path).read_text())
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


def _reason_ok(reason_class, status, reason):
    if reason_class == "live-verified":
        return status == "available" and (
            reason.startswith("live-verified")
            or "verified under" in reason)
    if status == "available":
        return False
    if reason_class == "floor-6.0":
        return "below the 6.0 floor" in reason
    if reason_class == "floor-6.11":
        return "below the 6.11 floor" in reason
    if reason_class == "no-cover":
        return "no profile covers" in reason
    if reason_class == "live-refused":
        if status != "unavailable":
            return False
        keys = ("not listed", "absent", "differs", "live", "BTF",
                "layout", "signature", "filter", "unreadable",
                "format", "attach")
        low = reason.lower()
        return any(k.lower() in low for k in keys)
    return False


def compare_doctor(expected, doctor):
    """Compare lock expectations with one doctor --json document.

    Admitted needs available plus a verified reason. Refused
    needs a non-available status plus its reason class. Returns
    (ok, detail) with one line per capability.
    """
    got = {}
    for cap in doctor.get("capabilities", []):
        got[cap.get("id")] = (cap.get("status"), cap.get("reason", ""))
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
        status, reason = got[cap]
        if _reason_ok(want["reason_class"], status, reason):
            lines.append("%s: match (%s)" % (cap, status))
        else:
            lines.append("%s: want %s/%s got %s (%s)"
                         % (cap, want["verdict"], want["reason_class"],
                            status, reason))
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


def oracle_interval(samples, start_ns, end_ns, key):
    """Conservative [lo, hi] oracle count for key over [start, end)."""
    before_start, after_start, before_end, after_end = bracket_oracle(
        samples, start_ns, end_ns)
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


def channel_bounds(samples, miss_samples, start_ns, end_ns, chan):
    """Oracle [lo, hi] for one channel, misses bracketed in."""
    kind, keys = KINDS[chan]
    del kind
    lo = hi = 0
    for key in keys:
        klo, khi = oracle_interval(samples, start_ns, end_ns, key)
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


def parse_detail_loss(reason):
    """Parse the strict detail loss grammar into counters."""
    match = re.fullmatch(
        r"detail loss (\d+) \(submit_fail=\((\d+)\) "
        r"malformed=\((\d+)\) dropped=\((\d+)\) "
        r"recursion_missed=\((\d+)\) size_omitted=\((\d+)\) "
        r"duration_omitted=\((\d+)\) signal_omitted=\((\d+)\) "
        r"rejected=\((\d+)\) write_failed=\((\d+)\)\)",
        reason or "")
    if not match:
        raise ValueError("detail loss grammar mismatch")
    nums = [int(v) for v in match.groups()]
    keys = ["total", "submit_fail", "malformed", "dropped",
            "recursion_missed", "size_omitted",
            "duration_omitted", "signal_omitted", "rejected",
            "write_failed"]
    parsed = dict(zip(keys, nums))
    expect = sum(parsed[k] for k in TRANSPORT_KEYS) \
        + parsed["recursion_missed"] \
        + sum(parsed[k] for k in POST_LATCH_KEYS)
    if parsed["total"] != expect:
        raise ValueError("Detail loss total contradicts parts")
    return parsed


def transport_loss(parsed):
    """Attributable transport loss, post-latch omits excluded."""
    return sum(parsed[key] for key in TRANSPORT_KEYS)


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
                    recovered):
    """Per-channel verdicts under the strict loss rules.

    Each shortfall must fit that channel memveil misses plus
    transport loss; the total shortfall must fit transport
    plus reported recursion misses, never post-latch omits;
    captured plus reported loss must stay inside the summed
    oracle bounds so over-reporting fails. Returns
    (per, overall, failed, info).
    """
    per = {}
    bounds = {}
    shortfalls = {}
    allowances = {}
    attributed = {}
    transport = transport_loss(loss)
    for chan in channels:
        kind, _ = KINDS[chan]
        try:
            lo, hi = channel_bounds(samples, miss_samples,
                                    start_ns, end_ns, chan)
            allowance = channel_allowance(
                miss_samples, start_ns, end_ns, chan,
                transport, recovered if chan == "copy" else 0)
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
    allowed_total = transport + loss["recursion_missed"]
    info.update({"sum_got": sum_got, "sum_lo": sum_lo,
                 "sum_hi": sum_hi, "total_short": total_short,
                 "allowed_total": allowed_total,
                 "over_reported": sum_got + reported_total > sum_hi})
    if any(v.startswith("SHORT-UNCOVERED") for v in per.values()):
        return per, "SHORT-UNCOVERED", True, info
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


def check_persisted_invariants(persisted, attributed):
    """Fixed workload ratios within attributed loss.

    Each map carries one attempt, one unmap and one sync;
    each map copies twice. Present channels only: a row
    with one channel has no ratio to check.
    """
    fails = []
    group = [k for k in ("bounce_attempt", "map_result", "unmap",
                         "sync_request") if k in persisted]
    for i in range(len(group)):
        for j in range(i + 1, len(group)):
            first, second = group[i], group[j]
            allow = attributed.get(_kind_channel(first), 0) \
                + attributed.get(_kind_channel(second), 0)
            if abs(persisted[first] - persisted[second]) > allow:
                fails.append("%s=%d vs %s=%d beyond loss %d"
                             % (first, persisted[first],
                                second, persisted[second], allow))
    if "copy" in persisted and "map_result" in persisted:
        allow = attributed.get("copy", 0) \
            + 2 * attributed.get("map", 0)
        if abs(persisted["copy"]
               - 2 * persisted["map_result"]) > allow:
            fails.append("copy=%d vs 2xmap=%d beyond loss %d"
                         % (persisted["copy"],
                            2 * persisted["map_result"], allow))
    return fails


def check_oracle_invariants(bounds):
    """Oracle intervals must share the workload ratios."""
    fails = []
    group = [c for c in ("attempt", "map", "unmap", "sync")
             if c in bounds]
    if len(group) >= 2:
        top = max(bounds[c][0] for c in group)
        bottom = min(bounds[c][1] for c in group)
        if top > bottom:
            fails.append("oracle attempt/map/unmap/sync disjoint")
    if "copy" in bounds and "map" in bounds:
        clo, chi = bounds["copy"]
        mlo, mhi = bounds["map"]
        if clo > 2 * mhi or 2 * mlo > chi:
            fails.append("oracle copy not twice map")
    return fails


def check_memveil_bytes(byte_sums, block_bytes, allowance,
                        channels):
    """Persisted byte sums must match the block layer total.

    Requested, mapped and sync sums plus each copy
    direction equal the sector bytes exactly at zero loss;
    any shortfall must fit the loss allowance. Over always
    fails. Present channels only.
    """
    try:
        sums = {"requested": int(byte_sums["requested"]),
                "mapped": int(byte_sums["mapped"]),
                "sync": int(byte_sums["sync"])}
        copies = {direction: int(byte_sums["copy"][direction])
                  for direction in COPY_DIRECTIONS}
    except (KeyError, TypeError, ValueError):
        return ["byte sums unreadable"]
    fails = []
    for chan, field in (("attempt", "requested"),
                        ("map", "mapped"), ("sync", "sync")):
        if chan not in channels:
            continue
        if sums[field] > block_bytes:
            fails.append("%s bytes %d over block %d"
                         % (field, sums[field], block_bytes))
        elif block_bytes - sums[field] > allowance:
            fails.append("%s bytes %d short of block %d beyond "
                         "loss %d" % (field, sums[field],
                                      block_bytes, allowance))
    if "copy" in channels:
        for direction in COPY_DIRECTIONS:
            got = copies[direction]
            if got > block_bytes:
                fails.append("copy %s bytes %d over block %d"
                             % (direction, got, block_bytes))
            elif block_bytes - got > allowance:
                fails.append("copy %s bytes %d short of block %d "
                             "beyond loss %d"
                             % (direction, got, block_bytes,
                                allowance))
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


def parse_blockstat(text):
    """Sectors read from one /sys/block/*/stat line."""
    try:
        return int((text or "").split()[2])
    except (IndexError, ValueError):
        raise ValueError("block stat line unparseable")


def check_sectors(before, after, dd_count):
    """Sectors read must track the fixed dd workload."""
    expect = WORKLOAD_GROUPS * int(dd_count) * 2048
    delta = after - before
    if delta <= 0:
        return False, "block sectors show no reads"
    if delta < expect // 2 or delta > expect * 2:
        return False, "block sectors %d far from %d expected" % (
            delta, expect)
    return True, "block sectors %d near %d expected" % (delta,
                                                        expect)


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


def check_refusal(exit_text, out_text, exists_text, want_reason):
    """One refusal probe: exit 3, reason, no output dir."""
    if (exit_text or "").strip() != "3":
        return False, "exit %r want 3" % (exit_text or "")
    if want_reason not in (out_text or ""):
        return False, "reason lacks %r" % want_reason
    if (exists_text or "").strip() != "no":
        return False, "left partial capture"
    return True, "refused exit 3 (%s)" % want_reason


def expected_doctor_exit(entry):
    """Doctor exits 3 exactly when attempt-trace is refused."""
    if entry["expected"]["attempt-trace"]["verdict"] == "admitted":
        return "0"
    return "3"


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
    """Fail when a raw address survived redaction."""
    if re.search(r"0x[0-9a-fA-F]", text or ""):
        raise ValueError("redacted text keeps 0x address")
    if re.search(r"[0-9a-fA-F]{16,}", text or ""):
        raise ValueError("redacted text keeps long hex run")


REDACT_SKIP_FILES = ("artifacts.json", "progs0.json",
                     "progs1.json", "progs2.json",
                     "progs3.json", "report.json")


def scan_export_redaction(export):
    """Assert every guest text export is redacted.

    Skips the capture dir (product output, covered by the
    product privacy suites) and the files that carry hashes
    and bpftool tags by design. Returns None when clean,
    else the first offending file and reason.
    """
    root = str(export)
    first = True
    for dirpath, dirnames, filenames in os.walk(root):
        if first:
            first = False
            if "cap" in dirnames:
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


def qemu_drive_opt(disk_img):
    """Read-only NVMe drive options, commas doubled for QEMU."""
    return "-drive file=%s,if=none,id=d0,format=raw," \
        "cache=none,readonly=on -device nvme,serial=mv0,drive=d0" \
        % disk_img.replace(",", ",,")


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


def cache_base(home, vng):
    """virtme-ng cache dir for one version."""
    return os.path.join(home, ".cache", "virtme-ng", vng, "amd64")


def vmlinuz_for_release(base, release):
    """Verified kernel file by release name."""
    return os.path.join(base, "boot", "vmlinuz-" + release)


def vng_download_cmd(vng, ver):
    """Populate one cache entry through vng itself."""
    return [vng, "--run", ver, "--dry-run"]


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
            entry["expected"], doctor)
    except ValueError as exc:
        doctor_ok, doctor_detail = False, "doctor.json bad: %s" % exc
    rec["doctor_ok"] = doctor_ok
    rec["doctor_detail"] = doctor_detail
    add("doctor", doctor_ok, doctor_detail)
    doctor_exit = (ev.get("doctor_exit") or "").strip()
    want_exit = expected_doctor_exit(entry)
    add("doctor_exit", doctor_exit == want_exit,
        "doctor exit %s want %s" % (doctor_exit, want_exit))
    ok, detail = check_boot_identity(ev.get("uname_text"),
                                     ev.get("mods_text"), release,
                                     ev.get("cache_dir"))
    add("boot_identity", ok, detail)
    try:
        hooks = json.loads(ev.get("hooks_text") or "")
        if not isinstance(hooks, dict):
            raise ValueError("hooks.json is not an object")
        actual_omitted = hooks.get("omitted")
    except ValueError:
        actual_omitted = None
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
    if refused:
        fails = []
        attempt = entry["expected"].get("attempt-trace", {})
        pair_blind = attempt.get("verdict") == "refused" \
            and attempt.get("reason_class") != "floor-6.0"
        for cap, cls in refused:
            if pair_blind and cap != "attempt-trace":
                fails.append("cap-%s: pair cannot attribute a "
                             "refusal while attempt-trace refuses "
                             "for %s" % (cap, attempt.get(
                                 "reason_class")))
                continue
            try:
                want = expected_record_refusal(release, cap, cls)
            except ValueError as exc:
                fails.append("cap-%s: %s" % (cap, exc))
                continue
            probe = (ev.get("refusals") or {}).get("cap-" + cap, {})
            ok, detail = check_refusal(probe.get("exit"),
                                       probe.get("out"),
                                       probe.get("exists"), want)
            if not ok:
                fails.append("cap-%s: %s" % (cap, detail))
        try:
            want = expected_combined_refusal(release, refused)
            probe = (ev.get("refusals") or {}).get("combined", {})
            ok, detail = check_refusal(probe.get("exit"),
                                       probe.get("out"),
                                       probe.get("exists"), want)
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
                     "aggregate_quality", "floors", "ceiling",
                     "recursion_reported", "channels",
                     "invariants", "bytes", "oracle_bytes",
                     "sectors", "oracle_health", "capture_valid"):
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
    if session is not None:
        try:
            parsed = parse_workload(ev.get("workload_text"))
            ok, detail = check_workload_window(parsed, start,
                                               end)
            add("window", ok, detail)
        except ValueError as exc:
            add("window", False, "workload: %s" % exc)
    if session is None:
        add("aggregate_quality", False, "aggregate needs session")
    else:
        agg = session["quality"].get("aggregate")
        if not isinstance(agg, dict):
            add("aggregate_quality", False,
                "aggregate quality unreadable")
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
    sec_before = sec_after = None
    sec_error = ""
    try:
        sec_before, sec_after = _parse_blockstat_doc(
            ev.get("blockstat_text"))
    except (ValueError, KeyError, TypeError) as exc:
        sec_error = str(exc)
    if sec_before is not None and sec_after - sec_before > 0:
        block_bytes = (sec_after - sec_before) * SECTOR_BYTES
    else:
        block_bytes = None
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
                end, channels, loss, reported_total, recovered)
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
    if bounds is not None and attributed is not None \
            and ev.get("persisted") is not None:
        fails = check_persisted_invariants(ev["persisted"],
                                           attributed)
        fails.extend(check_oracle_invariants(bounds))
        add("invariants", not fails,
            "; ".join(fails) or "workload ratios hold")
    else:
        add("invariants", False, "invariants need channels")
    if block_bytes is not None and loss is not None \
            and ev.get("persisted_bytes") is not None:
        allowance = (transport_loss(loss)
                     + loss["recursion_missed"]) * MAX_MAP_BYTES
        fails = check_memveil_bytes(ev["persisted_bytes"],
                                    block_bytes, allowance,
                                    channels)
        add("bytes", not fails,
            "; ".join(fails) or "byte sums match block total")
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
        fails = check_oracle_bytes(samples, miss_samples, start,
                                   end, block_bytes)
        add("oracle_bytes", not fails,
            "; ".join(fails) or "oracle bytes match block total")
    if sec_before is None:
        add("sectors", False, "sectors: %s" % sec_error)
    else:
        ok, detail = check_sectors(sec_before, sec_after,
                                   ev["dd_count"])
        add("sectors", ok, detail)
    ok, detail = check_oracle_stderr(ev.get("oracle_stderr"))
    add("oracle_health", ok, detail)
    if ev.get("validate_rc") == 0:
        add("capture_valid", True,
            (ev.get("validate_out") or "").strip()[:120])
    else:
        add("capture_valid", False, "validate-schemas rc=%s: %s"
            % (ev.get("validate_rc"),
               (ev.get("validate_out") or "").strip()[:200]))
    rec["ok"] = all(c["ok"] for c in rec["checks"])
    rec["detail"] = "; ".join(c["detail"] for c in rec["checks"]
                              if not c["ok"])
    return rec


def build_oracle_program(omitted=None):
    """Build the per-CPU count() oracle program text.

    Omitted probes (missing hooks) leave both the probe and
    their interval fields out so bpftrace still attaches.
    The tracepoint probe also sums bounced bytes into tpb.
    """
    omitted = set(omitted or [])
    for probe in omitted:
        if probe not in PROBES:
            raise ValueError("bad omitted probe " + probe)
    keep = [key for key in PROBES if key not in omitted]
    if not keep:
        raise ValueError("oracle needs at least one probe")
    lines = [_PROBE_SNIPPET[key] for key in keep]
    fields = []
    reads = []
    for key in keep:
        fields.append("%s=%%llu" % key)
        reads.append("(uint64)@%s" % key)
        if key == "tp":
            fields.append("tpb=%llu")
            reads.append("(uint64)@tpb")
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
