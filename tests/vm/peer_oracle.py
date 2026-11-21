#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Peer-network DMA-lifetime oracle at the outer DMA API + L11 leg judge.

The oracle observes streaming DMA lifetimes through tracefs
``events/dma`` (``dma_map_phys``/``dma_unmap_phys``) on the owned
off-loopback NIC while peer traffic runs, then pairs each
successful map to its release. The L11 judge checks nonzero
peer traffic, zero oracle loss, bracket attribution, and
agreement with persisted product lifecycle records for the
proven bounced subset, with gaps charged to declared loss
only.

Pairing rule (proven by the hook-coverage probe on the pinned
guest: exact 500/500 with zero orphans): pair by the
guest-local handle ``(device, dma_addr)`` with time-ordered
FIFO discipline, cross-checked by size and direction.
Generation is IMPLICIT IN ORDERING: there is no explicit
generation, sequence, or id field shared by both events. The
unmap record carries no ``phys_addr`` (kernel print format),
so physical identity never enters the correlator. Because
generation is implicit, pairing is only sound when ordering
is preserved; the judge therefore proves ordering (global
plus per-CPU non-decreasing timestamps over the filtered
device stream, strict map-before-unmap per FIFO head,
non-negative lifetimes) and fails closed on ANY order
violation instead of assuming an explicit generation.

Only the two streaming events are enabled. No siblings:
coherent ``dma_alloc``/``dma_free`` events cover a different
(allocation, not streaming-mapping) lifetime family the
pcnet path does not exercise here; ``dma_map_sg``/``unmap_sg``
cover scatter-gather lists the exercised path does not emit
(the probe window held exactly map/unmap pairs, all
single); ``dma_sync_*`` events carry no lifetime endpoints.
Enabling them would add unattributed records and buffer
pressure without covering any additional pcnet lifetime, so
the guest asserts the enabled set is exactly these two and
the judge requires it.

This module is stdlib-only and guest-safe: the guest flow
imports it to parse and pair in-guest (raw trace bytes never
cross to the host). Anything needing pytest or sibling
harness modules is imported lazily inside its function so a
guest import never touches them.

Battery adoption contract: case id ``peer`` (``CASE_ID``),
900 s timeout (``CASE_TIMEOUT``), full-machine network boot
(``CASE_NETWORK``), armed by ``MEMVEIL_VM_PEER=1``
(``PEER_ENV``), export prefix ``peer`` with inventory
``peer.json``, ``cap-session.json``, ``cap-events.ndjson``,
``record.out``, ``record.stderr``.
"""

import hashlib
import json
import os
import re
from collections import Counter, deque

CASE_ID = "peer"
CASE_TIMEOUT = 900
CASE_NETWORK = True
PEER_ENV = "MEMVEIL_VM_PEER"
# Product record stdout/stderr, exported from the guest on
# every path (success plus every failure) so a capture
# refusal stays diagnosable after the guest is gone.
RECORD_LOGS = ("record.out", "record.stderr")
EXPORT_NAMES = ("peer.json", "cap-session.json",
                "cap-events.ndjson") + RECORD_LOGS

MAP_EVENT = "dma_map_phys"
UNMAP_EVENT = "dma_unmap_phys"
MARK_EVENT = "tracing_mark_write"
ORACLE_EVENTS = (MAP_EVENT, UNMAP_EVENT)

# Bracket phase boundaries, written in-trace by the guest.
# Phases: pre = (PRE, DOWN), teardown = (DOWN, UP),
# post = (UP, END); POST must fall strictly inside post.
MARKERS = {
    "pre": "PEER-PRE",
    "down": "PEER-DOWN",
    "up": "PEER-UP",
    "post": "PEER-POST",
    "end": "PEER-END",
}
TRAFFIC_BEGIN = "PEER-TRAFFIC-BEGIN"
TRAFFIC_END = "PEER-TRAFFIC-END"

DIRS = ("BIDIRECTIONAL", "TO_DEVICE", "FROM_DEVICE", "NONE")

# Declared detail-loss grammar: nine pooled buckets in fixed
# order summing to the head count (product detail reason).
LOSS_BUCKETS = ("submit_fail", "malformed", "dropped",
                "recursion_missed", "size_omitted",
                "duration_omitted", "signal_omitted",
                "rejected", "write_failed")

PEER_SCHEMA = "memveil-peer-oracle/1"
RECEIPT_SCHEMA = "memveil-peer-leg-receipt/1"
RECORD_LOG_NOTE_SCHEMA = "memveil-peer-record-logs/1"
MONO_CLOCK = "CLOCK_MONOTONIC"

BDF_RE = re.compile(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:"
                    r"[0-9a-fA-F]{2}\.[0-9]")
LINE_RE = re.compile(
    r"^(?P<task>.*?)\s+\[(?P<cpu>\d+)\]\s+(?P<flags>\S+)"
    r"\s+(?P<ts>\d+\.\d+):\s+(?P<event>[A-Za-z_][A-Za-z0-9_]*)"
    r":\s*(?P<body>.*)$")
HEADER_RE = re.compile(
    r"#\s*entries-in-buffer/entries-written:\s*(\d+)/(\d+)")
PAIR_RE = re.compile(r"(\w+)=(\S+)")
READY_RE = re.compile(
    r"ready session=(cap-[0-9]+-[0-9]+|[a-z][a-z0-9_.-]{0,127})"
    r" start_ns=(0|[1-9][0-9]{0,19})")
LOSS_HEAD_RE = re.compile(r"detail loss (\d+) \(")
LOSS_PAIR_RE = re.compile(r"([A-Za-z_]+)=\((\d+)\)")
SHA_RE = re.compile(r"[0-9a-f]{64}")
IFACE_RE = re.compile(r"[a-zA-Z0-9_-]{1,32}")
CPU_RE = re.compile(r"cpu[0-9]+")
HEX_RE = re.compile(r"[0-9a-fA-F]+")
KEY_RE = re.compile(r"k[0-9]{4,}")


class OracleError(ValueError):
    """Fail-closed oracle failure (parse/order/pair/validate)."""


def parse_ts_us(text):
    """Trace ``seconds.fraction`` stamp to integer microseconds."""
    sec, dot, frac = text.partition(".")
    if not dot or not sec.isdigit() or not frac.isdigit():
        raise OracleError("bad timestamp %r" % (text,))
    return int(sec) * 1000000 + int((frac + "000000")[:6])


def parse_trace_line(line, lineno):
    """Parse one ``trace`` text line into a typed record.

    Returns ``(kind, record)`` with kind one of ``comment``,
    ``marker``, ``map``, ``unmap``, ``other``. Malformed DMA
    lines raise: the oracle never silently skips a record it
    was enabled to observe. The device arrives as a bare
    positional PCI BDF token (no ``dev=`` pair) and must
    match exactly; anything else is a parse failure, which
    also defeats device-alias confusion at the source.
    """
    if not line.strip() or line.lstrip().startswith("#"):
        return "comment", {"line": lineno, "text": line}
    match = LINE_RE.match(line)
    if match is None:
        raise OracleError("line %d: unparseable trace line %r"
                          % (lineno, line[:120]))
    event = match.group("event")
    body = match.group("body")
    if event == MARK_EVENT:
        return "marker", {"line": lineno,
                          "task": match.group("task").strip(),
                          "cpu": match.group("cpu"),
                          "ts_us": parse_ts_us(match.group("ts")),
                          "marker": body.strip()}
    if event not in ORACLE_EVENTS:
        return "other", {"line": lineno, "event": event,
                         "task": match.group("task").strip(),
                         "cpu": match.group("cpu"),
                         "ts_us": parse_ts_us(match.group("ts"))}
    fields = {}
    for key, value in PAIR_RE.findall(body):
        # First occurrence wins: the kernel emits each key
        # once, and a doubled key must not override it.
        fields.setdefault(key, value)
    tokens = body.split()
    device = None
    if len(tokens) >= 2:
        candidate = tokens[1] if tokens[0].endswith(":") \
            else tokens[0]
        if BDF_RE.fullmatch(candidate):
            device = candidate.lower()
    if device is None:
        raise OracleError("line %d: %s lacks a PCI BDF device"
                          % (lineno, event))
    direction = fields.get("dir")
    if direction not in DIRS:
        raise OracleError("line %d: %s bad dir %r"
                          % (lineno, event, direction))
    dma_addr = fields.get("dma_addr")
    if dma_addr is None or not HEX_RE.fullmatch(dma_addr) \
            or len(dma_addr) > 16:
        raise OracleError("line %d: %s bad dma_addr %r"
                          % (lineno, event, dma_addr))
    size = fields.get("size")
    if size is None or not size.isdigit() \
            or int(size) >= (1 << 64):
        raise OracleError("line %d: %s bad size %r"
                          % (lineno, event, size))
    record = {"line": lineno, "event": event,
              "task": match.group("task").strip(),
              "cpu": match.group("cpu"),
              "ts_us": parse_ts_us(match.group("ts")),
              "device": device, "dir": direction,
              "dma_addr": dma_addr.lower(), "size": int(size),
              "attrs": fields.get("attrs", "")}
    if event == MAP_EVENT:
        phys = fields.get("phys_addr")
        if phys is None or not HEX_RE.fullmatch(phys) \
                or len(phys) > 16:
            raise OracleError("line %d: map bad phys_addr %r"
                              % (lineno, phys))
        record["phys_addr"] = phys.lower()
    return ("map" if event == MAP_EVENT else "unmap"), record


def read_trace_window(text, device):
    """Parse one window dump for the owned device.

    Returns a dict with ``records`` (owned-device map/unmap
    in file order), ``markers`` (marker text to line list),
    ``header`` (entries in-buffer/written or None),
    ``other_device`` counts, ``other_events`` (unexpected
    kinds), and ``lines`` (total). The device filter is an
    exact BDF match on the parsed device field, never a
    substring search, so alias-shaped tokens cannot leak
    across devices.
    """
    want = device.lower()
    if not BDF_RE.fullmatch(device):
        raise OracleError("bad oracle device %r" % (device,))
    records = []
    markers = {}
    header = None
    other_device = Counter()
    other_events = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, 1):
        if header is None:
            match = HEADER_RE.search(line)
            if match:
                header = {"in_buffer": int(match.group(1)),
                          "written": int(match.group(2))}
        kind, record = parse_trace_line(line, lineno)
        if kind == "marker":
            markers.setdefault(record["marker"], []).append(
                record["line"])
        elif kind in ("map", "unmap"):
            if record["device"] != want:
                other_device[kind] += 1
            else:
                records.append(record)
        elif kind == "other":
            other_events.append(record)
    return {"records": records, "markers": markers,
            "header": header, "other_device": other_device,
            "other_events": other_events, "lines": len(lines)}


def check_ordering(records):
    """Prove ordering preservation over the pairing stream.

    Generation is implicit in ordering, so pairing is only
    sound on an order-preserving stream: timestamps must be
    non-decreasing globally (merged file order) and per CPU.
    Ties are allowed (equal stamps order by file position).
    Returns violation strings; empty proves the discipline.
    """
    bad = []
    previous = None
    per_cpu = {}
    for record in records:
        stamp = record["ts_us"]
        if previous is not None and stamp < previous:
            bad.append("global order violation at line %d: "
                       "%d < %d" % (record["line"], stamp,
                                    previous))
        previous = stamp
        cpu = record["cpu"]
        if cpu in per_cpu and stamp < per_cpu[cpu]:
            bad.append("cpu%s order violation at line %d: "
                       "%d < %d" % (cpu, record["line"], stamp,
                                    per_cpu[cpu]))
        per_cpu[cpu] = stamp
    return bad


def assign_key_ids(records):
    """Opaque key id per unique ``(device, dma_addr)`` handle.

    First-seen order, ``k0001``-style. The ids preserve the
    pairing structure (which events share a handle) while
    carrying no address bits, so the host can re-verify the
    full pairing discipline from opaque rows alone.
    """
    table = {}
    for record in records:
        key = (record["device"], record["dma_addr"])
        if key not in table:
            table[key] = "k%04d" % (len(table) + 1,)
    return table


def pair_fifo(records):
    """Pair maps to releases by handle with FIFO discipline.

    One FIFO queue per ``(device, dma_addr)`` handle: each
    unmap pops the earliest open map, which must match in
    size and direction with a non-negative lifetime. Any
    mismatch, negative lifetime, or order violation finding
    fails the judge downstream; this function reports every
    anomaly instead of guessing. Returns a dict with
    ``pairs``, ``orphans`` (unmap without an open map),
    ``still_open`` (map without a release),
    ``mismatches``, and ``counts``.
    """
    waiting = {}
    pairs = []
    orphans = []
    mismatches = []
    maps = 0
    for record in records:
        key = (record["device"], record["dma_addr"])
        if record["event"] == MAP_EVENT:
            maps += 1
            waiting.setdefault(key, deque()).append(record)
            continue
        queue = waiting.get(key)
        if not queue:
            orphans.append(record)
            continue
        opened = queue.popleft()
        if (record["size"] != opened["size"]
                or record["dir"] != opened["dir"]):
            mismatches.append({"map": opened, "unmap": record})
            continue
        lifetime = record["ts_us"] - opened["ts_us"]
        if lifetime < 0:
            mismatches.append({"map": opened, "unmap": record,
                               "negative_lifetime": lifetime})
            continue
        pairs.append({"id": "p%04d" % (len(pairs) + 1,),
                      "key": key, "dir": record["dir"],
                      "size": record["size"],
                      "map_line": opened["line"],
                      "unmap_line": record["line"],
                      "map_ts_us": opened["ts_us"],
                      "unmap_ts_us": record["ts_us"],
                      "lifetime_us": lifetime})
    still_open = []
    for key in sorted(waiting):
        still_open.extend(waiting[key])
    return {"pairs": pairs, "orphans": orphans,
            "still_open": still_open, "mismatches": mismatches,
            "counts": {"maps": maps,
                       "unmaps": len(records) - maps,
                       "pairs": len(pairs),
                       "orphans": len(orphans),
                       "still_open": len(still_open),
                       "mismatches": len(mismatches)}}


def export_rows(records):
    """Opaque per-event audit rows for the host re-verify.

    Each row carries line, timestamp, CPU, kind, opaque key
    id, direction, and size: exactly the pairing structure,
    with no address bits. The host re-runs ordering plus
    FIFO pairing from these rows and must reproduce the
    guest aggregates exactly.
    """
    table = assign_key_ids(records)
    rows = []
    for record in records:
        rows.append({
            "line": record["line"], "ts_us": record["ts_us"],
            "cpu": record["cpu"],
            "kind": ("map" if record["event"] == MAP_EVENT
                     else "unmap"),
            "key": table[(record["device"],
                          record["dma_addr"])],
            "dir": record["dir"], "size": record["size"]})
    return rows


def reverify_rows(rows):
    """Re-run ordering plus FIFO pairing on opaque rows.

    Mirrors ``check_ordering``/``pair_fifo`` without
    addresses: timestamps order by file position on ties,
    FIFO queues key on the opaque key id, size and direction
    cross-check each pop. Returns ``(violations,
    pairing)`` where pairing counts must equal the guest
    aggregates for the window to verify.
    """
    bad = []
    previous = None
    per_cpu = {}
    ordered = sorted(rows, key=lambda row: row["line"])
    for row in ordered:
        stamp = row["ts_us"]
        if previous is not None and stamp < previous:
            bad.append("reverify: global order violation at "
                       "row line %d" % (row["line"],))
        previous = stamp
        cpu = row["cpu"]
        if cpu in per_cpu and stamp < per_cpu[cpu]:
            bad.append("reverify: cpu%s order violation at "
                       "row line %d" % (cpu, row["line"]))
        per_cpu[cpu] = stamp
    waiting = {}
    pairs = 0
    orphans = 0
    mismatches = 0
    maps = 0
    for row in ordered:
        if row["kind"] == "map":
            maps += 1
            waiting.setdefault(row["key"], deque()).append(row)
            continue
        queue = waiting.get(row["key"])
        if not queue:
            orphans += 1
            continue
        opened = queue.popleft()
        if (row["size"] != opened["size"]
                or row["dir"] != opened["dir"]
                or row["ts_us"] < opened["ts_us"]):
            mismatches += 1
            continue
        pairs += 1
    still_open = sum(len(queue) for queue in waiting.values())
    return bad, {"maps": maps,
                 "unmaps": len(ordered) - maps,
                 "pairs": pairs, "orphans": orphans,
                 "still_open": still_open,
                 "mismatches": mismatches}


def split_bracket(records, markers, names=None):
    """Split bracket records into pre/teardown/post phases.

    Every boundary marker must appear exactly once, in
    PRE < DOWN < UP < POST < END line order; any duplicate,
    missing, misordered, or foreign marker, or any
    out-of-window event, is a finding. Pairing itself stays
    GLOBAL across the window
    (a pre-phase map may legitimately release during
    teardown); phases only attribute orphans and
    still-open records afterwards.
    """
    names = dict(MARKERS) if names is None else dict(names)
    bad = []
    lines = {}
    for phase, text in names.items():
        hits = markers.get(text, [])
        if len(hits) != 1:
            bad.append("marker %s appears %d times, want 1"
                       % (text, len(hits)))
        else:
            lines[phase] = hits[0]
    for text in sorted(markers):
        if text not in names.values():
            bad.append("foreign marker %s" % (text,))
    order = [lines.get(name) for name in
             ("pre", "down", "up", "post", "end")]
    if all(line is not None for line in order):
        if not (order[0] < order[1] < order[2]
                < order[3] < order[4]):
            bad.append("bracket markers out of order")
    phases = {"pre": [], "teardown": [], "post": []}
    if not bad:
        for record in records:
            line = record["line"]
            if line <= lines["pre"] or line >= lines["end"]:
                bad.append("bracket event outside window at "
                           "line %d" % (line,))
            elif line < lines["down"]:
                phases["pre"].append(record)
            elif line < lines["up"]:
                phases["teardown"].append(record)
            else:
                phases["post"].append(record)
    return bad, phases


def classify_bracket(pairing, phases, drops_clean,
                     iface_up_at_end):
    """Attribute bracket orphans and still-open records.

    Teardown-phase orphans are pre-existing mappings (their
    map predates the cleared window) and are explicit, never
    silent; this attribution is sound only with zero oracle
    loss, otherwise it fails closed. Orphans in pre/post
    phases, still-open records outside the post phase, and
    still-open records with the interface down all fail
    closed. Post-phase still-open records with the interface
    up are the held ring, counted explicitly.
    """
    bad = []
    teardown_lines = {record["line"] for record in
                      phases["teardown"]}
    post_lines = {record["line"] for record in phases["post"]}
    pre_existing = 0
    for record in pairing["orphans"]:
        if (record["line"] in teardown_lines
                and drops_clean):
            pre_existing += 1
        else:
            bad.append("unattributed orphan unmap at line %d"
                       % (record["line"],))
    held_open = 0
    for record in pairing["still_open"]:
        if (record["line"] in post_lines
                and record["event"] == MAP_EVENT
                and iface_up_at_end):
            held_open += 1
        else:
            bad.append("unattributed still-open map at line %d"
                       % (record["line"],))
    return bad, {"pre_existing": pre_existing,
                 "held_open": held_open}


def _pooled_loss_group(reason):
    """Split ``detail loss N (...)`` into count, group, rest.

    The pooled bucket group is extracted by parenthesis
    depth, so a ``; channels ...`` suffix (or any later
    suffix) can never leak bucket-looking text into the
    audit. Returns ``(None, None, None)`` when the head
    does not parse.
    """
    head = LOSS_HEAD_RE.match(reason)
    if head is None:
        return None, None, None
    depth = 0
    for pos in range(head.end() - 1, len(reason)):
        char = reason[pos]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return (int(head.group(1)),
                        reason[head.end():pos],
                        reason[pos + 1:].strip())
    return None, None, None


def parse_declared_loss(detail):
    """Parse and audit the declared detail-loss accounting.

    The detail reason must enumerate all nine loss buckets
    summing to the head count, which must equal loss_count:
    allowance = attributed = declared. Anything unparseable
    or unbalanced fails closed, so gaps can only ever be
    charged to fully declared loss.
    """
    if type(detail) is not dict:
        raise OracleError("detail quality is not an object")
    for key in ("status", "loss_count", "scope", "reason"):
        if key not in detail:
            raise OracleError("Detail quality lacks " + key)
    total = detail["loss_count"]
    if type(total) is str:
        if not total.isdigit():
            raise OracleError("bad Detail loss_count")
        total = int(total)
    elif type(total) is not int or total < 0:
        raise OracleError("bad Detail loss_count")
    reason = detail["reason"]
    if type(reason) is not str:
        raise OracleError("Detail reason is not text")
    total2, group, rest = _pooled_loss_group(reason)
    if total2 is None or total2 != total:
        raise OracleError("Detail reason head %r disagrees "
                          "with loss_count %d"
                          % (reason[:60], total))
    if rest != "" and not rest.startswith(";"):
        raise OracleError("unparsed tail after pooled buckets")
    buckets = dict(LOSS_PAIR_RE.findall(group))
    if (set(buckets) != set(LOSS_BUCKETS)
            or sum(int(value) for value in buckets.values())
            != total):
        raise OracleError("Detail buckets %r do not cover "
                          "loss_count %d" % (buckets, total))
    return {"total": total,
            "buckets": {name: int(buckets[name])
                        for name in LOSS_BUCKETS}}


def copy_cover_direction(direction):
    """Expected copy direction for one oracle direction.

    Map-time bounce covers TO_DEVICE (original to bounce
    buffer); release-time bounce covers FROM_DEVICE (bounce
    buffer back to original); BIDIRECTIONAL bounces at both
    ends so either copy direction covers it; NONE expects no
    bounce.
    """
    if direction == "TO_DEVICE":
        return ("original_to_bounce",)
    if direction == "FROM_DEVICE":
        return ("bounce_to_original",)
    if direction == "BIDIRECTIONAL":
        return ("original_to_bounce", "bounce_to_original")
    return ()


def parse_c9_stream(lines):
    """Fold validated C9 event lines to agreement counters.

    Callers validate every line with the schema validator
    first; this fold reads only kind/data counters, the
    profile set, and the session set. Returns counters plus
    ``profiles`` and ``sessions`` sets for binding checks.

    Attempt-channel records (``bounce_attempt``) are
    counted explicitly under ``attempts`` and deliberately
    excluded from the lifecycle counters: an attempt
    describes a requested bounce, not a completed mapping
    lifetime, so it can never agree with (or cover a gap
    in) the oracle's proven map-to-release pairs. The
    count proves the channel was observed, never silently
    dropped.
    """
    maps_by_size = Counter()
    copies_by_dir = Counter()
    copy_bytes_by_dir = Counter()
    unmaps = 0
    attempts = 0
    profiles = set()
    sessions = set()
    kinds = Counter()
    for lineno, line in enumerate(lines, 1):
        event = json.loads(line)
        kinds[event["kind"]] += 1
        sessions.add(event["session_id"])
        profiles.add(event["source"]["profile_id"])
        data = event["data"]
        if event["kind"] == "map_result":
            if data["success"] is True:
                maps_by_size[int(data["mapped_bytes"])] += 1
        elif event["kind"] == "unmap":
            unmaps += 1
        elif event["kind"] == "copy":
            copies_by_dir[data["direction"]] += 1
            copy_bytes_by_dir[data["direction"]] += int(
                data["bytes"])
        elif event["kind"] == "bounce_attempt":
            attempts += 1
    return {"maps_by_size": maps_by_size,
            "copies_by_dir": copies_by_dir,
            "copy_bytes_by_dir": copy_bytes_by_dir,
            "unmaps": unmaps, "attempts": attempts,
            "profiles": profiles, "sessions": sessions,
            "kinds": kinds, "events": len(lines)}


def agree_oracle_c9(proven, c9, declared):
    """Agreement for the proven bounced subset.

    ``proven`` maps size to pair count for the
    order-clean traffic-phase pairs (every such lifetime
    bounced under swiotlb=force, so each must appear in
    the persisted lifecycle records); ``c9`` is the
    ``parse_c9_stream`` fold; ``declared`` is the audited
    detail loss. Per-size map cover plus release cover,
    with record gaps charged to declared loss only:
    extra product records (other devices, other phases)
    never fail, but a proven lifetime missing beyond
    declared loss does. Bounce coverage needs nonzero
    observed copy bytes in a consistent direction per
    oracle direction class present.

    Attempt-channel records (``c9["attempts"]``) are
    explicitly excluded from the gap comparison: attempts
    and effective mappings are distinct measurements, so
    any number of attempt records neither covers a
    lifecycle gap nor creates one. The count is reported
    through, proving the exclusion was deliberate.
    """
    bad = []
    total = sum(proven.values())
    if total <= 0:
        return ["no proven bounced pairs to agree on"], {}
    attempts = c9["attempts"]
    map_gap = sum(max(0, proven[size] - c9["maps_by_size"].get(
        size, 0)) for size in proven)
    unmap_gap = max(0, total - c9["unmaps"])
    gap = map_gap + unmap_gap
    if gap > declared["total"]:
        bad.append("C9 gap %d (map %d + unmap %d) exceeds "
                   "declared loss %d"
                   % (gap, map_gap, unmap_gap,
                      declared["total"]))
    copy_bytes = sum(c9["copy_bytes_by_dir"].values())
    if copy_bytes <= 0:
        bad.append("no exercised bounce coverage in C9 "
                   "copies")
    return bad, {"pairs": total, "map_gap": map_gap,
                 "unmap_gap": unmap_gap, "gap": gap,
                 "declared": declared["total"],
                 "copy_bytes": copy_bytes,
                 "attempt_events": attempts}


def agree_bounce_dirs(pair_dirs, c9):
    """Per-direction bounce coverage for present classes."""
    bad = []
    for direction in sorted(pair_dirs):
        want = copy_cover_direction(direction)
        if not want:
            continue
        covered = sum(c9["copy_bytes_by_dir"].get(name, 0)
                      for name in want)
        if covered <= 0:
            bad.append("oracle direction %s has no covering "
                       "C9 copy bytes" % (direction,))
    return bad


def judge_window(name, window, require_markers):
    """Judge one window's hygiene, ordering, and pairing.

    Requires the marker set exactly once each with no
    foreign markers, all events strictly inside the
    first/last marker, header
    entries-written equal to parsed records plus markers
    (no truncation), in-buffer equal to written (no
    overwrite), zero unexpected event kinds, zero
    other-device records (quiet-guest proof), empty
    ordering violations, and empty FIFO mismatches.
    Returns ``(findings, pairing)``.
    """
    bad = []
    markers = window["markers"]
    for text in require_markers:
        hits = markers.get(text, [])
        if len(hits) != 1:
            bad.append("%s: marker %s appears %d times"
                       % (name, text, len(hits)))
    for text in sorted(markers):
        if text not in require_markers:
            bad.append("%s: foreign marker %s" % (name, text))
    header = window["header"]
    if header is None:
        bad.append("%s: missing entries header" % (name,))
    else:
        parsed = (len(window["records"])
                  + sum(window["other_device"].values())
                  + len(window["other_events"])
                  + sum(len(hit) for hit in markers.values()))
        if parsed != header["written"]:
            bad.append("%s: parsed %d != entries-written %d "
                       "(truncated window)" % (name, parsed,
                                               header["written"]))
        if header["in_buffer"] != header["written"]:
            bad.append("%s: entries overwrite %d != %d"
                       % (name, header["in_buffer"],
                          header["written"]))
    for record in window["other_events"]:
        bad.append("%s: unexpected %s at line %d"
                   % (name, record["event"], record["line"]))
    other = window["other_device"]
    if other["map"] or other["unmap"]:
        bad.append("%s: %d map + %d unmap on other devices"
                   % (name, other["map"], other["unmap"]))
    bounds = [markers[text][0] for text in require_markers
              if len(markers.get(text, [])) == 1]
    if len(bounds) == len(require_markers):
        first, last = min(bounds), max(bounds)
        for record in window["records"]:
            if not first < record["line"] < last:
                bad.append("%s: event outside markers at line "
                           "%d" % (name, record["line"]))
    bad.extend("%s: %s" % (name, finding)
               for finding in check_ordering(window["records"]))
    pairing = pair_fifo(window["records"])
    counts = pairing["counts"]
    if counts["mismatches"]:
        bad.append("%s: %d size/dir/lifetime mismatches"
                   % (name, counts["mismatches"]))
    return bad, pairing


def judge_traffic_reverify(traffic):
    """Host re-verify of the traffic window from opaque rows.

    Re-runs ordering plus FIFO pairing from the exported
    rows and requires exact reproduction of the guest
    aggregates, zero orphans/still-open/mismatches
    (traffic lifetimes are transient: every exercised map
    must release inside the window), and zero violations.
    """
    bad, derived = reverify_rows(traffic["events"])
    for key in ("maps", "unmaps", "pairs", "orphans",
                "still_open", "mismatches"):
        if derived[key] != traffic[key]:
            bad.append("traffic reverify %s: host %d != guest "
                       "%d" % (key, derived[key],
                               traffic[key]))
    for key in ("orphans", "still_open", "mismatches"):
        if traffic[key]:
            bad.append("traffic %s: %d, want 0"
                       % (key, traffic[key]))
    if traffic["pairs"] <= 0:
        bad.append("traffic pairs: 0, want nonzero")
    if traffic["order_violations"]:
        bad.append("traffic order_violations: %d, want 0"
                   % (traffic["order_violations"],))
    if traffic["other_device"]:
        bad.append("traffic other_device: %d, want 0"
                   % (traffic["other_device"],))
    return bad, derived


def judge_bracket_reverify(bracket, iface_up_at_end):
    """Host re-verify of the bracket window from opaque rows.

    Reproduces guest aggregates from opaque rows, requires
    teardown unmaps and post-UP maps (the bracket actually
    bracketed something), and attributes orphans to
    pre-existing mappings and still-open records to the
    held ring, all explicit. Phase membership here keys on
    exported line numbers against the exported marker
    lines, mirroring ``split_bracket``/``classify_bracket``.
    """
    bad, derived = reverify_rows(bracket["events"])
    for key in ("maps", "unmaps", "pairs", "orphans",
                "still_open", "mismatches"):
        if derived[key] != bracket[key]:
            bad.append("bracket reverify %s: host %d != guest "
                       "%d" % (key, derived[key],
                               bracket[key]))
    if bracket["mismatches"]:
        bad.append("bracket mismatches: %d, want 0"
                   % (bracket["mismatches"],))
    if bracket["order_violations"]:
        bad.append("bracket order_violations: %d, want 0"
                   % (bracket["order_violations"],))
    if bracket["other_device"]:
        bad.append("bracket other_device: %d, want 0"
                   % (bracket["other_device"],))
    lines = bracket["marker_lines"]
    order = [lines[name] for name in
             ("pre", "down", "up", "post", "end")]
    if not order[0] < order[1] < order[2] < order[3] < order[4]:
        bad.append("bracket marker lines out of order")
        return bad, derived
    teardown_unmaps = 0
    post_maps = 0
    orphans_pre_existing = 0
    held_open = 0
    waiting = {}
    for row in sorted(bracket["events"],
                      key=lambda row: row["line"]):
        line = row["line"]
        if not order[0] < line < order[4]:
            bad.append("bracket event outside window at line "
                       "%d" % (line,))
            continue
        if order[1] < line < order[2]:
            phase = "teardown"
        elif line > order[2]:
            phase = "post"
        else:
            phase = "pre"
        if row["kind"] == "map":
            if phase == "post":
                post_maps += 1
            waiting.setdefault(row["key"], deque()).append(
                (line, phase))
        else:
            if phase == "teardown":
                teardown_unmaps += 1
            queue = waiting.get(row["key"])
            if queue:
                queue.popleft()
            elif phase == "teardown":
                orphans_pre_existing += 1
            else:
                bad.append("bracket unattributed orphan "
                           "at line %d" % (line,))
    for queue in waiting.values():
        for line, phase in queue:
            if phase == "post" and iface_up_at_end:
                held_open += 1
            else:
                bad.append("bracket unattributed still-open "
                           "at line %d" % (line,))
    if not teardown_unmaps:
        bad.append("bracket teardown released nothing")
    if not post_maps:
        bad.append("bracket post-UP mapped nothing")
    if orphans_pre_existing != bracket["pre_existing"]:
        bad.append("bracket pre_existing: host %d != guest "
                   "%d" % (orphans_pre_existing,
                           bracket["pre_existing"]))
    if held_open != bracket["held_open"]:
        bad.append("bracket held_open: host %d != guest %d"
                   % (held_open, bracket["held_open"]))
    return bad, derived


def judge_drops(name, window):
    """Zero oracle loss per CPU for one window."""
    bad = []
    before = window["drops_before"]
    after = window["drops_after"]
    if set(before) != set(after):
        bad.append("%s: drop CPU set moved %r -> %r"
                   % (name, sorted(before), sorted(after)))
    for cpu in sorted(set(before) | set(after)):
        first = before.get(cpu, 0)
        last = after.get(cpu, 0)
        if last != first:
            bad.append("%s: %s drops %d -> %d (oracle loss)"
                       % (name, cpu, first, last))
    return bad


def judge_entries(name, window):
    """Window completeness from the entries header."""
    bad = []
    parsed = (window["maps"] + window["unmaps"]
              + window["markers"])
    if parsed != window["entries_written"]:
        bad.append("%s: parsed %d != entries-written %d"
                   % (name, parsed, window["entries_written"]))
    if window["entries_in_buffer"] != window["entries_written"]:
        bad.append("%s: entries overwrite %d != %d"
                   % (name, window["entries_in_buffer"],
                      window["entries_written"]))
    return bad


def judge_peer_leg(peer, c9, summary, declared):
    """Master L11 verdict from opaque exports + validated C9.

    ``peer`` is the validated ``peer.json`` doc; ``c9`` the
    ``parse_c9_stream`` fold over schema-validated events;
    ``summary`` the schema ``check_session`` summary plus
    the raw ``finalized``/``end_reason``/``synthetic``
    fields; ``declared`` the audited detail loss. Checks,
    in order: oracle parameters (exact event set, format
    binding; device shape is validated at export), zero
    oracle loss plus
    window completeness per window, traffic re-verify
    (nonzero transient pairs), bracket re-verify (explicit
    pre-existing/held-open), nonzero peer TX/RX plus NIC
    corroboration, C9 provenance (live, finalized,
    duration, single profile, single session bound to the
    ready line), same-clock window containment, per-size
    agreement with gaps to declared loss only, and
    per-direction bounce coverage. Returns ``(verdict,
    findings, agreement)``; verdict is True only with zero
    findings. No finding is ever advisory.
    """
    bad = []
    oracle = peer["oracle"]
    if list(oracle["events"]) != list(ORACLE_EVENTS):
        bad.append("oracle events %r, want exactly %r"
                   % (oracle["events"], list(ORACLE_EVENTS)))
    if not oracle["format_tokens_ok"]:
        bad.append("oracle format tokens not bound")
    traffic = peer["traffic"]
    bracket = peer["bracket"]
    bad.extend(judge_drops("traffic", traffic))
    bad.extend(judge_drops("bracket", bracket))
    bad.extend(judge_entries("traffic", traffic))
    bad.extend(judge_entries("bracket", bracket))
    traffic_bad, _ = judge_traffic_reverify(traffic)
    bad.extend(traffic_bad)
    bracket_bad, _ = judge_bracket_reverify(
        bracket, peer["guest"]["link_up_at_end"])
    bad.extend(bracket_bad)
    workload = peer["workload"]
    if workload["ping_tx"] <= 0 or workload["ping_rx"] <= 0:
        bad.append("peer traffic tx=%d rx=%d, want nonzero "
                   "both" % (workload["ping_tx"],
                             workload["ping_rx"]))
    nic_tx = workload["nic_tx_after"] - workload["nic_tx_before"]
    nic_rx = workload["nic_rx_after"] - workload["nic_rx_before"]
    if nic_tx <= 0 or nic_rx <= 0:
        bad.append("NIC corroboration tx=%d rx=%d, want "
                   "nonzero both" % (nic_tx, nic_rx))
    if summary.get("synthetic") is not False:
        bad.append("C9 capture is not live")
    if summary.get("finalized") is not True:
        bad.append("C9 capture not finalized")
    if summary.get("end_reason") != "duration":
        bad.append("C9 end_reason %r, want duration"
                   % (summary.get("end_reason"),))
    if len(c9["profiles"]) != 1:
        bad.append("C9 profiles %r, want exactly one"
                   % (sorted(c9["profiles"]),))
    if c9["sessions"] != {summary.get("id")}:
        bad.append("C9 event sessions %r do not bind %r"
                   % (sorted(c9["sessions"]),
                      summary.get("id")))
    ready = peer["c9"]["ready_session"]
    if ready != summary.get("id"):
        bad.append("C9 ready session %r does not bind %r"
                   % (ready, summary.get("id")))
    if peer["c9"]["window_clock"] != MONO_CLOCK:
        bad.append("C9 bind clock %r, want %s"
                   % (peer["c9"]["window_clock"], MONO_CLOCK))
    start = summary.get("start")
    end = summary.get("end")
    opened = peer["c9"]["mono_open_ns"]
    closed = peer["c9"]["mono_close_ns"]
    bounds = (start, end, opened, closed)
    if not all(type(value) is int for value in bounds):
        bad.append("window bounds are not integers")
    elif not (start <= opened <= closed <= end):
        bad.append("oracle window [%d, %d] escapes C9 window "
                   "[%d, %d]" % (opened, closed, start, end))
    proven = Counter()
    pair_dirs = set()
    for row in traffic["events"]:
        if row["kind"] == "map":
            proven[row["size"]] += 1
            pair_dirs.add(row["dir"])
    # Traffic re-verify already proved every map pairs, so
    # map rows here equal the proven bounced pairs.
    agree_bad, agreement = agree_oracle_c9(proven, c9, declared)
    bad.extend(agree_bad)
    bad.extend(agree_bounce_dirs(pair_dirs, c9))
    return not bad, sorted(set(bad)), agreement


def emit_receipt(peer, c9, summary, declared, agreement,
                 verdict, findings, harness, exports):
    """R103 Q1 receipt row for the peer leg.

    Binds harness commit, C9 seal plus executed bytes,
    guest/BTF/profile, oracle parameters, workload, and
    exports. ``harness`` carries ``commit`` (str),
    ``dirty`` (bool), ``c9_binary_sha``, and ``c9_seal``
    (manifest/bundle digests); ``exports`` maps export
    names to proven digests.
    """
    guest = peer["guest"]
    oracle = peer["oracle"]
    c9bind = peer["c9"]
    return {
        "schema": RECEIPT_SCHEMA,
        "leg": "L11",
        "case": CASE_ID,
        "verdict": "PASS" if verdict else "FAIL",
        "findings": list(findings),
        "harness": {"commit": harness["commit"],
                    "dirty": bool(harness["dirty"]),
                    "c9_binary_sha": harness["c9_binary_sha"],
                    "c9_seal": dict(harness.get("c9_seal",
                                                {}))},
        "c9": {"session_id": summary.get("id"),
               "profile_id": sorted(c9["profiles"]),
               "events": c9["events"],
               "kinds": {kind: c9["kinds"][kind]
                         for kind in sorted(c9["kinds"])},
               "window_ns": [summary.get("start"),
                             summary.get("end")],
               "end_reason": summary.get("end_reason"),
               "declared_loss": declared["total"],
               "gap": agreement.get("gap"),
               "copy_bytes": agreement.get("copy_bytes"),
               "attempt_events":
                   agreement.get("attempt_events")},
        "guest": {"release": guest["release"],
                  "btf_sha": guest["btf_sha"],
                  "swiotlb_force": guest["swiotlb_force"],
                  "iface": guest["iface"], "pci": guest["pci"],
                  "dma_mask_bits": guest["dma_mask_bits"]},
        "oracle": {"device": guest["pci"],
                   "events": list(oracle["events"]),
                   "event_ids": dict(oracle["event_ids"]),
                   "format_sha": dict(oracle["format_sha"]),
                   "buffer_kb": oracle["buffer_kb"],
                   "trace_clock": guest["trace_clock"],
                   "traffic_pairs": peer["traffic"]["pairs"],
                   "bracket_pre_existing":
                       peer["bracket"]["pre_existing"],
                   "bracket_held_open":
                       peer["bracket"]["held_open"]},
        "workload": {"ping_tx": peer["workload"]["ping_tx"],
                     "ping_rx": peer["workload"]["ping_rx"],
                     "nic_tx_delta":
                         peer["workload"]["nic_tx_after"]
                         - peer["workload"]["nic_tx_before"],
                     "nic_rx_delta":
                         peer["workload"]["nic_rx_after"]
                         - peer["workload"]["nic_rx_before"],
                     "mono_open_ns": c9bind["mono_open_ns"],
                     "mono_close_ns": c9bind["mono_close_ns"]},
        "exports": dict(exports),
    }


def _unique_object(pairs):
    doc = {}
    for key, value in pairs:
        if key in doc:
            raise ValueError("duplicate export JSON key")
        doc[key] = value
    return doc


def strict_json(text):
    """JSON with duplicate keys rejected."""
    return json.loads(text, object_pairs_hook=_unique_object)


def _keys(doc, required, optional=(), where="export"):
    if (type(doc) is not dict
            or not set(required) <= set(doc)
            or set(doc) - set(required) - set(optional)):
        raise ValueError("export key inventory drift: " + where)


def _integer(value, where):
    if type(value) is bool or type(value) is not int \
            or not 0 <= value < (1 << 64):
        raise ValueError("invalid export integer: " + where)


def _sha(value, where):
    if type(value) is not str or not SHA_RE.fullmatch(value):
        raise ValueError("invalid export hash: " + where)


def _drops(doc, where):
    _keys(doc, (), tuple(sorted(doc)), where)
    for cpu, value in doc.items():
        if not CPU_RE.fullmatch(cpu):
            raise ValueError("invalid cpu: " + where)
        _integer(value, where + "." + cpu)
    if not doc:
        raise ValueError("empty drop inventory: " + where)


def _event_row(row, where):
    # Opaque pairing structure only: line order, timestamps,
    # CPU, kind, opaque key id, direction, size. No address
    # bits by construction (no key may carry one).
    _keys(row, ("line", "ts_us", "cpu", "kind", "key", "dir",
                "size"), (), where)
    if type(row["line"]) is not int or row["line"] <= 0:
        raise ValueError("invalid row line: " + where)
    _integer(row["ts_us"], where + ".ts_us")
    if type(row["cpu"]) is not str \
            or not re.fullmatch(r"[0-9]+", row["cpu"]):
        raise ValueError("invalid row cpu: " + where)
    if row["kind"] not in ("map", "unmap"):
        raise ValueError("invalid row kind: " + where)
    if type(row["key"]) is not str \
            or not KEY_RE.fullmatch(row["key"]):
        raise ValueError("invalid row key: " + where)
    if row["dir"] not in DIRS:
        raise ValueError("invalid row dir: " + where)
    _integer(row["size"], where + ".size")


def _window(doc, where, bracket=False):
    required = ("entries_in_buffer", "entries_written",
                "markers", "drops_before", "drops_after",
                "maps", "unmaps", "pairs", "orphans",
                "still_open", "mismatches",
                "order_violations", "other_device", "events")
    if bracket:
        required += ("marker_lines", "pre_existing",
                     "held_open")
    _keys(doc, required, (), where)
    for key in required:
        if key in ("drops_before", "drops_after", "events",
                   "marker_lines"):
            continue
        _integer(doc[key], where + "." + key)
    _drops(doc["drops_before"], where + ".drops_before")
    _drops(doc["drops_after"], where + ".drops_after")
    rows = doc["events"]
    if type(rows) is not list or len(rows) > 100000:
        raise ValueError("invalid window rows: " + where)
    previous = 0
    for index, row in enumerate(rows):
        _event_row(row, "%s.events[%d]" % (where, index))
        if row["line"] <= previous:
            raise ValueError("window rows out of order: "
                             + where)
        previous = row["line"]
    if bracket:
        lines = doc["marker_lines"]
        _keys(lines, ("pre", "down", "up", "post", "end"), (),
               where + ".marker_lines")
        for key, value in lines.items():
            if type(value) is not int or value <= 0:
                raise ValueError("invalid marker line: "
                                 + where)


def validate_peer_doc(doc):
    """Allowlist validation for the ``peer.json`` export.

    Every field is metadata only, justified per key: kernel
    release/BTF/iface/PCI-BDF/DMA-mask identify the owned
    NIC and guest (binding, not payload); event ids,
    format hashes, buffer size, trace clock, and drop
    counters parameterize and audit the oracle; ping/NIC
    counters corroborate traffic; opaque key ids plus
    counts carry the pairing structure with no address
    bits; C9 bind fields (hashes, session, window) tie the
    capture file. No command lines, environment text,
    payloads, or DMA addresses may cross: the key inventory
    is exact at every level, so an address field cannot
    hide in it.
    """
    _keys(doc, ("schema", "case", "guest", "oracle", "c9",
                "workload", "traffic", "bracket"), (), "peer")
    if doc["schema"] != PEER_SCHEMA:
        raise ValueError("bad peer schema")
    if doc["case"] != CASE_ID:
        raise ValueError("bad peer case")
    guest = doc["guest"]
    _keys(guest, ("release", "swiotlb_force", "btf_sha",
                  "iface", "pci", "dma_mask_bits", "addr",
                  "link_up_at_end", "trace_root",
                  "trace_clock"), (), "peer.guest")
    if type(guest["release"]) is not str or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+[-A-Za-z0-9.+_]*",
            guest["release"]):
        raise ValueError("invalid kernel release")
    if guest["swiotlb_force"] is not True:
        raise ValueError("missing force boot option")
    _sha(guest["btf_sha"], "peer.guest.btf_sha")
    if type(guest["iface"]) is not str \
            or not IFACE_RE.fullmatch(guest["iface"]):
        raise ValueError("invalid interface")
    if type(guest["pci"]) is not str \
            or not BDF_RE.fullmatch(guest["pci"]):
        raise ValueError("invalid PCI device")
    if guest["dma_mask_bits"] != 32:
        raise ValueError("invalid DMA mask width")
    if type(guest["addr"]) is not str or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]{1,2}",
            guest["addr"]):
        raise ValueError("invalid owned address")
    if type(guest["link_up_at_end"]) is not bool:
        raise ValueError("invalid link flag")
    if guest["trace_root"] not in ("/sys/kernel/tracing",
                                   "/sys/kernel/debug/tracing"):
        raise ValueError("invalid trace root")
    if type(guest["trace_clock"]) is not str \
            or not 1 <= len(guest["trace_clock"]) <= 256:
        raise ValueError("invalid trace clock")
    oracle = doc["oracle"]
    _keys(oracle, ("events", "event_ids", "format_sha",
                   "format_tokens_ok", "buffer_kb"), (),
           "peer.oracle")
    if list(oracle["events"]) != list(ORACLE_EVENTS):
        raise ValueError("bad oracle event set")
    for key in ("event_ids", "format_sha"):
        _keys(oracle[key], ORACLE_EVENTS, (),
               "peer.oracle." + key)
    for key in ORACLE_EVENTS:
        _integer(oracle["event_ids"][key],
                 "peer.oracle.event_ids." + key)
        _sha(oracle["format_sha"][key],
              "peer.oracle.format_sha." + key)
    if oracle["format_tokens_ok"] is not True:
        raise ValueError("unbound oracle format")
    _integer(oracle["buffer_kb"], "peer.oracle.buffer_kb")
    if oracle["buffer_kb"] <= 0:
        raise ValueError("invalid buffer size")
    bind = doc["c9"]
    _keys(bind, ("binary_sha", "profile", "caps",
                 "duration_s", "record_exit", "ready_session",
                 "ready_start_ns", "window_clock",
                 "mono_open_ns", "mono_close_ns"), (),
           "peer.c9")
    _sha(bind["binary_sha"], "peer.c9.binary_sha")
    if type(bind["profile"]) is not str \
            or not 1 <= len(bind["profile"]) <= 128:
        raise ValueError("invalid C9 profile")
    if type(bind["caps"]) is not str \
            or not 1 <= len(bind["caps"]) <= 128:
        raise ValueError("invalid C9 capabilities")
    _integer(bind["duration_s"], "peer.c9.duration_s")
    if bind["duration_s"] <= 0:
        raise ValueError("invalid C9 duration")
    if bind["record_exit"] != 0:
        raise ValueError("C9 record failed")
    if type(bind["ready_session"]) is not str or not re.fullmatch(
            r"cap-[0-9]+-[0-9]+|[a-z][a-z0-9_.-]{0,127}",
            bind["ready_session"]):
        raise ValueError("invalid C9 ready session")
    _integer(bind["ready_start_ns"], "peer.c9.ready_start_ns")
    if bind["window_clock"] != MONO_CLOCK:
        raise ValueError("invalid C9 bind clock")
    _integer(bind["mono_open_ns"], "peer.c9.mono_open_ns")
    _integer(bind["mono_close_ns"], "peer.c9.mono_close_ns")
    if bind["mono_open_ns"] > bind["mono_close_ns"]:
        raise ValueError("inverted oracle window")
    workload = doc["workload"]
    _keys(workload, ("ping_tx", "ping_rx", "nic_tx_before",
                     "nic_tx_after", "nic_rx_before",
                     "nic_rx_after"), (), "peer.workload")
    for key, value in workload.items():
        _integer(value, "peer.workload." + key)
    if workload["nic_tx_after"] < workload["nic_tx_before"] \
            or workload["nic_rx_after"] < workload["nic_rx_before"]:
        raise ValueError("NIC counters ran backwards")
    _window(doc["traffic"], "peer.traffic")
    _window(doc["bracket"], "peer.bracket", bracket=True)
    return doc


def validate_peer_exports(got):
    """Validate the exact peer-leg export inventory."""
    if set(got) != set(EXPORT_NAMES):
        raise ValueError("peer export inventory drift: "
                         "%r" % (sorted(got),))
    return validate_peer_doc(
        strict_json(got["peer.json"].read_text()))


def load_schema_validator():
    """The repo product-schema validator module."""
    import importlib.util
    from importlib.machinery import SourceFileLoader
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] \
        / "tools" / "validate-schemas"
    loader = SourceFileLoader("peer_schema_validator",
                              str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def validate_c9_capture(validator, session_path, events_path):
    """Validate one C9 capture against the product schema.

    Runs ``check_session`` plus the strict streaming
    validator (per-line schema, sequence, identity, and
    integrity cross-check), folds the agreed counters, and
    audits the declared detail loss. Returns ``(summary,
    fold, declared, raw_session)``; summary carries the
    validator fields plus ``finalized``, ``end_reason``,
    and ``synthetic`` from the raw session for the judge.
    Any schema, stream, integrity, or loss-accounting
    failure raises: unvalidated captures never reach the
    judge.
    """
    raw = strict_json(session_path.read_text())
    summary = validator.check_session(raw)
    validator.validate_stream(summary, str(events_path))
    lines = events_path.read_text().splitlines()
    fold = parse_c9_stream(lines)
    declared = parse_declared_loss(raw["quality"]["detail"])
    summary["finalized"] = raw["capture"]["finalized"]
    summary["end_reason"] = raw["capture"].get("end_reason")
    summary["synthetic"] = raw["synthetic"]
    return summary, fold, declared, raw


def verify_peer_exports(tmp, sub, names):
    """Snapshot, inventory-check, and validate peer exports."""
    from evidence_retention import VerifiedExports, \
        snapshot_exports
    from pathlib import Path
    export = Path(tmp) / "export"
    got, verified = snapshot_exports(tmp, sub, list(names))
    want_files = {"%s-%s" % (sub, name) for name in names}
    want_files |= {"%s-%s.sha256" % (sub, name)
                   for name in names}
    have = {path.name for path in export.iterdir()}
    if have != want_files:
        raise AssertionError("export inventory drift: %r"
                             % (have ^ want_files,))
    validate_peer_exports(got)
    return VerifiedExports(got, verified)


def read_record_logs(export_dir, prefix="peer"):
    """Surface the guest-exported record logs, never raising.

    Reads ``record.out``/``record.stderr`` from a run
    export dir (live rwdir contents, usable on dead-guest
    and timeout paths where the snapshotter cannot run),
    hashing each against its ``.sha256`` sidecar. Returns
    a note dict with ``schema``, ``status`` (``present``
    when at least one log survived, ``absent`` when the
    guest exported neither, ``no-run-dir`` when there is
    no run dir at all), and a per-log ``logs`` mapping of
    ``present``, ``sha256``, ``bytes``, ``tail`` (last
    500 characters of diagnostic text), ``verified``
    (sidecar digest matches), and ``error``. Absent logs
    are an explicit marker, never silence. This is a
    forensics surface only: success-path strictness stays
    with the snapshotter, which fails closed on any
    missing or mismatched sidecar.
    """
    logs = {}
    if export_dir is None:
        for name in RECORD_LOGS:
            logs[name] = {"present": False, "sha256": None,
                          "bytes": None, "tail": "",
                          "verified": False,
                          "error": "no run dir"}
        return {"schema": RECORD_LOG_NOTE_SCHEMA,
                "status": "no-run-dir", "logs": logs}
    for name in RECORD_LOGS:
        entry = {"present": False, "sha256": None,
                 "bytes": None, "tail": "",
                 "verified": False, "error": None}
        live = os.path.join(str(export_dir),
                            "%s-%s" % (prefix, name))
        try:
            with open(live, "rb") as handle:
                data = handle.read()
        except OSError:
            if os.path.isfile(live):
                entry["present"] = True
                entry["error"] = "unreadable export"
            logs[name] = entry
            continue
        entry["present"] = True
        entry["sha256"] = hashlib.sha256(data).hexdigest()
        entry["bytes"] = len(data)
        entry["tail"] = data.decode("utf-8",
                                    "replace")[-500:]
        try:
            with open(live + ".sha256", "r",
                      encoding="utf-8") as handle:
                sidecar = handle.read()
        except OSError:
            entry["error"] = "missing sidecar"
            logs[name] = entry
            continue
        want = sidecar.split()
        if len(want) >= 1 and SHA_RE.fullmatch(want[0]) \
                and want[0] == entry["sha256"]:
            entry["verified"] = True
        else:
            entry["error"] = "hash mismatch"
        logs[name] = entry
    status = "present" if any(entry["present"]
                              for entry in logs.values()) \
        else "absent"
    return {"schema": RECORD_LOG_NOTE_SCHEMA,
            "status": status, "logs": logs}


def format_record_log_note(note):
    """Console lines for a record-log note, never silent.

    One status line plus one line per log: digest and
    byte count when present, the explicit absent marker
    otherwise, and the stderr tail so the product
    diagnostic reaches the host log even when the guest
    is dead.
    """
    lines = ["peer: record logs: %s"
             % (note.get("status", "absent"),)]
    for name in RECORD_LOGS:
        entry = note.get("logs", {}).get(name, {})
        if not entry.get("present"):
            lines.append("peer: %s: absent (%s)"
                         % (name,
                            entry.get("error")
                            or "no guest export"))
            continue
        lines.append("peer: %s: sha256=%s bytes=%s "
                     "verified=%s%s"
                     % (name, entry.get("sha256"),
                        entry.get("bytes"),
                        entry.get("verified"),
                        "" if not entry.get("error")
                        else " error=%s"
                        % (entry.get("error"),)))
        if name == "record.stderr" and entry.get("tail"):
            lines.append("peer: record.stderr tail: %s"
                         % (entry["tail"].strip()[-300:],))
    return lines


def require_peer_env():
    """Armed preflight for the peer leg.

    Skips fast without booting unless explicitly armed
    with MEMVEIL_VM_PEER=1; armed with missing pieces
    fails instead of skipping.
    """
    import pytest
    if os.environ.get(PEER_ENV) != "1":
        pytest.skip("peer leg needs MEMVEIL_VM_PEER=1")


def resolve_peer_kernel(lock_path, row_id="7.0"):
    """Resolve the pinned guest kernel from the kernel lock.

    Returns ``(vng_version, release, vmlinuz_sha256)`` for
    the archive row. Anything missing or ambiguous fails
    closed: the leg never boots an unpinned guest.
    """
    with open(lock_path, "r", encoding="utf-8") as handle:
        lock = json.load(handle)
    rows = [entry for entry in lock.get("kernels", [])
            if entry.get("id") == row_id]
    if len(rows) != 1:
        raise OracleError("kernel lock row %r ambiguous "
                          "(%d hits)" % (row_id, len(rows)))
    row = rows[0]
    source = row.get("source", {})
    if source.get("kind") != "archive":
        raise OracleError("kernel lock row %r is not an "
                          "archive row" % (row_id,))
    version = source.get("vng_version")
    release = row.get("release")
    digest = source.get("vmlinuz_sha256")
    if not version or not release or not digest:
        raise OracleError("kernel lock row %r lacks "
                          "version/release/sha" % (row_id,))
    if not SHA_RE.fullmatch(digest):
        raise OracleError("kernel lock row %r has a bad "
                          "vmlinuz sha" % (row_id,))
    return version, release, digest


def sha_file(path):
    """SHA-256 of a file, streamed."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = ["CASE_ID", "CASE_TIMEOUT", "CASE_NETWORK",
           "PEER_ENV", "EXPORT_NAMES", "RECORD_LOGS",
           "MAP_EVENT",
           "UNMAP_EVENT", "MARK_EVENT", "ORACLE_EVENTS",
           "MARKERS", "TRAFFIC_BEGIN", "TRAFFIC_END", "DIRS",
           "LOSS_BUCKETS", "PEER_SCHEMA", "RECEIPT_SCHEMA",
           "RECORD_LOG_NOTE_SCHEMA",
           "MONO_CLOCK", "OracleError", "parse_ts_us",
           "parse_trace_line", "read_trace_window",
           "check_ordering", "assign_key_ids", "pair_fifo",
           "export_rows", "reverify_rows", "split_bracket",
           "classify_bracket", "parse_declared_loss",
           "copy_cover_direction", "parse_c9_stream",
           "agree_oracle_c9", "agree_bounce_dirs",
           "judge_window", "judge_traffic_reverify",
           "judge_bracket_reverify", "judge_drops",
           "judge_entries", "judge_peer_leg", "emit_receipt",
           "strict_json", "validate_peer_doc",
           "validate_peer_exports", "load_schema_validator",
           "validate_c9_capture",
           "verify_peer_exports", "read_record_logs",
           "format_record_log_note", "require_peer_env",
           "resolve_peer_kernel", "sha_file"]
