// SPDX-License-Identifier: GPL-3.0-or-later
//! Event-stream requalification: the Rust probe set and the C probe set must
//! produce equivalent `record` event streams for the same workload in the
//! same guest, modulo timestamps, sequence numbers, and record ordering, with
//! agreeing counters.
//!
//! Method. One boot of the 7.0.14 ordinary cell; both recorders attach
//! SIMULTANEOUSLY to the same `swiotlb:swiotlb_bounced` tracepoint while a
//! fixed ping workload runs over the pcnet32 stimulus NIC, with an ftrace
//! `trace_pipe` oracle streaming as the independent third observer.
//! Sequential runs cannot work: bounce timing (and therefore counts) varies
//! run to run, so only simultaneous capture observes the same underlying
//! event set on both sides. The oracle breaks ties: each side must match the
//! oracle's in-window events exactly (zero loss), and the two sides must
//! match each other modulo the volatile fields.
//!
//! What is volatile (dropped before comparison): `seq`, `ts_ns`,
//! `session_id`, and per-recorder `operation_id` counters; record order is
//! normalized by sorting. Everything else — kind, hook, backend, profile,
//! device assignment, sizes, force flags, counter values — must agree.
//! `counter_snapshot` rows are time series whose intermediate points depend
//! on each recorder's attach instant, so only the FINAL value per counter
//! agrees. `pool_sample` rows are likewise cadence-driven (one side attaches
//! first and takes one more sample), so they agree by first+last sample per
//! pool with counts within two plus a `used_bytes` envelope (min and max
//! within one pool unit): sampling phase moves the observed envelope by a
//! sub-interval blip, never by a sustained level. Every sample also carries
//! a stable signature (kind, source, and the data members outside the live
//! `used_bytes`/`hiwater_bytes` readings) that must hold across the whole
//! series on each side and agree across sides, so a middle row with wrong
//! capacity, unit, or source metadata diverges; every other kind compares
//! as a full
//! normalized multiset. The boot pins `swiotlb=force`, so the workload must
//! be uniformly FORCED; any NORMAL hit (or mix) fails the workload shape.
//!
//! Layout. `Json`/`parse_json`/`canon` are a self-contained strict JSON
//! reader (the workspace builds offline with no serde); `diff_streams`
//! compares two `events.ndjson` documents; the `requal_*` unit tests pin the
//! differ offline; `requal_dual_capture_7014` runs the live cell when
//! `MEMVEIL_REQUAL_LIVE=1` and reports SKIP otherwise. The live test boots
//! `vng --run v7.0.14` (harness pinned by `tests/vm/harness.lock.json`,
//! kernel bytes pinned by `tests/vm/kernels.lock.json`) and fails closed on
//! any refusal; boot/timeout flakes retry 3x, divergences never retry.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Minimal strict JSON value + parser (no serde in this workspace).
// ---------------------------------------------------------------------------

/// A JSON value. Numbers keep their raw lexeme: captures render integers as
/// decimal text and the differ compares them lexically after normalization.
#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        if let Json::Obj(members) = self {
            members.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        } else {
            None
        }
    }

    fn as_str(&self) -> Option<&str> {
        if let Json::Str(text) = self {
            Some(text)
        } else {
            None
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(raw) => raw.parse::<u64>().ok(),
            Json::Str(text) => text.parse::<u64>().ok(),
            _ => None,
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn error(&self, what: &str) -> String {
        format!("byte {}: {what}", self.pos)
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error(&format!("want {byte:?}")))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.literal("null", Json::Null),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'[') => {
                self.pos += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                loop {
                    items.push(self.value()?);
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => {
                            self.pos += 1;
                        }
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Json::Arr(items));
                        }
                        _ => return Err(self.error("want , or ]")),
                    }
                }
            }
            Some(b'{') => {
                self.pos += 1;
                let mut members = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(Json::Obj(members));
                }
                loop {
                    self.skip_ws();
                    if self.peek() != Some(b'"') {
                        return Err(self.error("want string key"));
                    }
                    let key = self.string()?;
                    self.skip_ws();
                    self.expect(b':')?;
                    let val = self.value()?;
                    members.push((key, val));
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => {
                            self.pos += 1;
                        }
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(Json::Obj(members));
                        }
                        _ => return Err(self.error("want , or }")),
                    }
                }
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => Ok(Json::Num(self.number()?)),
            _ => Err(self.error("want value")),
        }
    }

    fn literal(&mut self, word: &str, val: Json) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(val)
        } else {
            Err(self.error(&format!("want {word}")))
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = self
                .peek()
                .ok_or_else(|| self.error("unterminated string"))?;
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let esc = self.peek().ok_or_else(|| self.error("bad escape"))?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            if self.pos + 4 > self.bytes.len() {
                                return Err(self.error("bad \\u escape"));
                            }
                            let digits = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
                                .map_err(|_| self.error("bad \\u escape"))?;
                            let unit = u32::from_str_radix(digits, 16)
                                .map_err(|_| self.error("bad \\u escape"))?;
                            self.pos += 4;
                            let ch =
                                char::from_u32(unit).ok_or_else(|| self.error("bad scalar"))?;
                            out.push(ch);
                        }
                        _ => return Err(self.error("bad escape")),
                    }
                }
                0x00..=0x1f => return Err(self.error("raw control in string")),
                _ => {
                    // Consume one UTF-8 scalar.
                    let rest = &self.bytes[self.pos..];
                    let text = std::str::from_utf8(rest).map_err(|_| self.error("bad utf-8"))?;
                    let ch = text.chars().next().ok_or_else(|| self.error("bad utf-8"))?;
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
    }

    fn number(&mut self) -> Result<String, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits = |p: &Parser<'a>| p.peek().is_some_and(|c| c.is_ascii_digit());
        if !digits(self) {
            return Err(self.error("want digits"));
        }
        // Strict means strict: JSON forbids leading zeros, so `0` starts a
        // number only alone, before `.`, or before an exponent. This matches
        // the product reader, which rejects `01` too.
        if self.bytes[self.pos] == b'0' {
            self.pos += 1;
            if digits(self) {
                return Err(self.error("leading zero"));
            }
        } else {
            while digits(self) {
                self.pos += 1;
            }
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !digits(self) {
                return Err(self.error("want digits"));
            }
            while digits(self) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !digits(self) {
                return Err(self.error("want digits"));
            }
            while digits(self) {
                self.pos += 1;
            }
        }
        String::from_utf8(self.bytes[start..self.pos].to_vec())
            .map_err(|_| self.error("bad number"))
    }
}

/// Parse one complete JSON document; trailing bytes refuse.
fn parse_json(text: &str) -> Result<Json, String> {
    let mut parser = Parser::new(text);
    let val = parser.value()?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(parser.error("trailing bytes"));
    }
    Ok(val)
}

/// Canonical render: object keys sorted, minimal separators, strings
/// re-escaped deterministically.
fn canon(val: &Json, out: &mut String) {
    match val {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Num(raw) => out.push_str(raw),
        Json::Str(text) => {
            out.push('"');
            for ch in text.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        out.push_str(&format!("\\u{:04x}", c as u32));
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Json::Arr(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                canon(item, out);
            }
            out.push(']');
        }
        Json::Obj(members) => {
            let mut sorted: Vec<(&String, &Json)> = members.iter().map(|(k, v)| (k, v)).collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (idx, (key, val)) in sorted.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                canon(&Json::Str((*key).clone()), out);
                out.push(':');
                canon(val, out);
            }
            out.push('}');
        }
    }
}

fn canon_string(val: &Json) -> String {
    let mut out = String::new();
    canon(val, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Normalization + stream differ.
// ---------------------------------------------------------------------------

/// Top-level volatile members: per-recorder counters and clocks.
const DROP_TOP: [&str; 3] = ["seq", "ts_ns", "session_id"];

/// `data` volatile members: per-recorder operation counters. `device_id`
/// stays: both recorders observe the same guest and must number devices
/// identically.
const DROP_DATA: [&str; 1] = ["operation_id"];

/// A normalized event: its kind plus the canonical form with volatile
/// members removed. `ts_ns` is returned alongside for window selection.
struct NormEvent {
    kind: String,
    ts_ns: u64,
    canon: String,
}

/// Strip volatile members from one parsed event line.
fn normalize_event(val: &Json) -> Result<NormEvent, String> {
    let Json::Obj(members) = val else {
        return Err("event is not an object".to_string());
    };
    let kind = val
        .get("kind")
        .and_then(Json::as_str)
        .ok_or_else(|| "event lacks string kind".to_string())?
        .to_string();
    let ts_ns = val
        .get("ts_ns")
        .and_then(Json::as_u64)
        .ok_or_else(|| format!("{kind} event lacks numeric ts_ns"))?;
    let mut kept: Vec<(String, Json)> = Vec::with_capacity(members.len());
    for (key, member) in members {
        if DROP_TOP.contains(&key.as_str()) {
            continue;
        }
        if key == "data"
            && let Json::Obj(data) = member
        {
            let held: Vec<(String, Json)> = data
                .iter()
                .filter(|(k, _)| !DROP_DATA.contains(&k.as_str()))
                .cloned()
                .collect();
            kept.push((key.clone(), Json::Obj(held)));
            continue;
        }
        kept.push((key.clone(), member.clone()));
    }
    let mut rendered = String::new();
    canon(&Json::Obj(kept), &mut rendered);
    Ok(NormEvent {
        kind,
        ts_ns,
        canon: rendered,
    })
}

/// First/last normalized sample, the `used_bytes` envelope, the sample
/// count, and the distinct stable signatures over EVERY sample for one
/// pool. A healthy series holds exactly one signature; more means a row
/// moved a field (capacity, unit, source) the cadence cannot explain.
struct PoolSeries {
    first: String,
    last: String,
    min_used: u64,
    max_used: u64,
    count: usize,
    stable: BTreeSet<String>,
}

/// Stable signature of one `pool_sample` line: kind, source, and the data
/// members outside the two live readings (`used_bytes`, covered by the
/// envelope, and `hiwater_bytes`, a watermark that legitimately grows
/// within a series). Everything else about a pool row is structural and
/// must not move sample to sample or side to side.
fn stable_pool_sig(val: &Json) -> Result<String, String> {
    let kind = val
        .get("kind")
        .and_then(Json::as_str)
        .ok_or_else(|| "sample lacks string kind".to_string())?;
    let source = val
        .get("source")
        .map(canon_string)
        .unwrap_or_else(|| "null".to_string());
    let Json::Obj(data) = val
        .get("data")
        .ok_or_else(|| "sample lacks data".to_string())?
    else {
        return Err("sample data is not an object".to_string());
    };
    let held: Vec<(String, Json)> = data
        .iter()
        .filter(|(key, _)| key != "used_bytes" && key != "hiwater_bytes")
        .cloned()
        .collect();
    let mut rendered = String::new();
    canon(&Json::Obj(held), &mut rendered);
    Ok(format!("{kind}|{source}|{rendered}"))
}

/// One parsed `events.ndjson` side: normalized multisets per kind plus the
/// final counter value per `(counter_id, scope)`.
struct StreamProfile {
    /// kind -> sorted normalized lines (`counter_snapshot` and
    /// `pool_sample` excluded: both are cadence-driven time series).
    multisets: BTreeMap<String, Vec<String>>,
    /// kind -> line count (all kinds, for the report).
    counts: BTreeMap<String, usize>,
    /// (counter_id, scope canon) -> final value, in stream order.
    counters_final: BTreeMap<(String, String), String>,
    /// (counter_id, scope canon) -> snapshot count, in stream order.
    counters_seen: BTreeMap<(String, String), usize>,
    /// pool_id -> first/last/envelope/count of its `pool_sample` series.
    pools: BTreeMap<String, PoolSeries>,
    /// (kind, ts_ns) of every line outside the window, for margin checks.
    /// Empty when no window was given.
    outside_window: Vec<(String, u64)>,
    total_lines: usize,
}

/// Parse one `events.ndjson` document into a profile. `window` restricts
/// multiset membership to `[start_ns, end_ns]`; counters still record their
/// stream-final value regardless of the window.
fn profile_stream(text: &str, window: Option<(u64, u64)>) -> Result<StreamProfile, String> {
    let mut profile = StreamProfile {
        multisets: BTreeMap::new(),
        counts: BTreeMap::new(),
        counters_final: BTreeMap::new(),
        counters_seen: BTreeMap::new(),
        pools: BTreeMap::new(),
        outside_window: Vec::new(),
        total_lines: 0,
    };
    for (lineno, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let val = parse_json(line).map_err(|e| format!("line {}: {e}", lineno + 1))?;
        let event = normalize_event(&val).map_err(|e| format!("line {}: {e}", lineno + 1))?;
        profile.total_lines += 1;
        *profile.counts.entry(event.kind.clone()).or_insert(0) += 1;
        let in_window =
            window.is_none_or(|(start, end)| start <= event.ts_ns && event.ts_ns <= end);
        if !in_window {
            profile
                .outside_window
                .push((event.kind.clone(), event.ts_ns));
        }
        if event.kind == "counter_snapshot" {
            let data = val
                .get("data")
                .ok_or_else(|| format!("line {}: snapshot lacks data", lineno + 1))?;
            let id = data
                .get("counter_id")
                .and_then(Json::as_str)
                .ok_or_else(|| format!("line {}: snapshot lacks counter_id", lineno + 1))?;
            let scope = data
                .get("scope")
                .map(canon_string)
                .unwrap_or_else(|| "null".to_string());
            let value = data
                .get("value")
                .and_then(Json::as_u64)
                .ok_or_else(|| format!("line {}: snapshot lacks numeric value", lineno + 1))?;
            let key = (id.to_string(), scope);
            profile
                .counters_final
                .insert(key.clone(), value.to_string());
            *profile.counters_seen.entry(key).or_insert(0) += 1;
            continue;
        }
        if event.kind == "pool_sample" {
            let data = val
                .get("data")
                .ok_or_else(|| format!("line {}: sample lacks data", lineno + 1))?;
            let pool = data
                .get("pool_id")
                .and_then(Json::as_str)
                .ok_or_else(|| format!("line {}: sample lacks pool_id", lineno + 1))?;
            let used = data
                .get("used_bytes")
                .and_then(Json::as_u64)
                .ok_or_else(|| format!("line {}: sample lacks numeric used_bytes", lineno + 1))?;
            let sig = stable_pool_sig(&val).map_err(|e| format!("line {}: {e}", lineno + 1))?;
            // Streams are ts-ordered, so first-seen is earliest.
            match profile.pools.get_mut(pool) {
                Some(series) => {
                    series.last = event.canon;
                    series.min_used = series.min_used.min(used);
                    series.max_used = series.max_used.max(used);
                    series.count += 1;
                    series.stable.insert(sig);
                }
                None => {
                    profile.pools.insert(
                        pool.to_string(),
                        PoolSeries {
                            first: event.canon.clone(),
                            last: event.canon,
                            min_used: used,
                            max_used: used,
                            count: 1,
                            stable: BTreeSet::from([sig]),
                        },
                    );
                }
            }
            continue;
        }
        if in_window {
            profile
                .multisets
                .entry(event.kind)
                .or_default()
                .push(event.canon);
        }
    }
    if profile.total_lines == 0 {
        return Err("empty event stream".to_string());
    }
    for lines in profile.multisets.values_mut() {
        lines.sort();
    }
    profile.outside_window.sort();
    Ok(profile)
}

/// Bounded comparison report between two profiles.
struct DiffReport {
    /// kind -> (rust lines, mojo lines) for kinds whose multisets differ.
    multiset_gaps: BTreeMap<String, (usize, usize)>,
    /// First lines only on one side, per gapped kind (bounded).
    only_rust: BTreeMap<String, Vec<String>>,
    only_mojo: BTreeMap<String, Vec<String>>,
    /// (counter_id, scope) -> (rust final, mojo final) for finals that
    /// differ or exist on one side only (`None` = absent).
    counter_gaps: BTreeMap<(String, String), (Option<String>, Option<String>)>,
    /// pool_id -> free-text cause for pool series that disagree.
    pool_gaps: BTreeMap<String, String>,
}

impl DiffReport {
    fn is_empty(&self) -> bool {
        self.multiset_gaps.is_empty() && self.counter_gaps.is_empty() && self.pool_gaps.is_empty()
    }
}

/// At most this many exemplar lines per kind per side in the report.
const EXEMPLARS: usize = 8;

/// Multiset difference of two SORTED line vecs into bounded exemplar lists.
fn multiset_gap(rust: &[String], mojo: &[String]) -> (Vec<String>, Vec<String>) {
    let mut only_rust = Vec::new();
    let mut only_mojo = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < rust.len() && j < mojo.len() {
        match rust[i].cmp(&mojo[j]) {
            std::cmp::Ordering::Less => {
                if only_rust.len() < EXEMPLARS {
                    only_rust.push(rust[i].clone());
                }
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                if only_mojo.len() < EXEMPLARS {
                    only_mojo.push(mojo[j].clone());
                }
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
        }
    }
    for line in &rust[i..] {
        if only_rust.len() >= EXEMPLARS {
            break;
        }
        only_rust.push(line.clone());
    }
    for line in &mojo[j..] {
        if only_mojo.len() >= EXEMPLARS {
            break;
        }
        only_mojo.push(line.clone());
    }
    (only_rust, only_mojo)
}

/// Pool-envelope tolerance in bytes: one pool unit (`unit_bytes` 2048 on
/// swiotlb-default). Sampling phase legitimately moves the `used_bytes`
/// envelope by one unit: a sub-sample-interval transient is caught by the
/// phase that lands on it and straddled by the other. Observed in 2 of 7
/// kept dual runs (one side max 67584, other 65536) with both sides'
/// `hiwater_bytes` agreeing at 69632 — the transient was real, the blip is
/// phase, and exact max/min would false-diverge. First/last stay exact, so
/// a systematic one-unit skew still diverges there; the envelope only
/// scopes *middle* content to uncharacterized-size drift.
const POOL_ENVELOPE_TOLERANCE: u64 = 2048;

/// Compare two profiles: every non-counter kind as a normalized multiset,
/// counters by stream-final value per `(counter_id, scope)`.
fn diff_profiles(rust: &StreamProfile, mojo: &StreamProfile) -> DiffReport {
    let mut report = DiffReport {
        multiset_gaps: BTreeMap::new(),
        only_rust: BTreeMap::new(),
        only_mojo: BTreeMap::new(),
        counter_gaps: BTreeMap::new(),
        pool_gaps: BTreeMap::new(),
    };
    let mut kinds: Vec<&String> = rust.multisets.keys().chain(mojo.multisets.keys()).collect();
    kinds.sort();
    kinds.dedup();
    for kind in kinds {
        let empty = Vec::new();
        let r = rust.multisets.get(kind).unwrap_or(&empty);
        let m = mojo.multisets.get(kind).unwrap_or(&empty);
        if r != m {
            let (only_r, only_m) = multiset_gap(r, m);
            report
                .multiset_gaps
                .insert((*kind).clone(), (r.len(), m.len()));
            report.only_rust.insert((*kind).clone(), only_r);
            report.only_mojo.insert((*kind).clone(), only_m);
        }
    }
    let mut counters: Vec<&(String, String)> = rust
        .counters_final
        .keys()
        .chain(mojo.counters_final.keys())
        .collect();
    counters.sort();
    counters.dedup();
    for key in counters {
        let r = rust.counters_final.get(key).cloned();
        let m = mojo.counters_final.get(key).cloned();
        if r != m {
            report.counter_gaps.insert((*key).clone(), (r, m));
        }
    }
    let mut pools: Vec<&String> = rust.pools.keys().chain(mojo.pools.keys()).collect();
    pools.sort();
    pools.dedup();
    for pool in pools {
        match (rust.pools.get(pool), mojo.pools.get(pool)) {
            (Some(r), Some(m)) => {
                // Pool-count allowance ±2: two characterized, content-neutral
                // variance components at 90 s windows. (1) attach skew ±1:
                // the earlier-attaching side takes up to one extra periodic
                // sample. (2) wake-lateness accumulation ±1: Rust median
                // period runs ~23 ms/tick longer than Mojo's (sleep-stepping
                // in Session::poll vs epoll_wait), so +23 ms/tick × ~90
                // ticks ≈ 2.1 s ≈ 2 samples of grid drift per 90 s window
                // (observed rust 89/89/90 vs mojo 91/91/91); first+last
                // payloads, event multisets, and counters stay exact, so the
                // offset is content-neutral. Revisit if long captures are
                // ever judged: per-tick lateness grows with window length.
                if r.count.abs_diff(m.count) > 2 {
                    report.pool_gaps.insert(
                        (*pool).clone(),
                        format!("count rust={} mojo={}", r.count, m.count),
                    );
                } else if r.stable.len() > 1 || m.stable.len() > 1 {
                    report.pool_gaps.insert(
                        (*pool).clone(),
                        format!(
                            "unstable pool fields within series (rust={} mojo={} variants)",
                            r.stable.len(),
                            m.stable.len()
                        ),
                    );
                } else if r.stable != m.stable {
                    report.pool_gaps.insert(
                        (*pool).clone(),
                        "stable pool fields differ across sides".to_string(),
                    );
                } else if r.first != m.first {
                    report
                        .pool_gaps
                        .insert((*pool).clone(), "first sample differs".to_string());
                } else if r.last != m.last {
                    report
                        .pool_gaps
                        .insert((*pool).clone(), "last sample differs".to_string());
                } else if r.min_used.abs_diff(m.min_used) > POOL_ENVELOPE_TOLERANCE {
                    report.pool_gaps.insert(
                        (*pool).clone(),
                        format!(
                            "min used_bytes rust={} mojo={} (beyond 1-unit tolerance)",
                            r.min_used, m.min_used
                        ),
                    );
                } else if r.max_used.abs_diff(m.max_used) > POOL_ENVELOPE_TOLERANCE {
                    report.pool_gaps.insert(
                        (*pool).clone(),
                        format!(
                            "max used_bytes rust={} mojo={} (beyond 1-unit tolerance)",
                            r.max_used, m.max_used
                        ),
                    );
                }
            }
            (Some(r), None) => {
                report.pool_gaps.insert(
                    (*pool).clone(),
                    format!("mojo lacks pool (rust count {})", r.count),
                );
            }
            (None, Some(m)) => {
                report.pool_gaps.insert(
                    (*pool).clone(),
                    format!("rust lacks pool (mojo count {})", m.count),
                );
            }
            (None, None) => {}
        }
    }
    report
}

/// Render the report for a failure message (bounded).
fn render_report(report: &DiffReport, rust: &StreamProfile, mojo: &StreamProfile) -> String {
    let mut out = String::from("event-stream divergence:\n");
    out.push_str(&format!(
        "  lines: rust={} mojo={}\n",
        rust.total_lines, mojo.total_lines
    ));
    for (kind, (r, m)) in &report.multiset_gaps {
        out.push_str(&format!("  kind {kind}: rust={r} mojo={m} lines\n"));
        for line in report.only_rust.get(kind).into_iter().flatten() {
            out.push_str(&format!("    rust-only: {line}\n"));
        }
        for line in report.only_mojo.get(kind).into_iter().flatten() {
            out.push_str(&format!("    mojo-only: {line}\n"));
        }
    }
    for ((id, scope), (r, m)) in &report.counter_gaps {
        out.push_str(&format!(
            "  counter {id} scope={scope}: rust={r:?} mojo={m:?}\n"
        ));
    }
    for (pool, cause) in &report.pool_gaps {
        out.push_str(&format!("  pool {pool}: {cause}\n"));
    }
    out
}

/// Kinds whose lines legitimately fall outside the workload window: the
/// cadence-driven series span recorder attach (before the workload) to
/// recorder exit (after it), so nearly every sample is out-of-window by
/// construction. Workload-driven events must never be.
const CADENCE_KINDS: [&str; 2] = ["counter_snapshot", "pool_sample"];

/// Quiet-margin divergences for one side: every out-of-window line is either
/// an exempt cadence-series sample or a divergence. A novel kind outside the
/// window fails closed instead of silently escaping the multiset (which only
/// holds in-window lines).
fn margin_divs(profile: &StreamProfile, side: &str) -> Vec<String> {
    let mut divs = Vec::new();
    for (kind, ts) in &profile.outside_window {
        if CADENCE_KINDS.contains(&kind.as_str()) {
            continue;
        }
        divs.push(format!("{side} {kind} persisted outside workload at {ts}"));
    }
    divs
}

/// Internal conservation for one side: the attempts counter final must equal
/// the persisted in-window bounce count, and the counter must exist under
/// exactly one scope. The single-scope requirement is the asserted form of
/// what the judge used to assume silently with a `.find`: a second scope
/// would otherwise escape the check entirely.
fn conservation_div(profile: &StreamProfile, side: &str, events_len: usize) -> Option<String> {
    let hits: Vec<&String> = profile
        .counters_final
        .iter()
        .filter(|((id, _), _)| id == "swiotlb.bounce_attempts")
        .map(|(_, value)| value)
        .collect();
    match hits.as_slice() {
        [value] if value.parse::<usize>().ok() == Some(events_len) => None,
        [value] => Some(format!(
            "{side} counter final {value} vs {events_len} persisted attempts"
        )),
        [] => Some(format!("{side} emits no swiotlb.bounce_attempts counter")),
        _ => Some(format!(
            "{side} attempts counter spans {} scopes, want exactly 1",
            hits.len()
        )),
    }
}

// ---------------------------------------------------------------------------
// Offline differ tests (no VM; always run).
// ---------------------------------------------------------------------------

/// One synthetic `bounce_attempt` line with controlled volatile fields.
fn attempt(seq: u64, ts: u64, session: &str, op: &str, size: u64, forced: bool) -> String {
    format!(
        "{{\"schema_version\":\"0.1.1\",\"session_id\":\"{session}\",\"seq\":\"{seq}\",\
         \"ts_ns\":\"{ts}\",\"kind\":\"bounce_attempt\",\
         \"source\":{{\"hook\":\"swiotlb:swiotlb_bounced\",\"backend\":\"tracepoint\",\
         \"profile_id\":\"p\",\"measurement\":\"observed\",\"correlation\":\"direct\"}},\
         \"data\":{{\"device_id\":\"d000001\",\"requested_bytes\":\"{size}\",\
         \"forced\":{forced},\"operation_id\":\"{op}\"}}}}"
    )
}

/// One synthetic `counter_snapshot` line.
fn snapshot(seq: u64, ts: u64, id: &str, value: u64) -> String {
    snapshot_scope(seq, ts, id, "{\"profile_id\":\"p\"}", value)
}

/// One synthetic `counter_snapshot` line under an explicit scope document.
fn snapshot_scope(seq: u64, ts: u64, id: &str, scope: &str, value: u64) -> String {
    format!(
        "{{\"schema_version\":\"0.1.1\",\"session_id\":\"s\",\"seq\":\"{seq}\",\
         \"ts_ns\":\"{ts}\",\"kind\":\"counter_snapshot\",\
         \"source\":{{\"hook\":\"swiotlb:swiotlb_bounced\",\"backend\":\"tracepoint\",\
         \"profile_id\":\"p\",\"measurement\":\"observed\",\"correlation\":\"direct\"}},\
         \"data\":{{\"counter_id\":\"{id}\",\"epoch\":\"0\",\
         \"scope\":{scope},\"value\":\"{value}\",\"unit\":\"count\"}}}}"
    )
}

/// One synthetic line of an arbitrary kind with empty data.
fn kind_line(kind: &str, seq: u64, ts: u64) -> String {
    format!(
        "{{\"schema_version\":\"0.1.1\",\"session_id\":\"s\",\"seq\":\"{seq}\",\
         \"ts_ns\":\"{ts}\",\"kind\":\"{kind}\",\
         \"source\":{{\"hook\":\"swiotlb:swiotlb_bounced\",\"backend\":\"tracepoint\",\
         \"profile_id\":\"p\",\"measurement\":\"observed\",\"correlation\":\"direct\"}},\
         \"data\":{{}}}}"
    )
}

#[test]
fn requal_equal_modulo_volatile_fields() {
    let rust = [
        attempt(0, 100, "cap-rust", "op0", 4096, false),
        attempt(1, 200, "cap-rust", "op1", 98, true),
        snapshot(2, 200, "swiotlb.bounce_attempts", 2),
    ]
    .join("\n");
    // Same content, shuffled order, disjoint seq/ts/session/op clocks.
    let mojo = [
        attempt(7, 900, "cap-mojo", "op9", 98, true),
        snapshot(9, 950, "swiotlb.bounce_attempts", 2),
        attempt(8, 800, "cap-mojo", "op8", 4096, false),
    ]
    .join("\n");
    let r = profile_stream(&rust, None).expect("rust parses");
    let m = profile_stream(&mojo, None).expect("mojo parses");
    let report = diff_profiles(&r, &m);
    assert!(report.is_empty(), "{}", render_report(&report, &r, &m));
}

#[test]
fn requal_size_divergence_reports() {
    let rust = attempt(0, 100, "s", "op0", 4096, false);
    let mojo = attempt(0, 100, "s", "op0", 98, false);
    let r = profile_stream(&rust, None).expect("rust parses");
    let m = profile_stream(&mojo, None).expect("mojo parses");
    let report = diff_profiles(&r, &m);
    assert!(!report.is_empty(), "size drift must diverge");
    assert!(report.multiset_gaps.contains_key("bounce_attempt"));
    assert_eq!(report.only_rust["bounce_attempt"].len(), 1);
    assert_eq!(report.only_mojo["bounce_attempt"].len(), 1);
}

#[test]
fn requal_count_divergence_reports() {
    let rust = [
        attempt(0, 100, "s", "op0", 98, false),
        attempt(1, 200, "s", "op1", 98, false),
    ]
    .join("\n");
    let mojo = attempt(0, 100, "s", "op0", 98, false);
    let r = profile_stream(&rust, None).expect("rust parses");
    let m = profile_stream(&mojo, None).expect("mojo parses");
    let report = diff_profiles(&r, &m);
    assert!(!report.is_empty(), "count drift must diverge");
    assert_eq!(
        report.multiset_gaps["bounce_attempt"],
        (2, 1),
        "{}",
        render_report(&report, &r, &m)
    );
}

#[test]
fn requal_device_drift_is_not_volatile() {
    let rust = attempt(0, 100, "s", "op0", 98, false);
    let mojo = rust.replace("d000001", "d000002");
    let r = profile_stream(&rust, None).expect("rust parses");
    let m = profile_stream(&mojo, None).expect("mojo parses");
    assert!(
        !diff_profiles(&r, &m).is_empty(),
        "device renumbering must diverge"
    );
}

#[test]
fn requal_counter_finals_agree_despite_series_drift() {
    // Different intermediate cadences, same final value: equivalent.
    let rust = [
        snapshot(0, 100, "swiotlb.bounce_attempts", 1),
        snapshot(1, 200, "swiotlb.bounce_attempts", 3),
        attempt(2, 200, "s", "op0", 98, false),
    ]
    .join("\n");
    let mojo = [
        snapshot(0, 150, "swiotlb.bounce_attempts", 2),
        snapshot(1, 250, "swiotlb.bounce_attempts", 3),
        attempt(2, 250, "s", "op0", 98, false),
    ]
    .join("\n");
    let r = profile_stream(&rust, None).expect("rust parses");
    let m = profile_stream(&mojo, None).expect("mojo parses");
    let report = diff_profiles(&r, &m);
    assert!(report.is_empty(), "{}", render_report(&report, &r, &m));
}

#[test]
fn requal_counter_final_drift_reports() {
    let rust = snapshot(0, 100, "swiotlb.bounce_attempts", 3);
    let mojo = snapshot(0, 100, "swiotlb.bounce_attempts", 2);
    let r = profile_stream(&rust, None).expect("rust parses");
    let m = profile_stream(&mojo, None).expect("mojo parses");
    let report = diff_profiles(&r, &m);
    assert!(!report.is_empty(), "counter drift must diverge");
    assert_eq!(report.counter_gaps.len(), 1);
}

#[test]
fn requal_window_selects_multisets() {
    let rust = [
        attempt(0, 100, "s", "op0", 98, false),
        attempt(1, 500, "s", "op1", 4096, false),
    ]
    .join("\n");
    let mojo = attempt(0, 100, "s", "op0", 98, false);
    let r = profile_stream(&rust, Some((50, 150))).expect("rust parses");
    let m = profile_stream(&mojo, Some((50, 150))).expect("mojo parses");
    let report = diff_profiles(&r, &m);
    assert!(report.is_empty(), "{}", render_report(&report, &r, &m));
    // Without the window the extra attempt diverges.
    let r = profile_stream(&rust, None).expect("rust parses");
    let m = profile_stream(&mojo, None).expect("mojo parses");
    assert!(!diff_profiles(&r, &m).is_empty());
}

/// One synthetic `pool_sample` line, in the real row shape (stable
/// `capacity_bytes`/`unit`/`allocator`/`unit_bytes` plus the live
/// `used_bytes`/`hiwater_bytes` readings).
fn pool_sample(seq: u64, ts: u64, used: u64) -> String {
    pool_sample_full(seq, ts, used, "67108864", "2048", "debugfs")
}

/// One synthetic `pool_sample` line with overridable stable fields.
fn pool_sample_full(
    seq: u64,
    ts: u64,
    used: u64,
    capacity: &str,
    unit_bytes: &str,
    backend: &str,
) -> String {
    format!(
        "{{\"schema_version\":\"0.1.1\",\"session_id\":\"s\",\"seq\":\"{seq}\",\
         \"ts_ns\":\"{ts}\",\"kind\":\"pool_sample\",\
         \"source\":{{\"hook\":\"swiotlb:debugfs\",\"backend\":\"{backend}\",\
         \"profile_id\":\"p\",\"measurement\":\"observed\",\"correlation\":\"direct\"}},\
         \"data\":{{\"pool_id\":\"swiotlb-default\",\"used_bytes\":\"{used}\",\
         \"capacity_bytes\":\"{capacity}\",\"unit\":\"bytes\",\"allocator\":\"swiotlb\",\
         \"unit_bytes\":\"{unit_bytes}\",\"hiwater_bytes\":\"69632\"}}}}"
    )
}

#[test]
fn requal_pool_series_agrees_within_cadence() {
    // One side takes an extra middle sample inside the shared envelope:
    // first+last agree, min/max agree, counts within two — equivalent.
    let rust = [
        pool_sample(0, 100, 10),
        pool_sample(1, 200, 10),
        pool_sample(2, 300, 10),
        attempt(3, 300, "s", "op0", 98, false),
    ]
    .join("\n");
    let mojo = [
        pool_sample(0, 100, 10),
        pool_sample(1, 300, 10),
        attempt(2, 300, "s", "op0", 98, false),
    ]
    .join("\n");
    let r = profile_stream(&rust, None).expect("rust parses");
    let m = profile_stream(&mojo, None).expect("mojo parses");
    let report = diff_profiles(&r, &m);
    assert!(report.is_empty(), "{}", render_report(&report, &r, &m));
}

#[test]
fn requal_pool_envelope_tolerates_one_unit_blip() {
    // A one-unit middle blip on one side only is phase, not content: the
    // observed 67584-vs-65536 split stays equivalent.
    let flat = [
        pool_sample(0, 100, 65536),
        pool_sample(1, 200, 65536),
        pool_sample(2, 300, 65536),
        attempt(3, 300, "s", "op0", 98, false),
    ]
    .join("\n");
    let blip = [
        pool_sample(0, 100, 65536),
        pool_sample(1, 200, 67584),
        pool_sample(2, 300, 65536),
        attempt(3, 300, "s", "op0", 98, false),
    ]
    .join("\n");
    let r = profile_stream(&blip, None).expect("rust parses");
    let m = profile_stream(&flat, None).expect("mojo parses");
    let report = diff_profiles(&r, &m);
    assert!(report.is_empty(), "{}", render_report(&report, &r, &m));
}

#[test]
fn requal_pool_envelope_drift_reports() {
    // A middle excursion beyond one unit diverges even when first+last agree
    // and counts are close: phase explains a blip, never a sustained level.
    let base = [
        pool_sample(0, 100, 65536),
        pool_sample(1, 200, 65536),
        pool_sample(2, 300, 65536),
        attempt(3, 300, "s", "op0", 98, false),
    ]
    .join("\n");
    let shifted = [
        pool_sample(0, 100, 65536),
        pool_sample(1, 200, 69632),
        pool_sample(2, 300, 65536),
        attempt(3, 300, "s", "op0", 98, false),
    ]
    .join("\n");
    let r = profile_stream(&base, None).expect("rust parses");
    let m = profile_stream(&shifted, None).expect("mojo parses");
    let report = diff_profiles(&r, &m);
    assert!(
        !report.is_empty(),
        "middle max beyond tolerance must diverge: {}",
        render_report(&report, &r, &m)
    );
    assert_eq!(
        report.pool_gaps["swiotlb-default"],
        "max used_bytes rust=65536 mojo=69632 (beyond 1-unit tolerance)"
    );
    let dipped = [
        pool_sample(0, 100, 65536),
        pool_sample(1, 200, 61440),
        pool_sample(2, 300, 65536),
        attempt(3, 300, "s", "op0", 98, false),
    ]
    .join("\n");
    let m = profile_stream(&dipped, None).expect("mojo parses");
    let report = diff_profiles(&r, &m);
    assert!(
        !report.is_empty(),
        "middle min beyond tolerance must diverge: {}",
        render_report(&report, &r, &m)
    );
    assert_eq!(
        report.pool_gaps["swiotlb-default"],
        "min used_bytes rust=65536 mojo=61440 (beyond 1-unit tolerance)"
    );
}

#[test]
fn requal_pool_middle_stable_drift_reports() {
    // A middle row that moves a stable field (capacity, unit size, source)
    // diverges even when counts, first+last, and the used envelope agree:
    // cadence explains timing, never structure.
    let base = [
        pool_sample(0, 100, 65536),
        pool_sample(1, 200, 65536),
        pool_sample(2, 300, 65536),
        attempt(3, 300, "s", "op0", 98, false),
    ]
    .join("\n");
    let m = profile_stream(&base, None).expect("mojo parses");
    for (tag, middle) in [
        (
            "capacity",
            pool_sample_full(1, 200, 65536, "33554432", "2048", "debugfs"),
        ),
        (
            "unit",
            pool_sample_full(1, 200, 65536, "67108864", "4096", "debugfs"),
        ),
        (
            "source",
            pool_sample_full(1, 200, 65536, "67108864", "2048", "tracefs"),
        ),
    ] {
        let mutated = [
            pool_sample(0, 100, 65536),
            middle,
            pool_sample(2, 300, 65536),
            attempt(3, 300, "s", "op0", 98, false),
        ]
        .join("\n");
        let r = profile_stream(&mutated, None).expect("rust parses");
        let report = diff_profiles(&r, &m);
        assert!(
            !report.is_empty(),
            "{tag}: middle stable drift must diverge: {}",
            render_report(&report, &r, &m)
        );
        assert_eq!(
            report.pool_gaps["swiotlb-default"],
            "unstable pool fields within series (rust=2 mojo=1 variants)",
            "{tag}"
        );
    }
    // A hiwater watermark that grows mid-series stays quiet: it is a live
    // reading like used_bytes, not structure.
    let grown = [
        pool_sample(0, 100, 65536),
        pool_sample(1, 200, 65536).replace(
            "\"hiwater_bytes\":\"69632\"",
            "\"hiwater_bytes\":\"131072\"",
        ),
        pool_sample(2, 300, 65536),
        attempt(3, 300, "s", "op0", 98, false),
    ]
    .join("\n");
    let r = profile_stream(&grown, None).expect("rust parses");
    let report = diff_profiles(&r, &m);
    assert!(report.is_empty(), "{}", render_report(&report, &r, &m));
}

#[test]
fn requal_pool_first_or_last_drift_reports() {
    let base = [
        pool_sample(0, 100, 10),
        pool_sample(1, 200, 10),
        attempt(2, 200, "s", "op0", 98, false),
    ]
    .join("\n");
    let drifted = [
        pool_sample(0, 100, 99),
        pool_sample(1, 200, 10),
        attempt(2, 200, "s", "op0", 98, false),
    ]
    .join("\n");
    let r = profile_stream(&base, None).expect("rust parses");
    let m = profile_stream(&drifted, None).expect("mojo parses");
    let report = diff_profiles(&r, &m);
    assert!(!report.is_empty(), "pool first-sample drift must diverge");
    assert!(report.pool_gaps.contains_key("swiotlb-default"));
    // Three extra samples exceed the ±2 pool-count allowance.
    let many = [
        pool_sample(0, 100, 10),
        pool_sample(1, 150, 10),
        pool_sample(2, 200, 10),
        pool_sample(3, 250, 10),
        pool_sample(4, 300, 10),
        attempt(5, 300, "s", "op0", 98, false),
    ]
    .join("\n");
    let r = profile_stream(&base, None).expect("rust parses");
    let m = profile_stream(&many, None).expect("mojo parses");
    assert!(
        !diff_profiles(&r, &m).is_empty(),
        "pool count drift beyond two must diverge"
    );
}

#[test]
fn requal_margins_flag_workload_lines_not_cadence() {
    // Window [50, 150]: the in-window attempt is quiet; the cadence series
    // before/after it is exempt; the out-of-window attempt and the novel
    // `gap` line diverge.
    let stream = [
        pool_sample(0, 10, 10),
        snapshot(1, 20, "swiotlb.bounce_attempts", 0),
        attempt(2, 100, "s", "op0", 98, false),
        attempt(3, 900, "s", "op1", 98, false),
        kind_line("gap", 4, 950),
        pool_sample(5, 960, 10),
        snapshot(6, 970, "swiotlb.bounce_attempts", 1),
    ]
    .join("\n");
    let profile = profile_stream(&stream, Some((50, 150))).expect("parses");
    assert_eq!(
        margin_divs(&profile, "rust"),
        vec![
            "rust bounce_attempt persisted outside workload at 900".to_string(),
            "rust gap persisted outside workload at 950".to_string(),
        ]
    );
}

#[test]
fn requal_conservation_asserts_single_scope() {
    let one = [
        attempt(0, 100, "s", "op0", 98, false),
        snapshot(1, 100, "swiotlb.bounce_attempts", 1),
    ]
    .join("\n");
    let profile = profile_stream(&one, None).expect("parses");
    assert_eq!(conservation_div(&profile, "rust", 1), None);
    assert!(conservation_div(&profile, "rust", 2).is_some());
    // Same counter under two scopes: the conservation check must flag the
    // split instead of silently comparing one scope's final.
    let two = [
        attempt(0, 100, "s", "op0", 98, false),
        snapshot(1, 100, "swiotlb.bounce_attempts", 1),
        snapshot_scope(
            2,
            100,
            "swiotlb.bounce_attempts",
            "{\"profile_id\":\"q\"}",
            0,
        ),
    ]
    .join("\n");
    let profile = profile_stream(&two, None).expect("parses");
    assert_eq!(
        conservation_div(&profile, "rust", 1),
        Some("rust attempts counter spans 2 scopes, want exactly 1".to_string())
    );
    // No attempts counter at all still diverges.
    let none = attempt(0, 100, "s", "op0", 98, false);
    let profile = profile_stream(&none, None).expect("parses");
    assert!(conservation_div(&profile, "rust", 1).is_some());
}

#[test]
fn requal_malformed_line_fails_loud() {
    assert!(profile_stream("{\"kind\":\n", None).is_err());
    assert!(profile_stream("", None).is_err());
    assert!(profile_stream("[1,2]\n", None).is_err());
    // Trailing garbage after a valid line refuses.
    let bad = attempt(0, 100, "s", "op0", 98, false) + " trailing";
    assert!(profile_stream(&bad, None).is_err());
}

#[test]
fn requal_json_parser_shapes() {
    let val = parse_json("{\"b\":[1,-2.5,1e3,true,null,\"a\\\"b\\u0041\"]}").expect("shapes parse");
    assert_eq!(
        canon_string(&val),
        "{\"b\":[1,-2.5,1e3,true,null,\"a\\\"bA\"]}"
    );
    assert!(parse_json("{\"a\":01}").is_err());
    assert!(parse_json("{\"a\":-01}").is_err());
    assert!(parse_json("{\"a\":0}").is_ok());
    assert!(parse_json("{\"a\":-0}").is_ok());
    assert!(parse_json("{\"a\":0.5}").is_ok());
    assert!(parse_json("{\"a\":0e1}").is_ok());
    assert!(parse_json("{\"a\":}").is_err());
    assert!(parse_json("{\"a\":1} ").is_ok());
    assert!(parse_json("{\"a\":1} x").is_err());
}

#[test]
fn requal_loss_count_requires_canonical_zero() {
    // Only the canonical string "0" certifies lossless: null and missing
    // mean unknown (session 0.1.4 distinguishes them from measured zero),
    // and numeric or padded forms are not canonical counts.
    let detail =
        |loss: &str| parse_json(&format!("{{\"loss_count\":{loss}}}")).expect("detail parses");
    assert_eq!(loss_div("rust", &detail("\"0\"")), None);
    assert_eq!(
        loss_div("rust", &detail("\"5\"")),
        Some("rust lost 5 events".to_string())
    );
    for (raw, want) in [
        ("null", "rust loss_count is not canonical: null"),
        ("0", "rust loss_count is not canonical: 0"),
        ("5", "rust loss_count is not canonical: 5"),
        ("\"00\"", "rust loss_count is not canonical: \"00\""),
        ("\"+0\"", "rust loss_count is not canonical: \"+0\""),
        ("\" 0\"", "rust loss_count is not canonical: \" 0\""),
        ("\"\"", "rust loss_count is not canonical: \"\""),
        ("true", "rust loss_count is not canonical: true"),
    ] {
        assert_eq!(
            loss_div("rust", &detail(raw)),
            Some(want.to_string()),
            "raw {raw}"
        );
    }
    let missing = parse_json("{}").expect("empty detail parses");
    assert_eq!(
        loss_div("rust", &missing),
        Some("rust loss_count missing (unknown loss, not zero)".to_string())
    );
    assert_eq!(canonical_u64("0"), Some(0));
    assert_eq!(canonical_u64("18446744073709551615"), Some(u64::MAX));
    assert_eq!(canonical_u64("18446744073709551616"), None);
    assert_eq!(canonical_u64("00"), None);
    assert_eq!(canonical_u64("+0"), None);
    assert_eq!(canonical_u64(""), None);
}

// ---------------------------------------------------------------------------
// Live dual-capture cell (needs MEMVEIL_REQUAL_LIVE=1 + the VM harness).
// ---------------------------------------------------------------------------

/// Set to `1` to boot the cell; anything else reports SKIP.
const LIVE_VAR: &str = "MEMVEIL_REQUAL_LIVE";
/// Keep every attempt directory (under the system temp dir) even on success.
const KEEP_VAR: &str = "MEMVEIL_REQUAL_KEEP";
/// Override the Mojo oracle binary (default: `build/mojo-memveil-compare`).
const MOJO_VAR: &str = "MEMVEIL_REQUAL_MOJO_BIN";

/// Guest kernel for the ordinary cell (cached virtme-ng entry).
const GUEST_KERNEL: &str = "v7.0.14";
/// Release the guest must report.
const GUEST_RELEASE: &str = "7.0.14-070014-generic";
/// Guest `/sys/kernel/btf/vmlinux` sha256 the judge pins: identical across
/// seven kept dual-capture runs of the pinned v7.0.14 image, so drift means
/// the kernel bytes moved under the pin. Re-record deliberately if the
/// kernels-lock pin ever changes.
const GUEST_BTF_SHA: &str = "ec3aa895be1da974a3116c24cd31adccc5e49fef1b4b089dc588aa9e32419a05";
/// Guest `swiotlb_bounced/format` sha256, same provenance and discipline as
/// [`GUEST_BTF_SHA`]: the probe offsets derive from this text.
const GUEST_FORMAT_SHA: &str = "7e95fff18d1bd16c18342d821e78680a0126ff84054936fbc641e181810f0b62";
/// Ordinary-cell shape: 2 vCPU / 4 GiB, full machine (the pcnet stimulus
/// NIC needs legacy PCI, so microvm stays off).
const GUEST_CPUS: &str = "2";
const GUEST_MEM: &str = "4G";
/// Fixed workload: adaptive ping flood over the pcnet32 NIC.
const WORKLOAD_PINGS: &str = "2000";
/// Recorder duration: comfortably covers boot-readiness plus the workload.
const RECORD_DURATION: &str = "90";
/// Whole-guest wall budget per attempt, in seconds.
const GUEST_TIMEOUT_SECS: &str = "900";
/// Boot/timeout flakes retry; divergences and refusals never retry.
const MAX_ATTEMPTS: usize = 3;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rust/ must have a parent directory")
        .to_path_buf()
}

fn read_text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}

/// First stdout line of `argv`, or a loud failure naming the tool.
fn tool_line(argv: &[&str]) -> Result<String, String> {
    let out = Command::new(argv[0])
        .args(&argv[1..])
        .output()
        .map_err(|e| format!("run {}: {e}", argv[0]))?;
    if !out.status.success() {
        return Err(format!("{} exited {}", argv[0], out.status));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .next()
        .map(str::to_string)
        .ok_or_else(|| format!("{} printed no version line", argv[0]))
}

/// URLs and paths must not smuggle shell metacharacters into the guest argv.
fn clean_path(tag: &str, val: &str) -> Result<(), String> {
    if val.is_empty()
        || val.bytes().any(|b| {
            b.is_ascii_whitespace()
                || matches!(
                    b,
                    b'\'' | b'"' | b'`' | b'$' | b'(' | b')' | b';' | b'&' | b'|' | b'<' | b'>'
                )
        })
    {
        return Err(format!("{tag} is not shell-clean: {val:?}"));
    }
    Ok(())
}

struct LiveInputs {
    vng: String,
    rust_bin: PathBuf,
    mojo_bin: PathBuf,
    c_obj: PathBuf,
    aya_obj: PathBuf,
    bridge: PathBuf,
    profiles: PathBuf,
    vmlinuz_sha: String,
}

/// Resolve and pin every live input. Armed means ready: anything missing or
/// drifted fails the test, never skips.
fn resolve_live() -> Result<LiveInputs, String> {
    let repo = repo_root();
    let lock_text = read_text(&repo.join("tests/vm/harness.lock.json"))?;
    let lock = parse_json(&lock_text).map_err(|e| format!("harness lock: {e}"))?;
    let want_vng = lock
        .get("vng")
        .and_then(Json::as_str)
        .ok_or_else(|| "harness lock lacks vng".to_string())?;
    let want_qemu = lock
        .get("qemu")
        .and_then(Json::as_str)
        .ok_or_else(|| "harness lock lacks qemu".to_string())?;
    let vng = std::env::var("VNG").unwrap_or_else(|_| "vng".to_string());
    let got_vng = tool_line(&[vng.as_str(), "--version"])?;
    if got_vng != want_vng {
        return Err(format!("vng drift: want {want_vng:?} got {got_vng:?}"));
    }
    let got_qemu = tool_line(&["qemu-system-x86_64", "--version"])?;
    if got_qemu != want_qemu && !got_qemu.starts_with(&format!("{want_qemu} (")) {
        return Err(format!(
            "qemu drift: want {want_qemu:?} got {got_qemu:?} \
             (PATH must put the pinned QEMU first)"
        ));
    }
    if !Path::new("/dev/kvm").exists() {
        return Err("/dev/kvm is missing".to_string());
    }
    // Kernel bytes pinned by the matrix lock: the guest must boot the exact
    // cached image, never a fresh download.
    let kernels_text = read_text(&repo.join("tests/vm/kernels.lock.json"))?;
    let kernels = parse_json(&kernels_text).map_err(|e| format!("kernels lock: {e}"))?;
    let Json::Arr(rows) = kernels.get("kernels").ok_or("kernels lock lacks rows")? else {
        return Err("kernels lock rows are not an array".to_string());
    };
    let mut vmlinuz_sha = None;
    for row in rows {
        let source = row.get("source");
        let matches = source
            .and_then(|s| s.get("vng_version"))
            .and_then(Json::as_str)
            == Some(GUEST_KERNEL);
        if matches {
            vmlinuz_sha = source
                .and_then(|s| s.get("vmlinuz_sha256"))
                .and_then(Json::as_str)
                .map(str::to_string);
        }
    }
    let vmlinuz_sha =
        vmlinuz_sha.ok_or_else(|| format!("kernels lock lacks a {GUEST_KERNEL} vmlinuz pin"))?;
    let home = std::env::var("HOME").map_err(|_| "HOME is unset".to_string())?;
    let cache = Path::new(&home)
        .join(".cache/virtme-ng")
        .join(GUEST_KERNEL)
        .join("amd64");
    let vmlinuz = cache.join("boot").join(format!("vmlinuz-{GUEST_RELEASE}"));
    if !vmlinuz.is_file() {
        return Err(format!(
            "cached guest kernel missing: {}",
            vmlinuz.display()
        ));
    }
    let digest = sha256_file(&vmlinuz)?;
    if digest != vmlinuz_sha {
        return Err(format!(
            "guest vmlinuz drift for {GUEST_KERNEL}: want {vmlinuz_sha} got {digest}"
        ));
    }
    let rust_bin = PathBuf::from(env!("CARGO_BIN_EXE_memveil"));
    let mojo_bin = std::env::var(MOJO_VAR)
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo.join("build/mojo-memveil-compare"));
    let c_obj = repo.join("build/bpf/swiotlb_attempt.bpf.o");
    let aya_obj = PathBuf::from(env!("DEP_MEMVEIL_EBPF_ATTEMPT_PATH"));
    let bridge = repo.join("build/deps/lmb/lib/libbpf_mojo.so.1");
    let profiles = repo.join("profiles");
    for (tag, path) in [
        ("rust binary", &rust_bin),
        ("mojo binary", &mojo_bin),
        ("C object", &c_obj),
        ("Aya object", &aya_obj),
        ("bridge", &bridge),
    ] {
        if !path.is_file() {
            return Err(format!("{} is missing: {}", tag, path.display()));
        }
        clean_path(tag, &path.to_string_lossy())?;
    }
    if !profiles.join("linux-x86_64-7.0-reference.json").is_file() {
        return Err(format!(
            "7.0 reference profile is missing under {}",
            profiles.display()
        ));
    }
    clean_path("profiles dir", &profiles.to_string_lossy())?;
    clean_path("vng", &vng)?;
    Ok(LiveInputs {
        vng,
        rust_bin,
        mojo_bin,
        c_obj,
        aya_obj,
        bridge,
        profiles,
        vmlinuz_sha,
    })
}

/// SHA-256 via the host `sha256sum`: the workspace carries no hash crate
/// for integration tests, and shelling out keeps the dependency set shut.
fn sha256_file(path: &Path) -> Result<String, String> {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|e| format!("run sha256sum: {e}"))?;
    if !out.status.success() {
        return Err(format!("sha256sum failed on {}", path.display()));
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .map(str::to_string)
        .ok_or_else(|| "sha256sum printed no digest".to_string())
}

/// Outcome of one guest attempt: either exports to judge, a retryable flake,
/// or a terminal failure.
enum Attempt {
    Exports(PathBuf),
    Flake(String),
    Fatal(String),
}

/// Boot the cell and run the dual capture once.
fn run_attempt(inputs: &LiveInputs, attempt: usize) -> Attempt {
    let base = std::env::temp_dir().join(format!("requal-{}-{attempt}", std::process::id()));
    let export = base.join("export");
    if let Err(e) = std::fs::create_dir_all(&export) {
        return Attempt::Fatal(format!("mkdir {}: {e}", export.display()));
    }
    let script = base.join("requal_guest.py");
    if let Err(e) = std::fs::write(&script, GUEST_PY) {
        return Attempt::Fatal(format!("write {}: {e}", script.display()));
    }
    let str_of = |p: &Path| p.to_string_lossy().into_owned();
    // NB: the guest swallows the first --exec word: the script lands in
    // argv[0], so the guest sees 11 entries for these 12 words (verified by
    // direct probe; the same convention the committed gate flows use).
    let exec = format!(
        "python3 {} /tmp/vmgate-work /tmp/export {} {} {} {} {} {} {} {}",
        str_of(&script),
        str_of(&inputs.mojo_bin),
        str_of(&inputs.rust_bin),
        str_of(&inputs.c_obj),
        str_of(&inputs.aya_obj),
        str_of(&inputs.bridge),
        str_of(&inputs.profiles),
        RECORD_DURATION,
        WORKLOAD_PINGS,
    );
    if exec.len() > 1800 {
        return Attempt::Fatal(format!(
            "guest argv {} chars risks the kernel cmdline limit",
            exec.len()
        ));
    }
    let uname = Command::new("uname").arg("-r").output();
    let release = uname
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let host_vmlinuz = format!("/boot/vmlinuz-{release}");
    // Mirror the gate prefix: direct vng when the host image is readable
    // and KVM is writable, else passwordless sudo with the verified cache.
    let direct = Path::new(&host_vmlinuz).is_file()
        && std::fs::File::open(&host_vmlinuz).is_ok()
        && std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/kvm")
            .is_ok();
    let mut cmd = Command::new("timeout");
    cmd.arg(GUEST_TIMEOUT_SECS);
    if direct {
        cmd.arg(&inputs.vng);
    } else {
        let sudo = Command::new("sudo")
            .args(["-n", "true"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !sudo {
            return Attempt::Fatal("vng needs root and no passwordless sudo".to_string());
        }
        let path = std::env::var("PATH").unwrap_or_default();
        let home = std::env::var("HOME").unwrap_or_default();
        cmd.args([
            "sudo",
            "-n",
            "env",
            &format!("PATH={path}"),
            &format!("HOME={home}"),
            &inputs.vng,
        ]);
    }
    cmd.args([
        "--run",
        GUEST_KERNEL,
        "-m",
        GUEST_MEM,
        "--cpus",
        GUEST_CPUS,
        "--disable-microvm",
        "--network",
        "user",
        "--qemu-opts=-cpu host",
        "--qemu-opts=-device pcnet,netdev=pcnet0 -netdev user,id=pcnet0,net=10.0.3.0/24",
        "--append",
        "swiotlb=force",
        &format!("--rwdir=/tmp/export={}", str_of(&export)),
        "--exec",
        &exec,
    ]);
    println!(
        "requal: attempt {attempt}: booting {GUEST_KERNEL} ({})",
        if direct { "direct" } else { "sudo" }
    );
    let out = match cmd.output() {
        Ok(out) => out,
        Err(e) => return Attempt::Flake(format!("spawn vng: {e}")),
    };
    let log = base.join("vng.log");
    let transcript = format!(
        "exit: {}\n--- stdout ---\n{}\n--- stderr ---\n{}\n",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::write(&log, &transcript);
    match out.status.code() {
        Some(0) => Attempt::Exports(base),
        Some(124) => Attempt::Flake(format!(
            "vng timed out after {GUEST_TIMEOUT_SECS}s (see {})",
            log.display()
        )),
        Some(code) => {
            // A nonzero guest exit is a refusal until proven a boot flake:
            // only vng's own boot failures (no guest output at all) retry.
            let guest_ran = export.join("ledger.json").is_file()
                || String::from_utf8_lossy(&out.stdout).contains("requal-guest:");
            if guest_ran {
                Attempt::Fatal(format!(
                    "guest refused, exit {code} (see {})",
                    log.display()
                ))
            } else {
                Attempt::Flake(format!(
                    "vng boot failed, exit {code} (see {})",
                    log.display()
                ))
            }
        }
        None => Attempt::Flake(format!(
            "vng killed by signal {} (see {})",
            out.status,
            log.display()
        )),
    }
}

/// Files the guest must export (each with a `.sha256` sidecar). The raw
/// ftrace pipe never crosses: only the allowlisted oracle does.
const EXPORT_NAMES: [&str; 11] = [
    "ledger.json",
    "oracle.json",
    "ping.txt",
    "mojo.session.json",
    "mojo.events.ndjson",
    "mojo.record.stdout",
    "mojo.record.stderr",
    "rust.session.json",
    "rust.events.ndjson",
    "rust.record.stdout",
    "rust.record.stderr",
];

/// Exact-inventory plus sidecar-hash check over one attempt's exports.
fn verify_exports(base: &Path) -> Result<BTreeMap<String, String>, String> {
    let export = base.join("export");
    let mut names: Vec<String> = std::fs::read_dir(&export)
        .map_err(|e| format!("read {}: {e}", export.display()))?
        .map(|e| e.map(|x| x.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("list {}: {e}", export.display()))?;
    names.sort();
    let mut want: Vec<String> = EXPORT_NAMES
        .iter()
        .flat_map(|n| [(*n).to_string(), format!("{n}.sha256")])
        .collect();
    want.sort();
    if names != want {
        return Err(format!(
            "export inventory drift: have {names:?} want {want:?}"
        ));
    }
    // No raw DMA addresses may cross: the exports carry sizes, flags, and
    // counters only. `dev_addr`/`phys_addr=` text refuses the attempt.
    let mut texts = BTreeMap::new();
    for name in EXPORT_NAMES {
        let path = export.join(name);
        let digest = sha256_file(&path)?;
        let sidecar = read_text(&export.join(format!("{name}.sha256")))?;
        let pinned = sidecar
            .split_whitespace()
            .next()
            .ok_or_else(|| format!("{name}.sha256 is empty"))?;
        if pinned != digest {
            return Err(format!("{name} sidecar mismatch"));
        }
        let text = read_text(&path)?;
        for marker in ["dev_addr", "phys_addr=", "swiotlb_tbl"] {
            if text.contains(marker) {
                return Err(format!("{name} leaks a raw-address marker"));
            }
        }
        texts.insert(name.to_string(), text);
    }
    Ok(texts)
}

fn json_field<'a>(val: &'a Json, key: &str) -> Result<&'a Json, String> {
    val.get(key)
        .ok_or_else(|| format!("document lacks {key:?}"))
}

fn u64_field(val: &Json, key: &str) -> Result<u64, String> {
    json_field(val, key)?
        .as_u64()
        .ok_or_else(|| format!("{key:?} is not numeric"))
}

/// Canonical decimal count: all digits, no leading zero, no sign, nonempty.
/// `str::parse::<u64>` alone is looser (it accepts `+0` and `00`), so the
/// shape check comes first.
fn canonical_u64(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    text.parse::<u64>().ok()
}

/// Loss verdict for one side's `quality.detail`: `None` when the side
/// measured zero loss, else the divergence line. Session 0.1.4 carries
/// counts as canonical decimal strings and distinguishes null (unknown)
/// from measured zero, so only the string `"0"` certifies lossless: a
/// missing, null, numeric, or malformed `loss_count` diverges instead of
/// defaulting to zero.
fn loss_div(side: &str, detail: &Json) -> Option<String> {
    match detail.get("loss_count") {
        Some(Json::Str(text)) => match canonical_u64(text) {
            Some(0) => None,
            Some(loss) => Some(format!("{side} lost {loss} events")),
            None => Some(format!("{side} loss_count is not canonical: {text:?}")),
        },
        Some(other) => Some(format!(
            "{side} loss_count is not canonical: {}",
            canon_string(other)
        )),
        None => Some(format!(
            "{side} loss_count missing (unknown loss, not zero)"
        )),
    }
}

/// Judge one attempt's exports: oracle integrity, quiet margins, per-side
/// oracle equality, then the cross-side stream diff. Returns the one-line
/// evidence summary.
fn judge_exports(texts: &BTreeMap<String, String>, inputs: &LiveInputs) -> Result<String, String> {
    let ledger: Json = parse_json(&texts["ledger.json"]).map_err(|e| format!("ledger: {e}"))?;
    let oracle: Json = parse_json(&texts["oracle.json"]).map_err(|e| format!("oracle: {e}"))?;
    if ledger.get("guest_release").and_then(Json::as_str) != Some(GUEST_RELEASE) {
        return Err(format!(
            "guest booted {:?}, want {GUEST_RELEASE:?}",
            ledger.get("guest_release").map(canon_string)
        ));
    }
    // The ledger records the guest BTF and tracepoint-format shas; the judge
    // pins them, not just the release: the probes decode against exactly
    // these bytes, so drift voids the judged streams.
    for (key, want) in [("btf_sha", GUEST_BTF_SHA), ("format_sha", GUEST_FORMAT_SHA)] {
        let seen = ledger
            .get(key)
            .and_then(Json::as_str)
            .ok_or_else(|| format!("ledger lacks {key}"))?;
        if seen != want {
            return Err(format!("guest {key} drift: want {want} got {seen}"));
        }
    }
    for side in ["mojo", "rust"] {
        let exit = u64_field(&ledger, &format!("{side}_exit"))?;
        if exit != 0 {
            return Err(format!(
                "{side} recorder exited {exit}: {}",
                texts[&format!("{side}.record.stderr")]
                    .chars()
                    .rev()
                    .take(1500)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>()
            ));
        }
    }
    let pings: u64 = WORKLOAD_PINGS.parse().expect("pings numeric");
    if u64_field(&ledger, "ping_transmitted")? != pings {
        return Err("workload short: ping_transmitted drift".to_string());
    }
    if u64_field(&ledger, "lost_markers")? != 0 {
        return Err("oracle unreliable: lost markers present".to_string());
    }
    let percpu = json_field(&ledger, "percpu")?;
    let Json::Obj(cpus) = percpu else {
        return Err("percpu is not an object".to_string());
    };
    for (cpu, stats) in cpus {
        for key in ["overrun", "commit overrun", "dropped events"] {
            let val = stats
                .get("values")
                .and_then(|v| v.get(key))
                .and_then(Json::as_u64)
                .ok_or_else(|| format!("percpu {cpu} lacks {key}"))?;
            if val != 0 {
                return Err(format!("ftrace loss on {cpu}: {key}={val}"));
            }
        }
    }
    // Guest-measured binary/object provenance must match the host-measured
    // inputs: the judged streams came from exactly these bytes.
    for (key, path) in [
        ("mojo_sha", &inputs.mojo_bin),
        ("rust_sha", &inputs.rust_bin),
        ("c_obj_sha", &inputs.c_obj),
        ("aya_obj_sha", &inputs.aya_obj),
        ("bridge_sha", &inputs.bridge),
    ] {
        let seen = ledger
            .get(key)
            .and_then(Json::as_str)
            .ok_or_else(|| format!("ledger lacks {key}"))?;
        let held = sha256_file(path)?;
        if seen != held {
            return Err(format!("{key} drift: guest {seen} vs host {held}"));
        }
    }
    let start = u64_field(&ledger, "workload_start_ns")?;
    let end = u64_field(&ledger, "workload_end_ns")?;
    if !(start < end) {
        return Err("empty workload window".to_string());
    }
    // Both recorders were ready before the workload started.
    for side in ["mojo", "rust"] {
        let ready = u64_field(&ledger, &format!("{side}_ready_ns"))?;
        if !(ready < start) {
            return Err(format!("{side} was not ready before the workload"));
        }
    }
    // Oracle: lossless, nonempty, uniformly FORCED (the boot pins
    // `swiotlb=force`); every hit inside the window.
    let Json::Arr(hits) = json_field(&oracle, "events")? else {
        return Err("oracle events are not an array".to_string());
    };
    if u64_field(&oracle, "lost_lines")? != 0 || u64_field(&oracle, "lost_events")? != 0 {
        return Err("oracle lost lines".to_string());
    }
    if hits.is_empty() {
        return Err("oracle saw no events".to_string());
    }
    let mut oracle_in: Vec<(u64, bool)> = Vec::new();
    for hit in hits {
        let ts = u64_field(hit, "ts_ns")?;
        let size = u64_field(hit, "size")?;
        let forced = json_field(hit, "forced")? == &Json::Bool(true);
        if !forced {
            return Err("NORMAL hit under swiotlb=force: workload shape drift".to_string());
        }
        if start <= ts && ts <= end {
            oracle_in.push((size, forced));
        } else {
            return Err(format!("oracle activity outside workload at {ts}"));
        }
    }
    oracle_in.sort();
    let oracle_bytes: u64 = oracle_in.iter().map(|(s, _)| s).sum();
    // Per side: zero loss, quiet margins, exact oracle equality. Side
    // divergences accumulate so one run reports closure AND streams.
    let mut divs: Vec<String> = Vec::new();
    let mut sides: BTreeMap<&str, StreamProfile> = BTreeMap::new();
    for side in ["mojo", "rust"] {
        let session: Json = parse_json(&texts[&format!("{side}.session.json")])
            .map_err(|e| format!("{side} session: {e}"))?;
        let detail = session
            .get("quality")
            .and_then(|q| q.get("detail"))
            .ok_or_else(|| format!("{side} session lacks quality.detail"))?;
        let status = detail
            .get("status")
            .and_then(Json::as_str)
            .ok_or_else(|| format!("{side} detail lacks status"))?;
        if status != "complete_for_scope" {
            divs.push(format!(
                "{side} detail status is {status:?} (reason: {})",
                detail.get("reason").and_then(Json::as_str).unwrap_or("?")
            ));
        }
        if let Some(div) = loss_div(side, detail) {
            divs.push(div);
        }
        let profile = profile_stream(&texts[&format!("{side}.events.ndjson")], Some((start, end)))
            .map_err(|e| format!("{side} events: {e}"))?;
        divs.extend(margin_divs(&profile, side));
        let events = profile
            .multisets
            .get("bounce_attempt")
            .cloned()
            .unwrap_or_default();
        if events.is_empty() {
            divs.push(format!("{side} persisted no attempts"));
        }
        // (size, forced) multiset equality against the oracle, mirroring
        // the attempt gate's exact cross-check.
        let mut persisted: Vec<(u64, bool)> = Vec::with_capacity(events.len());
        for line in &events {
            let val = parse_json(line).map_err(|e| format!("{side} reparse: {e}"))?;
            let data = json_field(&val, "data")?;
            let size = u64_field(data, "requested_bytes")?;
            let forced = json_field(data, "forced")? == &Json::Bool(true);
            persisted.push((size, forced));
        }
        persisted.sort();
        if persisted != oracle_in {
            divs.push(format!(
                "{side} vs oracle: {} persisted vs {} oracle hits",
                persisted.len(),
                oracle_in.len()
            ));
        }
        // Internal conservation: the attempts counter final must equal the
        // persisted bounce count on each side, under exactly one scope.
        if let Some(div) = conservation_div(&profile, side, events.len()) {
            divs.push(div);
        }
        sides.insert(side, profile);
    }
    // The cross-side diff: stream equivalence plus counter agreement.
    let report = diff_profiles(&sides["rust"], &sides["mojo"]);
    if !report.is_empty() {
        divs.push(render_report(&report, &sides["rust"], &sides["mojo"]));
    }
    if !divs.is_empty() {
        return Err(divs.join("\n"));
    }
    Ok(format!(
        "oracle={} bytes={oracle_bytes} kinds={:?} exact",
        oracle_in.len(),
        sides["rust"].counts.keys().collect::<Vec<_>>(),
    ))
}

#[allow(unreachable_code)]
#[test]
fn requal_dual_capture_7014() {
    if std::env::var(LIVE_VAR).as_deref() != Ok("1") {
        eprintln!("SKIP requal_dual_capture_7014: set MEMVEIL_REQUAL_LIVE=1 with the VM harness");
        return;
    }
    // Cutover: dual rust-vs-Mojo capture retired permanently (no Mojo
    // oracle binary exists anymore); single-sided Rust
    // requalification is future work. The offline export-comparison
    // tests below keep judging retained captures.
    eprintln!("SKIP requal_dual_capture_7014: dual rust-vs-Mojo capture retired at cutover");
    return;
    let inputs = resolve_live().unwrap_or_else(|e| panic!("requal preflight: {e}"));
    println!(
        "requal: vmlinuz {} pinned {}",
        GUEST_KERNEL, inputs.vmlinuz_sha
    );
    let keep = std::env::var(KEEP_VAR).as_deref() == Ok("1");
    let mut flakes: Vec<String> = Vec::new();
    for attempt in 1..=MAX_ATTEMPTS {
        match run_attempt(&inputs, attempt) {
            Attempt::Flake(why) => {
                println!("requal: attempt {attempt} flake: {why}");
                flakes.push(why);
            }
            Attempt::Fatal(why) => {
                panic!("requal: attempt {attempt} fatal: {why}");
            }
            Attempt::Exports(base) => {
                let texts = verify_exports(&base).unwrap_or_else(|e| {
                    panic!(
                        "requal: attempt {attempt}: {e} (kept at {})",
                        base.display()
                    )
                });
                match judge_exports(&texts, &inputs) {
                    Ok(summary) => {
                        println!("requal: attempt {attempt}: {summary}");
                        if !keep {
                            let _ = std::fs::remove_dir_all(&base);
                        } else {
                            println!("requal: kept at {}", base.display());
                        }
                        if !flakes.is_empty() {
                            println!("requal: {} earlier flake(s) retried", flakes.len());
                        }
                        return;
                    }
                    Err(divergence) => {
                        // Divergence fails closed: no retry, exports kept.
                        panic!(
                            "requal: attempt {attempt} DIVERGENCE (kept at {}):\n{divergence}",
                            base.display()
                        );
                    }
                }
            }
        }
    }
    panic!("requal: {MAX_ATTEMPTS} flakes, no judged attempt: {flakes:?}");
}

// ---------------------------------------------------------------------------
// Guest driver (runs as root inside the cell; written to a temp file).
// ---------------------------------------------------------------------------

/// Dual-capture guest flow: stimulate over pcnet32, run the Mojo and Rust
/// recorders simultaneously under one ftrace oracle, export both captures
/// plus the allowlisted oracle. Every refusal aborts FAIL (exit 1), never
/// skip. Mirrors the proven attempt-gate guest logic (streamer, oracle
/// shutdown, quiet-guest setup); the dual-recorder orchestration is new.
const GUEST_PY: &str = r##"#!/usr/bin/env python3
import ctypes
import ctypes.util
import hashlib
import json
import os
import re
import select
import shutil
import subprocess
import sys
import threading
import time

TR = '/sys/kernel/tracing'
EVT = TR + '/events/swiotlb/swiotlb_bounced'
FMT_PATH = EVT + '/format'

FTRACE_RE = re.compile(
    r'^\s*\S+\s+\[(\d+)\]\s+\S+\s+(\d+)\.(\d+):\s+swiotlb_bounced:\s+(.*)$'
)
SIZE_RE = re.compile(r'\bsize=(\d+)')
FLAG_RE = re.compile(r'\b(FORCE|NORMAL)\s*$')


def fail(msg):
    print('requal-guest: FAIL: ' + msg, file=sys.stderr, flush=True)
    sys.exit(1)


def say(msg):
    print('requal-guest: ' + msg, flush=True)


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


class PipeStreamer:
    def __init__(self, pipe, out_path):
        self._pipe = pipe
        self._out_path = out_path
        self._stop = threading.Event()
        self._error = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self, timeout=15):
        self._stop.set()
        self._thread.join(timeout)
        if self._thread.is_alive():
            fail('pipe streamer did not stop')
        if self._error is not None:
            fail('pipe streamer failed: %r' % (self._error,))

    def _run(self):
        try:
            infd = os.open(self._pipe, os.O_RDONLY)
            try:
                outfd = os.open(
                    self._out_path,
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
                try:
                    while not self._stop.is_set():
                        ready, _, _ = select.select([infd], [], [], 0.5)
                        if not ready:
                            continue
                        chunk = os.read(infd, 65536)
                        if not chunk:
                            break
                        view = memoryview(chunk)
                        while view:
                            done = os.write(outfd, view)
                            view = view[done:]
                finally:
                    os.close(outfd)
            finally:
                os.close(infd)
        except Exception as exc:
            self._error = exc


def sha_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()


def read_bytes(path):
    with open(path, 'rb') as fh:
        return fh.read()


def preflight_fs(work):
    trial = os.path.join(work, 'preflight')
    os.makedirs(trial, exist_ok=True)
    f1 = os.path.join(trial, 'a.tmp')
    f2 = os.path.join(trial, 'b.tmp')
    fd = os.open(f1, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        os.write(fd, b'0123456789abcdef')
        os.pwrite(fd, b'XY', 4)
        os.fsync(fd)
    finally:
        os.close(fd)
    libc_name = ctypes.util.find_library('c')
    if not libc_name:
        fail('no libc for renameat2 preflight')
    libc = ctypes.CDLL(libc_name, use_errno=True)
    if libc.renameat2(-100, f1.encode(), -100, f2.encode(), 1) != 0:
        fail('renameat2 noreplace failed: errno %d' % ctypes.get_errno())
    st = sh(['stat', '-f', trial])
    fstype = 'unknown'
    m = re.search(r'Type:\s*(\S+)', st.stdout)
    if m:
        fstype = m.group(1)
    shutil.rmtree(trial, ignore_errors=True)
    return fstype


def find_pcnet():
    for iface in sorted(os.listdir('/sys/class/net')):
        drv = os.path.join('/sys/class/net', iface, 'device', 'driver')
        try:
            if os.readlink(drv).endswith('pcnet32'):
                mb = read_bytes(os.path.join(
                    '/sys/class/net', iface, 'device', 'dma_mask_bits'
                )).decode().strip()
                return iface, mb
        except OSError:
            continue
    return None, None


def configure_net(iface):
    r = sh(['sysctl', '-w', 'net.ipv6.conf.%s.disable_ipv6=1' % iface])
    if r.returncode != 0:
        fail('ipv6 disable failed: %s' % r.stderr.strip())
    r = sh(['ip', 'link', 'set', iface, 'up'])
    if r.returncode != 0:
        fail('ip link up failed: %s' % r.stderr.strip())
    r = sh(['ip', 'addr', 'add', '10.0.3.15/24', 'dev', iface])
    if r.returncode != 0 and 'exists' not in r.stderr:
        fail('ip addr failed: %s' % r.stderr.strip())
    r = sh(['ping', '-c', '1', '-W', '3', '10.0.3.2'])
    if r.returncode != 0:
        fail('gateway ping failed: %s %s' % (r.stdout.strip(), r.stderr.strip()))


def hiwater():
    try:
        return read_bytes(
            '/sys/kernel/debug/swiotlb/io_tlb_used_hiwater'
        ).decode().strip()
    except OSError:
        return None


def percpu_stats():
    out = {}
    base = TR + '/per_cpu'
    try:
        cpus = sorted(os.listdir(base))
    except OSError:
        fail('no per_cpu trace stats')
    for cpu in cpus:
        try:
            raw = read_bytes(os.path.join(base, cpu, 'stats')).decode()
        except OSError:
            fail('unreadable stats for ' + cpu)
        vals = {}
        for key in ('overrun', 'commit overrun', 'dropped events'):
            m = re.search(r'^%s:\s*(\d+)' % re.escape(key), raw, re.M)
            vals[key] = int(m.group(1)) if m else None
        out[cpu] = {'values': vals}
    return out


def parse_ftrace(blob):
    if blob and not blob.endswith(b'\n'):
        fail('truncated ftrace final line')
    events = []
    headers = blanks = lost = lost_events = 0
    for raw in blob.splitlines():
        line = raw.decode('utf-8', 'strict')
        if not line.strip():
            blanks += 1
        elif line.lstrip().startswith('#'):
            headers += 1
        elif re.fullmatch(r'\s*CPU:\d+ \[LOST \d+ EVENTS\]\s*', line):
            lost += 1
            lost_events += int(re.search(r'\[LOST (\d+) EVENTS\]', line).group(1))
        else:
            m = FTRACE_RE.fullmatch(line)
            if not m:
                fail('malformed/unexpected ftrace line')
            sm = SIZE_RE.search(m.group(4))
            fm = FLAG_RE.search(m.group(4))
            if not sm or not fm or len(re.findall(r'\bsize=', m.group(4))) != 1:
                fail('malformed ftrace payload')
            if len(m.group(3)) != 6:
                fail('unexpected ftrace timestamp precision')
            events.append(dict(ts_ns=int(m.group(2)) * 1000000000 + int(m.group(3)) * 1000,
                               size=int(sm.group(1)), forced=fm.group(1) == 'FORCE'))
    return dict(schema='memveil-vm-oracle/2', lost_lines=lost,
                lost_events=lost_events, pipe_bytes=len(blob),
                pipe_lines=blob.count(b'\n'), header_lines=headers,
                blank_lines=blanks, events=events)


def wait_ready(proc, tag, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], 1.0)
        if ready:
            line = proc.stdout.readline()
            if line and 'ready session=' in line:
                return line.strip()
        if proc.poll() is not None:
            return None
    return None


def start_recorder(work, tag, binary, obj, bridge, profiles, duration):
    cap = os.path.join(work, 'cap-' + tag)
    err_path = os.path.join(work, tag + '.record.stderr')
    proc = subprocess.Popen(
        [binary, 'record',
         '--duration', duration,
         '--output', cap,
         '--object', obj,
         '--bridge', bridge,
         '--profiles-dir', profiles],
        stdout=subprocess.PIPE,
        stderr=open(err_path, 'wb'),
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    ready = wait_ready(proc, tag)
    if ready is None:
        try:
            proc.kill()
        except OSError:
            pass
        proc.wait()
        try:
            with open(err_path, 'rb') as fh:
                tail = fh.read()[-1500:].decode('utf-8', 'replace')
        except OSError:
            tail = '(stderr unreadable)'
        fail('%s never reached readiness: %s' % (tag, tail.strip()))
    say('%s ready' % tag)
    return proc, cap, ready


def main():
    # argv[0] is this script: the guest runner swallows the
    # leading 'python3' word of --exec (same as the committed
    # gate flows).
    if len(sys.argv) != 11:
        fail('usage: requal_guest.py WORK EXPORT MOJO RUST C_OBJ AYA_OBJ '
             'BRIDGE PROFILES DURATION PINGS')
    work, export, mojo, rust, c_obj, aya_obj, bridge, profiles, dur, pings = sys.argv[1:11]
    if os.geteuid() != 0:
        fail('guest flow requires root')
    if not pings.isdigit() or int(pings) < 1:
        fail('bad PINGS %s' % pings)
    os.makedirs(work, exist_ok=True)
    os.makedirs(export, exist_ok=True)
    ledger = {'mode': 'dual'}
    ledger['guest_release'] = os.uname().release
    ledger['fs_type'] = preflight_fs(work)
    try:
        ledger['btf_sha'] = sha_file('/sys/kernel/btf/vmlinux')
    except OSError:
        fail('guest BTF unreadable')
    try:
        ledger['format_sha'] = sha_file(FMT_PATH)
    except OSError:
        fail('swiotlb tracepoint format unreadable')
    try:
        ledger['config_sha'] = hashlib.sha256(read_bytes('/proc/config.gz')).hexdigest()
        ledger['config_src'] = 'gz'
    except OSError:
        ledger['config_sha'] = None
        ledger['config_src'] = None
    ledger['mojo_sha'] = sha_file(mojo)
    ledger['rust_sha'] = sha_file(rust)
    ledger['c_obj_sha'] = sha_file(c_obj)
    ledger['aya_obj_sha'] = sha_file(aya_obj)
    ledger['bridge_sha'] = sha_file(bridge)
    ledger['hiwater_before'] = hiwater()
    iface, mb = find_pcnet()
    if not iface:
        fail('no pcnet32 NIC found')
    if mb != '32':
        fail('pcnet dma_mask_bits is %s, want 32' % mb)
    ledger['iface'] = iface
    ledger['dma_mask_bits'] = int(mb)
    configure_net(iface)
    ledger['link_ok'] = True
    with open(TR + '/trace_clock', 'w') as fh:
        fh.write('mono')
    with open(TR + '/trace_clock') as fh:
        ledger['trace_clock'] = fh.read().strip()
    if '[mono]' not in ledger['trace_clock']:
        fail('trace clock is %s' % ledger['trace_clock'])
    with open(EVT + '/enable', 'w') as fh:
        fh.write('1')
    pipe_path = os.path.join(work, 'pipe.ram')
    streamer = PipeStreamer(TR + '/trace_pipe', pipe_path)
    streamer.start()
    procs = {}
    caps = {}
    for tag, binary, obj in (('mojo', mojo, c_obj), ('rust', rust, aya_obj)):
        proc, cap, ready = start_recorder(
            work, tag, binary, obj, bridge, profiles, dur)
        procs[tag] = proc
        caps[tag] = cap
        ledger[tag + '_ready'] = ready
        ledger[tag + '_ready_ns'] = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        with open(os.path.join(work, tag + '.record.stdout'), 'w') as fh:
            fh.write(ready + '\n')
    time.sleep(2)
    start_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    ping = sh(['timeout', '60', 'ping', '-A', '-c', pings, '-q', '10.0.3.2'])
    if ping.returncode != 0:
        fail('ping workload failed exit %d' % ping.returncode)
    end_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    ledger['workload_start_ns'] = start_ns
    ledger['workload_end_ns'] = end_ns
    with open(os.path.join(work, 'ping.txt'), 'w') as fh:
        fh.write(ping.stdout)
        fh.write(ping.stderr)
    m = re.search(r'(\d+) packets transmitted', ping.stdout)
    ledger['ping_transmitted'] = int(m.group(1)) if m else None
    m2 = re.search(r'(\d+) received', ping.stdout)
    ledger['ping_received'] = int(m2.group(1)) if m2 else None
    time.sleep(2)
    for tag, proc in procs.items():
        try:
            rc = proc.wait(timeout=300)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            fail('%s record did not exit' % tag)
        ledger[tag + '_exit'] = rc
        try:
            rest = proc.stdout.read() or ''
        except OSError:
            rest = ''
        with open(os.path.join(work, tag + '.record.stdout'), 'a') as fh:
            fh.write(rest)
    with open(TR + '/tracing_on', 'w') as fh:
        fh.write('0')
    streamer.stop()
    drained = 0
    end_drain = time.monotonic() + 10
    pfd = os.open(TR + '/trace_pipe', os.O_RDONLY | os.O_NONBLOCK)
    try:
        with open(pipe_path, 'ab') as fh:
            while time.monotonic() < end_drain:
                try:
                    chunk = os.read(pfd, 1048576)
                except OSError:
                    break
                if not chunk:
                    break
                drained += len(chunk)
                fh.write(chunk)
    finally:
        os.close(pfd)
    ledger['drained_bytes'] = drained
    with open(EVT + '/enable', 'w') as fh:
        fh.write('0')
    ledger['percpu'] = percpu_stats()
    ledger['hiwater_after'] = hiwater()
    with open(pipe_path, 'rb') as fh:
        blob = fh.read()
    ledger['pipe_bytes'] = len(blob)
    ledger['pipe_lines'] = blob.count(b'\n')
    ledger['lost_markers'] = len(re.findall(rb'lost', blob, flags=re.IGNORECASE))
    oracle = parse_ftrace(blob)
    with open(os.path.join(work, 'oracle.json'), 'w') as fh:
        json.dump(oracle, fh, indent=1, sort_keys=True)
        fh.write('\n')
    with open(os.path.join(work, 'ledger.json'), 'w') as fh:
        json.dump(ledger, fh, indent=1, sort_keys=True)
        fh.write('\n')
    for name, src in (
        ('ledger.json', os.path.join(work, 'ledger.json')),
        ('oracle.json', os.path.join(work, 'oracle.json')),
        ('ping.txt', os.path.join(work, 'ping.txt')),
    ):
        dst = os.path.join(export, name)
        shutil.copyfile(src, dst)
        with open(dst + '.sha256', 'w') as fh:
            fh.write('%s  %s\n' % (sha_file(dst), name))
    for tag in ('mojo', 'rust'):
        pairs = (
            ('session.json', os.path.join(caps[tag], 'session.json')),
            ('events.ndjson', os.path.join(caps[tag], 'events.ndjson')),
            ('record.stdout', os.path.join(work, tag + '.record.stdout')),
            ('record.stderr', os.path.join(work, tag + '.record.stderr')),
        )
        for name, src in pairs:
            if not os.path.isfile(src):
                fail('missing %s export %s' % (tag, name))
            dst = os.path.join(export, '%s.%s' % (tag, name))
            shutil.copyfile(src, dst)
            with open(dst + '.sha256', 'w') as fh:
                fh.write('%s  %s.%s\n' % (sha_file(dst), tag, name))
    say('exported mojo_exit=%d rust_exit=%d' % (ledger['mojo_exit'], ledger['rust_exit']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
"##;
