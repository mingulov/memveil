// SPDX-License-Identifier: GPL-3.0-or-later
//! Effective Cargo flag selection for builds that append path remaps.
//!
//! Every funnel that remaps build-machine paths out of its output (the
//! release-build test helpers and the BPF child build) starts from the flag
//! set Cargo itself would use: the encoded spelling when set, else `RUSTFLAGS`
//! when set, else the config layer carried forward. Presence selects the
//! channel, not non-emptiness: a set-but-empty channel still shadows
//! everything below it. Merging channels would forward conflicting flags
//! Cargo would never pass together, and exporting remaps alone would shadow
//! config-sourced flags, so the remap pair extends the effective set exactly
//! once and leaves through the encoded channel alone.
//!
//! Anything this reader cannot reproduce exactly refuses with a remedy (pass
//! the flags through `RUSTFLAGS`) instead of silently shadowing: config
//! `include` entries, any `target.*.rustflags` in files or
//! `CARGO_TARGET_*_RUSTFLAGS` in the environment, unreadable or invalid
//! config files, and mistyped values.
//!
//! TOML subset: table headers and dotted keys with bare, basic-string, and
//! literal-string segments; string, array (including multi-line), inline
//! table, and scalar values; `#` comments; CRLF line endings; nesting to 64
//! deep. Triple-quoted strings refuse, so no multi-line string can form and
//! every value stays on one logical line.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// Process environment as UTF-8 pairs for flag selection: the live
/// process environment through `process_env_from`.
pub fn process_env() -> Result<BTreeMap<String, String>, String> {
    process_env_from(std::env::vars_os())
}

/// Process raw environment pairs as UTF-8 for flag selection.
///
/// Entries that are not valid UTF-8 are dropped, except a non-UTF-8 name
/// matching the target-flags pattern byte-for-byte, which refuses like its
/// readable counterpart: presence alone refuses, so an unreadable match
/// must too. A set-but-unreadable value refuses as well when the name feeds
/// selection (the flag channels, the home lookups, or the target pattern):
/// treating it as unset would silently fall through to a lower layer.
fn process_env_from<I>(pairs: I) -> Result<BTreeMap<String, String>, String>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut env = BTreeMap::new();
    for (key, value) in pairs {
        let name = match key.into_string() {
            Ok(name) => name,
            Err(raw) => {
                if is_target_rustflags(raw.as_encoded_bytes()) {
                    return Err(format!(
                        "{} sets target rustflags: pass its flags through RUSTFLAGS instead",
                        raw.to_string_lossy()
                    ));
                }
                continue;
            }
        };
        let Ok(value) = value.into_string() else {
            if is_target_rustflags(name.as_bytes()) {
                return Err(format!(
                    "{name} sets target rustflags: pass its flags through RUSTFLAGS instead"
                ));
            }
            if is_significant_env(&name) {
                return Err(format!(
                    "{name} value is not valid UTF-8: unset it or set UTF-8 text instead"
                ));
            }
            continue;
        };
        env.insert(name, value);
    }
    Ok(env)
}

/// Whether `name` feeds flag selection: its value is read, so a
/// set-but-unreadable spelling refuses rather than reading as unset.
fn is_significant_env(name: &str) -> bool {
    matches!(
        name,
        "RUSTFLAGS" | "CARGO_ENCODED_RUSTFLAGS" | "CARGO_BUILD_RUSTFLAGS" | "CARGO_HOME" | "HOME"
    )
}

/// Whether `name` selects target rustflags: `CARGO_TARGET_*_RUSTFLAGS` with a
/// non-empty middle, exactly the spelling that shadows `build.rustflags`.
fn is_target_rustflags(name: &[u8]) -> bool {
    const PREFIX: &[u8] = b"CARGO_TARGET_";
    const SUFFIX: &[u8] = b"_RUSTFLAGS";
    name.len() > PREFIX.len() + SUFFIX.len() && name.starts_with(PREFIX) && name.ends_with(SUFFIX)
}

/// Effective flag set plus every config path probed along the way.
#[derive(Debug)]
pub struct Effective {
    /// The flag set Cargo itself would use for this environment.
    pub flags: Vec<String>,
    /// Every `config`/`config.toml` path probed, read or not, so a build
    /// script can watch them for rebuilds.
    pub config_files: Vec<PathBuf>,
}

/// The flag set Cargo itself would use: the encoded spelling when set, else
/// `RUSTFLAGS` when set (a set-but-empty channel still shadows the rest),
/// else the config layer carried forward.
pub fn effective_rustflags(
    env: &BTreeMap<String, String>,
    build_dir: &Path,
) -> Result<Effective, String> {
    if let Some(encoded) = env.get("CARGO_ENCODED_RUSTFLAGS") {
        // Cargo passes empty segments through verbatim (rustc errors on
        // them); only a wholly empty channel means no flags.
        let flags = if encoded.is_empty() {
            Vec::new()
        } else {
            encoded.split('\u{1f}').map(str::to_string).collect()
        };
        return Ok(Effective {
            flags,
            config_files: Vec::new(),
        });
    }
    if let Some(rustflags) = env.get("RUSTFLAGS") {
        return Ok(Effective {
            flags: split_rustflags(rustflags),
            config_files: Vec::new(),
        });
    }
    let (flags, config_files) = config_layer_rustflags(build_dir, env)?;
    Ok(Effective {
        flags,
        config_files,
    })
}

/// Append the home/checkout remap pair: home first, checkout root last, so
/// checkout paths land under /build-root. A missing or empty home
/// contributes no remap.
pub fn append_remaps(flags: &mut Vec<String>, home: &str, root: &Path) {
    if !home.is_empty() {
        flags.push(format!("--remap-path-prefix={home}=/build-prefix"));
    }
    flags.push(format!(
        "--remap-path-prefix={}=/build-root",
        abspath(root).display()
    ));
}

/// Extend `env` with the remap pair, exporting through the encoded channel
/// alone: the effective set plus the pair lands there, and `RUSTFLAGS` is
/// dropped so the export shadows nothing and duplicates nothing.
pub fn remap_build_paths(env: &mut BTreeMap<String, String>, dir: &Path) -> Result<(), String> {
    let effective = effective_rustflags(env, dir)?;
    let mut flags = effective.flags;
    let home = env.get("HOME").map(String::as_str).unwrap_or("");
    append_remaps(&mut flags, home, dir);
    env.insert("CARGO_ENCODED_RUSTFLAGS".to_string(), flags.join("\u{1f}"));
    env.remove("RUSTFLAGS");
    Ok(())
}

/// Absolute form of `path`, resolving a relative path against the working
/// directory. Callers pass absolute build roots; a relative path with an
/// unreadable working directory cannot remap and panics.
fn abspath(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .expect("working directory is readable")
        .join(path)
}

/// Split a flag string the way Cargo splits `RUSTFLAGS`.
///
/// Words break on the space character alone; every other byte stays
/// literal, so quotes and backslashes reach the compiler untouched.
/// Empty words never form: leading, trailing, and repeated spaces
/// vanish. Splitting never fails.
fn split_rustflags(text: &str) -> Vec<String> {
    text.split(' ')
        .filter(|word| !word.is_empty())
        .map(str::to_string)
        .collect()
}

/// Config-layer flags for a build with no channel set.
///
/// Only consulted when neither `CARGO_ENCODED_RUSTFLAGS` nor `RUSTFLAGS` is
/// set: Cargo checks the encoded spelling, then `RUSTFLAGS`, then the config
/// layer. Merges the home config first, then each ancestor config down to
/// the build directory: a nearer string replaces, arrays join, and a
/// string meeting an array across files refuses like Cargo does. The
/// dotted environment spelling appends after the merged file flags, and
/// an empty one leaves them standing. A home directory that overlaps an
/// ancestor loads once at the ancestor; at one directory the extensionless
/// config wins over config.toml wholesale. Fails closed rather than
/// shadowing flags it cannot see. Returns the probed config paths
/// alongside, read or not.
fn config_layer_rustflags(
    build_dir: &Path,
    env: &BTreeMap<String, String>,
) -> Result<(Vec<String>, Vec<PathBuf>), String> {
    for name in env.keys() {
        if is_target_rustflags(name.as_bytes()) {
            return Err(format!(
                "{name} sets target rustflags: pass its flags through RUSTFLAGS instead"
            ));
        }
    }
    let home = match env.get("CARGO_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => match env.get("HOME") {
            Some(parent) if !parent.is_empty() => Path::new(parent).join(".cargo"),
            _ => PathBuf::new(),
        },
    };
    let build_dir = abspath(build_dir);
    let home = if home.as_os_str().is_empty() || home.is_absolute() {
        home
    } else {
        build_dir.join(&home)
    };
    let mut chain = Vec::new();
    let mut cursor = Some(build_dir);
    while let Some(dir) = cursor {
        chain.push(dir.clone());
        cursor = dir.parent().map(Path::to_path_buf);
    }
    let mut flag_dirs: Vec<PathBuf> = chain
        .iter()
        .rev()
        .map(|ancestor| ancestor.join(".cargo"))
        .collect();
    if !home.as_os_str().is_empty() {
        let key = dir_key(&home);
        if !flag_dirs.iter().any(|dir| dir_key(dir) == key) {
            flag_dirs.insert(0, home);
        }
    }
    let mut merged: Option<FlagsValue> = None;
    let mut probed = Vec::new();
    for flag_dir in &flag_dirs {
        let plain = flag_dir.join("config");
        let dotted = flag_dir.join("config.toml");
        probed.push(plain.clone());
        probed.push(dotted.clone());
        // At one directory the extensionless config wins wholesale:
        // when it exists the dotted leaf stays unread, even when the
        // winner carries no flags. Existence follows symlinks, so a
        // broken link counts as absent.
        let path = if plain.exists() {
            Some(plain)
        } else if dotted.exists() {
            Some(dotted)
        } else {
            None
        };
        let Some(path) = path else {
            continue;
        };
        let Some(value) = config_file_rustflags(&path)? else {
            continue;
        };
        match (merged, value) {
            (None, value) => merged = Some(value),
            (Some(FlagsValue::Str(_)), FlagsValue::Str(text)) => {
                merged = Some(FlagsValue::Str(text));
            }
            (Some(FlagsValue::Arr(mut prior)), FlagsValue::Arr(mut more)) => {
                prior.append(&mut more);
                merged = Some(FlagsValue::Arr(prior));
            }
            _ => {
                return Err(format!(
                    "cargo config {} mixes string and array build.rustflags across files: \
                     pass its flags through RUSTFLAGS instead",
                    path.display()
                ));
            }
        }
    }
    if let Some(dotted) = env.get("CARGO_BUILD_RUSTFLAGS") {
        let extra: Vec<String> = dotted.split_whitespace().map(str::to_string).collect();
        if !extra.is_empty() {
            match merged {
                None => merged = Some(FlagsValue::Arr(extra)),
                Some(FlagsValue::Str(text)) => {
                    let mut flags: Vec<String> =
                        text.split_whitespace().map(str::to_string).collect();
                    flags.extend(extra);
                    merged = Some(FlagsValue::Arr(flags));
                }
                Some(FlagsValue::Arr(mut flags)) => {
                    flags.extend(extra);
                    merged = Some(FlagsValue::Arr(flags));
                }
            }
        }
    }
    let flags = match merged {
        None => Vec::new(),
        Some(FlagsValue::Str(text)) => text.split_whitespace().map(str::to_string).collect(),
        Some(FlagsValue::Arr(flags)) => flags,
    };
    Ok((flags, probed))
}

/// Canonical identity of a config directory: resolved symlinks when
/// the directory exists, lexical cleanup otherwise, so overlapping
/// spellings of one directory compare equal.
fn dir_key(dir: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(dir) {
        return canonical;
    }
    let mut out = PathBuf::new();
    for comp in dir.components() {
        match comp {
            Component::Prefix(part) => out.push(part.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() || out.as_os_str().is_empty() {
                    out = PathBuf::from("/");
                }
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

/// A `build.rustflags` value as read: merging across files needs the
/// type, since a nearer string replaces while arrays join.
enum FlagsValue {
    Str(String),
    Arr(Vec<String>),
}

/// `build.rustflags` from one Cargo config file, else None.
///
/// Returns the raw string or array for the merge. Fails closed on
/// anything this reader cannot reproduce exactly: an include entry,
/// target-specific rustflags (those shadow `build.rustflags`), or a
/// mistyped value.
fn config_file_rustflags(path: &Path) -> Result<Option<FlagsValue>, String> {
    let bytes = std::fs::read(path)
        .map_err(|err| format!("cannot read cargo config {}: {err}", path.display()))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        format!(
            "cannot parse cargo config {}: not valid UTF-8",
            path.display()
        )
    })?;
    let doc = parse_config(text, path)?;
    for key in doc.values.keys().chain(doc.tables.iter()) {
        if key.first().is_some_and(|head| head == "include") {
            return Err(format!(
                "cargo config {} uses include: pass its flags through RUSTFLAGS instead",
                path.display()
            ));
        }
    }
    let target_key = vec!["target".to_string()];
    if let Some(value) = doc.values.get(&target_key) {
        match value {
            Value::Inline(items) => check_target_inline(items, path)?,
            _ => {
                return Err(format!(
                    "cargo config {} has a non-table target",
                    path.display()
                ));
            }
        }
    }
    for key in doc.values.keys().chain(doc.tables.iter()) {
        if key.len() >= 3 && key[0] == "target" && key[2] == "rustflags" {
            return Err(target_refused(path));
        }
    }
    for (key, value) in &doc.values {
        if key.len() == 2
            && key[0] == "target"
            && let Value::Inline(items) = value
        {
            for item in items.keys() {
                if item.first().is_some_and(|head| head == "rustflags") {
                    return Err(target_refused(path));
                }
            }
        }
    }
    let build_key = vec!["build".to_string()];
    if let Some(value) = doc.values.get(&build_key) {
        match value {
            Value::Inline(items) => {
                for (key, item) in items {
                    if key.first().is_some_and(|head| head == "rustflags") {
                        if key.len() > 1 {
                            return Err(mistype(path));
                        }
                        return flags_value(item, path).map(Some);
                    }
                }
                return Ok(None);
            }
            _ => {
                return Err(format!(
                    "cargo config {} has a non-table build",
                    path.display()
                ));
            }
        }
    }
    for key in doc.tables.iter() {
        if key.len() >= 2 && key[0] == "build" && key[1] == "rustflags" {
            return Err(mistype(path));
        }
    }
    for (key, value) in &doc.values {
        if key.len() >= 2 && key[0] == "build" && key[1] == "rustflags" {
            if key.len() > 2 {
                return Err(mistype(path));
            }
            return flags_value(value, path).map(Some);
        }
    }
    Ok(None)
}

/// Refusal for proven target rustflags: those shadow `build.rustflags`, so
/// reading on would silently drop them.
fn target_refused(path: &Path) -> String {
    format!(
        "cargo config {} sets target rustflags: pass its flags through RUSTFLAGS instead",
        path.display()
    )
}

/// Refusal for a `target = {...}` line whose direct children hide rustflags.
///
/// Each one-level entry is a direct child: a nested table carrying
/// `rustflags` shadows `build.rustflags` exactly like a `[target.*]`
/// section, and a dotted `x.rustflags` entry builds the same shape.
/// Anything else is not a table carrying rustflags and stays ignored.
fn check_target_inline(items: &BTreeMap<Vec<String>, Value>, path: &Path) -> Result<(), String> {
    for (key, value) in items {
        if key.len() > 1 && key[1] == "rustflags" {
            return Err(target_refused(path));
        }
        if key.len() == 1
            && let Value::Inline(nested) = value
        {
            for inner in nested.keys() {
                if inner.first().is_some_and(|head| head == "rustflags") {
                    return Err(target_refused(path));
                }
            }
        }
    }
    Ok(())
}

/// Refusal for a mistyped `build.rustflags`: present but neither a string
/// nor an array of strings.
fn mistype(path: &Path) -> String {
    format!(
        "cargo config {} has a non-string build.rustflags",
        path.display()
    )
}

/// A `rustflags` value as read: strings stay whole for the merge,
/// arrays pass through verbatim, anything else refuses.
fn flags_value(value: &Value, path: &Path) -> Result<FlagsValue, String> {
    match value {
        Value::Str(text) => Ok(FlagsValue::Str(text.clone())),
        Value::Arr(items) => {
            let mut flags = Vec::new();
            for item in items {
                match item {
                    Value::Str(flag) => flags.push(flag.clone()),
                    _ => return Err(mistype(path)),
                }
            }
            Ok(FlagsValue::Arr(flags))
        }
        _ => Err(mistype(path)),
    }
}

/// A config value: only strings and string arrays reach the flag reader;
/// inline tables scan one level for rustflags at the build/target keys and
/// every other scalar stays opaque and ignored.
#[derive(Clone, PartialEq)]
enum Value {
    Str(String),
    Arr(Vec<Value>),
    Inline(BTreeMap<Vec<String>, Value>),
    Other,
}

/// A parsed config file: header paths plus dotted key paths to values.
struct Doc {
    tables: BTreeSet<Vec<String>>,
    values: BTreeMap<Vec<String>, Value>,
}

/// Refusal for text outside the readable subset: the file may be valid
/// TOML Cargo would accept, but this reader cannot reproduce it exactly.
fn parse_err(path: &Path, reason: &str) -> String {
    format!("cannot parse cargo config {}: {reason}", path.display())
}

/// Whether `ch` is forbidden outside strings: TOML allows only tab for
/// horizontal whitespace, so every other control refuses.
fn is_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{0}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{d}'..='\u{1f}' | '\u{7f}'
    )
}

/// Parse a config file into header and value paths.
///
/// Duplicate tables, duplicate keys, and key/table shape conflicts refuse
/// like the invalid TOML they are; anything else outside the subset refuses
/// rather than guessing.
fn parse_config(text: &str, path: &Path) -> Result<Doc, String> {
    let mut doc = Doc {
        tables: BTreeSet::new(),
        values: BTreeMap::new(),
    };
    let mut current: Vec<String> = Vec::new();
    for logical in logical_lines(text, path)? {
        let line = strip_comment(&logical).trim_matches(|ch| ch == ' ' || ch == '\t');
        if line.is_empty() {
            continue;
        }
        if let Some(after) = line.strip_prefix('[') {
            let header = parse_header(after, path)?;
            if !doc.tables.insert(header.clone()) {
                return Err(parse_err(path, "duplicate table"));
            }
            for len in 1..=header.len() {
                if doc.values.contains_key(&header[..len]) {
                    return Err(parse_err(path, "table redefines a value"));
                }
            }
            for existing in doc.values.keys() {
                if existing.len() > header.len() && existing[..header.len()] == header[..] {
                    return Err(parse_err(path, "table redefines a dotted key"));
                }
            }
            current = header;
            continue;
        }
        let (key, value) = parse_key_value(line, path)?;
        let mut full = current.clone();
        full.extend(key);
        insert_dotted(&mut doc.values, full.clone(), value, path)?;
        if doc.tables.contains(&full) {
            return Err(parse_err(path, "value redefines a table"));
        }
        for existing in doc.tables.iter() {
            if existing.len() > full.len() && existing[..full.len()] == full[..] {
                return Err(parse_err(path, "value redefines a table"));
            }
        }
    }
    Ok(doc)
}

/// Insert a dotted key, refusing duplicates and value/table shape conflicts
/// the way invalid TOML refuses. Extending a header-made table stays legal.
fn insert_dotted(
    map: &mut BTreeMap<Vec<String>, Value>,
    key: Vec<String>,
    value: Value,
    path: &Path,
) -> Result<(), String> {
    if map.contains_key(&key) {
        return Err(parse_err(path, "duplicate key"));
    }
    for len in 1..key.len() {
        if map.contains_key(&key[..len]) {
            return Err(parse_err(path, "key extends a value"));
        }
    }
    for existing in map.keys() {
        if existing.len() > key.len() && existing[..key.len()] == key[..] {
            return Err(parse_err(path, "key collapses a table"));
        }
    }
    map.insert(key, value);
    Ok(())
}

/// Physical lines joined into logical lines: each line loses its `#`
/// comment first (quote-aware), then an unclosed `[` continues on the next
/// line so multi-line arrays parse; braces must close on their own line
/// since inline tables stay single-line. Comment text never joins lines or
/// unbalances brackets, exactly as the TOML reader treats it.
fn logical_lines(text: &str, path: &Path) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.chars().any(is_control) {
            return Err(parse_err(path, "invalid control character"));
        }
        let line = strip_comment(line);
        if !buf.is_empty() {
            buf.push('\n');
        }
        buf.push_str(line);
        let (brackets, braces) = scan_brackets(&buf);
        if braces != 0 {
            return Err(parse_err(path, "table braces must close on their line"));
        }
        if brackets < 0 {
            return Err(parse_err(path, "unbalanced bracket"));
        }
        if brackets == 0 {
            out.push(std::mem::take(&mut buf));
        }
    }
    if !buf.is_empty() {
        return Err(parse_err(path, "unclosed array"));
    }
    Ok(out)
}

/// Bracket and brace depth outside strings; an unterminated quote simply
/// hides the rest of the line, and the value parser refuses it later.
fn scan_brackets(text: &str) -> (i32, i32) {
    let mut brackets = 0;
    let mut braces = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars() {
        if let Some(mark) = quote {
            if escaped {
                escaped = false;
            } else if mark == '"' && ch == '\\' {
                escaped = true;
            } else if ch == mark {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '[' => brackets += 1,
            ']' => brackets -= 1,
            '{' => braces += 1,
            '}' => braces -= 1,
            _ => {}
        }
    }
    (brackets, braces)
}

/// Cut a `#` comment outside strings; an unterminated quote hides the rest
/// of the line, and the value parser refuses it later.
fn strip_comment(line: &str) -> &str {
    let mut basic = false;
    let mut literal = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if basic {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                basic = false;
            }
            continue;
        }
        if literal {
            if ch == '\'' {
                literal = false;
            }
            continue;
        }
        match ch {
            '"' => basic = true,
            '\'' => literal = true,
            '#' => return &line[..idx],
            _ => {}
        }
    }
    line
}

/// Byte cursor over one logical line; the position always rests on a
/// character boundary.
struct Cursor<'a> {
    text: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<char> {
        self.text[self.pos..].chars().next()
    }

    fn next(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn rest(&self) -> &'a str {
        &self.text[self.pos..]
    }

    /// Skip separation whitespace: a newline only ever appears inside a
    /// joined array, where TOML allows it.
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n')) {
            self.next();
        }
    }
}

/// Parse one `key = value` line into dotted segments and a value; anything
/// past the value refuses.
fn parse_key_value(line: &str, path: &Path) -> Result<(Vec<String>, Value), String> {
    let mut scan = Cursor { text: line, pos: 0 };
    let key = parse_key(&mut scan, path)?;
    scan.skip_ws();
    let value = parse_value(&mut scan, path, 0)?;
    scan.skip_ws();
    if scan.peek().is_some() {
        return Err(parse_err(path, "unexpected trailing text"));
    }
    Ok((key, value))
}

/// Parse dotted key segments up to `=`.
fn parse_key(scan: &mut Cursor, path: &Path) -> Result<Vec<String>, String> {
    let mut segments = Vec::new();
    loop {
        scan.skip_ws();
        segments.push(parse_segment(&mut *scan, path)?);
        scan.skip_ws();
        match scan.next() {
            Some('.') => continue,
            Some('=') => return Ok(segments),
            _ => return Err(parse_err(path, "expected `=`")),
        }
    }
}

/// Parse a table header (the text after `[`) into segments; array tables
/// refuse, since no config table this reader consults is one.
fn parse_header(after: &str, path: &Path) -> Result<Vec<String>, String> {
    let mut scan = Cursor {
        text: after,
        pos: 0,
    };
    if scan.peek() == Some('[') {
        return Err(parse_err(path, "array tables refuse"));
    }
    let mut segments = Vec::new();
    loop {
        scan.skip_ws();
        segments.push(parse_segment(&mut scan, path)?);
        scan.skip_ws();
        match scan.next() {
            Some('.') => continue,
            Some(']') => {
                scan.skip_ws();
                if scan.peek().is_some() {
                    return Err(parse_err(path, "unexpected trailing text"));
                }
                return Ok(segments);
            }
            _ => return Err(parse_err(path, "expected `.` or `]`")),
        }
    }
}

/// One dotted key segment: bare, basic, or literal.
fn parse_segment(scan: &mut Cursor, path: &Path) -> Result<String, String> {
    match scan.peek() {
        Some('"') => parse_basic_string(scan, path),
        Some('\'') => parse_literal_string(scan, path),
        Some(ch) if is_bare_char(ch) => {
            let mut out = String::new();
            while let Some(ch) = scan.peek() {
                if !is_bare_char(ch) {
                    break;
                }
                out.push(ch);
                scan.next();
            }
            Ok(out)
        }
        _ => Err(parse_err(path, "expected a key")),
    }
}

/// Bare key characters: ASCII letters, digits, underscores, and dashes.
fn is_bare_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
}

/// Nesting depth past which values refuse rather than recursing.
const MAX_DEPTH: usize = 64;

/// Parse a value: strings, arrays, and inline tables recurse; bare scalars
/// stay opaque.
fn parse_value(scan: &mut Cursor, path: &Path, depth: usize) -> Result<Value, String> {
    if depth > MAX_DEPTH {
        return Err(parse_err(path, "nesting too deep"));
    }
    scan.skip_ws();
    match scan.peek() {
        Some('"') => parse_basic_string(scan, path).map(Value::Str),
        Some('\'') => parse_literal_string(scan, path).map(Value::Str),
        Some('[') => parse_array(scan, path, depth),
        Some('{') => parse_inline(scan, path, depth),
        Some(_) => parse_bare(scan, path),
        None => Err(parse_err(path, "expected a value")),
    }
}

/// Parse an array, allowing newlines and a trailing comma.
fn parse_array(scan: &mut Cursor, path: &Path, depth: usize) -> Result<Value, String> {
    scan.next();
    let mut items = Vec::new();
    loop {
        scan.skip_ws();
        if scan.peek() == Some(']') {
            scan.next();
            return Ok(Value::Arr(items));
        }
        items.push(parse_value(scan, path, depth + 1)?);
        scan.skip_ws();
        match scan.next() {
            Some(',') => continue,
            Some(']') => return Ok(Value::Arr(items)),
            _ => return Err(parse_err(path, "expected `,` or `]`")),
        }
    }
}

/// Parse an inline table into dotted items; duplicates and shape conflicts
/// refuse like their document-level twins.
fn parse_inline(scan: &mut Cursor, path: &Path, depth: usize) -> Result<Value, String> {
    scan.next();
    let mut items = BTreeMap::new();
    loop {
        scan.skip_ws();
        if scan.peek() == Some('}') {
            scan.next();
            return Ok(Value::Inline(items));
        }
        let key = parse_key(scan, path)?;
        scan.skip_ws();
        let value = parse_value(scan, path, depth + 1)?;
        insert_dotted(&mut items, key, value, path)?;
        scan.skip_ws();
        match scan.next() {
            Some(',') => continue,
            Some('}') => return Ok(Value::Inline(items)),
            _ => return Err(parse_err(path, "expected `,` or `}`")),
        }
    }
}

/// Parse a bare scalar as an opaque ignored value: booleans and numbers
/// validate exactly, so invalid TOML refuses here instead of passing as an
/// ignored setting. Dates and times refuse: no Cargo key takes one, so a
/// file using them cannot carry flags this reader would miss.
fn parse_bare(scan: &mut Cursor, path: &Path) -> Result<Value, String> {
    let mut token = String::new();
    while let Some(ch) = scan.peek() {
        if !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '+' | '-' | '.' | ':')) {
            break;
        }
        token.push(ch);
        scan.next();
    }
    if token.is_empty() {
        return Err(parse_err(path, "expected a value"));
    }
    if !is_scalar(&token) {
        return Err(parse_err(path, "bad scalar"));
    }
    Ok(Value::Other)
}

/// Whether `token` is a TOML boolean or number: full scalar grammar, so a
/// bare word or a malformed number refuses instead of passing as ignored.
fn is_scalar(token: &str) -> bool {
    token == "true" || token == "false" || is_int(token) || is_float(token)
}

/// Whether `token` is a TOML integer: an optional sign plus `0`, a
/// leading-nonzero decimal run, or an unsigned radix run, with underscores
/// strictly between digits.
fn is_int(token: &str) -> bool {
    if let Some(rest) = token.strip_prefix("0x") {
        return is_radix_run(rest, char::is_ascii_hexdigit);
    }
    if let Some(rest) = token.strip_prefix("0o") {
        return is_radix_run(rest, |ch| matches!(ch, '0'..='7'));
    }
    if let Some(rest) = token.strip_prefix("0b") {
        return is_radix_run(rest, |ch| matches!(ch, '0' | '1'));
    }
    is_mantissa_int(token.strip_prefix(['+', '-']).unwrap_or(token))
}

/// Whether `run` continues a digit run: underscores strictly between
/// digits, with a leading underscore allowed since it follows the caller's
/// already-checked digit.
fn is_digit_run(run: &[char], digit: impl Fn(&char) -> bool) -> bool {
    if run.last() == Some(&'_') {
        return false;
    }
    let mut was_underscore = false;
    for ch in run {
        if *ch == '_' {
            if was_underscore {
                return false;
            }
            was_underscore = true;
        } else {
            if !digit(ch) {
                return false;
            }
            was_underscore = false;
        }
    }
    true
}

/// Whether `run` is a radix run: a leading digit plus a strict run.
fn is_radix_run(run: &str, digit: impl Fn(&char) -> bool) -> bool {
    let chars: Vec<char> = run.chars().collect();
    if chars.is_empty() || !digit(&chars[0]) {
        return false;
    }
    is_digit_run(&chars[1..], digit)
}

/// Whether `token` is a TOML float: lowercase infinity/NaN with an optional
/// sign, or a mantissa with a fraction, an exponent, or both.
fn is_float(token: &str) -> bool {
    let rest = token.strip_prefix(['+', '-']).unwrap_or(token);
    if rest == "inf" || rest == "nan" {
        return true;
    }
    let mut parts = rest.splitn(2, ['e', 'E']);
    let mantissa = parts.next().unwrap_or("");
    let exponent = parts.next();
    if exponent.is_some_and(|exp| exp.contains(['e', 'E'])) {
        return false;
    }
    let int_part;
    let frac_part;
    if let Some((head, tail)) = mantissa.split_once('.') {
        int_part = head;
        frac_part = Some(tail);
    } else {
        if exponent.is_none() {
            return false;
        }
        int_part = mantissa;
        frac_part = None;
    }
    if !is_mantissa_int(int_part) {
        return false;
    }
    if let Some(frac) = frac_part {
        let chars: Vec<char> = frac.chars().collect();
        if chars.is_empty()
            || !chars[0].is_ascii_digit()
            || !is_digit_run(&chars, char::is_ascii_digit)
        {
            return false;
        }
    }
    if let Some(exp) = exponent {
        let digits = exp.strip_prefix(['+', '-']).unwrap_or(exp);
        let chars: Vec<char> = digits.chars().collect();
        if chars.is_empty()
            || !chars[0].is_ascii_digit()
            || !is_digit_run(&chars, char::is_ascii_digit)
        {
            return false;
        }
    }
    true
}

/// Whether `part` is a float mantissa integer: `0` or a leading-nonzero run
/// with strict underscores.
fn is_mantissa_int(part: &str) -> bool {
    if part == "0" {
        return true;
    }
    let mut chars = part.chars();
    if !chars.next().is_some_and(|ch| matches!(ch, '1'..='9')) {
        return false;
    }
    is_digit_run(&chars.collect::<Vec<_>>(), char::is_ascii_digit)
}

/// Parse a basic string with escapes; triple quotes refuse, since no
/// multi-line string can form on one logical line.
fn parse_basic_string(scan: &mut Cursor, path: &Path) -> Result<String, String> {
    scan.next();
    if scan.rest().starts_with("\"\"") {
        return Err(parse_err(path, "triple-quoted strings refuse"));
    }
    let mut out = String::new();
    loop {
        match scan.next() {
            None => return Err(parse_err(path, "unterminated string")),
            Some('"') => return Ok(out),
            Some('\\') => out.push(parse_escape(scan, path)?),
            Some('\n') => return Err(parse_err(path, "unescaped newline in string")),
            Some(ch) => out.push(ch),
        }
    }
}

/// Parse a literal string; backslashes stay literal, triple quotes refuse.
fn parse_literal_string(scan: &mut Cursor, path: &Path) -> Result<String, String> {
    scan.next();
    if scan.rest().starts_with("''") {
        return Err(parse_err(path, "triple-quoted strings refuse"));
    }
    let mut out = String::new();
    loop {
        match scan.next() {
            None => return Err(parse_err(path, "unterminated string")),
            Some('\'') => return Ok(out),
            Some('\n') => return Err(parse_err(path, "unescaped newline in string")),
            Some(ch) => out.push(ch),
        }
    }
}

/// Parse one backslash escape; anything outside the TOML alphabet refuses.
fn parse_escape(scan: &mut Cursor, path: &Path) -> Result<char, String> {
    match scan.next() {
        Some('"') => Ok('"'),
        Some('\\') => Ok('\\'),
        Some('b') => Ok('\u{8}'),
        Some('f') => Ok('\u{c}'),
        Some('n') => Ok('\n'),
        Some('r') => Ok('\r'),
        Some('t') => Ok('\t'),
        Some('u') => parse_hex(scan, path, 4),
        Some('U') => parse_hex(scan, path, 8),
        _ => Err(parse_err(path, "bad escape")),
    }
}

/// Parse exactly `len` hex digits into a character; surrogates and
/// out-of-range scalars refuse.
fn parse_hex(scan: &mut Cursor, path: &Path, len: usize) -> Result<char, String> {
    let mut digits = String::new();
    for _ in 0..len {
        match scan.peek() {
            Some(ch) if ch.is_ascii_hexdigit() => {
                digits.push(ch);
                scan.next();
            }
            _ => return Err(parse_err(path, "bad escape")),
        }
    }
    let scalar = u32::from_str_radix(&digits, 16).expect("hex digits parse");
    char::from_u32(scalar).ok_or_else(|| parse_err(path, "bad escape"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Scratch directory removed on drop; unique per test process.
    struct TestDir {
        dir: PathBuf,
    }

    impl TestDir {
        fn fresh(tag: &str) -> TestDir {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let id = NEXT.fetch_add(1, Ordering::SeqCst);
            let dir = std::env::temp_dir().join(format!(
                "memveil-remap-flags-{tag}-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("scratch dir");
            TestDir { dir }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// Synthetic build tree with no ambient cargo config: an isolated home,
    /// cargo home, and build directory.
    struct Fixture {
        _dir: TestDir,
        env: BTreeMap<String, String>,
        build: PathBuf,
        cargo_home: PathBuf,
    }

    impl Fixture {
        fn fresh(tag: &str) -> Fixture {
            let dir = TestDir::fresh(tag);
            let home = dir.dir.join("home");
            let cargo_home = dir.dir.join("cargo-home");
            let build = dir.dir.join("build");
            fs::create_dir_all(&home).expect("home dir");
            fs::create_dir_all(&cargo_home).expect("cargo home dir");
            fs::create_dir_all(&build).expect("build dir");
            let mut env = BTreeMap::new();
            env.insert(
                "HOME".to_string(),
                home.to_str().expect("UTF-8 home").to_string(),
            );
            env.insert(
                "CARGO_HOME".to_string(),
                cargo_home.to_str().expect("UTF-8 cargo home").to_string(),
            );
            Fixture {
                _dir: dir,
                env,
                build,
                cargo_home,
            }
        }

        /// Move the build directory deeper for ancestor join-order tests.
        fn nest(&mut self, rel: &str) {
            self.build = self._dir.dir.join(rel);
            fs::create_dir_all(&self.build).expect("nested build dir");
        }

        /// The expected remap pair: home first, build root last.
        fn pair(&self) -> Vec<String> {
            vec![
                format!("--remap-path-prefix={}=/build-prefix", self.env["HOME"]),
                format!(
                    "--remap-path-prefix={}=/build-root",
                    abspath(&self.build).display()
                ),
            ]
        }

        /// Run the remap export; the encoded channel carries the flags and
        /// `RUSTFLAGS` is gone.
        fn remap(&mut self) -> Vec<String> {
            remap_build_paths(&mut self.env, &self.build).expect("remap succeeds");
            assert!(!self.env.contains_key("RUSTFLAGS"));
            self.env["CARGO_ENCODED_RUSTFLAGS"]
                .split('\u{1f}')
                .map(str::to_string)
                .collect()
        }

        fn write_at(base: &Path, rel: &str, text: &str) {
            let path = base.join(rel);
            fs::create_dir_all(path.parent().expect("parent")).expect("parent dir");
            fs::write(&path, text).expect("config write");
        }

        fn write(&self, rel: &str, text: &str) {
            Self::write_at(&self.build, rel, text);
        }

        fn write_home(&self, rel: &str, text: &str) {
            Self::write_at(&self.cargo_home, rel, text);
        }
    }

    /// Both channels set: the encoded set wins whole, once.
    #[test]
    fn conflicting_channels_export_encoded_only() {
        let mut fx = Fixture::fresh("conflict");
        fx.env.insert(
            "CARGO_ENCODED_RUSTFLAGS".to_string(),
            "-Copt-level=3".to_string(),
        );
        fx.env
            .insert("RUSTFLAGS".to_string(), "-Copt-level=0".to_string());
        let mut want = vec!["-Copt-level=3".to_string()];
        want.extend(fx.pair());
        let got = fx.remap();
        assert_eq!(got, want);
        assert!(!got.iter().any(|flag| flag == "-Copt-level=0"));
    }

    #[test]
    fn rustflags_channel_moves_to_encoded() {
        let mut fx = Fixture::fresh("moves");
        fx.env
            .insert("RUSTFLAGS".to_string(), "-C opt-level=0".to_string());
        let mut want = vec!["-C".to_string(), "opt-level=0".to_string()];
        want.extend(fx.pair());
        assert_eq!(fx.remap(), want);
    }

    /// A set channel wins over config files, like Cargo.
    #[test]
    fn rustflags_channel_shadows_config() {
        let mut fx = Fixture::fresh("shadows");
        fx.write(
            ".cargo/config.toml",
            "[build]\nrustflags = [\"-C\", \"opt-level=1\"]\n",
        );
        fx.env
            .insert("RUSTFLAGS".to_string(), "-C opt-level=0".to_string());
        let mut want = vec!["-C".to_string(), "opt-level=0".to_string()];
        want.extend(fx.pair());
        assert_eq!(fx.remap(), want);
    }

    /// A set channel never even reads the config layer.
    #[test]
    fn channel_set_ignores_broken_config() {
        let mut fx = Fixture::fresh("broken-unread");
        fx.write(".cargo/config.toml", "not = [valid\n");
        fx.env
            .insert("RUSTFLAGS".to_string(), "-C opt-level=0".to_string());
        let mut want = vec!["-C".to_string(), "opt-level=0".to_string()];
        want.extend(fx.pair());
        assert_eq!(fx.remap(), want);
    }

    /// Presence selects the channel, not non-emptiness.
    #[test]
    fn empty_encoded_shadows_rustflags() {
        let mut fx = Fixture::fresh("empty-encoded");
        fx.env
            .insert("CARGO_ENCODED_RUSTFLAGS".to_string(), String::new());
        fx.env
            .insert("RUSTFLAGS".to_string(), "-C opt-level=0".to_string());
        assert_eq!(fx.remap(), fx.pair());
    }

    #[test]
    fn empty_rustflags_shadows_config() {
        let mut fx = Fixture::fresh("empty-rustflags");
        fx.write(
            ".cargo/config.toml",
            "[build]\nrustflags = [\"-C\", \"opt-level=1\"]\n",
        );
        fx.env.insert("RUSTFLAGS".to_string(), String::new());
        assert_eq!(fx.remap(), fx.pair());
    }

    /// Cargo passes empty segments through; so must we.
    #[test]
    fn encoded_empty_segments_preserved() {
        let mut fx = Fixture::fresh("segments");
        fx.env.insert(
            "CARGO_ENCODED_RUSTFLAGS".to_string(),
            "-C\u{1f}\u{1f}-X".to_string(),
        );
        let mut want = vec!["-C".to_string(), String::new(), "-X".to_string()];
        want.extend(fx.pair());
        assert_eq!(fx.remap(), want);
    }

    /// Quotes ride through untouched: Cargo words on spaces alone.
    #[test]
    fn rustflags_channel_keeps_quotes() {
        let mut fx = Fixture::fresh("quotes");
        fx.env.insert(
            "RUSTFLAGS".to_string(),
            "--cfg mv_cfg=\"quoted\"".to_string(),
        );
        let mut want = vec!["--cfg".to_string(), "mv_cfg=\"quoted\"".to_string()];
        want.extend(fx.pair());
        assert_eq!(fx.remap(), want);
    }

    /// Former refusals pass through: splitting never fails.
    #[test]
    fn rustflags_channel_never_refuses() {
        for (n, text) in ["foo\"bar", "\"a", "'a", "a\\", "\\", "\""]
            .into_iter()
            .enumerate()
        {
            let mut fx = Fixture::fresh(&format!("passthrough-{n}"));
            fx.env.insert("RUSTFLAGS".to_string(), text.to_string());
            let mut want = vec![text.to_string()];
            want.extend(fx.pair());
            assert_eq!(fx.remap(), want, "{text:?}");
        }
    }

    /// Config-sourced flags ride along with the remaps.
    #[test]
    fn config_file_array_survives() {
        let mut fx = Fixture::fresh("array");
        fx.write(
            ".cargo/config.toml",
            "[build]\nrustflags = [\"-C\", \"opt-level=1\"]\n",
        );
        let mut want = vec!["-C".to_string(), "opt-level=1".to_string()];
        want.extend(fx.pair());
        assert_eq!(fx.remap(), want);
    }

    /// String values split on whitespace; quotes stay literal.
    #[test]
    fn config_file_string_splits_on_whitespace() {
        let mut fx = Fixture::fresh("string");
        fx.write(
            ".cargo/config.toml",
            "[build]\nrustflags = \"--cfg foo=\\\"a b\\\"\"\n",
        );
        let mut want = vec![
            "--cfg".to_string(),
            "foo=\"a".to_string(),
            "b\"".to_string(),
        ];
        want.extend(fx.pair());
        assert_eq!(fx.remap(), want);
    }

    /// Home, then ancestors down, then the dotted spelling.
    #[test]
    fn config_join_order() {
        let mut fx = Fixture::fresh("join");
        fx.nest("outer/inner");
        let outer = fx._dir.dir.join("outer");
        fx.write_home(
            "config.toml",
            "[build]\nrustflags = [\"--cfg\", \"home\"]\n",
        );
        Fixture::write_at(
            &outer,
            ".cargo/config.toml",
            "[build]\nrustflags = [\"--cfg\", \"parent\"]\n",
        );
        fx.write(
            ".cargo/config.toml",
            "[build]\nrustflags = [\"--cfg\", \"child\"]\n",
        );
        fx.env.insert(
            "CARGO_BUILD_RUSTFLAGS".to_string(),
            "--cfg dotted".to_string(),
        );
        let mut want = vec![
            "--cfg", "home", "--cfg", "parent", "--cfg", "child", "--cfg", "dotted",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        want.extend(fx.pair());
        assert_eq!(fx.remap(), want);
    }

    #[test]
    fn extensionless_config_wins_same_level() {
        let mut fx = Fixture::fresh("same-level");
        fx.write(
            ".cargo/config.toml",
            "[build]\nrustflags = [\"--cfg\", \"dotted\"]\n",
        );
        fx.write(
            ".cargo/config",
            "[build]\nrustflags = [\"--cfg\", \"plain\"]\n",
        );
        let mut want = vec!["--cfg".to_string(), "plain".to_string()];
        want.extend(fx.pair());
        assert_eq!(fx.remap(), want);
    }

    /// A broken config.toml stays unread where the extensionless
    /// config wins: the winner suppresses the loser wholesale.
    #[test]
    fn broken_losing_leaf_ignored() {
        let mut fx = Fixture::fresh("losing-leaf");
        fx.write(
            ".cargo/config",
            "[build]\nrustflags = [\"--cfg\", \"plain\"]\n",
        );
        fx.write(".cargo/config.toml", "not = [valid\n");
        let mut want = vec!["--cfg".to_string(), "plain".to_string()];
        want.extend(fx.pair());
        assert_eq!(fx.remap(), want);
    }

    /// The extensionless winner suppresses the dotted leaf even when
    /// the winner itself carries no flags.
    #[test]
    fn extensionless_without_flags_suppresses_toml() {
        let mut fx = Fixture::fresh("wholesale");
        fx.write(".cargo/config", "[build]\njobs = 2\n");
        fx.write(
            ".cargo/config.toml",
            "[build]\nrustflags = [\"--cfg\", \"ignored\"]\n",
        );
        assert_eq!(fx.remap(), fx.pair());
    }

    /// A nearer string replaces the ancestor string outright.
    #[test]
    fn layered_strings_replace() {
        let mut fx = Fixture::fresh("replace");
        fx.nest("outer/inner");
        Fixture::write_at(
            &fx._dir.dir.join("outer"),
            ".cargo/config.toml",
            "[build]\nrustflags = \"--cfg old\"\n",
        );
        fx.write(".cargo/config.toml", "[build]\nrustflags = \"--cfg new\"\n");
        let mut want = vec!["--cfg".to_string(), "new".to_string()];
        want.extend(fx.pair());
        assert_eq!(fx.remap(), want);
    }

    /// A string meeting an array across files refuses, either way
    /// round: Cargo cannot merge the two shapes.
    #[test]
    fn mixed_string_array_refuses() {
        for (n, (outer, inner)) in [
            (
                "[build]\nrustflags = \"--cfg old\"\n",
                "[build]\nrustflags = [\"--cfg\", \"new\"]\n",
            ),
            (
                "[build]\nrustflags = [\"--cfg\", \"old\"]\n",
                "[build]\nrustflags = \"--cfg new\"\n",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let mut fx = Fixture::fresh(&format!("mixed-{n}"));
            fx.nest("outer/inner");
            Fixture::write_at(&fx._dir.dir.join("outer"), ".cargo/config.toml", outer);
            fx.write(".cargo/config.toml", inner);
            let err = remap_build_paths(&mut fx.env, &fx.build).expect_err("must refuse");
            assert!(err.contains("mixes string and array"), "{err}");
        }
    }

    /// A home directory that overlaps an ancestor loads once, at the
    /// ancestor: the flag appears a single time.
    #[test]
    fn home_ancestor_overlap_loads_once() {
        let mut fx = Fixture::fresh("overlap");
        fx.nest("outer/inner");
        let outer_cargo = fx._dir.dir.join("outer").join(".cargo");
        fx.env.insert(
            "CARGO_HOME".to_string(),
            outer_cargo.to_str().expect("UTF-8").to_string(),
        );
        Fixture::write_at(
            &fx._dir.dir.join("outer"),
            ".cargo/config.toml",
            "[build]\nrustflags = [\"--cfg\", \"dup\"]\n",
        );
        fx.write(
            ".cargo/config.toml",
            "[build]\nrustflags = [\"--cfg\", \"child\"]\n",
        );
        let mut want = vec![
            "--cfg".to_string(),
            "dup".to_string(),
            "--cfg".to_string(),
            "child".to_string(),
        ];
        want.extend(fx.pair());
        let flags = fx.remap();
        assert_eq!(flags, want);
        assert_eq!(
            flags.iter().filter(|flag| flag.as_str() == "dup").count(),
            1
        );
    }

    /// Overlap through a symlinked spelling loads once too.
    #[test]
    fn home_ancestor_overlap_symlink_loads_once() {
        let mut fx = Fixture::fresh("overlap-link");
        fx.nest("outer/inner");
        let outer_cargo = fx._dir.dir.join("outer").join(".cargo");
        std::fs::create_dir_all(&outer_cargo).expect("outer cargo dir");
        let link = fx._dir.dir.join("cargo-link");
        std::os::unix::fs::symlink(&outer_cargo, &link).expect("link home");
        fx.env.insert(
            "CARGO_HOME".to_string(),
            link.to_str().expect("UTF-8").to_string(),
        );
        Fixture::write_at(
            &fx._dir.dir.join("outer"),
            ".cargo/config.toml",
            "[build]\nrustflags = [\"--cfg\", \"dup\"]\n",
        );
        let mut want = vec!["--cfg".to_string(), "dup".to_string()];
        want.extend(fx.pair());
        let flags = fx.remap();
        assert_eq!(flags, want);
        assert_eq!(
            flags.iter().filter(|flag| flag.as_str() == "dup").count(),
            1
        );
    }

    /// The dotted spelling appends after a file string; an empty one
    /// leaves the file flags standing. Both config leaves behave alike.
    #[test]
    fn dotted_env_appends_after_file_string() {
        for (n, leaf) in [".cargo/config", ".cargo/config.toml"]
            .into_iter()
            .enumerate()
        {
            let mut fx = Fixture::fresh(&format!("dotted-append-{n}"));
            fx.write(leaf, "[build]\nrustflags = \"--cfg file\"\n");
            fx.env.insert(
                "CARGO_BUILD_RUSTFLAGS".to_string(),
                "--cfg dotted".to_string(),
            );
            let mut want = vec![
                "--cfg".to_string(),
                "file".to_string(),
                "--cfg".to_string(),
                "dotted".to_string(),
            ];
            want.extend(fx.pair());
            assert_eq!(fx.remap(), want, "{leaf}");
            let mut fx = Fixture::fresh(&format!("dotted-append-empty-{n}"));
            fx.write(leaf, "[build]\nrustflags = \"--cfg file\"\n");
            fx.env
                .insert("CARGO_BUILD_RUSTFLAGS".to_string(), String::new());
            let mut want = vec!["--cfg".to_string(), "file".to_string()];
            want.extend(fx.pair());
            assert_eq!(fx.remap(), want, "{leaf}");
        }
    }

    /// A broken link counts as absent: the dotted leaf serves.
    #[test]
    fn broken_symlink_counts_as_absent() {
        let mut fx = Fixture::fresh("broken-link");
        let cargo_dir = fx.build.join(".cargo");
        std::fs::create_dir_all(&cargo_dir).expect("cargo dir");
        std::os::unix::fs::symlink(fx.build.join("nowhere"), cargo_dir.join("config"))
            .expect("broken link");
        fx.write(
            ".cargo/config.toml",
            "[build]\nrustflags = [\"--cfg\", \"dotted\"]\n",
        );
        let mut want = vec!["--cfg".to_string(), "dotted".to_string()];
        want.extend(fx.pair());
        assert_eq!(fx.remap(), want);
    }

    /// An extensionless directory refuses like the unreadable file it
    /// is: Cargo fails the read instead of falling through.
    #[test]
    fn directory_leaf_refuses() {
        let mut fx = Fixture::fresh("dir-leaf");
        let dir = fx.build.join(".cargo/config");
        std::fs::create_dir_all(&dir).expect("config dir");
        fx.write(
            ".cargo/config.toml",
            "[build]\nrustflags = [\"--cfg\", \"dotted\"]\n",
        );
        remap_build_paths(&mut fx.env, &fx.build).expect_err("must refuse");
    }

    /// Non-flag settings never trip the reader.
    #[test]
    fn unrelated_config_keys_ignored() {
        let mut fx = Fixture::fresh("unrelated");
        fx.write(
            ".cargo/config.toml",
            "[build]\njobs = 4\n[target.x86_64-unknown-linux-gnu]\nlinker = \"cc\"\n",
        );
        fx.env.insert(
            "CARGO_TARGET_DIR".to_string(),
            fx.build.join("target").to_str().expect("UTF-8").to_string(),
        );
        fx.env.insert(
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER".to_string(),
            "cc".to_string(),
        );
        assert_eq!(fx.remap(), fx.pair());
    }

    #[test]
    fn dotted_env_only() {
        let mut fx = Fixture::fresh("dotted");
        fx.env.insert(
            "CARGO_BUILD_RUSTFLAGS".to_string(),
            "-C opt-level=2".to_string(),
        );
        let mut want = vec!["-C".to_string(), "opt-level=2".to_string()];
        want.extend(fx.pair());
        assert_eq!(fx.remap(), want);
    }

    /// No channels, no configs: exactly the remap pair.
    #[test]
    fn ambient_empty_exports_remaps_only() {
        let mut fx = Fixture::fresh("ambient-empty");
        assert_eq!(fx.remap(), fx.pair());
    }

    #[test]
    fn remap_pair_present_exactly_once() {
        let mut fx = Fixture::fresh("once");
        fx.env
            .insert("RUSTFLAGS".to_string(), "--cfg ambient".to_string());
        let flags = fx.remap();
        let pair = fx.pair();
        assert_eq!(flags[..2], ["--cfg".to_string(), "ambient".to_string()]);
        assert_eq!(flags[2..], pair);
        assert_eq!(flags.iter().filter(|flag| *flag == &pair[0]).count(), 1);
        assert_eq!(flags.iter().filter(|flag| *flag == &pair[1]).count(), 1);
    }

    #[test]
    fn missing_home_skips_home_remap() {
        let mut fx = Fixture::fresh("no-home");
        fx.env.insert("HOME".to_string(), String::new());
        let flags = fx.remap();
        assert_eq!(flags.len(), 1);
        assert!(flags[0].ends_with("=/build-root"), "{}", flags[0]);
    }

    /// The effective query reports every config path it probed, read or
    /// not, so a build script can watch them for rebuilds.
    #[test]
    fn effective_reports_probed_config_paths() {
        let fx = Fixture::fresh("probed");
        let effective = effective_rustflags(&fx.env, &fx.build).expect("no channels");
        assert!(effective.flags.is_empty());
        assert!(
            effective
                .config_files
                .contains(&fx.build.join(".cargo/config"))
        );
        assert!(
            effective
                .config_files
                .contains(&fx.build.join(".cargo/config.toml"))
        );
        assert!(
            effective
                .config_files
                .contains(&fx.cargo_home.join("config"))
        );
        assert!(
            effective
                .config_files
                .contains(&fx.cargo_home.join("config.toml"))
        );
    }

    /// A set channel probes no config file.
    #[test]
    fn channel_set_probes_no_config_paths() {
        let mut fx = Fixture::fresh("no-probe");
        fx.env
            .insert("RUSTFLAGS".to_string(), "--cfg ambient".to_string());
        let effective = effective_rustflags(&fx.env, &fx.build).expect("channel set");
        assert!(effective.config_files.is_empty());
    }

    /// The build-script composition: effective set, then extras, then the
    /// remap pair exactly once at the end.
    #[test]
    fn effective_extends_with_extras_before_remaps() {
        let mut fx = Fixture::fresh("compose");
        fx.env
            .insert("RUSTFLAGS".to_string(), "--cfg ambient".to_string());
        let effective = effective_rustflags(&fx.env, &fx.build).expect("channel set");
        let mut flags = effective.flags;
        flags.extend(["-C".to_string(), "linker=bpf-linker".to_string()]);
        append_remaps(&mut flags, &fx.env["HOME"], &fx.build);
        let pair = fx.pair();
        assert_eq!(
            flags,
            [
                "--cfg".to_string(),
                "ambient".to_string(),
                "-C".to_string(),
                "linker=bpf-linker".to_string(),
                pair[0].clone(),
                pair[1].clone(),
            ]
        );
    }

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    /// Effective flags for a lone build config file.
    fn effective_of(tag: &str, text: &str) -> Vec<String> {
        let fx = Fixture::fresh(tag);
        fx.write(".cargo/config.toml", text);
        effective_rustflags(&fx.env, &fx.build)
            .expect("reads")
            .flags
    }

    /// Refusal message for a lone build config file.
    fn effective_err(tag: &str, text: &str) -> String {
        let fx = Fixture::fresh(tag);
        fx.write(".cargo/config.toml", text);
        effective_rustflags(&fx.env, &fx.build).expect_err("refuses")
    }

    /// Target entries shadow the build key: never guess.
    #[test]
    fn target_rustflags_refuse() {
        let err = effective_err(
            "target-file",
            "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"opt-level=2\"]\n",
        );
        assert!(err.contains("target rustflags"), "{err}");
    }

    #[test]
    fn target_env_rustflags_refuse() {
        let mut fx = Fixture::fresh("target-env");
        fx.env.insert(
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS".to_string(),
            "-C opt-level=2".to_string(),
        );
        let err = effective_rustflags(&fx.env, &fx.build).expect_err("refuses");
        assert!(err.contains("target rustflags"), "{err}");
    }

    /// An empty middle is not the target-flags spelling.
    #[test]
    fn target_env_empty_middle_ignored() {
        let mut fx = Fixture::fresh("target-empty");
        fx.env.insert(
            "CARGO_TARGET__RUSTFLAGS".to_string(),
            "-C opt-level=2".to_string(),
        );
        assert_eq!(fx.remap(), fx.pair());
    }

    #[test]
    fn include_refuses() {
        let err = effective_err("include", "include = [\"extra.toml\"]\n");
        assert!(err.contains("include"), "{err}");
    }

    #[test]
    fn include_table_refuses() {
        let err = effective_err("include-table", "[include]\n");
        assert!(err.contains("include"), "{err}");
    }

    #[test]
    fn invalid_toml_refuses() {
        let err = effective_err("invalid", "not = [valid\n");
        assert!(err.contains("cannot parse"), "{err}");
    }

    #[test]
    fn mistyped_config_refuses() {
        for (tag, body) in [
            ("int", "[build]\nrustflags = 42\n"),
            ("mixed", "[build]\nrustflags = [\"-C\", 42]\n"),
            ("build", "build = \"nope\"\n"),
            ("target", "target = \"nope\"\n"),
        ] {
            effective_err(&format!("mistype-{tag}"), body);
        }
    }

    #[test]
    fn non_file_config_refuses() {
        let fx = Fixture::fresh("non-file");
        let dir = fx.build.join(".cargo/config.toml");
        fs::create_dir_all(&dir).expect("config dir");
        effective_rustflags(&fx.env, &fx.build).expect_err("refuses");
    }

    #[test]
    fn non_utf8_config_refuses() {
        let fx = Fixture::fresh("non-utf8");
        let path = fx.build.join(".cargo/config.toml");
        fs::create_dir_all(path.parent().expect("parent")).expect("parent dir");
        fs::write(&path, [0xff, 0xfe]).expect("raw write");
        let err = effective_rustflags(&fx.env, &fx.build).expect_err("refuses");
        assert!(err.contains("not valid UTF-8"), "{err}");
    }

    #[test]
    fn duplicate_tables_and_keys_refuse() {
        for (tag, body) in [
            ("dup-table", "[build]\n[build]\n"),
            ("dup-key", "[build]\nrustflags = \"a\"\nrustflags = \"b\"\n"),
            ("dotted-then-table", "a.b.c = 1\n[a.b]\n"),
            ("value-then-table", "build = 1\n[build]\n"),
        ] {
            effective_err(&format!("dup-{tag}"), body);
        }
    }

    /// A `[build.rustflags]` table is present but not flags.
    #[test]
    fn build_rustflags_table_refuses() {
        let err = effective_err("build-table", "[build]\n[build.rustflags]\n");
        assert!(err.contains("non-string"), "{err}");
    }

    #[test]
    fn nesting_past_sixty_four_refuses() {
        let mut body = String::from("[build]\nfoo = ");
        for _ in 0..70 {
            body.push('[');
        }
        for _ in 0..70 {
            body.push(']');
        }
        body.push('\n');
        let err = effective_err("deep", &body);
        assert!(err.contains("nesting too deep"), "{err}");
    }

    #[test]
    fn multiline_array_survives() {
        assert_eq!(
            effective_of(
                "multiline",
                "[build]\nrustflags = [\n  \"-C\",\n  \"x\",\n]\n"
            ),
            words(&["-C", "x"])
        );
    }

    /// A `[` in a comment must not join the following lines into it: the
    /// flags survive instead of vanishing with a clean parse.
    #[test]
    fn comment_bracket_does_not_swallow_next_line() {
        assert_eq!(
            effective_of(
                "comment-swallow",
                "[build]\njobs = 4 # [\nrustflags = [\"-C\", \"x\"] # ]\n"
            ),
            words(&["-C", "x"])
        );
    }

    /// A comment-only bracket line must not swallow the header below it.
    #[test]
    fn comment_bracket_does_not_swallow_header() {
        assert_eq!(
            effective_of(
                "comment-swallow-header",
                "# [\n[build] # ]\nrustflags = [\"-C\", \"x\"]\n"
            ),
            words(&["-C", "x"])
        );
    }

    /// The same sandwich around an array table still refuses: the shape is
    /// visible again instead of hidden inside a joined comment.
    #[test]
    fn comment_bracket_array_table_still_refuses() {
        let err = effective_err(
            "comment-swallow-array-table",
            "# [\n[[build]]\njobs = 4 # ]\n",
        );
        assert!(err.contains("array tables"), "{err}");
    }

    /// Unbalanced brackets and braces in comments neither join nor refuse.
    #[test]
    fn unbalanced_comment_brackets_accepted() {
        for (n, comment) in ["# ]", "# [", "# {", "# }", "# [[", "# c [x]"]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                effective_of(
                    &format!("comment-bracket-{n}"),
                    &format!("[build]\njobs = 4 {comment}\nrustflags = [\"-C\"]\n")
                ),
                words(&["-C"]),
                "{comment}"
            );
        }
    }

    /// A comment inside a multi-line array is not a syntax error.
    #[test]
    fn comment_inside_multiline_array_accepts() {
        assert_eq!(
            effective_of(
                "comment-multiline",
                "[build]\nrustflags = [\"a\", # trailing\n\"b\"]\n"
            ),
            words(&["a", "b"])
        );
        assert_eq!(
            effective_of(
                "comment-multiline-own-line",
                "[build]\nrustflags = [\n# whole line\n\"a\",\n]\n"
            ),
            words(&["a"])
        );
    }

    /// A set-but-unreadable significant name refuses instead of reading as
    /// unset; anything else unreadable stays dropped. Raw pairs feed the
    /// parser directly, so the test never touches the live process
    /// environment.
    #[test]
    fn non_utf8_significant_env_refuses() {
        use std::os::unix::ffi::OsStrExt;
        let raw = std::ffi::OsStr::from_bytes(b"\xff\xfe");
        for name in [
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
            "CARGO_HOME",
            "HOME",
        ] {
            let err = process_env_from([(OsString::from(name), raw.to_os_string())])
                .expect_err("must refuse");
            assert!(err.contains("not valid UTF-8"), "{name}: {err}");
        }
        // Presence alone refuses on the target pattern, readable or not.
        let err = process_env_from([(
            OsString::from("CARGO_TARGET_X_RUSTFLAGS"),
            raw.to_os_string(),
        )])
        .expect_err("must refuse");
        assert!(err.contains("target rustflags"), "{err}");
        let raw_name = std::ffi::OsStr::from_bytes(b"CARGO_TARGET_\xff_RUSTFLAGS");
        let err = process_env_from([(raw_name.to_os_string(), OsString::from("x"))])
            .expect_err("must refuse");
        assert!(err.contains("target rustflags"), "{err}");
        // Unrelated unreadable entries stay dropped, not refused.
        let env = process_env_from([(
            OsString::from("MEMVEIL_REMAP_FLAGS_PROBE"),
            raw.to_os_string(),
        )])
        .expect("unrelated stays dropped");
        assert!(!env.keys().any(|key| key == "MEMVEIL_REMAP_FLAGS_PROBE"));
        // Readable pairs pass through untouched.
        let env = process_env_from([
            (OsString::from("RUSTFLAGS"), OsString::from("--cfg x")),
            (OsString::from("ELSEWHERE"), OsString::from("y")),
        ])
        .expect("readable pairs pass");
        assert_eq!(env.get("RUSTFLAGS").map(String::as_str), Some("--cfg x"));
        assert_eq!(env.get("ELSEWHERE").map(String::as_str), Some("y"));
    }

    #[test]
    fn dotted_build_rustflags_survives() {
        assert_eq!(
            effective_of("dotted-build", "build.rustflags = [\"-C\", \"x\"]\n"),
            words(&["-C", "x"])
        );
    }

    #[test]
    fn inline_build_rustflags_survives() {
        assert_eq!(
            effective_of("inline-build", "build = {rustflags = [\"-C\", \"x\"]}\n"),
            words(&["-C", "x"])
        );
    }

    #[test]
    fn inline_build_without_rustflags_ignored() {
        assert_eq!(
            effective_of("inline-build-none", "build = {jobs = [1, 2]}\n"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn dotted_target_rustflags_refuse() {
        let err = effective_err("dotted-target", "target.x.rustflags = [\"-C\", \"x\"]\n");
        assert!(err.contains("target rustflags"), "{err}");
    }

    #[test]
    fn inline_target_rustflags_refuse() {
        let err = effective_err(
            "inline-target",
            "target.x = {rustflags = [\"-C\", \"x\"]}\n",
        );
        assert!(err.contains("target rustflags"), "{err}");
        let err = effective_err(
            "inline-target-nested",
            "target = {x = {rustflags = [\"-C\"]}}\n",
        );
        assert!(err.contains("target rustflags"), "{err}");
    }

    #[test]
    fn inline_target_without_rustflags_ignored() {
        assert_eq!(
            effective_of("inline-target-none", "target.x = {linker = \"cc\"}\n"),
            Vec::<String>::new()
        );
        assert_eq!(
            effective_of(
                "inline-target-nested-none",
                "target = {x = {linker = \"cc\"}}\n"
            ),
            Vec::<String>::new()
        );
    }

    /// `rustflags` directly under `[target]` is not a target entry.
    #[test]
    fn target_table_itself_ignored() {
        assert_eq!(
            effective_of("target-direct", "[target]\nrustflags = [\"-C\", \"x\"]\n"),
            Vec::<String>::new()
        );
    }

    /// Only direct target children count; deeper nesting is not an entry.
    #[test]
    fn deep_target_ignored() {
        assert_eq!(
            effective_of("target-deep", "[target.a.b]\nrustflags = [\"-C\", \"x\"]\n"),
            Vec::<String>::new()
        );
    }

    /// A top-level `rustflags` is not a Cargo spelling.
    #[test]
    fn top_level_rustflags_ignored() {
        assert_eq!(
            effective_of("top-flags", "rustflags = [\"-C\", \"x\"]\n"),
            Vec::<String>::new()
        );
    }

    /// A quoted dotted segment is still one target name.
    #[test]
    fn quoted_target_segment_refuses() {
        let err = effective_err(
            "quoted-target",
            "[target.\"a.b\"]\nrustflags = [\"-C\", \"x\"]\n",
        );
        assert!(err.contains("target rustflags"), "{err}");
    }

    #[test]
    fn config_surface_shapes_accepted() {
        assert_eq!(
            effective_of("crlf", "[build]\r\nrustflags = [\"-C\"]\r\n"),
            words(&["-C"])
        );
        assert_eq!(
            effective_of(
                "comments",
                "# lead\n[build] # tail\nrustflags = [\"a\",] # comma\n"
            ),
            words(&["a"])
        );
        assert_eq!(effective_of("empty", ""), Vec::<String>::new());
        assert_eq!(
            effective_of("ws-table", "  [build]  \n  rustflags  =  [ \"-C\" ]  \n"),
            words(&["-C"])
        );
        assert_eq!(
            effective_of("escapes", "[build]\nrustflags = \"a\\\"b\\\\c\\u0041\"\n"),
            words(&["a\"b\\cA"])
        );
        assert_eq!(
            effective_of("literal", "[build]\nrustflags = 'a\"b'\n"),
            words(&["a\"b"])
        );
        assert_eq!(
            effective_of("mixed-array", "[build]\nrustflags = [\"a\", 'b']\n"),
            words(&["a", "b"])
        );
    }

    /// Booleans and numbers validate exactly; dates and times refuse (no
    /// Cargo key takes one), as do bare words and malformed numbers.
    #[test]
    fn scalar_shapes() {
        for (n, scalar) in [
            "4",
            "+0",
            "-0",
            "1_000",
            "0xdeadbeef",
            "0o755",
            "0b101",
            "true",
            "false",
            "4.0",
            "1e6",
            "1E6",
            "1e+6",
            "6.02e23",
            "224_617.445_991_228",
            "0.1",
            "-3.14",
            "+1_000",
            "1e06",
            "inf",
            "+inf",
            "-inf",
            "nan",
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                effective_of(
                    &format!("scalar-ok-{n}"),
                    &format!("[build]\njobs = {scalar}\n")
                ),
                Vec::<String>::new(),
                "{scalar}"
            );
        }
        for (n, scalar) in [
            ".5",
            "5.",
            "00",
            "01",
            "1_",
            "_1",
            "1__0",
            "+0x1",
            "-0o7",
            "0X1",
            "0x",
            "0b2",
            "0o8",
            "0xg",
            "bar",
            "truex",
            "1e",
            "e6",
            "1.5e",
            "INF",
            "NaN",
            "1979-05-27",
            "07:32:00",
            "1979-05-27T07:32:00Z",
        ]
        .into_iter()
        .enumerate()
        {
            effective_err(
                &format!("scalar-bad-{n}"),
                &format!("[build]\njobs = {scalar}\n"),
            );
        }
    }

    #[test]
    fn unsupported_config_shapes_refuse() {
        for (tag, body) in [
            ("bom", "\u{feff}[build]\nrustflags = [\"-C\"]\n"),
            ("triple", "[build]\nrustflags = \"\"\"-C\"\"\"\n"),
            ("array-table", "[[build]]\n"),
            ("bad-escape", "[build]\nrustflags = \"a\\qb\"\n"),
            ("x-escape", "[build]\nrustflags = \"a\\x41b\"\n"),
            ("surrogate", "[build]\nrustflags = \"a\\ud800b\"\n"),
            ("unclosed-array", "[build]\nrustflags = [\"a\"\n"),
            ("unclosed-string", "[build]\nrustflags = \"a\n"),
            ("no-value", "[build]\nrustflags =\n"),
            ("multiline-inline", "[build]\nfoo = {a = 1,\nb = 2}\n"),
            ("trailing-dot", "[a.]\n"),
            ("empty-table", "[]\n"),
            ("leading-dot", "[.a]\n"),
            ("bare-gap", "[a b]\n"),
            ("dotted-gap", "a. = 1\n"),
        ] {
            effective_err(&format!("shape-{tag}"), body);
        }
    }

    /// Only spaces split; quotes, backslashes, and every other blank
    /// stay literal, and splitting never fails.
    #[test]
    fn rustflags_words_break_on_spaces_alone() {
        for (text, want) in [
            (
                "--cfg mv_cfg=\"quoted\"",
                vec!["--cfg", "mv_cfg=\"quoted\""],
            ),
            ("--cfg mv=\"a b\"", vec!["--cfg", "mv=\"a", "b\""]),
            ("--cfg 'a b'", vec!["--cfg", "'a", "b'"]),
            ("\"a b\" c", vec!["\"a", "b\"", "c"]),
            ("a\"b c\"d", vec!["a\"b", "c\"d"]),
            ("a'b c'd", vec!["a'b", "c'd"]),
            ("a\\ b", vec!["a\\", "b"]),
            ("a\\", vec!["a\\"]),
            ("\\", vec!["\\"]),
            ("\"a", vec!["\"a"]),
            ("'a", vec!["'a"]),
            ("\"\"", vec!["\"\""]),
            ("''", vec!["''"]),
            ("\"", vec!["\""]),
            ("foo\"bar", vec!["foo\"bar"]),
            ("a\tb", vec!["a\tb"]),
            ("a\nb", vec!["a\nb"]),
            ("a\rb", vec!["a\rb"]),
            ("a\x0bb", vec!["a\x0bb"]),
            ("a\x0cb", vec!["a\x0cb"]),
            ("a\u{a0}", vec!["a\u{a0}"]),
            ("a\u{a0}b", vec!["a\u{a0}b"]),
            ("a  b", vec!["a", "b"]),
            ("  a  ", vec!["a"]),
            ("", Vec::<&str>::new()),
            ("   ", Vec::<&str>::new()),
            ("#foo", vec!["#foo"]),
        ] {
            assert_eq!(split_rustflags(text), words(&want), "{text:?}");
        }
    }

    /// Repository toolchain pin: the channel named by the nearest
    /// toolchain file above this crate, the single source of the
    /// compiler under test.
    fn pinned_channel() -> String {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        loop {
            let pin = dir.join("rust-toolchain.toml");
            if pin.is_file() {
                let text = fs::read_to_string(&pin).expect("pin reads");
                for line in text.lines() {
                    let line = line.trim();
                    if let Some(rest) = line.strip_prefix("channel") {
                        let channel = rest.trim().trim_start_matches('=').trim().trim_matches('"');
                        assert!(!channel.is_empty(), "pin names a channel");
                        return channel.to_string();
                    }
                }
                panic!("pin names no channel: {}", pin.display());
            }
            if !dir.pop() {
                panic!("no toolchain file above {}", env!("CARGO_MANIFEST_DIR"));
            }
        }
    }

    /// Scratch crate that refuses to compile without the exact quoted
    /// flag, so a build proves the flag reached the compiler.
    fn quoted_probe(proj: &Path) {
        fs::create_dir_all(proj.join("src")).expect("proj dirs");
        fs::write(
            proj.join("Cargo.toml"),
            "[package]\nname = \"quoted\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("manifest write");
        fs::write(
            proj.join("src/main.rs"),
            "#[cfg(not(mv_cfg = \"quoted\"))]\n\
             compile_error!(\"quoted flag did not reach rustc\");\n\
             fn main() {}\n",
        )
        .expect("source write");
    }

    /// Pinned cargo proven by its own version string: the binary under
    /// test plus the repository pin it must report.
    fn pinned_cargo() -> (PathBuf, String) {
        use std::process::Command;
        let cargo = PathBuf::from(std::env::var_os("CARGO").expect("CARGO is set by cargo"));
        let probe = Command::new(&cargo)
            .arg("--version")
            .env_remove("RUSTUP_TOOLCHAIN")
            .output()
            .expect("cargo --version runs");
        assert!(probe.status.success());
        let version = String::from_utf8_lossy(&probe.stdout);
        let pin = pinned_channel();
        assert!(
            version.starts_with(&format!("cargo {pin} ")),
            "pinned cargo, got {version:?}"
        );
        (cargo, pin)
    }

    /// Pinned cargo proven by its own version string, then a build of
    /// the quoted probe driven by exactly `flags`. The build inherits
    /// the ambient environment minus flag channels and toolchain
    /// overrides, with the home, target, and offline settings pinned
    /// to the scratch tree; the probe carries the repository pin so
    /// the same compiler runs wherever the suite does.
    fn pinned_build(dir: &TestDir, flags: &[String]) -> std::process::Output {
        use std::process::Command;
        let (cargo, pin) = pinned_cargo();
        let proj = dir.dir.join("proj");
        quoted_probe(&proj);
        fs::write(
            proj.join("rust-toolchain.toml"),
            format!("[toolchain]\nchannel = \"{pin}\"\n"),
        )
        .expect("pin write");
        let cargo_home = dir.dir.join("cargo-home");
        fs::create_dir_all(&cargo_home).expect("cargo home dir");
        Command::new(&cargo)
            .arg("build")
            .arg("--offline")
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("CARGO_BUILD_RUSTFLAGS")
            .env_remove("RUSTUP_TOOLCHAIN")
            .env_remove("RUSTC")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env("CARGO_HOME", &cargo_home)
            .env("CARGO_TARGET_DIR", dir.dir.join("target"))
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_ENCODED_RUSTFLAGS", flags.join("\u{1f}"))
            .current_dir(&proj)
            .output()
            .expect("cargo build runs")
    }

    /// The quoted flag reaches the pinned compiler untouched, end to
    /// end: the effective tokens drive a real build of a crate that
    /// refuses to compile without the exact quoted flag.
    #[test]
    fn quoted_flag_accepted_by_pinned_cargo() {
        let dir = TestDir::fresh("pinned-e2e");
        let cargo_home = dir.dir.join("cargo-home");
        fs::create_dir_all(&cargo_home).expect("cargo home dir");
        let mut env = BTreeMap::new();
        env.insert(
            "RUSTFLAGS".to_string(),
            "--cfg mv_cfg=\"quoted\"".to_string(),
        );
        env.insert(
            "CARGO_HOME".to_string(),
            cargo_home.to_str().expect("UTF-8").to_string(),
        );
        let proj = dir.dir.join("proj");
        let effective = effective_rustflags(&env, &proj).expect("splits");
        assert_eq!(effective.flags, words(&["--cfg", "mv_cfg=\"quoted\""]));
        let out = pinned_build(&dir, &effective.flags);
        assert!(
            out.status.success(),
            "quoted flag builds: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The end-to-end harness discriminates: stripped quotes fail the
    /// same build, so the acceptance above is not vacuous.
    #[test]
    fn unquoted_flag_rejected_by_pinned_cargo() {
        let dir = TestDir::fresh("pinned-negative");
        let out = pinned_build(&dir, &words(&["--cfg", "mv_cfg=quoted"]));
        assert!(!out.status.success(), "stripped flag must fail");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("invalid"), "{stderr}");
    }

    /// Compiler-argument log from a real pinned build of a scratch crate
    /// carrying `leaf` with `file_body` under `.cargo`, driven with the
    /// dotted environment spelling set to `dotted` (even when empty). A
    /// wrapper script sits between cargo and the compiler: it appends
    /// each compiler argument vector to the log, then runs the compiler
    /// it was given, so the log holds exactly what the compiler saw.
    fn wrapper_argv_log(
        dir: &TestDir,
        tag: &str,
        leaf: &str,
        file_body: &str,
        dotted: &str,
    ) -> String {
        use std::process::Command;
        let (cargo, pin) = pinned_cargo();
        let proj = dir.dir.join(format!("proj-{tag}"));
        fs::create_dir_all(proj.join("src")).expect("proj dirs");
        fs::write(
            proj.join("Cargo.toml"),
            "[package]\nname = \"flagprobe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("manifest write");
        fs::write(proj.join("src/main.rs"), "fn main() {}\n").expect("source write");
        fs::write(
            proj.join("rust-toolchain.toml"),
            format!("[toolchain]\nchannel = \"{pin}\"\n"),
        )
        .expect("pin write");
        let cargo_dir = proj.join(".cargo");
        fs::create_dir_all(&cargo_dir).expect("cargo dir");
        fs::write(cargo_dir.join(leaf), file_body).expect("config write");
        let wrapper = dir.dir.join(format!("wrapper-{tag}.sh"));
        fs::write(
            &wrapper,
            "#!/bin/sh\n\
             rustc=\"$1\"\n\
             shift\n\
             printf '%s\\n' \"$*\" >> \"$MEMVEIL_RUSTC_ARGV_LOG\"\n\
             exec \"$rustc\" \"$@\"\n",
        )
        .expect("wrapper write");
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&wrapper).expect("wrapper meta").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&wrapper, perms).expect("wrapper exec");
        let cargo_home = dir.dir.join(format!("cargo-home-{tag}"));
        fs::create_dir_all(&cargo_home).expect("cargo home dir");
        let log = dir.dir.join(format!("argv-{tag}.log"));
        let out = Command::new(&cargo)
            .arg("build")
            .arg("--offline")
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("RUSTUP_TOOLCHAIN")
            .env_remove("RUSTC")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env("CARGO_HOME", &cargo_home)
            .env("CARGO_TARGET_DIR", dir.dir.join(format!("target-{tag}")))
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_BUILD_RUSTFLAGS", dotted)
            .env("RUSTC_WRAPPER", &wrapper)
            .env("MEMVEIL_RUSTC_ARGV_LOG", &log)
            .current_dir(&proj)
            .output()
            .expect("cargo build runs");
        assert!(
            out.status.success(),
            "probe build succeeds: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        fs::read_to_string(&log).expect("argv log reads")
    }

    /// Effective flags for one config leaf plus the dotted spelling, the
    /// same shape the probe build above drives: the helper must agree
    /// with the compiler log flag for flag.
    fn helper_flags_for(leaf: &str, file_body: &str, dotted: &str) -> Vec<String> {
        let fx = Fixture::fresh("wrapper-helper");
        fx.write(&format!(".cargo/{leaf}"), file_body);
        let mut env = fx.env.clone();
        env.insert("CARGO_BUILD_RUSTFLAGS".to_string(), dotted.to_string());
        effective_rustflags(&env, &fx.build).expect("reads").flags
    }

    /// The dotted spelling appends after file flags on the real compiler
    /// command line, and an empty one leaves them standing: the wrapper
    /// log holds exactly what the compiler saw, and the helper agrees
    /// with it flag for flag. Both config leaves behave alike.
    #[test]
    fn dotted_env_matches_compiler_invocation() {
        for (n, leaf) in ["config", "config.toml"].into_iter().enumerate() {
            let dir = TestDir::fresh(&format!("wrapper-{n}"));
            let body = "[build]\nrustflags = \"--cfg file\"\n";
            let log = wrapper_argv_log(&dir, &format!("{n}-append"), leaf, body, "--cfg dotted");
            let seen: Vec<&str> = log
                .lines()
                .filter(|line| line.contains("--cfg file"))
                .collect();
            assert!(!seen.is_empty(), "compiler saw the file flag: {log:?}");
            assert!(
                seen.iter().any(|line| line.contains("--cfg dotted")),
                "compiler saw the dotted flag: {log:?}"
            );
            for line in &seen {
                if line.contains("--cfg dotted") {
                    let file_at = line.find("--cfg file").expect("file flag logged");
                    let dotted_at = line.find("--cfg dotted").expect("dotted flag logged");
                    assert!(file_at < dotted_at, "file flags precede dotted: {line:?}");
                }
            }
            assert_eq!(
                helper_flags_for(leaf, body, "--cfg dotted"),
                words(&["--cfg", "file", "--cfg", "dotted"]),
                "{leaf}"
            );
            let log = wrapper_argv_log(&dir, &format!("{n}-empty"), leaf, body, "");
            assert!(
                log.lines().any(|line| line.contains("--cfg file")),
                "file flag survives an empty dotted value: {log:?}"
            );
            assert!(
                !log.contains("--cfg dotted"),
                "empty dotted value adds nothing: {log:?}"
            );
            assert_eq!(
                helper_flags_for(leaf, body, ""),
                words(&["--cfg", "file"]),
                "{leaf}"
            );
        }
    }
}
