// SPDX-License-Identifier: GPL-3.0-or-later
//! Unarmed negative-object oracle: parse-only judgments.
//!
//! Reads each object path from argv and prints one JSON document
//! mapping path to the loader-visible parse: declared maps (name,
//! type, key/value size, max entries, exactly the rows the session
//! declared-map gate compares), program names with their section
//! kinds, and whether the object carries BTF CO-RE relocations.
//! Pure parse: no BPF syscalls, no loads, nothing privileged.
//! Exit 0 with JSON on stdout; any parse failure exits 1 naming
//! the object.

use std::collections::BTreeMap;

fn section_kind(program: &aya_obj::ProgramSection) -> &'static str {
    match program {
        aya_obj::ProgramSection::TracePoint => "tracepoint",
        aya_obj::ProgramSection::FEntry { .. } => "fentry",
        aya_obj::ProgramSection::FExit { .. } => "fexit",
        _ => "other",
    }
}

/// One JSON string literal; object-carried names are escaped.
fn lit(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn main() {
    let mut docs: BTreeMap<String, String> = BTreeMap::new();
    let mut failed = false;
    for path in std::env::args().skip(1) {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("oracle: cannot read {path}: {error}");
                failed = true;
                continue;
            }
        };
        let object = match aya_obj::Object::parse(&bytes) {
            Ok(object) => object,
            Err(error) => {
                eprintln!("oracle: cannot parse {path}: {error}");
                failed = true;
                continue;
            }
        };
        let mut maps: Vec<String> = object
            .maps
            .iter()
            .map(|(name, map)| {
                format!(
                    "{{\"name\":{},\"type\":{},\"key_size\":{},\"value_size\":{},\"max_entries\":{}}}",
                    lit(name),
                    map.map_type(),
                    map.key_size(),
                    map.value_size(),
                    map.max_entries(),
                )
            })
            .collect();
        maps.sort();
        let mut programs: Vec<String> = object
            .programs
            .iter()
            .map(|(name, program)| {
                format!(
                    "{{\"name\":{},\"section\":{}}}",
                    lit(name),
                    lit(section_kind(&program.section)),
                )
            })
            .collect();
        programs.sort();
        docs.insert(
            path,
            format!(
                "{{\"maps\":[{}],\"programs\":[{}],\"btf_relocations\":{}}}",
                maps.join(","),
                programs.join(","),
                object.has_btf_relocations(),
            ),
        );
    }
    let body: Vec<String> = docs
        .iter()
        .map(|(path, doc)| format!("{}:{doc}", lit(path)))
        .collect();
    println!("{{{}}}", body.join(","));
    if failed {
        std::process::exit(1);
    }
}
