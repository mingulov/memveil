// SPDX-License-Identifier: GPL-3.0-or-later
//! Probe differential: the Plan 1 bpf probe and the Plan 2 narrow probe must
//! agree exactly over a shared corpus — identical encoded tables and moved
//! flags on success, identical refusal strings on failure. The live path
//! uses narrow's probe while `bpf::probe_trace_offsets` stays re-exported,
//! so this test is the link pinning the two implementations together.

use memveil::bpf::probe_trace_offsets as bpf_probe;
use memveil::platform::narrow::{encode_offsets_table, probe_trace_offsets as narrow_probe};

/// Pinned-format bytes mirroring the live `swiotlb_bounced` layout.
fn pinned_format() -> Vec<u8> {
    b"name: swiotlb_bounced\nID: 403\nformat:\n\
      \tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
      \tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\
      \tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\
      \tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\
      \n\
      \tfield:__data_loc char[] dev_name;\toffset:8;\tsize:4;\tsigned:0;\n\
      \tfield:u64 dma_mask;\toffset:16;\tsize:8;\tsigned:0;\n\
      \tfield:dma_addr_t dev_addr;\toffset:24;\tsize:8;\tsigned:0;\n\
      \tfield:size_t size;\toffset:32;\tsize:8;\tsigned:0;\n\
      \tfield:bool force;\toffset:40;\tsize:1;\tsigned:0;\n"
        .to_vec()
}

/// Pinned format with one textual substitution applied.
fn substituted(from: &str, to: &str) -> Vec<u8> {
    String::from_utf8(pinned_format())
        .expect("pinned format is ASCII")
        .replace(from, to)
        .into_bytes()
}

fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut cases: Vec<(&'static str, Vec<u8>)> = vec![
        ("pinned", pinned_format()),
        (
            "moved-size",
            substituted("size;\toffset:32;", "size;\toffset:48;"),
        ),
        (
            "moved-force",
            substituted("force;\toffset:40;", "force;\toffset:44;"),
        ),
        (
            "missing-force",
            substituted("\tfield:bool force;\toffset:40;\tsize:1;\tsigned:0;\n", ""),
        ),
        (
            "missing-anchor",
            substituted(
                "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n",
                "",
            ),
        ),
        (
            "retype-force",
            substituted("field:bool force;", "field:u8 force;"),
        ),
        (
            "resize-size",
            substituted(
                "field:size_t size;\toffset:32;\tsize:8;",
                "field:size_t size;\toffset:32;\tsize:4;",
            ),
        ),
        (
            "anchor-type-drift",
            substituted(
                "field:unsigned short common_type;",
                "field:u16 common_type;",
            ),
        ),
        (
            "anchor-offset-drift",
            substituted(
                "field:unsigned short common_type;\toffset:0;",
                "field:unsigned short common_type;\toffset:4;",
            ),
        ),
        (
            "overlap-size-force",
            substituted("force;\toffset:40;", "force;\toffset:36;"),
        ),
        (
            "cap-breach-size",
            substituted("size;\toffset:32;", "size;\toffset:200;"),
        ),
        // Huge but parseable offset: both probes parse it (under the
        // i32::MAX parse cap) and refuse in extent validation with the
        // same string, exercising the saturating-arithmetic path values.
        (
            "huge-offset",
            substituted("size;\toffset:32;", "size;\toffset:2000000000;"),
        ),
        (
            "duplicate-force",
            [
                pinned_format(),
                b"\tfield:bool force;\toffset:40;\tsize:1;\tsigned:0;\n".to_vec(),
            ]
            .concat(),
        ),
        (
            "unparseable-line",
            [pinned_format(), b"\tfield:bogus\n".to_vec()].concat(),
        ),
        ("no-trailing-newline", {
            let mut trimmed = pinned_format();
            assert_eq!(trimmed.pop(), Some(b'\n'));
            trimmed
        }),
        ("empty", Vec::new()),
        (
            "header-only",
            b"name: swiotlb_bounced\nID: 403\nformat:\n".to_vec(),
        ),
    ];
    // NUL inside a field name: both probes must refuse identically.
    let mut nul_name = pinned_format();
    if let Some(pos) = nul_name
        .windows(b"force;".len())
        .position(|window| window == b"force;")
    {
        nul_name[pos] = 0;
    }
    cases.push(("nul-in-name", nul_name));
    cases
}

#[test]
fn probe_implementations_agree_on_corpus() {
    let mut successes = 0;
    let mut refusals = 0;
    for (name, bytes) in corpus() {
        let bpf = bpf_probe(&bytes);
        let narrow = narrow_probe(&bytes);
        match bpf {
            Ok(probed) => {
                assert!(
                    narrow.ok,
                    "{name}: bpf ok but narrow refused: {}",
                    narrow.message
                );
                assert_eq!(narrow.moved, probed.moved, "{name}: moved differs");
                let encoded = encode_offsets_table(
                    narrow.loc_off,
                    narrow.size_off,
                    narrow.force_off,
                    narrow.fixed_end,
                );
                assert_eq!(encoded, probed.table.to_vec(), "{name}: table bytes differ");
                successes += 1;
            }
            Err(error) => {
                assert!(!narrow.ok, "{name}: bpf refused but narrow ok");
                assert_eq!(narrow.message, error.to_string(), "{name}: refusal differs");
                refusals += 1;
            }
        }
    }
    assert!(successes > 0, "corpus must probe at least one success");
    assert!(refusals > 0, "corpus must probe at least one refusal");
}
