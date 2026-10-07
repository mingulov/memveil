# SPDX-License-Identifier: GPL-3.0-or-later

"""Renderer unit tests: escaping plus golden text/Markdown reports.

Golden files pin the exact text and Markdown layouts; the JSON
renderer is pinned here for well-formedness and escaping, and in the
reports lane against the schema oracle plus A01's expected counts.
"""

from std.pathlib import Path
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.attempts import AttemptAnalyzer
from memveil.capture.reader import default_limits, read_capture
from memveil.cli.report import (
    check_rendered_size,
    exit_for_report,
    neutralize_controls,
    sanitize_diagnostic,
    scrub_paths,
)
from memveil.jsonscan import Scanner
from memveil.model.report import Report
from memveil.render.render import RenderError, render
from memveil.render.text import escape_text, render_text
from memveil.render.json import escape_json, render_json
from memveil.render.markdown import escape_markdown, render_markdown


def analyze(dir: String) raises -> Report:
    var r = read_capture(dir, False, default_limits())
    var a = AttemptAnalyzer(r.session)
    while r.has_more():
        a.consume(r.next_event())
    return a.finish(r.session.window_end_ns, r.partial)


def parsed(doc: String) raises -> String:
    var s = Scanner(doc)
    var out = s.parse_string()
    return out


def test_escape_text() raises:
    var fffd = parsed(String('"\\ufffd"'))
    var e9 = parsed(String('"\\u00e9"'))
    var inp = parsed(String('"a\\n\\t\\r\\u001bb\\u0001c\\u007fd\\u00e9e"'))
    var got = escape_text(inp)
    var want = (
        String("a\\n\\t\\r")
        + fffd
        + String("b")
        + fffd
        + String("c")
        + fffd
        + String("d")
        + e9
        + String("e")
    )
    assert_equal(got, want)


def test_escape_text_clean_passthrough() raises:
    assert_equal(escape_text(String("plain-1.5 ok")), String("plain-1.5 ok"))
    assert_equal(
        escape_text(String("café ☺")), String("café ☺")
    )


def test_scrub_paths() raises:
    assert_equal(
        scrub_paths(
            String(
                "/nonexistent-bridge-dir/nolib.so: cannot open shared"
                " object file"
            )
        ),
        String("nolib.so: cannot open shared object file"),
    )
    assert_equal(
        scrub_paths(String("~/lib/x.so failed")),
        String("x.so failed"),
    )
    # Spaced paths split into tokens; every token still loses
    # everything through its last slash, so middle components
    # (including home directories) never survive.
    assert_equal(
        scrub_paths(String("/opt/my dir/x.so: bad")),
        String("my x.so: bad"),
    )
    assert_equal(
        scrub_paths(String("op=open domain=bridge code=2: ok")),
        String("op=open domain=bridge code=2: ok"),
    )
    assert_equal(scrub_paths(String("")), String(""))
    assert_equal(scrub_paths(String("/")), String(""))
    # Fail-closed direction: any slash token loses its head, even
    # prose like and/or. Diagnostics must not rely on slashes.
    assert_equal(scrub_paths(String("reads/writes")), String("writes"))


def test_escape_json_roundtrip() raises:
    var cases = List[String]()
    cases.append(String("plain"))
    cases.append(parsed(String('"a\\"b\\\\c\\/d\\u00e9\\ud83d\\ude00"')))
    cases.append(parsed(String('"x\\u0001\\u001b\\u007f\\n\\t end"')))
    for i in range(len(cases)):
        var enc = escape_json(cases[i])
        var back = parsed(enc)
        assert_equal(back, cases[i])
    assert_equal(escape_json(String("a")), String('"a"'))
    assert_equal(
        escape_json(String('say "hi"')), String('"say \\"hi\\""')
    )


def test_escape_markdown() raises:
    assert_equal(
        escape_markdown(String("a|b*c_d[e]f`g\\h")),
        String("a\\|b\\*c\\_d\\[e\\]f\\`g\\\\h"),
    )
    assert_equal(
        escape_markdown(String("plain (v1.5): ok")),
        String("plain (v1.5): ok"),
    )
    assert_equal(
        escape_markdown(String("a&b<c>d")),
        String("a&amp;b&lt;c&gt;d"),
    )
    # Review html-label payload: comments and tags must not survive.
    assert_equal(
        escape_markdown(
            String("<!-- hidden --> <strong>forged</strong>")
        ),
        String(
            "&lt;!-- hidden --&gt; &lt;strong&gt;forged&lt;/strong&gt;"
        ),
    )
    # Entity-shaped input is escaped, never decoded: no double unescape.
    assert_equal(
        escape_markdown(String("&lt;already&gt;")),
        String("&amp;lt;already&amp;gt;"),
    )
    # Plain text has no tag layer: angle brackets stay literal while
    # controls are still neutralized.
    assert_equal(
        escape_text(String("<b>x</b>")),
        String("<b>x</b>"),
    )
    assert_equal(
        escape_markdown(String("<!-- hidden --> <strong>x</strong>")),
        String("&lt;!-- hidden --&gt; &lt;strong&gt;x&lt;/strong&gt;"),
    )


def test_rendered_size_limit() raises:
    check_rendered_size(String("tiny"), 100)
    var raised = False
    try:
        check_rendered_size(String("too big"), 4)
    except:
        raised = True
    assert_true(raised)


def test_render_json_tristate_echo() raises:
    var rep = analyze(String("tests/fixtures/reader/f6-absent-asserted"))
    var doc = render_json(rep)
    assert_equal(doc.find(String('"asserted_mode":')), -1)
    assert_true(doc.find(String('"driver":')) != -1)
    var rep2 = analyze(String("tests/fixtures/reader/f6-absent-driver"))
    var doc2 = render_json(rep2)
    assert_equal(doc2.find(String('"driver":')), -1)
    assert_true(doc2.find(String('"asserted_mode":')) != -1)


def test_render_text_attempts() raises:
    var rep = analyze(String("tests/fixtures/attempts"))
    var want = Path("tests/golden/report-attempts.txt").read_text()
    assert_equal(render_text(rep), want)


def test_render_text_escape() raises:
    var rep = analyze(String("tests/fixtures/reader/escape"))
    var want = Path("tests/golden/report-escape.txt").read_text()
    assert_equal(render_text(rep), want)


def test_render_markdown_attempts() raises:
    var rep = analyze(String("tests/fixtures/attempts"))
    var want = Path("tests/golden/report-attempts.md").read_text()
    assert_equal(render_markdown(rep), want)


def test_render_markdown_escape() raises:
    var rep = analyze(String("tests/fixtures/reader/escape"))
    var want = Path("tests/golden/report-escape.md").read_text()
    assert_equal(render_markdown(rep), want)


def test_render_json_wellformed() raises:
    var rep = analyze(String("tests/fixtures/reader/escape"))
    var out = render_json(rep)
    var s = Scanner(out)
    s.skip_value()
    s.skip_ws()
    assert_true(s.at_end())


def test_render_json_escapes() raises:
    var rep = analyze(String("tests/fixtures/reader/escape"))
    var out = render_json(rep)
    var parts = out.split(String('"a\\"b\\\\c|d_e*f[g]h`i&<j>k"'))
    assert_equal(len(parts), 2)
    var drv = out.split(String('"dr\\nv\\u001be"'))
    assert_equal(len(drv), 2)


def test_f12_sanitize_diagnostic() raises:
    var esc = parsed(String('"\\u001b[2J"'))
    var nl = parsed(String('"\\n"'))
    var dele = parsed(String('"\\u007f"'))
    var e9 = parsed(String('"\\u00e9"'))
    var fffd = parsed(String('"\\ufffd"'))
    var frag = (
        String("opt ") + esc + nl + String("next") + dele
        + String(" ") + e9
    )
    var clean = sanitize_diagnostic(frag)
    var raw = clean.as_bytes()
    for i in range(len(raw)):
        var b = raw[i]
        assert_true(b == UInt8(0x5C) or b >= UInt8(0x20))
    assert_true(clean.find(String("\\n")) != -1)
    assert_true(clean.find(esc) == -1)
    assert_true(clean.find(e9) != -1)
    var multi = (
        String("usage:") + nl + String("  memveil ") + esc
        + String(" report") + nl
    )
    var kept = neutralize_controls(multi)
    assert_true(
        kept.find(String("usage:") + nl + String("  memveil ")) != -1
    )
    assert_true(kept.find(esc) == -1)
    assert_true(kept.find(fffd) != -1)
    var kraw = kept.as_bytes()
    for i in range(len(kraw)):
        var b = kraw[i]
        assert_true(
            b == UInt8(0x0A) or b == UInt8(0x5C) or b >= UInt8(0x20)
        )


def test_f10_optional_correlation_exit() raises:
    var clean = analyze(String("tests/fixtures/attempts"))
    assert_equal(exit_for_report(clean), 0)
    var unrequested = analyze(
        String("tests/fixtures/reader/optional-correlation")
    )
    assert_equal(unrequested.q_correlation.status, "partial")
    assert_equal(exit_for_report(unrequested), 0)
    var gapped = analyze(
        String("tests/fixtures/reader/f8-correlation-gap")
    )
    assert_equal(gapped.q_correlation.status, "partial")
    assert_equal(exit_for_report(gapped), 0)
    var disagree = analyze(
        String("tests/fixtures/reader/f9-mismatch")
    )
    assert_true(disagree.counter_disagreement)
    assert_equal(exit_for_report(disagree), 4)


def test_device_name_filter_resolves() raises:
    var rep = analyze(String("tests/fixtures/attempts"))
    # The catalog names dev-1 "testdev0": filtering by the name
    # must show exactly the id-filtered rows.
    var by_name = render_text(rep, String("testdev0"))
    var by_id = render_text(rep, String("dev-1"))
    assert_equal(by_name, by_id)
    assert_true(by_name.find("{device=dev-1}") != -1)
    var unknown = render_text(rep, String("nope"))
    assert_true(unknown.find("{device=") == -1)
    assert_equal(
        render_json(rep, String("testdev0")),
        render_json(rep, String("dev-1")),
    )
    assert_equal(
        render_markdown(rep, String("testdev0")),
        render_markdown(rep, String("dev-1")),
    )


def test_render_dispatch() raises:
    var rep = analyze(String("tests/fixtures/attempts"))
    var t = render(rep, String("text"))
    var j = render(rep, String("json"))
    var m = render(rep, String("markdown"))
    assert_true(t != j)
    assert_true(t != m)
    assert_true(j != m)
    var raised = False
    try:
        _ = render(rep, String("yaml"))
    except e:
        raised = True
        assert_true(e.message.byte_length() > 0)
    assert_true(raised)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_escape_text]()
    suite.test[test_escape_text_clean_passthrough]()
    suite.test[test_scrub_paths]()
    suite.test[test_escape_json_roundtrip]()
    suite.test[test_escape_markdown]()
    suite.test[test_render_text_attempts]()
    suite.test[test_render_text_escape]()
    suite.test[test_render_markdown_attempts]()
    suite.test[test_render_markdown_escape]()
    suite.test[test_render_json_wellformed]()
    suite.test[test_render_json_escapes]()
    suite.test[test_render_json_tristate_echo]()
    suite.test[test_rendered_size_limit]()
    suite.test[test_device_name_filter_resolves]()
    suite.test[test_render_dispatch]()
    suite.test[test_f10_optional_correlation_exit]()
    suite.test[test_f12_sanitize_diagnostic]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
