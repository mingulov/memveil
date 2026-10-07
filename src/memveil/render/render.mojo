# SPDX-License-Identifier: GPL-3.0-or-later

"""Format dispatch for report rendering."""

from memveil.model.report import Report
from memveil.render.json import render_json
from memveil.render.markdown import render_markdown
from memveil.render.text import render_text


@fieldwise_init
struct RenderError(Copyable, Writable):
    """One rendering failure."""

    var message: String


def render(
    rep: Report, format: String, device_filter: String = ""
) raises RenderError -> String:
    """Render the report in the named format.

    Accepts text, json, and markdown; anything else raises. A
    non-empty device filter shows global rows plus only the
    matching device's per-device rows.
    """
    if format != "text" and format != "json" and format != "markdown":
        raise RenderError("unknown format: " + format)
    try:
        if format == "json":
            return render_json(rep, device_filter)
        if format == "markdown":
            return render_markdown(rep, device_filter)
        return render_text(rep, device_filter)
    except e:
        raise RenderError("render failed: " + String(e))
