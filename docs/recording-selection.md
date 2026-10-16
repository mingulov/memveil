<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Recording selection

`memveil record --output DIR --device NAME` narrows one
capture to a single device. The selector is an exact
literal device name: the observed raw name bytes must
equal `NAME` byte for byte, with no glob, prefix, case
folding, or whitespace trimming. Session-local ids such
as `d000001` are assigned during the capture and are not
valid capture selectors; presentation filters accept them.

## The three scopes

A device selector narrows only device-attributed detail.
Everything else keeps its own scope:

| Scope | Selector | What it narrows |
| --- | --- | --- |
| Device | `record --device NAME` | `bounce_attempt` events only |
| Channel | `record --capability IDS` | Admits the lifecycle/copy channels as a whole |
| Global | none | Counter snapshots, pool samples, conversions, gaps, markers |

Lifecycle and copy wire records carry no device
identity, so the device selector can never narrow them:
every admitted `map_result`, `unmap`, `copy`, and
`sync_request` record is retained, and every map keeps
its unmap completion evidence. Counters, pool samples,
and conversion results are pool- or guest-wide
measurements and are likewise always retained.

Matching runs per event before catalog interning, so a
device first observed late in the capture still matches
and dropped devices consume no catalog ids. A name that
never appears selects nothing: the capture still
finalizes, with zero device rows and the selector on
record. Malformed (non-UTF8) names stay rejected under
a filter; they are never counted as selection drops.

## Recorded metadata

The selector is stored in the session capture filters
(`capture.filters.device`), and the detail quality scope
names the dropped-attempt count, for example
`3 bounce_attempt events; device selection 0000:00:1f.2
dropped 12 non-matching attempts`. Dropped attempts are
deliberate narrowing, not evidence loss: they stay out
of the loss totals.

Selectors hold 1..256 characters and are stored exactly
as given. The scope phrase is itself bounded to 256
characters, so a selector too long to name there is
elided from that phrase only (`3 bounce_attempt events;
device selection dropped 12 non-matching attempts`)
while the recorded filter keeps the literal selector.

## Replay

`memveil report DIR` and replay `memveil top DIR` read
the recorded selector from the session. Device-scoped
metric rows say `recorded devices (filter: NAME)` while
conversion, region, and other global rows keep their
window-only scope, so the two views never read as one
scope. Report scopes keep the same 256-character bound
as the session scope phrase: a selector too long to
name there renders as `recorded devices (filtered)`,
and the exact selector is preserved in the report
limitations. A global counter next to a narrowed detail
channel compares as inconclusive rather than agreeing
or disagreeing. The `top --device NAME` display filter
composes with the recorded selector and warns once when
it matches no rows.
