# SPDX-License-Identifier: GPL-3.0-or-later

"""Event encoder microbenchmark (development tool, not shipped).

Usage: bench_encode [iterations]
Build like the product, then run:
  pixi run --frozen mojo build -I src --target-cpu x86-64-v2 \\
      -o build/bench_encode tests/perf/bench_encode.mojo
  build/bench_encode 400000
Encodes a live-consumer mix (bounce_attempt, map_result, copy,
sync_request, unmap) through encode_event_line and prints
events/s over the best of several rounds. Throughput only; the
output bytes are pinned by the writer lane, not here.
"""

from std.sys import argv, exit

from memveil.model.encode import encode_event_line
from memveil.model.event import Event
from memveil.platform.clock import MonoClock


comptime _ROUNDS = 5
comptime _DEFAULT_ITERATIONS = 400000


def _base(seq: Int, hook: String, backend: String, corr: String) -> Event:
    var ev = Event()
    ev.session_id = String("cap-31673397184-520")
    ev.seq = UInt64(seq + 1)
    ev.ts_ns = UInt64(31868650021) + UInt64(seq) * UInt64(20989)
    ev.source_hook = hook
    ev.source_backend = backend
    ev.source_profile_id = String("linux-x86_64-7.0.0-34-generic")
    ev.source_measurement = String("observed")
    ev.source_correlation = corr
    return ev^


def _mix(n: Int) -> List[Event]:
    """Fixture-shaped events in the live lifecycle order."""
    var out = List[Event]()
    for i in range(n):
        var op = String("lc-") + String(i // 5)
        var gen = String("gen-") + String(i // 5 + 1)
        var which = i % 5
        if which == 0:
            var ev = _base(
                i, String("swiotlb:swiotlb_bounced"),
                String("tracepoint"), String("direct"),
            )
            ev.kind = String("bounce_attempt")
            ev.bounce.device_id = String("d000001")
            ev.bounce.requested_bytes = UInt64(4096)
            ev.bounce.forced = True
            ev.bounce.operation_id = String("op") + String(i // 5)
            out.append(ev^)
        elif which == 1:
            var ev = _base(
                i, String("fexit:swiotlb_tbl_map_single"),
                String("tracing"), String("direct"),
            )
            ev.kind = String("map_result")
            ev.map_result.operation_id = op
            ev.map_result.success = True
            ev.map_result.has_mapping_id = True
            ev.map_result.mapping_id = gen
            ev.map_result.has_mapped_bytes = True
            ev.map_result.mapped_bytes = UInt64(4096)
            ev.map_result.has_wire_generation = True
            ev.map_result.wire_generation = UInt64(i // 5 + 1)
            ev.map_result.has_wire_identity = True
            ev.map_result.wire_identity = String("known")
            out.append(ev^)
        elif which == 2:
            var ev = _base(
                i, String("fentry:swiotlb_bounce"),
                String("tracing"), String("unpaired"),
            )
            ev.kind = String("copy")
            ev.copy.operation_id = op
            ev.copy.direction = String("original_to_bounce")
            ev.copy.bytes = UInt64(4096)
            out.append(ev^)
        elif which == 3:
            var ev = _base(
                i, String("fentry:__swiotlb_sync_single_for_cpu"),
                String("tracing"), String("unpaired"),
            )
            ev.kind = String("sync_request")
            ev.sync.operation_id = op
            ev.sync.has_mapping_id = True
            ev.sync.mapping_id = op
            ev.sync.length = UInt64(4096)
            out.append(ev^)
        else:
            var ev = _base(
                i, String("fentry:__swiotlb_tbl_unmap_single"),
                String("tracing"), String("direct"),
            )
            ev.kind = String("unmap")
            ev.unmap.has_mapping_id = True
            ev.unmap.mapping_id = gen
            ev.unmap.has_wire_generation = True
            ev.unmap.wire_generation = UInt64(i // 5 + 1)
            ev.unmap.has_wire_identity = True
            ev.unmap.wire_identity = String("known")
            out.append(ev^)
    return out^


def main() raises:
    var iterations = _DEFAULT_ITERATIONS
    var args = argv()
    if len(args) > 2:
        print("usage: bench_encode [iterations]")
        exit(2)
    if len(args) == 2:
        iterations = Int(String(args[1]))
        if iterations <= 0:
            print("bench_encode: iterations must be positive")
            exit(2)
    var events = _mix(1000)
    var clock = MonoClock()
    var best_ns = UInt64(0)
    var total_bytes = 0
    for _ in range(_ROUNDS):
        var bytes = 0
        var t0 = clock.now()
        for i in range(iterations):
            var line = encode_event_line(events[i % len(events)])
            bytes += len(line)
        var dt = clock.now() - t0
        if best_ns == UInt64(0) or dt < best_ns:
            best_ns = dt
        total_bytes = bytes
    var rate = Float64(iterations) * 1.0e9 / Float64(best_ns)
    print(
        "bench_encode: iterations", iterations,
        "rounds", _ROUNDS,
        "bytes/round", total_bytes,
        "best_ms", Float64(best_ns) / 1.0e6,
        "events/s", Int(rate),
    )
