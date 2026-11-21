#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Mock collector and report for the SIGKILL harness self-test.

Mimics only the harness-visible protocol: a `ready session=` line, honest
checkpoint books, marker files and SIGSTOP at the fault boundary. It never
touches BPF and proves nothing about the product; it proves the harness
waits for the real boundary, delivers SIGKILL, and verifies the prefix and
cleanup through the same code the armed run uses.
"""
import hashlib
import json
import os
import signal
import sys
import time
from pathlib import Path

SESSION = 'mock-session-01'
EVENT_COUNT = 25
RESERVE_BYTES = 17 * 1048576


def write_reserve(path):
    path = Path(path)
    try:
        with open(path, 'wb') as stream:
            os.posix_fallocate(stream.fileno(), 0, RESERVE_BYTES)
    except (AttributeError, OSError):
        with open(path, 'wb') as stream:
            for _ in range(RESERVE_BYTES // 1048576):
                stream.write(b'\0' * 1048576)


def integrity_for(events, kinds, lie=False):
    digest = hashlib.sha256(events).hexdigest()
    if lie:
        digest = '0' * 63 + ('1' if digest[-1] != '1' else '2')
    counts = dict.fromkeys(kinds, 0)
    for line in events.splitlines():
        counts[json.loads(line)['kind']] += 1
    return {'events_bytes': str(len(events)),
            'line_count': str(len(events.splitlines())),
            'events_sha256': digest,
            'kinds': {key: str(value) for key, value in counts.items()}}


def checkpoint_doc(generation, events, kinds, lie=False):
    return {'session_id': SESSION,
            'capture': {'finalized': False, 'end_reason': 'checkpoint',
                        'checkpoint_generation': str(generation),
                        'integrity': integrity_for(events, kinds, lie=lie)}}


def make_events(count):
    kinds = ['bounce_attempt']
    lines = []
    for seq in range(count):
        lines.append(json.dumps({'session_id': SESSION, 'seq': str(seq),
                                 'kind': 'bounce_attempt',
                                 'ts_ns': str(1700000000000000000 + seq)}
                                ) + '\n')
    return ''.join(lines).encode(), kinds


def publish(capture, generation, events, kinds, lie=False):
    (capture / 'events.ndjson').write_bytes(events)
    (capture / 'checkpoint.json').write_text(
        json.dumps(checkpoint_doc(generation, events, kinds, lie=lie)) + '\n')


def collector(capture, marker, mode, lie=False):
    capture = Path(capture)
    capture.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_reserve(capture / '.finalization-reserve')
    events, kinds = make_events(0)
    publish(capture, 1, events, kinds)
    # The real writer stages the empty session.finalizing file at setup
    # (EventWriter::prepare), so it exists at every post-setup kill.
    (capture / 'session.finalizing').write_bytes(b'')
    previous = (capture / 'checkpoint.json').read_text()
    sys.stdout.write('ready session=%s\n' % SESSION)
    sys.stdout.flush()
    if mode == 'readiness':
        while True:
            time.sleep(1)
    if mode == 'none':
        return 0
    time.sleep(0.3)
    events, _ = make_events(EVENT_COUNT)
    generation = 3 if mode == 'checkpoint-2' else 2
    publish(capture, generation, events, kinds, lie=lie)
    if mode == 'final-stop':
        finalizing = {'session_id': SESSION,
                      'capture': checkpoint_doc(
                          generation, events, kinds)['capture']}
        finalizing['capture']['finalized'] = True
        (capture / 'session.finalizing').write_text(json.dumps(finalizing)
                                                   + '\n')
        marker_text = 'final-stop'
    elif mode == 'checkpoint-2':
        # The checkpoint-2 fault halts the collector after the exchange
        # rename but before the previous checkpoint is removed, so the
        # previous generation stays behind at checkpoint.json.tmp.
        (capture / 'checkpoint.json.tmp').write_text(previous)
        marker_text = 'checkpoint-2'
    else:
        sys.stderr.write('mock collector: unknown mode %s\n' % mode)
        return 3
    Path(marker).write_text(marker_text)
    os.kill(os.getpid(), signal.SIGSTOP)
    while True:
        time.sleep(1)


def reporter(capture, argv):
    capture = Path(capture)
    allow_partial = '--allow-partial' in argv
    wrong_exit = '--wrong-exit' in argv
    wrong_count = '--wrong-count' in argv
    final = capture / 'session.json'
    if final.exists():
        doc = json.loads(final.read_text())
        out = {'integrity': {'status': 'verified',
                             'verified_bytes': doc['capture']['integrity']['events_bytes'],
                             'verified_events': doc['capture']['integrity']['line_count']}}
        sys.stdout.write(json.dumps(out) + '\n')
        return 0
    if not allow_partial:
        sys.stderr.write('mock report: capture is unfinalized\n')
        return 0 if wrong_exit else 2
    checkpoint = json.loads((capture / 'checkpoint.json').read_text())
    sealed = checkpoint['capture']['integrity']
    size = (capture / 'events.ndjson').stat().st_size
    verified = str(int(sealed['line_count']) + 1) if wrong_count else sealed['line_count']
    out = {'integrity': {'status': 'checkpoint_prefix',
                         'verified_bytes': sealed['events_bytes'],
                         'verified_events': verified,
                         'unverified_bytes': str(size - int(sealed['events_bytes']))}}
    sys.stdout.write(json.dumps(out) + '\n')
    return 0 if wrong_exit else 4


def main(argv):
    if len(argv) < 2:
        sys.stderr.write('usage: sigkill_mock.py collector|report ...\n')
        return 2
    if argv[0] == 'collector':
        lie = '--lie' in argv
        args = [a for a in argv[1:] if a != '--lie']
        return collector(*args, lie=lie)
    if argv[0] == 'report':
        return reporter(argv[-1], argv[1:])
    sys.stderr.write('unknown mock role\n')
    return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
