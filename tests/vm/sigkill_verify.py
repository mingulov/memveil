#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared verdicts for the collector-SIGKILL recovery gate.

One definition of the barrier/result contract used by the guest flow, the
host runner and the offline self-test. The host re-derives prefix hashes and
counts from exported bytes with its own code path here, never by trusting
the collector's books or the guest's word alone.
"""
import hashlib
import json

SCENARIOS = ('readiness', 'checkpoint', 'finalization')
MARKERS = {'readiness': 'readiness-announced',
           'checkpoint': 'checkpoint-2',
           'finalization': 'final-stop'}
EMPTY_SHA = hashlib.sha256(b'').hexdigest()
RESERVE_BYTES = 17 * 1048576
KILLED_BY_SIGKILL = -9

# Owned capture members per scenario. A SIGKILL always precedes final
# publication, so session.json must never exist; session.finalizing is
# expected only when the kill lands during finalization.
CAPTURE_INVENTORY = {
    'readiness': frozenset(('.finalization-reserve', 'checkpoint.json',
                            'events.ndjson')),
    'checkpoint': frozenset(('.finalization-reserve', 'checkpoint.json',
                             'events.ndjson')),
    'finalization': frozenset(('.finalization-reserve', 'checkpoint.json',
                               'events.ndjson', 'session.finalizing')),
}
EXPORT_INVENTORY = frozenset(('barrier.json', 'result.json',
                              'prefix-events.ndjson', 'checkpoint.json',
                              'record.stderr'))


def load_json(path):
    with open(path, 'r', encoding='utf-8') as stream:
        return json.load(stream)


def recompute_prefix(events_bytes, checkpoint_doc):
    """Independently re-derive the durable prefix integrity.

    Reads only raw event bytes plus the checkpoint's declared extent and
    session binding, then re-checks the digest, line framing, per-line
    session/sequence binding and per-kind counts. Raises ValueError on any
    mismatch; returns the recomputed integrity dict otherwise.
    """
    declared = checkpoint_doc['capture']['integrity']
    extent = int(declared['events_bytes'])
    if extent < 0 or extent > len(events_bytes):
        raise ValueError('prefix extent exceeds retained bytes')
    prefix = bytes(events_bytes[:extent])
    digest = hashlib.sha256(prefix).hexdigest()
    if digest != declared['events_sha256']:
        raise ValueError('prefix sha256 mismatch: recomputed %s declared %s'
                         % (digest, declared['events_sha256']))
    lines = prefix.splitlines(keepends=True)
    if any(not line.endswith(b'\n') for line in lines):
        raise ValueError('prefix holds an unterminated line')
    if len(lines) != int(declared['line_count']):
        raise ValueError('prefix line count mismatch: recomputed %d declared %s'
                         % (len(lines), declared['line_count']))
    counts = dict.fromkeys(declared['kinds'], 0)
    for seq, line in enumerate(lines):
        event = json.loads(line.decode('utf-8'))
        if event.get('session_id') != checkpoint_doc['session_id']:
            raise ValueError('prefix line %d binds to another session' % seq)
        if event.get('seq') != str(seq):
            raise ValueError('prefix line %d breaks sequence continuity' % seq)
        if event.get('kind') not in counts:
            raise ValueError('prefix line %d carries an undeclared kind' % seq)
        counts[event['kind']] += 1
    rendered = {key: str(value) for key, value in counts.items()}
    if rendered != declared['kinds']:
        raise ValueError('prefix kind counts mismatch')
    return {'events_bytes': str(extent), 'line_count': str(len(lines)),
            'events_sha256': digest, 'kinds': rendered}


def validate_barrier(doc, nonce, scenario, inputs):
    """Check a pre-kill barrier snapshot. Raises ValueError."""
    if doc.get('nonce') != nonce:
        raise ValueError('barrier ownership nonce mismatch')
    if doc.get('scenario') != scenario:
        raise ValueError('barrier scenario mismatch')
    if doc.get('stopped') is not True:
        raise ValueError('collector was not held at the boundary')
    if doc.get('marker') != MARKERS[scenario]:
        raise ValueError('wrong boundary marker: %r' % (doc.get('marker'),))
    if doc.get('ready_observed') is not True:
        raise ValueError('readiness announcement not observed')
    if not isinstance(doc.get('reserve_allocated'), int) or \
            doc['reserve_allocated'] < RESERVE_BYTES:
        raise ValueError('allocated 17 MiB reserve missing at barrier')
    integrity = doc.get('integrity')
    if not isinstance(integrity, dict):
        raise ValueError('barrier prefix integrity absent')
    for key in ('events_bytes', 'line_count', 'events_sha256', 'kinds'):
        if key not in integrity:
            raise ValueError('barrier integrity lacks ' + key)
    count = int(integrity['line_count'])
    if scenario == 'readiness':
        if count != 0 or integrity['events_bytes'] != '0' or \
                integrity['events_sha256'] != EMPTY_SHA:
            raise ValueError('readiness is not an empty durable prefix')
    elif count <= 0 or int(integrity['events_bytes']) <= 0:
        raise ValueError('killed prefix is empty')
    if scenario == 'finalization':
        if doc.get('session_json_absent') is not True:
            raise ValueError('final session already published before kill')
        if doc.get('finalizing_present') is not True:
            raise ValueError('finalization staging absent at kill')
    identity = doc.get('identity', {})
    if identity.get('inputs') != inputs:
        raise ValueError('candidate identity changed at barrier')
    for key in ('boot_id', 'release', 'banner', 'btf_sha256'):
        if not identity.get(key):
            raise ValueError('guest identity lacks ' + key)
    if doc.get('checkpoint_sha256') is None:
        raise ValueError('barrier checkpoint digest absent')


def validate_result(doc, barrier, inputs):
    """Check a post-kill result against its barrier. Raises ValueError."""
    if doc.get('nonce') != barrier['nonce']:
        raise ValueError('result ownership nonce mismatch')
    if doc.get('scenario') != barrier['scenario']:
        raise ValueError('result scenario mismatch')
    if doc.get('killed_by_sigkill') is not True or \
            doc.get('collector_returncode') != KILLED_BY_SIGKILL:
        raise ValueError('collector death was not SIGKILL: %r'
                         % (doc.get('collector_returncode'),))
    if doc.get('integrity') != barrier['integrity']:
        raise ValueError('durable prefix changed across the kill')
    if doc.get('checkpoint_sha256') != barrier['checkpoint_sha256']:
        raise ValueError('checkpoint bytes changed across the kill')
    report = doc.get('report', {})
    if report.get('plain_exit') != 2:
        raise ValueError('unfinalized capture did not refuse plain report')
    if report.get('partial_exit') != 4 or report.get('partial_strict_exit') != 4:
        raise ValueError('partial recovery exits are not 4/4')
    if report.get('verified_events') != barrier['integrity']['line_count']:
        raise ValueError('recovered event count disagrees with barrier')
    cleanup = doc.get('cleanup', {})
    if cleanup.get('session_json_absent') is not True:
        raise ValueError('final session appeared after the kill')
    if cleanup.get('stray_processes') not in ([], ()):
        raise ValueError('collector processes survived: %r'
                         % (cleanup.get('stray_processes'),))
    if cleanup.get('dir_lock_released') is not True:
        raise ValueError('capture directory lock still held')
    want = sorted(CAPTURE_INVENTORY[barrier['scenario']])
    if sorted(cleanup.get('capture_inventory', [])) != want:
        raise ValueError('capture inventory drift: %r'
                         % (cleanup.get('capture_inventory'),))
    if doc.get('identity', {}).get('inputs') != inputs:
        raise ValueError('candidate identity changed after the kill')


def validate_export_inventory(names, scenario):
    """The guest must export exactly the receipt set, nothing else."""
    del scenario
    if frozenset(names) != EXPORT_INVENTORY:
        raise ValueError('export inventory drift: %r' % sorted(names))
