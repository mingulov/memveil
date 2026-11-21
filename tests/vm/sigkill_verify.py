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

# Owned capture members per scenario, bound to the product writer's file
# lifecycle and the fault-shim stop points (not a bare list):
# - EventWriter::new creates events.ndjson (src/capture/writer.rs:461-470).
# - LiveWriter::create runs prepare(), which creates the EMPTY
#   session.finalizing staging file AND the 17 MiB .finalization-reserve
#   (src/capture/writer.rs:584-591) before any append; the product's own
#   live.rs::reserves_before_append asserts both exist right after create
#   with staging size 0. So session.finalizing is present at EVERY
#   post-setup kill, not only during finalization.
# - The readiness checkpoint publishes checkpoint.json BEFORE the `ready`
#   line (src/capture/collector.rs:1568 vs :1604), so every post-readiness
#   kill sees all four files.
# - The checkpoint-2 shim stops the collector inside checkpoint #2's
#   post-rename dir syncs (tests/cli/capture_faults.c:70-77,84-87),
#   before the exchanged previous checkpoint is removed
#   (src/capture/writer.rs:732-734), so the checkpoint kill also sees
#   checkpoint.json.tmp holding the previous generation.
# A SIGKILL always precedes final publication, so session.json must never
# exist (final-stop halts at the session.json rename itself,
# tests/cli/capture_faults.c:82).
# The finalization set is the final-stop halt INSIDE finalize(), derived
# per name from the writer lifecycle and the shim stop point:
# - .finalization-reserve: ABSENT. finalize() releases it first
#   (src/capture/writer.rs:928-936 calls release_reserve, which unlinks
#   it at :1212), before staging (:945) and the stopped rename (:989).
# - session.finalizing: PRESENT, filled with the session document.
#   prepare() creates it empty (:584); fill_or_write_stage (:945) fills
#   it via fill_stage (:1226-1251); the rename to session.json at :989
#   never runs because the shim raises SIGSTOP first
#   (tests/cli/capture_faults.c:82).
# - session.json: ABSENT. It is the rename target at :989 that never runs.
# - checkpoint.json: PRESENT. finalize() removes it only after the rename
#   succeeds (:1047-1056), which never happens here.
# - checkpoint.json.tmp: ABSENT. Every completed checkpoint exchange
#   removes the previous generation (:732-734), and no checkpoint is in
#   flight during finalize().
# - session.json.tmp: ABSENT. Only the unprepared finalize path stages
#   here (:1269); record always prepares (checkpoint() calls prepare()
#   at :652, and the armed readiness capture holds the reserve).
# - events.ndjson: PRESENT, created by EventWriter::new (:461) and fsynced
#   in finalize() before staging (:937).
CAPTURE_INVENTORY = {
    'readiness': frozenset(('.finalization-reserve', 'checkpoint.json',
                            'events.ndjson', 'session.finalizing')),
    'checkpoint': frozenset(('.finalization-reserve', 'checkpoint.json',
                             'checkpoint.json.tmp', 'events.ndjson',
                             'session.finalizing')),
    'finalization': frozenset(('checkpoint.json', 'events.ndjson',
                               'session.finalizing')),
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
    if scenario == 'finalization':
        # finalize() unlinks the reserve before the stopped rename, so
        # ABSENCE is the release proof here; a still-present reserve is
        # an unreleased one, not a proof.
        if doc.get('reserve_released') is not True:
            raise ValueError('finalization barrier must prove '
                             'reserve release')
        if doc.get('reserve_allocated') is not None:
            raise ValueError('finalization barrier must not claim '
                             'allocated reserve')
    else:
        if not isinstance(doc.get('reserve_allocated'), int) or \
                doc['reserve_allocated'] < RESERVE_BYTES:
            raise ValueError('allocated 17 MiB reserve missing at barrier')
        if doc.get('reserve_released') is not False:
            raise ValueError('reserve release misreported '
                             'before finalization')
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
