#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Operator phase for the durability checkpoint leg (owned-I/O leg).

An idle guest does not establish the nonempty checkpoint case. The
operator arranges a reproducible owned-I/O sweep before the capture
boot, the guest runs that sweep while the collector records and
writes window markers to the oracle log, and the verdict judges two
predicates: same-UUID recovery across the power cut, and a durable
prefix independently re-verified from raw bytes. Both judgments are
retained. Sampling evidence alone, without operator records, leaves
the leg NOT RUN -- never PASS.

This module is shared by the runner, the guest flow, and the offline
dry-run. It never boots a guest and needs no armed variables; the raw
bytes it re-verifies come from the recorded fixture (dry-run) or from
the guest that holds the owned disk (live recover phase).
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SCHEMA = 'memveil-durability-operator/1'
ORACLE_LOG_NAME = 'oracle.log'
OPERATOR_PLAN_NAME = 'operator-plan.json'
OPERATOR_VERDICT_NAME = 'operator-verdict.json'
OPERATOR_WINDOW_NAME = 'operator-window.json'

WORKLOAD_ID = 'owned-io-sweep/1'
WORKLOAD_BLOCK_BYTES = 65536
WORKLOAD_BLOCK_COUNT = 64
WORKLOAD_SEED = '9f2c4a7e0b1d8e3f6a5c7d9e0b1d4a6c'
WORKLOAD_TARGET = 'operator-io'


def workload_spec():
    """The one reproducible sweep the operator arranges."""
    return dict(id=WORKLOAD_ID, block_bytes=WORKLOAD_BLOCK_BYTES,
                block_count=WORKLOAD_BLOCK_COUNT,
                total_bytes=WORKLOAD_BLOCK_BYTES * WORKLOAD_BLOCK_COUNT,
                seed=WORKLOAD_SEED, target=WORKLOAD_TARGET)


def sweep_block(spec, index):
    """Deterministic block bytes: the seed plus the block index."""
    digest = hashlib.sha256(
        bytes.fromhex(spec['seed']) + index.to_bytes(8, 'little')).digest()
    repeats, rest = divmod(spec['block_bytes'], len(digest))
    return digest * repeats + digest[:rest]


def expected_workload_sha(spec):
    h = hashlib.sha256()
    for index in range(spec['block_count']):
        h.update(sweep_block(spec, index))
    return h.hexdigest()


def run_workload(mount, spec):
    """Stream the arranged sweep onto owned storage and read it back.

    mount is the owned filesystem root; the target stays a plain file
    name inside it. Returns the observed byte counts and content hash.
    """
    target = spec['target']
    if '/' in target or target in ('', '.', '..') or Path(target).name != target:
        raise ValueError('operator workload target escapes its mount')
    path = Path(mount) / target
    written, hasher = 0, hashlib.sha256()
    with open(path, 'wb') as stream:
        for index in range(spec['block_count']):
            block = sweep_block(spec, index)
            stream.write(block)
            hasher.update(block)
            written += len(block)
        stream.flush()
    import os
    with open(path, 'rb') as stream:
        os.fsync(stream.fileno())
    observed, read = hashlib.sha256(), 0
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            observed.update(block)
            read += len(block)
    if observed.hexdigest() != hasher.hexdigest():
        raise ValueError('operator workload readback differs from its writes')
    return dict(bytes_written=written, bytes_read=read,
                workload_sha256=observed.hexdigest())


def write_plan(case, nonce):
    """Retain the arranged sweep for one checkpoint case."""
    plan = dict(schema=SCHEMA, scenario='checkpoint', nonce=nonce,
                workload=workload_spec())
    path = Path(case) / OPERATOR_PLAN_NAME
    path.write_text(json.dumps(plan, indent=2, sort_keys=True) + '\n')
    return plan


def parse_markers(text):
    """Strict oracle-log lines: JSON objects with a known marker."""
    rows = []
    for line in text.splitlines():
        if not line.strip():
            raise ValueError('operator oracle log has a foreign line')
        try:
            row = json.loads(line)
        except ValueError:
            raise ValueError('operator oracle log has a foreign line')
        if not isinstance(row, dict) or row.get('marker') not in ('window-start', 'window-end'):
            raise ValueError('operator oracle log has a foreign line')
        rows.append(row)
    return rows


def validate_window(plan, text):
    """Judge the recorded I/O window against the arranged plan."""
    rows = parse_markers(text)
    starts = [row for row in rows if row['marker'] == 'window-start']
    ends = [row for row in rows if row['marker'] == 'window-end']
    if len(starts) != 1:
        raise ValueError('operator window is missing its start marker')
    if len(ends) != 1:
        raise ValueError('operator window is missing its end marker')
    start, end = starts[0], ends[0]
    if rows.index(start) > rows.index(end):
        raise ValueError('operator window markers out of order')
    spec = plan['workload']
    for row in (start, end):
        if row.get('workload') != spec['id'] or row.get('nonce') != plan['nonce']:
            raise ValueError('operator window breaks the arranged plan')
    if start.get('seq') != '0' or end.get('seq') != '1':
        raise ValueError('operator window breaks the arranged plan')
    if int(end['mono_ns']) <= int(start['mono_ns']):
        raise ValueError('operator window markers out of order')
    if int(end.get('bytes_written', '0')) <= 0 or int(end.get('bytes_read', '0')) <= 0:
        raise ValueError('operator window recorded no owned I/O')
    if end.get('bytes_written') != str(spec['total_bytes']) or \
            end.get('bytes_read') != str(spec['total_bytes']):
        raise ValueError('operator workload bytes differ from the arranged sweep')
    if end.get('workload_sha256') != expected_workload_sha(spec):
        raise ValueError('operator workload bytes differ from the arranged sweep')
    return dict(start_ns=start['mono_ns'], end_ns=end['mono_ns'],
                bytes_written=end['bytes_written'], bytes_read=end['bytes_read'],
                workload_sha256=end['workload_sha256'])


def independent_prefix(raw_capture):
    """Re-derive the durable prefix from raw capture bytes.

    Returns (integrity, detail): the independently re-verified
    integrity dict, or (None, reason) when the raw bytes refuse it.
    """
    if str(ROOT / 'tests/cli') not in sys.path:
        sys.path.insert(0, str(ROOT / 'tests/cli'))
    from test_checkpoint_writer import independent
    try:
        doc = independent(Path(raw_capture))
    except (AssertionError, ValueError, KeyError, OSError) as exc:
        return None, 'raw bytes refuse the claimed prefix: ' + str(exc)
    if doc is None:
        return None, 'raw bytes hold no checkpoint prefix'
    return doc['capture']['integrity'], 're-verified from raw bytes'


def judge_verdict(promised, recovered_fs_uuid, raw_capture):
    """Judge same-UUID recovery plus the raw-bytes prefix re-check."""
    uuid_ok = recovered_fs_uuid == promised['fs_uuid']
    recovered, detail = independent_prefix(raw_capture)
    prefix_ok = recovered is not None and recovered == promised['integrity']
    predicates = {
        'same_uuid_recovery': dict(
            status='PASS' if uuid_ok else 'FAIL',
            promised_fs_uuid=promised['fs_uuid'],
            recovered_fs_uuid=recovered_fs_uuid),
        'prefix_reverified_from_raw_bytes': dict(
            status='PASS' if prefix_ok else 'FAIL',
            promised_events_sha256=promised['integrity']['events_sha256'],
            promised_line_count=promised['integrity']['line_count'],
            recovered_events_sha256=recovered['events_sha256'] if recovered else None,
            recovered_line_count=recovered['line_count'] if recovered else None,
            detail=detail if prefix_ok else (
                detail if recovered is None else 'durable prefix changed across remount')),
    }
    return dict(schema=SCHEMA, nonce=promised['nonce'], scenario=promised['scenario'],
                status='PASS' if uuid_ok and prefix_ok else 'FAIL',
                predicates=predicates)


def validate_verdict(verdict, promised):
    """Re-judge a retained verdict: every PASS claim must cohere."""
    if verdict.get('schema') != SCHEMA or verdict.get('nonce') != promised['nonce'] \
            or verdict.get('scenario') != promised['scenario']:
        raise ValueError('operator verdict claim does not match its retained values')
    predicates = verdict.get('predicates') or {}
    uuid_pred = predicates.get('same_uuid_recovery') or {}
    prefix_pred = predicates.get('prefix_reverified_from_raw_bytes') or {}
    uuid_ok = uuid_pred.get('promised_fs_uuid') == promised['fs_uuid'] \
        and uuid_pred.get('recovered_fs_uuid') == promised['fs_uuid']
    prefix_ok = prefix_pred.get('promised_events_sha256') == promised['integrity']['events_sha256'] \
        and prefix_pred.get('promised_line_count') == promised['integrity']['line_count'] \
        and prefix_pred.get('recovered_events_sha256') == promised['integrity']['events_sha256'] \
        and prefix_pred.get('recovered_line_count') == promised['integrity']['line_count']
    if uuid_pred.get('status') != ('PASS' if uuid_ok else 'FAIL') \
            or prefix_pred.get('status') != ('PASS' if prefix_ok else 'FAIL') \
            or verdict.get('status') != ('PASS' if uuid_ok and prefix_ok else 'FAIL'):
        raise ValueError('operator verdict claim does not match its retained values')
    return verdict['status']


def leg_status(case):
    """Campaign judgment for one checkpoint case directory.

    Operator records absent means the run repeated sampling alone:
    the leg is NOT RUN, never PASS. Present records are re-judged.
    """
    case = Path(case)
    plan_path = case / OPERATOR_PLAN_NAME
    log_path = case / 'export' / ORACLE_LOG_NAME
    barrier_path = case / 'export' / 'barrier.json'
    verdict_path = case / 'export' / OPERATOR_VERDICT_NAME
    retained = case / OPERATOR_VERDICT_NAME
    if not plan_path.is_file() or not log_path.is_file() or not barrier_path.is_file() \
            or (not verdict_path.is_file() and not retained.is_file()):
        return 'NOT RUN'
    try:
        plan = json.loads(plan_path.read_text())
        validate_window(plan, log_path.read_text())
        source = verdict_path if verdict_path.is_file() else retained
        return validate_verdict(json.loads(source.read_text()),
                                json.loads(barrier_path.read_text()))
    except ValueError:
        return 'FAIL'


def dry_run(fixture, out):
    """Offline verdict over recorded operator evidence (no guests)."""
    fixture, out = Path(fixture), Path(out)
    plan_path = fixture / OPERATOR_PLAN_NAME
    log_path = fixture / ORACLE_LOG_NAME
    barrier_path = fixture / 'barrier.json'
    recovered_path = fixture / 'recovered.json'
    raw_capture = fixture / 'raw-capture'
    if not plan_path.is_file() or not log_path.is_file() or not barrier_path.is_file() \
            or not recovered_path.is_file() or not (raw_capture / 'checkpoint.json').is_file():
        return 'NOT RUN', 'recorded operator evidence absent: sampling alone leaves the leg open'
    plan = json.loads(plan_path.read_text())
    try:
        window = validate_window(plan, log_path.read_text())
    except ValueError as exc:
        return 'FAIL', str(exc)
    promised = json.loads(barrier_path.read_text())
    recovered = json.loads(recovered_path.read_text())
    verdict = judge_verdict(promised, recovered['fs_uuid'], raw_capture)
    out.mkdir(mode=0o700)
    (out / 'window.json').write_text(json.dumps(window, indent=2, sort_keys=True) + '\n')
    (out / 'verdict.json').write_text(json.dumps(verdict, indent=2, sort_keys=True) + '\n')
    if verdict['status'] != 'PASS':
        failed = sorted(name for name, pred in verdict['predicates'].items()
                        if pred['status'] != 'PASS')
        return 'FAIL', 'operator predicates failed: ' + ', '.join(failed)
    return 'PASS', 'same-UUID recovery and raw-bytes prefix both re-verified'


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Offline dry-run of the durability operator verdict over '
                    'recorded fixtures. Never boots a guest. Exit 0 on PASS, '
                    '1 on FAIL, 3 when operator evidence is absent (NOT RUN).')
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        status, detail = dry_run(args.fixture, args.out)
    except (OSError, ValueError) as exc:
        print('operator-dry-run: FAIL: ' + str(exc))
        return 1
    print('operator-dry-run: ' + status + ': ' + detail)
    return {'PASS': 0, 'FAIL': 1, 'NOT RUN': 3}[status]


if __name__ == '__main__':
    raise SystemExit(main())
