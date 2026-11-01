#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Join independent owned native requests to a separately extracted observation projection."""
import json
import os
from pathlib import Path
import re
from owned_region import compare_observations, digest, parse_ledger

IDENTITY = {'mode', 'profile', 'kernel_release', 'kernel_source_sha256',
            'kernel_config_sha256', 'oracle_source_sha256', 'btf_sha256', 'module_sha256', 'product_sha256', 'profile_sha256'}
HASH = re.compile('[0-9a-f]{64}')
DECIMAL = re.compile('0|[1-9][0-9]*')


def exact(document, fields, schema):
    if not isinstance(document, dict) or set(document) != fields | {'schema'} or document['schema'] != schema:
        raise ValueError('invalid evidence fields or version')


def number(text):
    if not isinstance(text, str) or not DECIMAL.fullmatch(text) or int(text) >= 2**64:
        raise ValueError('invalid canonical unsigned integer')
    return int(text)


def validate(admission, native, observed):
    exact(admission, IDENTITY | {'caller', 'restore_contract', 'safety_review_sha256', 'transport_sha256'},
          'memveil-owned-admission/1')
    exact(native, IDENTITY | {'cases'}, 'memveil-owned-native/1')
    exact(observed, IDENTITY | {'cases', 'capture_sha256', 'quality'}, 'memveil-owned-observations/1')
    if admission['mode'] not in {'sev-snp', 'tdx', 'hyperv-snp', 'hyperv-tdx'}:
        raise ValueError('real confidential platform admission required')
    for key in IDENTITY:
        if native[key] != admission[key] or observed[key] != admission[key]:
            raise ValueError('artifact/environment identity mismatch')
    for doc in (admission, native, observed):
        for key, value in doc.items():
            if key.endswith('_sha256') and (not isinstance(value, str) or not HASH.fullmatch(value)):
                raise ValueError('invalid artifact digest')
    if (admission['restore_contract'] != 'whole_range_native_success'
            or not isinstance(admission['caller'], str)
            or not re.fullmatch(r'[A-Za-z0-9_ .\[\]-]{1,128}', admission['caller'])
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', admission['profile'])
            or not re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}', admission['kernel_release'])):
        raise ValueError('missing bounded caller/profile or restore admission')
    if observed['quality'] != {'lost': '0', 'censored': '0', 'ambiguous': '0',
                              'foreign': '0', 'closure': 'settled', 'callers': 'admitted'}:
        raise ValueError('incomplete observation evidence')
    if not isinstance(native['cases'], list) or len(native['cases']) != 2 or not isinstance(observed['cases'], list) or len(observed['cases']) != 2:
        raise ValueError('zero-retention and retained/revert cases required')
    epochs = set()
    for i, (case, rows) in enumerate(zip(native['cases'], observed['cases'])):
        if not isinstance(case, dict) or set(case) != {'epoch', 'pages', 'retained_seconds', 'ledger', 'cleanup'}:
            raise ValueError('invalid native case metadata')
        epoch, pages, retained = number(case['epoch']), number(case['pages']), number(case['retained_seconds'])
        if not epoch or epoch in epochs or case['cleanup'] != 'unloaded' or (i == 0 and retained != 0) or (i == 1 and not 1 <= retained <= 3):
            raise ValueError('native case sequence/cleanup mismatch')
        epochs.add(epoch)
        compare_observations(parse_ledger(case['ledger'], epoch, pages), rows, admission['caller'])


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('evidence file missing or outside bounds')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate evidence key')
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique)


def verify_transport(root, admission):
    path = root / 'transport.json'
    if digest(path) != admission['transport_sha256']:
        raise ValueError('ordinary transport receipt digest mismatch')
    receipt = read_json(path)
    exact(receipt, {'status', 'semantics', 'kernel_release', 'btf_sha256', 'module_sha256',
                   'runner_sha256', 'oracle_source_sha256', 'pages', 'cycles', 'bpftrace_version',
                   'bpftrace_sha256', 'shared_hook_blind_spot', 'state_claim'}, 'memveil-owned-transport/1')
    if (not isinstance(receipt['kernel_release'], str)
            or not re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}', receipt['kernel_release'])):
        raise ValueError('invalid ordinary kernel identity')
    for key in ('btf_sha256', 'module_sha256', 'runner_sha256', 'oracle_source_sha256', 'bpftrace_sha256'):
        if not isinstance(receipt[key], str) or not HASH.fullmatch(receipt[key]):
            raise ValueError('invalid ordinary artifact digest')
    lock = read_json(Path(__file__).resolve().parent.parent / 'vm' / 'kernels.lock.json')
    if receipt['bpftrace_version'] != lock['tools']['bpftrace']:
        raise ValueError('ordinary tracer version differs from repository lock')
    if receipt['shared_hook_blind_spot'] is not True:
        raise ValueError('ordinary shared-hook blind spot must be disclosed')
    if not 1 <= number(receipt['pages']) <= 256:
        raise ValueError('ordinary page count outside bounds')
    if (receipt.get('schema') != 'memveil-owned-transport/1' or receipt.get('status') != 'PASS'
            or receipt.get('semantics') != 'ordinary_noop_transport_only'
            or receipt.get('oracle_source_sha256') != admission['oracle_source_sha256']
            or receipt.get('state_claim') != 'unavailable'):
        raise ValueError('ordinary transport prerequisite not met for this module')
    cycles = receipt.get('cycles')
    if not isinstance(cycles, list) or not 6 <= len(cycles) <= 20 or len(cycles) % 2:
        raise ValueError('repeated ordinary transport cases missing')
    epochs = set()
    for i, item in enumerate(cycles):
        if not isinstance(item, dict) or set(item) != {'epoch', 'retained_seconds', 'counts', 'receipt_sha256', 'receipt'}:
            raise ValueError('invalid ordinary cycle fields')
        name = item.get('receipt', '')
        if not re.fullmatch(r'cycle-[0-9]+-[0-3]\.json', name):
            raise ValueError('invalid ordinary receipt name')
        if not isinstance(item['receipt_sha256'], str) or not HASH.fullmatch(item['receipt_sha256']):
            raise ValueError('invalid ordinary case digest')
        child = root / name
        if digest(child) != item.get('receipt_sha256'):
            raise ValueError('ordinary case digest mismatch')
        case = read_json(child)
        if set(case) != {'epoch', 'pages', 'rows', 'cleanup', 'retained_seconds', 'status'} or case['pages'] != receipt['pages']:
            raise ValueError('invalid ordinary case fields/pages')
        if not isinstance(case['rows'], list) or any(not isinstance(row, list) or len(row) != 3 or type(row[2]) is not int for row in case['rows']):
            raise ValueError('invalid ordinary native result')
        epoch = number(case['epoch'])
        retained = number(case['retained_seconds'])
        if (not epoch or epoch in epochs or case['status'] != 'PASS' or case['cleanup'] != 'unloaded'
                or case['epoch'] != item.get('epoch') or case['retained_seconds'] != item.get('retained_seconds')
                or (i % 2 == 0 and retained != 0) or (i % 2 == 1 and not 1 <= retained <= 3)
                or item.get('counts') != {k: '1' for k in ('shared_entry', 'private_entry', 'shared_exit', 'private_exit')}
                or case['rows'] != [['shared', receipt['pages'], 0], ['private', receipt['pages'], 0]]):
            raise ValueError('ordinary counts, ownership or sequence incomplete')
        epochs.add(epoch)


def gate(variable, label):
    if os.environ.get(variable) != '1':
        print(f'{label}: SKIP: requires {variable}=1 and separately admitted guest evidence')
        return 77
    try:
        root = Path(os.environ['MEMVEIL_OWNED_EVIDENCE'])
        admission = read_json(root / 'admission.json')
        native = read_json(root / 'native.json')
        observations = read_json(root / 'observations.json')
        validate(admission, native, observations)
        verify_transport(root, admission)
        if digest(root / 'safety-review.txt') != admission['safety_review_sha256']:
            raise ValueError('independent safety review identity mismatch')
        if digest(root / 'events.ndjson') != observations['capture_sha256']:
            raise ValueError('independently retained product capture identity mismatch')
    except (OSError, ValueError, KeyError, TypeError):
        print(f'FAIL {label}: missing, invalid or mismatched native, observation, admission or transport evidence')
        return 1
    print(f'{label}: PASS: exact owned request/result agreement; persistent region state unavailable; I/O qualification is separate')
    return 0
