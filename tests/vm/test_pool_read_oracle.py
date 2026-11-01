# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic read-cadence receipts never establish live sampling qualification."""
import importlib.util
from pathlib import Path
import sys
import pytest
sys.path.insert(0, str(Path(__file__).parent))


def api():
    assert importlib.util.find_spec('pool_read_oracle'), 'pool read oracle missing'
    import pool_read_oracle
    return pool_read_oracle


def inputs():
    samples = [str(i * 10**9) for i in range(4097)] + [str(4271 * 10**9)]
    window = {'start_ns': str(10 * 10**9), 'end_ns': str(4270 * 10**9)}
    records = [{'field': field, 'returned_bytes': '5', 'received_ns': str(i * 10**9)}
               for i in range(1, 4270) for field in ('used', 'capacity')]
    return samples, window, {'records': records, 'errors': [], 'cleanup': 'detached'}, str(4271 * 10**9)


def test_quiet_thinning_accepts_reads_without_postcap_persisted_events():
    api().validate_pool(*inputs())


@pytest.mark.parametrize('damage', ['endpoints', 'stopped', 'missing-label', 'failed-read', 'burst', 'middle-gap', 'after-stop', 'outside-window-count'])
def test_pool_rejects_incomplete_oracle_and_endpoint_only_captures(damage):
    samples, window, oracle, stop = inputs()
    if damage == 'endpoints': samples = [samples[0], samples[-1]]
    if damage == 'stopped': oracle['records'] = [r for r in oracle['records'] if int(r['received_ns']) <= 4096 * 10**9]
    if damage == 'missing-label': oracle['records'] = [r for r in oracle['records'] if r['field'] == 'used']
    if damage == 'failed-read': oracle['records'][0]['returned_bytes'] = '0'
    if damage == 'burst':
        for r in oracle['records']: r['received_ns'] = '1'
    if damage == 'middle-gap': oracle['records'] = [r for r in oracle['records'] if not 2000 * 10**9 < int(r['received_ns']) < 2008 * 10**9]
    if damage == 'outside-window-count':
        oracle['records'] = [dict(r, received_ns='1') for r in oracle['records']] + [
            {'field': field, 'returned_bytes': '5', 'received_ns': str(i * 10**9)}
            for i in range(10, 4270, 2) for field in ('used', 'capacity')]
    if damage == 'after-stop':
        for r in oracle['records']:
            if int(r['received_ns']) > 4096 * 10**9: r['received_ns'] = stop
    with pytest.raises(ValueError): api().validate_pool(samples, window, oracle, stop)


def test_parser_projects_only_allowlisted_read_metadata():
    m = api()
    line = b'123 1000.000000 read(7</sys/kernel/debug/swiotlb/io_tlb_used>, ""..., 64) = 5\n'
    result = m.project_read(line, 900000000000, 1000000001000, lambda tid: tid == 123)
    assert result == {'field': 'used', 'returned_bytes': '5', 'received_ns': '900000000000'}
    assert m.project_read(line.replace(b' = 5', b' = 0'), 900000000000, 1000000001000, lambda tid: True) is None
    for bad in [line.replace(b'io_tlb_used', b'foreign'), line.replace(b' = 5', b' = -1 EIO'),
                line.replace(b'123 ', b'999 '), b'x' * 65537]:
        with pytest.raises(ValueError): m.project_read(bad, 900000000000, 1000000001000, lambda tid: tid == 123)
    with pytest.raises(ValueError): m.project_read(line, 900000000000, 1001000000000, lambda tid: True)
