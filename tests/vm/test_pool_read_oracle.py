# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic read-cadence receipts never establish live sampling qualification."""
import errno
import importlib.util
import io
import json
from pathlib import Path
import sys
import time
import types
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


def test_oracle_quiet_thinning():
    api().validate_pool(*inputs())


@pytest.mark.parametrize('damage', ['endpoints', 'stopped', 'missing-label', 'failed-read', 'burst', 'middle-gap', 'after-stop', 'outside-window-count'])
def test_oracle_rejects_damaged_traces(damage):
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


POOL_PREFIX = b'/sys/kernel/debug/swiotlb/'
CANARY = 'QZXnoPayloadBytesQZX'


def stamp(when):
    return ('%d.%06d' % (int(when), int((when % 1) * 10**6))).encode('ascii')


def good_line(tid=123, field='io_tlb_used', count=5, when=None):
    when = time.time() - 0.05 if when is None else when
    return b'%d %s read(7<%s%s>, ""..., 64) = %d\n' % (tid, stamp(when), POOL_PREFIX, field.encode('ascii'), count)


def unfinished_line(tid=123, field='io_tlb_used', when=None):
    when = time.time() - 0.05 if when is None else when
    return b'%d %s read(7<%s%s>, "", 64 <unfinished ...>\n' % (tid, stamp(when), POOL_PREFIX, field.encode('ascii'))


def resumed_line(tid=123, result=b'5', when=None):
    when = time.time() - 0.05 if when is None else when
    return b'%d %s <... read resumed>"", 64) = %s\n' % (tid, stamp(when), result)


def drive_reader(lines, stopping=False, owned=(123,), stderr=None):
    """Drive the oracle reader loop with no tracer, product, or threads."""
    m = api()
    oracle = m.PoolReadOracle.__new__(m.PoolReadOracle)
    oracle.product = types.SimpleNamespace(pid=123)
    oracle.tracer = types.SimpleNamespace(poll=lambda: None,
                                          stderr=io.BytesIO(b''.join(lines)) if stderr is None else stderr)
    oracle.stopping = stopping
    oracle.observation = {'records': [], 'errors': [], 'skipped_detach_control': []}
    oracle._owned_thread = lambda tid: tid in owned
    oracle._read()
    return oracle.observation


RECORD_KEYS = {'class', 'shape', 'seq', 'last_good_seq', 'last_good_received_ns',
               'failed_received_ns', 'failed_wall_ns', 'gap_ns', 'line_len', 'stopping'}


def sole_error(observation):
    assert observation['errors'] and len(observation['errors']) == 1, observation['errors']
    record = observation['errors'][0]
    assert isinstance(record, dict), record
    assert RECORD_KEYS <= set(record), record
    assert all(isinstance(value, str) for value in record.values()), record
    json.dumps(observation)
    return record


def test_failure_record_classifies_each_check():
    now = time.time()
    foreign = b'123 ' + stamp(now - 0.05) + b' read(7</sys/kernel/debug/swiotlb/zz' + CANARY.encode() + \
        b'>, ""..., 64) = 5\n'
    garbage = b'garbage ' + CANARY.encode() + b' tail\n'
    cases = [
        ('line_too_long', b'y' * 70000, 'line_too_long', 'exceeds_65536', {}),
        ('grammar', garbage, 'grammar', 'unrecognized', {}),
        ('ownership', good_line(tid=999), 'ownership', 'unowned_or_exited_tid', {}),
        ('delivery_late', good_line(when=now - 10), 'delivery', 'late', {}),
        ('delivery_future', good_line(when=now + 10), 'delivery', 'future', {}),
        ('path', foreign, 'path', 'foreign_path', {}),
        ('count_bound', good_line(count=66), 'count_bound', 'over_65', {'count': '66'}),
        ('decode', b'123 ' + stamp(now - 0.05) +
         b' read(7</sys/kernel/debug/swiotlb/\xff\xfe>, ""..., 64) = 5\n', 'decode', 'non_ascii_path', {}),
    ]
    for name, line, check, shape, extra in cases:
        observation = drive_reader([good_line(), good_line(), line])
        record = sole_error(observation)
        assert (record['class'], record['shape']) == (check, shape), name
        assert record['seq'] == '2', name
        assert record['last_good_seq'] == '1', name
        assert record['last_good_received_ns'] == observation['records'][1]['received_ns'], name
        assert int(record['failed_received_ns']) >= int(record['last_good_received_ns']), name
        assert int(record['gap_ns']) == int(record['failed_received_ns']) - int(record['last_good_received_ns']), name
        assert record['line_len'] == str(len(line) if len(line) <= 65537 else 65537), name
        assert record['stopping'] == 'false', name
        for key, value in extra.items():
            assert record[key] == value, name
        assert CANARY not in json.dumps(observation), name


def test_failure_record_reports_signed_delivery_skew():
    now = time.time()
    late = sole_error(drive_reader([good_line(when=now - 10)]))
    assert late['class'] == 'delivery' and late['shape'] == 'late'
    assert 5 * 10**9 < int(late['skew_ns']) < 15 * 10**9
    future = sole_error(drive_reader([good_line(when=now + 10)]))
    assert future['class'] == 'delivery' and future['shape'] == 'future'
    assert -15 * 10**9 < int(future['skew_ns']) < -5 * 10**9


def test_failure_record_names_detach_control_mid_window():
    for line, shape in [(unfinished_line(), 'control_unfinished'), (resumed_line(), 'control_resumed')]:
        observation = drive_reader([good_line(), line])
        record = sole_error(observation)
        assert (record['class'], record['shape']) == ('grammar', shape)
        assert record['stopping'] == 'false'
        assert len(observation['records']) == 1


def test_trace_bounds_stay_fatal_with_class(monkeypatch):
    m = api()
    monkeypatch.setattr(m, 'MAX_TRACE_BYTES', 150)
    record = sole_error(drive_reader([good_line(), good_line()]))
    assert (record['class'], record['shape']) == ('trace_bytes_bound', 'over_bound')
    assert record['seq'] == '1'
    monkeypatch.setattr(m, 'MAX_TRACE_BYTES', 8 * 1024**2)
    monkeypatch.setattr(m, 'MAX_RECORDS', 2)
    record = sole_error(drive_reader([good_line(), good_line(), good_line()]))
    assert (record['class'], record['shape']) == ('trace_records_bound', 'over_bound')
    assert record['seq'] == '2'


def test_read_os_error_kills_reader_loudly():
    class Failing:
        def readline(self, *args): raise OSError(errno.EIO, 'Input/output error')
    observation = drive_reader([], stderr=Failing())
    record = sole_error(observation)
    assert (record['class'], record['shape']) == ('read_os_error', 'readline_failed')
    assert record['errno'] == str(errno.EIO)
    assert record['seq'] == '0' and record['last_good_seq'] == 'none'


def test_stopping_skips_bounded_detach_control():
    lines = [good_line(), unfinished_line(), resumed_line(), good_line()]
    observation = drive_reader(lines, stopping=True)
    assert observation['errors'] == []
    assert len(observation['records']) == 2
    assert [skip['shape'] for skip in observation['skipped_detach_control']] == ['unfinished', 'resumed']
    assert all(skip['class'] == 'detach_control' for skip in observation['skipped_detach_control'])
    assert all(skip['stopping'] == 'true' for skip in observation['skipped_detach_control'])
    abandoned = drive_reader([unfinished_line(), resumed_line(result=b'?')], stopping=True)
    assert abandoned['errors'] == [] and len(abandoned['skipped_detach_control']) == 2


def test_stopping_bounds_detach_control_per_thread_and_total():
    observation = drive_reader([unfinished_line()] * 3, stopping=True)
    record = sole_error(observation)
    assert (record['class'], record['shape']) == ('detach_control_bound', 'per_thread_pair')
    assert len(observation['skipped_detach_control']) == 2
    lines = [unfinished_line(tid=123), resumed_line(tid=123), unfinished_line(tid=124),
             resumed_line(tid=124), unfinished_line(tid=125)]
    observation = drive_reader(lines, stopping=True, owned=(123, 124, 125))
    record = sole_error(observation)
    assert (record['class'], record['shape']) == ('detach_control_bound', 'over_total')
    assert len(observation['skipped_detach_control']) == 4


def test_stopping_tolerates_nothing_else():
    now = time.time()
    foreign_control = unfinished_line(field='zz' + CANARY + 'zz')
    cases = [
        ('garbage', b'garbage\n', 'grammar', 'unrecognized'),
        ('foreign_control', foreign_control, 'path', 'control_unfinished_foreign_path'),
        ('late', good_line(when=now - 10), 'delivery', 'late'),
    ]
    for name, line, check, shape in cases:
        observation = drive_reader([line], stopping=True)
        record = sole_error(observation)
        assert (record['class'], record['shape']) == (check, shape), name
        assert record['stopping'] == 'true', name
        assert observation['skipped_detach_control'] == [], name
    assert CANARY not in json.dumps(drive_reader([foreign_control], stopping=True))
    observation = drive_reader([unfinished_line(tid=999)], stopping=True)
    record = sole_error(observation)
    assert (record['class'], record['shape']) == ('ownership', 'control_unfinished_unowned')


def test_silent_reader_still_fails_validate_pool():
    samples, window, _, stop = inputs()
    oracle = {'records': [], 'errors': [], 'cleanup': 'detached'}
    with pytest.raises(ValueError): api().validate_pool(samples, window, oracle, stop)


def test_mid_window_death_still_fails_validate_pool():
    samples, window, _, stop = inputs()
    observation = drive_reader([good_line(), good_line(), b'garbage\n'])
    assert observation['errors']
    oracle = {'records': observation['records'], 'errors': observation['errors'], 'cleanup': 'detached'}
    with pytest.raises(ValueError): api().validate_pool(samples, window, oracle, stop)
