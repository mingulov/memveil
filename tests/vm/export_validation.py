# SPDX-License-Identifier: GPL-3.0-or-later
"""Allowlisted VM export contracts. Raw diagnostics remain guest-local."""
import importlib.util
import json
import re
import math
from importlib.machinery import SourceFileLoader
from pathlib import Path
from consume import SUMMARY_LINE, parse_consume_file, parse_oracle_log


def _unique_object(pairs):
    doc={}
    for key,value in pairs:
        if key in doc:raise ValueError('duplicate export JSON key')
        doc[key]=value
    return doc


def strict_json(text):
    return json.loads(text,object_pairs_hook=_unique_object)


def keys(doc, required, optional=()):
    if type(doc) is not dict or not set(required) <= set(doc) or set(doc)-set(required)-set(optional):
        raise ValueError('export key inventory drift')


def integer(value, negative=False):
    if type(value) is not int or not (-(1 << 63) if negative else 0) <= value < (1 << 64):
        raise ValueError('invalid export integer')


def integer_list(value):
    if type(value) is not list:raise ValueError('invalid integer sample list')
    for item in value:integer(item)


def settle_seconds(value):
    if type(value) not in (int, float) or not 0 <= value <= 30:
        raise ValueError('invalid settle seconds')


def numbers(doc):
    for value in doc.values(): integer(value)


def sha(value):
    if type(value) is not str or not re.fullmatch('[0-9a-f]{64}',value):
        raise ValueError('invalid export hash')


def identity(doc):
    keys(doc,('release','swiotlb_force','config_sha','btf_sha','bridge_sha',
              'consume_sha','lc_sha','cp_sha','ko_sha'),('iface',))
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+[-A-Za-z0-9.]*',doc['release']):
        raise ValueError('invalid kernel release')
    if doc['swiotlb_force'] is not True: raise ValueError('missing force boot option')
    for key,value in doc.items():
        if key.endswith('_sha'): sha(value)
    if 'iface' in doc and not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}',doc['iface']):
        raise ValueError('invalid interface')


def health(doc):
    required=('observed','badframe','badrec','cnt_obs','cnt_obsb','cnt_emit',
              'cnt_emitb','cnt_fail','cnt_flags','rx','dlv','mal','drop')
    keys(doc,required); numbers(doc)


def inventory_snapshot(doc):
    keys(doc,('bpf','io_tlb_used','files'))
    keys(doc['bpf'],('progs','maps')); numbers(doc['bpf'])
    integer_list(doc['io_tlb_used'])
    if type(doc['files']) is not list or any(type(name) is not str or not re.fullmatch(r'[a-zA-Z0-9_.-]+',name) for name in doc['files']):
        raise ValueError('invalid work inventory')


def validate_perf_pairs(pairs, expected_count=None):
    """Bind ordered off/observed legs to distinct producer window IDs."""
    if type(pairs) is not list:raise ValueError('invalid pairs')
    for index, pair in enumerate(pairs):
        if type(pair) is not list or len(pair)!=2:raise ValueError('invalid pair cardinality')
        if [leg.get('mode') for leg in pair if type(leg) is dict] != ['off', 'observed']:
            raise ValueError('invalid perf interleaving')
        if any(leg.get('pair') != index for leg in pair):
            raise ValueError('invalid perf pair identity')
        for leg in pair:
            keys(leg,('pair','mode','ping','dd','end_ns'),('attach_ns','detach_ns'))
            if leg['mode'] not in ('off','observed'):raise ValueError('invalid perf mode')
            integer(leg['pair']);integer(leg['end_ns'])
            for k in ('attach_ns','detach_ns'):
                if k in leg:integer(leg[k])
            keys(leg['ping'],('tx','rx','seconds','p99_ms','sample_tx','sample_rx','sample_count'))
            keys(leg['dd'],('bytes','seconds'))
            for v in leg['ping'].values():
                if v is not None and (type(v) not in (int,float) or not math.isfinite(v) or v < 0):raise ValueError('invalid ping metric')
            for v in leg['dd'].values():
                if type(v) not in (int,float) or not math.isfinite(v) or v < 0:raise ValueError('invalid dd metric')
    if expected_count is not None and len(pairs) != expected_count:
        raise ValueError("missing or unexpected perf pair identity")


def _nonneg_number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError('invalid export measurement')


def _overhead_counts(doc):
    keys(doc, ('progs', 'maps')); numbers(doc)


def _overhead_workload(doc):
    from overhead_guest import (WARMUP_MAX_S, WARMUP_MIN_S,
                                WINDOW_SLACK_S)
    keys(doc, ('window', 'warmup', 'ping', 'dd'))
    window = doc['window']
    keys(window, ('warmup_start_ns', 'measured_start_ns', 'end_ns'))
    for key in window: integer(window[key])
    if not window['warmup_start_ns'] < window['measured_start_ns'] < window['end_ns']:
        raise ValueError('empty overhead window')
    warmup = doc['warmup']
    keys(warmup, ('seconds', 'ok', 'detail'))
    _nonneg_number(warmup['seconds'])
    warmup_ep = (window['measured_start_ns']
                 - window['warmup_start_ns']) / 1e9
    if not WARMUP_MIN_S <= warmup_ep <= WARMUP_MAX_S:
        raise ValueError('overhead warmup window %.2fs '
                         'outside [%.0f, %.0f] s endpoints'
                         % (warmup_ep, WARMUP_MIN_S,
                            WARMUP_MAX_S))
    if abs(warmup['seconds'] - warmup_ep) > WINDOW_SLACK_S:
        raise ValueError('overhead warmup seconds field %.2fs '
                         'contradicts %.2fs endpoints'
                         % (warmup['seconds'], warmup_ep))
    if warmup['ok'] is not True and warmup['ok'] is not False:
        raise ValueError('invalid warmup flag')
    _overhead_warmup_detail(warmup['detail'])
    ping = doc['ping']
    keys(ping, ('tx', 'rx', 'seconds', 'rtts', 'sample_tx',
                'sample_rx', 'sample_count', 'p50_ms', 'p95_ms',
                'p99_ms'))
    integer(ping['tx']); integer(ping['rx'])
    _nonneg_number(ping['seconds'])
    rtts = ping['rtts']
    if type(rtts) is not list or len(rtts) > 10000:
        raise ValueError('invalid RTT sample')
    for value in rtts: _nonneg_number(value)
    for key in ('sample_tx', 'sample_rx'):
        if ping[key] is not None: integer(ping[key])
    integer(ping['sample_count'])
    for key in ('p50_ms', 'p95_ms', 'p99_ms'):
        _nonneg_number(ping[key])
    dd = doc['dd']
    keys(dd, ('bytes', 'seconds'))
    integer(dd['bytes']); _nonneg_number(dd['seconds'])


def _overhead_collector(doc):
    if type(doc) is not dict or 'kind' not in doc:
        raise ValueError('invalid overhead collector')
    kind = doc['kind']
    if kind == 'none':
        keys(doc, ('kind',))
    elif kind == 'product':
        keys(doc, ('kind', 'capabilities', 'exit', 'ready',
                   'stopped', 'killed', 'utime_s', 'stime_s',
                   'maxrss_kb', 'attach_ns', 'detach_ns',
                   'term_ns', 'stderr_tail', 'capture_bytes'))
        caps = doc['capabilities']
        if type(caps) is not list or not caps or any(
                c not in ('attempt-trace', 'mapping-lifecycle',
                          'copy-actual') for c in caps):
            raise ValueError('invalid overhead capabilities')
        integer(doc['exit'], True)
        if type(doc['ready']) is not str or \
                'ready session=' not in doc['ready']:
            raise ValueError('invalid overhead readiness')
        if doc['stopped'] is not True and doc['stopped'] is not False:
            raise ValueError('invalid stopped flag')
        if doc['killed'] is not True and doc['killed'] is not False:
            raise ValueError('invalid killed flag')
        _nonneg_number(doc['utime_s']); _nonneg_number(doc['stime_s'])
        integer(doc['maxrss_kb'])
        for key in ('attach_ns', 'detach_ns', 'term_ns'):
            integer(doc[key])
        if not doc['attach_ns'] < doc['term_ns'] < doc['detach_ns']:
            raise ValueError('incoherent overhead stop order')
        _overhead_stderr_tail(doc['stderr_tail'])
        integer(doc['capture_bytes'])
    elif kind == 'lab':
        keys(doc, ('kind', 'rings', 'lc', 'cp', 'attach_ns',
                   'detach_ns', 'capture_bytes'))
        if doc['rings'] != ['mv_lifecycle', 'mv_copies']:
            raise ValueError('invalid overhead lab rings')
        for side in ('lc', 'cp'):
            keys(doc[side], ('exit', 'utime_s', 'stime_s',
                             'maxrss_kb'))
            integer(doc[side]['exit'], True)
            _nonneg_number(doc[side]['utime_s'])
            _nonneg_number(doc[side]['stime_s'])
            integer(doc[side]['maxrss_kb'])
        integer(doc['attach_ns']); integer(doc['detach_ns'])
        if not doc['attach_ns'] < doc['detach_ns']:
            raise ValueError('incoherent overhead lab window')
        integer(doc['capture_bytes'])
    else:
        raise ValueError('unknown overhead collector kind')


def _overhead_diag(value, what):
    """Allowlisted `code k=v ...` diagnostics: codes, integer facts."""
    from overhead_guest import LEG_ERROR_CODES, LEG_FACT_KEYS
    if type(value) is not str or len(value) > 300:
        raise ValueError('invalid overhead ' + what)
    if not value:
        return
    parts = value.split(' ')
    if parts[0] not in LEG_ERROR_CODES:
        raise ValueError('unknown overhead ' + what)
    for fact in parts[1:]:
        key, sep, num = fact.partition('=')
        if not sep or key not in LEG_FACT_KEYS or \
                not re.fullmatch(r'-?[0-9]{1,20}', num):
            raise ValueError('invalid overhead ' + what)


def _overhead_warmup_detail(value):
    if value == 'ok':
        return
    if type(value) is not str or len(value) > 300:
        raise ValueError('invalid warmup detail')
    if value == 'warmup dd unparseable':
        return
    if re.fullmatch(r'warmup ping rc=-?[0-9]{1,20}', value):
        return
    if re.fullmatch(r'warmup dd bytes=[0-9]{1,20}', value):
        return
    if re.fullmatch(r'warmup dd rc=-?[0-9]{1,20}', value):
        return
    raise ValueError('invalid warmup detail')


def _overhead_stderr_tail(value):
    if value == '':
        return
    if type(value) is not str or not re.fullmatch(
            r'record-stderr (bytes=[0-9]{1,20} '
            r'lines=[0-9]{1,20}|unreadable)', value):
        raise ValueError('invalid overhead diagnostics')


def _overhead_mem_reason(value):
    if value in ('no collector', 'no mem snapshot'):
        return
    if type(value) is not str or len(value) > 200:
        raise ValueError('invalid memlock reason')
    if re.fullmatch(r'owned [0-9]{1,20} progs [0-9]{1,20} '
                    r'maps', value):
        return
    if re.fullmatch(r'bytes_memlock missing for (prog|map) '
                    r'[0-9]{1,20}', value):
        return
    _overhead_diag(value, 'memlock reason')


def _overhead_bpf(bpf):
    keys(bpf, ('before', 'after', 'settled_waited_s', 'settled'))
    _overhead_counts(bpf['before']); _overhead_counts(bpf['after'])
    settle_seconds(bpf['settled_waited_s'])
    if bpf['settled'] is not True and bpf['settled'] is not False:
        raise ValueError('invalid settled flag')


def _overhead_bpf_mem(mem):
    keys(mem, ('owned_memlock_bytes', 'reason'))
    if mem['owned_memlock_bytes'] is not None:
        integer(mem['owned_memlock_bytes'])
    _overhead_mem_reason(mem['reason'])


def _overhead_io_tlb(io_tlb):
    keys(io_tlb, ('before', 'after'))
    for key in ('before', 'after'):
        integer_list(io_tlb[key])
        if len(io_tlb[key]) != 3:
            raise ValueError('invalid io_tlb sample count')


def _overhead_leg(leg):
    keys(leg, ('seq', 'round', 'mode', 'pair', 'tag', 'files',
               'error'),
         ('workload', 'collector', 'bpf', 'bpf_mem', 'io_tlb'))
    integer(leg['seq']); integer(leg['round'])
    if leg['mode'] not in ('off', 'attached-idle', 'summary',
                           'detail', 'undersized-buffer'):
        raise ValueError('invalid overhead mode')
    if type(leg['pair']) is not str or not leg['pair']:
        raise ValueError('invalid overhead pair identity')
    if type(leg['tag']) is not str or not re.fullmatch(
            r'[a-z][0-9]{1,2}', leg['tag']):
        raise ValueError('invalid overhead leg tag')
    files = leg['files']
    if type(files) is not list or any(
            type(name) is not str or not re.fullmatch(
                r'[a-z][0-9]{1,2}-(session\.json|events\.ndjson|lc\.txt|cp\.txt)',
                name) for name in files):
        raise ValueError('invalid overhead leg files')
    _overhead_diag(leg['error'], 'leg error')
    if leg['error']:
        for key, check in (
                ('workload', _overhead_workload),
                ('collector', _overhead_collector),
                ('bpf', _overhead_bpf),
                ('bpf_mem', _overhead_bpf_mem),
                ('io_tlb', _overhead_io_tlb)):
            if key in leg:
                check(leg[key])
        return
    for key in ('workload', 'collector', 'bpf', 'bpf_mem',
                'io_tlb'):
        if key not in leg:
            raise ValueError('clean overhead leg lacks ' + key)
    _overhead_workload(leg['workload'])
    _overhead_collector(leg['collector'])
    _overhead_bpf(leg['bpf'])
    _overhead_bpf_mem(leg['bpf_mem'])
    _overhead_io_tlb(leg['io_tlb'])


def _overhead_common(doc, schema):
    keys(doc, ('schema', 'seed', 'artifacts', 'workload',
               'fixture', 'legs', 'epilogue'),
         ('rounds', 'schedule'))
    if doc['schema'] != schema:
        raise ValueError('unexpected overhead schema')
    integer(doc['seed'])
    artifacts = doc['artifacts']
    keys(artifacts, ('memveil_sha', 'attempt_sha', 'lc_sha',
                     'cp_sha', 'lc_test_sha', 'cp_test_sha',
                     'bridge_sha', 'profile_sha', 'profile_id'))
    for key, value in artifacts.items():
        if key == 'profile_id':
            if type(value) is not str or not value:
                raise ValueError('invalid overhead profile id')
        else:
            sha(value)
    spec = doc['workload']
    keys(spec, ('gateway', 'flood_count', 'sample_count',
                'warmup_ping_count', 'dd_count', 'dd_bytes',
                'warmup_dd_count', 'record_duration_s',
                'lab_window_s', 'seed', 'rounds'))
    if spec['gateway'] != '10.0.3.2':
        raise ValueError('workload gateway drift')
    for key in ('flood_count', 'sample_count',
                'warmup_ping_count', 'dd_count', 'dd_bytes',
                'warmup_dd_count', 'record_duration_s',
                'lab_window_s', 'seed', 'rounds'):
        integer(spec[key])
    fixture = doc['fixture']
    keys(fixture, ('iface', 'disk', 'nslabs', 'bpf_boot',
                   'io_tlb_boot'))
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}', fixture['iface']):
        raise ValueError('invalid overhead iface')
    if not re.fullmatch(r'/dev/sd[a-z]', fixture['disk']):
        raise ValueError('invalid overhead disk')
    integer(fixture['nslabs'])
    _overhead_counts(fixture['bpf_boot'])
    integer_list(fixture['io_tlb_boot'])
    if len(fixture['io_tlb_boot']) != 3:
        raise ValueError('invalid boot io_tlb samples')
    epilogue = doc['epilogue']
    keys(epilogue, ('bpf_end', 'settled_waited_s', 'settled'))
    _overhead_counts(epilogue['bpf_end'])
    settle_seconds(epilogue['settled_waited_s'])
    if epilogue['settled'] is not True and \
            epilogue['settled'] is not False:
        raise ValueError('invalid epilogue settled flag')


def validate_overhead_legs(doc):
    """Bind 40 campaign legs to the frozen seeded schedule."""
    from overhead_guest import SEED, build_schedule
    _overhead_common(doc, 'memveil-overhead-legs/1')
    if doc['seed'] != SEED:
        raise ValueError('overhead seed drift')
    if doc['rounds'] != 5:
        raise ValueError('overhead round drift')
    expected = [[rnd, mode, pair]
                for rnd, mode, pair in build_schedule(SEED)]
    if doc['schedule'] != expected:
        raise ValueError('overhead schedule drift')
    legs = doc['legs']
    if type(legs) is not list or len(legs) != 40:
        raise ValueError('overhead leg count drift')
    seen = set()
    for seq, leg in enumerate(legs):
        _overhead_leg(leg)
        if leg['seq'] != seq:
            raise ValueError('overhead leg order drift')
        rnd, mode, pair = expected[seq]
        if (leg['round'], leg['mode'], leg['pair']) != \
                (rnd, mode, pair):
            raise ValueError('overhead leg identity drift')
        if leg['tag'] != 'l%02d' % seq:
            raise ValueError('overhead leg tag drift')
        seen.add(pair)
    if len(seen) != 20:
        raise ValueError('overhead pair count drift')
    for pair in seen:
        members = [leg for leg in legs if leg['pair'] == pair]
        modes = [leg['mode'] for leg in members]
        if len(members) != 2 or 'off' not in modes or \
                len(set(modes)) != 2:
            raise ValueError('overhead pair is not off/observed')


def validate_overhead_probe(doc):
    """Bind the 2-leg fail-fast probe document."""
    from overhead_guest import SEED
    _overhead_common(doc, 'memveil-overhead-probe/1')
    if doc['seed'] != SEED:
        raise ValueError('overhead probe seed drift')
    if 'rounds' in doc or 'schedule' in doc:
        raise ValueError('probe carries campaign fields')
    legs = doc['legs']
    if type(legs) is not list or len(legs) != 2:
        raise ValueError('overhead probe leg drift')
    for leg, mode, pair, tag in (
            (legs[0], 'summary', 'probe-summary', 'p0'),
            (legs[1], 'attached-idle', 'probe-idle', 'p1')):
        _overhead_leg(leg)
        if leg['mode'] != mode or leg['pair'] != pair or \
                leg['tag'] != tag:
            raise ValueError('overhead probe identity drift')


def validate_lifecycle_exports(got,sub):
    for name,path in got.items():
        if name=='identity.json': identity(strict_json(path.read_text()))
        elif name.endswith(('-lc.txt','-cp.txt')): parse_consume_file(path)
        elif name.endswith('-oracle.log'):
            # Only oracle bodies plus a dmesg monotonic prefix may cross.
            for line in path.read_text().splitlines():
                if not re.fullmatch(r'(?:\[\s*\d+\.\d+\]\s*)?mv-oracle: [A-Za-z0-9_ =-]+',line):
                    raise ValueError('unexpected oracle export line')
            parse_oracle_log(path)
        elif name=='ledger.json':
            rows=strict_json(path.read_text())
            if type(rows) is not list: raise ValueError('invalid cycle ledger')
            for row in rows:
                if sub=='cleanup':
                    keys(row,('cycle','traffic','health','error'))
                    if type(row['traffic']) is not bool: raise ValueError('invalid traffic flag')
                    keys(row['health'],('lc','cp'))
                    health(row['health']['lc']);health(row['health']['cp'])
                    keys(row['error'],('case','rc')); integer(row['error']['rc'],True)
                    if row['error']['case'] not in ('none','insmod-unarmed','bad-object','bad-ring'):
                        raise ValueError('unknown error case')
                elif sub=='stop':
                    keys(row,('cycle','mode','lc_exit','cp_exit'),
                         ('victim_alive','victim_signal','victim_signal_ns','victim_rc','victim_file'))
                    if row['mode'] not in ('quiet','short','stop-both','stop-lc','term-cp'):
                        raise ValueError('invalid stop mode')
                    for k in ('lc_exit','cp_exit'): integer(row[k],True)
                    if row['mode']!='term-cp':
                        keys(row,('cycle','mode','lc_exit','cp_exit'))
                    if row['mode']=='term-cp':
                        keys(row,('cycle','mode','lc_exit','cp_exit','victim_alive','victim_signal',
                                  'victim_signal_ns','victim_rc','victim_file'))
                        if type(row['victim_alive']) is not bool or type(row['victim_file']) is not bool:
                            raise ValueError('invalid victim flags')
                        for k in ('victim_signal','victim_signal_ns'):integer(row[k])
                        integer(row['victim_rc'],True)
                else: raise ValueError('unknown cycle ledger')
                integer(row['cycle'])
        elif name=='inventory.json':
            doc=strict_json(path.read_text())
            keys(doc,('baseline','after','bpf_settle_s','dmesg_marker_present','suspicious'))
            inventory_snapshot(doc['baseline']); inventory_snapshot(doc['after'])
            settle_seconds(doc['bpf_settle_s'])
            if doc['dmesg_marker_present'] is not True:raise ValueError('missing dmesg marker')
            integer(doc['suspicious'])
        elif name=='workload.json':
            doc=strict_json(path.read_text())
            keys(doc,('iface','used_before','used_after','start_ns','end_ns','detach_ns',
                      'ping_tx','ping_rx','disk','disk_bytes'))
            if not re.fullmatch(r'/dev/sd[a-z]',doc['disk']):raise ValueError('invalid owned disk')
            if not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}',doc['iface']):raise ValueError('invalid iface')
            for k in ('used_before','used_after'):integer_list(doc[k])
            for k in ('start_ns','end_ns','detach_ns','ping_tx','ping_rx','disk_bytes'):integer(doc[k])
        elif name=='pairs.json':
            pairs=strict_json(path.read_text())
            validate_perf_pairs(pairs)
        elif name.endswith('-session.json'):
            validator=_schemas()
            validator.check_session(strict_json(path.read_text()))
        elif name.endswith('-events.ndjson'):
            validator=_schemas()
            sibling=name[:-len('-events.ndjson')]+'-session.json'
            session=validator.check_session(strict_json(got[sibling].read_text()))
            for i,line in enumerate(path.read_text().splitlines(),1):
                validator.check_event(strict_json(line),i,session)
        elif name=='record.json' or name.endswith('-record.json'):
            doc=strict_json(path.read_text())
            keys(doc,('exit','ready'))
            integer(doc['exit'],True)
            if type(doc['ready']) is not str or 'ready session=' not in doc['ready']:
                raise ValueError('invalid record readiness')
        elif name=='bundle.json':
            doc=strict_json(path.read_text())
            keys(doc,('tarball','tarball_sha','manifest_sha','files_verified','verified',
                      'bin_sha','attempt_sha','lc_sha','cp_sha','bridge_sha',
                      'report_exit','phases','console_tail'))
            if type(doc['tarball']) is not str or not doc['tarball'].endswith('.tar.gz'):
                raise ValueError('invalid bundle tarball name')
            for k in ('tarball_sha','manifest_sha','bin_sha','attempt_sha','lc_sha','cp_sha','bridge_sha'):
                sha(doc[k])
            integer(doc['files_verified'])
            if doc['verified'] is not True: raise ValueError('bundle verification failed')
            integer(doc['report_exit'],True)
            phases=doc['phases']
            keys(phases,('oracle','fail','io'))
            order=[]
            for tag in ('oracle','fail','io'):
                window=phases[tag]
                if type(window) is not list or len(window) != 2: raise ValueError('invalid bundle phase')
                integer(window[0]);integer(window[1])
                if window[0] >= window[1]: raise ValueError('empty bundle phase')
                order.append(window)
            if not order[0][1] <= order[1][0] <= order[1][1] <= order[2][0]:
                raise ValueError('bundle phases overlap')
            if type(doc['console_tail']) is not str or len(doc['console_tail']) > 2048:
                raise ValueError('invalid bundle console tail')
        elif name=='report.json' or name.endswith('-report.json'):
            doc=strict_json(path.read_text())
            for k in ('schema_version','session_id','quality','metrics'):
                if k not in doc: raise ValueError('report lacks '+k)
            sibling='cap-session.json' if name=='report.json' else name[:-len('-report.json')]+'-session.json'
            session=strict_json(got[sibling].read_text())
            if doc['session_id'] != session['session_id']:
                raise ValueError('report session mismatch')
            if type(doc['metrics']) is not list or not doc['metrics']:
                raise ValueError('report lacks metrics')
        elif name=='walk.json':
            doc=strict_json(path.read_text())
            keys(doc,('memveil_rc','memveil_sha','attempt_sha','profile_sha','profile_ids','end_reason',
                      'bpf_before','bpf_after','settled_waited_s','witness','workload',
                      'live_stdout_sha','live_stderr_sha'))
            integer(doc['memveil_rc'],True)
            sha(doc['memveil_sha']); sha(doc['attempt_sha']); sha(doc['profile_sha'])
            keys(doc['profile_ids'],('bounce_attempts','mapping_lifecycle','copy_bytes','pool_stats'))
            for k in doc['profile_ids']:
                if type(doc['profile_ids'][k]) is not str:
                    raise ValueError('invalid walk profile id')
            if type(doc['end_reason']) is not str:
                raise ValueError('invalid walk end reason')
            for k in ('bpf_before','bpf_after'):
                keys(doc[k],('progs','maps'))
                integer(doc[k]['progs']); integer(doc[k]['maps'])
            settle_seconds(doc['settled_waited_s'])
            witness=doc['witness']
            keys(witness,('nslabs','used_before','used_after','nslabs_after'))
            integer(witness['nslabs']); integer(witness['nslabs_after'])
            integer_list(witness['used_before']); integer_list(witness['used_after'])
            workload=doc['workload']
            keys(workload,('disk','start_ns','end_ns','writer_alive','stat_before','stat_after'))
            if not re.fullmatch(r'/dev/sd[a-z]',workload['disk']):
                raise ValueError('invalid owned disk')
            integer(workload['start_ns']); integer(workload['end_ns'])
            if type(workload['writer_alive']) is not bool:
                raise ValueError('invalid walk writer flag')
            for k in ('stat_before','stat_after'):
                if type(workload[k]) is not list or len(workload[k]) < 5:
                    raise ValueError('invalid walk block stat')
                for v in workload[k]:
                    if type(v) is not str or not re.fullmatch(r'[0-9]+',v):
                        raise ValueError('invalid walk block stat')
            sha(doc['live_stdout_sha']); sha(doc['live_stderr_sha'])
        elif name=='faults.json':
            rows=strict_json(path.read_text())
            if type(rows) is not list or not rows: raise ValueError('invalid faults ledger')
            seen=set()
            for row in rows:
                keys(row,('scenario','exit','stderr','progs_before','progs_after',
                          'maps_before','maps_after','settle_s','cap'),
                     ('events_kept','ready','window'))
                if row['scenario'] not in ('f1','f2','f3a','f3b','f3b-report','f4',
                                           'f5a','f5b','f5c','f6'):
                    raise ValueError('unknown fault scenario')
                if row['scenario'] in seen: raise ValueError('duplicate fault scenario')
                seen.add(row['scenario'])
                integer(row['exit'],True)
                if type(row['stderr']) is not str or len(row['stderr']) > 512:
                    raise ValueError('invalid fault stderr')
                for k in ('progs_before','progs_after','maps_before','maps_after'):
                    integer(row[k])
                settle_seconds(row['settle_s'])
                if type(row['cap']) is not bool: raise ValueError('invalid fault cap flag')
                if 'events_kept' in row and type(row['events_kept']) is not bool:
                    raise ValueError('invalid events_kept flag')
                if 'ready' in row and (type(row['ready']) is not str or 'ready session=' not in row['ready']):
                    raise ValueError('invalid fault readiness')
                if 'window' in row:
                    window=row['window']
                    if type(window) is not list or len(window) != 2:
                        raise ValueError('invalid fault window')
                    integer(window[0]);integer(window[1])
                    if window[0] >= window[1]: raise ValueError('empty fault window')
        elif name=='live.txt':
            body=path.read_text()
            lines=body.splitlines()
            if not lines or 'ready session=' not in lines[0]:
                raise ValueError('live blocks lack readiness preamble')
            if '--- refresh ' not in body:
                raise ValueError('live blocks lack refreshes')
            if len(body) > 1048576:
                raise ValueError('live blocks exceed 1 MiB cap')
        elif name=='live.err':
            body=path.read_text()
            if len(body) > 65536:
                raise ValueError('live diagnostics exceed 64 KiB cap')
        elif name=='legs.json':
            validate_overhead_legs(strict_json(path.read_text()))
        elif name=='probe.json':
            validate_overhead_probe(strict_json(path.read_text()))
        else: raise ValueError('unrecognized lifecycle export '+name)


RECEIPT_SCHEMA='memveil-gate-evidence/1'
RECEIPT_DISPOSITIONS=('passed','failed','skipped','cleanup-uncertain')
RECEIPT_FILE_ERRORS=('missing sidecar','hash mismatch',
                     'unreadable source','copy failed',
                     'missing export','no verified exports')


def receipt_gate(value):
    if type(value) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}',value):
        raise ValueError('invalid evidence gate identity')


RECEIPT_DETAIL_STATUS=('PASS','FAIL','SKIP','BLOCKED')
RECEIPT_DETAIL_COUNTS=('files_verified','cycles','suspicious',
                       'owned_processes','reaped_descendants',
                       'remaining_owned','signal_errors')
RECEIPT_DETAIL_EXITS=('native_exit','report_exit')
RECEIPT_DETAIL_KEYS=('status','timed_out')+RECEIPT_DETAIL_EXITS+RECEIPT_DETAIL_COUNTS


def receipt_detail(doc):
    """Explicit allowlisted summary: lane status plus bounded counts.

    Only the fixed status, exit, flag, and count fields wired by
    gates and the lane runner may cross. No payloads, raw
    addresses, command lines, or environment text may cross
    into retained evidence. Errors never echo the offending
    value.
    """
    if doc is None:return
    if type(doc) is not dict:raise ValueError('invalid evidence detail')
    for key,value in doc.items():
        if key not in RECEIPT_DETAIL_KEYS:
            raise ValueError('invalid evidence detail key')
        if key=='status':
            if value not in RECEIPT_DETAIL_STATUS:
                raise ValueError('invalid evidence detail value')
            continue
        if key=='timed_out':
            if type(value) is not bool:
                raise ValueError('invalid evidence detail value')
            continue
        if key in RECEIPT_DETAIL_EXITS:
            if key=='native_exit' and value is None:continue
            if type(value) is bool or type(value) is not int:
                raise ValueError('invalid evidence detail value')
            if not -128 <= value <= 255:
                raise ValueError('invalid evidence detail value')
            continue
        if type(value) is bool or type(value) is not int:
            raise ValueError('invalid evidence detail value')
        if not 0 <= value <= 1000000:
            raise ValueError('invalid evidence detail value')


def validate_evidence_receipt(doc):
    """Sanitized receipt inventory grammar (no filesystem)."""
    keys(doc,('schema','gate','disposition','complete','files','file_errors','detail'),('export_prefix',))
    if doc['schema'] != RECEIPT_SCHEMA:raise ValueError('invalid evidence schema')
    receipt_gate(doc['gate'])
    if 'export_prefix' in doc:
        receipt_gate(doc['export_prefix'])
    prefix=doc.get('export_prefix') or doc['gate']
    if doc['disposition'] not in RECEIPT_DISPOSITIONS:
        raise ValueError('unknown evidence disposition')
    if doc['complete'] is not True and doc['complete'] is not False:
        raise ValueError('invalid evidence completeness flag')
    if type(doc['files']) is not list:raise ValueError('invalid evidence file inventory')
    for entry in doc['files']:
        keys(entry,('name','sha256','bytes'))
        name=entry['name']
        if type(name) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9-.]{0,127}',name):
            raise ValueError('invalid evidence file name')
        if not name.startswith(prefix+'-'):
            raise ValueError('evidence file outside gate inventory')
        sha(entry['sha256']);integer(entry['bytes'])
    if type(doc['file_errors']) is not list:
        raise ValueError('invalid evidence error inventory')
    for entry in doc['file_errors']:
        keys(entry,('name','error'))
        if type(entry['name']) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9-.]{0,127}',entry['name']):
            raise ValueError('invalid evidence error name')
        if entry['error'] not in RECEIPT_FILE_ERRORS:
            raise ValueError('unrecognized evidence file error')
    receipt_detail(doc['detail'])
    if doc['complete'] is True and (doc['disposition'] != 'passed' or not doc['files'] or doc['file_errors']):
        raise ValueError('complete evidence requires a passed gate with verified files')


def _schemas():
    path=Path(__file__).resolve().parents[2]/'tools/validate-schemas'
    loader=SourceFileLoader('vm_schema_validator',str(path))
    spec=importlib.util.spec_from_loader(loader.name,loader)
    module=importlib.util.module_from_spec(spec);loader.exec_module(module)
    return module


def validate_attempt_exports(got, mode=None):
    validator=_schemas()
    session=validator.check_session(strict_json(got['session.json'].read_text()))
    for i,line in enumerate(got['events.ndjson'].read_text().splitlines(),1):
        validator.check_event(strict_json(line),i,session)
    doc=strict_json(got['oracle.json'].read_text())
    keys(doc,('schema','lost_lines','pipe_bytes','pipe_lines','header_lines','blank_lines','events'))
    if doc['schema'] != 'memveil-vm-oracle/1':raise ValueError('invalid oracle schema')
    for k in ('lost_lines','pipe_bytes','pipe_lines','header_lines','blank_lines'):integer(doc[k])
    if type(doc['events']) is not list:raise ValueError('invalid oracle event inventory')
    if doc['pipe_lines'] != len(doc['events'])+doc['header_lines']+doc['blank_lines']+doc['lost_lines']:
        raise ValueError('oracle line cardinality drift')
    if doc['pipe_bytes'] < doc['pipe_lines']:raise ValueError('oracle byte cardinality drift')
    for event in doc['events']:
        keys(event,('ts_ns','size','forced'));integer(event['ts_ns']);integer(event['size'])
        if type(event['forced']) is not bool:raise ValueError('invalid force flag')
    ledger=strict_json(got['ledger.json'].read_text())
    keys(ledger,('mode','fs_type','identity','hiwater_before','iface','dma_mask_bits','link_ok',
                'trace_clock','ready','workload_start_ns','workload_end_ns','ping_transmitted',
                'ping_received','record_exit','drained_bytes','percpu','hiwater_after',
                'pipe_bytes','pipe_lines','lost_markers'))
    if ledger['mode'] not in ('correctness','saturation') or mode is not None and ledger['mode'] != mode:
        raise ValueError('invalid attempt lane identity')
    if type(ledger['fs_type']) is not str or ledger['fs_type'] not in ('ext2/ext3','ext4','btrfs','tmpfs','overlayfs','xfs','ramfs','tracefs'):
        raise ValueError('invalid filesystem identity')
    for k in ('hiwater_before','hiwater_after'):
        value=ledger[k]
        if value is not None and (type(value) is not str or not re.fullmatch(r'0|[1-9][0-9]{0,19}',value) or int(value)>=1<<64):
            raise ValueError('invalid hiwater scalar')
    if type(ledger['iface']) is not str or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,31}',ledger['iface']):
        raise ValueError('invalid interface identity')
    if type(ledger['dma_mask_bits']) is not int or ledger['dma_mask_bits'] != 32:
        raise ValueError('invalid DMA mask width')
    if ledger['link_ok'] is not True:raise ValueError('invalid link flag')
    clocks=r'(?:local|global|counter|uptime|perf|mono|mono_raw|boot|tai|x86-tsc)'
    token=r'(?:'+clocks+r'|\['+clocks+r'\])'
    if type(ledger['trace_clock']) is not str or not re.fullmatch(token+r'(?: '+token+r')*',ledger['trace_clock']):
        raise ValueError('invalid trace clock inventory')
    if '[mono]' not in ledger['trace_clock'] and ledger['trace_clock'] != 'mono':
        raise ValueError('oracle monotonic clock not selected')
    ready=r'ready session=(?:cap-[0-9]+-[0-9]+|[a-z][a-z0-9_.-]{0,127}) start_ns=(?:0|[1-9][0-9]{0,19})'
    if type(ledger['ready']) is not str or not re.fullmatch(ready,ledger['ready']):
        raise ValueError('invalid readiness acknowledgement')
    if ledger['ready'] not in got['record.stdout'].read_text().splitlines():
        raise ValueError('readiness acknowledgement differs from record stdout')
    ident=ledger['identity']
    keys(ident,('release','config_src','config_sha','btf_sha','format_sha','image_sha','image_bid'))
    if type(ident['release']) is not str or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+[-A-Za-z0-9.]*',ident['release']):
        raise ValueError('invalid kernel release')
    for key in ('config_sha','btf_sha','format_sha','image_sha'):sha(ident[key])
    if ident['config_src'] not in ('gz','file'):raise ValueError('invalid config source')
    if not re.fullmatch(r'[0-9a-f]{16,128}',ident['image_bid']):raise ValueError('invalid build id')
    for key in ('workload_start_ns','workload_end_ns','ping_transmitted','ping_received','record_exit',
                'drained_bytes','pipe_bytes','pipe_lines','lost_markers'):integer(ledger[key])
    if type(ledger["percpu"]) is not dict:raise ValueError("invalid CPU inventory")
    for cpu,stats in ledger['percpu'].items():
        if not re.fullmatch('cpu[0-9]+',cpu):raise ValueError('invalid cpu')
        keys(stats,('values',));keys(stats['values'],('overrun','commit overrun','dropped events'))
        numbers(stats['values'])
    for line in got['record.stdout'].read_text().splitlines():
        if not re.fullmatch(r'ready session=[A-Za-z0-9_.-]+ start_ns=\d+|record: end=(duration|signal) outcome=finalized exit=4',line):
            raise ValueError('unexpected record stdout')
    if got['record.stderr'].read_text().strip():raise ValueError('record diagnostics must remain guest-local')
    for line in got['ping.txt'].read_text().splitlines():
        if line and not re.fullmatch(r'PING 10\.0\.3\.2 \(10\.0\.3\.2\) [0-9]+\([0-9]+\) bytes of data\.|--- 10\.0\.3\.2 ping statistics ---|[0-9]+ packets transmitted, [0-9]+ received, [0-9]+(?:\.[0-9]+)?% packet loss, time [0-9]+ms|rtt min/avg/max/mdev = [0-9]+(?:\.[0-9]+)?/[0-9]+(?:\.[0-9]+)?/[0-9]+(?:\.[0-9]+)?/[0-9]+(?:\.[0-9]+)? ms(?:, pipe [0-9]+)?(?:, ipg/ewma [0-9]+(?:\.[0-9]+)?/[0-9]+(?:\.[0-9]+)? ms)?',line):
            raise ValueError('unexpected ping export text')
