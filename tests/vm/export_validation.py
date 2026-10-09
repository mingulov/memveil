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
            keys(doc,('baseline','after','dmesg_marker_present','suspicious'))
            inventory_snapshot(doc['baseline']); inventory_snapshot(doc['after'])
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
        elif name=='cap-session.json':
            validator=_schemas()
            validator.check_session(strict_json(path.read_text()))
        elif name=='cap-events.ndjson':
            validator=_schemas()
            session=validator.check_session(strict_json(got['cap-session.json'].read_text()))
            for i,line in enumerate(path.read_text().splitlines(),1):
                validator.check_event(strict_json(line),i,session)
        elif name=='record.json':
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
        elif name=='report.json':
            doc=strict_json(path.read_text())
            for k in ('schema_version','session_id','quality','metrics'):
                if k not in doc: raise ValueError('report lacks '+k)
            session=strict_json(got['cap-session.json'].read_text())
            if doc['session_id'] != session['session_id']:
                raise ValueError('report session mismatch')
            if type(doc['metrics']) is not list or not doc['metrics']:
                raise ValueError('report lacks metrics')
        else: raise ValueError('unrecognized lifecycle export '+name)


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
