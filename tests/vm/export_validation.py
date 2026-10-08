# SPDX-License-Identifier: GPL-3.0-or-later
"""Allowlisted VM export contracts. Raw diagnostics remain guest-local."""
import importlib.util
import json
import re
import math
from importlib.machinery import SourceFileLoader
from pathlib import Path
from consume import SUMMARY_LINE, parse_consume_file, parse_oracle_log


def keys(doc, required, optional=()):
    if type(doc) is not dict or not set(required) <= set(doc) or set(doc)-set(required)-set(optional):
        raise ValueError('export key inventory drift')


def integer(value, negative=False):
    if type(value) is not int or not (-(1 << 63) if negative else 0) <= value < (1 << 64):
        raise ValueError('invalid export integer')


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
    for value in doc['io_tlb_used']: integer(value)
    if any(not re.fullmatch(r'[a-zA-Z0-9_.-]+',name) for name in doc['files']):
        raise ValueError('invalid work inventory')


def validate_lifecycle_exports(got,sub):
    for name,path in got.items():
        if name=='identity.json': identity(json.loads(path.read_text()))
        elif name.endswith(('-lc.txt','-cp.txt')): parse_consume_file(path)
        elif name.endswith('-oracle.log'):
            # Only oracle bodies plus a dmesg monotonic prefix may cross.
            for line in path.read_text().splitlines():
                if not re.fullmatch(r'(?:\[\s*\d+\.\d+\]\s*)?mv-oracle: [A-Za-z0-9_ =-]+',line):
                    raise ValueError('unexpected oracle export line')
            parse_oracle_log(path)
        elif name=='ledger.json':
            rows=json.loads(path.read_text())
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
            doc=json.loads(path.read_text())
            keys(doc,('baseline','after','dmesg_marker_present','suspicious'))
            inventory_snapshot(doc['baseline']); inventory_snapshot(doc['after'])
            if doc['dmesg_marker_present'] is not True:raise ValueError('missing dmesg marker')
            integer(doc['suspicious'])
        elif name=='workload.json':
            doc=json.loads(path.read_text())
            keys(doc,('iface','used_before','used_after','start_ns','end_ns','detach_ns',
                      'ping_tx','ping_rx','disk','disk_bytes'))
            if not re.fullmatch(r'/dev/sd[a-z]',doc['disk']):raise ValueError('invalid owned disk')
            if not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}',doc['iface']):raise ValueError('invalid iface')
            for k in ('used_before','used_after'):
                for v in doc[k]:integer(v)
            for k in ('start_ns','end_ns','detach_ns','ping_tx','ping_rx','disk_bytes'):integer(doc[k])
        elif name=='pairs.json':
            pairs=json.loads(path.read_text())
            if type(pairs) is not list:raise ValueError('invalid pairs')
            for pair in pairs:
                if type(pair) is not list or len(pair)!=2:raise ValueError('invalid pair cardinality')
                for leg in pair:
                    keys(leg,('pair','mode','ping','dd','end_ns'),('attach_ns','detach_ns'))
                    if leg['mode'] not in ('off','observed'):raise ValueError('invalid perf mode')
                    integer(leg['pair']);integer(leg['end_ns'])
                    keys(leg['ping'],('tx','rx','seconds','p99_ms','sample_tx','sample_rx','sample_count'))
                    keys(leg['dd'],('bytes','seconds'))
                    for v in leg['ping'].values():
                        if v is not None and (type(v) not in (int,float) or not math.isfinite(v) or v < 0):raise ValueError('invalid ping metric')
                    for v in leg['dd'].values():
                        if type(v) not in (int,float) or not math.isfinite(v) or v < 0:raise ValueError('invalid dd metric')
        else: raise ValueError('unrecognized lifecycle export '+name)


def _schemas():
    path=Path(__file__).resolve().parents[2]/'tools/validate-schemas'
    loader=SourceFileLoader('vm_schema_validator',str(path))
    spec=importlib.util.spec_from_loader(loader.name,loader)
    module=importlib.util.module_from_spec(spec);loader.exec_module(module)
    return module


def validate_attempt_exports(got, mode=None):
    validator=_schemas()
    session=validator.check_session(json.loads(got['session.json'].read_text()))
    for i,line in enumerate(got['events.ndjson'].read_text().splitlines(),1):
        validator.check_event(json.loads(line),i,session)
    doc=json.loads(got['oracle.json'].read_text())
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
    ledger=json.loads(got['ledger.json'].read_text())
    keys(ledger,('mode','fs_type','identity','hiwater_before','iface','dma_mask_bits','link_ok',
                'trace_clock','ready','workload_start_ns','workload_end_ns','ping_transmitted',
                'ping_received','record_exit','drained_bytes','percpu','hiwater_after',
                'pipe_bytes','pipe_lines','lost_markers'))
    if ledger['mode'] not in ('correctness','saturation') or mode is not None and ledger['mode'] != mode:
        raise ValueError('invalid attempt lane identity')
    if type(ledger['fs_type']) is not str or ledger['fs_type'] not in ('ext4','btrfs','tmpfs','overlayfs','xfs','ramfs','tracefs'):
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
