#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
import copy
import json
import os
import tempfile
from unittest.mock import patch
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent))


class QualificationTests(unittest.TestCase):
    def fixture(self):
        identity = {'mode': 'sev-snp', 'profile': 'source-reviewed-test',
                    'kernel_release': '6.11.0-test', 'kernel_source_sha256': '1'*64,
                    'oracle_source_sha256': 'a'*64, 'kernel_config_sha256': '2'*64, 'btf_sha256': '3'*64,
                    'module_sha256': '4'*64, 'product_sha256': '5'*64,
                    'profile_sha256': '6'*64}
        admission = dict(identity, schema='memveil-owned-admission/1',
                         caller='memveil_region_oracle', restore_contract='whole_range_native_success',
                         safety_review_sha256='7'*64, transport_sha256='8'*64)
        cases = []
        for epoch, retained in [('1', '0'), ('2', '1')]:
            cases.append({'epoch': epoch, 'pages': '3', 'retained_seconds': retained,
                          'ledger': f'epoch={epoch} ordinal=1 direction=shared pages=3 result=0\n'
                                    f'epoch={epoch} ordinal=2 direction=private pages=3 result=0\n',
                          'cleanup': 'unloaded'})
        native = dict(identity, schema='memveil-owned-native/1', cases=cases)
        observed = dict(identity, schema='memveil-owned-observations/1',
                        capture_sha256='9'*64, quality={'lost': '0', 'censored': '0', 'ambiguous': '0',
                            'foreign': '0', 'closure': 'settled', 'callers': 'admitted'},
                        cases=[[{'direction': direction, 'pages': '3', 'result': 0,
                                 'caller': 'memveil_region_oracle'} for direction in ('shared', 'private')]
                               for _ in cases])
        return admission, native, observed

    def test_exact_independent_join_and_negative_controls(self):
        from owned_qualification import validate
        a, n, o = self.fixture()
        validate(a, n, o)
        mutations = [lambda a,n,o: n['cases'][0].update(cleanup='quarantined'),
                     lambda a,n,o: n['cases'][1].update(epoch='1'),
                     lambda a,n,o: n['cases'][1].update(retained_seconds='0'),
                     lambda a,n,o: o['quality'].update(lost='1'),
                     lambda a,n,o: o.update(profile='other'),
                     lambda a,n,o: o['cases'][0][0].update(caller='unknown'),
                     lambda a,n,o: a.update(mode='ordinary'),
                     lambda a,n,o: a.update(restore_contract='inferred'),
                     lambda a,n,o: o['cases'].pop(),
                     lambda a,n,o: o.update(address='redacted')]
        for mutation in mutations:
            aa, nn, oo = copy.deepcopy((a, n, o))
            mutation(aa, nn, oo)
            with self.assertRaises(ValueError):
                validate(aa, nn, oo)

    def test_gate_binds_every_evidence_file_and_transport_case(self):
        import owned_qualification as q
        from owned_region import digest
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a, n, o = self.fixture()
            (root/'safety-review.txt').write_text('Authored validator fixture, no admission.\n')
            (root/'events.ndjson').write_text('{"synthetic":true}\n')
            a['safety_review_sha256'] = digest(root/'safety-review.txt')
            o['capture_sha256'] = digest(root/'events.ndjson')
            cycles = []
            for i in range(6):
                name = f'cycle-{i//2}-{i%2}.json'
                case = {'epoch': str(i+1), 'pages': '3', 'retained_seconds': str(i%2),
                        'rows': [['shared', '3', 0], ['private', '3', 0]],
                        'cleanup': 'unloaded', 'status': 'PASS'}
                (root/name).write_text(json.dumps(case))
                cycles.append({'epoch': str(i+1), 'retained_seconds': str(i%2), 'receipt': name,
                               'receipt_sha256': digest(root/name),
                               'counts': {k: '1' for k in ('shared_entry','private_entry','shared_exit','private_exit')}})
            transport = {'schema': 'memveil-owned-transport/1', 'status': 'PASS',
                         'semantics': 'ordinary_noop_transport_only', 'state_claim': 'unavailable',
                         'oracle_source_sha256': a['oracle_source_sha256'], 'pages': '3', 'cycles': cycles,
                         'kernel_release': '6.11.0-test', 'btf_sha256': 'a'*64, 'module_sha256': 'b'*64,
                         'runner_sha256': 'c'*64, 'bpftrace_version': 'bpftrace v0.25.0',
                         'bpftrace_sha256': 'd'*64, 'shared_hook_blind_spot': True}
            (root/'transport.json').write_text(json.dumps(transport))
            a['transport_sha256'] = digest(root/'transport.json')
            for name, doc in [('admission.json', a), ('native.json', n), ('observations.json', o)]:
                (root/name).write_text(json.dumps(doc))
            env = {'MEMVEIL_CONFIDENTIAL_REAL': '1', 'MEMVEIL_OWNED_EVIDENCE': str(root)}
            with patch.dict(os.environ, env):
                self.assertEqual(q.gate('MEMVEIL_CONFIDENTIAL_REAL', 'synthetic-validator'), 0)
                for name in ('safety-review.txt', 'events.ndjson', 'cycle-0-0.json', 'transport.json'):
                    path = root/name
                    before = path.read_bytes()
                    path.write_text('{}')
                    self.assertEqual(q.gate('MEMVEIL_CONFIDENTIAL_REAL', 'synthetic-validator'), 1)
                    path.write_bytes(before)
                for mutate in (lambda t: t['cycles'][0]['counts'].update(shared_entry='0'),
                               lambda t: t['cycles'].pop(),
                               lambda t: t.update(oracle_source_sha256='b'*64)):
                    bad = copy.deepcopy(transport)
                    mutate(bad)
                    (root/'transport.json').write_text(json.dumps(bad))
                    a['transport_sha256'] = digest(root/'transport.json')
                    with self.assertRaises(ValueError):
                        q.verify_transport(root, a)

    def test_json_refuses_duplicate_keys_oversize_and_symlinks(self):
        from owned_qualification import read_json
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root/'case.json'
            for text in ('{"a":1,"a":2}', ' ' * 65537):
                target.write_text(text)
                with self.assertRaises(ValueError):
                    read_json(target)
            target.write_text('{}')
            link = root/'link.json'
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                read_json(link)


if __name__ == '__main__':
    unittest.main()
