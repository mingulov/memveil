#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent Python bytes exercise the native decoder with sanitizers."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]

def wire(**changes):
    fields = dict(magic=0x524a564d, version=1, kind=1, flags=1, direction=1, cpu=0,
                  seq=0, exit_ns=30, epoch=1, token=9, entry_ns=20, pages=3, result=-5,
                  caller=0, cls=0, label=0, reserved=0)
    fields.update(changes)
    return struct.pack('<IHHHHIQQQQQiiHHHH', *fields.values())


def main():
    with tempfile.TemporaryDirectory() as temporary:
        tmp = Path(temporary)
        source = tmp / 'decode.c'
        source.write_text('''#include <stdio.h>
#include "bpf/include/memveil_journal.h"
int main(void) {
    unsigned char b[73]; struct mv_journal out;
    size_t n = fread(b, 1, sizeof(b), stdin);
    int rc = mv_decode_journal(b, n, &out);
    if (rc != MV_OK) return 2;
    printf("%u %u %llu %llu %llu %llu %llu %d %d %u %u %u %u\\n",
           out.direction, out.cpu, (unsigned long long)out.sequence,
           (unsigned long long)out.exit_ns, (unsigned long long)out.epoch,
           (unsigned long long)out.token, (unsigned long long)out.entry_ns,
           out.pages, out.native_result, out.caller_status, out.caller_class,
           out.caller_label, out.matched);
    return 0;
}
''')
        binary = tmp / 'decode'
        subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                        '-I', str(ROOT), str(source), '-o', str(binary)], check=True)
        env = dict(os.environ, UBSAN_OPTIONS='halt_on_error=1')
        good = subprocess.run([str(binary)], input=wire(), capture_output=True, env=env)
        assert good.returncode == 0 and good.stdout == b'1 0 0 30 1 9 20 3 -5 0 0 0 1\n' and good.stderr == b'', good
        valid = [wire(pages=-2147483648, result=2147483647), wire(flags=0,token=0,entry_ns=0),
                 wire(direction=2,cpu=42,seq=9007199254740993,epoch=23,token=9007199254740993,caller=1,cls=1,label=1), wire(caller=1,cls=2,label=6), wire(caller=1,cls=3,label=10)]
        invalid = [wire()[:i] for i in range(72)] + [wire()+b'\0']
        for k,v in [('magic',0),('version',2),('kind',2),('flags',2),('direction',0),('cpu',1048576),
                    ('epoch',0),('token',0),('entry_ns',31),('caller',5),('cls',1),('label',1),('reserved',1)]:
            invalid.append(wire(**{k:v}))
        invalid += [wire(caller=1,cls=2,label=1), wire(flags=0), wire(token=2**64-1)]
        for raw in valid:
            got=subprocess.run([str(binary)],input=raw,capture_output=True,env=env)
            fields = struct.unpack('<IHHHHIQQQQQiiHHHH', raw)
            expected = (' '.join(str(fields[i]) for i in [4,5,6,7,8,9,10,11,12,13,14,15,3]) + '\n').encode()
            assert got.returncode == 0 and got.stdout == expected and not got.stderr, got
        for raw in invalid:
            got=subprocess.run([str(binary)],input=raw,capture_output=True,env=env)
            assert got.returncode == 2 and not got.stdout and not got.stderr, got
        print('native journal: 6 positive,',len(invalid),'negative vectors; ASan/UBSan clean')

if __name__ == '__main__':
    main()
