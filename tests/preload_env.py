# SPDX-License-Identifier: GPL-3.0-or-later
"""Compose test interposers without losing sanitizer or inherited guards."""
from functools import lru_cache
import os
from pathlib import Path
import re
import subprocess


@lru_cache(maxsize=None)
def sanitizer_runtime(binary):
    # Query the executable's dependencies, not the parent's injected libraries.
    # Otherwise ldd prints an already-preloaded runtime without a "=>" mapping.
    query_env = dict(os.environ)
    query_env.pop('LD_PRELOAD', None)
    result = subprocess.run(['ldd', str(binary)], env=query_env,
                            check=True, capture_output=True, text=True)
    for line in result.stdout.splitlines():
        match = re.search(r'(?:libasan[^ ]*|libclang_rt\.asan[^ ]*) => (/\S+)', line)
        if match and Path(match[1]).is_file():
            return str(Path(match[1]).resolve())
    raise RuntimeError('sanitized test executable has no resolved ASan runtime: ' + str(binary))


def preload_env(binary, *adapters, env=None):
    result = dict(os.environ if env is None else env)
    inherited = re.split(r'[:\s]+', result.get('LD_PRELOAD', ''))
    first = [sanitizer_runtime(str(binary))] if result.get('LMB_SANITIZE') == '1' else []
    ordered = []
    seen = set()
    for entry in [*first, *map(str, adapters), *inherited]:
        if entry and os.path.realpath(entry) not in seen:
            ordered.append(entry)
            seen.add(os.path.realpath(entry))
    result['LD_PRELOAD'] = ':'.join(ordered)
    return result
