#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Suite skip-code convention: skips exit 77, never 0.

A suite that runs zero assertions must not report success.
Drives the env-gated VM suites unarmed (and with a bogus
arming value) and requires exit 77 with a SKIP diagnostic.
Exits nonzero on the first failure.
"""

import os
import subprocess
import sys

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def main():
    cases = (("vm-kernels", "MEMVEIL_VM_KERNELS", None),
             ("vm-kernels", "MEMVEIL_VM_KERNELS", "bogus"),
             ("vm-scenarios", "MEMVEIL_VM_SCENARIOS", None))
    for suite, var, env_value in cases:
        label = "%s-%s" % (suite, "unset" if env_value is None else "bogus")
        env = dict(os.environ)
        env.pop(var, None)
        if env_value is not None:
            env[var] = env_value
        proc = subprocess.run(
            [os.path.join(REPO, "tools", "test"), suite],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        check("%s-exit-77" % label, proc.returncode == 77,
              "exit %d" % proc.returncode)
        check("%s-says-skipped" % label, b"SKIP" in proc.stdout)


if __name__ == "__main__":
    main()
