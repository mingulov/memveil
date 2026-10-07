#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Suite skip-code convention: skips exit 77, never 0.

A suite that runs zero assertions must not report success.
Drives tools/test buildcache without LMB_PACKAGE (and with a
bogus path) and requires exit 77 with a 'skipped' diagnostic.
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
    for label, env_value in (("unset", None),
                             ("bogus", "/nonexistent-lmb.tgz")):
        env = dict(os.environ)
        env.pop("LMB_PACKAGE", None)
        if env_value is not None:
            env["LMB_PACKAGE"] = env_value
        proc = subprocess.run(
            [os.path.join(REPO, "tools", "test"), "buildcache"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        check("%s-exit-77" % label, proc.returncode == 77,
              "exit %d" % proc.returncode)
        check("%s-says-skipped" % label, b"skipped" in proc.stdout)


if __name__ == "__main__":
    main()
