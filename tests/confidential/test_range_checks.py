#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Confidential-ranges gate: owned live range-identity checks.

Requires MEMVEIL_CONFIDENTIAL_RANGES=1 with an admitted
confidential guest manifest. Unarmed runs exit 77 without
touching any guest; armed runs fail loudly until the owned
live range flow ships with real guest access.
"""

import os
import sys

CONFIDENTIAL = os.path.dirname(os.path.abspath(__file__))


def main():
    if os.environ.get("MEMVEIL_CONFIDENTIAL_RANGES", "0") != "1":
        print("confidential-ranges: SKIP: needs "
              "MEMVEIL_CONFIDENTIAL_RANGES=1 with an admitted guest")
        return 77
    manifest = os.path.join(CONFIDENTIAL, "range_manifest.json")
    if not os.path.isfile(manifest):
        print("confidential-ranges: SKIP: no admitted guest manifest")
        return 77
    print("FAIL confidential-ranges: armed but the owned live range "
          "flow is not implemented")
    return 1


if __name__ == "__main__":
    sys.exit(main())
