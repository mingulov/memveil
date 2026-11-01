#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate owned native request tuples; no inferred persistent range identity."""
import sys
from owned_qualification import gate


def main():
    return gate('MEMVEIL_CONFIDENTIAL_RANGES', 'confidential-ranges')


if __name__ == '__main__':
    sys.exit(main())
