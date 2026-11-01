#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate separately admitted real-guest owned conversion evidence; never provision or load."""
import sys
from owned_qualification import gate


def main():
    return gate('MEMVEIL_CONFIDENTIAL_REAL', 'confidential-real')


if __name__ == '__main__':
    sys.exit(main())
