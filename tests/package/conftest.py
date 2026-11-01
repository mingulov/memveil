# SPDX-License-Identifier: GPL-3.0-or-later
"""Candidate package qualification never turns required skips into success."""
import os
from pathlib import Path
import sys
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from support.candidate_input import requested, load


def pytest_sessionstart(session):
    if requested(): load(required=True)


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    reporter = session.config.pluginmanager.get_plugin('terminalreporter')
    if requested() and reporter and reporter.stats.get('skipped') and session.exitstatus == 0:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
