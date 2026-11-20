# SPDX-License-Identifier: GPL-3.0-or-later
"""Candidate package qualification never turns required skips into success."""
from pathlib import Path
import sys
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from support.candidate_input import requested, load
from support.deferred_skips import unlisted_skips


def pytest_sessionstart(session):
    if requested():
        load(required=True)


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    reporter = session.config.pluginmanager.get_plugin(
        'terminalreporter')
    if requested() and reporter \
            and reporter.stats.get('skipped') \
            and session.exitstatus == 0:
        unlisted = unlisted_skips(
            reporter.stats.get('skipped'))
        if unlisted:
            reporter.write_line(
                'candidate session refuses unlisted skips:')
            for line in unlisted:
                reporter.write_line('  ' + line)
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
