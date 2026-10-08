# SPDX-License-Identifier: GPL-3.0-or-later
"""An armed qualification selection must not silently pass pytest skips."""
import os
import pytest


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session,exitstatus):
    armed=any(k.startswith('MEMVEIL_VM_') and v=='1' for k,v in os.environ.items())
    reporter=session.config.pluginmanager.get_plugin('terminalreporter')
    if armed and reporter and reporter.stats.get('skipped') and session.exitstatus==0:
        session.exitstatus=pytest.ExitCode.TESTS_FAILED
