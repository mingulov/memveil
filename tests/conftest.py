# SPDX-License-Identifier: GPL-3.0-or-later
"""Tree-wide pytest marker registration.

The qualification/dev-fixture selection markers are used
by the dispatched package files and read (for constants)
outside them; registering here keeps every session quiet.
"""


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "qualification: tests that run under dispatched "
        "candidate inputs")
    config.addinivalue_line(
        "markers",
        "dev_fixture: development fixture tests, excluded "
        "from dispatched qualification")
