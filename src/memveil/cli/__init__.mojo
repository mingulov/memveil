# SPDX-License-Identifier: GPL-3.0-or-later

"""Command-line verbs for offline inspection and passive doctor."""

from memveil.cli.doctor import (
    DoctorReport,
    build_doctor_report,
    default_profiles_dir,
    render_doctor_json,
    render_doctor_text,
    resolve_profiles_dir,
    run_doctor,
    run_doctor_with,
)
from memveil.cli.report import CliError, ReportOptions, run_report
