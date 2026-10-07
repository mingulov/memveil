# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared fallible-outcome shape for native-backed operations.

OpOut lives here (not in the collector) so replay verbs can use
signal and clock helpers without importing live collection or
the native bridge.
"""


@fieldwise_init
struct OpOut(Copyable, Movable):
    """One fallible kernel-side operation outcome."""

    var ok: Bool
    var message: String
