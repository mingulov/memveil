"""Offline capture inspection for MemVeil.

This package reads authored or recorded capture directories, reduces
their events to attempt metrics, and renders text, JSON, and Markdown
reports. It never collects: no kernel, device, or bridge import is
needed to use it.
"""

from memveil.jsonscan import Scanner, ScanError
