# SPDX-License-Identifier: GPL-3.0-or-later
"""Disposable guest processes run in an owned process group."""
import os
import signal
import subprocess


def run_owned_guest(cmd,timeout):
    proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          text=True,start_new_session=True)
    try:
        out,err=proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Descendant QEMU processes share this newly created group. Nothing
        # from before this invocation is addressed by the cleanup.
        os.killpg(proc.pid,signal.SIGTERM)
        try:
            proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid,signal.SIGKILL)
            proc.communicate()
        raise
    return subprocess.CompletedProcess(cmd,proc.returncode,out,err)
