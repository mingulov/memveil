# SPDX-License-Identifier: GPL-3.0-or-later
"""Disposable guest processes run in an owned process group."""
import os
import signal
import subprocess


# Post-kill grace for the final pipe drain. Killed group
# members already wrote everything they will ever write;
# only an out-of-group holder can keep the pipes open past
# SIGKILL, and its further output is not this capture's
# forensics. Total timeout-path time stays bounded by
# timeout + 10 s + this grace.
FINAL_DRAIN_GRACE = 1


def _partial_text(pipe, blob):
    """Decode a TimeoutExpired partial like text-mode pipes.

    Matches communicate()'s own translation (locale
    decoding plus universal newlines) so the final drain
    carries the same bytes a completed read would.
    """
    if blob is None:
        blob = b""
    text = blob.decode(pipe.encoding, pipe.errors)
    return text.replace("\r\n", "\n").replace("\r", "\n")


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
            out,err=proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid,signal.SIGKILL)
            try:
                out,err=proc.communicate(timeout=FINAL_DRAIN_GRACE)
            except subprocess.TimeoutExpired as final:
                # Either pipe may still be complete (EOF closes
                # it); only a pipe the deadline caught open is
                # truncated, and it says so instead of silently
                # dropping whatever the holder still withheld.
                out=_partial_text(proc.stdout,final.output)
                err=_partial_text(proc.stderr,final.stderr)
                if not proc.stdout.closed:
                    out+=("\n[vm_process: stdout truncated after "
                           "%ds post-kill drain]\n" % FINAL_DRAIN_GRACE)
                elif final.output is None:
                    out+=("\n[vm_process: stdout unavailable: "
                           "process unreaped with closed pipes]\n")
                if not proc.stderr.closed:
                    err+=("\n[vm_process: stderr truncated after "
                           "%ds post-kill drain]\n" % FINAL_DRAIN_GRACE)
                elif final.stderr is None:
                    err+=("\n[vm_process: stderr unavailable: "
                           "process unreaped with closed pipes]\n")
        # The post-kill drain holds the partial console
        # capture; attach it so a timeout still leaves
        # forensics instead of discarding everything. The
        # same TimeoutExpired type propagates, now carrying
        # output.
        raise subprocess.TimeoutExpired(cmd,timeout,output=out,
                                        stderr=err)
    return subprocess.CompletedProcess(cmd,proc.returncode,out,err)
