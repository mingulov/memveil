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


def _capture_text(blob, stream):
    """Decode captured bytes, lossy-but-total, honestly.

    Text pipes would raise UnicodeDecodeError on a
    truncated multibyte tail; that must never cost the
    receipt both streams. Undecodable bytes surface as
    U+FFFD with an explicit note naming the stream, so
    the receipt shows the replacement instead of
    silently carrying corrupted text.
    """
    if blob is None:
        blob = b""
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        text = blob.decode("utf-8", "replace")
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        return (text + "\n[vm_process: %s has undecodable "
                "bytes; shown as U+FFFD]\n" % stream)
    return text.replace("\r\n", "\n").replace("\r", "\n")


def run_owned_guest(cmd,timeout):
    proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          start_new_session=True)
    try:
        raw_out,raw_err=proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Descendant QEMU processes share this newly created group. Nothing
        # from before this invocation is addressed by the cleanup.
        os.killpg(proc.pid,signal.SIGTERM)
        try:
            raw_out,raw_err=proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid,signal.SIGKILL)
            try:
                raw_out,raw_err=proc.communicate(
                    timeout=FINAL_DRAIN_GRACE)
            except subprocess.TimeoutExpired as final:
                # Either pipe may still be complete (EOF closes
                # it); only a pipe the deadline caught open is
                # truncated, and it says so instead of silently
                # dropping whatever the holder still withheld.
                out=_capture_text(final.output,"stdout")
                err=_capture_text(final.stderr,"stderr")
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
                raise subprocess.TimeoutExpired(cmd,timeout,output=out,
                                                stderr=err)
        out=_capture_text(raw_out,"stdout")
        err=_capture_text(raw_err,"stderr")
        # The post-kill drain holds the partial console
        # capture; attach it so a timeout still leaves
        # forensics instead of discarding everything. The
        # same TimeoutExpired type propagates, now carrying
        # output.
        raise subprocess.TimeoutExpired(cmd,timeout,output=out,
                                        stderr=err)
    out=_capture_text(raw_out,"stdout")
    err=_capture_text(raw_err,"stderr")
    return subprocess.CompletedProcess(cmd,proc.returncode,out,err)
