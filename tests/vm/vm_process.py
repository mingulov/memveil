# SPDX-License-Identifier: GPL-3.0-or-later
"""Disposable guest processes run in an owned process group."""
import os
import selectors
import signal
import subprocess
import time


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


def _unavailable_note(key,reason):
    """Bytes marking one unregistered stream lost.

    Names the stream and the registration error, so
    a collection missing a stream carries its reason
    instead of reporting clean success.
    """
    name={"out":"stdout","err":"stderr"}[key]
    return ("\n[vm_process: %s unavailable: "
            "selector registration failed "
            "(%s)]\n"%(name,reason)).encode("utf-8")


def _collect(proc,timeout):
    """Drain both pipes with a deadline, then reap.

    Returns (out_bytes, err_bytes, done): done means
    both pipes hit EOF and the child reaped. Partial
    bytes survive either deadline: unlike
    Popen.communicate, a child that outlives its
    closed pipes costs the reap only, never the bytes
    already read (communicate raises its final wait
    timeout with empty output fields, discarding
    them). EOF'd streams are closed, as with
    communicate. Readiness waits use the default
    selector, which has no fd-number ceiling
    (unlike select()'s 1024 fd_set). A stream the
    selector refuses stays visible: its bytes carry
    an unavailable-with-reason note, and done is
    False, so a collection missing a stream never
    reports clean success. No stdin pipe: the caller
    leaves stdin inherited.
    """
    want={}
    for key,name in (("out","stdout"),("err","stderr")):
        stream=getattr(proc,name,None)
        if stream is not None and not stream.closed:
            want[stream]=key
    chunks={"out":[],"err":[]}
    for stream in want:
        try:
            os.set_blocking(stream.fileno(),False)
        except (OSError,ValueError):
            pass
    open_streams=list(want)
    end=time.monotonic()+timeout
    selector=selectors.DefaultSelector()
    lost={}
    try:
        for stream in open_streams:
            try:
                selector.register(stream,
                                  selectors.EVENT_READ)
            except (OSError,ValueError) as exc:
                # Refused is unavailable, not EOF: the
                # sibling still drains, and the note
                # below keeps the loss visible.
                lost[stream]="%s: %s"%(type(exc).__name__,
                                       exc)
                try:
                    stream.close()
                except (OSError,ValueError):
                    pass
        open_streams=[stream for stream in open_streams
                      if not stream.closed]
        while open_streams:
            remaining=end-time.monotonic()
            if remaining<=0:
                break
            try:
                events=selector.select(min(remaining,0.5))
            except (OSError,ValueError):
                break
            for key,_mask in events:
                stream=key.fileobj
                try:
                    data=os.read(stream.fileno(),65536)
                except BlockingIOError:
                    continue
                except (OSError,ValueError):
                    data=b""
                if data:
                    chunks[want[stream]].append(data)
                    continue
                try:
                    selector.unregister(stream)
                except (OSError,ValueError,KeyError):
                    pass
                try:
                    stream.close()
                except (OSError,ValueError):
                    pass
                open_streams.remove(stream)
    finally:
        selector.close()
        for stream in open_streams:
            try:
                os.set_blocking(stream.fileno(),True)
            except (OSError,ValueError):
                pass
    for stream,reason in lost.items():
        chunks[want[stream]].append(
            _unavailable_note(want[stream],reason))
    try:
        proc.wait(timeout=max(end-time.monotonic(),0))
    except subprocess.TimeoutExpired:
        return (b"".join(chunks["out"]),
                b"".join(chunks["err"]),False)
    return (b"".join(chunks["out"]),b"".join(chunks["err"]),
            not open_streams and not lost)


def run_owned_guest(cmd,timeout):
    proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          start_new_session=True)
    first_out,first_err,done=_collect(proc,timeout)
    if done:
        out=_capture_text(first_out,"stdout")
        err=_capture_text(first_err,"stderr")
        return subprocess.CompletedProcess(cmd,proc.returncode,out,err)
    # Descendant QEMU processes share this newly created group. Nothing
    # from before this invocation is addressed by the cleanup.
    # The drain above reaps the child once it exits, so the
    # group may already be empty; that means there is
    # nothing left to signal.
    try:
        os.killpg(proc.pid,signal.SIGTERM)
    except ProcessLookupError:
        pass
    second_out,second_err,done=_collect(proc,10)
    raw_out=first_out+second_out
    raw_err=first_err+second_err
    if done:
        out=_capture_text(raw_out,"stdout")
        err=_capture_text(raw_err,"stderr")
        # The post-kill drain holds the partial console
        # capture; attach it so a timeout still leaves
        # forensics instead of discarding everything. The
        # same TimeoutExpired type propagates, now carrying
        # output.
        raise subprocess.TimeoutExpired(cmd,timeout,output=out,
                                        stderr=err)
    try:
        os.killpg(proc.pid,signal.SIGKILL)
    except ProcessLookupError:
        pass
    third_out,third_err,_final=_collect(proc,FINAL_DRAIN_GRACE)
    out=_capture_text(raw_out+third_out,"stdout")
    err=_capture_text(raw_err+third_err,"stderr")
    # Either pipe may still be complete (EOF closes
    # it); only a pipe the deadline caught open is
    # truncated, and it says so instead of silently
    # dropping whatever the holder still withheld.
    if not proc.stdout.closed:
        out+=("\n[vm_process: stdout truncated after "
               "%ds post-kill drain]\n" % FINAL_DRAIN_GRACE)
    if not proc.stderr.closed:
        err+=("\n[vm_process: stderr truncated after "
               "%ds post-kill drain]\n" % FINAL_DRAIN_GRACE)
    if proc.poll() is None:
        err+=("\n[vm_process: child unreaped after "
               "SIGKILL; showing captured output]\n")
    raise subprocess.TimeoutExpired(cmd,timeout,output=out,
                                    stderr=err)
