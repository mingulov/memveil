# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain verified gate evidence in the workflow-owned directory.

Gates verify exports in a temporary directory that success-path
cleanup deletes. When MEMVEIL_EVIDENCE_DIR names the
workflow-owned evidence directory, retain_gate_evidence copies
the verified export files plus sidecars into
<evidence>/gates/<gate>/, writes a sanitized receipt manifest
(receipt.json) with per-file hashes, and verifies the copy
before the caller deletes the temporary directory. Only
allowlisted metadata crosses: file hashes, counts, flags, and
short tokens. Payloads, keys, raw addresses, command lines,
and environment text are refused.
"""
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from export_validation import (RECEIPT_DISPOSITIONS,
                               receipt_detail, receipt_gate,
                               strict_json,
                               validate_evidence_receipt)

EVIDENCE_ENV = "MEMVEIL_EVIDENCE_DIR"


def evidence_dir():
    """The workflow-owned evidence directory, or None locally."""
    raw = os.environ.get(EVIDENCE_ENV)
    if not raw:
        return None
    return Path(raw)


def infer_gate(tmp):
    """The single gate prefix verified under tmp/export, or None."""
    export = Path(tmp) / "export"
    if not export.is_dir():
        return None
    gates = set()
    for path in export.iterdir():
        name = path.name
        if name.endswith(".sha256"):
            name = name[:-len(".sha256")]
        if "-" not in name:
            return None
        gates.add(name.split("-", 1)[0])
    if len(gates) != 1:
        return None
    return next(iter(gates))


def _sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


class VerifiedExports(dict):
    """Verifier output with the hashes captured at verification.

    Gate verifiers return this mapping of short export names to
    paths; verified_hashes carries the full export names and
    digests proven during verification, immune to later
    replacement of the mutable export files.
    """

    def __init__(self, mapping, verified_hashes):
        super().__init__(mapping)
        self.verified_hashes = dict(verified_hashes)


def snapshot_exports(tmp, prefix, names):
    """Hash live exports into an immutable snapshot for verification.

    Each named export is read exactly once: those bytes are
    hashed against the sidecar digest and written to a snapshot
    directory under tmp, outside the live export tree. Returns
    (got, verified): got maps short names to snapshot paths for
    every later semantic check, and verified maps full export
    names to the digests proven here.

    Hashing and every later semantic check consume these
    snapshot bytes, never the mutable live paths, so bytes
    swapped in after their hash cannot pass verification.
    Distinct names sharing one live source (symlink or
    hardlink) are rejected, so snapshotting cannot launder
    aliases into distinct snapshot paths. Source identity
    comes from fstat() on the same open handle the bytes
    are read from, so a path swapped between a stat and a
    later read cannot bypass the reuse check.
    """
    export = Path(tmp) / "export"
    staged = Path(tempfile.mkdtemp(
        prefix=".verified-" + prefix + "-", dir=str(Path(tmp))))
    got = {}
    verified = {}
    seen = {}
    for name in names:
        target = export / f"{prefix}-{name}"
        sidecar = Path(str(target) + ".sha256")
        assert target.is_file(), f"missing export {prefix}-{name}"
        assert sidecar.is_file(), \
            f"missing sidecar {prefix}-{name}.sha256"
        sidecar_text = sidecar.read_text()
        assert re.fullmatch(
            r"[0-9a-f]{64}(?:  " + re.escape(target.name)
            + r")?\n", sidecar_text), "invalid hash sidecar"
        want = sidecar_text.split()[0]
        with target.open("rb") as handle:
            source = os.fstat(handle.fileno())
            identity = (source.st_dev, source.st_ino)
            assert identity not in seen, \
                f"reused export source {prefix}-{name}"
            seen[identity] = name
            data = handle.read()
        digest = hashlib.sha256(data).hexdigest()
        assert digest == want, f"hash mismatch {prefix}-{name}"
        (staged / target.name).write_bytes(data)
        got[name] = staged / target.name
        verified[f"{prefix}-{name}"] = digest
    return got, verified


def expected_from_verified(got, prefix):
    """Verified names and hashes for retention.

    got maps short export names to paths, as returned by the
    gate verifiers; prefix is the on-disk export prefix. The
    result requires every verified export during retention.
    When the verifier carried its proven hashes, those are
    reused verbatim instead of rehashing the mutable paths.
    """
    receipt_gate(prefix)
    carried = getattr(got, "verified_hashes", None)
    if carried is not None:
        want = {prefix + "-" + short for short in got}
        if set(carried) != want:
            raise ValueError("verified export identity drift")
        for digest in carried.values():
            if type(digest) is not str or not re.fullmatch(
                    r"[0-9a-f]{64}", digest):
                raise ValueError("verified export identity drift")
        return dict(carried)
    expected = {}
    for short, path in got.items():
        expected[prefix + "-" + short] = _sha_file(path)
    return expected


def _sidecar_digest(raw, name):
    try:
        text = raw.decode("ascii")
    except (AttributeError, UnicodeDecodeError):
        return None, "missing sidecar"
    if not re.fullmatch(
            r"[0-9a-f]{64}(?:  " + re.escape(name) + r")?\n",
            text):
        return None, "missing sidecar"
    return text.split()[0], ""


def _copy_verified(source, dest):
    """Copy one file with a single source read, then prove it.

    Returns the staged digest. The source is read exactly
    once; the proof rereads only the staged copy, never the
    mutable source.
    """
    digest = hashlib.sha256()
    tmp = dest.with_name(dest.name + ".partial")
    try:
        with open(source, "rb") as origin, open(tmp, "wb") as kept:
            for chunk in iter(lambda: origin.read(1048576), b""):
                digest.update(chunk)
                kept.write(chunk)
        os.replace(tmp, dest)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    if _sha_file(dest) != digest.hexdigest():
        raise ValueError("retained copy drifted")
    return digest.hexdigest()


_ATTEMPT_NAMES = frozenset((
    "ledger.json", "oracle.json", "ping.txt", "record.stdout",
    "record.stderr", "session.json", "events.ndjson"))


def _validate_export_contents(short_got, export_prefix):
    """Grammar validation for the exact bytes about to be copied.

    Hashing proves survival; only the export grammar proves
    sanitization. Raises ValueError when the allowlisted
    filenames or their contents are rejected.
    """
    if set(short_got) == _ATTEMPT_NAMES:
        from export_validation import validate_attempt_exports
        validate_attempt_exports(short_got, None)
        return
    from export_validation import validate_lifecycle_exports
    validate_lifecycle_exports(short_got, export_prefix)


def retain_gate_evidence(tmp, gate, disposition, detail=None,
                         expected=None, export_prefix=None):
    """Copy verified exports into the owned directory.

    Returns the receipt path, or None when retention is not
    configured. Raises before publishing anything when a
    passed gate cannot be verified; failed gates record
    per-file errors and are never complete.

    expected carries the names and hashes already verified by
    the gate; every expected export is required, and a
    vanished pair reports missing export instead of silently
    passing with the survivors. export_prefix names the
    on-disk export prefix when the retained gate identity is
    distinct from it.

    Sources are read exactly once into a staging directory
    outside the uploaded gates tree; grammar validation and
    the receipt proof run against those staged bytes, and the
    finished directory is published atomically. A failure
    leaves no partial gate directory behind.
    """
    receipt_gate(gate)
    if export_prefix is not None:
        receipt_gate(export_prefix)
    prefix = export_prefix or gate
    if disposition not in RECEIPT_DISPOSITIONS:
        raise ValueError("unknown evidence disposition")
    receipt_detail(detail)
    root = evidence_dir()
    if root is None:
        return None
    export = Path(tmp) / "export" if tmp is not None else None
    want_hashes = {}
    names = []
    if expected is not None:
        if isinstance(expected, dict):
            names = sorted(expected.keys())
            want_hashes = dict(expected)
        else:
            names = sorted(expected)
        for name in names:
            if not re.fullmatch(r'[a-z0-9][a-z0-9-.]{0,127}',
                                name):
                raise ValueError("unexpected retained export")
            if not name.startswith(prefix + "-"):
                raise ValueError("unexpected retained export")
        if export is not None and export.is_dir():
            present = {p.name for p in export.iterdir()
                       if p.is_file()
                       and p.name.startswith(prefix + "-")
                       and not p.name.endswith(".sha256")}
            extras = present - set(names)
            if extras and disposition == "passed":
                raise ValueError(
                    "passed gate without verified exports")
    else:
        if export is not None and export.is_dir():
            names = sorted(p.name for p in export.iterdir()
                           if p.is_file()
                           and p.name.startswith(prefix + "-")
                           and not p.name.endswith(".sha256"))
    dest = root / "gates" / gate
    root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(
        prefix=".staging-" + gate + "-", dir=str(root)))
    published = False
    try:
        files = []
        errors = []
        if not names and disposition == "passed":
            raise ValueError(
                "passed gate without verified exports")
        if not names:
            errors.append({"name": gate + "-exports",
                           "error": "no verified exports"})
        staged = []
        for name in names:
            source = export / name if export is not None else None
            if source is None or not source.is_file():
                errors.append({"name": name,
                               "error": "missing export"})
                continue
            sidecar = Path(str(source) + ".sha256")
            if not sidecar.is_file():
                errors.append({"name": name,
                               "error": "missing sidecar"})
                continue
            try:
                sidecar_bytes = sidecar.read_bytes()
            except OSError:
                errors.append({"name": name,
                               "error": "missing sidecar"})
                continue
            want, problem = _sidecar_digest(sidecar_bytes, name)
            if problem:
                errors.append({"name": name, "error": problem})
                continue
            try:
                digest = _copy_verified(source, staging / name)
            except OSError:
                if disposition == "passed":
                    raise
                errors.append({"name": name,
                               "error": "copy failed"})
                continue
            if digest != want or (name in want_hashes
                                  and digest != want_hashes[name]):
                (staging / name).unlink(missing_ok=True)
                errors.append({"name": name,
                               "error": "hash mismatch"})
                continue
            try:
                (staging / (name + ".sha256")).write_bytes(
                    sidecar_bytes)
            except OSError:
                (staging / name).unlink(missing_ok=True)
                if disposition == "passed":
                    raise
                errors.append({"name": name,
                               "error": "copy failed"})
                continue
            staged.append((name, digest))
        if staged:
            short_got = {name[len(prefix) + 1:]: staging / name
                         for name, _ in staged}
            try:
                _validate_export_contents(short_got, prefix)
            except (ValueError, KeyError, OSError, TypeError,
                    IndexError):
                if disposition == "passed":
                    raise ValueError(
                        "passed gate without verified exports")
                for name, _ in staged:
                    (staging / name).unlink(missing_ok=True)
                    (staging / (name + ".sha256")).unlink(
                        missing_ok=True)
                staged = []
                if not errors:
                    errors.append(
                        {"name": gate + "-exports",
                         "error": "no verified exports"})
        for name, digest in staged:
            files.append({"name": name, "sha256": digest,
                          "bytes": (staging / name).stat().st_size})
        if disposition == "passed" and errors:
            raise ValueError("passed gate without verified exports")
        complete = (disposition == "passed" and bool(files)
                    and not errors)
        receipt = {"schema": "memveil-gate-evidence/1",
                   "gate": gate, "disposition": disposition,
                   "complete": complete, "files": files,
                   "file_errors": errors, "detail": detail}
        if export_prefix is not None and export_prefix != gate:
            receipt["export_prefix"] = export_prefix
        validate_evidence_receipt(receipt)
        (staging / "receipt.json").write_text(json.dumps(
            receipt, indent=2, sort_keys=True) + "\n")
        _verify_published(staging, receipt, gate)
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.rename(staging, dest)
        published = True
        return dest / "receipt.json"
    finally:
        if not published:
            shutil.rmtree(staging, ignore_errors=True)


def retain_failure(tmp, gate, expected=None,
                   export_prefix=None):
    """Best-effort failed receipt for a gate failure path.

    Returns the receipt path, or None when retention is not
    configured or nothing verifiable remains. Never raises:
    the gate error stays the failure signal.
    """
    if evidence_dir() is None:
        return None
    try:
        return retain_gate_evidence(tmp, gate, "failed",
                                    expected=expected,
                                    export_prefix=export_prefix)
    except (OSError, ValueError, TypeError, IndexError,
            KeyError):
        return None


def record_lane_disposition(suite, disposition, detail=None,
                            root=None):
    """A lane receipt for suites that ran no gate exports.

    Skipped lanes never boot a guest; lanes blocked by
    unresolved cleanup cannot trust their temporary
    directories. Both record an incomplete receipt so the
    owned directory still explains the lane.
    """
    receipt_gate(suite)
    if disposition not in ("skipped", "cleanup-uncertain",
                           "failed"):
        raise ValueError("lane receipts cannot pass")
    receipt_detail(detail)
    owned = root if root is not None else evidence_dir()
    if owned is None:
        return None
    root = owned
    dest = root / "gates" / suite
    dest.mkdir(parents=True, exist_ok=True)
    receipt = {"schema": "memveil-gate-evidence/1",
               "gate": suite, "disposition": disposition,
               "complete": False, "files": [],
               "file_errors": [], "detail": detail}
    validate_evidence_receipt(receipt)
    receipt_path = dest / "receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2,
                                       sort_keys=True) + "\n")
    verify_retained(suite, root)
    return receipt_path


def _verify_published(directory, receipt, gate):
    """Prove a receipt against the bytes beside it.

    Every manifest file must match its recorded size and
    hash, every sidecar must bind the same digest to the same
    name, and the directory must hold nothing else.
    """
    if receipt["gate"] != gate:
        raise ValueError("retained receipt names another gate")
    for entry in receipt["files"]:
        target = directory / entry["name"]
        sidecar = directory / (entry["name"] + ".sha256")
        if not target.is_file() or not sidecar.is_file():
            raise ValueError("retained export is missing")
        if target.stat().st_size != entry["bytes"]:
            raise ValueError("retained export changed size")
        if _sha_file(target) != entry["sha256"]:
            raise ValueError("retained export changed bytes")
        try:
            raw = sidecar.read_bytes()
        except OSError:
            raise ValueError("retained export is missing")
        want, problem = _sidecar_digest(raw, entry["name"])
        if problem or want != entry["sha256"]:
            raise ValueError("retained sidecar changed")
    want = {"receipt.json"}
    for entry in receipt["files"]:
        want.add(entry["name"])
        want.add(entry["name"] + ".sha256")
    have = ({p.name for p in directory.iterdir()}
            if directory.is_dir() else set())
    if have != want:
        raise ValueError("retained inventory drift")


def verify_retained(gate, root=None):
    """The retained receipt, proven against the retained bytes."""
    receipt_gate(gate)
    owned = root if root is not None else evidence_dir()
    if owned is None:
        raise ValueError("evidence retention is not configured")
    receipt_path = owned / "gates" / gate / "receipt.json"
    receipt = validate_receipt_file(receipt_path)
    _verify_published(owned / "gates" / gate, receipt, gate)
    return receipt


def validate_receipt_file(path):
    """Parse one receipt with duplicate-key refusal plus grammar."""
    try:
        text = Path(path).read_text()
    except OSError:
        raise ValueError("retained receipt is missing")
    receipt = strict_json(text)
    validate_evidence_receipt(receipt)
    return receipt


def mark_cleanup_uncertain(gate, root=None):
    """Replace a retained receipt with cleanup-uncertain.

    The retained bytes stay; only the disposition changes to
    record that temporary-directory removal failed. The gate
    still fails; the uploaded receipt no longer claims a
    clean passed run.
    """
    receipt_gate(gate)
    owned = root if root is not None else evidence_dir()
    if owned is None:
        raise ValueError("evidence retention is not configured")
    receipt_path = owned / "gates" / gate / "receipt.json"
    receipt = validate_receipt_file(receipt_path)
    if receipt["gate"] != gate:
        raise ValueError("retained receipt names another gate")
    receipt["disposition"] = "cleanup-uncertain"
    receipt["complete"] = False
    validate_evidence_receipt(receipt)
    receipt_path.write_text(json.dumps(receipt, indent=2,
                                       sort_keys=True) + "\n")
    verify_retained(gate, owned)
    return receipt_path


def retained_inventory(root=None):
    """Every retained receipt under the owned directory.

    Each receipt is proven against its retained bytes and
    its exact directory inventory, and any entry without a
    receipt is rejected, so the uploaded file set matches
    the manifests rather than a random path.
    """
    owned = root if root is not None else evidence_dir()
    if owned is None:
        raise ValueError("evidence retention is not configured")
    gates = owned / "gates"
    if not gates.is_dir():
        return []
    for child in sorted(gates.iterdir()):
        if not child.is_dir() or not (
                child / "receipt.json").is_file():
            raise ValueError("unmanifested retained evidence")
    found = sorted(p for p in gates.glob("*/receipt.json")
                   if p.is_file())
    for path in found:
        verify_retained(path.parent.name, owned)
    return found
