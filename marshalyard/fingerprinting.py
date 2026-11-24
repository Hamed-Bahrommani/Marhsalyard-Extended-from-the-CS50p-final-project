"""Fingerprinting per spec 7.2: a best-effort consistency check, not an atomic snapshot.

Built on the FileSystem port only, so the in-memory fake can inject races between
any two calls.
"""

import hashlib
from dataclasses import dataclass

from marshalyard.filesystem import FileKind, FileSystem, FsError
from marshalyard.models import (
    HASH_THRESHOLD,
    FileEntry,
    Fingerprint,
    FpMethod,
    Unplanned,
    UnplannedReason,
)

CHUNK_SIZE = 1024 * 1024
_FIELDS = ("dev", "ino", "nlink", "size", "mtime_ns")


@dataclass(frozen=True, slots=True)
class FingerprintFailure:
    reason: UnplannedReason
    detail: str


def _differences(left, right) -> list[str]:
    return [name for name in _FIELDS if getattr(left, name) != getattr(right, name)]


def _changed(detail: str) -> FingerprintFailure:
    return FingerprintFailure(UnplannedReason.CHANGED_DURING_PLANNING, detail)


def fingerprint(fs: FileSystem, entry: FileEntry, threshold: int = HASH_THRESHOLD) -> Fingerprint | FingerprintFailure:
    path = entry.path
    try:
        s0 = fs.lstat(path)
    except FsError:
        return FingerprintFailure(UnplannedReason.UNREADABLE, "cannot be inspected")
    if s0 is None:
        return _changed("file disappeared after scan")
    if s0.kind is not FileKind.FILE:
        return _changed("no longer a regular file")
    diff = _differences(s0, entry)
    if diff:
        return _changed(f"metadata changed after scan: {', '.join(diff)}")
    if s0.dev == 0 or s0.ino == 0:
        return FingerprintFailure(UnplannedReason.IDENTITY_UNAVAILABLE, "")
    if s0.nlink <= 0:
        return FingerprintFailure(UnplannedReason.LINK_COUNT_UNAVAILABLE, "")
    if s0.nlink > 1:
        return FingerprintFailure(UnplannedReason.MULTIPLE_LINKS, f"nlink={s0.nlink}")

    if s0.size > threshold:  # nothing is read above the threshold
        return Fingerprint(
            dev=s0.dev, ino=s0.ino, nlink=s0.nlink, size=s0.size, mtime_ns=s0.mtime_ns,
            sha256=None, method=FpMethod.METADATA,
        )

    try:
        handle = fs.open_read(path)
    except FsError:
        return FingerprintFailure(UnplannedReason.UNREADABLE, "cannot be opened")
    try:
        s1 = handle.fstat()
        if (s1.dev, s1.ino) != (s0.dev, s0.ino):
            return _changed("file was replaced before it was read")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        s2 = handle.fstat()
    except FsError:
        return FingerprintFailure(UnplannedReason.UNREADABLE, "cannot be read")
    finally:
        handle.close()

    try:
        s3 = fs.lstat(path)
    except FsError:
        return FingerprintFailure(UnplannedReason.UNREADABLE, "cannot be inspected")
    if s3 is None:
        return _changed("file disappeared during planning")
    if s3.kind is not FileKind.FILE:
        return _changed("no longer a regular file")
    for stage in (s1, s2, s3):
        diff = _differences(stage, s0)
        if diff:
            return _changed(f"metadata changed while reading: {', '.join(diff)}")
    if total != s0.size:
        return _changed("content length differs from size")

    return Fingerprint(
        dev=s0.dev, ino=s0.ino, nlink=s0.nlink, size=s0.size, mtime_ns=s0.mtime_ns,
        sha256=digest.hexdigest(), method=FpMethod.CONTENT,
    )


def to_unplanned(entry: FileEntry, failure: FingerprintFailure) -> Unplanned:
    return Unplanned(entry.path, failure.reason, failure.detail)
