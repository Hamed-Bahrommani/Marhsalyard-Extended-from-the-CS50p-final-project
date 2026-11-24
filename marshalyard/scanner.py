"""Scanner: one directory level per source, name checks first, no recursion.

Produces a Snapshot. It decides only what is never a candidate (spec 6, steps 1-2);
matching, age and fingerprinting belong to the planner.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from marshalyard.config import glob_matches
from marshalyard.filesystem import FileKind, FileSystem, FsError, StatInfo
from marshalyard.models import AbsPath, FileEntry, SkipReason, SkippedEntry, Snapshot

_DB_SUFFIXES = ("", "-wal", "-shm", "-journal", ".lock")


@dataclass(frozen=True, slots=True)
class SourceError:
    source: AbsPath
    reason: str


@dataclass(frozen=True, slots=True)
class ScanResult:
    snapshot: Snapshot
    source_errors: tuple[SourceError, ...]


def runtime_files(config_path: AbsPath, db_path: AbsPath) -> frozenset[AbsPath]:
    """Control files Marshal itself owns: never candidates, wherever they live."""
    paths = {config_path}
    for suffix in _DB_SUFFIXES:
        paths.add(db_path.with_name(db_path.name + suffix))
    return frozenset(paths)


def _name_skip(name: str, path: AbsPath, patterns: tuple[str, ...], runtime: frozenset[AbsPath]) -> SkipReason | None:
    if path in runtime:
        return SkipReason.RUNTIME_FILE
    if any(glob_matches(pattern, name) for pattern in patterns):
        return SkipReason.EXCLUDED
    return None


def _stat_skip(info: StatInfo) -> SkipReason | None:
    if info.kind is FileKind.SYMLINK:
        return SkipReason.SYMLINK
    if info.reparse_point:
        return SkipReason.REPARSE_POINT
    if info.kind is not FileKind.FILE:
        return SkipReason.NOT_REGULAR
    if info.hidden_or_system:
        return SkipReason.HIDDEN_OR_SYSTEM
    return None


def scan(
    fs: FileSystem,
    sources: Iterable[AbsPath],
    *,
    exclude: Iterable[str],
    runtime: Iterable[AbsPath] = (),
    taken_at_ns: int,
) -> ScanResult:
    patterns = tuple(exclude)
    runtime_set = frozenset(runtime)

    unique: list[AbsPath] = []
    seen: set[AbsPath] = set()
    for source in sorted(sources, key=lambda p: p.as_posix()):
        if source not in seen:
            seen.add(source)
            unique.append(source)

    scanned: list[AbsPath] = []
    errors: list[SourceError] = []
    entries: list[FileEntry] = []
    skipped: list[SkippedEntry] = []

    for source in unique:
        try:
            names = fs.list_dir(source)
        except FsError as exc:
            errors.append(SourceError(source, exc.reason))
            continue
        scanned.append(source)
        for name in names:
            path = source / name
            reason = _name_skip(name, path, patterns, runtime_set)
            if reason is not None:
                skipped.append(SkippedEntry(path, reason))
                continue
            try:
                info = fs.lstat(path)
            except FsError:
                skipped.append(SkippedEntry(path, SkipReason.UNREADABLE))
                continue
            if info is None:  # vanished between listing and stat
                continue
            reason = _stat_skip(info)
            if reason is not None:
                skipped.append(SkippedEntry(path, reason))
                continue
            entries.append(FileEntry(path, info.size, info.mtime_ns, info.dev, info.ino, info.nlink))

    snapshot = Snapshot(
        taken_at_ns,
        tuple(scanned),
        tuple(sorted(entries, key=lambda e: e.path.as_posix())),
        tuple(sorted(skipped, key=lambda s: s.path.as_posix())),
    )
    return ScanResult(snapshot, tuple(errors))
