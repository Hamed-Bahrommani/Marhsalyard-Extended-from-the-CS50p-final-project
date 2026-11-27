"""The FileSystem port: the only way domain and planner code touches a disk.

M2 provides an in-memory fake; M3 provides the real implementation. Keeping the
port to four primitives lets the fake interleave faults and races between
individual calls, which is how the safety protocols get tested.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from marshalyard.models import AbsPath, Flavor


class FileKind(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class StatInfo:
    """Result of a no-follow stat. Zero dev/ino/nlink mean 'unavailable'."""

    kind: FileKind
    dev: int
    ino: int
    nlink: int
    size: int
    mtime_ns: int
    hidden_or_system: bool = False
    reparse_point: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.kind, FileKind):
            raise ValueError("StatInfo.kind must be a FileKind")
        for name in ("dev", "ino", "nlink", "size"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"StatInfo.{name} must be an int >= 0")
        if isinstance(self.mtime_ns, bool) or not isinstance(self.mtime_ns, int):
            raise ValueError("StatInfo.mtime_ns must be an int")
        if not isinstance(self.hidden_or_system, bool) or not isinstance(self.reparse_point, bool):
            raise ValueError("StatInfo flags must be bools")


class FsError(Exception):
    """An I/O failure other than 'does not exist' (which lstat reports as None)."""

    def __init__(self, path: AbsPath, reason: str) -> None:
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason


class ReadHandle(Protocol):
    def fstat(self) -> StatInfo: ...

    def read(self, size: int = -1) -> bytes: ...

    def close(self) -> None: ...


class FileSystem(Protocol):
    @property
    def flavor(self) -> Flavor: ...

    def lstat(self, path: AbsPath) -> StatInfo | None:
        """No-follow stat. None if the path does not exist; FsError otherwise on failure."""

    def list_dir(self, path: AbsPath) -> tuple[str, ...]:
        """Names directly inside a directory. FsError if it is missing, not a directory or unreadable."""

    def open_read(self, path: AbsPath) -> ReadHandle:
        """Open a regular file for reading without following links. FsError on failure."""

    def realpath(self, path: AbsPath) -> AbsPath:
        """The path with every link resolved."""
    
    def move_no_clobber(self, src: AbsPath, dst: AbsPath) -> None: ...

class SourceMissing(FsError):
    """move_no_clobber: the source is not there."""


class DestinationExists(FsError):
    """move_no_clobber: something already occupies the destination; nothing was moved."""


class NoReplaceUnsupported(FsError):
    """move_no_clobber: this platform or filesystem cannot guarantee a no-replace rename."""
