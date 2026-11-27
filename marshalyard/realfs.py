"""The real FileSystem (POSIX and Windows), built on os and stat only.

Stat values come from fresh no-follow os.lstat calls; DirEntry data is never used
(on Windows it reports zero identity). Files are opened without following links.
"""

import os
import stat
from pathlib import PurePosixPath, PureWindowsPath

from marshalyard.filesystem import FileKind, FsError, StatInfo
from marshalyard.models import AbsPath, Flavor

_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_HIDDEN_MASK = getattr(stat, "FILE_ATTRIBUTE_HIDDEN", 0) | getattr(stat, "FILE_ATTRIBUTE_SYSTEM", 0)
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)


def _stat_info(st: os.stat_result) -> StatInfo:
    mode = st.st_mode
    if stat.S_ISLNK(mode):
        kind = FileKind.SYMLINK
    elif stat.S_ISREG(mode):
        kind = FileKind.FILE
    elif stat.S_ISDIR(mode):
        kind = FileKind.DIRECTORY
    else:
        kind = FileKind.OTHER
    attributes = getattr(st, "st_file_attributes", 0)
    return StatInfo(
        kind=kind,
        dev=st.st_dev,
        ino=st.st_ino,
        nlink=st.st_nlink,
        size=st.st_size if kind is FileKind.FILE else 0,
        mtime_ns=st.st_mtime_ns,
        hidden_or_system=bool(attributes & _HIDDEN_MASK),
        reparse_point=bool(attributes & _REPARSE),
    )


def _reason(exc: BaseException) -> str:
    return getattr(exc, "strerror", None) or type(exc).__name__


class _RealHandle:
    def __init__(self, path: AbsPath, fd: int) -> None:
        self._path = path
        self._fd = fd
        self._closed = False

    def _live(self) -> None:
        if self._closed:
            raise FsError(self._path, "handle is closed")

    def fstat(self) -> StatInfo:
        self._live()
        try:
            return _stat_info(os.fstat(self._fd))
        except OSError as exc:
            raise FsError(self._path, _reason(exc)) from None

    def read(self, size: int = -1) -> bytes:
        self._live()
        try:
            if size is None or size < 0:
                chunks = []
                while True:
                    chunk = os.read(self._fd, 1024 * 1024)
                    if not chunk:
                        return b"".join(chunks)
                    chunks.append(chunk)
            return os.read(self._fd, size)
        except OSError as exc:
            raise FsError(self._path, _reason(exc)) from None

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            os.close(self._fd)


class RealFileSystem:
    def __init__(self) -> None:
        self._flavor = Flavor.WINDOWS if os.name == "nt" else Flavor.POSIX
        self._path_type = PureWindowsPath if os.name == "nt" else PurePosixPath

    @property
    def flavor(self) -> Flavor:
        return self._flavor

    def _check(self, path: AbsPath) -> None:
        if type(path) is not self._path_type or not path.is_absolute():
            raise ValueError(f"{path!r} is not an absolute {self._flavor.value} path")

    def lstat(self, path: AbsPath) -> StatInfo | None:
        self._check(path)
        try:
            return _stat_info(os.lstat(str(path)))
        except (FileNotFoundError, NotADirectoryError):
            return None
        except (OSError, ValueError) as exc:
            raise FsError(path, _reason(exc)) from None

    def list_dir(self, path: AbsPath) -> tuple[str, ...]:
        self._check(path)
        try:
            return tuple(os.listdir(str(path)))
        except FileNotFoundError:
            raise FsError(path, "no such directory") from None
        except NotADirectoryError:
            raise FsError(path, "not a directory") from None
        except (OSError, ValueError) as exc:
            raise FsError(path, _reason(exc)) from None

    def open_read(self, path: AbsPath) -> _RealHandle:
        self._check(path)
        before = self.lstat(path)
        if before is None:
            raise FsError(path, "no such file")
        if before.kind is FileKind.SYMLINK or before.reparse_point:
            raise FsError(path, "refusing to follow a symlink")
        if before.kind is not FileKind.FILE:
            raise FsError(path, "not a regular file")
        flags = os.O_RDONLY | _O_BINARY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC
        try:
            fd = os.open(str(path), flags)
        except OSError as exc:
            raise FsError(path, _reason(exc)) from None
        try:
            after = _stat_info(os.fstat(fd))
        except OSError as exc:
            os.close(fd)
            raise FsError(path, _reason(exc)) from None
        if after.kind is not FileKind.FILE or (after.dev, after.ino) != (before.dev, before.ino):
            os.close(fd)
            raise FsError(path, "the file changed while being opened")
        return _RealHandle(path, fd)

    def realpath(self, path: AbsPath) -> AbsPath:
        self._check(path)
        try:
            return self._path_type(os.path.realpath(str(path)))
        except (OSError, ValueError) as exc:
            raise FsError(path, _reason(exc)) from None
