"""The real FileSystem (POSIX and Windows), built on os and stat only.

Stat values come from fresh no-follow os.lstat calls; DirEntry data is never used
(on Windows it reports zero identity). Files are opened without following links.
"""

import ctypes
import errno
import functools
import os
import stat
import sys
from pathlib import PurePosixPath, PureWindowsPath

from marshalyard.filesystem import (
    DestinationExists,
    FileKind,
    FsError,
    NoReplaceUnsupported,
    SourceMissing,
    StatInfo,
)
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

_AT_FDCWD = -100
_RENAME_NOREPLACE = 1


@functools.lru_cache(maxsize=1)
def _renameat2():
    """The C library's renameat2, or None. There is deliberately no fallback."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        function = ctypes.CDLL(None, use_errno=True).renameat2
    except (OSError, AttributeError):
        return None
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    return function


def _native_rename(src: str, dst: str) -> None:
    """Atomic rename that never replaces an existing destination, or raise.

    FileExistsError: the destination exists. NotImplementedError: the platform or
    filesystem cannot guarantee no-replace. OSError: anything else.
    """
    if os.name == "nt":
        os.rename(src, dst)  # MoveFileEx without REPLACE_EXISTING: fails if dst exists
        return
    function = _renameat2()
    if function is None:
        raise NotImplementedError("no atomic no-replace rename is available on this platform")
    ctypes.set_errno(0)
    if function(_AT_FDCWD, os.fsencode(src), _AT_FDCWD, os.fsencode(dst), _RENAME_NOREPLACE) == 0:
        return
    code = ctypes.get_errno()
    if code in (errno.EINVAL, errno.ENOSYS):
        raise NotImplementedError("this filesystem does not support RENAME_NOREPLACE")
    raise OSError(code, os.strerror(code))  # EEXIST becomes FileExistsError automatically


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

    def move_no_clobber(self, src: AbsPath, dst: AbsPath) -> None:
        self._check(src)
        self._check(dst)
        source = self.lstat(src)
        if source is None:
            raise SourceMissing(src, "no such file")
        if source.kind is FileKind.SYMLINK or source.reparse_point:
            raise FsError(src, "refusing to move a symlink")
        if source.kind is not FileKind.FILE:
            raise FsError(src, "not a regular file")
        # Also stops a Windows case-only "rename" of the same file, which os.rename would allow.
        if self.lstat(dst) is not None:
            raise DestinationExists(dst, "destination already exists")
        try:
            _native_rename(str(src), str(dst))  # the atomic step: this is the real guarantee
        except NotImplementedError as exc:
            raise NoReplaceUnsupported(dst, str(exc)) from None
        except FileExistsError:
            raise DestinationExists(dst, "destination already exists") from None
        except FileNotFoundError:
            if self.lstat(src) is None:
                raise SourceMissing(src, "the source disappeared") from None
            raise FsError(dst, "destination directory does not exist") from None
        except OSError as exc:
            if exc.errno == errno.EXDEV:
                raise FsError(dst, "source and destination are on different devices") from None
            if self.lstat(dst) is not None:
                raise DestinationExists(dst, "destination already exists") from None
            raise FsError(dst, _reason(exc)) from None
