"""Shared fixtures. `env` runs a test twice: once on the in-memory fake, once on the real disk."""

import os
from pathlib import PurePosixPath, PureWindowsPath

import pytest

from marshalyard.memoryfs import MemoryFileSystem
from marshalyard.realfs import RealFileSystem


class MemoryEnv:
    kind = "memory"

    def __init__(self):
        self.fs = MemoryFileSystem()
        self.root = PurePosixPath("/base")
        self.fs.add_dir(self.root)

    def p(self, *parts):
        return self.root.joinpath(*parts)

    def add_dir(self, path):
        self.fs.add_dir(path)

    def add_file(self, path, content=b"", mtime_ns=None, hidden=False):
        self.fs.add_file(path, content, mtime_ns=mtime_ns, hidden=hidden)

    def add_symlink(self, link, target):
        self.fs.add_symlink(link, target)

    def add_hardlink(self, existing, new):
        self.fs.add_hardlink(existing, new)

    def write(self, path, content):
        self.fs.write(path, content)

    def remove(self, path):
        self.fs.remove(path)

    def touch(self, path, mtime_ns):
        self.fs.touch(path, mtime_ns)


class RealEnv:
    kind = "real"

    def __init__(self, base):
        self.fs = RealFileSystem()
        path_type = PureWindowsPath if os.name == "nt" else PurePosixPath
        self.root = path_type(str(base.resolve()))

    def p(self, *parts):
        return self.root.joinpath(*parts)

    def add_dir(self, path):
        os.makedirs(str(path), exist_ok=True)

    def add_file(self, path, content=b"", mtime_ns=None, hidden=False):
        os.makedirs(str(path.parent), exist_ok=True)
        with open(str(path), "wb") as handle:
            handle.write(content)
        if mtime_ns is not None:
            os.utime(str(path), ns=(mtime_ns, mtime_ns))
        if hidden:
            if os.name != "nt":
                pytest.skip("the hidden attribute exists only on Windows")
            import ctypes

            if not ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x2):
                raise OSError("could not set the hidden attribute")

    def add_symlink(self, link, target):
        os.makedirs(str(link.parent), exist_ok=True)
        try:
            os.symlink(str(target), str(link), target_is_directory=os.path.isdir(str(target)))
        except OSError:
            pytest.skip("symlinks are not available here (Windows needs Developer Mode or admin)")

    def add_hardlink(self, existing, new):
        os.makedirs(str(new.parent), exist_ok=True)
        os.link(str(existing), str(new))

    def write(self, path, content):
        with open(str(path), "wb") as handle:  # truncates in place: same inode
            handle.write(content)

    def remove(self, path):
        os.remove(str(path))

    def touch(self, path, mtime_ns):
        os.utime(str(path), ns=(mtime_ns, mtime_ns))


@pytest.fixture(params=["memory", "real"])
def env(request, tmp_path):
    if request.param == "memory":
        return MemoryEnv()
    return RealEnv(tmp_path)
