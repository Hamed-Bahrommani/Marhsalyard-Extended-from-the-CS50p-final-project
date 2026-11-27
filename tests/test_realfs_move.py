import errno
import os
import sys
from pathlib import PurePosixPath, PureWindowsPath

import pytest

from marshalyard import realfs
from marshalyard.filesystem import DestinationExists, FsError, NoReplaceUnsupported, SourceMissing
from marshalyard.realfs import RealFileSystem

fs = RealFileSystem()


def anchor(path):
    path_type = PureWindowsPath if os.name == "nt" else PurePosixPath
    return path_type(str(path.resolve()))


def pair(tmp_path):
    (tmp_path / "in").mkdir()
    (tmp_path / "out").mkdir()
    (tmp_path / "in" / "a").write_bytes(b"x")
    return anchor(tmp_path) / "in" / "a", anchor(tmp_path) / "out" / "a"


def test_a_read_only_source_can_be_moved(tmp_path):
    src, dst = pair(tmp_path)
    os.chmod(str(src), 0o444)
    try:
        fs.move_no_clobber(src, dst)
        assert os.stat(str(dst)).st_mode & 0o200 == 0  # still read-only after the move
    finally:
        os.chmod(str(dst), 0o666)


def boom(error):
    def raiser(src, dst):
        raise error

    return raiser


@pytest.mark.parametrize(
    "error, expected",
    [
        (FileExistsError(errno.EEXIST, "exists"), DestinationExists),
        (NotImplementedError("no support"), NoReplaceUnsupported),
        (OSError(errno.EXDEV, "cross-device"), FsError),
        (FileNotFoundError(errno.ENOENT, "gone"), FsError),
        (PermissionError(errno.EACCES, "denied"), FsError),
    ],
)
def test_native_errors_are_mapped(tmp_path, monkeypatch, error, expected):
    src, dst = pair(tmp_path)
    monkeypatch.setattr(realfs, "_native_rename", boom(error))
    with pytest.raises(FsError) as caught:
        fs.move_no_clobber(src, dst)
    assert type(caught.value) is expected
    assert fs.lstat(src) is not None and fs.lstat(dst) is None


def test_a_source_that_vanishes_during_the_move_is_reported_as_missing(tmp_path, monkeypatch):
    src, dst = pair(tmp_path)

    def vanish(source, target):
        os.remove(source)
        raise FileNotFoundError(errno.ENOENT, "gone")

    monkeypatch.setattr(realfs, "_native_rename", vanish)
    with pytest.raises(SourceMissing):
        fs.move_no_clobber(src, dst)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="renameat2 is Linux-only")
def test_a_missing_renameat2_fails_closed(tmp_path, monkeypatch):
    src, dst = pair(tmp_path)
    monkeypatch.setattr(realfs, "_renameat2", lambda: None)
    with pytest.raises(NoReplaceUnsupported):
        fs.move_no_clobber(src, dst)
    assert fs.lstat(src) is not None and fs.lstat(dst) is None


def test_the_atomic_primitive_itself_refuses_to_clobber_a_file(tmp_path):
    src, dst = pair(tmp_path)
    (tmp_path / "out" / "a").write_bytes(b"old")
    with pytest.raises(FileExistsError):
        realfs._native_rename(str(src), str(dst))
    assert (tmp_path / "in" / "a").read_bytes() == b"x"
    assert (tmp_path / "out" / "a").read_bytes() == b"old"


def test_the_atomic_primitive_refuses_an_existing_directory(tmp_path):
    src, _ = pair(tmp_path)
    target = tmp_path / "out" / "dir"
    target.mkdir()
    with pytest.raises(OSError):
        realfs._native_rename(str(src), str(anchor(tmp_path) / "out" / "dir"))
    assert target.is_dir()
    assert (tmp_path / "in" / "a").read_bytes() == b"x"