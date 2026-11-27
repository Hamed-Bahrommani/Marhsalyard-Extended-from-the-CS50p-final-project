from pathlib import PurePosixPath as P
from pathlib import PureWindowsPath as W

import pytest

from marshalyard.filesystem import DestinationExists, FsError, SourceMissing
from marshalyard.memoryfs import MemoryFileSystem
from marshalyard.models import Flavor


def test_windows_flavour_collides_case_insensitively():
    fs = MemoryFileSystem(Flavor.WINDOWS)
    fs.add_file(W("C:/in/x"), b"new")
    fs.add_file(W("C:/out/a.pdf"), b"old")
    with pytest.raises(DestinationExists):
        fs.move_no_clobber(W("C:/in/x"), W("C:/out/A.PDF"))
    assert fs.mutations == []


def test_windows_flavour_refuses_a_case_only_rename():
    fs = MemoryFileSystem(Flavor.WINDOWS)
    fs.add_file(W("C:/d/a.pdf"), b"x")
    with pytest.raises(DestinationExists):
        fs.move_no_clobber(W("C:/d/a.pdf"), W("C:/d/A.PDF"))
    assert fs.list_dir(W("C:/d")) == ("a.pdf",)


def test_the_destination_keeps_the_spelling_it_was_given():
    fs = MemoryFileSystem(Flavor.WINDOWS)
    fs.add_file(W("C:/in/x"), b"x")
    fs.add_dir(W("C:/out"))
    fs.move_no_clobber(W("C:/in/x"), W("C:/out/New.PDF"))
    assert fs.list_dir(W("C:/out")) == ("New.PDF",)


def test_cross_device_moves_are_refused():
    fs = MemoryFileSystem()
    fs.add_file(P("/in/a"), b"x")
    fs.add_dir(P("/other"), dev=2)
    with pytest.raises(FsError) as caught:
        fs.move_no_clobber(P("/in/a"), P("/other/a"))
    assert type(caught.value) is FsError
    assert fs.lstat(P("/in/a")) is not None
    assert fs.mutations == []


def test_successful_moves_are_logged_and_failed_ones_are_not():
    fs = MemoryFileSystem()
    fs.add_file(P("/in/a"), b"x")
    fs.add_dir(P("/out"))
    with pytest.raises(SourceMissing):
        fs.move_no_clobber(P("/in/missing"), P("/out/missing"))
    assert fs.mutations == []
    fs.move_no_clobber(P("/in/a"), P("/out/a"))
    assert fs.mutations == [("move", P("/in/a"), P("/out/a"))]
    assert ("move_no_clobber", P("/in/a")) in fs.calls


def test_a_race_between_planning_and_moving_is_caught():
    fs = MemoryFileSystem()
    fs.add_file(P("/in/a"), b"mine")
    fs.add_dir(P("/out"))
    fs.inject("move_no_clobber", lambda f, p: f.add_file(P("/out/a"), b"theirs"), path=P("/in/a"))
    with pytest.raises(DestinationExists):
        fs.move_no_clobber(P("/in/a"), P("/out/a"))
    assert fs.read_bytes(P("/out/a")) == b"theirs"
    assert fs.read_bytes(P("/in/a")) == b"mine"
    assert fs.mutations == []
