from pathlib import PurePosixPath as P
from pathlib import PureWindowsPath as W

import pytest

from marshalyard.filesystem import FileKind, FsError
from marshalyard.memoryfs import MemoryFileSystem
from marshalyard.models import Flavor


def posix():
    return MemoryFileSystem()


def windows():
    return MemoryFileSystem(Flavor.WINDOWS)


# ------------------------------------------------------------ stat


def test_root_exists_once_something_is_added():
    fs = posix()
    fs.add_dir(P("/a"))
    assert fs.lstat(P("/")).kind is FileKind.DIRECTORY


def test_missing_paths_are_none():
    fs = posix()
    assert fs.lstat(P("/x")) is None
    fs.add_dir(P("/a"))
    assert fs.lstat(P("/a/b")) is None


def test_file_stat():
    fs = posix()
    ino = fs.add_file(P("/d/a.pdf"), b"hello", mtime_ns=123)
    info = fs.lstat(P("/d/a.pdf"))
    assert (info.kind, info.size, info.mtime_ns, info.nlink, info.dev, info.ino) == (
        FileKind.FILE, 5, 123, 1, 1, ino
    )
    assert ino >= 1


def test_default_mtime_attribute_is_used():
    fs = posix()
    fs.default_mtime_ns = 777
    fs.add_file(P("/d/a"))
    assert fs.lstat(P("/d/a")).mtime_ns == 777


def test_special_hidden_and_reparse_flags():
    fs = posix()
    fs.add_special(P("/d/fifo"))
    fs.add_file(P("/d/h"), hidden=True, reparse_point=True)
    assert fs.lstat(P("/d/fifo")).kind is FileKind.OTHER
    info = fs.lstat(P("/d/h"))
    assert info.hidden_or_system and info.reparse_point


def test_hidden_identity_reads_as_zero():
    fs = posix()
    fs.add_file(P("/d/a"), hide_identity=True)
    info = fs.lstat(P("/d/a"))
    assert (info.dev, info.ino, info.nlink) == (0, 0, 0)


def test_device_is_inherited_and_can_be_overridden():
    fs = posix()
    fs.add_dir(P("/mnt"), dev=7)
    fs.add_file(P("/mnt/a"))
    fs.add_file(P("/b"))
    assert fs.lstat(P("/mnt/a")).dev == 7
    assert fs.lstat(P("/b")).dev == 1


def test_hard_links_share_identity_and_count():
    fs = posix()
    fs.add_file(P("/d/a"), b"x")
    fs.add_hardlink(P("/d/a"), P("/d/b"))
    first, second = fs.lstat(P("/d/a")), fs.lstat(P("/d/b"))
    assert first.ino == second.ino and first.nlink == second.nlink == 2
    fs.remove(P("/d/b"))
    assert fs.lstat(P("/d/a")).nlink == 1


def test_hard_links_cannot_cross_devices():
    fs = posix()
    fs.add_file(P("/d/a"))
    fs.add_dir(P("/mnt"), dev=9)
    with pytest.raises(ValueError):
        fs.add_hardlink(P("/d/a"), P("/mnt/b"))


# ------------------------------------------------------------ directories and links


def test_list_dir_returns_names():
    fs = posix()
    fs.add_file(P("/d/a"))
    fs.add_file(P("/d/b"))
    fs.add_dir(P("/d/sub"))
    assert set(fs.list_dir(P("/d"))) == {"a", "b", "sub"}


def test_list_dir_errors():
    fs = posix()
    fs.add_file(P("/d/a"))
    with pytest.raises(FsError):
        fs.list_dir(P("/missing"))
    with pytest.raises(FsError):
        fs.list_dir(P("/d/a"))


def test_symlink_is_reported_not_followed_by_lstat():
    fs = posix()
    fs.add_file(P("/real/a"))
    fs.add_symlink(P("/link"), P("/real"))
    assert fs.lstat(P("/link")).kind is FileKind.SYMLINK


def test_intermediate_symlinks_are_followed():
    fs = posix()
    fs.add_file(P("/real/a"))
    fs.add_symlink(P("/link"), P("/real"))
    assert fs.lstat(P("/link/a")).kind is FileKind.FILE
    assert fs.list_dir(P("/link")) == ("a",)


def test_realpath_resolves_links():
    fs = posix()
    fs.add_file(P("/real/a"))
    fs.add_symlink(P("/link"), P("/real"))
    assert fs.realpath(P("/link/a")) == P("/real/a")


def test_realpath_of_a_missing_path_keeps_the_remainder():
    fs = posix()
    fs.add_dir(P("/d"))
    assert fs.realpath(P("/d/x/y")) == P("/d/x/y")


def test_symlink_loop_is_an_error():
    fs = posix()
    fs.add_symlink(P("/a"), P("/b"))
    fs.add_symlink(P("/b"), P("/a"))
    with pytest.raises(FsError):
        fs.lstat(P("/a/x"))


# ------------------------------------------------------------ reading


def test_handle_reads_whole_and_chunked():
    fs = posix()
    fs.add_file(P("/d/a"), b"abcdef")
    handle = fs.open_read(P("/d/a"))
    assert handle.read(2) == b"ab"
    assert handle.read() == b"cdef"
    assert handle.read() == b""


def test_handle_fstat_matches_lstat():
    fs = posix()
    fs.add_file(P("/d/a"), b"abc")
    assert fs.open_read(P("/d/a")).fstat() == fs.lstat(P("/d/a"))


def test_handle_follows_the_inode_after_a_write():
    fs = posix()
    fs.add_file(P("/d/a"), b"abc")
    handle = fs.open_read(P("/d/a"))
    fs.write(P("/d/a"), b"longer")
    assert handle.fstat().size == 6
    assert handle.read() == b"longer"


def test_handle_survives_removal_of_the_path():
    fs = posix()
    fs.add_file(P("/d/a"), b"abc")
    handle = fs.open_read(P("/d/a"))
    fs.remove(P("/d/a"))
    assert handle.read() == b"abc"


def test_open_read_refuses_links_directories_and_missing_files():
    fs = posix()
    fs.add_file(P("/d/a"))
    fs.add_symlink(P("/d/l"), P("/d/a"))
    for target in (P("/d/l"), P("/d"), P("/d/nope")):
        with pytest.raises(FsError):
            fs.open_read(target)


def test_closed_handle_raises():
    fs = posix()
    fs.add_file(P("/d/a"), b"abc")
    handle = fs.open_read(P("/d/a"))
    handle.close()
    with pytest.raises(FsError):
        handle.read()


# ------------------------------------------------------------ flavors


def test_windows_lookup_is_case_insensitive_and_keeps_the_stored_spelling():
    fs = windows()
    fs.add_file(W(r"C:\Data\A.pdf"))
    assert fs.lstat(W(r"c:\data\a.PDF")) is not None
    assert fs.list_dir(W(r"C:\DATA")) == ("A.pdf",)
    assert str(fs.realpath(W(r"c:\DATA\a.pdf"))) == r"C:\Data\A.pdf"


def test_posix_lookup_is_case_sensitive():
    fs = posix()
    fs.add_file(P("/d/A.pdf"))
    assert fs.lstat(P("/d/a.pdf")) is None


def test_wrong_flavor_or_relative_paths_are_rejected():
    fs = posix()
    with pytest.raises(ValueError):
        fs.lstat(W(r"C:\a"))
    with pytest.raises(ValueError):
        fs.lstat(P("rel"))
    with pytest.raises(ValueError):
        fs.add_file(W(r"C:\a"))


# ------------------------------------------------------------ setup errors


def test_duplicate_and_conflicting_adds_are_rejected():
    fs = posix()
    fs.add_file(P("/d/a"))
    with pytest.raises(ValueError):
        fs.add_file(P("/d/a"))
    with pytest.raises(ValueError):
        fs.add_file(P("/d/a/b"))


def test_remove_missing_path_is_rejected():
    with pytest.raises(ValueError):
        posix().remove(P("/nope"))


def test_write_keeps_mtime_unless_given():
    fs = posix()
    fs.add_file(P("/d/a"), b"x", mtime_ns=5)
    fs.write(P("/d/a"), b"yy")
    assert fs.lstat(P("/d/a")).mtime_ns == 5
    fs.write(P("/d/a"), b"zzz", mtime_ns=9)
    assert fs.lstat(P("/d/a")).mtime_ns == 9
    assert fs.read_bytes(P("/d/a")) == b"zzz"


# ------------------------------------------------------------ call log and injection


def test_port_calls_are_logged_and_setup_is_not():
    fs = posix()
    fs.add_file(P("/d/a"), b"x")
    fs.lstat(P("/d/a"))
    fs.list_dir(P("/d"))
    handle = fs.open_read(P("/d/a"))
    handle.fstat()
    handle.read()
    assert [op for op, _ in fs.calls] == ["lstat", "list_dir", "open_read", "fstat", "read"]


def test_injected_action_runs_once_before_the_call():
    fs = posix()
    fs.add_file(P("/d/a"), b"x")
    fs.inject("lstat", lambda f, p: f.write(P("/d/a"), b"xx"))
    assert fs.lstat(P("/d/a")).size == 2
    fs.write(P("/d/a"), b"xxxx")
    assert fs.lstat(P("/d/a")).size == 4


def test_injected_fault_raises_then_clears():
    fs = posix()
    fs.add_file(P("/d/a"))

    def fail(f, p):
        raise FsError(p, "disk on fire")

    fs.inject("lstat", fail)
    with pytest.raises(FsError):
        fs.lstat(P("/d/a"))
    assert fs.lstat(P("/d/a")) is not None


def test_injection_can_be_limited_to_one_path():
    fs = posix()
    fs.add_file(P("/d/a"))
    fs.add_file(P("/d/b"))

    def fail(f, p):
        raise FsError(p, "boom")

    fs.inject("lstat", fail, path=P("/d/b"))
    assert fs.lstat(P("/d/a")) is not None
    with pytest.raises(FsError):
        fs.lstat(P("/d/b"))


def test_race_between_fstat_and_read():
    fs = posix()
    fs.add_file(P("/d/a"), b"abc")
    handle = fs.open_read(P("/d/a"))
    before = handle.fstat()
    fs.inject("read", lambda f, p: f.write(P("/d/a"), b"a much longer body"))
    handle.read()
    assert handle.fstat().size != before.size
