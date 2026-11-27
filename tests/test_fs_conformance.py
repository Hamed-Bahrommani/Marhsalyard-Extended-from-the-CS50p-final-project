from pathlib import PurePosixPath as P
from pathlib import PureWindowsPath as W

import pytest

from marshalyard.filesystem import FileKind, FsError

MT = 1_700_000_000 * 10**9  # a whole number of seconds: exact on every filesystem


# ------------------------------------------------------------ stat


def test_missing_path_is_none(env):
    assert env.fs.lstat(env.p("nope")) is None


def test_file_stat_fields(env):
    path = env.p("d", "a.pdf")
    env.add_file(path, b"hello", mtime_ns=MT)
    info = env.fs.lstat(path)
    assert info.kind is FileKind.FILE
    assert (info.size, info.mtime_ns, info.nlink) == (5, MT, 1)
    assert info.dev > 0 and info.ino > 0
    assert not info.hidden_or_system and not info.reparse_point


def test_directory_stat(env):
    env.add_dir(env.p("d"))
    info = env.fs.lstat(env.p("d"))
    assert info.kind is FileKind.DIRECTORY and info.size == 0


def test_path_below_a_file_is_absent(env):
    env.add_file(env.p("f"), b"x")
    assert env.fs.lstat(env.p("f", "x")) is None


def test_hidden_attribute_is_reported(env):
    env.add_file(env.p("h"), b"x", hidden=True)
    assert env.fs.lstat(env.p("h")).hidden_or_system is True


# ------------------------------------------------------------ directories


def test_list_dir_returns_names(env):
    env.add_file(env.p("d", "a"), b"")
    env.add_file(env.p("d", "b"), b"")
    env.add_dir(env.p("d", "sub"))
    assert set(env.fs.list_dir(env.p("d"))) == {"a", "b", "sub"}


def test_list_dir_errors(env):
    env.add_file(env.p("d", "a"), b"")
    with pytest.raises(FsError):
        env.fs.list_dir(env.p("missing"))
    with pytest.raises(FsError):
        env.fs.list_dir(env.p("d", "a"))


# ------------------------------------------------------------ links


def test_symlink_is_reported_not_followed(env):
    env.add_file(env.p("real", "a"), b"x")
    env.add_symlink(env.p("link"), env.p("real"))
    assert env.fs.lstat(env.p("link")).kind is FileKind.SYMLINK


def test_intermediate_symlinks_are_followed(env):
    env.add_file(env.p("real", "a"), b"x")
    env.add_symlink(env.p("link"), env.p("real"))
    assert env.fs.lstat(env.p("link", "a")).kind is FileKind.FILE


def test_list_dir_follows_a_directory_symlink(env):
    env.add_file(env.p("real", "a"), b"x")
    env.add_symlink(env.p("link"), env.p("real"))
    assert env.fs.list_dir(env.p("link")) == ("a",)


def test_hard_links_share_identity_and_count(env):
    first, second = env.p("d", "a"), env.p("d", "b")
    env.add_file(first, b"x")
    env.add_hardlink(first, second)
    one, two = env.fs.lstat(first), env.fs.lstat(second)
    assert one.ino == two.ino and one.nlink == two.nlink == 2
    env.remove(second)
    assert env.fs.lstat(first).nlink == 1


def test_identity_survives_an_in_place_write(env):
    path = env.p("d", "a")
    env.add_file(path, b"x")
    before = env.fs.lstat(path)
    env.write(path, b"longer content")
    after = env.fs.lstat(path)
    assert (after.dev, after.ino) == (before.dev, before.ino) and after.size == 14


# ------------------------------------------------------------ reading


def test_handle_reads_whole_and_chunked(env):
    path = env.p("d", "a")
    env.add_file(path, b"abcdef")
    handle = env.fs.open_read(path)
    try:
        assert handle.read(2) == b"ab"
        assert handle.read() == b"cdef"
        assert handle.read() == b""
    finally:
        handle.close()


def test_empty_file_reads_as_empty(env):
    path = env.p("d", "empty")
    env.add_file(path, b"")
    handle = env.fs.open_read(path)
    try:
        assert handle.read() == b""
        assert handle.fstat().size == 0
    finally:
        handle.close()


def test_handle_fstat_matches_lstat(env):
    path = env.p("d", "a")
    env.add_file(path, b"abc", mtime_ns=MT)
    handle = env.fs.open_read(path)
    try:
        assert handle.fstat() == env.fs.lstat(path)
    finally:
        handle.close()


def test_handle_sees_an_in_place_write(env):
    path = env.p("d", "a")
    env.add_file(path, b"abc")
    handle = env.fs.open_read(path)
    try:
        env.write(path, b"longer")
        assert handle.fstat().size == 6
        assert handle.read() == b"longer"
    finally:
        handle.close()


def test_open_read_refuses_directories_and_missing_files(env):
    env.add_dir(env.p("d"))
    for target in (env.p("d"), env.p("nope")):
        with pytest.raises(FsError):
            env.fs.open_read(target)


def test_open_read_refuses_a_symlink(env):
    env.add_file(env.p("a"), b"x")
    env.add_symlink(env.p("l"), env.p("a"))
    with pytest.raises(FsError):
        env.fs.open_read(env.p("l"))


def test_closed_handle_raises(env):
    path = env.p("d", "a")
    env.add_file(path, b"abc")
    handle = env.fs.open_read(path)
    handle.close()
    with pytest.raises(FsError):
        handle.read()


# ------------------------------------------------------------ realpath


def test_realpath_of_a_plain_path_is_itself(env):
    env.add_file(env.p("d", "a"), b"x")
    assert env.fs.realpath(env.p("d", "a")) == env.p("d", "a")


def test_realpath_of_a_missing_path_keeps_the_remainder(env):
    env.add_dir(env.p("d"))
    assert env.fs.realpath(env.p("d", "x", "y")) == env.p("d", "x", "y")


def test_realpath_resolves_links(env):
    env.add_file(env.p("real", "a"), b"x")
    env.add_symlink(env.p("link"), env.p("real"))
    assert env.fs.realpath(env.p("link", "a")) == env.p("real", "a")


# ------------------------------------------------------------ argument checks


def test_wrong_flavor_and_relative_paths_are_rejected(env):
    foreign = W("C:\\a") if isinstance(env.root, P) else P("/a")
    with pytest.raises(ValueError):
        env.fs.lstat(foreign)
    with pytest.raises(ValueError):
        env.fs.lstat(type(env.root)("relative"))
