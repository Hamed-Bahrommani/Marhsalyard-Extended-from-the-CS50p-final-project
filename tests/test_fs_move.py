import os

import pytest

from marshalyard.filesystem import DestinationExists, FsError, SourceMissing

MT = 1_700_000_000 * 10**9


def read(env, path):
    handle = env.fs.open_read(path)
    try:
        return handle.read()
    finally:
        handle.close()


def insensitive(env):
    return env.kind == "real" and os.name == "nt"


def test_move_keeps_identity_content_and_mtime(env):
    src, dst = env.p("in", "a.pdf"), env.p("out", "a.pdf")
    env.add_file(src, b"hello", mtime_ns=MT)
    env.add_dir(env.p("out"))
    before = env.fs.lstat(src)
    env.fs.move_no_clobber(src, dst)
    assert env.fs.lstat(src) is None
    after = env.fs.lstat(dst)
    assert (after.dev, after.ino, after.size, after.mtime_ns, after.nlink) == (
        before.dev, before.ino, 5, MT, 1,
    )
    assert read(env, dst) == b"hello"


def test_move_within_one_directory(env):
    env.add_file(env.p("d", "a"), b"x")
    env.fs.move_no_clobber(env.p("d", "a"), env.p("d", "b"))
    assert env.fs.lstat(env.p("d", "a")) is None
    assert read(env, env.p("d", "b")) == b"x"


def test_missing_destination_directory_is_refused_and_not_created(env):
    src = env.p("in", "a")
    env.add_file(src, b"x")
    with pytest.raises(FsError) as caught:
        env.fs.move_no_clobber(src, env.p("out", "a"))
    assert type(caught.value) is FsError
    assert env.fs.lstat(src) is not None
    assert env.fs.lstat(env.p("out")) is None


def test_an_existing_destination_is_never_replaced(env):
    src, dst = env.p("in", "a"), env.p("out", "a")
    env.add_file(src, b"new")
    env.add_file(dst, b"old")
    with pytest.raises(DestinationExists):
        env.fs.move_no_clobber(src, dst)
    assert read(env, src) == b"new"
    assert read(env, dst) == b"old"


def test_missing_source(env):
    env.add_dir(env.p("out"))
    with pytest.raises(SourceMissing):
        env.fs.move_no_clobber(env.p("in", "nope"), env.p("out", "nope"))
    assert env.fs.lstat(env.p("out", "nope")) is None


def test_an_existing_directory_at_the_destination_is_refused(env):
    src = env.p("in", "a")
    env.add_file(src, b"x")
    env.add_file(env.p("out", "a", "inner"), b"y")
    with pytest.raises(DestinationExists):
        env.fs.move_no_clobber(src, env.p("out", "a"))
    assert read(env, env.p("out", "a", "inner")) == b"y"
    assert env.fs.lstat(src) is not None


def test_a_directory_source_is_refused(env):
    env.add_file(env.p("in", "sub", "x"), b"y")
    env.add_dir(env.p("out"))
    with pytest.raises(FsError):
        env.fs.move_no_clobber(env.p("in", "sub"), env.p("out", "sub"))
    assert env.fs.lstat(env.p("in", "sub", "x")) is not None
    assert env.fs.lstat(env.p("out", "sub")) is None


def test_a_symlink_source_is_refused(env):
    env.add_file(env.p("in", "real"), b"x")
    env.add_symlink(env.p("in", "link"), env.p("in", "real"))
    env.add_dir(env.p("out"))
    with pytest.raises(FsError):
        env.fs.move_no_clobber(env.p("in", "link"), env.p("out", "link"))
    assert env.fs.lstat(env.p("in", "link")) is not None
    assert env.fs.lstat(env.p("out", "link")) is None


def test_a_dangling_symlink_at_the_destination_counts_as_occupied(env):
    src = env.p("in", "a")
    env.add_file(src, b"x")
    env.add_symlink(env.p("out", "a"), env.p("nowhere"))
    with pytest.raises(DestinationExists):
        env.fs.move_no_clobber(src, env.p("out", "a"))
    assert env.fs.lstat(src) is not None


def test_moving_a_file_onto_itself_is_refused(env):
    path = env.p("d", "a")
    env.add_file(path, b"x")
    with pytest.raises(DestinationExists):
        env.fs.move_no_clobber(path, path)
    assert read(env, path) == b"x"


def test_moving_one_name_of_a_hard_link_leaves_the_other(env):
    first, second = env.p("d", "a"), env.p("d", "b")
    env.add_file(first, b"x")
    env.add_hardlink(first, second)
    env.add_dir(env.p("out"))
    env.fs.move_no_clobber(first, env.p("out", "a"))
    assert env.fs.lstat(first) is None
    assert env.fs.lstat(second).nlink == 2
    assert env.fs.lstat(env.p("out", "a")).ino == env.fs.lstat(second).ino


def test_a_case_variant_of_an_existing_destination(env):
    src, existing, variant = env.p("in", "x"), env.p("out", "a.pdf"), env.p("out", "A.PDF")
    env.add_file(src, b"new")
    env.add_file(existing, b"old")
    if insensitive(env):
        with pytest.raises(DestinationExists):
            env.fs.move_no_clobber(src, variant)
        assert read(env, existing) == b"old"
        assert env.fs.lstat(src) is not None
    else:
        env.fs.move_no_clobber(src, variant)
        assert read(env, variant) == b"new"
        assert read(env, existing) == b"old"


def test_a_case_only_rename_of_the_same_file(env):
    old, new = env.p("d", "a.pdf"), env.p("d", "A.PDF")
    env.add_file(old, b"x")
    if insensitive(env):
        with pytest.raises(DestinationExists):
            env.fs.move_no_clobber(old, new)
        assert read(env, old) == b"x"
    else:
        env.fs.move_no_clobber(old, new)
        assert env.fs.lstat(old) is None
        assert read(env, new) == b"x"
