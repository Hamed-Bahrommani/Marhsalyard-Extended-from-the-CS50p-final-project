from pathlib import PurePosixPath as P
from pathlib import PureWindowsPath as W

import pytest

from marshalyard.config import BUILTIN_EXCLUDES
from marshalyard.filesystem import FsError
from marshalyard.memoryfs import MemoryFileSystem
from marshalyard.models import Flavor, SkipReason
from marshalyard.scanner import runtime_files, scan

SRC = P("/d/in")


def run(fs, sources=(SRC,), exclude=BUILTIN_EXCLUDES, runtime=(), taken=1):
    return scan(fs, sources, exclude=exclude, runtime=runtime, taken_at_ns=taken)


def names(items):
    return [p.path.name for p in items]


def reasons(result):
    return {s.path.name: s.reason for s in result.snapshot.skipped}


# ------------------------------------------------------------ entries


def test_regular_file_becomes_an_entry_with_fresh_stat_values():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "a.pdf", b"hello", mtime_ns=123)
    info = fs.lstat(SRC / "a.pdf")
    entry = run(fs).snapshot.entries[0]
    assert (entry.path, entry.size, entry.mtime_ns, entry.dev, entry.ino, entry.nlink) == (
        SRC / "a.pdf", 5, 123, info.dev, info.ino, info.nlink
    )


def test_entries_and_skips_are_sorted_whatever_the_listing_order():
    fs = MemoryFileSystem()
    for name in ("c.pdf", "a.pdf", "b.pdf"):
        fs.add_file(SRC / name)
    for name in ("z.tmp", "m.tmp"):
        fs.add_file(SRC / name)
    result = run(fs).snapshot
    assert names(result.entries) == ["a.pdf", "b.pdf", "c.pdf"]
    assert names(result.skipped) == ["m.tmp", "z.tmp"]


def test_empty_source_is_scanned_and_recorded():
    fs = MemoryFileSystem()
    fs.add_dir(SRC)
    snapshot = run(fs).snapshot
    assert snapshot.sources == (SRC,) and snapshot.entries == ()


def test_taken_at_is_preserved():
    fs = MemoryFileSystem()
    fs.add_dir(SRC)
    assert run(fs, taken=42).snapshot.taken_at_ns == 42


def test_unavailable_identity_is_still_an_entry():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "a.pdf", hide_identity=True)
    entry = run(fs).snapshot.entries[0]
    assert (entry.dev, entry.ino, entry.nlink) == (0, 0, 0)


def test_hard_linked_file_is_still_an_entry():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "a.pdf")
    fs.add_hardlink(SRC / "a.pdf", SRC / "b.pdf")
    assert [e.nlink for e in run(fs).snapshot.entries] == [2, 2]


def test_scan_is_deterministic():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "a.pdf")
    fs.add_file(SRC / "b.tmp")
    assert run(fs) == run(fs)


# ------------------------------------------------------------ skips by type


def test_symlink_is_skipped():
    fs = MemoryFileSystem()
    fs.add_file(P("/elsewhere/real.pdf"))
    fs.add_symlink(SRC / "link.pdf", P("/elsewhere/real.pdf"))
    assert reasons(run(fs)) == {"link.pdf": SkipReason.SYMLINK}


def test_reparse_point_is_skipped():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "cloud.pdf", reparse_point=True)
    assert reasons(run(fs)) == {"cloud.pdf": SkipReason.REPARSE_POINT}


def test_hidden_or_system_file_is_skipped():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "secret.pdf", hidden=True)
    assert reasons(run(fs)) == {"secret.pdf": SkipReason.HIDDEN_OR_SYSTEM}


def test_directories_and_special_files_are_not_regular():
    fs = MemoryFileSystem()
    fs.add_dir(SRC / "folder")
    fs.add_special(SRC / "pipe")
    assert reasons(run(fs)) == {"folder": SkipReason.NOT_REGULAR, "pipe": SkipReason.NOT_REGULAR}


def test_scan_is_not_recursive():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "sub" / "deep.pdf")
    result = run(fs)
    assert result.snapshot.entries == ()
    assert ("list_dir", SRC / "sub") not in fs.calls


# ------------------------------------------------------------ skips by name


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("x.part", id="part"),
        pytest.param("x.crdownload", id="crdownload"),
        pytest.param("x.tmp", id="tmp"),
        pytest.param("desktop.ini", id="desktop-ini"),
        pytest.param(".hidden", id="dotfile"),
        pytest.param("X.PART", id="part-upper"),
        pytest.param("Desktop.INI", id="desktop-ini-upper"),
    ],
)
def test_builtin_exclusions(name):
    fs = MemoryFileSystem()
    fs.add_file(SRC / name)
    assert reasons(run(fs)) == {name: SkipReason.EXCLUDED}


def test_user_exclusions_are_applied():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "thumbs.db")
    fs.add_file(SRC / "big.iso.part")
    fs.add_file(SRC / "keep.pdf")
    result = run(fs, exclude=BUILTIN_EXCLUDES + ("thumbs.db", "*.iso.part"))
    assert names(result.snapshot.entries) == ["keep.pdf"]
    assert set(reasons(result).values()) == {SkipReason.EXCLUDED}


def test_excluded_files_are_never_statted():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "a.tmp")
    fs.add_file(SRC / "b.pdf")
    run(fs)
    assert [p for op, p in fs.calls if op == "lstat"] == [SRC / "b.pdf"]


def test_runtime_files_lists_config_and_database_companions():
    files = runtime_files(P("/d/in/marshal.toml"), P("/d/in/m.db"))
    assert files == frozenset(
        {
            P("/d/in/marshal.toml"),
            P("/d/in/m.db"),
            P("/d/in/m.db-wal"),
            P("/d/in/m.db-shm"),
            P("/d/in/m.db-journal"),
            P("/d/in/m.db.lock"),
        }
    )


def test_runtime_files_are_never_candidates():
    fs = MemoryFileSystem()
    runtime = runtime_files(SRC / "marshal.toml", SRC / "m.db")
    for path in runtime:
        fs.add_file(path)
    fs.add_file(SRC / "a.pdf")
    result = run(fs, runtime=runtime)
    assert names(result.snapshot.entries) == ["a.pdf"]
    assert set(reasons(result).values()) == {SkipReason.RUNTIME_FILE}
    assert len(result.snapshot.skipped) == 6


def test_runtime_check_wins_over_exclusion():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "state.tmp")
    result = run(fs, runtime=[SRC / "state.tmp"])
    assert reasons(result) == {"state.tmp": SkipReason.RUNTIME_FILE}


# ------------------------------------------------------------ failures and races


def test_unreadable_entry_is_reported_and_the_rest_still_scan():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "bad.pdf")
    fs.add_file(SRC / "good.pdf")

    def fail(f, p):
        raise FsError(p, "permission denied")

    fs.inject("lstat", fail, path=SRC / "bad.pdf")
    result = run(fs).snapshot
    assert names(result.entries) == ["good.pdf"]
    assert reasons(run(MemoryFileSystem())) == {}
    assert [(s.path.name, s.reason) for s in result.skipped] == [("bad.pdf", SkipReason.UNREADABLE)]


def test_file_that_vanishes_between_listing_and_stat_is_ignored():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "gone.pdf")
    fs.add_file(SRC / "stays.pdf")
    fs.inject("lstat", lambda f, p: f.remove(p), path=SRC / "gone.pdf")
    result = run(fs).snapshot
    assert names(result.entries) == ["stays.pdf"] and result.skipped == ()


# ------------------------------------------------------------ sources


def test_missing_source_is_an_error_and_other_sources_still_scan():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "a.pdf")
    result = run(fs, sources=(P("/d/missing"), SRC))
    assert result.snapshot.sources == (SRC,)
    assert [(e.source, bool(e.reason)) for e in result.source_errors] == [(P("/d/missing"), True)]
    assert names(result.snapshot.entries) == ["a.pdf"]


def test_a_file_given_as_a_source_is_an_error():
    fs = MemoryFileSystem()
    fs.add_file(P("/d/file"))
    result = run(fs, sources=(P("/d/file"),))
    assert result.snapshot.sources == () and len(result.source_errors) == 1


def test_duplicate_sources_are_scanned_once():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "a.pdf")
    result = run(fs, sources=(SRC, SRC))
    assert result.snapshot.sources == (SRC,)
    assert [c for c in fs.calls if c[0] == "list_dir"] == [("list_dir", SRC)]


def test_sources_are_sorted_in_the_snapshot():
    fs = MemoryFileSystem()
    fs.add_dir(P("/d/b"))
    fs.add_dir(P("/d/a"))
    assert run(fs, sources=(P("/d/b"), P("/d/a"))).snapshot.sources == (P("/d/a"), P("/d/b"))


# ------------------------------------------------------------ Windows flavour


def test_windows_exclusions_and_runtime_files_ignore_case():
    fs = MemoryFileSystem(Flavor.WINDOWS)
    source = W(r"C:\In")
    fs.add_file(source / "THUMBS.DB")
    fs.add_file(source / "m.db")
    fs.add_file(source / "a.pdf")
    result = scan(
        fs,
        [source],
        exclude=BUILTIN_EXCLUDES + ("thumbs.db",),
        runtime=[W(r"C:\IN\M.DB")],
        taken_at_ns=1,
    )
    assert names(result.snapshot.entries) == ["a.pdf"]
    assert reasons(result) == {"THUMBS.DB": SkipReason.EXCLUDED, "m.db": SkipReason.RUNTIME_FILE}

