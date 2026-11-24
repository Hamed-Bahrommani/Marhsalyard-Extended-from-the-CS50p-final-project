from pathlib import PurePosixPath as P
from pathlib import PureWindowsPath as W

import pytest

from marshalyard.models import FileEntry, SkippedEntry, Snapshot, SkipReason

SRC = P("/d/in")


def entry(name="a.pdf", parent=SRC, **kw):
    values = dict(size=1, mtime_ns=2, dev=3, ino=4, nlink=1)
    values.update(kw)
    return FileEntry(parent / name, **values)


def skipped(name="x.tmp", parent=SRC, reason=SkipReason.EXCLUDED):
    return SkippedEntry(parent / name, reason)


def snap(entries=(), skips=(), sources=(SRC,), taken=1):
    return Snapshot(taken, tuple(sources), tuple(entries), tuple(skips))


# ------------------------------------------------------------ FileEntry / SkippedEntry


def test_unavailable_identity_is_representable():
    assert entry(dev=0, ino=0, nlink=0).ino == 0


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: FileEntry(P("rel/a"), 1, 2, 3, 4, 1), id="relative"),
        pytest.param(lambda: entry(size=-1), id="negative-size"),
        pytest.param(lambda: entry(size=True), id="bool-size"),
        pytest.param(lambda: entry(dev=-1), id="negative-dev"),
        pytest.param(lambda: entry(nlink=-1), id="negative-nlink"),
        pytest.param(lambda: entry(mtime_ns=1.5), id="float-mtime"),
        pytest.param(lambda: SkippedEntry(P("rel/a"), SkipReason.EXCLUDED), id="skipped-relative"),
        pytest.param(lambda: SkippedEntry(P("/d/a"), "EXCLUDED"), id="skipped-bad-reason"),
    ],
)
def test_invalid_entries(build):
    with pytest.raises(ValueError):
        build()


# ------------------------------------------------------------ Snapshot


def test_valid_snapshot():
    snapshot = snap([entry("a.pdf"), entry("b.pdf")], [skipped("c.tmp")])
    assert len(snapshot.entries) == 2


def test_empty_snapshot_is_valid():
    assert snap(sources=()).entries == ()


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: snap([entry("b.pdf"), entry("a.pdf")]), id="entries-unsorted"),
        pytest.param(lambda: snap([entry("a.pdf"), entry("a.pdf")]), id="entries-duplicate"),
        pytest.param(lambda: snap(skips=[skipped("b.tmp"), skipped("a.tmp")]), id="skipped-unsorted"),
        pytest.param(lambda: snap(skips=[skipped("a.tmp"), skipped("a.tmp")]), id="skipped-duplicate"),
        pytest.param(lambda: snap([entry("a.pdf")], [skipped("a.pdf")]), id="overlap"),
        pytest.param(lambda: snap([entry("a.pdf", parent=P("/d/other"))]), id="entry-parent-not-source"),
        pytest.param(lambda: snap(skips=[skipped("a", parent=P("/d/other"))]), id="skipped-parent-not-source"),
        pytest.param(lambda: snap(sources=[SRC, SRC]), id="duplicate-sources"),
        pytest.param(lambda: snap(sources=[P("d/in")]), id="relative-source"),
        pytest.param(lambda: snap(sources=[SRC, W("C:\\d\\in")]), id="mixed-flavors"),
        pytest.param(lambda: snap(taken=-1), id="negative-time"),
    ],
)
def test_invalid_snapshots(build):
    with pytest.raises(ValueError):
        build()
