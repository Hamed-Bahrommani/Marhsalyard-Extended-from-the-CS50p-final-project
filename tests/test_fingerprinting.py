import hashlib
from pathlib import PurePosixPath as P

import pytest

from marshalyard.filesystem import FsError
from marshalyard.fingerprinting import CHUNK_SIZE, FingerprintFailure, fingerprint, to_unplanned
from marshalyard.memoryfs import MemoryFileSystem
from marshalyard.models import FileEntry, Fingerprint, FpMethod, UnplannedReason

PATH = P("/d/in/a.pdf")
MTIME = 5_000


def make(content=b"abc"):
    fs = MemoryFileSystem()
    fs.add_file(PATH, content, mtime_ns=MTIME)
    return fs


def entry_of(fs, path=PATH):
    info = fs.lstat(path)
    fs.calls.clear()
    return FileEntry(path, info.size, info.mtime_ns, info.dev, info.ino, info.nlink)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def failure(result, reason):
    assert isinstance(result, FingerprintFailure), result
    assert result.reason is reason
    return result


def boom(f, p):
    raise FsError(p, "boom")


# ------------------------------------------------------------ success


def test_small_file_gets_a_content_fingerprint():
    fs = make(b"hello")
    entry = entry_of(fs)
    result = fingerprint(fs, entry)
    assert isinstance(result, Fingerprint)
    assert result.method is FpMethod.CONTENT and result.sha256 == sha(b"hello")
    assert (result.dev, result.ino, result.nlink, result.size, result.mtime_ns) == (
        entry.dev, entry.ino, 1, 5, MTIME
    )


def test_empty_file():
    fs = make(b"")
    result = fingerprint(fs, entry_of(fs))
    assert result.sha256 == sha(b"") and result.size == 0


def test_content_larger_than_one_chunk_is_hashed_completely():
    data = b"x" * (2 * CHUNK_SIZE + 17)
    fs = make(data)
    assert fingerprint(fs, entry_of(fs)).sha256 == sha(data)


def test_protocol_order_is_stat_open_fstat_read_fstat_stat():
    fs = make(b"abc")
    fingerprint(fs, entry_of(fs))
    assert [op for op, _ in fs.calls] == ["lstat", "open_read", "fstat", "read", "read", "fstat", "lstat"]


def test_fingerprint_is_deterministic():
    fs = make(b"abc")
    entry = entry_of(fs)
    assert fingerprint(fs, entry) == fingerprint(fs, entry)


# ------------------------------------------------------------ threshold


def test_file_at_the_threshold_is_hashed():
    fs = make(b"x" * 10)
    result = fingerprint(fs, entry_of(fs), threshold=10)
    assert result.method is FpMethod.CONTENT


def test_file_above_the_threshold_gets_a_metadata_fingerprint_and_is_never_opened():
    fs = make(b"x" * 11)
    result = fingerprint(fs, entry_of(fs), threshold=10)
    assert result.method is FpMethod.METADATA and result.sha256 is None
    assert [op for op, _ in fs.calls] == ["lstat"]


def test_large_file_changed_since_the_scan_is_refused():
    fs = make(b"x" * 11)
    entry = entry_of(fs)
    fs.touch(PATH, MTIME + 1)
    result = failure(fingerprint(fs, entry, threshold=10), UnplannedReason.CHANGED_DURING_PLANNING)
    assert result.detail == "metadata changed after scan: mtime_ns"


# ------------------------------------------------------------ changes since the scan


def test_file_modified_after_the_scan():
    fs = make(b"abc")
    entry = entry_of(fs)
    fs.write(PATH, b"abcdef", mtime_ns=MTIME + 1)
    result = failure(fingerprint(fs, entry), UnplannedReason.CHANGED_DURING_PLANNING)
    assert result.detail == "metadata changed after scan: size, mtime_ns"


def test_file_that_disappeared_after_the_scan():
    fs = make()
    entry = entry_of(fs)
    fs.remove(PATH)
    failure(fingerprint(fs, entry), UnplannedReason.CHANGED_DURING_PLANNING)


def test_file_replaced_by_a_directory_after_the_scan():
    fs = make()
    entry = entry_of(fs)
    fs.remove(PATH)
    fs.add_dir(PATH)
    failure(fingerprint(fs, entry), UnplannedReason.CHANGED_DURING_PLANNING)


def test_hard_link_appearing_after_the_scan_is_a_change():
    fs = make()
    entry = entry_of(fs)
    fs.add_hardlink(PATH, P("/d/in/b.pdf"))
    result = failure(fingerprint(fs, entry), UnplannedReason.CHANGED_DURING_PLANNING)
    assert "nlink" in result.detail


def test_entry_that_was_already_multiply_linked_is_refused_by_the_ladder():
    fs = make()
    fs.add_hardlink(PATH, P("/d/in/b.pdf"))
    entry = entry_of(fs)
    result = failure(fingerprint(fs, entry), UnplannedReason.MULTIPLE_LINKS)
    assert result.detail == "nlink=2"


# ------------------------------------------------------------ I/O failures


def test_open_failure_is_unreadable():
    fs = make()
    entry = entry_of(fs)
    fs.inject("open_read", boom)
    assert failure(fingerprint(fs, entry), UnplannedReason.UNREADABLE).detail == "cannot be opened"


def test_read_failure_is_unreadable():
    fs = make()
    entry = entry_of(fs)
    fs.inject("read", boom)
    assert failure(fingerprint(fs, entry), UnplannedReason.UNREADABLE).detail == "cannot be read"


def test_stat_failure_is_unreadable():
    fs = make()
    entry = entry_of(fs)
    fs.inject("lstat", boom)
    failure(fingerprint(fs, entry), UnplannedReason.UNREADABLE)


# ------------------------------------------------------------ races (P8)


def test_content_growing_during_the_read_is_detected():
    fs = make(b"abc")
    entry = entry_of(fs)
    fs.inject("read", lambda f, p: f.write(PATH, b"a much longer body"))
    result = failure(fingerprint(fs, entry), UnplannedReason.CHANGED_DURING_PLANNING)
    assert result.detail.startswith("metadata changed while reading")


def test_mtime_changing_during_the_read_is_detected():
    fs = make(b"abc")
    entry = entry_of(fs)
    fs.inject("read", lambda f, p: f.touch(PATH, MTIME + 99))
    failure(fingerprint(fs, entry), UnplannedReason.CHANGED_DURING_PLANNING)


def test_hard_link_appearing_during_the_read_is_detected():
    fs = make(b"abc")
    entry = entry_of(fs)
    fs.inject("read", lambda f, p: f.add_hardlink(PATH, P("/d/in/b.pdf")))
    failure(fingerprint(fs, entry), UnplannedReason.CHANGED_DURING_PLANNING)


def test_file_replaced_between_stat_and_open_is_detected():
    fs = make(b"abc")
    entry = entry_of(fs)

    def swap(f, p):
        f.remove(PATH)
        f.add_file(PATH, b"other", mtime_ns=MTIME)

    fs.inject("open_read", swap)
    result = failure(fingerprint(fs, entry), UnplannedReason.CHANGED_DURING_PLANNING)
    assert result.detail == "file was replaced before it was read"


def test_change_after_the_read_is_caught_by_the_final_stat():
    fs = make(b"abc")
    entry = entry_of(fs)
    seen = {"n": 0}

    def late(f, p):
        seen["n"] += 1
        if seen["n"] == 2:  # the second lstat is s3
            f.touch(PATH, MTIME + 7)

    fs.inject("lstat", late, times=2)
    result = failure(fingerprint(fs, entry), UnplannedReason.CHANGED_DURING_PLANNING)
    assert "mtime_ns" in result.detail


def test_file_removed_after_the_read_is_detected():
    fs = make(b"abc")
    entry = entry_of(fs)
    seen = {"n": 0}

    def late(f, p):
        seen["n"] += 1
        if seen["n"] == 2:
            f.remove(PATH)

    fs.inject("lstat", late, times=2)
    failure(fingerprint(fs, entry), UnplannedReason.CHANGED_DURING_PLANNING)


def test_same_size_same_mtime_rewrite_is_a_documented_undetectable_limitation():
    fs = make(b"abc")
    entry = entry_of(fs)
    fs.inject("read", lambda f, p: f.write(PATH, b"ZZZ"))
    result = fingerprint(fs, entry)
    assert isinstance(result, Fingerprint)
    assert result.sha256 == sha(b"ZZZ")  # consistent metadata, so accepted: spec 7.2 limitation


def test_race_details_are_deterministic():
    def run():
        fs = make(b"abc")
        entry = entry_of(fs)
        fs.inject("read", lambda f, p: f.write(PATH, b"a much longer body"))
        return fingerprint(fs, entry)

    assert run() == run()


# ------------------------------------------------------------ conversion


def test_failure_converts_to_an_unplanned_entry():
    fs = make()
    entry = entry_of(fs)
    item = to_unplanned(entry, FingerprintFailure(UnplannedReason.UNREADABLE, "cannot be read"))
    assert (item.src, item.reason, item.detail) == (PATH, UnplannedReason.UNREADABLE, "cannot be read")
