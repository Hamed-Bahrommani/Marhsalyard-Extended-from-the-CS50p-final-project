from pathlib import PurePosixPath as P

import pytest

from marshalyard.filesystem import FileKind, FsError, StatInfo


def stat(**overrides):
    values = dict(kind=FileKind.FILE, dev=1, ino=2, nlink=1, size=3, mtime_ns=4)
    values.update(overrides)
    return StatInfo(**values)


def test_valid_stat_info():
    info = stat()
    assert info.kind is FileKind.FILE
    assert info.hidden_or_system is False and info.reparse_point is False


def test_unavailable_identity_is_representable():
    assert stat(dev=0, ino=0, nlink=0).ino == 0


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"kind": "file"}, id="kind-not-enum"),
        pytest.param({"size": -1}, id="negative-size"),
        pytest.param({"nlink": True}, id="bool-nlink"),
        pytest.param({"mtime_ns": 1.5}, id="float-mtime"),
        pytest.param({"hidden_or_system": 1}, id="flag-not-bool"),
        pytest.param({"reparse_point": None}, id="reparse-not-bool"),
    ],
)
def test_invalid_stat_info(overrides):
    with pytest.raises(ValueError):
        stat(**overrides)


def test_fs_error_carries_path_and_reason():
    error = FsError(P("/d/x"), "permission denied")
    assert error.path == P("/d/x") and error.reason == "permission denied"
    assert "permission denied" in str(error)
