from pathlib import PurePosixPath, PureWindowsPath

import pytest

from marshalyard.canonical import containing_root, portable_key

P = PurePosixPath
W = PureWindowsPath


# ------------------------------------------------------------ portable_key


@pytest.mark.parametrize(
    "a, b",
    [
        pytest.param(P("/d/caf\u00e9.pdf"), P("/d/cafe\u0301.pdf"), id="composed-vs-decomposed"),
        pytest.param(P("/d/Stra\u00dfe.pdf"), P("/d/STRASSE.pdf"), id="sharp-s"),
        pytest.param(P("/d/A.PDF"), P("/d/a.pdf"), id="case"),
    ],
)
def test_colliding_names_have_equal_keys(a, b):
    assert portable_key(a) == portable_key(b)


def test_different_names_have_different_keys():
    assert portable_key(P("/d/a.pdf")) != portable_key(P("/d/b.pdf"))


def test_separators_matter():
    assert portable_key(P("/a/bc")) != portable_key(P("/ab/c"))


def test_posix_key_shape():
    assert portable_key(P("/Data/A.pdf")) == "/data/a.pdf"


def test_windows_key_shape():
    assert portable_key(W("C:\\Users\\X\\A.pdf")) == "c:/users/x/a.pdf"


def test_anchor_only_paths():
    assert portable_key(P("/")) == "/"
    assert portable_key(W("C:\\")) == "c:/"


def test_relative_path_is_rejected():
    with pytest.raises(ValueError):
        portable_key(P("a/b"))


# ------------------------------------------------------------ containing_root


def test_nested_roots_pick_the_most_specific():
    docs = P("/home/u/Documents")
    sorted_ = P("/home/u/Documents/Sorted")
    assert containing_root(P("/home/u/Documents/Sorted/A/x.pdf"), [docs, sorted_]) == sorted_


def test_outer_root_is_used_outside_the_nested_root():
    docs = P("/home/u/Documents")
    sorted_ = P("/home/u/Documents/Sorted")
    assert containing_root(P("/home/u/Documents/other.pdf"), [docs, sorted_]) == docs


def test_path_equal_to_a_root_is_contained():
    root = P("/data/downloads")
    assert containing_root(root, [root]) == root


def test_path_in_no_root_returns_none():
    assert containing_root(P("/elsewhere/x.pdf"), [P("/data/downloads")]) is None


def test_sibling_prefix_is_not_contained():
    assert containing_root(P("/data/downloads-evil/x.pdf"), [P("/data/downloads")]) is None


def test_windows_containment_is_case_insensitive():
    root = W("C:\\Users\\X\\Downloads")
    assert containing_root(W("c:\\users\\x\\downloads\\a.pdf"), [root]) == root


def test_posix_containment_is_case_sensitive():
    assert containing_root(P("/data/Downloads/a.pdf"), [P("/data/downloads")]) is None


def test_mixed_flavors_are_rejected():
    with pytest.raises(ValueError):
        containing_root(P("/a/b"), [W("C:\\a")])


def test_root_order_does_not_matter():
    docs = P("/home/u/Documents")
    sorted_ = P("/home/u/Documents/Sorted")
    path = P("/home/u/Documents/Sorted/x.pdf")
    assert containing_root(path, [docs, sorted_]) == containing_root(path, [sorted_, docs])
    