from pathlib import PurePosixPath as P
from pathlib import PureWindowsPath as W

import pytest

from marshalyard.config import (
    FieldError,
    SplitPath,
    check_glob,
    check_portable_component,
    check_rule_name,
    dedupe,
    file_extension,
    glob_matches,
    normalise_extension,
    parse_duration,
    parse_path,
    split_path,
)
from marshalyard.models import Flavor

POSIX = Flavor.POSIX
WINDOWS = Flavor.WINDOWS
HOMES = {POSIX: P("/home/u"), WINDOWS: W("C:\\Users\\X")}


def parse(raw, flavor):
    return parse_path(raw, flavor, HOMES[flavor])


# ------------------------------------------------------------ durations


@pytest.mark.parametrize(
    "text, seconds",
    [
        pytest.param("0s", 0, id="zero"),
        pytest.param("10m", 600, id="minutes"),
        pytest.param("2h", 7200, id="hours"),
        pytest.param("7d", 604800, id="days"),
        pytest.param("3650d", 3650 * 86400, id="maximum"),
    ],
)
def test_valid_durations(text, seconds):
    assert parse_duration(text) == seconds


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("10", id="no-unit"),
        pytest.param("10 m", id="space"),
        pytest.param("1h30m", id="compound"),
        pytest.param("1.5h", id="fraction"),
        pytest.param("-5m", id="negative"),
        pytest.param("10M", id="uppercase-unit"),
        pytest.param("", id="empty"),
        pytest.param("10m\n", id="trailing-newline"),
        pytest.param("\u0661\u0660m", id="non-ascii-digits"),
    ],
)
def test_invalid_durations(text):
    with pytest.raises(FieldError) as info:
        parse_duration(text)
    assert info.value.code == "DURATION_INVALID"


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("3651d", id="just-over"),
        pytest.param("99999999999999s", id="huge"),
        pytest.param("9" * 5000 + "s", id="absurdly-long"),
    ],
)
def test_out_of_range_durations(text):
    with pytest.raises(FieldError) as info:
        parse_duration(text)
    assert info.value.code == "DURATION_OUT_OF_RANGE"


# ------------------------------------------------------------ valid paths


@pytest.mark.parametrize(
    "flavor, raw, expected",
    [
        pytest.param(POSIX, "/", P("/"), id="posix-root"),
        pytest.param(POSIX, "/a/b", P("/a/b"), id="posix-plain"),
        pytest.param(POSIX, "/a/b/", P("/a/b"), id="posix-trailing-sep"),
        pytest.param(POSIX, "~", P("/home/u"), id="posix-tilde"),
        pytest.param(POSIX, "~/", P("/home/u"), id="posix-tilde-slash"),
        pytest.param(POSIX, "~/Downloads", P("/home/u/Downloads"), id="posix-tilde-sub"),
        pytest.param(POSIX, "~/Downloads/", P("/home/u/Downloads"), id="posix-tilde-sub-trailing"),
        pytest.param(WINDOWS, "C:\\Users\\X\\Downloads", W("C:\\Users\\X\\Downloads"), id="win-backslash"),
        pytest.param(WINDOWS, "C:/Users/X/Downloads", W("C:\\Users\\X\\Downloads"), id="win-forward-slash"),
        pytest.param(WINDOWS, "C:\\", W("C:\\"), id="win-drive-root"),
        pytest.param(WINDOWS, "C:\\a\\", W("C:\\a"), id="win-trailing-sep"),
        pytest.param(WINDOWS, "~\\Docs", W("C:\\Users\\X\\Docs"), id="win-tilde-backslash"),
        pytest.param(WINDOWS, "~/Docs", W("C:\\Users\\X\\Docs"), id="win-tilde-slash"),
        pytest.param(WINDOWS, "~", W("C:\\Users\\X"), id="win-tilde"),
    ],
)
def test_valid_paths(flavor, raw, expected):
    assert parse(raw, flavor) == expected


# ------------------------------------------------------------ invalid paths


@pytest.mark.parametrize(
    "flavor, raw, code",
    [
        pytest.param(POSIX, "", "PATH_EMPTY", id="empty"),
        pytest.param(POSIX, "Downloads", "PATH_NOT_ABSOLUTE", id="relative-name"),
        pytest.param(POSIX, "a/b", "PATH_NOT_ABSOLUTE", id="relative-two"),
        pytest.param(POSIX, "./x", "PATH_NOT_ABSOLUTE", id="relative-dot"),
        pytest.param(WINDOWS, "C:foo", "PATH_NOT_ABSOLUTE", id="win-drive-relative"),
        pytest.param(WINDOWS, "C:", "PATH_NOT_ABSOLUTE", id="win-drive-only"),
        pytest.param(WINDOWS, "\\foo", "PATH_NOT_ABSOLUTE", id="win-rooted-no-drive"),
        pytest.param(WINDOWS, "/foo", "PATH_NOT_ABSOLUTE", id="win-slash-no-drive"),
        pytest.param(POSIX, "/a/../b", "PATH_DOT_COMPONENT", id="dotdot-middle"),
        pytest.param(POSIX, "/a/./b", "PATH_DOT_COMPONENT", id="dot-middle"),
        pytest.param(POSIX, "/a/..", "PATH_DOT_COMPONENT", id="dotdot-end"),
        pytest.param(POSIX, "/a//b", "PATH_EMPTY_COMPONENT", id="double-sep"),
        pytest.param(POSIX, "/a/b//", "PATH_EMPTY_COMPONENT", id="double-trailing"),
        pytest.param(POSIX, "//x", "PATH_EMPTY_COMPONENT", id="posix-leading-double"),
        pytest.param(WINDOWS, "C:\\\\", "PATH_EMPTY_COMPONENT", id="win-drive-double-sep"),
        pytest.param(WINDOWS, "C:\\a\\\\b", "PATH_EMPTY_COMPONENT", id="win-double-sep"),
        pytest.param(POSIX, "~root/x", "PATH_TILDE_USER", id="tilde-user-path"),
        pytest.param(POSIX, "~root", "PATH_TILDE_USER", id="tilde-user"),
        pytest.param(POSIX, "/a\x00b", "PATH_INVALID_CHARS", id="nul"),
        pytest.param(POSIX, "/a\tb", "PATH_INVALID_CHARS", id="tab"),
        pytest.param(WINDOWS, "\\\\srv\\share\\x", "PATH_NETWORK_UNSUPPORTED", id="unc-backslash"),
        pytest.param(WINDOWS, "//srv/x", "PATH_NETWORK_UNSUPPORTED", id="unc-slash"),
        pytest.param(WINDOWS, "\\\\?\\C:\\x", "PATH_NETWORK_UNSUPPORTED", id="extended-length"),
    ],
)
def test_invalid_paths(flavor, raw, code):
    with pytest.raises(FieldError) as info:
        parse(raw, flavor)
    assert info.value.code == code


# ------------------------------------------------------------ other path behaviour


def test_backslash_is_an_ordinary_character_on_posix():
    assert parse("/a\\b", POSIX) == P("/a\\b")


def test_windows_drive_letter_spelling_is_preserved():
    assert str(parse("c:\\Users", WINDOWS)) == "c:\\Users"


def test_split_path_returns_anchor_and_components():
    assert split_path("/a/b/", POSIX, HOMES[POSIX]) == SplitPath("/", ("a", "b"))
    assert split_path("C:\\a\\b", WINDOWS, HOMES[WINDOWS]) == SplitPath("C:\\", ("a", "b"))


def test_tilde_needs_a_home_of_the_same_flavor():
    with pytest.raises(ValueError):
        parse_path("~", WINDOWS, P("/home/u"))


def test_field_error_carries_its_code():
    with pytest.raises(FieldError) as info:
        parse("", POSIX)
    assert info.value.code == "PATH_EMPTY"

# ------------------------------------------------------------ rule names


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("invoices", id="word"),
        pytest.param("a", id="single"),
        pytest.param("a-b_c9", id="symbols"),
        pytest.param("0start", id="digit-first"),
        pytest.param("a" * 64, id="max-length"),
    ],
)
def test_valid_rule_names(name):
    assert check_rule_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("Bad Name", id="space-and-caps"),
        pytest.param("", id="empty"),
        pytest.param("A", id="uppercase"),
        pytest.param("-start", id="dash-first"),
        pytest.param("_x", id="underscore-first"),
        pytest.param("a" * 65, id="too-long"),
        pytest.param("(undo)", id="reserved"),
        pytest.param("a b", id="space"),
        pytest.param("name\n", id="newline"),
    ],
)
def test_invalid_rule_names(name):
    with pytest.raises(FieldError) as info:
        check_rule_name(name)
    assert info.value.code == "RULE_NAME_INVALID"


# ------------------------------------------------------------ extensions


@pytest.mark.parametrize(
    "text, expected",
    [
        pytest.param("pdf", "pdf", id="plain"),
        pytest.param("PDF", "pdf", id="uppercase"),
        pytest.param("c++", "c++", id="plus"),
        pytest.param("7z", "7z", id="digit-first"),
        pytest.param("tar_gz", "tar_gz", id="underscore"),
        pytest.param("a" * 16, "a" * 16, id="max-length"),
    ],
)
def test_valid_extensions(text, expected):
    assert normalise_extension(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(".pdf", id="leading-dot"),
        pytest.param("tar.gz", id="inner-dot"),
        pytest.param("", id="empty"),
        pytest.param("a" * 17, id="too-long"),
        pytest.param("p df", id="space"),
        pytest.param("\u212a", id="kelvin-sign"),
        pytest.param("pdf\n", id="newline"),
        pytest.param("\u00e9", id="non-ascii"),
    ],
)
def test_invalid_extensions(text):
    with pytest.raises(FieldError) as info:
        normalise_extension(text)
    assert info.value.code == "EXTENSION_INVALID"


@pytest.mark.parametrize(
    "name, expected",
    [
        pytest.param("a.pdf", "pdf", id="simple"),
        pytest.param("a.PDF", "pdf", id="uppercase"),
        pytest.param("a.tar.gz", "gz", id="last-dot"),
        pytest.param(".bashrc", None, id="dotfile"),
        pytest.param("file.", None, id="trailing-dot"),
        pytest.param("noext", None, id="none"),
        pytest.param(".a.pdf", "pdf", id="dotfile-with-extension"),
        pytest.param("a.b.C", "c", id="mixed-case"),
        pytest.param("", None, id="empty"),
    ],
)
def test_file_extension(name, expected):
    assert file_extension(name) == expected


def test_dedupe_keeps_first_seen_order():
    assert dedupe(["b", "a", "b", "c", "a"]) == ("b", "a", "c")


# ------------------------------------------------------------ globs


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param("invoice*", id="star"),
        pytest.param("*.tar.gz", id="suffix"),
        pytest.param("[abc]*", id="set"),
        pytest.param("[!a]x", id="negated-set"),
        pytest.param("[]a]", id="bracket-in-set"),
        pytest.param("a]", id="stray-closing-bracket"),
        pytest.param("report-??.pdf", id="question-marks"),
    ],
)
def test_valid_globs(pattern):
    assert check_glob(pattern) == pattern


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param("", id="empty"),
        pytest.param("a/b", id="slash"),
        pytest.param("a\\b", id="backslash"),
        pytest.param("a\tb", id="control-char"),
        pytest.param("[", id="lone-bracket"),
        pytest.param("[abc", id="unclosed-set"),
        pytest.param("[]", id="empty-set"),
    ],
)
def test_invalid_globs(pattern):
    with pytest.raises(FieldError) as info:
        check_glob(pattern)
    assert info.value.code == "GLOB_INVALID"


def test_glob_check_uses_the_code_it_is_given():
    with pytest.raises(FieldError) as info:
        check_glob("[", code="EXCLUDE_PATTERN_INVALID")
    assert info.value.code == "EXCLUDE_PATTERN_INVALID"


@pytest.mark.parametrize(
    "pattern, name, expected",
    [
        pytest.param("INVOICE*", "invoice-1.PDF", True, id="case-insensitive-prefix"),
        pytest.param("*.pdf", "A.PDF", True, id="case-insensitive-suffix"),
        pytest.param("*.tar.gz", "a.tar.gz", True, id="multi-dot"),
        pytest.param("a?c", "abc", True, id="question-mark"),
        pytest.param("[a-c]x", "Bx", True, id="range-case-insensitive"),
        pytest.param("*.pdf", "a.txt", False, id="no-match"),
        pytest.param("a*", "b", False, id="different-start"),
        pytest.param("[!a]x", "ax", False, id="negated-set"),
    ],
)
def test_glob_matches(pattern, name, expected):
    assert glob_matches(pattern, name) is expected


# ------------------------------------------------------------ portable component names


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("Invoices", id="word"),
        pytest.param("2026", id="digits"),
        pytest.param("My Files", id="inner-space"),
        pytest.param("a.b", id="inner-dot"),
        pytest.param("\u00e9", id="accent"),
        pytest.param("CONSOLE", id="starts-like-reserved"),
        pytest.param("COM10", id="com10-is-not-reserved"),
        pytest.param("a" * 255, id="255-ascii-bytes"),
        pytest.param("\u20ac" * 85, id="255-utf8-bytes"),
    ],
)
def test_valid_components(name):
    assert check_portable_component(name) == name


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("", id="empty"),
        pytest.param("CON", id="con"),
        pytest.param("con", id="con-lowercase"),
        pytest.param("con.txt", id="con-with-extension"),
        pytest.param("NUL.tar.gz", id="nul-multi-dot"),
        pytest.param("COM1", id="com1"),
        pytest.param("LPT9", id="lpt9"),
        pytest.param("com\u00b9", id="com-superscript"),
        pytest.param("a.", id="trailing-dot"),
        pytest.param("a ", id="trailing-space"),
        pytest.param("a:b", id="colon"),
        pytest.param("a|b", id="pipe"),
        pytest.param('a"b', id="quote"),
        pytest.param("a<b", id="less-than"),
        pytest.param("a>b", id="greater-than"),
        pytest.param("a?b", id="question"),
        pytest.param("a*b", id="star"),
        pytest.param("a/b", id="slash"),
        pytest.param("a\\b", id="backslash"),
        pytest.param("a\tb", id="control-char"),
        pytest.param("a" * 256, id="256-ascii-bytes"),
        pytest.param("\u20ac" * 86, id="258-utf8-bytes"),
    ],
)
def test_invalid_components(name):
    with pytest.raises(FieldError) as info:
        check_portable_component(name)
    assert info.value.code == "TEMPLATE_COMPONENT_INVALID"