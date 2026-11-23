import dataclasses
import sys
from pathlib import PurePosixPath as P
from pathlib import PureWindowsPath as W

import pytest

from marshalyard.config import BUILTIN_EXCLUDES, parse_config
from marshalyard.models import Flavor, ModifiedToken, Severity

POSIX = Flavor.POSIX
WINDOWS = Flavor.WINDOWS
HOMES = {POSIX: P("/home/u"), WINDOWS: W("C:\\Users\\X")}


def rule(name="pdfs", source="/data/in", destination="/data/out/{ext}", extra='extensions = ["pdf"]'):
    return (
        f"[[rule]]\nname = '{name}'\nsource = '{source}'\n"
        f"destination = '{destination}'\n{extra}\n"
    )


def doc(rules=None, roots="['/data/in', '/data/out']", settings="", top=""):
    body = "".join(rules if rules is not None else [rule()])
    return f"version = 1\n{top}\n[settings]\nroots = {roots}\n{settings}\n{body}"


def parse(text, flavor=POSIX):
    return parse_config(text, flavor, HOMES[flavor])


def pairs(text, flavor=POSIX):
    return [(i.code, i.location) for i in parse(text, flavor).issues]


def norm(items):
    return sorted(items, key=lambda p: (p[1], p[0]))


WIN_ROOTS = r"['C:\data\in', 'C:\data\out']"
WIN_DEST = r"C:\data\out\{ext}"

FULL_EXAMPLE = """
version = 1

[settings]
roots = ["~/Downloads", "~/Documents/Sorted"]
timezone = "local"
min_age = "10m"
max_operations = 2000
exclude = ["*.iso.part", "thumbs.db"]

[[rule]]
name = "invoices-by-year"
source = "~/Downloads"
extensions = ["pdf"]
name_glob = "invoice*"
destination = "~/Documents/Sorted/Invoices/{modified:%Y}"

[[rule]]
name = "images"
source = "~/Downloads"
extensions = ["jpg", "jpeg", "png"]
min_age = "1h"
destination = "~/Documents/Sorted/Images/{ext}"
"""


# ------------------------------------------------------------ valid configs


def test_minimal_config():
    result = parse(doc())
    assert result.issues == ()
    assert result.config is not None
    assert result.config.rules[0].name == "pdfs"


def test_full_example_is_normalised():
    result = parse(FULL_EXAMPLE)
    assert result.issues == ()
    config = result.config
    assert config.roots == (P("/home/u/Downloads"), P("/home/u/Documents/Sorted"))
    assert [r.min_age_s for r in config.rules] == [600, 3600]
    assert config.exclude == BUILTIN_EXCLUDES + ("*.iso.part", "thumbs.db")
    assert config.rules[0].source == P("/home/u/Downloads")
    assert config.rules[0].destination.base == P("/home/u/Documents/Sorted/Invoices")
    assert config.rules[0].destination.components == ((ModifiedToken("%Y"),),)
    assert config.rules[1].extensions == ("jpg", "jpeg", "png")


def test_extensions_are_lowercased_and_deduplicated():
    result = parse(doc([rule(extra="extensions = ['PDF', 'pdf']")]))
    assert result.config.rules[0].extensions == ("pdf",)


# ------------------------------------------------------------ syntax, version, structure


def test_syntax_error_has_no_config():
    result = parse("version = ")
    assert result.config is None
    assert [i.code for i in result.issues] == ["TOML_SYNTAX"]


def test_missing_version_has_no_config():
    result = parse("")
    assert result.config is None
    assert [(i.code, i.location) for i in result.issues] == [("VERSION_MISSING", "version")]


def test_typo_key_and_unknown_top_level_key():
    text = doc([rule(extra="extenions = ['pdf']")], top="bogus = 1")
    assert pairs(text) == norm(
        [
            ("UNKNOWN_KEY", "bogus"),
            ("UNKNOWN_KEY", "rule[0].extenions"),
            ("RULE_NO_CONDITION", "rule[0]"),
        ]
    )


# ------------------------------------------------------------ durations


@pytest.mark.parametrize(
    "text, seconds",
    [
        pytest.param("0s", 0, id="0s"),
        pytest.param("10m", 600, id="10m"),
        pytest.param("2h", 7200, id="2h"),
        pytest.param("7d", 604800, id="7d"),
        pytest.param("3650d", 315360000, id="max"),
    ],
)
def test_valid_durations(text, seconds):
    result = parse(doc([rule(extra=f"extensions = ['pdf']\nmin_age = '{text}'")]))
    assert result.issues == ()
    assert result.config.rules[0].min_age_s == seconds


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("10", id="no-unit"),
        pytest.param("10 m", id="space"),
        pytest.param("1h30m", id="compound"),
        pytest.param("1.5h", id="fraction"),
        pytest.param("-5m", id="negative"),
        pytest.param("10M", id="uppercase"),
    ],
)
def test_invalid_durations(text):
    assert pairs(doc([rule(extra=f"extensions = ['pdf']\nmin_age = '{text}'")])) == [
        ("DURATION_INVALID", "rule[0].min_age")
    ]


def test_duration_out_of_range():
    assert pairs(doc([rule(extra="extensions = ['pdf']\nmin_age = '3651d'")])) == [
        ("DURATION_OUT_OF_RANGE", "rule[0].min_age")
    ]


# ------------------------------------------------------------ path syntax


@pytest.mark.parametrize(
    "raw, code",
    [
        pytest.param("Downloads", "PATH_NOT_ABSOLUTE", id="relative"),
        pytest.param("./x", "PATH_NOT_ABSOLUTE", id="dot-relative"),
        pytest.param("/a/../b", "PATH_DOT_COMPONENT", id="dotdot"),
        pytest.param("/a/./b", "PATH_DOT_COMPONENT", id="dot"),
        pytest.param("/a//b", "PATH_EMPTY_COMPONENT", id="double-sep"),
        pytest.param("/a/b//", "PATH_EMPTY_COMPONENT", id="trailing-double"),
        pytest.param("~root/x", "PATH_TILDE_USER", id="tilde-user"),
    ],
)
def test_invalid_source_paths_posix(raw, code):
    assert pairs(doc([rule(source=raw)])) == [(code, "rule[0].source")]


@pytest.mark.parametrize(
    "raw, code",
    [
        pytest.param(r"C:foo", "PATH_NOT_ABSOLUTE", id="drive-relative"),
        pytest.param(r"\foo", "PATH_NOT_ABSOLUTE", id="rooted-only"),
        pytest.param(r"\\srv\share\x", "PATH_NETWORK_UNSUPPORTED", id="unc"),
        pytest.param("//srv/x", "PATH_NETWORK_UNSUPPORTED", id="slash-unc"),
        pytest.param(r"\\?\C:\x", "PATH_NETWORK_UNSUPPORTED", id="extended"),
    ],
)
def test_invalid_source_paths_windows(raw, code):
    text = doc([rule(source=raw, destination=WIN_DEST)], roots=WIN_ROOTS)
    assert pairs(text, WINDOWS) == [(code, "rule[0].source")]


# ------------------------------------------------------------ roots


HOME_RULE = dict(source="/home/u/x", destination="/home/u/y/{ext}")


@pytest.mark.parametrize(
    "roots, rule_args, expected",
    [
        pytest.param("[]", {}, [("ROOTS_EMPTY", "settings.roots")], id="empty"),
        pytest.param("['/']", {}, [("ROOT_TOO_BROAD", "settings.roots[0]")], id="slash"),
        pytest.param("['/home/u']", HOME_RULE, [("ROOT_TOO_BROAD", "settings.roots[0]")], id="home"),
        pytest.param("['/home']", HOME_RULE, [("ROOT_TOO_BROAD", "settings.roots[0]")], id="home-parent"),
        pytest.param(
            "['/data/in', '/data/in', '/data/out']", {}, [("ROOT_DUPLICATE", "settings.roots[1]")], id="duplicate"
        ),
        pytest.param(
            "['/data/in', '/data/in/', '/data/out']", {}, [("ROOT_DUPLICATE", "settings.roots[1]")], id="dup-slash"
        ),
    ],
)
def test_root_problems(roots, rule_args, expected):
    assert pairs(doc([rule(**rule_args)], roots=roots)) == expected


def test_windows_drive_root_is_too_broad():
    text = doc([rule(source=r"C:\data\in", destination=WIN_DEST)], roots=r"['C:\']")
    assert pairs(text, WINDOWS) == [("ROOT_TOO_BROAD", "settings.roots[0]")]


def test_too_many_roots():
    extra = ", ".join(f"'/data/r{i}'" for i in range(19))
    roots = f"['/data/in', '/data/out', {extra}]"
    assert pairs(doc(roots=roots)) == [("ROOTS_TOO_MANY", "settings.roots")]


# ------------------------------------------------------------ containment


def test_source_outside_roots():
    assert pairs(doc([rule(source="/elsewhere")])) == [("RULE_SOURCE_OUTSIDE_ROOTS", "rule[0].source")]


def test_sibling_prefix_is_not_inside_root():
    assert pairs(doc([rule(source="/data/in-evil")])) == [("RULE_SOURCE_OUTSIDE_ROOTS", "rule[0].source")]


def test_destination_outside_roots():
    assert pairs(doc([rule(destination="/data/outside/{ext}")])) == [
        ("RULE_DESTINATION_OUTSIDE_ROOTS", "rule[0].destination")
    ]


def test_case_variant_accepted_on_windows():
    text = doc(
        [rule(source=r"c:\data\in", destination=r"c:\data\out\{ext}")],
        roots=r"['C:\Data\In', 'C:\Data\Out']",
    )
    assert pairs(text, WINDOWS) == []


def test_case_variant_rejected_on_posix():
    text = doc(roots="['/Data/In', '/Data/Out']")
    assert pairs(text) == norm(
        [
            ("RULE_SOURCE_OUTSIDE_ROOTS", "rule[0].source"),
            ("RULE_DESTINATION_OUTSIDE_ROOTS", "rule[0].destination"),
        ]
    )


# ------------------------------------------------------------ conditions


def test_rule_without_condition():
    assert pairs(doc([rule(extra="")])) == [("RULE_NO_CONDITION", "rule[0]")]


def test_empty_extension_list_is_no_condition():
    assert pairs(doc([rule(extra="extensions = []")])) == [("RULE_NO_CONDITION", "rule[0]")]


def test_invalid_extensions():
    assert pairs(doc([rule(extra="extensions = ['.pdf', 'tar.gz']")])) == [
        ("EXTENSION_INVALID", "rule[0].extensions[0]"),
        ("EXTENSION_INVALID", "rule[0].extensions[1]"),
    ]


def test_glob_with_separator_is_invalid():
    assert pairs(doc([rule(extra="name_glob = 'a/b'")])) == [("GLOB_INVALID", "rule[0].name_glob")]


def test_glob_only_rule_is_valid():
    result = parse(doc([rule(extra="name_glob = 'invoice*'")]))
    assert result.issues == ()
    assert result.config.rules[0].name_glob == "invoice*"


def test_glob_and_extensions_can_combine():
    result = parse(doc([rule(extra="extensions = ['pdf']\nname_glob = 'invoice*'")]))
    assert result.issues == ()


# ------------------------------------------------------------ rule names


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("Bad Name", id="space-upper"),
        pytest.param("", id="empty"),
        pytest.param("x" * 65, id="too-long"),
    ],
)
def test_invalid_rule_names(name):
    assert pairs(doc([rule(name=name)])) == [("RULE_NAME_INVALID", "rule[0].name")]


def test_duplicate_rule_name_reported_on_the_later_rule():
    text = doc([rule(name="a"), rule(name="a", extra="extensions = ['jpg']")])
    assert pairs(text) == [("RULE_NAME_DUPLICATE", "rule[1].name")]


# ------------------------------------------------------------ templates and components


@pytest.mark.parametrize(
    "raw, code",
    [
        pytest.param("/data/out/{name}", "TEMPLATE_UNKNOWN_PLACEHOLDER", id="name"),
        pytest.param("/data/out/{ext", "TEMPLATE_SYNTAX", id="unclosed"),
        pytest.param("/data/out/{modified}", "TEMPLATE_BAD_FORMAT", id="no-format"),
        pytest.param("/data/out/{modified:%H}", "TEMPLATE_BAD_FORMAT", id="hour"),
        pytest.param("/data/out/{modified:%Y%B}", "TEMPLATE_BAD_FORMAT", id="month-name"),
        pytest.param("/data/out/a{", "TEMPLATE_SYNTAX", id="literal-brace"),
        pytest.param("/data/out/{modified:%Y/%m}", "TEMPLATE_SYNTAX", id="split"),
    ],
)
def test_invalid_templates(raw, code):
    assert pairs(doc([rule(destination=raw)])) == [(code, "rule[0].destination")]


@pytest.mark.parametrize(
    "component",
    [
        pytest.param("CON", id="con"),
        pytest.param("con.txt", id="con-ext"),
        pytest.param("a.", id="trailing-dot"),
        pytest.param("a:b", id="colon"),
        pytest.param("a|b", id="pipe"),
        pytest.param("a" * 256, id="256-ascii"),
        pytest.param("\u20ac" * 86, id="86-euro"),
        pytest.param("{ext}/CON", id="after-placeholder"),
    ],
)
def test_invalid_destination_components(component):
    assert pairs(doc([rule(destination=f"/data/out/{component}")])) == [
        ("TEMPLATE_COMPONENT_INVALID", "rule[0].destination")
    ]


@pytest.mark.parametrize(
    "component",
    [
        pytest.param("a" * 255, id="255-ascii"),
        pytest.param("\u20ac" * 85, id="85-euro"),
        pytest.param("Invoices", id="plain"),
    ],
)
def test_valid_destination_components(component):
    assert pairs(doc([rule(destination=f"/data/out/{component}")])) == []


# ------------------------------------------------------------ destination equals source


def test_static_destination_equal_to_source():
    assert pairs(doc([rule(destination="/data/in")])) == [("RULE_DESTINATION_IS_SOURCE", "rule[0].destination")]


def test_static_destination_equal_to_source_with_trailing_slash():
    assert pairs(doc([rule(destination="/data/in/")])) == [("RULE_DESTINATION_IS_SOURCE", "rule[0].destination")]


def test_source_with_placeholder_subdirectory_is_fine():
    assert pairs(doc([rule(destination="/data/in/{ext}")])) == []


# ------------------------------------------------------------ overlap and chain


def two(first, second):
    return doc([first, second])


def test_overlap_same_source_same_extension_no_globs():
    text = two(rule(name="a"), rule(name="b"))
    assert pairs(text) == [("RULE_OVERLAP", "rule[1]")]
    assert parse(text).config is None


def test_glob_on_one_rule_removes_overlap():
    text = two(rule(name="a"), rule(name="b", extra="extensions = ['pdf']\nname_glob = 'x*'"))
    assert pairs(text) == []


def test_chain_warning_keeps_config():
    first = rule(name="a", destination="/data/out")
    second = rule(name="b", source="/data/out", destination="/data/in/{ext}")
    result = parse(two(first, second))
    assert [(i.code, i.location, i.severity) for i in result.issues] == [
        ("RULE_CHAIN", "rule[0].destination", Severity.WARNING)
    ]
    assert result.config is not None


def test_no_chain_when_extensions_are_disjoint():
    first = rule(name="a", destination="/data/out")
    second = rule(name="b", source="/data/out", destination="/data/in/{ext}", extra="extensions = ['jpg']")
    assert pairs(two(first, second)) == []


def test_no_chain_for_ancestor_destination():
    first = rule(name="a", destination="/data/out/Archive")
    second = rule(name="b", source="/data/out", destination="/data/in/{ext}")
    assert pairs(two(first, second)) == []


def test_no_chain_for_placeholder_destination():
    first = rule(name="a", destination="/data/out/{ext}")
    second = rule(name="b", source="/data/out", destination="/data/in/{ext}")
    assert pairs(two(first, second)) == []


# ------------------------------------------------------------ settings values


@pytest.mark.parametrize("value", [1, 100000])
def test_valid_max_operations(value):
    result = parse(doc(settings=f"max_operations = {value}"))
    assert result.config.max_operations == value


@pytest.mark.parametrize("value", [0, 100001])
def test_invalid_max_operations(value):
    assert pairs(doc(settings=f"max_operations = {value}")) == [
        ("MAX_OPERATIONS_OUT_OF_RANGE", "settings.max_operations")
    ]


def test_utc_timezone_is_accepted():
    assert parse(doc(settings="timezone = 'utc'")).issues == ()


def test_unknown_timezone_is_rejected():
    assert pairs(doc(settings="timezone = 'GMT'")) == [("TIMEZONE_INVALID", "settings.timezone")]


@pytest.mark.parametrize("pattern", ["a/b", "a[b"])
def test_invalid_exclude_patterns(pattern):
    assert pairs(doc(settings=f"exclude = ['{pattern}']")) == [
        ("EXCLUDE_PATTERN_INVALID", "settings.exclude[0]")
    ]


# ------------------------------------------------------------ determinism and cap


def test_same_input_gives_identical_issues():
    text = doc([rule(name="Bad Name", source="/elsewhere"), rule(name="ok", destination="/x/{name}")])
    first = parse(text).issues
    assert first == parse(text).issues
    assert len(first) >= 3
    assert [(i.location, i.code) for i in first] == sorted((i.location, i.code) for i in first)


def test_sixty_errors_yield_fifty_plus_cap_marker():
    rules = [rule(name=f"Bad Name {i}") for i in range(60)]
    issues = parse(doc(rules)).issues
    codes = [i.code for i in issues]
    assert len(issues) == 51
    assert codes.count("RULE_NAME_INVALID") == 50
    assert codes.count("TOO_MANY_ERRORS") == 1


# ------------------------------------------------------------ config_hash


def test_config_hash_is_64_hex():
    config = parse(doc()).config
    assert len(config.config_hash) == 64
    assert set(config.config_hash) <= set("0123456789abcdef")


def test_trailing_slashes_do_not_change_the_hash():
    plain = parse(doc()).config
    slashed = parse(
        doc([rule(source="/data/in/", destination="/data/out/{ext}/")], roots="['/data/in/', '/data/out/']")
    ).config
    assert plain.config_hash == slashed.config_hash


def test_rule_order_does_not_change_the_hash():
    a = rule(name="a", extra="extensions = ['pdf']")
    b = rule(name="b", source="/data/out", destination="/data/in/{ext}", extra="extensions = ['jpg']")
    assert parse(two(a, b)).config.config_hash == parse(two(b, a)).config.config_hash


def test_root_and_extension_order_do_not_change_the_hash():
    one = parse(doc([rule(extra="extensions = ['pdf', 'txt']")], roots="['/data/in', '/data/out']")).config
    other = parse(doc([rule(extra="extensions = ['txt', 'pdf']")], roots="['/data/out', '/data/in']")).config
    assert one.config_hash == other.config_hash


def test_editing_a_destination_changes_the_hash():
    one = parse(doc([rule(destination="/data/out/{ext}")])).config
    other = parse(doc([rule(destination="/data/out/files/{ext}")])).config
    assert one.config_hash != other.config_hash


def test_a_wrong_config_hash_is_rejected():
    config = parse(doc()).config
    with pytest.raises(ValueError):
        dataclasses.replace(config, config_hash="0" * 64)
