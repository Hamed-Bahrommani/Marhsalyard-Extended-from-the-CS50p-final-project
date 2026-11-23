import sys

import pytest

from marshalyard.config import check_structure


def build(settings="", rule="", top=""):
    return (
        "version = 1\n"
        f"{top}\n"
        "[settings]\n"
        'roots = ["/data/in"]\n'
        f"{settings}\n"
        "[[rule]]\n"
        'name = "pdfs"\n'
        'source = "/data/in"\n'
        'destination = "/data/in/{ext}"\n'
        f"{rule}\n"
    )


def pairs(text):
    return [(issue.code, issue.location) for issue in check_structure(text)]


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


# ------------------------------------------------------------ valid


def test_minimal_structure_is_clean():
    assert pairs(build()) == []


def test_full_example_structure_is_clean():
    assert pairs(FULL_EXAMPLE) == []


# ------------------------------------------------------------ syntax and version


def test_toml_syntax_error():
    issues = check_structure("version = ")
    assert len(issues) == 1
    issue = issues[0]
    assert (issue.code, issue.location) == ("TOML_SYNTAX", "$")
    assert issue.message
    if sys.version_info >= (3, 14):
        assert isinstance(issue.line, int) and isinstance(issue.column, int)
    else:
        assert issue.line is None and issue.column is None


@pytest.mark.parametrize(
    "text, code",
    [
        pytest.param("", "VERSION_MISSING", id="empty"),
        pytest.param("junk = 1", "VERSION_MISSING", id="no-version-with-junk"),
        pytest.param('[settings]\nroots = ["/a"]', "VERSION_MISSING", id="tables-only"),
        pytest.param("version = 2", "VERSION_UNSUPPORTED", id="two"),
        pytest.param('version = "1"', "VERSION_UNSUPPORTED", id="string"),
        pytest.param("version = true", "VERSION_UNSUPPORTED", id="bool"),
        pytest.param("version = 1.0", "VERSION_UNSUPPORTED", id="float"),
    ],
)
def test_version_stops_everything_else(text, code):
    assert pairs(text) == [(code, "version")]


# ------------------------------------------------------------ unknown keys


def test_unknown_keys_at_every_level():
    text = build(
        settings='colour = "red"',
        rule='extenions = ["pdf"]',
        top="bogus = 1",
    )
    assert pairs(text) == [
        ("UNKNOWN_KEY", "bogus"),
        ("UNKNOWN_KEY", "rule[0].extenions"),
        ("UNKNOWN_KEY", "settings.colour"),
    ]


# ------------------------------------------------------------ wrong types


def test_four_wrong_types_without_cascade():
    text = (
        "version = 1\n\n[settings]\n"
        'roots = "x"\n'
        "max_operations = true\n\n"
        "[[rule]]\n"
        'name = "a"\nsource = "/s"\ndestination = "/d/{ext}"\n'
        'extensions = "pdf"\n'
        "min_age = 600\n"
    )
    assert pairs(text) == [
        ("WRONG_TYPE", "rule[0].extensions"),
        ("WRONG_TYPE", "rule[0].min_age"),
        ("WRONG_TYPE", "settings.max_operations"),
        ("WRONG_TYPE", "settings.roots"),
    ]


@pytest.mark.parametrize(
    "settings, location",
    [
        pytest.param("timezone = 3", "settings.timezone", id="timezone-int"),
        pytest.param("min_age = 600", "settings.min_age", id="min-age-int"),
        pytest.param('max_operations = "5"', "settings.max_operations", id="max-ops-str"),
        pytest.param("max_operations = 1.5", "settings.max_operations", id="max-ops-float"),
        pytest.param("max_operations = true", "settings.max_operations", id="max-ops-bool"),
        pytest.param('exclude = "x"', "settings.exclude", id="exclude-str"),
        pytest.param("exclude = [1]", "settings.exclude[0]", id="exclude-element"),
    ],
)
def test_settings_wrong_types(settings, location):
    assert pairs(build(settings=settings)) == [("WRONG_TYPE", location)]


@pytest.mark.parametrize(
    "rule, location",
    [
        pytest.param("name_glob = 3", "rule[0].name_glob", id="glob-int"),
        pytest.param("min_age = 600", "rule[0].min_age", id="min-age-int"),
        pytest.param('extensions = "pdf"', "rule[0].extensions", id="ext-str"),
        pytest.param("extensions = [1]", "rule[0].extensions[0]", id="ext-element"),
    ],
)
def test_rule_wrong_types(rule, location):
    assert pairs(build(rule=rule)) == [("WRONG_TYPE", location)]


@pytest.mark.parametrize(
    "old, new, location",
    [
        pytest.param('name = "pdfs"', "name = 3", "rule[0].name", id="name"),
        pytest.param('source = "/data/in"\n', "source = 3\n", "rule[0].source", id="source"),
        pytest.param('destination = "/data/in/{ext}"', "destination = 3", "rule[0].destination", id="dest"),
    ],
)
def test_rule_required_fields_wrong_types(old, new, location):
    text = build().replace(old, new, 1)
    assert pairs(text) == [("WRONG_TYPE", location)]


@pytest.mark.parametrize(
    "roots, location",
    [
        pytest.param('"x"', "settings.roots", id="string"),
        pytest.param('["/a", 3]', "settings.roots[1]", id="element"),
    ],
)
def test_roots_wrong_types(roots, location):
    text = build().replace('roots = ["/data/in"]', f"roots = {roots}")
    assert pairs(text) == [("WRONG_TYPE", location)]


# ------------------------------------------------------------ missing keys and rules


def test_missing_settings_table():
    text = (
        "version = 1\n[[rule]]\n"
        'name = "a"\nsource = "/s"\ndestination = "/d/{ext}"\n'
    )
    assert pairs(text) == [("MISSING_KEY", "settings")]


def test_missing_roots():
    text = (
        "version = 1\n[settings]\ntimezone = \"utc\"\n[[rule]]\n"
        'name = "a"\nsource = "/s"\ndestination = "/d/{ext}"\n'
    )
    assert pairs(text) == [("MISSING_KEY", "settings.roots")]


def test_rule_missing_name_source_and_destination():
    text = 'version = 1\n[settings]\nroots = ["/a"]\n[[rule]]\n'
    assert pairs(text) == [
        ("MISSING_KEY", "rule[0].destination"),
        ("MISSING_KEY", "rule[0].name"),
        ("MISSING_KEY", "rule[0].source"),
    ]


def test_no_rule_key():
    assert pairs('version = 1\n[settings]\nroots = ["/a"]\n') == [("NO_RULES", "rule")]


def test_empty_rule_array():
    assert pairs('version = 1\nrule = []\n[settings]\nroots = ["/a"]\n') == [("NO_RULES", "rule")]


def test_too_many_rules():
    block = '[[rule]]\nname = "r"\nsource = "/s"\ndestination = "/d/{ext}"\n'
    text = 'version = 1\n[settings]\nroots = ["/a"]\n' + block * 201
    assert pairs(text) == [("TOO_MANY_RULES", "rule")]


def test_settings_not_a_table():
    text = 'version = 1\nsettings = 3\n[[rule]]\nname = "a"\nsource = "/s"\ndestination = "/d/{ext}"\n'
    assert pairs(text) == [("WRONG_TYPE", "settings")]


def test_rule_not_an_array():
    text = 'version = 1\nrule = 3\n[settings]\nroots = ["/a"]\n'
    assert pairs(text) == [("WRONG_TYPE", "rule")]


def test_rule_array_of_non_tables():
    text = 'version = 1\nrule = [1]\n[settings]\nroots = ["/a"]\n'
    assert pairs(text) == [("WRONG_TYPE", "rule[0]")]


def test_rule_as_single_table_is_rejected():
    text = 'version = 1\n[settings]\nroots = ["/a"]\n[rule]\nname = "a"\n'
    assert pairs(text) == [("WRONG_TYPE", "rule")]


# ------------------------------------------------------------ cap and determinism


def test_error_cap_is_fifty_plus_one():
    top = "".join(f"k{i} = 1\n" for i in range(60))
    issues = check_structure(build(top=top))
    codes = [issue.code for issue in issues]
    assert len(issues) == 51
    assert codes.count("UNKNOWN_KEY") == 50
    assert codes.count("TOO_MANY_ERRORS") == 1


def test_issues_are_sorted_and_deterministic():
    text = build(top="zeta = 1\nalpha = 1")
    first = check_structure(text)
    assert first == check_structure(text)
    assert [issue.location for issue in first] == ["alpha", "zeta"]
