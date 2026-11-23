from pathlib import PurePosixPath as P
from pathlib import PureWindowsPath as W

import pytest

from marshalyard.config import FieldError, parse_template
from marshalyard.models import (
    DestinationTemplate,
    ExtToken,
    Flavor,
    ModifiedToken,
    TextToken,
)

POSIX = Flavor.POSIX
WINDOWS = Flavor.WINDOWS
HOMES = {POSIX: P("/home/u"), WINDOWS: W("C:\\Users\\X")}


def tpl(raw, flavor=POSIX):
    return parse_template(raw, flavor, HOMES[flavor])


# ------------------------------------------------------------ valid templates


@pytest.mark.parametrize(
    "flavor, raw, base, components",
    [
        pytest.param(POSIX, "/a/b", P("/a/b"), (), id="static"),
        pytest.param(POSIX, "/Sorted/{ext}", P("/Sorted"), ((ExtToken(),),), id="ext"),
        pytest.param(
            POSIX, "/Sorted/Invoices/{modified:%Y}", P("/Sorted/Invoices"),
            ((ModifiedToken("%Y"),),), id="modified-year",
        ),
        pytest.param(
            POSIX, "/Sorted/{modified:%Y-%m}/done", P("/Sorted"),
            ((ModifiedToken("%Y-%m"),), (TextToken("done"),)), id="literal-after-placeholder",
        ),
        pytest.param(
            POSIX, "/Sorted/files-{ext}", P("/Sorted"),
            ((TextToken("files-"), ExtToken()),), id="text-and-placeholder",
        ),
        pytest.param(
            POSIX, "/S/{modified:%Y}_{ext}", P("/S"),
            ((ModifiedToken("%Y"), TextToken("_"), ExtToken()),), id="two-placeholders",
        ),
        pytest.param(POSIX, "~/Sorted/{ext}", P("/home/u/Sorted"), ((ExtToken(),),), id="tilde"),
        pytest.param(WINDOWS, "C:\\Sorted\\{ext}", W("C:\\Sorted"), ((ExtToken(),),), id="windows"),
        pytest.param(POSIX, "/Sorted/{ext}/", P("/Sorted"), ((ExtToken(),),), id="trailing-separator"),
        pytest.param(POSIX, "/{ext}", P("/"), ((ExtToken(),),), id="placeholder-first"),
        pytest.param(
            POSIX, "/S/{modified:%Y%m%d}", P("/S"),
            ((ModifiedToken("%Y%m%d"),),), id="compact-format",
        ),
    ],
)
def test_valid_templates(flavor, raw, base, components):
    template = tpl(raw, flavor)
    assert template.base == base
    assert template.components == components


def test_raw_text_is_preserved():
    assert tpl("/Sorted/{ext}").raw == "/Sorted/{ext}"


def test_home_directory_components_are_not_scanned_for_placeholders():
    template = parse_template("~/x", POSIX, P("/home/{weird}"))
    assert template.base == P("/home/{weird}/x")
    assert template.components == ()


# ------------------------------------------------------------ invalid templates


@pytest.mark.parametrize(
    "raw, code",
    [
        pytest.param("/a/{name}", "TEMPLATE_UNKNOWN_PLACEHOLDER", id="name"),
        pytest.param("/a/{stem}", "TEMPLATE_UNKNOWN_PLACEHOLDER", id="stem"),
        pytest.param("/a/{}", "TEMPLATE_UNKNOWN_PLACEHOLDER", id="empty-braces"),
        pytest.param("/a/{EXT}", "TEMPLATE_UNKNOWN_PLACEHOLDER", id="uppercase"),
        pytest.param("/a/{ext", "TEMPLATE_SYNTAX", id="unclosed"),
        pytest.param("/a/ext}", "TEMPLATE_SYNTAX", id="stray-close"),
        pytest.param("/a/{", "TEMPLATE_SYNTAX", id="lone-open"),
        pytest.param("/a/{a{b}", "TEMPLATE_SYNTAX", id="nested"),
        pytest.param("/a/{modified:%Y/%m}", "TEMPLATE_SYNTAX", id="separator-splits-placeholder"),
        pytest.param("/a/{modified}", "TEMPLATE_BAD_FORMAT", id="modified-without-format"),
        pytest.param("/a/{modified:}", "TEMPLATE_BAD_FORMAT", id="empty-format"),
        pytest.param("/a/{modified:%H}", "TEMPLATE_BAD_FORMAT", id="disallowed-directive"),
        pytest.param("/a/{modified:%Y%B}", "TEMPLATE_BAD_FORMAT", id="second-directive-disallowed"),
        pytest.param("/a/{modified:Y}", "TEMPLATE_BAD_FORMAT", id="no-percent"),
        pytest.param("relative/{ext}", "PATH_NOT_ABSOLUTE", id="relative"),
        pytest.param("/a//{ext}", "PATH_EMPTY_COMPONENT", id="empty-component"),
        pytest.param("/a/../{ext}", "PATH_DOT_COMPONENT", id="dotdot"),
    ],
)
def test_invalid_templates(raw, code):
    with pytest.raises(FieldError) as info:
        tpl(raw)
    assert info.value.code == code


# ------------------------------------------------------------ token and template invariants


def test_empty_text_token_is_rejected():
    with pytest.raises(ValueError):
        TextToken("")


@pytest.mark.parametrize("fmt", ["%Y", "%Y-%m", "%Y_%m_%d", "%Y%m%d"])
def test_valid_modified_formats(fmt):
    assert ModifiedToken(fmt).fmt == fmt


@pytest.mark.parametrize("fmt", ["", "%H", "Y", "%Y%B"])
def test_invalid_modified_formats_are_rejected(fmt):
    with pytest.raises(ValueError):
        ModifiedToken(fmt)


def test_first_variable_component_must_contain_a_placeholder():
    with pytest.raises(ValueError):
        DestinationTemplate("x", P("/a"), ((TextToken("b"),),))


def test_template_base_must_be_absolute():
    with pytest.raises(ValueError):
        DestinationTemplate("x", P("a"), ())


def test_template_components_may_not_be_empty():
    with pytest.raises(ValueError):
        DestinationTemplate("x", P("/a"), ((),))

