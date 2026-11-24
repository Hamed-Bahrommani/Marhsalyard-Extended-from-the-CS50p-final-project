import builtins
import os
import pathlib
import re

import pytest

import marshalyard
from marshalyard.config import MAX_CONFIG_BYTES, load_config, parse_config
from marshalyard.models import Flavor

POSIX = Flavor.POSIX
WINDOWS = Flavor.WINDOWS
HOME = pathlib.PurePosixPath("/home/u")
PACKAGE_DIR = pathlib.Path(marshalyard.__file__).parent

CATALOGUE = {
    "CONFIG_NOT_FOUND", "CONFIG_UNREADABLE", "CONFIG_TOO_LARGE", "CONFIG_NOT_UTF8",
    "TOML_SYNTAX", "VERSION_MISSING", "VERSION_UNSUPPORTED", "UNKNOWN_KEY", "WRONG_TYPE",
    "MISSING_KEY", "NO_RULES", "TOO_MANY_RULES", "ROOTS_EMPTY", "ROOTS_TOO_MANY",
    "TIMEZONE_INVALID", "DURATION_INVALID", "DURATION_OUT_OF_RANGE",
    "MAX_OPERATIONS_OUT_OF_RANGE", "EXCLUDE_PATTERN_INVALID", "PATH_EMPTY",
    "PATH_NOT_ABSOLUTE", "PATH_DOT_COMPONENT", "PATH_EMPTY_COMPONENT", "PATH_TILDE_USER",
    "PATH_INVALID_CHARS", "PATH_NETWORK_UNSUPPORTED", "ROOT_DUPLICATE", "ROOT_TOO_BROAD",
    "RULE_NAME_INVALID", "RULE_NAME_DUPLICATE", "RULE_NO_CONDITION", "EXTENSION_INVALID",
    "GLOB_INVALID", "RULE_SOURCE_OUTSIDE_ROOTS", "RULE_DESTINATION_OUTSIDE_ROOTS",
    "RULE_DESTINATION_IS_SOURCE", "RULE_OVERLAP", "RULE_CHAIN", "TEMPLATE_SYNTAX",
    "TEMPLATE_UNKNOWN_PLACEHOLDER", "TEMPLATE_BAD_FORMAT", "TEMPLATE_COMPONENT_INVALID",
    "TOO_MANY_ERRORS",
}


def rule(name="pdfs", source="/data/in", destination="/data/out/{ext}", extra='extensions = ["pdf"]'):
    return (
        f"[[rule]]\nname = '{name}'\nsource = '{source}'\n"
        f"destination = '{destination}'\n{extra}\n"
    )


def doc(rules=None, roots="['/data/in', '/data/out']", settings="", top=""):
    body = "".join(rules if rules is not None else [rule()])
    return f"version = 1\n{top}\n[settings]\nroots = {roots}\n{settings}\n{body}"


def parsed(text, flavor=POSIX):
    return {i.code for i in parse_config(text, flavor, HOME).issues}


def loaded(tmp_path, data):
    path = tmp_path / "c.toml"
    path.write_bytes(data)
    return {i.code for i in load_config(path, POSIX, HOME).issues}


MANY_ROOTS = "['/data/in', '/data/out', " + ", ".join(f"'/data/r{i}'" for i in range(19)) + "]"
BASE_TEXT = 'version = 1\n[settings]\nroots = ["/a"]\n'

TRIGGERS = {
    "CONFIG_NOT_FOUND": lambda t: {i.code for i in load_config(t / "nope.toml", POSIX, HOME).issues},
    "CONFIG_UNREADABLE": lambda t: {i.code for i in load_config(t, POSIX, HOME).issues},
    "CONFIG_TOO_LARGE": lambda t: loaded(t, b"#" * (MAX_CONFIG_BYTES + 1)),
    "CONFIG_NOT_UTF8": lambda t: loaded(t, b"\xff\xfe\x00"),
    "TOML_SYNTAX": lambda t: parsed("version = "),
    "VERSION_MISSING": lambda t: parsed(""),
    "VERSION_UNSUPPORTED": lambda t: parsed("version = 2"),
    "UNKNOWN_KEY": lambda t: parsed(doc(top="bogus = 1")),
    "WRONG_TYPE": lambda t: parsed(doc(settings="max_operations = true")),
    "MISSING_KEY": lambda t: parsed("version = 1\n[[rule]]\n"),
    "NO_RULES": lambda t: parsed(BASE_TEXT),
    "TOO_MANY_RULES": lambda t: parsed(BASE_TEXT + '[[rule]]\nname = "r"\nsource = "/s"\ndestination = "/d/{ext}"\n' * 201),
    "ROOTS_EMPTY": lambda t: parsed(doc(roots="[]")),
    "ROOTS_TOO_MANY": lambda t: parsed(doc(roots=MANY_ROOTS)),
    "TIMEZONE_INVALID": lambda t: parsed(doc(settings="timezone = 'x'")),
    "DURATION_INVALID": lambda t: parsed(doc([rule(extra="extensions = ['pdf']\nmin_age = '10'")])),
    "DURATION_OUT_OF_RANGE": lambda t: parsed(doc([rule(extra="extensions = ['pdf']\nmin_age = '3651d'")])),
    "MAX_OPERATIONS_OUT_OF_RANGE": lambda t: parsed(doc(settings="max_operations = 0")),
    "EXCLUDE_PATTERN_INVALID": lambda t: parsed(doc(settings="exclude = ['a/b']")),
    "PATH_EMPTY": lambda t: parsed(doc([rule(source="")])),
    "PATH_NOT_ABSOLUTE": lambda t: parsed(doc([rule(source="rel")])),
    "PATH_DOT_COMPONENT": lambda t: parsed(doc([rule(source="/a/../b")])),
    "PATH_EMPTY_COMPONENT": lambda t: parsed(doc([rule(source="/a//b")])),
    "PATH_TILDE_USER": lambda t: parsed(doc([rule(source="~root/x")])),
    "PATH_INVALID_CHARS": lambda t: parsed(doc().replace("source = '/data/in'", 'source = "/a\\u0001b"')),
    "PATH_NETWORK_UNSUPPORTED": lambda t: parsed(
        doc([rule(source=r"\\srv\share\x")], roots=r"['C:\d\in']"), WINDOWS
    ),
    "ROOT_DUPLICATE": lambda t: parsed(doc(roots="['/data/in', '/data/in', '/data/out']")),
    "ROOT_TOO_BROAD": lambda t: parsed(doc(roots="['/']")),
    "RULE_NAME_INVALID": lambda t: parsed(doc([rule(name="Bad Name")])),
    "RULE_NAME_DUPLICATE": lambda t: parsed(doc([rule(name="a"), rule(name="a", extra="extensions = ['jpg']")])),
    "RULE_NO_CONDITION": lambda t: parsed(doc([rule(extra="")])),
    "EXTENSION_INVALID": lambda t: parsed(doc([rule(extra="extensions = ['.pdf']")])),
    "GLOB_INVALID": lambda t: parsed(doc([rule(extra="name_glob = 'a/b'")])),
    "RULE_SOURCE_OUTSIDE_ROOTS": lambda t: parsed(doc([rule(source="/elsewhere")])),
    "RULE_DESTINATION_OUTSIDE_ROOTS": lambda t: parsed(doc([rule(destination="/elsewhere/{ext}")])),
    "RULE_DESTINATION_IS_SOURCE": lambda t: parsed(doc([rule(destination="/data/in")])),
    "RULE_OVERLAP": lambda t: parsed(doc([rule(name="a"), rule(name="b")])),
    "RULE_CHAIN": lambda t: parsed(
        doc([rule(name="a", destination="/data/out"), rule(name="b", source="/data/out", destination="/data/in/{ext}")])
    ),
    "TEMPLATE_SYNTAX": lambda t: parsed(doc([rule(destination="/data/out/{ext")])),
    "TEMPLATE_UNKNOWN_PLACEHOLDER": lambda t: parsed(doc([rule(destination="/data/out/{name}")])),
    "TEMPLATE_BAD_FORMAT": lambda t: parsed(doc([rule(destination="/data/out/{modified}")])),
    "TEMPLATE_COMPONENT_INVALID": lambda t: parsed(doc([rule(destination="/data/out/CON")])),
    "TOO_MANY_ERRORS": lambda t: parsed(doc([rule(name=f"Bad Name {i}") for i in range(60)])),
}


def test_triggers_cover_the_whole_catalogue():
    assert set(TRIGGERS) == CATALOGUE


@pytest.mark.parametrize("code", sorted(CATALOGUE))
def test_every_catalogue_code_is_produced(code, tmp_path):
    assert code in TRIGGERS[code](tmp_path)


def test_config_module_uses_only_catalogue_codes():
    source = (PACKAGE_DIR / "config.py").read_text(encoding="utf-8")
    found = set(re.findall(r"""["']([A-Z][A-Z0-9_]{3,})["']""", source))
    assert found <= CATALOGUE, f"codes outside the catalogue: {sorted(found - CATALOGUE)}"


def test_no_module_uses_typing_literal():
    for path in PACKAGE_DIR.glob("*.py"):
        assert not re.search(r"\bLiteral\b", path.read_text(encoding="utf-8")), path.name


def test_pure_modules_import_no_io_libraries():
    pattern = re.compile(r"^\s*(?:import|from)\s+(?:sqlite3|ctypes|subprocess)\b", re.MULTILINE)
    for path in PACKAGE_DIR.glob("*.py"):
        assert not pattern.search(path.read_text(encoding="utf-8")), path.name


def test_parse_config_never_touches_the_filesystem(monkeypatch):
    texts = [doc(), "version = ", "", doc([rule(source="/x")]), doc(roots="['/']")]
    parse_config(texts[0], POSIX, HOME)  # warm lazy imports before patching

    def boom(*args, **kwargs):
        raise AssertionError("parse_config touched the filesystem")

    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", boom)
        patch.setattr(os, "stat", boom)
        patch.setattr(os, "listdir", boom)
        patch.setattr(os, "scandir", boom)
        patch.setattr(pathlib.Path, "resolve", boom)
        for text in texts:
            parse_config(text, POSIX, HOME)

