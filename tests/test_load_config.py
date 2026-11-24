from pathlib import PurePosixPath as P

from marshalyard.config import MAX_CONFIG_BYTES, load_config
from marshalyard.models import Flavor

HOME = P("/home/u")
VALID = (
    "version = 1\n[settings]\nroots = ['/d/in', '/d/out']\n"
    "[[rule]]\nname = 'pdfs'\nsource = '/d/in'\nextensions = ['pdf']\n"
    "destination = '/d/out/{ext}'\n"
)


def load(path):
    return load_config(path, Flavor.POSIX, HOME)


def codes(result):
    return [(i.code, i.location) for i in result.issues]


def test_missing_file(tmp_path):
    result = load(tmp_path / "nope.toml")
    assert result.config is None
    assert codes(result) == [("CONFIG_NOT_FOUND", "$")]


def test_directory_is_unreadable(tmp_path):
    assert codes(load(tmp_path)) == [("CONFIG_UNREADABLE", "$")]


def test_file_over_the_limit_is_too_large(tmp_path):
    path = tmp_path / "big.toml"
    path.write_bytes(b"#" * (MAX_CONFIG_BYTES + 1))
    assert codes(load(path)) == [("CONFIG_TOO_LARGE", "$")]


def test_file_exactly_at_the_limit_is_parsed(tmp_path):
    path = tmp_path / "edge.toml"
    path.write_bytes(b"#" * MAX_CONFIG_BYTES)
    assert codes(load(path)) == [("VERSION_MISSING", "version")]


def test_non_utf8_file(tmp_path):
    path = tmp_path / "bad.toml"
    path.write_bytes(b"\xff\xfe\x00")
    assert codes(load(path)) == [("CONFIG_NOT_UTF8", "$")]


def test_valid_file_loads(tmp_path):
    path = tmp_path / "ok.toml"
    path.write_text(VALID, encoding="utf-8")
    result = load(path)
    assert result.issues == ()
    assert result.config.rules[0].name == "pdfs"
