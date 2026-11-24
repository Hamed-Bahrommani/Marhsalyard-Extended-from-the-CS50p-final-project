from project import find_root, main, names_collide, version_string, load_rules
import pytest


def test_version_string():
    assert version_string().startswith("marshalyard ")


def test_main_version(capsys):
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.startswith("marshalyard ")


def test_main_without_arguments_is_usage_error(capsys):
    assert main([]) == 2
    assert "usage" in capsys.readouterr().out


def test_names_collide_on_case_and_unicode():
    assert names_collide("/d/A.PDF", "/d/a.pdf")
    assert names_collide("/d/caf\u00e9.pdf", "/d/cafe\u0301.pdf")


def test_names_do_not_collide_when_different():
    assert not names_collide("/d/a.pdf", "/d/b.pdf")


def test_names_collide_with_windows_paths():
    assert names_collide("C:\\Docs\\A.pdf", "c:\\docs\\a.PDF", windows=True)


def test_find_root_picks_the_most_specific_root():
    roots = ["/home/u/Documents", "/home/u/Documents/Sorted"]
    assert find_root("/home/u/Documents/Sorted/x.pdf", roots) == "/home/u/Documents/Sorted"


def test_find_root_returns_none_outside_every_root():
    assert find_root("/elsewhere/x.pdf", ["/data/downloads"]) is None


def test_find_root_windows_is_case_insensitive():
    roots = ["C:\\Users\\X\\Downloads"]
    assert find_root("c:\\users\\x\\downloads\\a.pdf", roots, windows=True) == "C:\\Users\\X\\Downloads"

def _write_config(tmp_path, version="1"):
    inbox = tmp_path / "in"
    out = tmp_path / "out"
    text = (
        f"version = {version}\n[settings]\nroots = ['{inbox}', '{out}']\n"
        f"[[rule]]\nname = 'pdfs'\nsource = '{inbox}'\nextensions = ['pdf']\n"
        f"destination = '{out}/{{ext}}'\n"
    )
    path = tmp_path / "marshal.toml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_load_rules_returns_rule_names(tmp_path):
    assert load_rules(_write_config(tmp_path)) == ["pdfs"]


def test_load_rules_rejects_an_invalid_file(tmp_path):
    with pytest.raises(ValueError, match="VERSION_UNSUPPORTED"):
        load_rules(_write_config(tmp_path, version="2"))


def test_load_rules_reports_a_missing_file(tmp_path):
    with pytest.raises(ValueError, match="CONFIG_NOT_FOUND"):
        load_rules(str(tmp_path / "missing.toml"))

