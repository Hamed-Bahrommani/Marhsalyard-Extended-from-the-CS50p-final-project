import dataclasses
import re
from pathlib import Path
from pathlib import PurePosixPath as P
from pathlib import PureWindowsPath as W

import marshalyard
from marshalyard.config import parse_config
from marshalyard.environment import check_environment
from marshalyard.memoryfs import MemoryFileSystem
from marshalyard.models import Flavor, Severity

HOME = P("/home/u")


def rule(source="/d/in", destination="/d/out/{ext}", name="pdfs"):
    return f"[[rule]]\nname = '{name}'\nsource = '{source}'\ndestination = '{destination}'\nextensions = ['pdf']\n"


def config(*rules, roots="['/d/in', '/d/out']"):
    text = f"version = 1\n[settings]\nroots = {roots}\n" + "".join(rules or [rule()])
    result = parse_config(text, Flavor.POSIX, HOME)
    assert result.config is not None, result.issues
    return result.config


def healthy():
    fs = MemoryFileSystem()
    fs.add_dir(P("/d/in"))
    fs.add_dir(P("/d/out"))
    return fs


def pairs(fs, cfg):
    return [(i.code, i.location) for i in check_environment(fs, cfg)]


# ------------------------------------------------------------ healthy and roots


def test_a_healthy_environment_has_no_issues():
    assert check_environment(healthy(), config()) == ()


def test_missing_root():
    fs = MemoryFileSystem()
    fs.add_dir(P("/d/in"))
    assert pairs(fs, config()) == [("ENV_ROOT_MISSING", "settings.roots[1]")]


def test_root_that_is_a_file():
    fs = MemoryFileSystem()
    fs.add_dir(P("/d/in"))
    fs.add_file(P("/d/out"))
    assert pairs(fs, config()) == [("ENV_ROOT_NOT_DIRECTORY", "settings.roots[1]")]


def test_root_without_usable_identity():
    class ZeroIdentity(MemoryFileSystem):
        def lstat(self, path):
            info = super().lstat(path)
            return None if info is None else dataclasses.replace(info, dev=0, ino=0, nlink=0)

    fs = ZeroIdentity()
    fs.add_dir(P("/d/in"))
    fs.add_dir(P("/d/out"))
    assert pairs(fs, config()) == [
        ("ENV_IDENTITY_UNAVAILABLE", "settings.roots[0]"),
        ("ENV_IDENTITY_UNAVAILABLE", "settings.roots[1]"),
    ]


def test_a_root_reached_through_a_link_is_fine():
    fs = MemoryFileSystem()
    fs.add_dir(P("/real/in"))
    fs.add_symlink(P("/d/in"), P("/real/in"))
    fs.add_dir(P("/d/out"))
    assert check_environment(fs, config()) == ()


def test_rules_under_a_bad_root_do_not_cascade():
    fs = MemoryFileSystem()
    fs.add_dir(P("/d/in"))
    assert [code for code, _ in pairs(fs, config())] == ["ENV_ROOT_MISSING"]


# ------------------------------------------------------------ sources


def test_missing_source_is_only_a_warning():
    cfg = config(rule(source="/d/in/sub"))
    issues = check_environment(healthy(), cfg)
    assert [(i.code, i.location, i.severity) for i in issues] == [
        ("ENV_SOURCE_MISSING", "rule[0].source", Severity.WARNING)
    ]


def test_source_that_is_a_file():
    fs = healthy()
    fs.add_file(P("/d/in/sub"))
    assert pairs(fs, config(rule(source="/d/in/sub"))) == [("ENV_SOURCE_NOT_DIRECTORY", "rule[0].source")]


def test_source_below_a_file_is_not_a_directory():
    fs = healthy()
    fs.add_file(P("/d/in/f"))
    assert pairs(fs, config(rule(source="/d/in/f/x"))) == [("ENV_SOURCE_NOT_DIRECTORY", "rule[0].source")]


def test_source_that_is_a_link_inside_the_root():
    fs = healthy()
    fs.add_dir(P("/d/in/other"))
    fs.add_symlink(P("/d/in/sub"), P("/d/in/other"))
    assert pairs(fs, config(rule(source="/d/in/sub"))) == [("ENV_LINK_IN_PATH", "rule[0].source")]


def test_source_link_that_leaves_the_root_also_escapes():
    fs = healthy()
    fs.add_dir(P("/elsewhere"))
    fs.add_symlink(P("/d/in/sub"), P("/elsewhere"))
    assert pairs(fs, config(rule(source="/d/in/sub"))) == [
        ("ENV_ESCAPES_ROOT", "rule[0].source"),
        ("ENV_LINK_IN_PATH", "rule[0].source"),
    ]


def test_link_in_the_middle_of_the_source_chain():
    fs = healthy()
    fs.add_dir(P("/d/in/real/b"))
    fs.add_symlink(P("/d/in/a"), P("/d/in/real"))
    assert pairs(fs, config(rule(source="/d/in/a/b"))) == [("ENV_LINK_IN_PATH", "rule[0].source")]


def test_source_equal_to_the_root_is_fine():
    assert check_environment(healthy(), config(rule(source="/d/in"))) == ()


# ------------------------------------------------------------ destinations


def test_link_in_the_destination_base_chain():
    fs = healthy()
    fs.add_dir(P("/d/out/x"))
    fs.add_symlink(P("/d/out/archive"), P("/d/out/x"))
    cfg = config(rule(destination="/d/out/archive/{ext}"))
    assert pairs(fs, cfg) == [("ENV_LINK_IN_PATH", "rule[0].destination")]


def test_destination_link_that_leaves_the_root_also_escapes():
    fs = healthy()
    fs.add_dir(P("/elsewhere"))
    fs.add_symlink(P("/d/out/archive"), P("/elsewhere"))
    cfg = config(rule(destination="/d/out/archive/{ext}"))
    assert pairs(fs, cfg) == [
        ("ENV_ESCAPES_ROOT", "rule[0].destination"),
        ("ENV_LINK_IN_PATH", "rule[0].destination"),
    ]


def test_missing_destination_directories_are_fine():
    cfg = config(rule(destination="/d/out/a/b/c/{ext}"))
    assert check_environment(healthy(), cfg) == ()


def test_a_file_in_the_destination_chain_is_left_to_plan_time():
    fs = healthy()
    fs.add_file(P("/d/out/archive"))
    assert check_environment(fs, config(rule(destination="/d/out/archive/{ext}"))) == ()


# ------------------------------------------------------------ devices


def test_cross_device_is_a_warning():
    fs = MemoryFileSystem()
    fs.add_dir(P("/d/in"))
    fs.add_dir(P("/d/out"), dev=7)
    issues = check_environment(fs, config())
    assert [(i.code, i.location, i.severity) for i in issues] == [
        ("ENV_CROSS_DEVICE", "rule[0].destination", Severity.WARNING)
    ]


def test_nested_mount_below_the_destination_base_is_cross_device():
    fs = healthy()
    fs.add_dir(P("/d/out/archive"), dev=9)
    cfg = config(rule(destination="/d/out/archive/{ext}"))
    assert pairs(fs, cfg) == [("ENV_CROSS_DEVICE", "rule[0].destination")]


def test_no_device_comparison_when_the_source_is_missing():
    fs = MemoryFileSystem()
    fs.add_dir(P("/d/in"))
    fs.add_dir(P("/d/out"), dev=7)
    cfg = config(rule(source="/d/in/sub"))
    assert pairs(fs, cfg) == [("ENV_SOURCE_MISSING", "rule[0].source")]


# ------------------------------------------------------------ shape of the result


def test_locations_use_the_rule_index():
    cfg = config(rule(name="a"), rule(name="b", source="/d/in/sub"))
    assert pairs(healthy(), cfg) == [("ENV_SOURCE_MISSING", "rule[1].source")]


def test_result_is_sorted_and_deterministic():
    fs = MemoryFileSystem()
    fs.add_dir(P("/d/in"))
    fs.add_file(P("/d/out"))
    cfg = config(rule(source="/d/in/sub"))
    first = check_environment(fs, cfg)
    assert first == check_environment(fs, cfg)
    assert [(i.location, i.code) for i in first] == sorted((i.location, i.code) for i in first)


def test_the_check_only_stats_and_resolves_paths():
    fs = healthy()
    fs.add_file(P("/d/in/a.pdf"), b"secret")
    check_environment(fs, config())
    assert {op for op, _ in fs.calls} <= {"lstat", "realpath"}


def test_the_module_uses_exactly_the_expected_codes():
    source = (Path(marshalyard.__file__).parent / "environment.py").read_text(encoding="utf-8")
    assert set(re.findall(r'"(ENV_[A-Z_]+)"', source)) == {
        "ENV_ROOT_MISSING", "ENV_ROOT_NOT_DIRECTORY", "ENV_SOURCE_MISSING",
        "ENV_SOURCE_NOT_DIRECTORY", "ENV_ESCAPES_ROOT", "ENV_LINK_IN_PATH",
        "ENV_IDENTITY_UNAVAILABLE", "ENV_CROSS_DEVICE",
    }


# ------------------------------------------------------------ Windows


def test_windows_paths_compare_case_insensitively():
    text = (
        "version = 1\n[settings]\nroots = ['C:\\in', 'C:\\out']\n"
        "[[rule]]\nname = 'pdfs'\nsource = 'c:\\IN\\Sub'\nextensions = ['pdf']\ndestination = 'C:\\out\\{ext}'\n"
    )
    cfg = parse_config(text, Flavor.WINDOWS, W("C:\\Users\\X")).config
    assert cfg is not None
    fs = MemoryFileSystem(Flavor.WINDOWS)
    fs.add_dir(W(r"C:\In\sub"))
    fs.add_dir(W(r"C:\out"))
    assert check_environment(fs, cfg) == ()
