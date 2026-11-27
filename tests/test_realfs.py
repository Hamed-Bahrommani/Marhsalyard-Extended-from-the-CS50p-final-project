import os
import subprocess
import time
from pathlib import Path

import pytest

from marshalyard.config import parse_config
from marshalyard.filesystem import FileKind, FsError
from marshalyard.models import Flavor, SkipReason
from marshalyard.planner import build_plan
from marshalyard.realfs import RealFileSystem
from marshalyard.scanner import scan

fs = RealFileSystem()


def path_of(base, *parts):
    path_type = type(fs.realpath(type(fs.realpath.__self__._path_type("/") if False else None) if False else None)) if False else None
    return None


def test_flavor_matches_the_platform():
    assert fs.flavor is (Flavor.WINDOWS if os.name == "nt" else Flavor.POSIX)


def real(tmp_path):
    path_type = type(fs.realpath(_anchor(tmp_path)))
    return path_type(str(tmp_path.resolve()))


def _anchor(tmp_path):
    from pathlib import PurePosixPath, PureWindowsPath

    path_type = PureWindowsPath if os.name == "nt" else PurePosixPath
    return path_type(str(tmp_path.resolve()))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX named pipes")
def test_a_named_pipe_is_reported_and_never_opened(tmp_path):
    pipe = tmp_path / "pipe"
    os.mkfifo(str(pipe))
    target = _anchor(tmp_path) / "pipe"
    assert fs.lstat(target).kind is FileKind.OTHER
    with pytest.raises(FsError):
        fs.open_read(target)  # must return, not hang


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="needs a non-root POSIX user")
def test_permission_denied_is_an_fs_error(tmp_path):
    secret = tmp_path / "secret"
    secret.write_bytes(b"x")
    secret.chmod(0)
    with pytest.raises(FsError):
        fs.open_read(_anchor(tmp_path) / "secret")


@pytest.mark.skipif(os.name != "nt", reason="junctions exist only on Windows")
def test_a_junction_is_reported_as_a_link_or_reparse_point(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "junction"
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
    if result.returncode != 0:
        pytest.skip("could not create a junction")
    info = fs.lstat(_anchor(tmp_path) / "junction")
    assert info.kind is FileKind.SYMLINK or info.reparse_point


# ------------------------------------------------------------ integration on a real disk


def make_tree(tmp_path):
    source = tmp_path / "in"
    out = tmp_path / "out"
    source.mkdir()
    out.mkdir()
    old = time.time_ns() - 3600 * 10**9
    for name, content in (("a.pdf", b"alpha"), (".hidden.pdf", b"secret"), ("notes.txt", b"n")):
        (source / name).write_bytes(content)
        os.utime(str(source / name), ns=(old, old))
    return source, out


def real_config(source, out):
    text = (
        f"version = 1\n[settings]\nroots = ['{source}', '{out}']\n"
        f"[[rule]]\nname = 'pdfs'\nsource = '{source}'\nextensions = ['pdf']\n"
        f"destination = '{out}/{{ext}}'\n"
    )
    home = _anchor(Path.home())
    result = parse_config(text, fs.flavor, home)
    assert result.config is not None, result.issues
    return result.config


def test_scanning_a_real_directory(tmp_path):
    source, _ = make_tree(tmp_path)
    root = _anchor(source)
    result = scan(fs, [root], exclude=(".*",), taken_at_ns=time.time_ns())
    names = [entry.path.name for entry in result.snapshot.entries]
    assert names == ["a.pdf", "notes.txt"]
    assert all(entry.dev > 0 and entry.ino > 0 and entry.nlink == 1 for entry in result.snapshot.entries)
    assert [(s.path.name, s.reason) for s in result.snapshot.skipped] == [(".hidden.pdf", SkipReason.EXCLUDED)]


def test_scanner_skips_a_real_symlink(tmp_path):
    source, _ = make_tree(tmp_path)
    try:
        os.symlink(str(source / "a.pdf"), str(source / "link.pdf"))
    except OSError:
        pytest.skip("symlinks are not available here")
    result = scan(fs, [_anchor(source)], exclude=(".*",), taken_at_ns=time.time_ns())
    assert {s.path.name: s.reason for s in result.snapshot.skipped}["link.pdf"] is SkipReason.SYMLINK


def test_planning_real_files_end_to_end(tmp_path):
    source, out = make_tree(tmp_path)
    config = real_config(_anchor(source), _anchor(out))
    now = time.time_ns()
    snapshot = scan(fs, [_anchor(source)], exclude=config.exclude, taken_at_ns=now).snapshot
    outcome = build_plan(fs, config, snapshot, now)
    [op] = outcome.plan.operations
    assert op.src == _anchor(source) / "a.pdf"
    assert op.dst == _anchor(out) / "pdf" / "a.pdf"
    assert op.fingerprint.sha256 is not None and op.fingerprint.nlink == 1
    assert os.listdir(str(out)) == []  # planning changed nothing on disk
    assert (source / "a.pdf").read_bytes() == b"alpha"
