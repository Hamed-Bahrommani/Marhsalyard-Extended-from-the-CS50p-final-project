from pathlib import PurePosixPath as P
from pathlib import PureWindowsPath as W

import pytest

from marshalyard.config import parse_config
from marshalyard.memoryfs import MemoryFileSystem
from marshalyard.models import FileEntry, Flavor, Snapshot, UnplannedReason
from marshalyard.planner import match_entries
from marshalyard.scanner import scan

POSIX = Flavor.POSIX
HOME = P("/home/u")
MTIME = 1_000_000_000_000
SETTLED = MTIME + 600 * 10**9  # exactly the default 10-minute boundary
SRC = P("/d/in")


def rule(name="pdfs", source="/d/in", extra="extensions = ['pdf']"):
    return (
        f"[[rule]]\nname = '{name}'\nsource = '{source}'\n"
        f"destination = '/d/out/{{ext}}'\n{extra}\n"
    )


def config(*rules, roots="['/d/in', '/d/in2', '/d/out']"):
    text = f"version = 1\n[settings]\nroots = {roots}\n" + "".join(rules or [rule()])
    result = parse_config(text, POSIX, HOME)
    assert result.config is not None, result.issues
    return result.config


def outcome(fs, cfg, now=SETTLED):
    sources = {r.source for r in cfg.rules}
    snapshot = scan(fs, sources, exclude=cfg.exclude, taken_at_ns=now).snapshot
    return match_entries(cfg, snapshot, now)


def fs_with(*names, parent=SRC, **kw):
    fs = MemoryFileSystem()
    for name in names:
        fs.add_file(parent / name, mtime_ns=MTIME, **kw)
    return fs


def paths(items):
    return [getattr(item, "entry", item).path.name if hasattr(item, "entry") else item.src.name for item in items]


# ------------------------------------------------------------ scope and match


def test_matching_file_is_a_candidate_with_its_rule():
    cfg = config()
    result = outcome(fs_with("a.pdf"), cfg)
    assert len(result.candidates) == 1
    assert result.candidates[0].entry.path == SRC / "a.pdf"
    assert result.candidates[0].rule is cfg.rules[0]
    assert result.unplanned == ()


def test_extension_match_ignores_case():
    assert paths(outcome(fs_with("A.PDF"), config()).candidates) == ["A.PDF"]


def test_file_matching_no_rule_is_not_reported_at_all():
    result = outcome(fs_with("a.txt"), config())
    assert result.candidates == () and result.unplanned == ()


def test_extensionless_file_never_matches_an_extension_rule():
    result = outcome(fs_with("README"), config())
    assert result.candidates == () and result.unplanned == ()


def test_glob_only_rule_matches_by_name():
    cfg = config(rule(extra="name_glob = 'inv*'"))
    result = outcome(fs_with("invoice.txt", "other.txt"), cfg)
    assert paths(result.candidates) == ["invoice.txt"]


def test_extension_and_glob_must_both_match():
    cfg = config(rule(extra="extensions = ['pdf']\nname_glob = 'inv*'"))
    result = outcome(fs_with("inv.pdf", "inv.txt", "x.pdf"), cfg)
    assert paths(result.candidates) == ["inv.pdf"]


def test_rules_only_see_files_directly_in_their_source():
    cfg = config(rule(name="a", source="/d/in"), rule(name="b", source="/d/in2", extra="extensions = ['txt']"))
    fs = fs_with("a.pdf")
    fs.add_file(P("/d/in2/b.txt"), mtime_ns=MTIME)
    fs.add_file(P("/d/in2/c.pdf"), mtime_ns=MTIME)
    result = outcome(fs, cfg)
    assert sorted(c.entry.path.as_posix() for c in result.candidates) == ["/d/in/a.pdf", "/d/in2/b.txt"]
    assert result.unplanned == ()


def test_candidates_and_unplanned_are_sorted():
    cfg = config()
    fs = fs_with("c.pdf", "a.pdf", "b.pdf")
    assert paths(outcome(fs, cfg).candidates) == ["a.pdf", "b.pdf", "c.pdf"]
    fresh = outcome(fs, cfg, now=MTIME)
    assert paths(fresh.unplanned) == ["a.pdf", "b.pdf", "c.pdf"]


# ------------------------------------------------------------ conflicts


def conflicting():
    return config(rule(name="by-ext"), rule(name="by-glob", extra="name_glob = 'inv*'"))


def test_file_matching_two_rules_is_a_conflict():
    result = outcome(fs_with("inv.pdf"), conflicting())
    assert result.candidates == ()
    [item] = result.unplanned
    assert item.reason is UnplannedReason.RULE_CONFLICT
    assert item.detail == "matches rules: by-ext, by-glob"


def test_conflict_is_reported_regardless_of_age():
    result = outcome(fs_with("inv.pdf"), conflicting(), now=MTIME)
    assert [u.reason for u in result.unplanned] == [UnplannedReason.RULE_CONFLICT]


def test_conflict_blocks_only_the_affected_file():
    result = outcome(fs_with("inv.pdf", "plain.pdf"), conflicting())
    assert paths(result.candidates) == ["plain.pdf"]
    assert paths(result.unplanned) == ["inv.pdf"]


# ------------------------------------------------------------ age


def test_file_one_nanosecond_too_young_is_not_settled():
    result = outcome(fs_with("a.pdf"), config(), now=SETTLED - 1)
    assert result.candidates == ()
    [item] = result.unplanned
    assert (item.reason, item.detail) == (UnplannedReason.NOT_SETTLED, "min_age=600s")


def test_file_exactly_at_the_boundary_is_settled():
    assert len(outcome(fs_with("a.pdf"), config(), now=SETTLED).candidates) == 1


def test_rule_specific_min_age_overrides_the_default():
    zero = config(rule(extra="extensions = ['pdf']\nmin_age = '0s'"))
    assert len(outcome(fs_with("a.pdf"), zero, now=MTIME).candidates) == 1
    hour = config(rule(extra="extensions = ['pdf']\nmin_age = '1h'"))
    result = outcome(fs_with("a.pdf"), hour, now=MTIME + 3599 * 10**9)
    assert result.unplanned[0].detail == "min_age=3600s"


def test_future_mtime_is_not_settled_even_with_zero_min_age():
    cfg = config(rule(extra="extensions = ['pdf']\nmin_age = '0s'"))
    fs = MemoryFileSystem()
    fs.add_file(SRC / "a.pdf", mtime_ns=MTIME + 10**10)
    result = outcome(fs, cfg, now=MTIME)
    assert [u.reason for u in result.unplanned] == [UnplannedReason.NOT_SETTLED]


def test_details_do_not_depend_on_the_time_of_planning():
    fs = fs_with("a.pdf")
    first = outcome(fs, config(), now=MTIME + 1)
    second = outcome(fs, config(), now=MTIME + 100 * 10**9)
    assert first.unplanned == second.unplanned and first.unplanned


# ------------------------------------------------------------ identity and links


def test_unavailable_identity_is_refused():
    result = outcome(fs_with("a.pdf", hide_identity=True), config())
    assert [u.reason for u in result.unplanned] == [UnplannedReason.IDENTITY_UNAVAILABLE]


def test_hard_linked_files_are_refused_with_the_count():
    fs = fs_with("a.pdf")
    fs.add_hardlink(SRC / "a.pdf", SRC / "b.pdf")
    result = outcome(fs, config())
    assert result.candidates == ()
    assert [(u.reason, u.detail) for u in result.unplanned] == [
        (UnplannedReason.MULTIPLE_LINKS, "nlink=2"),
        (UnplannedReason.MULTIPLE_LINKS, "nlink=2"),
    ]


def entry_snapshot(**overrides):
    values = dict(size=1, mtime_ns=MTIME, dev=1, ino=2, nlink=1)
    values.update(overrides)
    return Snapshot(SETTLED, (SRC,), (FileEntry(SRC / "a.pdf", **values),), ())


def test_unavailable_link_count_is_refused():
    result = match_entries(config(), entry_snapshot(nlink=0), SETTLED)
    assert [u.reason for u in result.unplanned] == [UnplannedReason.LINK_COUNT_UNAVAILABLE]


def test_refusal_ladder_reports_identity_before_link_problems():
    result = match_entries(config(), entry_snapshot(dev=0, nlink=2), SETTLED)
    assert [u.reason for u in result.unplanned] == [UnplannedReason.IDENTITY_UNAVAILABLE]


def test_age_is_checked_before_identity():
    result = outcome(fs_with("a.pdf", hide_identity=True), config(), now=MTIME)
    assert [u.reason for u in result.unplanned] == [UnplannedReason.NOT_SETTLED]


def test_candidate_has_a_single_link_and_real_identity():
    [candidate] = outcome(fs_with("a.pdf"), config()).candidates
    assert candidate.entry.nlink == 1 and candidate.entry.dev > 0 and candidate.entry.ino > 0


# ------------------------------------------------------------ flavours


def test_mixed_flavors_are_rejected():
    windows_snapshot = Snapshot(1, (W(r"C:\in"),), (FileEntry(W(r"C:\in\a.pdf"), 1, 2, 3, 4, 1),), ())
    with pytest.raises(ValueError):
        match_entries(config(), windows_snapshot, SETTLED)


def test_windows_source_scope_ignores_case():
    text = (
        "version = 1\n[settings]\nroots = ['C:\\in', 'C:\\out']\n"
        "[[rule]]\nname = 'pdfs'\nsource = 'c:\\IN'\nextensions = ['pdf']\ndestination = 'C:\\out\\{ext}'\n"
    )
    cfg = parse_config(text, Flavor.WINDOWS, W("C:\\Users\\X")).config
    assert cfg is not None
    fs = MemoryFileSystem(Flavor.WINDOWS)
    fs.add_file(W(r"C:\In\a.pdf"), mtime_ns=MTIME)
    snapshot = scan(fs, [W(r"C:\In")], exclude=cfg.exclude, taken_at_ns=SETTLED).snapshot
    result = match_entries(cfg, snapshot, SETTLED)
    assert len(result.candidates) == 1
