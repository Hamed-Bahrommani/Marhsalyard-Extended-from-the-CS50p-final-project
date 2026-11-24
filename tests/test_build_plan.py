from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath as P
from pathlib import PureWindowsPath as W

import pytest

from marshalyard.config import parse_config
from marshalyard.memoryfs import MemoryFileSystem
from marshalyard.models import Flavor, FpMethod, PlanKind, UnplannedReason
from marshalyard.planner import PlanTooLarge, build_plan
from marshalyard.scanner import scan

POSIX = Flavor.POSIX
HOME = P("/home/u")
UTC = timezone.utc
MTIME = 1_000_000_000_000
NOW = MTIME + 600 * 10**9
SRC = P("/d/in")
OUT = P("/d/out")


def rule(name="pdfs", source="/d/in", destination="/d/out/{ext}", extra="extensions = ['pdf']"):
    return f"[[rule]]\nname = '{name}'\nsource = '{source}'\ndestination = '{destination}'\n{extra}\n"


def config(*rules, settings="", roots="['/d/in', '/d/in2', '/d/out']"):
    text = f"version = 1\n[settings]\nroots = {roots}\n{settings}\n" + "".join(rules or [rule()])
    result = parse_config(text, POSIX, HOME)
    assert result.config is not None, result.issues
    return result.config


def world(*names, parent=SRC, mtime=MTIME):
    fs = MemoryFileSystem()
    fs.add_dir(OUT)
    for name in names:
        fs.add_file(parent / name, name.encode(), mtime_ns=mtime)
    return fs


def plan(fs, cfg, now=NOW, tz=UTC, **kw):
    sources = {r.source for r in cfg.rules}
    snapshot = scan(fs, sources, exclude=cfg.exclude, taken_at_ns=now).snapshot
    return build_plan(fs, cfg, snapshot, now, tz, **kw)


def reasons(outcome):
    return {u.src.name: u.reason for u in outcome.unplanned}


def ns(year, month, day, hour=0):
    return int(datetime(year, month, day, hour, tzinfo=UTC).timestamp()) * 10**9


# ------------------------------------------------------------ the plan itself


def test_a_settled_file_is_planned():
    cfg = config()
    outcome = plan(world("a.pdf"), cfg)
    plan_ = outcome.plan
    [op] = plan_.operations
    assert (op.seq, op.src, op.dst, op.rule_name) == (1, SRC / "a.pdf", OUT / "pdf" / "a.pdf", "pdfs")
    assert op.fingerprint.method is FpMethod.CONTENT and op.fingerprint.nlink == 1
    assert (plan_.kind, plan_.config_hash, plan_.created_at_ns, plan_.derived_from_run) == (
        PlanKind.ORGANIZE, cfg.config_hash, NOW, None
    )


def test_planning_is_deterministic():
    fs = world("a.pdf", "b.pdf")
    cfg = config()
    assert plan(fs, cfg) == plan(fs, cfg)


def test_created_at_does_not_change_the_plan_id():
    fs = world("a.pdf")
    cfg = config()
    assert plan(fs, cfg, now=NOW).plan.plan_id == plan(fs, cfg, now=NOW + 5 * 10**9).plan.plan_id


def test_unsettled_report_is_stable_across_times_on_the_same_side_of_the_boundary():
    fs = world("a.pdf", "b.pdf")
    fs.add_file(SRC / "c.pdf", b"c", mtime_ns=NOW)  # fresh at both times below
    cfg = config()
    first = plan(fs, cfg, now=NOW + 10)
    second = plan(fs, cfg, now=NOW + 500)
    assert first.plan.plan_id == second.plan.plan_id


def test_operations_are_ordered_by_source_path():
    outcome = plan(world("c.pdf", "a.pdf", "b.pdf"), config())
    assert [(op.seq, op.src.name) for op in outcome.plan.operations] == [(1, "a.pdf"), (2, "b.pdf"), (3, "c.pdf")]


def test_nothing_to_do_gives_no_plan_but_still_a_report():
    outcome = plan(world("a.pdf"), config(), now=MTIME)
    assert outcome.plan is None
    assert reasons(outcome) == {"a.pdf": UnplannedReason.NOT_SETTLED}


def test_every_stage_contributes_to_one_sorted_report():
    fs = world("good.pdf", "fresh.pdf", "bad.pdf")
    fs.touch(SRC / "fresh.pdf", NOW)
    fs.add_file(SRC / "hidden-id.pdf", b"x", mtime_ns=MTIME, hide_identity=True)
    fs.add_file(OUT / "pdf" / "bad.pdf", b"already here")
    outcome = plan(fs, config())
    assert [op.src.name for op in outcome.plan.operations] == ["good.pdf"]
    assert reasons(outcome) == {
        "bad.pdf": UnplannedReason.DESTINATION_EXISTS,
        "fresh.pdf": UnplannedReason.NOT_SETTLED,
        "hidden-id.pdf": UnplannedReason.IDENTITY_UNAVAILABLE,
    }
    assert [u.src.name for u in outcome.unplanned] == sorted(u.src.name for u in outcome.unplanned)


# ------------------------------------------------------------ rendering


@pytest.mark.parametrize(
    "template, expected",
    [
        pytest.param("/d/out/archive", "/d/out/archive/a.pdf", id="static"),
        pytest.param("/d/out/{modified:%Y}", "/d/out/2026/a.pdf", id="year"),
        pytest.param("/d/out/{modified:%Y-%m}/{ext}", "/d/out/2026-03/pdf/a.pdf", id="year-month-ext"),
        pytest.param("/d/out/{modified:%Y%m%d}", "/d/out/20260305/a.pdf", id="compact"),
        pytest.param("/d/out/by_{ext}_{modified:%Y}", "/d/out/by_pdf_2026/a.pdf", id="mixed"),
    ],
)
def test_templates_render(template, expected):
    cfg = config(rule(destination=template))
    mtime = ns(2026, 3, 5, 10)
    outcome = plan(world("a.pdf", mtime=mtime), cfg, now=mtime + 600 * 10**9)
    assert outcome.plan.operations[0].dst == P(expected)

def test_modified_uses_the_configured_zone():
    cfg = config(rule(destination="/d/out/{modified:%Y}"))
    mtime = ns(2026, 12, 31, 22)
    later = mtime + 600 * 10**9
    fs = world("a.pdf", mtime=mtime)
    in_utc = plan(fs, cfg, now=later, tz=UTC).plan.operations[0].dst
    ahead = plan(fs, cfg, now=later, tz=timezone(timedelta(hours=3, minutes=30))).plan.operations[0].dst
    assert (in_utc.parent.name, ahead.parent.name) == ("2026", "2027")

def test_ext_on_an_extensionless_file_is_invalid():
    cfg = config(rule(extra="name_glob = 'README*'"))
    outcome = plan(world("README"), cfg)
    [item] = outcome.unplanned
    assert item.reason is UnplannedReason.INVALID_DESTINATION and "extension" in item.detail


def test_rendered_component_that_is_a_reserved_name_is_invalid():
    cfg = config(rule(extra="extensions = ['con']"))
    outcome = plan(world("a.con"), cfg)
    assert reasons(outcome) == {"a.con": UnplannedReason.INVALID_DESTINATION}


def test_destination_length_boundary():
    def run(directory_length):
        cfg = config(rule(destination="/d/out/" + "a" * directory_length))
        return plan(world("a.pdf"), cfg)

    assert run(227).plan is not None  # exactly 240 UTF-16 code units
    assert reasons(run(228)) == {"a.pdf": UnplannedReason.INVALID_DESTINATION}


def test_destination_directory_equal_to_the_source_directory_is_invalid():
    cfg = config(rule(source="/d/in/pdf", destination="/d/in/{ext}"))
    fs = world()
    fs.add_file(SRC / "pdf" / "a.pdf", b"x", mtime_ns=MTIME)
    outcome = plan(fs, cfg)
    assert reasons(outcome) == {"a.pdf": UnplannedReason.INVALID_DESTINATION}


# ------------------------------------------------------------ the destination chain


def test_symlink_in_the_destination_chain_is_refused():
    fs = world("a.pdf")
    fs.add_symlink(OUT / "pdf", P("/d/elsewhere"))
    [item] = plan(fs, config()).unplanned
    assert (item.reason, item.detail) == (UnplannedReason.INVALID_DESTINATION, "destination path contains a link")


def test_reparse_point_in_the_destination_chain_is_refused():
    fs = world("a.pdf")
    fs.add_dir(OUT / "pdf", reparse_point=True)
    assert reasons(plan(fs, config())) == {"a.pdf": UnplannedReason.INVALID_DESTINATION}


def test_file_where_a_destination_directory_should_be_is_refused():
    fs = world("a.pdf")
    fs.add_file(OUT / "pdf", b"i am a file")
    [item] = plan(fs, config()).unplanned
    assert item.detail == "destination path component is not a directory"


def test_missing_destination_directories_are_fine():
    outcome = plan(world("a.pdf"), config(rule(destination="/d/out/a/b/c/{ext}")))
    assert outcome.plan.operations[0].dst == OUT / "a" / "b" / "c" / "pdf" / "a.pdf"


def test_missing_root_is_refused():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "a.pdf", b"x", mtime_ns=MTIME)
    [item] = plan(fs, config()).unplanned
    assert item.detail == "destination root is not an existing directory"


# ------------------------------------------------------------ devices and existing paths


def test_destination_on_another_device_is_cross_device():
    fs = MemoryFileSystem()
    fs.add_file(SRC / "a.pdf", b"x", mtime_ns=MTIME)
    fs.add_dir(OUT, dev=7)
    assert reasons(plan(fs, config())) == {"a.pdf": UnplannedReason.CROSS_DEVICE}


def test_a_nested_mount_below_the_root_is_cross_device():
    fs = world("a.pdf")
    fs.add_dir(OUT / "pdf", dev=9)
    assert reasons(plan(fs, config())) == {"a.pdf": UnplannedReason.CROSS_DEVICE}


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_anything_already_at_the_destination_blocks_the_move(kind):
    fs = world("a.pdf")
    if kind == "file":
        fs.add_file(OUT / "pdf" / "a.pdf", b"existing")
    else:
        fs.add_dir(OUT / "pdf" / "a.pdf")
    assert reasons(plan(fs, config())) == {"a.pdf": UnplannedReason.DESTINATION_EXISTS}


# ------------------------------------------------------------ collisions


def collision_world():
    fs = MemoryFileSystem()
    fs.add_dir(OUT)
    fs.add_file(SRC / "a.pdf", b"1", mtime_ns=MTIME)
    fs.add_file(P("/d/in2/A.PDF"), b"2", mtime_ns=MTIME)
    fs.add_file(SRC / "other.pdf", b"3", mtime_ns=MTIME)
    return fs


def test_two_files_with_one_destination_are_both_refused():
    cfg = config(rule(name="r1", source="/d/in"), rule(name="r2", source="/d/in2"))
    outcome = plan(collision_world(), cfg)
    assert [op.src.name for op in outcome.plan.operations] == ["other.pdf"]
    assert reasons(outcome) == {
        "a.pdf": UnplannedReason.DESTINATION_COLLISION,
        "A.PDF": UnplannedReason.DESTINATION_COLLISION,
    }
    details = {u.src.name: u.detail for u in outcome.unplanned}
    assert details["a.pdf"] == "collides with: /d/in2/A.PDF"
    assert details["A.PDF"] == "collides with: /d/in/a.pdf"


# ------------------------------------------------------------ fingerprint stage


def test_unreadable_file_is_reported_and_the_others_still_planned():
    from marshalyard.filesystem import FsError

    fs = world("a.pdf", "b.pdf")

    def fail(f, p):
        raise FsError(p, "boom")

    fs.inject("open_read", fail, path=SRC / "a.pdf")
    outcome = plan(fs, config())
    assert [op.src.name for op in outcome.plan.operations] == ["b.pdf"]
    assert reasons(outcome) == {"a.pdf": UnplannedReason.UNREADABLE}


def test_a_file_changing_during_planning_is_not_planned():
    fs = world("a.pdf")
    fs.inject("read", lambda f, p: f.write(SRC / "a.pdf", b"a much longer body"), path=SRC / "a.pdf")
    outcome = plan(fs, config())
    assert outcome.plan is None
    assert reasons(outcome) == {"a.pdf": UnplannedReason.CHANGED_DURING_PLANNING}


def test_large_files_get_metadata_fingerprints():
    outcome = plan(world("a.pdf"), config(), hash_threshold=2)
    assert outcome.plan.operations[0].fingerprint.method is FpMethod.METADATA


# ------------------------------------------------------------ the cap


def test_exceeding_max_operations_raises():
    cfg = config(settings="max_operations = 2")
    with pytest.raises(PlanTooLarge) as info:
        plan(world("a.pdf", "b.pdf", "c.pdf"), cfg)
    assert (info.value.count, info.value.limit) == (3, 2)


def test_exactly_max_operations_is_allowed():
    cfg = config(settings="max_operations = 2")
    assert len(plan(world("a.pdf", "b.pdf"), cfg).plan.operations) == 2


# ------------------------------------------------------------ safety properties (P5-P7)


def messy_world():
    fs = collision_world()
    fs.add_file(SRC / "linked.pdf", b"l", mtime_ns=MTIME)
    fs.add_hardlink(SRC / "linked.pdf", SRC / "linked2.pdf")
    fs.add_file(SRC / "noid.pdf", b"n", mtime_ns=MTIME, hide_identity=True)
    fs.add_file(OUT / "pdf" / "taken.pdf", b"t")
    fs.add_file(SRC / "taken.pdf", b"t2", mtime_ns=MTIME)
    return fs


def messy_config():
    return config(rule(name="r1", source="/d/in"), rule(name="r2", source="/d/in2"))


def test_p5_no_two_destinations_collide_and_none_exists():
    from marshalyard.canonical import portable_key

    fs = messy_world()
    ops = plan(fs, messy_config()).plan.operations
    keys = [portable_key(op.dst) for op in ops]
    assert len(set(keys)) == len(keys)
    assert all(fs.lstat(op.dst) is None for op in ops)


def test_p6_every_operation_stays_inside_the_roots():
    from marshalyard.canonical import containing_root

    cfg = messy_config()
    for op in plan(messy_world(), cfg).plan.operations:
        assert containing_root(op.src, cfg.roots) is not None
        assert containing_root(op.dst, cfg.roots) is not None


def test_p7_files_without_identity_or_with_extra_links_are_never_planned():
    outcome = plan(messy_world(), messy_config())
    for op in outcome.plan.operations:
        assert op.fingerprint.nlink == 1 and op.fingerprint.dev > 0 and op.fingerprint.ino > 0
    planned = {op.src.name for op in outcome.plan.operations}
    assert planned.isdisjoint({"linked.pdf", "linked2.pdf", "noid.pdf"})


def test_every_entry_lands_in_exactly_one_bucket():
    outcome = plan(messy_world(), messy_config())
    planned = {op.src for op in outcome.plan.operations}
    reported = {u.src for u in outcome.unplanned}
    assert planned.isdisjoint(reported)


# ------------------------------------------------------------ Windows


def test_windows_planning_renders_and_checks_with_windows_semantics():
    text = (
        "version = 1\n[settings]\nroots = ['C:\\in', 'C:\\out']\n"
        "[[rule]]\nname = 'pdfs'\nsource = 'C:\\in'\nextensions = ['pdf']\ndestination = 'C:\\out\\{ext}'\n"
    )
    cfg = parse_config(text, Flavor.WINDOWS, W("C:\\Users\\X")).config
    assert cfg is not None
    fs = MemoryFileSystem(Flavor.WINDOWS)
    fs.add_dir(W(r"C:\out"))
    fs.add_file(W(r"C:\in\Report.PDF"), b"x", mtime_ns=MTIME)
    snapshot = scan(fs, [W(r"C:\in")], exclude=cfg.exclude, taken_at_ns=NOW).snapshot
    outcome = build_plan(fs, cfg, snapshot, NOW, UTC)
    assert outcome.plan.operations[0].dst == W(r"C:\out\pdf\Report.PDF")
