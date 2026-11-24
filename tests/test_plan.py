from pathlib import PurePosixPath as P
from pathlib import PureWindowsPath as W

import pytest

from marshalyard.canonical import compute_plan_id
from marshalyard.models import (
    UNDO_RULE,
    Fingerprint,
    FpMethod,
    Plan,
    PlanKind,
    PlannedOperation,
    Unplanned,
    UnplannedReason,
)

H = "b" * 64


def fp(**overrides):
    values = dict(dev=1, ino=2, nlink=1, size=3, mtime_ns=4, sha256="a" * 64, method=FpMethod.CONTENT)
    values.update(overrides)
    return Fingerprint(**values)


def op(seq=1, src="/d/in/a.pdf", dst="/d/out/pdf/a.pdf", rule="r", cls=P, **fp_overrides):
    return PlannedOperation(seq, cls(src), cls(dst), rule, fp(**fp_overrides))


def unp(src="/d/in/b.pdf", reason=UnplannedReason.NOT_SETTLED, detail="min_age=600s", cls=P):
    return Unplanned(cls(src), reason, detail)


def make(kind=PlanKind.ORGANIZE, config_hash=H, derived=None, ops=None, unplanned=(), created=1, plan_id=None):
    operations = tuple(ops) if ops is not None else (op(),)
    unplanned = tuple(unplanned)
    pid = plan_id or compute_plan_id(
        kind=kind,
        config_hash=config_hash,
        derived_from_run=derived,
        operations=operations,
        unplanned=unplanned,
    )
    return Plan(pid, kind, config_hash, created, derived, operations, unplanned)


def make_undo(ops=None, **kw):
    ops = ops if ops is not None else (op(rule=UNDO_RULE),)
    return make(kind=PlanKind.UNDO, config_hash=None, derived=1, ops=ops, **kw)


# ------------------------------------------------------------ valid plans and identity


def test_valid_organize_plan():
    plan = make(unplanned=[unp()])
    assert plan.kind is PlanKind.ORGANIZE
    assert len(plan.plan_id) == 64


def test_valid_undo_plan():
    plan = make_undo()
    assert plan.config_hash is None and plan.derived_from_run == 1


def test_created_at_is_not_part_of_the_id():
    assert make(created=1).plan_id == make(created=999).plan_id


def test_unplanned_report_is_part_of_the_id():
    assert make(unplanned=[]).plan_id != make(unplanned=[unp()]).plan_id


def test_config_hash_is_part_of_the_id():
    assert make(config_hash="b" * 64).plan_id != make(config_hash="c" * 64).plan_id


def test_unplanned_order_does_not_change_the_id():
    first = unp("/d/in/b.pdf")
    second = unp("/d/in/c.pdf")
    assert make(unplanned=[first, second]).plan_id == make(unplanned=[second, first]).plan_id


def test_destination_spelling_is_preserved():
    plan = make(ops=[op(dst="/d/out/Stra\u00dfe.pdf")])
    assert plan.operations[0].dst == P("/d/out/Stra\u00dfe.pdf")


def test_golden_plan_id_posix():
    plan_id = compute_plan_id(
        kind=PlanKind.ORGANIZE,
        config_hash=H,
        derived_from_run=None,
        operations=(op(),),
        unplanned=(unp(),),
    )
    assert plan_id == "f4f448b892fc3e80e10ee85b89504c7dd2f074b7ff8cf983fdba48b662ad5bf4"


def test_golden_plan_id_windows():
    plan_id = compute_plan_id(
        kind=PlanKind.ORGANIZE,
        config_hash=H,
        derived_from_run=None,
        operations=(op(src=r"C:\d\in\a.pdf", dst=r"C:\d\out\pdf\a.pdf", cls=W),),
        unplanned=(unp(src=r"C:\d\in\b.pdf", cls=W),),
    )
    assert plan_id == "cf1be41bf1936998d274bb8dd65395dd8e4c1478e3262ef9818bf9ebdbcb6054"


# ------------------------------------------------------------ invalid plans


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: make(plan_id="0" * 64), id="wrong-id"),
        pytest.param(lambda: make(ops=[]), id="empty-ops"),
        pytest.param(lambda: make(ops=[op(1), op(3, src="/d/in/c.pdf", dst="/d/out/c.pdf")]), id="seq-gap"),
        pytest.param(lambda: make(ops=[op(2)]), id="seq-starts-at-2"),
        pytest.param(lambda: make(ops=[op(1), op(2, dst="/d/out/other.pdf")]), id="duplicate-source"),
        pytest.param(
            lambda: make(ops=[op(1, dst="/d/out/A.pdf"), op(2, src="/d/in/c.pdf", dst="/d/out/a.pdf")]),
            id="dst-collision",
        ),
        pytest.param(lambda: make(kind=PlanKind.UNDO, config_hash=H, derived=1, ops=[op(rule=UNDO_RULE)]), id="undo-with-hash"),
        pytest.param(lambda: make(kind=PlanKind.UNDO, config_hash=None, derived=None, ops=[op(rule=UNDO_RULE)]), id="undo-no-run"),
        pytest.param(lambda: make(derived=1), id="organize-with-run"),
        pytest.param(lambda: make(config_hash=None), id="organize-no-hash"),
        pytest.param(lambda: make_undo(ops=[op(rule="r")]), id="undo-ordinary-rule"),
        pytest.param(lambda: make(ops=[op(rule=UNDO_RULE)]), id="organize-undo-rule"),
        pytest.param(
            lambda: make(ops=[op(1), op(2, src=r"C:\d\in\c.pdf", dst=r"C:\d\out\c.pdf", cls=W)]),
            id="mixed-flavors",
        ),
        pytest.param(lambda: make(ops=[op(src="rel/a.pdf")]), id="relative-src"),
        pytest.param(lambda: make(ops=[op(dst="/d/in/a.pdf")]), id="dst-equals-src"),
        pytest.param(lambda: make(ops=[op(nlink=2)]), id="nlink-2"),
        pytest.param(
            lambda: make(unplanned=[unp(), unp(reason=UnplannedReason.UNREADABLE)]),
            id="unplanned-duplicate",
        ),
        pytest.param(lambda: make(unplanned=[unp(src="/d/in/a.pdf")]), id="unplanned-overlaps-op"),
        pytest.param(lambda: make(unplanned=[unp(src=r"C:\d\in\b.pdf", cls=W)]), id="unplanned-mixed-flavor"),
        pytest.param(lambda: make(created=-1), id="negative-created"),
        pytest.param(lambda: make(config_hash="xyz"), id="bad-config-hash"),
    ],
)
def test_invalid_plans_are_rejected(build):
    with pytest.raises(ValueError):
        build()


# ------------------------------------------------------------ component invariants


def test_operation_seq_must_be_positive():
    with pytest.raises(ValueError):
        op(seq=0)


def test_operation_rule_name_must_be_non_empty():
    with pytest.raises(ValueError):
        op(rule="")


def test_unplanned_source_must_be_absolute():
    with pytest.raises(ValueError):
        Unplanned(P("rel/b.pdf"), UnplannedReason.NOT_SETTLED)


def test_unplanned_reason_must_be_an_enum():
    with pytest.raises(ValueError):
        Unplanned(P("/d/in/b.pdf"), "NOT_SETTLED")
