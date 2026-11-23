import dataclasses

import pytest

from marshalyard.models import (
    HASH_THRESHOLD,
    UNDO_RULE,
    DirIdentity,
    Fingerprint,
    FpMethod,
    OpState,
    Observation,
    PlanKind,
    RecordReason,
    RunState,
    SkipReason,
    TransitionCause,
    UnplannedReason,
    Flavor,
)

GOOD_SHA = "a" * 64


def make(**overrides):
    base = dict(
        dev=1, ino=2, nlink=1, size=10, mtime_ns=123,
        sha256=GOOD_SHA, method=FpMethod.CONTENT,
    )
    base.update(overrides)
    return Fingerprint(**base)




def test_valid_content_fingerprint():
    fp = make()
    assert fp.verifies_content is True


def test_valid_metadata_fingerprint():
    fp = make(sha256=None, method=FpMethod.METADATA)
    assert fp.verifies_content is False


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"dev": 0}, id="dev-zero"),
        pytest.param({"ino": 0}, id="ino-zero"),
        pytest.param({"nlink": 0}, id="nlink-zero"),
        pytest.param({"size": -1}, id="size-negative"),
        pytest.param({"sha256": None}, id="content-without-hash"),
        pytest.param({"method": FpMethod.METADATA}, id="metadata-with-hash"),
        pytest.param({"sha256": "A" * 64}, id="hash-uppercase"),
        pytest.param({"sha256": "a" * 63}, id="hash-too-short"),
        pytest.param({"dev": True}, id="dev-bool"),
        pytest.param({"ino": "1"}, id="ino-string"),
    ],
)
def test_invalid_fingerprints_are_rejected(overrides):
    with pytest.raises(ValueError):
        make(**overrides)


def test_fingerprint_is_frozen():
    fp = make()
    with pytest.raises(dataclasses.FrozenInstanceError):
        fp.size = 99


def test_verifies_content_follows_method():
    assert make().verifies_content is True
    assert make(sha256=None, method=FpMethod.METADATA).verifies_content is False


def test_matches_identical():
    assert make().matches(make())


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"dev": 9}, id="dev"),
        pytest.param({"ino": 9}, id="ino"),
        pytest.param({"nlink": 2}, id="nlink"),
        pytest.param({"size": 11}, id="size"),
        pytest.param({"mtime_ns": 124}, id="mtime"),
    ],
)
def test_matches_false_when_a_field_differs(overrides):
    assert not make().matches(make(**overrides))


def test_matches_false_when_hash_differs():
    assert not make().matches(make(sha256="b" * 64))


def test_matches_false_when_method_differs():
    assert not make().matches(make(sha256=None, method=FpMethod.METADATA))




def test_valid_dir_identity():
    assert DirIdentity(dev=1, ino=2).ino == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"dev": 0, "ino": 1}, id="dev-zero"),
        pytest.param({"dev": 1, "ino": 0}, id="ino-zero"),
        pytest.param({"dev": True, "ino": 1}, id="dev-bool"),
    ],
)
def test_invalid_dir_identity_is_rejected(kwargs):
    with pytest.raises(ValueError):
        DirIdentity(**kwargs)



def test_state_enums_use_lowercase_values():
    assert OpState.PENDING == "pending"
    assert RunState.RUNNING == "running"
    assert PlanKind.UNDO == "undo"
    assert TransitionCause.RECOVERY == "recovery"
    assert FpMethod.CONTENT == "content"
    assert Flavor.WINDOWS == "windows"


def test_code_enums_use_uppercase_values():
    assert UnplannedReason.RULE_CONFLICT == "RULE_CONFLICT"
    assert RecordReason.POST_MOVE_MISMATCH == "POST_MOVE_MISMATCH"
    assert SkipReason.RUNTIME_FILE == "RUNTIME_FILE"
    assert Observation.ROOT_CHANGED == "ROOT_CHANGED"


def test_constants():
    assert HASH_THRESHOLD == 64 * 1024 * 1024
    assert UNDO_RULE == "(undo)"