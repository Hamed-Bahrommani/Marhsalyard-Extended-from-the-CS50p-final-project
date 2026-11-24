import itertools

import pytest

from marshalyard.models import (
    FpMethod,
    Observation,
    OperationRecord,
    OpState,
    RecordReason,
    Run,
    RunState,
    TransitionCause,
)
from marshalyard.transitions import LEGAL_TRANSITIONS, classify_recovery, transition

S = OpState
C = TransitionCause
R = RecordReason

PLAN_ID = "a" * 64

EXPECTED_LEGAL = {
    (S.PENDING, S.ATTEMPTING, C.EXECUTION, None),
    (S.ATTEMPTING, S.DONE, C.EXECUTION, None),
    (S.ATTEMPTING, S.FAILED, C.EXECUTION, R.DESTINATION_EXISTS),
    (S.ATTEMPTING, S.FAILED, C.EXECUTION, R.SOURCE_MISSING),
    (S.ATTEMPTING, S.FAILED, C.EXECUTION, R.NOREPLACE_UNSUPPORTED),
    (S.ATTEMPTING, S.FAILED, C.EXECUTION, R.PATH_UNSAFE),
    (S.ATTEMPTING, S.UNRESOLVED, C.EXECUTION, R.UNEXPECTED_ERROR),
    (S.ATTEMPTING, S.UNRESOLVED, C.EXECUTION, R.POST_MOVE_MISMATCH),
    (S.PENDING, S.SKIPPED, C.ABORT, R.RUN_ABORTED),
    (S.PENDING, S.SKIPPED, C.RECOVERY, R.RUN_INTERRUPTED),
    (S.ATTEMPTING, S.SKIPPED, C.RECOVERY, R.NOT_STARTED),
    (S.ATTEMPTING, S.DONE, C.RECOVERY, R.RECOVERED),
    (S.ATTEMPTING, S.DONE, C.RECOVERY, R.RECOVERED_METADATA_ONLY),
    (S.ATTEMPTING, S.UNRESOLVED, C.RECOVERY, R.AMBIGUOUS_OBSERVATION),
}


def rec(state, cause=None, reason=None, attempted=None, finished=None):
    return OperationRecord(1, 1, state, cause, reason, attempted, finished)


FROM_RECORDS = {
    S.PENDING: rec(S.PENDING),
    S.ATTEMPTING: rec(S.ATTEMPTING, C.EXECUTION, None, 10),
    S.DONE: rec(S.DONE, C.EXECUTION, None, 10, 20),
    S.FAILED: rec(S.FAILED, C.EXECUTION, R.DESTINATION_EXISTS, 10, 20),
    S.SKIPPED: rec(S.SKIPPED, C.ABORT, R.RUN_ABORTED, None, 20),
    S.UNRESOLVED: rec(S.UNRESOLVED, C.EXECUTION, R.UNEXPECTED_ERROR, 10, 20),
}


# ------------------------------------------------------------ the table


def test_legal_transitions_match_the_spec_table():
    assert LEGAL_TRANSITIONS == EXPECTED_LEGAL


def test_transition_accepts_exactly_the_legal_tuples():
    accepted = set()
    for new_state, cause, reason in itertools.product(OpState, TransitionCause, [None, *RecordReason]):
        for old_state, record in FROM_RECORDS.items():
            try:
                result = transition(record, new_state, reason, cause, 100)
            except ValueError:
                continue
            accepted.add((old_state, new_state, cause, reason))
            assert result.state is new_state and result.cause is cause
    assert accepted == EXPECTED_LEGAL


def test_attempting_to_skipped_is_rejected_under_execution():
    with pytest.raises(ValueError):
        transition(FROM_RECORDS[S.ATTEMPTING], S.SKIPPED, R.NOT_STARTED, C.EXECUTION, 100)


@pytest.mark.parametrize("state", [S.DONE, S.FAILED, S.SKIPPED, S.UNRESOLVED])
def test_terminal_states_have_no_outgoing_edges(state):
    assert not any(edge[0] is state for edge in LEGAL_TRANSITIONS)


# ------------------------------------------------------------ transition effects


def test_pending_to_attempting_sets_attempted_at():
    result = transition(FROM_RECORDS[S.PENDING], S.ATTEMPTING, None, C.EXECUTION, 50)
    assert (result.attempted_at_ns, result.finished_at_ns, result.reason) == (50, None, None)


def test_attempting_to_done_sets_finished_at_and_keeps_attempted_at():
    result = transition(FROM_RECORDS[S.ATTEMPTING], S.DONE, None, C.EXECUTION, 50)
    assert (result.attempted_at_ns, result.finished_at_ns) == (10, 50)


def test_pending_to_skipped_has_no_attempted_at():
    result = transition(FROM_RECORDS[S.PENDING], S.SKIPPED, R.RUN_ABORTED, C.ABORT, 50)
    assert result.attempted_at_ns is None and result.cause is C.ABORT


def test_recovery_cause_is_stored():
    result = transition(FROM_RECORDS[S.ATTEMPTING], S.DONE, R.RECOVERED, C.RECOVERY, 50)
    assert result.cause is C.RECOVERY and result.reason is R.RECOVERED


def test_transition_does_not_mutate_the_input():
    before = FROM_RECORDS[S.PENDING]
    transition(before, S.ATTEMPTING, None, C.EXECUTION, 50)
    assert before.state is S.PENDING


def test_time_going_backwards_is_rejected():
    with pytest.raises(ValueError):
        transition(FROM_RECORDS[S.ATTEMPTING], S.DONE, None, C.EXECUTION, 5)


# ------------------------------------------------------------ classify_recovery


def test_classification_matrix_is_exhaustive():
    for src, dst, method in itertools.product(Observation, Observation, FpMethod):
        state, reason = classify_recovery(src, dst, method)
        if (src, dst) == (Observation.ABSENT, Observation.MATCHES_PLAN):
            expected = (
                (S.DONE, R.RECOVERED) if method is FpMethod.CONTENT else (S.DONE, R.RECOVERED_METADATA_ONLY)
            )
        elif (src, dst) == (Observation.MATCHES_PLAN, Observation.ABSENT):
            expected = (S.SKIPPED, R.NOT_STARTED)
        else:
            expected = (S.UNRESOLVED, R.AMBIGUOUS_OBSERVATION)
        assert (state, reason) == expected


def test_both_present_and_matching_is_unresolved():
    assert classify_recovery(Observation.MATCHES_PLAN, Observation.MATCHES_PLAN, FpMethod.CONTENT) == (
        S.UNRESOLVED,
        R.AMBIGUOUS_OBSERVATION,
    )


def test_both_absent_is_unresolved():
    assert classify_recovery(Observation.ABSENT, Observation.ABSENT, FpMethod.CONTENT) == (
        S.UNRESOLVED,
        R.AMBIGUOUS_OBSERVATION,
    )


@pytest.mark.parametrize("src, dst, method", [
    pytest.param(Observation.ABSENT, Observation.MATCHES_PLAN, FpMethod.CONTENT, id="content"),
    pytest.param(Observation.ABSENT, Observation.MATCHES_PLAN, FpMethod.METADATA, id="metadata"),
    pytest.param(Observation.MATCHES_PLAN, Observation.ABSENT, FpMethod.CONTENT, id="not-started"),
])
def test_every_classification_result_is_a_legal_recovery_transition(src, dst, method):
    state, reason = classify_recovery(src, dst, method)
    assert (S.ATTEMPTING, state, C.RECOVERY, reason) in LEGAL_TRANSITIONS


# ------------------------------------------------------------ OperationRecord invariants


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: rec(S.PENDING, cause=C.EXECUTION), id="pending-cause"),
        pytest.param(lambda: rec(S.PENDING, reason=R.NOT_STARTED), id="pending-reason"),
        pytest.param(lambda: rec(S.PENDING, attempted=1), id="pending-attempted"),
        pytest.param(lambda: rec(S.PENDING, finished=1), id="pending-finished"),
        pytest.param(lambda: rec(S.ATTEMPTING, C.RECOVERY, None, 1), id="attempting-recovery-cause"),
        pytest.param(lambda: rec(S.ATTEMPTING, C.EXECUTION, None, None), id="attempting-no-time"),
        pytest.param(lambda: rec(S.ATTEMPTING, C.EXECUTION, None, 1, 2), id="attempting-finished"),
        pytest.param(lambda: rec(S.ATTEMPTING, C.EXECUTION, R.NOT_STARTED, 1), id="attempting-reason"),
        pytest.param(lambda: rec(S.DONE, None, None, 1, 2), id="done-no-cause"),
        pytest.param(lambda: rec(S.DONE, C.EXECUTION, None, 1, None), id="done-no-finished"),
        pytest.param(lambda: rec(S.FAILED, C.EXECUTION, None, 1, 2), id="failed-no-reason"),
        pytest.param(lambda: rec(S.SKIPPED, C.ABORT, None, None, 2), id="skipped-no-reason"),
        pytest.param(lambda: rec(S.UNRESOLVED, C.EXECUTION, None, 1, 2), id="unresolved-no-reason"),
        pytest.param(lambda: rec(S.DONE, C.EXECUTION, R.DESTINATION_EXISTS, 1, 2), id="done-bad-reason"),
        pytest.param(lambda: rec(S.DONE, C.EXECUTION, None, 5, 2), id="finished-before-attempted"),
        pytest.param(lambda: OperationRecord(0, 1, S.PENDING, None, None), id="run-id-zero"),
        pytest.param(lambda: OperationRecord(1, 0, S.PENDING, None, None), id="seq-zero"),
        pytest.param(lambda: rec(S.DONE, C.EXECUTION, None, -1, 2), id="negative-time"),
        pytest.param(lambda: rec("pending"), id="state-not-enum"),
    ],
)
def test_invalid_operation_records(build):
    with pytest.raises(ValueError):
        build()


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: rec(S.PENDING), id="pending"),
        pytest.param(lambda: rec(S.ATTEMPTING, C.EXECUTION, None, 1), id="attempting"),
        pytest.param(lambda: rec(S.DONE, C.EXECUTION, None, 1, 2), id="done"),
        pytest.param(lambda: rec(S.DONE, C.RECOVERY, R.RECOVERED, 1, 2), id="done-recovered"),
        pytest.param(lambda: rec(S.DONE, C.RECOVERY, R.RECOVERED_METADATA_ONLY, 1, 2), id="done-metadata"),
        pytest.param(lambda: rec(S.FAILED, C.EXECUTION, R.SOURCE_MISSING, 1, 2), id="failed"),
        pytest.param(lambda: rec(S.SKIPPED, C.ABORT, R.RUN_ABORTED, None, 2), id="skipped-pending"),
        pytest.param(lambda: rec(S.SKIPPED, C.RECOVERY, R.NOT_STARTED, 1, 2), id="skipped-attempted"),
        pytest.param(lambda: rec(S.UNRESOLVED, C.RECOVERY, R.AMBIGUOUS_OBSERVATION, 1, 2), id="unresolved"),
    ],
)
def test_valid_operation_records(build):
    assert build() is not None


def test_done_accepts_only_three_reasons():
    accepted = set()
    for reason in [None, *RecordReason]:
        try:
            rec(S.DONE, C.RECOVERY, reason, 1, 2)
        except ValueError:
            continue
        accepted.add(reason)
    assert accepted == {None, R.RECOVERED, R.RECOVERED_METADATA_ONLY}


# ------------------------------------------------------------ Run invariants


def run(state=RunState.RUNNING, finished=None, recovered=None, abort=None, started=10, plan_id=PLAN_ID):
    return Run(1, plan_id, state, started, finished, recovered, abort)


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: run(), id="running"),
        pytest.param(lambda: run(RunState.FINISHED, finished=20), id="finished"),
        pytest.param(lambda: run(RunState.FINISHED, finished=20, recovered=30), id="recovered"),
        pytest.param(lambda: run(RunState.ABORTED, finished=20, abort="NOREPLACE_UNSUPPORTED"), id="aborted"),
    ],
)
def test_valid_runs(build):
    assert build() is not None


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: run(finished=20), id="running-with-finished"),
        pytest.param(lambda: run(RunState.FINISHED), id="finished-without-time"),
        pytest.param(lambda: run(RunState.ABORTED, finished=20), id="aborted-no-reason"),
        pytest.param(lambda: run(RunState.FINISHED, finished=20, abort="x"), id="finished-with-reason"),
        pytest.param(lambda: run(recovered=30), id="running-recovered"),
        pytest.param(lambda: run(RunState.ABORTED, finished=20, recovered=30, abort="x"), id="aborted-recovered"),
        pytest.param(lambda: run(plan_id="xyz"), id="bad-plan-id"),
        pytest.param(lambda: run(RunState.FINISHED, finished=5), id="finished-before-start"),
    ],
)
def test_invalid_runs(build):
    with pytest.raises(ValueError):
        build()
