"""Operation state transitions and the recovery observation matrix.

Pure: no I/O, no clock. The journal persists what these functions return.
"""

from dataclasses import replace

from marshalyard.models import (
    FpMethod,
    Observation,
    OperationRecord,
    OpState,
    RecordReason,
    TransitionCause,
)

_S = OpState
_C = TransitionCause
_R = RecordReason

# (from, to, cause, reason): spec 3.5 is the single source of truth.
LEGAL_TRANSITIONS: frozenset[tuple[OpState, OpState, TransitionCause, RecordReason | None]] = frozenset(
    {
        (_S.PENDING, _S.ATTEMPTING, _C.EXECUTION, None),
        (_S.ATTEMPTING, _S.DONE, _C.EXECUTION, None),
        (_S.ATTEMPTING, _S.FAILED, _C.EXECUTION, _R.DESTINATION_EXISTS),
        (_S.ATTEMPTING, _S.FAILED, _C.EXECUTION, _R.SOURCE_MISSING),
        (_S.ATTEMPTING, _S.FAILED, _C.EXECUTION, _R.NOREPLACE_UNSUPPORTED),
        (_S.ATTEMPTING, _S.FAILED, _C.EXECUTION, _R.PATH_UNSAFE),
        (_S.ATTEMPTING, _S.UNRESOLVED, _C.EXECUTION, _R.UNEXPECTED_ERROR),
        (_S.ATTEMPTING, _S.UNRESOLVED, _C.EXECUTION, _R.POST_MOVE_MISMATCH),
        (_S.PENDING, _S.SKIPPED, _C.ABORT, _R.RUN_ABORTED),
        (_S.PENDING, _S.SKIPPED, _C.RECOVERY, _R.RUN_INTERRUPTED),
        (_S.ATTEMPTING, _S.SKIPPED, _C.RECOVERY, _R.NOT_STARTED),
        (_S.ATTEMPTING, _S.DONE, _C.RECOVERY, _R.RECOVERED),
        (_S.ATTEMPTING, _S.DONE, _C.RECOVERY, _R.RECOVERED_METADATA_ONLY),
        (_S.ATTEMPTING, _S.UNRESOLVED, _C.RECOVERY, _R.AMBIGUOUS_OBSERVATION),
    }
)


def transition(
    record: OperationRecord,
    new_state: OpState,
    reason: RecordReason | None,
    cause: TransitionCause,
    now_ns: int,
) -> OperationRecord:
    """Return the record after one legal transition, or raise ValueError."""
    if (record.state, new_state, cause, reason) not in LEGAL_TRANSITIONS:
        raise ValueError(
            f"illegal transition: {record.state} -> {new_state} (cause={cause}, reason={reason})"
        )
    if new_state is OpState.ATTEMPTING:
        return replace(record, state=new_state, cause=cause, reason=None, attempted_at_ns=now_ns)
    return replace(record, state=new_state, cause=cause, reason=reason, finished_at_ns=now_ns)


def classify_recovery(
    src: Observation, dst: Observation, method: FpMethod
) -> tuple[OpState, RecordReason]:
    """The recovery observation matrix (spec 11). Anything not listed is UNRESOLVED."""
    if src is Observation.ABSENT and dst is Observation.MATCHES_PLAN:
        reason = _R.RECOVERED if method is FpMethod.CONTENT else _R.RECOVERED_METADATA_ONLY
        return _S.DONE, reason
    if src is Observation.MATCHES_PLAN and dst is Observation.ABSENT:
        return _S.SKIPPED, _R.NOT_STARTED
    return _S.UNRESOLVED, _R.AMBIGUOUS_OBSERVATION
