"""Planner. This part: scope, match, conflict, age, identity and link-count checks.

Pure: no filesystem access, no clock. `now_ns` is injected.
"""

from dataclasses import dataclass

from marshalyard.config import file_extension, glob_matches
from marshalyard.models import (
    AbsPath,
    Config,
    FileEntry,
    Rule,
    Snapshot,
    Unplanned,
    UnplannedReason,
)

_NS_PER_S = 1_000_000_000


@dataclass(frozen=True, slots=True)
class Candidate:
    entry: FileEntry
    rule: Rule


@dataclass(frozen=True, slots=True)
class MatchOutcome:
    candidates: tuple[Candidate, ...]
    unplanned: tuple[Unplanned, ...]


def _matches(rule: Rule, name: str) -> bool:
    if rule.extensions:
        extension = file_extension(name)
        if extension is None or extension not in rule.extensions:
            return False
    if rule.name_glob is not None and not glob_matches(rule.name_glob, name):
        return False
    return True


def _refusal(entry: FileEntry, rule: Rule, now_ns: int) -> tuple[UnplannedReason, str] | None:
    """Steps 5-7 of the pipeline, in order. Returns the first refusal, if any."""
    if now_ns - entry.mtime_ns < rule.min_age_s * _NS_PER_S:  # also true for a future mtime
        return UnplannedReason.NOT_SETTLED, f"min_age={rule.min_age_s}s"
    if entry.dev == 0 or entry.ino == 0:
        return UnplannedReason.IDENTITY_UNAVAILABLE, ""
    if entry.nlink <= 0:
        return UnplannedReason.LINK_COUNT_UNAVAILABLE, ""
    if entry.nlink > 1:
        return UnplannedReason.MULTIPLE_LINKS, f"nlink={entry.nlink}"
    return None


def match_entries(config: Config, snapshot: Snapshot, now_ns: int) -> MatchOutcome:
    if snapshot.entries and type(snapshot.entries[0].path) is not type(config.roots[0]):
        raise ValueError("config and snapshot use different path flavors")

    by_source: dict[AbsPath, list[Rule]] = {}
    for rule in config.rules:
        by_source.setdefault(rule.source, []).append(rule)

    candidates: list[Candidate] = []
    unplanned: list[Unplanned] = []
    for entry in snapshot.entries:
        in_scope = by_source.get(entry.path.parent)
        if not in_scope:
            continue
        matched = [rule for rule in in_scope if _matches(rule, entry.path.name)]
        if not matched:
            continue
        if len(matched) > 1:
            names = ", ".join(sorted(rule.name for rule in matched))
            unplanned.append(Unplanned(entry.path, UnplannedReason.RULE_CONFLICT, f"matches rules: {names}"))
            continue
        rule = matched[0]
        refusal = _refusal(entry, rule, now_ns)
        if refusal is None:
            candidates.append(Candidate(entry, rule))
        else:
            unplanned.append(Unplanned(entry.path, refusal[0], refusal[1]))

    unplanned.sort(key=lambda item: (item.src.as_posix(), item.reason.value))
    return MatchOutcome(tuple(candidates), tuple(unplanned))
