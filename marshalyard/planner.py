"""Planner: match, fingerprint, render destinations, check them, assemble a Plan.

Pure given its inputs: the FileSystem port (read-only calls), the config, the
snapshot, an injected `now_ns` and an injected time zone. It never mutates anything.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo

from marshalyard.canonical import compute_plan_id, containing_root, portable_key
from marshalyard.config import FieldError, check_portable_component, file_extension, glob_matches
from marshalyard.filesystem import FileKind, FileSystem, FsError
from marshalyard.fingerprinting import FingerprintFailure, fingerprint, to_unplanned
from marshalyard.models import (
    HASH_THRESHOLD,
    AbsPath,
    Config,
    DestinationTemplate,
    ExtToken,
    FileEntry,
    Fingerprint,
    Plan,
    PlanKind,
    PlannedOperation,
    Rule,
    Snapshot,
    TextToken,
    Unplanned,
    UnplannedReason,
)

_NS_PER_S = 1_000_000_000
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_DESTINATION_UTF16 = 240
_DIRECTIVE_RE = re.compile(r"%[Ymd]")


@dataclass(frozen=True, slots=True)
class Candidate:
    entry: FileEntry
    rule: Rule


@dataclass(frozen=True, slots=True)
class MatchOutcome:
    candidates: tuple[Candidate, ...]
    unplanned: tuple[Unplanned, ...]


@dataclass(frozen=True, slots=True)
class PlanOutcome:
    plan: Plan | None  # None when there is nothing to do
    unplanned: tuple[Unplanned, ...]


class PlanTooLarge(Exception):
    def __init__(self, count: int, limit: int) -> None:
        super().__init__(f"plan has {count} operations; max_operations is {limit}")
        self.count = count
        self.limit = limit


class _Invalid(Exception):
    """A destination problem, carrying its deterministic detail."""


# ---------------------------------------------------------------- steps 3-7: scope, match, age, identity


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

    unplanned.sort(key=_unplanned_key)
    return MatchOutcome(tuple(candidates), tuple(unplanned))


def _unplanned_key(item: Unplanned) -> tuple[str, str]:
    return (item.src.as_posix(), item.reason.value)


# ---------------------------------------------------------------- step 9: destinations


def _format_modified(fmt: str, mtime_ns: int, tz: tzinfo | None) -> str:
    seconds = mtime_ns // _NS_PER_S
    try:
        if tz is None:
            moment = datetime.fromtimestamp(seconds)  # the machine's own zone rules
        else:
            moment = (_EPOCH + timedelta(seconds=seconds)).astimezone(tz)
    except (OverflowError, OSError, ValueError):
        raise _Invalid("modification time is out of range") from None

    def expand(match: re.Match) -> str:
        directive = match.group(0)
        if directive == "%Y":
            return f"{moment.year:04d}"
        if directive == "%m":
            return f"{moment.month:02d}"
        return f"{moment.day:02d}"

    return _DIRECTIVE_RE.sub(expand, fmt)


def _render_dir(template: DestinationTemplate, entry: FileEntry, tz: tzinfo | None) -> AbsPath:
    parts: list[str] = []
    for tokens in template.components:
        pieces: list[str] = []
        for token in tokens:
            if isinstance(token, TextToken):
                pieces.append(token.text)
            elif isinstance(token, ExtToken):
                extension = file_extension(entry.path.name)
                if extension is None:
                    raise _Invalid("{ext} is used on a file without an extension")
                pieces.append(extension)
            else:
                pieces.append(_format_modified(token.fmt, entry.mtime_ns, tz))
        component = "".join(pieces)
        try:
            check_portable_component(component)
        except FieldError:
            raise _Invalid(f"rendered component {component!r} is not a valid name") from None
        parts.append(component)
    return template.base.joinpath(*parts)


def _inspect_chain(fs: FileSystem, config: Config, directory: AbsPath) -> int:
    """Walk the destination directory below its containing root; return the device
    of the deepest directory that already exists. Links are refused (spec 7.5 D3)."""
    root = containing_root(directory, config.roots)
    if root is None:
        raise _Invalid("destination is outside every root")
    try:
        info = fs.lstat(fs.realpath(root))
    except FsError:
        raise _Invalid("destination path cannot be inspected") from None
    if info is None or info.kind is not FileKind.DIRECTORY:
        raise _Invalid("destination root is not an existing directory")
    device = info.dev
    current = root
    for part in directory.parts[len(root.parts) :]:
        current = current / part
        try:
            info = fs.lstat(current)
        except FsError:
            raise _Invalid("destination path cannot be inspected") from None
        if info is None:
            break
        if info.kind is FileKind.SYMLINK or info.reparse_point:
            raise _Invalid("destination path contains a link")
        if info.kind is not FileKind.DIRECTORY:
            raise _Invalid("destination path component is not a directory")
        device = info.dev
    return device


def _utf16_units(path: AbsPath) -> int:
    return len(str(path).encode("utf-16-le")) // 2


def _plan_destination(
    fs: FileSystem, config: Config, candidate: Candidate, tz: tzinfo | None
) -> AbsPath | Unplanned:
    entry, rule = candidate.entry, candidate.rule
    try:
        directory = _render_dir(rule.destination, entry, tz)
        dst = directory / entry.path.name
        if directory == entry.path.parent:
            raise _Invalid("destination directory is the source directory")
        if containing_root(dst, config.roots) is None:
            raise _Invalid("destination is outside every root")
        if _utf16_units(dst) > MAX_DESTINATION_UTF16:
            raise _Invalid(f"destination is longer than {MAX_DESTINATION_UTF16} UTF-16 code units")
        device = _inspect_chain(fs, config, directory)
    except _Invalid as problem:
        return Unplanned(entry.path, UnplannedReason.INVALID_DESTINATION, str(problem))

    if device != entry.dev:
        return Unplanned(entry.path, UnplannedReason.CROSS_DEVICE, "source and destination are on different devices")
    try:
        existing = fs.lstat(dst)
    except FsError:
        return Unplanned(entry.path, UnplannedReason.INVALID_DESTINATION, "destination path cannot be inspected")
    if existing is not None:
        return Unplanned(entry.path, UnplannedReason.DESTINATION_EXISTS, "")
    return dst


# ---------------------------------------------------------------- the pipeline


def build_plan(
    fs: FileSystem,
    config: Config,
    snapshot: Snapshot,
    now_ns: int,
    tz: tzinfo | None = None,
    hash_threshold: int = HASH_THRESHOLD,
) -> PlanOutcome:
    """scan (done by the caller) -> match -> fingerprint -> destinations -> collisions -> Plan."""
    matched = match_entries(config, snapshot, now_ns)
    unplanned: list[Unplanned] = list(matched.unplanned)

    survivors: list[tuple[Candidate, Fingerprint, AbsPath]] = []
    for candidate in matched.candidates:
        result = fingerprint(fs, candidate.entry, hash_threshold)
        if isinstance(result, FingerprintFailure):
            unplanned.append(to_unplanned(candidate.entry, result))
            continue
        destination = _plan_destination(fs, config, candidate, tz)
        if isinstance(destination, Unplanned):
            unplanned.append(destination)
            continue
        survivors.append((candidate, result, destination))

    groups: dict[str, list[tuple[Candidate, Fingerprint, AbsPath]]] = {}
    for item in survivors:
        groups.setdefault(portable_key(item[2]), []).append(item)
    kept: list[tuple[Candidate, Fingerprint, AbsPath]] = []
    for members in groups.values():
        if len(members) == 1:
            kept.append(members[0])
            continue
        for member in members:
            others = sorted(o[0].entry.path.as_posix() for o in members if o is not member)
            unplanned.append(
                Unplanned(member[0].entry.path, UnplannedReason.DESTINATION_COLLISION, "collides with: " + ", ".join(others))
            )

    unplanned.sort(key=_unplanned_key)
    if not kept:
        return PlanOutcome(None, tuple(unplanned))
    if len(kept) > config.max_operations:
        raise PlanTooLarge(len(kept), config.max_operations)

    kept.sort(key=lambda item: item[0].entry.path.as_posix())
    operations = tuple(
        PlannedOperation(seq, item[0].entry.path, item[2], item[0].rule.name, item[1])
        for seq, item in enumerate(kept, start=1)
    )
    unplanned_tuple = tuple(unplanned)
    plan_id = compute_plan_id(
        kind=PlanKind.ORGANIZE,
        config_hash=config.config_hash,
        derived_from_run=None,
        operations=operations,
        unplanned=unplanned_tuple,
    )
    plan = Plan(plan_id, PlanKind.ORGANIZE, config.config_hash, now_ns, None, operations, unplanned_tuple)
    return PlanOutcome(plan, unplanned_tuple)
