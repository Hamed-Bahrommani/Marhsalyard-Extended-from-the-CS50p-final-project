import re
from dataclasses import dataclass
from enum import StrEnum, auto
from pathlib import PurePosixPath, PureWindowsPath

MODIFIED_FORMAT_RE = re.compile(r"(?:%[Ymd]|[-_])+")

AbsPath = PurePosixPath | PureWindowsPath

HASH_THRESHOLD = 64 * 1024 * 1024  # bytes; size <= threshold => CONTENT fingerprint
UNDO_RULE = "(undo)"

_SHA256_RE = re.compile(r"[0-9a-f]{64}")

class _CodeEnum(StrEnum):
    """StrEnum whose auto() value is the member name unchanged (UPPERCASE)."""

    @staticmethod
    def _generate_next_value_(name, start, count, last_values):
        return name


class Flavor(StrEnum):
    POSIX = auto()
    WINDOWS = auto()


class Timezone(StrEnum):
    LOCAL = auto()
    UTC = auto()


class Severity(StrEnum):
    ERROR = auto()
    WARNING = auto()


class FpMethod(StrEnum):
    CONTENT = auto()
    METADATA = auto()


class PlanKind(StrEnum):
    ORGANIZE = auto()
    UNDO = auto()


class RunState(StrEnum):
    RUNNING = auto()
    FINISHED = auto()
    ABORTED = auto()


class OpState(StrEnum):
    PENDING = auto()
    ATTEMPTING = auto()
    DONE = auto()
    FAILED = auto()
    SKIPPED = auto()
    UNRESOLVED = auto()


class TransitionCause(StrEnum):
    EXECUTION = auto()
    RECOVERY = auto()
    ABORT = auto()


class SkipReason(_CodeEnum):
    EXCLUDED = auto()
    SYMLINK = auto()
    REPARSE_POINT = auto()
    NOT_REGULAR = auto()
    HIDDEN_OR_SYSTEM = auto()
    RUNTIME_FILE = auto()


class Observation(_CodeEnum):
    ABSENT = auto()
    MATCHES_PLAN = auto()
    DIFFERENT = auto()
    NOT_REGULAR = auto()
    UNREADABLE = auto()
    ROOT_CHANGED = auto()


class UnplannedReason(_CodeEnum):
    RULE_CONFLICT = auto()
    NOT_SETTLED = auto()
    IDENTITY_UNAVAILABLE = auto()
    LINK_COUNT_UNAVAILABLE = auto()
    MULTIPLE_LINKS = auto()
    UNREADABLE = auto()
    CHANGED_DURING_PLANNING = auto()
    CROSS_DEVICE = auto()
    INVALID_DESTINATION = auto()
    DESTINATION_EXISTS = auto()
    DESTINATION_COLLISION = auto()
    # undo plans only
    MODIFIED = auto()
    MISSING = auto()
    ORIGINAL_PATH_OCCUPIED = auto()
    ROOT_CHANGED = auto()


class RecordReason(_CodeEnum):
    NOT_STARTED = auto()
    RECOVERED = auto()
    RECOVERED_METADATA_ONLY = auto()
    RUN_INTERRUPTED = auto()
    RUN_ABORTED = auto()
    DESTINATION_EXISTS = auto()
    SOURCE_MISSING = auto()
    NOREPLACE_UNSUPPORTED = auto()
    PATH_UNSAFE = auto()
    UNEXPECTED_ERROR = auto()
    POST_MOVE_MISMATCH = auto()
    AMBIGUOUS_OBSERVATION = auto()



def _is_int(value) -> bool:
    """True for real ints. bool is an int subclass in Python, so exclude it."""
    return isinstance(value, int) and not isinstance(value, bool)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True, slots=True)
class DirIdentity:
    """Identity of a directory: (st_dev, st_ino). Zero means 'unavailable'."""

    dev: int
    ino: int

    def __post_init__(self) -> None:
        _require(_is_int(self.dev) and self.dev >= 1, "DirIdentity.dev must be a positive int")
        _require(_is_int(self.ino) and self.ino >= 1, "DirIdentity.ino must be a positive int")


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """Verified state of a plannable file at one moment.

    A Fingerprint cannot be built for a file whose identity or link count is
    unavailable. The 64 MiB threshold policy lives in the fingerprinting
    function (M3), not here.
    """

    dev: int
    ino: int
    nlink: int
    size: int
    mtime_ns: int
    sha256: str | None
    method: FpMethod

    def __post_init__(self) -> None:
        for name in ("dev", "ino", "nlink", "size", "mtime_ns"):
            _require(_is_int(getattr(self, name)), f"Fingerprint.{name} must be an int")
        _require(self.dev >= 1, "Fingerprint.dev must be positive (identity available)")
        _require(self.ino >= 1, "Fingerprint.ino must be positive (identity available)")
        _require(self.nlink >= 1, "Fingerprint.nlink must be >= 1 (link count available)")
        _require(self.size >= 0, "Fingerprint.size must be >= 0")
        _require(isinstance(self.method, FpMethod), "Fingerprint.method must be an FpMethod")
        if self.sha256 is not None:
            _require(
                isinstance(self.sha256, str) and _SHA256_RE.fullmatch(self.sha256) is not None,
                "Fingerprint.sha256 must be 64 lowercase hex characters",
            )
        _require(
            (self.method is FpMethod.CONTENT) == (self.sha256 is not None),
            "Fingerprint: a hash is present if and only if method is CONTENT",
        )

    @property
    def verifies_content(self) -> bool:
        """True only for content fingerprints (SHA-256 recomputable)."""
        return self.method is FpMethod.CONTENT

    def matches(self, other: "Fingerprint") -> bool:
        """The single definition of 'unchanged' (spec section 7.1)."""
        return (
            self.dev == other.dev
            and self.ino == other.ino
            and self.nlink == other.nlink
            and self.size == other.size
            and self.mtime_ns == other.mtime_ns
            and self.method is other.method
            and self.sha256 == other.sha256
        )


# ---------------------------------------------------------------- template tokens


@dataclass(frozen=True, slots=True)
class TextToken:
    text: str

    def __post_init__(self) -> None:
        _require(isinstance(self.text, str) and self.text != "", "TextToken.text must be a non-empty string")


@dataclass(frozen=True, slots=True)
class ExtToken:
    """Placeholder {ext}: the file's lowercase extension."""


@dataclass(frozen=True, slots=True)
class ModifiedToken:
    """Placeholder {modified:FMT}; FMT uses only %Y %m %d and '-' '_'."""

    fmt: str

    def __post_init__(self) -> None:
        _require(
            isinstance(self.fmt, str) and MODIFIED_FORMAT_RE.fullmatch(self.fmt) is not None,
            "ModifiedToken.fmt may contain only %Y, %m, %d, '-' and '_'",
        )


Token = TextToken | ExtToken | ModifiedToken


@dataclass(frozen=True, slots=True)
class DestinationTemplate:
    """A destination directory template.

    `base` is every leading placeholder-free component (it must later be inside
    a root). `components` is the variable part; () means fully static.
    """

    raw: str
    base: AbsPath
    components: tuple[tuple[Token, ...], ...]

    def __post_init__(self) -> None:
        _require(self.base.is_absolute(), "DestinationTemplate.base must be absolute")
        for component in self.components:
            _require(
                len(component) >= 1 and all(isinstance(t, (TextToken, ExtToken, ModifiedToken)) for t in component),
                "every template component needs at least one valid token",
            )
        if self.components:
            _require(
                any(not isinstance(t, TextToken) for t in self.components[0]),
                "the first variable component must contain a placeholder",
            )


# ---------------------------------------------------------------- validation output


@dataclass(frozen=True, slots=True)
class Issue:
    code: str
    location: str
    message: str
    severity: Severity
    line: int | None = None  # TOML_SYNTAX only, best-effort
    column: int | None = None

    def __post_init__(self) -> None:
        _require(isinstance(self.code, str) and self.code != "", "Issue.code must be a non-empty string")
        _require(isinstance(self.location, str) and self.location != "", "Issue.location must be a non-empty string")
        _require(isinstance(self.message, str) and self.message != "", "Issue.message must be a non-empty string")
        _require(isinstance(self.severity, Severity), "Issue.severity must be a Severity")
        for value in (self.line, self.column):
            _require(value is None or (_is_int(value) and value >= 1), "Issue.line/column must be None or >= 1")



# ---------------------------------------------------------------- rules and config


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    source: AbsPath
    extensions: tuple[str, ...]
    name_glob: str | None
    min_age_s: int
    destination: DestinationTemplate

    def __post_init__(self) -> None:
        _require(isinstance(self.name, str) and self.name != "", "Rule.name must be a non-empty string")
        _require(
            isinstance(self.source, (PurePosixPath, PureWindowsPath)) and self.source.is_absolute(),
            "Rule.source must be an absolute path",
        )
        _require(isinstance(self.extensions, tuple), "Rule.extensions must be a tuple")
        _require(self.name_glob is None or isinstance(self.name_glob, str), "Rule.name_glob must be a string or None")
        _require(_is_int(self.min_age_s) and self.min_age_s >= 0, "Rule.min_age_s must be an int >= 0")
        _require(isinstance(self.destination, DestinationTemplate), "Rule.destination must be a DestinationTemplate")


@dataclass(frozen=True, slots=True)
class Config:
    version: int
    flavor: Flavor
    roots: tuple[AbsPath, ...]
    timezone: Timezone
    default_min_age_s: int
    max_operations: int
    exclude: tuple[str, ...]
    rules: tuple[Rule, ...]
    config_hash: str

    def __post_init__(self) -> None:
        _require(self.version == 1, "Config.version must be 1")
        _require(isinstance(self.flavor, Flavor), "Config.flavor must be a Flavor")
        _require(isinstance(self.timezone, Timezone), "Config.timezone must be a Timezone")
        _require(len(self.roots) >= 1, "Config needs at least one root")
        _require(len(self.rules) >= 1, "Config needs at least one rule")
        _require(_is_int(self.default_min_age_s) and self.default_min_age_s >= 0, "Config.default_min_age_s must be >= 0")
        _require(_is_int(self.max_operations) and 1 <= self.max_operations <= 100000, "Config.max_operations out of range")
        _require(
            isinstance(self.config_hash, str) and _SHA256_RE.fullmatch(self.config_hash) is not None,
            "Config.config_hash must be 64 lowercase hex characters",
        )
        from marshalyard.canonical import compute_config_hash  # lazy: canonical imports models

        expected = compute_config_hash(
            version=self.version,
            flavor=self.flavor,
            roots=self.roots,
            timezone=self.timezone,
            default_min_age_s=self.default_min_age_s,
            max_operations=self.max_operations,
            exclude=self.exclude,
            rules=self.rules,
        )
        _require(self.config_hash == expected, "Config.config_hash does not match its content")


@dataclass(frozen=True, slots=True)
class ValidationResult:
    config: Config | None
    issues: tuple[Issue, ...]

    def __post_init__(self) -> None:
        has_error = any(issue.severity is Severity.ERROR for issue in self.issues)
        _require((self.config is None) == has_error, "ValidationResult.config is None iff there is an error")


# ---------------------------------------------------------------- plans


def _paths_share_flavor(paths) -> bool:
    classes = {type(path) for path in paths}
    return len(classes) == 1 and next(iter(classes)) in (PurePosixPath, PureWindowsPath)


@dataclass(frozen=True, slots=True)
class PlannedOperation:
    seq: int
    src: AbsPath
    dst: AbsPath
    rule_name: str
    fingerprint: Fingerprint

    def __post_init__(self) -> None:
        _require(_is_int(self.seq) and self.seq >= 1, "PlannedOperation.seq must be an int >= 1")
        _require(_paths_share_flavor((self.src, self.dst)), "PlannedOperation paths must be of one pure-path class")
        _require(self.src.is_absolute() and self.dst.is_absolute(), "PlannedOperation paths must be absolute")
        _require(self.dst != self.src, "PlannedOperation.dst must differ from src")
        _require(isinstance(self.rule_name, str) and self.rule_name != "", "PlannedOperation.rule_name must be non-empty")
        _require(isinstance(self.fingerprint, Fingerprint), "PlannedOperation.fingerprint must be a Fingerprint")
        _require(self.fingerprint.nlink == 1, "PlannedOperation.fingerprint.nlink must be 1")


@dataclass(frozen=True, slots=True)
class Unplanned:
    src: AbsPath
    reason: UnplannedReason
    detail: str = ""

    def __post_init__(self) -> None:
        _require(
            isinstance(self.src, (PurePosixPath, PureWindowsPath)) and self.src.is_absolute(),
            "Unplanned.src must be an absolute path",
        )
        _require(isinstance(self.reason, UnplannedReason), "Unplanned.reason must be an UnplannedReason")
        _require(isinstance(self.detail, str), "Unplanned.detail must be a string")


@dataclass(frozen=True, slots=True)
class Plan:
    plan_id: str
    kind: PlanKind
    config_hash: str | None  # None iff kind == UNDO
    created_at_ns: int
    derived_from_run: int | None  # set iff kind == UNDO
    operations: tuple[PlannedOperation, ...]
    unplanned: tuple[Unplanned, ...]

    def __post_init__(self) -> None:
        _require(isinstance(self.kind, PlanKind), "Plan.kind must be a PlanKind")
        _require(_is_int(self.created_at_ns) and self.created_at_ns >= 0, "Plan.created_at_ns must be an int >= 0")
        _require(isinstance(self.operations, tuple) and len(self.operations) >= 1, "a Plan needs at least one operation")
        _require(isinstance(self.unplanned, tuple), "Plan.unplanned must be a tuple")

        is_undo = self.kind is PlanKind.UNDO
        _require((self.derived_from_run is not None) == is_undo, "derived_from_run is set iff the plan is an undo")
        _require((self.config_hash is None) == is_undo, "config_hash is None iff the plan is an undo")
        if self.derived_from_run is not None:
            _require(_is_int(self.derived_from_run) and self.derived_from_run >= 1, "derived_from_run must be >= 1")
        if self.config_hash is not None:
            _require(
                isinstance(self.config_hash, str) and _SHA256_RE.fullmatch(self.config_hash) is not None,
                "Plan.config_hash must be 64 lowercase hex characters",
            )

        all_paths = [p for op in self.operations for p in (op.src, op.dst)] + [u.src for u in self.unplanned]
        _require(_paths_share_flavor(all_paths), "all paths in a Plan must be of one pure-path class")

        _require(
            [op.seq for op in self.operations] == list(range(1, len(self.operations) + 1)),
            "operation seq must run 1..N in order",
        )
        for op in self.operations:
            _require((op.rule_name == UNDO_RULE) == is_undo, "rule_name is the undo marker iff the plan is an undo")

        sources = [op.src for op in self.operations]
        _require(len(set(sources)) == len(sources), "operation sources must be unique")

        from marshalyard.canonical import compute_plan_id, portable_key  # lazy: canonical imports models

        keys = [portable_key(op.dst) for op in self.operations]
        _require(len(set(keys)) == len(keys), "operation destinations must be unique (portable_key collision)")

        unplanned_sources = [u.src for u in self.unplanned]
        _require(len(set(unplanned_sources)) == len(unplanned_sources), "unplanned sources must be unique")
        _require(not (set(unplanned_sources) & set(sources)), "an unplanned source cannot also be planned")

        expected = compute_plan_id(
            kind=self.kind,
            config_hash=self.config_hash,
            derived_from_run=self.derived_from_run,
            operations=self.operations,
            unplanned=self.unplanned,
        )
        _require(self.plan_id == expected, "Plan.plan_id does not match its content")
