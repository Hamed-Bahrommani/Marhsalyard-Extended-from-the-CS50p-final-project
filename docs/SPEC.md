# Switchyard — v1 Specification

**Status:** M1 frozen. Parts I–II are authoritative; where a later milestone discovers a conflict, the spec is amended first, then the code.
**Name:** "Switchyard" is a working codename. A distinctive public name is needed before the repository is published.
**Audience:** two developers implementing independently must arrive at the same semantics.

> **Defining principle.** Whenever Switchyard cannot establish that an operation is safe, it refuses the operation and explains why.

**Contents**

- Part I — M1: domain model and configuration (normative now)
  1. Scope and decision register
  2. Foundations
  3. Domain model
  4. TOML v1 configuration
  5. Validation catalogue
  6. Per-file decision pipeline
  7. Filesystem requirements (binding on M2–M5)
  8. Tests
  9. M1 acceptance criteria
- Part II — System design (normative for M2–M8)
  10. Operation and run state machines
  11. Recovery
  12. Undo
  13. Journal schema
  14. CLI contract
  15. System acceptance criteria
  16. Milestones
  17. Known limitations and non-guarantees
  18. Repository layout

---

# Part I — M1

## 1. Scope and decision register

| Area | Decision |
|---|---|
| Language | Python 3.11+ |
| Configuration | TOML (`tomllib`) |
| Persistence | SQLite journal |
| Filesystem access | A port with a real and an in-memory implementation |
| Operations | Move regular files only. Filenames are never changed. Symlinks, junctions and reparse points are never followed or moved; they are skipped. No copy, delete or overwrite |
| Scan depth | One directory level per rule source. No recursion |
| Windows move | `os.rename()` (refuses an existing destination) |
| Linux move | `renameat2(RENAME_NOREPLACE)` via `ctypes`; fail closed if unavailable; no raw-syscall fallback |
| macOS | Outside v1 |
| Cross-device moves | Rejected |
| Content hash threshold | 64 MiB: up to it, SHA-256 plus metadata; above it, identity, size and mtime only |
| Plan vs run | A Plan (immutable proposal), an Operation (one move) and a Run (an execution) are separate entities |
| Roots | Each operation persists its source and destination containing roots, with their directory identities; apply, recovery and undo use the persisted roots, never the current config |
| Post-move check | After every rename the destination is verified against the planned fingerprint before `DONE` is recorded |
| Runtime control files | The active config, the journal database, its sidecars and the lock file are never candidates |
| Recovery | Read-only reconciliation: inspects the filesystem, updates SQLite, never moves files, never resumes |
| Undo | A plan generated from a run, executed by the same executor; conditional and verified |
| Empty directories | Created as needed, left in place afterwards |
| CLI | Seven commands; no GUI; no `--json` in v1 |
| Concurrency | One active run |
| Dry-run meaning | No changes to managed files. The journal (application metadata) is written |
| Network and cloud-synced filesystems | Outside supported claims |
| Journal model | Immutable plans with monotonic, validated state transitions (not append-only) |

## 2. Foundations

1. **Domain paths are pure.** Every path in the model is an absolute, lexically normalised `PurePosixPath` or `PureWindowsPath`. The filesystem port converts to real paths at the boundary. M1 touches no filesystem, and Linux CI can test Windows path semantics.
2. **Validation is two-phase.** Phase 1 (`parse_config`) is pure and lexical and belongs to M1. Phase 2 (environment: existence, `realpath`, identity, capability) runs through the filesystem port and arrives in M2/M3. Its codes (`ENV_*`) are reserved in §5.
3. **Every dataclass is frozen with `slots`.** A "state change" is a new value from a pure `transition()` that the journal then persists.
4. **Time is an `int` of UTC epoch nanoseconds,** injected, never read from a clock inside domain code.
5. **No `typing.Literal` in the model.** Closed sets are `StrEnum`s, so template-token names cannot collide with typing constructs.
6. **Enum value casing.** State-like enums (`Flavor`, `Timezone`, `Severity`, `FpMethod`, `PlanKind`, `RunState`, `OpState`, `TransitionCause`) have **lowercase** values, matching the SQL `CHECK` lists. Code-like enums (`SkipReason`, `Observation`, `UnplannedReason`, `RecordReason`) have **UPPERCASE** values, matching the catalogue and the `plan_id` JSON.
7. **Identity integers are positive.** `st_dev` and `st_ino` values are `>= 1` in every identity type; zero means "unavailable" and negative values are invalid.
8. **CI matrix:** Windows and Linux, on Python 3.11 and the newest available.
9. **Repository layout** is fixed in §18, including the CS50P-shaped root `project.py` and `test_project.py`.

## 3. Domain model

### 3.1 Declarations

```python
class Flavor(StrEnum):           POSIX; WINDOWS                 # lowercase values
class Timezone(StrEnum):         LOCAL; UTC
class Severity(StrEnum):         ERROR; WARNING
class FpMethod(StrEnum):         CONTENT; METADATA
class PlanKind(StrEnum):         ORGANIZE; UNDO
class RunState(StrEnum):         RUNNING; FINISHED; ABORTED
class OpState(StrEnum):          PENDING; ATTEMPTING; DONE; FAILED; SKIPPED; UNRESOLVED
class TransitionCause(StrEnum): EXECUTION; RECOVERY; ABORT

# UPPERCASE values:
class SkipReason(StrEnum):
    EXCLUDED; SYMLINK; REPARSE_POINT; NOT_REGULAR; HIDDEN_OR_SYSTEM; RUNTIME_FILE
class Observation(StrEnum):
    ABSENT; MATCHES_PLAN; DIFFERENT; NOT_REGULAR; UNREADABLE; ROOT_CHANGED
class UnplannedReason(StrEnum):
    RULE_CONFLICT; NOT_SETTLED; IDENTITY_UNAVAILABLE; LINK_COUNT_UNAVAILABLE
    MULTIPLE_LINKS; UNREADABLE; CHANGED_DURING_PLANNING; CROSS_DEVICE
    INVALID_DESTINATION; DESTINATION_EXISTS; DESTINATION_COLLISION
    MODIFIED; MISSING; ORIGINAL_PATH_OCCUPIED; ROOT_CHANGED    # last four: undo plans only
class RecordReason(StrEnum):
    NOT_STARTED; RECOVERED; RECOVERED_METADATA_ONLY
    RUN_INTERRUPTED; RUN_ABORTED
    DESTINATION_EXISTS; SOURCE_MISSING; NOREPLACE_UNSUPPORTED; PATH_UNSAFE
    UNEXPECTED_ERROR; POST_MOVE_MISMATCH; AMBIGUOUS_OBSERVATION

AbsPath = PurePosixPath | PureWindowsPath
HASH_THRESHOLD = 64 * 1024 * 1024          # bytes; size <= threshold => CONTENT fingerprint
UNDO_RULE = "(undo)"

# ---------------- identities and fingerprints ----------------
@dataclass(frozen=True, slots=True)
class DirIdentity:
    dev: int; ino: int                             # invariant: both >= 1

@dataclass(frozen=True, slots=True)
class Fingerprint:
    dev: int; ino: int; nlink: int; size: int; mtime_ns: int
    sha256: str | None; method: FpMethod
    # invariants: dev >= 1; ino >= 1; nlink >= 1; size >= 0; all ints are real ints (not bool)
    #   (method == CONTENT) == (sha256 is not None); sha256 = 64 lowercase hex
    @property
    def verifies_content(self) -> bool: ...          # method == CONTENT
    def matches(self, other: "Fingerprint") -> bool: ...
    # equal dev, ino, nlink, size, mtime_ns, method; equal sha256 if CONTENT

# ---------------- config ----------------
@dataclass(frozen=True, slots=True)
class TextToken:      text: str
@dataclass(frozen=True, slots=True)
class ExtToken:       pass
@dataclass(frozen=True, slots=True)
class ModifiedToken:  fmt: str                    # only %Y %m %d and "-" "_"
Token = TextToken | ExtToken | ModifiedToken

@dataclass(frozen=True, slots=True)
class DestinationTemplate:
    raw: str                                      # as written, for messages
    base: AbsPath                                 # leading placeholder-free components
    components: tuple[tuple[Token, ...], ...]     # variable part; () => fully static
    # invariant: components[0], if present, contains >= 1 placeholder

@dataclass(frozen=True, slots=True)
class Rule:
    name: str; source: AbsPath
    extensions: tuple[str, ...]; name_glob: str | None
    min_age_s: int; destination: DestinationTemplate

@dataclass(frozen=True, slots=True)
class Config:
    version: int; flavor: Flavor; roots: tuple[AbsPath, ...]
    timezone: Timezone; default_min_age_s: int; max_operations: int
    exclude: tuple[str, ...]; rules: tuple[Rule, ...]; config_hash: str

# ---------------- scanning ----------------
@dataclass(frozen=True, slots=True)
class FileEntry:
    path: AbsPath; size: int; mtime_ns: int
    dev: int; ino: int; nlink: int                # from a fresh os.stat(follow_symlinks=False)
    # dev/ino == 0 or nlink <= 0 are representable ("unavailable"), never plannable
@dataclass(frozen=True, slots=True)
class SkippedEntry:   path: AbsPath; reason: SkipReason
@dataclass(frozen=True, slots=True)
class Snapshot:
    taken_at_ns: int; sources: tuple[AbsPath, ...]
    entries: tuple[FileEntry, ...]; skipped: tuple[SkippedEntry, ...]

# ---------------- plans ----------------
@dataclass(frozen=True, slots=True)
class PlannedOperation:
    seq: int; src: AbsPath; dst: AbsPath
    src_root: AbsPath; dst_root: AbsPath            # containing roots, chosen by the planner
    src_root_id: DirIdentity; dst_root_id: DirIdentity
    rule_name: str; fingerprint: Fingerprint
@dataclass(frozen=True, slots=True)
class Unplanned:      src: AbsPath; reason: UnplannedReason; detail: str = ""
@dataclass(frozen=True, slots=True)
class Plan:
    plan_id: str; kind: PlanKind
    config_hash: str | None                       # None iff kind == UNDO
    created_at_ns: int; derived_from_run: int | None
    operations: tuple[PlannedOperation, ...]; unplanned: tuple[Unplanned, ...]

# ---------------- journal ----------------
@dataclass(frozen=True, slots=True)
class Run:
    run_id: int; plan_id: str; state: RunState
    started_at_ns: int; finished_at_ns: int | None
    recovered_at_ns: int | None; abort_reason: str | None
@dataclass(frozen=True, slots=True)
class OperationRecord:
    run_id: int; seq: int; state: OpState
    cause: TransitionCause | None                 # cause of the transition into `state`; None iff PENDING
    reason: RecordReason | None
    attempted_at_ns: int | None; finished_at_ns: int | None
@dataclass(frozen=True, slots=True)
class UnresolvedOp:   seq: int; src_observed: Observation; dst_observed: Observation
@dataclass(frozen=True, slots=True)
class RecoveryResult:
    run_id: int; records: tuple[OperationRecord, ...]; unresolved: tuple[UnresolvedOp, ...]

# ---------------- validation output ----------------
@dataclass(frozen=True, slots=True)
class Issue:
    code: str; location: str; message: str; severity: Severity
    line: int | None = None; column: int | None = None      # TOML_SYNTAX only, best-effort
@dataclass(frozen=True, slots=True)
class ValidationResult:
    config: Config | None                          # None iff any error
    issues: tuple[Issue, ...]
```

**Pure functions delivered by M1:** `parse_config`, `load_config` (thin, impure), `compute_config_hash`, `compute_plan_id`, `portable_key`, `containing_root`, `transition`, `classify_recovery`, plus the shared `check_*` helpers.

### 3.2 Validation responsibilities

| Layer | Handles | Reports via |
|---|---|---|
| Constructors (`__post_init__`) | structural invariants of one value | `ValueError` naming the invariant; an invalid object is a bug, never user input |
| `parse_config` | everything a user can get wrong in TOML | `Issue`s, accumulated |
| Planner (M2) | facts about the disk | `Unplanned` reasons |

The validator and the constructors share one set of `check_*` helpers, so there is a single rule set.

### 3.3 Invariants

- **Paths.** Every path in `Config`, `Rule`, `FileEntry`, `Snapshot` (sources, entries, skipped), `PlannedOperation` (including its roots) and `Unplanned` is absolute and of **one** pure-path class within its owning object. A mixed object raises `ValueError`. `Config.flavor` agrees with the class of its paths.
- **DirIdentity.** Both integers are real ints (not `bool`) and `>= 1`.
- **Config.** `version == 1`; roots non-empty and unique (flavor-native equality); 1–200 rules with unique names; `1 <= max_operations <= 100000`; every rule `source` and `destination.base` inside some root; `config_hash` equals `compute_config_hash` of the rest.
- **Rule.** At least one of `extensions` or `name_glob`; `0 <= min_age_s <= 3650 days`; name matches `^[a-z0-9][a-z0-9_-]{0,63}$`. The reserved name `(undo)` fails that pattern by construction.
- **Fingerprint.** As declared. A fingerprint cannot be built for a file whose identity or link count is unavailable.
- **PlannedOperation.** `fingerprint.nlink == 1`; `dst != src`; `src` is inside `src_root` and `dst` is inside `dst_root` (flavor-native containment); both roots are absolute and of the same path class as `src`; `src_root_id` and `dst_root_id` are valid `DirIdentity`s. The planner chooses each root with `containing_root` over the configured roots. The constructor cannot check "most specific", because it has no config; that check belongs to the M2 planner tests.
- **Plan.**
  - at least one operation (an empty plan is "nothing to do" and does not exist)
  - `seq` runs 1..N
  - sources unique; destinations unique by `portable_key`
  - `(kind == UNDO) == (derived_from_run is not None) == (config_hash is None)`
  - every operation's `rule_name == UNDO_RULE` iff `kind == UNDO`
  - unplanned sources unique and disjoint from operation sources
  - within one plan, operations whose root paths are equal (flavor-native) carry **equal** root identities
  - `plan_id == compute_plan_id(...)` (this also detects a plan loaded from a damaged journal)
- **Snapshot.** Entries sorted by `as_posix()` and unique; skipped entries sorted, unique, disjoint from entries; the parent of every entry and every skipped entry is in `sources`.
- **OperationRecord.**
  - `PENDING`: no cause, no reason, no timestamps
  - `ATTEMPTING`: cause `EXECUTION`, `attempted_at` set, `finished_at` unset
  - terminal states: cause and `finished_at` set
  - `FAILED`, `SKIPPED`, `UNRESOLVED`: reason required
  - `DONE`: reason is `None`, `RECOVERED` or `RECOVERED_METADATA_ONLY`
- **Run.** `finished_at is None` iff `RUNNING`; `abort_reason` set iff `ABORTED`; `recovered_at` set only on `FINISHED`.

### 3.4 Canonical forms

**Canonical JSON** everywhere: UTF-8, `sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=True`, integers only (no floats), paths via `as_posix()`, hashes as lowercase hex SHA-256.

**`compute_plan_id`** — digest of the whole immutable proposal; the only excluded field is `created_at_ns`:

```
{"kind", "config_hash", "derived_from_run",
 "ops": [{"seq","src","dst","src_root","dst_root",
          "src_root_id": {"dev","ino"}, "dst_root_id": {"dev","ino"},
          "rule",
          "fp": {"dev","ino","nlink","size","mtime_ns","sha256","method"}}],
 "unplanned": [{"src","reason","detail"}]}          # sorted by (src.as_posix(), reason)
```

- Two proposals differing only in their unplanned report, their roots or their root identities get different ids, so the journal's primary key cannot collide, and an approval covers the physical directories the user saw.
- Re-planning an unchanged state gives the same id; persistence is `INSERT OR IGNORE` and the first `created_at_ns` is kept.
- **`detail` is deterministic and time-independent.** Identical planning inputs and filesystem observations produce identical details. A detail contains no relative ages, timestamps, random identifiers or volatile measurements. `NOT_SETTLED` states the rule's setting (`min_age=600s`), never a measured age.
- Plan ids are deterministic across runs and Python versions. They are **not** comparable across operating systems, because paths differ.

**`compute_config_hash`** — excludes `config_hash` itself:

```
{"version","flavor","timezone","default_min_age_s","max_operations",
 "roots": [as_posix, sorted],
 "exclude": [sorted],
 "rules": [ {"name","source","extensions": [sorted],"name_glob","min_age_s",
             "destination": {"base","components": [[token,...],...]}} ]}   # sorted by name
```

Tokens serialise as `["t", text]`, `["e"]`, `["m", fmt]`. `Config.rules` keeps file order for display; only the hash sorts. The hash is **invariant under reordering** of rules, roots, extensions and exclusions. It is **spelling-sensitive** for paths and globs: `~/Downloads` and `~/downloads`, or `*.PDF` and `*.pdf`, hash differently even where the flavor treats them as equal. It identifies the configuration's normalised content for provenance; it is not a semantic-equivalence test. A trailing slash on a path does not change it, because that is removed during parsing.

**`portable_key(path) -> str`:**
1. For each component: `NFC(casefold(NFC(component)))`.
2. Casefold the anchor.
3. Join with `/`.

It is a deliberately **conservative approximation** of "could these collide on some supported filesystem". Over-detection is the safe direction. It is not a claim to equal any filesystem's rule (NTFS's `$UpCase` table, locale cases such as Turkish dotless i). Example: `Straße.pdf` and `STRASSE.pdf` collide. Stored paths keep their original spelling. `portable_key` is used only for destination collisions and the stored `dst_key`. It is **not** used for root or rule-name duplicate checks, because on POSIX `/data/A` and `/data/a` are distinct directories. Config containment uses flavor-native comparison; two spellings of one name in different Unicode normal forms are treated as different paths, which fails closed.

**`containing_root(path, roots) -> AbsPath | None`** — among the roots that contain `path` (component-wise, flavor-native, a path equal to a root counts as contained), returns the **most specific** one: the root with the greatest number of components. Roots are unique, so ties are impossible. The **planner** uses it to choose `src_root` and `dst_root`. After planning, **apply, recovery and undo never recompute roots from the configuration**; they use the roots persisted in the plan.

### 3.5 `transition` and recovery classification

```python
def transition(record, new_state, reason, cause, now_ns) -> OperationRecord: ...
def classify_recovery(src: Observation, dst: Observation,
                      method: FpMethod) -> tuple[OpState, RecordReason]: ...
```

`LEGAL_TRANSITIONS` is a frozenset of exactly **14** `(from, to, cause, reason)` tuples. `transition` raises on anything else. The resulting record stores the cause (the journal persists it, §13). The table groups reasons; each row expands to one tuple per listed reason:

| From → To | Cause | Reason(s) | Tuples |
|---|---|---|---|
| `PENDING` → `ATTEMPTING` | EXECUTION | none | 1 |
| `ATTEMPTING` → `DONE` | EXECUTION | none | 1 |
| `ATTEMPTING` → `FAILED` | EXECUTION | `DESTINATION_EXISTS`, `SOURCE_MISSING`, `NOREPLACE_UNSUPPORTED`, `PATH_UNSAFE` | 4 |
| `ATTEMPTING` → `UNRESOLVED` | EXECUTION | `UNEXPECTED_ERROR`, `POST_MOVE_MISMATCH` | 2 |
| `PENDING` → `SKIPPED` | ABORT | `RUN_ABORTED` | 1 |
| `PENDING` → `SKIPPED` | RECOVERY | `RUN_INTERRUPTED` | 1 |
| `ATTEMPTING` → `SKIPPED` | RECOVERY | `NOT_STARTED` | 1 |
| `ATTEMPTING` → `DONE` | RECOVERY | `RECOVERED`, `RECOVERED_METADATA_ONLY` | 2 |
| `ATTEMPTING` → `UNRESOLVED` | RECOVERY | `AMBIGUOUS_OBSERVATION` | 1 |

Terminal states (`DONE`, `FAILED`, `SKIPPED`, `UNRESOLVED`) have no outgoing edges. `classify_recovery` is the single place the recovery observation matrix (§11) lives; it returns the pair recovery then feeds to `transition`.

## 4. TOML v1 configuration

### 4.1 Example

```toml
version = 1

[settings]
roots = ["~/Downloads", "~/Documents/Sorted"]
timezone = "local"
min_age = "10m"
max_operations = 2000
exclude = ["*.iso.part", "thumbs.db"]

[[rule]]
name = "invoices-by-year"
source = "~/Downloads"
extensions = ["pdf"]
name_glob = "invoice*"
destination = "~/Documents/Sorted/Invoices/{modified:%Y}"

[[rule]]
name = "images"
source = "~/Downloads"
extensions = ["jpg", "jpeg", "png"]
min_age = "1h"
destination = "~/Documents/Sorted/Images/{ext}"
```

### 4.2 Fields

| Key | Type | Required | Default | Rules |
|---|---|---|---|---|
| `version` | integer | yes | — | exactly `1` |
| `settings` | table | yes | — | |
| `settings.roots` | array of string | yes | — | 1–20 paths |
| `settings.timezone` | `"local"` / `"utc"` | no | `"local"` | nothing else |
| `settings.min_age` | duration string | no | `"10m"` | |
| `settings.max_operations` | integer | no | `2000` | 1..100000; booleans rejected |
| `settings.exclude` | array of string | no | `[]` | **added to** the built-ins |
| `rule` | array of tables | yes | — | 1–200 |
| `rule.name` | string | yes | — | `^[a-z0-9][a-z0-9_-]{0,63}$`, unique |
| `rule.source` | string (path) | yes | — | inside a root |
| `rule.extensions` | array of string | no | — | |
| `rule.name_glob` | string | no | — | |
| `rule.min_age` | duration string | no | settings value | |
| `rule.destination` | string (template) | yes | — | |

Unknown keys are errors at every level. Booleans are never accepted for integers.

**Built-in exclusions** (users may extend, never remove): `*.part`, `*.crdownload`, `*.tmp`, `desktop.ini`, `.*`. Consequently `.env` and `.gitignore` are never organised in v1. The runtime control files (§7.7) are excluded separately.

**Duration:** `^[0-9]+(s|m|h|d)$` — a string with one integer and one lowercase unit. `0s` is allowed; maximum `3650d`. Rejected: `10`, `10 m`, `1h30m`, `1.5h`, `-5m`, `10M`, a TOML integer.

**Extension of a name:** the text after the **last** dot, if that dot is neither the first nor the last character, lowercased. `a.tar.gz` has extension `gz`; for `tar.gz` use `name_glob = "*.tar.gz"`. Extensionless files never match an `extensions` condition. Configured extensions are lowercased on load, must match `^[a-z0-9_+-]{1,16}$`, and are deduplicated with order kept.

**Globs** match the file name only, contain no separator, and are matched with `fnmatch.fnmatchcase` on `casefold()`ed pattern and name (plain `fnmatch` changes behaviour per OS). `[` must be balanced.

**Time zone:** `local` is the machine's zone *at plan time*; `utc` is UTC. `{modified}` uses `mtime_ns // 1_000_000_000` converted to that zone. The result is baked into the plan.

### 4.3 Path grammar (raw string first)

Applied to every path-valued field and to templates **before any `PurePath` is constructed**, because `PurePath` silently collapses repeated separators and `.` components.

1. Empty string → `PATH_EMPTY`. NUL or any control character (< 0x20) → `PATH_INVALID_CHARS`.
2. **Tilde.** Exactly `~`, or `~` followed by a separator, expands to the injected `home`. A leading `~` followed by anything else → `PATH_TILDE_USER`.
3. **Separators.** `/` on both flavors, plus `\` on Windows only. On POSIX a backslash is an ordinary character. Tokenise the raw string on separators.
4. **Anchor.** POSIX: a leading `/`, otherwise `PATH_NOT_ABSOLUTE`. Windows: `X:` followed by a separator. A leading `\\` or `//` (including `\\?\`) → `PATH_NETWORK_UNSUPPORTED`. Everything else (`C:foo`, `\foo`, relative) → `PATH_NOT_ABSOLUTE`.
5. **Components after the anchor.** Exactly **one** trailing separator after a non-empty final component is permitted and discarded. Any other empty component (repeated separators, `//` at the end) → `PATH_EMPTY_COMPONENT`. `.` or `..` → `PATH_DOT_COMPONENT`.
6. Only then is the `PurePath` constructed from the validated components. An anchor-only path (`/`, `C:\`) is a valid lexical path with no trailing-separator concept; roots reject it as too broad and sources reject it as outside roots. `C:\\` is `PATH_EMPTY_COMPONENT`.
7. **Containment** is `is_relative_to` on pure paths of the flavor: component-wise; case-insensitive on Windows, case-sensitive on POSIX. `/data/downloads-evil` is not inside `/data/downloads`.

**Roots** must not be a filesystem root, the home directory, or an ancestor of it (`ROOT_TOO_BROAD`). Duplicate roots are an error. Nested roots are allowed; `containing_root` selects the most specific one.

### 4.4 Template grammar (after `~` expansion and tokenising)

```
component   = ( text | placeholder )+
placeholder = "{ext}" | "{modified:" fmt "}"
fmt         = ( "%Y" | "%m" | "%d" | "-" | "_" )+
text        = any character except "{", "}" and control characters
```

- No literal braces and no escape syntax. A placeholder spanning a separator is a syntax error, because separators are consumed first.
- `{modified}` without a format is an error. `{name}`, `{stem}` and unknown placeholders → `TEMPLATE_UNKNOWN_PLACEHOLDER`.
- **`base`** is every component before the first component containing a placeholder; it must be inside a root. A rendered path cannot escape `base` (placeholder values contain no separators); the planner re-checks at plan time.
- **Portable-name rule**, applied on all platforms to every literal component below the containing root: non-empty; at most **255 bytes of UTF-8** (UTF-8 is never shorter than UTF-16 in code units, so this also satisfies NTFS's 255-code-unit limit); none of `<>:"|?*\/`; no trailing dot or space; not a reserved Windows name (`CON PRN AUX NUL COM1..9 LPT1..9`, with or without extension). Rendered components get the same check at plan time (`INVALID_DESTINATION`). At plan time the whole rendered destination must also be at most **240 UTF-16 code units** (clear of Windows `MAX_PATH`).
- `{ext}` on an extensionless file is `INVALID_DESTINATION` at plan time.

## 5. Validation catalogue

`location` is a TOML key path with **0-based** indices (`rule[2].destination`), or `$` for the whole file. Messages carry the rule name when one exists.

### 5.1 Accumulation rules

| Stage | Behaviour |
|---|---|
| S0 read (`load_config`) | **stop** |
| S1 TOML parse | **stop** (one issue) |
| S2 `version` | **stop** if missing or unsupported |
| S3 field checks | **accumulate**; a field with a wrong type is skipped by later checks, so errors do not cascade |
| S4 cross-checks | **accumulate**, only over entities that passed S3 |

- Cap: 50 issues, then one `TOO_MANY_ERRORS`.
- `config is None` iff any error exists. Warnings never block.
- Issues are sorted by `(location, code)`, stably.
- **TOML syntax locations are best-effort.** `TOML_SYNTAX` always carries the parser's message. On Python 3.14+, `line` and `column` come from the exception's attributes; on 3.11–3.13 they are `None`. Line and column are never parsed out of message text.

### 5.2 Codes

| Code | Sev | Location | Trigger |
|---|---|---|---|
| `CONFIG_NOT_FOUND`, `CONFIG_UNREADABLE`, `CONFIG_TOO_LARGE` (> 1 MiB), `CONFIG_NOT_UTF8` | E | `$` | file-level |
| `TOML_SYNTAX` | E | `$` | parse failure |
| `VERSION_MISSING`, `VERSION_UNSUPPORTED` | E | `version` | S2 |
| `UNKNOWN_KEY` | E | key path | any unrecognised key |
| `WRONG_TYPE` | E | field | wrong TOML type, including bool for int |
| `MISSING_KEY` | E | the absent key's path | absent `settings`; absent `settings.roots`; absent `rule[i].name`, `.source` or `.destination` |
| `NO_RULES`, `TOO_MANY_RULES` | E | `rule` | zero / over 200 |
| `ROOTS_EMPTY` | E | `settings.roots` | present but empty |
| `TIMEZONE_INVALID` | E | `settings.timezone` | not `local` or `utc` |
| `DURATION_INVALID`, `DURATION_OUT_OF_RANGE` | E | field | syntax / over 3650d |
| `MAX_OPERATIONS_OUT_OF_RANGE` | E | `settings.max_operations` | outside 1..100000 |
| `EXCLUDE_PATTERN_INVALID` | E | `settings.exclude[i]` | separator or unbalanced `[` |
| `PATH_EMPTY`, `PATH_NOT_ABSOLUTE`, `PATH_DOT_COMPONENT`, `PATH_EMPTY_COMPONENT`, `PATH_TILDE_USER`, `PATH_INVALID_CHARS`, `PATH_NETWORK_UNSUPPORTED` | E | path field | §4.3 |
| `ROOT_DUPLICATE`, `ROOT_TOO_BROAD` | E | `settings.roots[i]` | §4.3 |
| `RULE_NAME_INVALID`, `RULE_NAME_DUPLICATE` | E | `rule[i].name` | pattern / uniqueness (reported on the later one) |
| `RULE_NO_CONDITION` | E | `rule[i]` | neither `extensions` nor `name_glob` |
| `EXTENSION_INVALID`, `GLOB_INVALID` | E | field | §4.2 |
| `RULE_SOURCE_OUTSIDE_ROOTS`, `RULE_DESTINATION_OUTSIDE_ROOTS` | E | `rule[i].source` / `.destination` | containment |
| `RULE_DESTINATION_IS_SOURCE` | E | `rule[i].destination` | fully static and equal to its own `source` |
| `RULE_OVERLAP` | E | `rule[j]` | same source, **both without** `name_glob`, extension sets intersect |
| `RULE_CHAIN` | **W** | `rule[i].destination` | see below |
| `TEMPLATE_SYNTAX`, `TEMPLATE_UNKNOWN_PLACEHOLDER`, `TEMPLATE_BAD_FORMAT`, `TEMPLATE_COMPONENT_INVALID` | E | `rule[i].destination` | §4.4 |
| `TOO_MANY_ERRORS` | E | `$` | cap reached |

**`RULE_CHAIN` (warning).** Files moved into rule A's **fully static** destination **may be picked up by rule B on a subsequent planning run**. It does *not* claim the current plan processes files it has just moved: scanning is non-recursive and snapshot-based, so the current plan never rescans. Trigger: A's destination is fully static, equals B's `source` (A ≠ B, flavor-native equality), and B is not provably disjoint from A — i.e. it is *not* the case that both have non-empty `extensions` sets that do not intersect. Ancestor/descendant relationships never warn. Destinations with placeholders are not evaluated at config time.

**`RULE_OVERLAP`** is an error only when definite (same source, no globs on either, intersecting extensions). Whether two globs intersect is not decided; anything uncertain falls to the runtime `RULE_CONFLICT`.

### 5.3 Reserved for phase 2 (M2/M3; not implemented in M1)

| Code | Sev | Meaning |
|---|---|---|
| `ENV_ROOT_MISSING`, `ENV_ROOT_NOT_DIRECTORY` | E | root absent or not a directory (also checked at apply preflight for every distinct persisted root, exit 3) |
| `ENV_ROOT_CHANGED` | E | a root's current resolved identity differs from the one recorded in the plan (§7.8) |
| `ENV_SOURCE_MISSING` | W | a rule cannot run until its source exists |
| `ENV_SOURCE_NOT_DIRECTORY` | E | wrong kind of path |
| `ENV_ESCAPES_ROOT` | E | inside a root lexically; not after `realpath` |
| `ENV_LINK_IN_PATH` | E | a symlink, junction or reparse point below the containing root in a source chain or a destination-base chain (§7.5 D3) |
| `ENV_IDENTITY_UNAVAILABLE` | E | the filesystem does not give usable `(dev, ino)` for a file or a root |
| `ENV_NOREPLACE_UNAVAILABLE` | E | Linux libc has no callable `renameat2` |
| `ENV_CROSS_DEVICE` | W | a source and its destination base are on different devices |
| `ENV_CONTROL_FILE_IN_SOURCE` | W | the config file, journal database, a sidecar or the lock file lies in an active rule source; they are excluded anyway (§7.7), and this tells the user why a matching file is never moved |

## 6. Per-file decision pipeline

Decided here, implemented in M2. Each file is evaluated in this order:

1. **Scope.** Its directory equals a rule's `source` (non-recursive).
2. **Skip.** Excluded by a built-in or user pattern (`EXCLUDED`); a runtime control file (`RUNTIME_FILE`, §7.7); symlink; Windows reparse point; non-regular file; hidden or system attribute. These become `SkippedEntry`s, not candidates.
3. **Match.** (`extensions` empty, or the extension is in it) **and** (`name_glob` unset, or it matches). All present conditions must hold.
4. **Conflict.** Two or more rules match → `RULE_CONFLICT`, regardless of age. Only the affected file is blocked.
5. **Age.** `now_ns - mtime_ns < min_age_s * 10^9` → `NOT_SETTLED`. A future mtime (negative age) is also `NOT_SETTLED`.
6. **Identity.** `dev == 0` or `ino == 0` → `IDENTITY_UNAVAILABLE`.
7. **Link count.** Unavailable (`nlink <= 0`) → `LINK_COUNT_UNAVAILABLE`; `nlink > 1` → `MULTIPLE_LINKS`. These checks use scan data, **before any content is read**.
8. **Fingerprint** (filesystem read, §7.2). Disagreement between observations → `CHANGED_DURING_PLANNING`; unreadable → `UNREADABLE`.
9. **Destination.** Render; validity (`INVALID_DESTINATION`); device (`CROSS_DEVICE`); existence (`DESTINATION_EXISTS`); collision (`DESTINATION_COLLISION`, by `portable_key`; all files in the collision are unplanned).

The plan pipeline is: **scan → match → fingerprint selected candidates → pure plan finalisation → persist.** Only files that survive step 7 are read. Hashing a whole directory is never required.

**`plan --rule NAME` never bypasses conflict detection.** The planner evaluates **all** rules for every scanned file, runs conflict detection (step 4) first, and only then restricts the output to the selected rule. A file is planned only if the selected rule is its **only** matching rule and it passes every later step. A file matched by the selected rule *and* another rule stays unplanned as `RULE_CONFLICT` and is listed. Files that match only other rules are omitted. An unknown rule name is a usage error (exit 2). The stored plan's `unplanned` list contains only files the selected rule matched, so the plan id stays deterministic.

## 7. Filesystem requirements

Binding on M2–M5. M1 only encodes them in types.

### 7.1 Identity

A file's identity is `(st_dev, st_ino)` from a **fresh `os.stat(path, follow_symlinks=False)`** of that path. `DirEntry.stat()` is used for names and type only, because on Windows it reports zero for `st_ino`, `st_dev` and `st_nlink`; it never feeds a `FileEntry` or a `Fingerprint`. A scanner test fails if a planned entry has a zero identity or link count. `Fingerprint.matches` is the single definition of "unchanged".

| Assumption | Failure mode | Behaviour |
|---|---|---|
| NTFS, ext4, xfs, btrfs, tmpfs keep `st_ino` across a rename | a filesystem changes the id on rename (FAT-family ids derive from directory position) | recovery sees a mismatch → `UNRESOLVED`, never a false `DONE`. M3 tests this per filesystem |
| `os.stat` on Windows fills `st_dev`, `st_ino`, `st_nlink` | zero on some filesystems | `IDENTITY_UNAVAILABLE` / `LINK_COUNT_UNAVAILABLE` |
| `st_nlink` is reliable | not on all filesystems | unknown is refused |
| Windows reparse points (junctions, OneDrive placeholders) | misleading metadata | skipped as `REPARSE_POINT` via `st_file_attributes` |
| `mtime_ns` granularity is fixed per filesystem | coarse timestamps (FAT: 2 s) | compared only between observations of the same filesystem |

**Refusal ladder:** `IDENTITY_UNAVAILABLE`, then `LINK_COUNT_UNAVAILABLE`, then `MULTIPLE_LINKS`. "Unavailable" is never reported as "multiple".

**Link-count rechecks.** The full-fingerprint comparison at preflight includes `nlink`. Immediately before each rename the executor re-stats the source and compares `dev`, `ino`, `nlink == 1`, `size` and `mtime_ns`. Undo plans apply the same checks to the file being moved back.

### 7.2 Fingerprinting (best-effort consistency check)

For files **up to 64 MiB**:

1. `os.stat(path, follow_symlinks=False)` → `s0`; compare with the scan entry.
2. Open the file (POSIX: `O_NOFOLLOW`) and `os.fstat(fd)` → `s1`; require `(dev, ino)` of `s1` to equal `s0`.
3. Stream the content through SHA-256 from that handle.
4. `os.fstat(fd)` → `s2`.
5. `os.stat(path, follow_symlinks=False)` → `s3`.

`s0..s3` must agree on `dev`, `ino`, `nlink`, `size` and `mtime_ns`, and `nlink` must be 1. Otherwise `CHANGED_DURING_PLANNING`.

**What this establishes.** Agreement establishes *consistency of the observed metadata* across the read. It is **not** a guarantee that the contents did not change, and not an atomic snapshot. It detects the common cases (a growing download, a rewrite that changes size or mtime) and reduces the probability of a fingerprint describing a state that never existed. **Documented limitation:** a modification that preserves identity, size and mtime — for example a same-timestamp write on a coarse-timestamp filesystem — is undetectable. A file held open exclusively by another process fails to open and becomes `UNREADABLE`; Windows sharing-mode behaviour is unverified and M3 must test it.

For files **above 64 MiB** nothing is read; a fresh stat is compared with the scan entry.

### 7.3 Verification strength

- `Fingerprint.verifies_content` is true only for `CONTENT` fingerprints.
- Recovery, undo and post-move verification of a `CONTENT` fingerprint **recompute and compare the actual SHA-256**, not just metadata. A `METADATA` fingerprint proves only that identity, size and mtime match; it **cannot** prove the bytes are unchanged.
- Recovery records `RECOVERED` for content-verified successes and `RECOVERED_METADATA_ONLY` otherwise. History, `explain` and `plan` output show the strength per operation.
- **README text (mandatory):** "Switchyard never modifies file contents; it only renames. Before recovery or undo, files up to 64 MiB are verified by SHA-256 plus metadata. Larger files are verified by identity, size and modification time only, which cannot prove the contents are unchanged."

### 7.4 No-replace move

`move_no_clobber(src, dst)` is one interface with per-platform strategies and a shared conformance suite (destination exists, source missing, directory target, case-only collision, read-only source, cross-device).

- **Windows:** `os.rename`. M3 must verify on real Windows that it raises when the destination exists and fails across volumes.
- **Linux:** `renameat2(..., RENAME_NOREPLACE)` via `ctypes` (`use_errno=True`, `AT_FDCWD = -100`, `RENAME_NOREPLACE = 1`), resolved from the libc symbol. If the symbol is missing, `ENV_NOREPLACE_UNAVAILABLE`: `apply` refuses before creating a run (exit 3). **No raw-syscall fallback.**
- **Filesystem support** is discovered when the move is attempted. `EINVAL`, `ENOSYS` or `EOPNOTSUPP` marks the operation `FAILED` (`NOREPLACE_UNSUPPORTED`), **aborts the run**, preserves completed operations and marks the rest `SKIPPED`. There is never a fallback to ordinary rename, and no probe files are created.
- **Rejected primitives:** hard-link-then-unlink (an unlink deletes whatever now sits at the source name; Windows read-only and open-file failures; filesystem limits; an extra intermediate state) and reserve-then-replace (a third party can replace the placeholder before the `replace`).
- **Residual risk (documented, demonstrated by race-injection tests):** no-replace rename protects the destination but does not atomically verify that the source still holds the fingerprinted file. The executor's post-move verification (§10 step 3) detects many such swaps after the fact; it does not prevent them.

### 7.5 Directory safety contract

| # | Requirement |
|---|---|
| D1 | Missing destination directories **are created automatically**, one level at a time with `os.mkdir` (never `makedirs`), only **below the containing root**. The containing root itself must already exist and is never created. |
| D2 | A `FileExistsError` from `mkdir` is resolved by re-`lstat`ing the component: it must be a real directory (not a symlink or reparse point), otherwise the operation is refused. |
| D3 | **No symlink, junction or reparse point below the containing root** in a **source** parent chain (including `rule.source` itself) or a **destination** parent chain. The root itself may be reached through a link (phase 2 resolves it with `realpath`), but its resolved identity is bound to the plan (§7.8). Plan time: `ENV_LINK_IN_PATH` for config chains and `INVALID_DESTINATION` (deterministic detail) per file. Execution time: operation `FAILED` with `PATH_UNSAFE`. The checks use the roots persisted in the plan (`src_root`, `dst_root`). |
| D4 | Immediately before each rename the executor re-`lstat`s every existing component below the containing root, of **both** the source parent chain and the destination parent chain, and re-checks both root identities (§7.8). A swapped directory or root fails the operation with `PATH_UNSAFE`. |
| D5 | **Linux (recommended for M3):** open each root as a directory fd and `fstat` that fd to confirm its identity; walk each chain from its own root fd with `os.open(name, O_RDONLY\|O_DIRECTORY\|O_NOFOLLOW, dir_fd=parent_fd)` per component; fingerprint the source through an fd-relative open; call `renameat2(src_dirfd, src_name, dst_dirfd, dst_name, RENAME_NOREPLACE)`. This closes the window in which a **source or destination parent directory** is swapped for a symlink between the D4 check and the rename. Source and destination chains may have different containing roots. **Windows:** the same window remains and is documented. In both cases the final source *name* can still be swapped (the §7.4 residual). |
| D6 | **Crash during directory creation:** each directory is recorded in `created_dirs` *after* `mkdir`. A crash between the two leaves an unrecorded empty directory, which is harmless and fails in the safe direction. Recovery never touches directories. Recording before `mkdir` could wrongly claim a directory that already existed. |
| D7 | v1 never removes directories, including after undo. |
| D8 | Directories are created with default permissions (`os.mkdir` default and the umask; ACL inheritance on Windows). No mode is configurable. |
| D9 | The planner chooses `src_root` and `dst_root` with `containing_root` (most specific root). The executor, recovery and undo use the **persisted** roots. |

### 7.6 Supported-platform claim (README)

NTFS on Windows; ext4, xfs, btrfs and tmpfs on Linux. Network filesystems and cloud-synced folders are excluded from the claims. UNC paths are refused, but a network share mounted on Linux cannot be reliably detected, so that boundary is documentation, not a guarantee.

### 7.7 Runtime control files

The following are **never planner candidates**, regardless of rules, globs or user exclusions. The exclusion is built in, cannot be removed, and is computed at run time rather than stored in the configuration:

- the active configuration file
- the journal database file
- its sidecars: `<db>-wal`, `<db>-shm`, `<db>-journal`
- the lock file, whose path is `<db>.lock`

A scanned file is excluded (`RUNTIME_FILE`) if its path equals one of these (flavor-native comparison after `realpath`) **or** its `(st_dev, st_ino)` equals the identity of an existing one. The identity check catches hard-link aliases. Where a control file does not exist yet, comparison is by path only. `check` also reports `ENV_CONTROL_FILE_IN_SOURCE` (warning).

### 7.8 Root identity

A root's **identity** is `(st_dev, st_ino)` of the **resolved** directory, taken from `os.stat(realpath(root))` at planning time, so a root reached through a symlink is identified by its target. A root whose identity is unavailable (`dev == 0` or `ino == 0`) fails phase 2 with `ENV_IDENTITY_UNAVAILABLE`. The identities are persisted with every operation and are part of `plan_id`, so an approval covers the physical directories the user saw.

- **Apply (preflight):** before traversing either root, resolve it again and compare its identity with the persisted one. A mismatch refuses the whole `apply` with `ENV_ROOT_CHANGED` (exit 3) and creates no run.
- **Apply (per operation):** the D4 re-check also re-stats both roots and compares identity. On Linux, D5 opens each root as a directory fd and `fstat`s that fd, so the checked directory is the one traversed. A mismatch fails the operation with `PATH_UNSAFE`.
- **Recovery:** if either root's identity does not match (or the root is missing), recovery does **not** traverse paths under it. The affected observation is `ROOT_CHANGED`, which `classify_recovery` maps to `UNRESOLVED`.
- **Undo:** an undo operation inherits the original operation's root identities and swaps them together with the roots and paths. If a recorded root's current identity differs when the undo plan is generated, the affected files are unplanned with `ROOT_CHANGED`.
- A root that still exists but is a *different directory* is therefore never silently accepted; a symlinked root remains supported as long as its target does not change.

## 8. Tests

All configuration tests call `parse_config(text, flavor=..., home=...)` and assert on `(code, location)` pairs. Use `pytest.param(..., id="short")` with short ids (long parametrised ids break on Windows).

### 8.1 Twenty-one configuration cases

| # | Case | Expected |
|---|---|---|
| 1 | Minimal valid config | `config` set, no issues |
| 2 | The full example in §4.1 | normalised: `min_age_s` 600 and 3600; exclude = built-ins plus user entries; `~` expanded; extensions case-folded |
| 3 | Malformed TOML | one `TOML_SYNTAX`, `config is None`, non-empty message. **Python 3.14+ only:** `line` and `column` set. On 3.11–3.13: both `None` |
| 4 | Empty file; file without `version` | `VERSION_MISSING` only (stop) |
| 5 | `version = 2` | `VERSION_UNSUPPORTED` only |
| 6 | Typo `extenions`, plus an unknown top-level key | `UNKNOWN_KEY` ×2 **and** `RULE_NO_CONDITION` |
| 7 | `extensions = "pdf"`, `min_age = 600`, `max_operations = true`, `roots = "x"` | four `WRONG_TYPE` at the right locations; no cascade |
| 8 | Durations. Valid: `0s 10m 2h 7d 3650d`. Invalid: `10`, `10 m`, `1h30m`, `1.5h`, `-5m`, `10M`, `3651d` | `DURATION_INVALID` / `DURATION_OUT_OF_RANGE` accordingly |
| 9 | Relative: `Downloads`, `./x`; Windows: `C:foo`, `\foo` | `PATH_NOT_ABSOLUTE` |
| 10 | Raw-string checks. Invalid: `/a/../b`, `/a/./b`, `/a//b`, `/a/b//`, `~root/x`, a NUL character. Valid: `~/Downloads/` and `/a/b/` (normalised; identical `config_hash` to the no-slash forms). `/` and Windows `C:\` as sources | `PATH_DOT_COMPONENT` ×2, `PATH_EMPTY_COMPONENT` ×2, `PATH_TILDE_USER`, `PATH_INVALID_CHARS`; valid forms accepted; anchor-only sources lexically valid, failing containment. Asserts nothing invalid was silently normalised into a valid config |
| 11 | Windows flavor: `\\srv\share\x`, `//srv/x`, `\\?\C:\x` | `PATH_NETWORK_UNSUPPORTED` ×3 |
| 12 | Roots: `[]`, `/`, `C:\` (Windows), home itself, a parent of home, duplicate roots | `ROOTS_EMPTY`, `ROOT_TOO_BROAD` ×4, `ROOT_DUPLICATE` |
| 13 | Containment: source outside roots; destination in sibling `/data/downloads-evil` vs root `/data/downloads`; the same path in different case under both flavors | outside-roots errors on POSIX; the case variant accepted on Windows and rejected on POSIX |
| 14 | No conditions; extensions `.pdf` and `tar.gz`; `PDF` | `RULE_NO_CONDITION`, `EXTENSION_INVALID` ×2; `PDF` normalised to `pdf` |
| 15 | Rule names: `Bad Name`, empty, 65 characters, duplicate | `RULE_NAME_INVALID` ×3, `RULE_NAME_DUPLICATE` on the second |
| 16 | Templates: `{name}`, `{ext`, `{modified}`, `{modified:%H}`, `{modified:%Y%B}`, literal `{`, `{modified:%Y/%m}` | `TEMPLATE_UNKNOWN_PLACEHOLDER`, `TEMPLATE_SYNTAX`, `TEMPLATE_BAD_FORMAT` ×3, `TEMPLATE_SYNTAX`, `TEMPLATE_SYNTAX` (the separator splits the placeholder) |
| 17 | Components: `CON`, `con.txt`, `a.`, `a:b`, `a\|b`; byte limits: 255 ASCII characters pass, 256 fail; 85 × `€` (255 bytes) passes, 86 × `€` (258 bytes, only 86 characters) fails | `TEMPLATE_COMPONENT_INVALID` for each failing case |
| 18 | Destination equals source (static) vs `source/{ext}` | `RULE_DESTINATION_IS_SOURCE` for the first; none for the second |
| 19 | **Overlap and chain.** (a) two `pdf` rules, same source, no globs → `RULE_OVERLAP`; (b) add a glob to one → clean; (c) A's static destination equals B's source, both `pdf` → `RULE_CHAIN` warning; (d) same but A `pdf`, B `jpg` → clean; (e) A's destination `Downloads/Archive/2026`, B's source `Downloads` → clean; (f) A's destination `Sorted/{ext}`, B's source `Sorted` → clean | per row; in (c) `config` is still non-`None` |
| 20 | Five independent errors; the same input twice; 60 errors | all five reported, sorted by `(location, code)`, byte-identical on rerun; the large case yields 50 plus `TOO_MANY_ERRORS` |
| 21 | `MISSING_KEY`: absent `[settings]`; absent `settings.roots`; a `[[rule]]` with no `name`, `source` or `destination`; and `roots = []` | `MISSING_KEY` at each location; `ROOTS_EMPTY` for the empty array |

### 8.2 Eighteen model cases

| # | Case | Expected |
|---|---|---|
| M1 | `Fingerprint` with `dev=0`, `ino=0`, `nlink=0`, `size=-1`; `CONTENT` without hash; `METADATA` with a hash; uppercase or short hash; `bool` or `str` in an int field | `ValueError` each |
| M2 | `Fingerprint.matches` when only `nlink` differs; when only `mtime_ns` differs; METADATA vs CONTENT | `False` each |
| M3 | `PlannedOperation` whose fingerprint has `nlink=2`; `dst == src`; `src` not inside `src_root`; `dst` not inside `dst_root`; relative or mixed-flavor roots | `ValueError` each |
| M4 | Two plans with identical operations but different `unplanned` | different `plan_id` |
| M5 | Same plan, different `created_at_ns` | identical `plan_id` |
| M6 | Same plan, different `config_hash` | different `plan_id` |
| M7 | Wrong `plan_id`; undo plan with a `config_hash`; organize plan with `derived_from_run`; empty operation list; non-contiguous `seq` | `ValueError` each |
| M8 | `portable_key`: `é` composed vs decomposed; `Straße` vs `STRASSE`; `A.PDF` vs `a.pdf`; `a.pdf` vs `b.pdf` | first three pairs equal; last pair different |
| M9 | Plan with two destinations whose `portable_key` collide; stored path keeps original spelling | `ValueError`; spelling preserved |
| M10 | **Exhaustive** `(from × to × cause × reason)` over all enum values | the legal set equals exactly the **14 tuples** below, each written out in the test (not generated from grouped rows); every other element of the full product is rejected |
| M11 | `OperationRecord` / `Run` invariants: each failing combination in §3.3, including cause rules (`PENDING` with a cause; terminal state without one) | `ValueError` each |
| M12 | Golden values: `config_hash` and `plan_id` for fixed synthetic `PurePosixPath` and `PureWindowsPath` inputs (regenerate whenever the canonical JSON changes) | committed constants |
| M13 | `DONE` accepts reasons `None`, `RECOVERED`, `RECOVERED_METADATA_ONLY` only; `verifies_content` follows the method | per statement |
| M14 | Mixed path flavors in one `Plan`, `Snapshot` or `Config`; relative paths; `UNDO_RULE` on an organize plan; an undo plan with an ordinary rule name; duplicate, out-of-source or entry-overlapping skipped entries | `ValueError` each |
| M15 | `config_hash`: unchanged by reordering rules, roots, extensions and exclusions and by a trailing slash; **changed** by a case-only change to a path or a glob and by editing a destination; a wrong `config_hash` rejected | per statement |
| M16 | `containing_root`: nested roots pick the most specific; a path equal to a root is contained; a path in none returns `None`; a sibling-prefix path is not contained | per statement |
| M17 | `classify_recovery` exhaustive over `Observation × Observation × FpMethod`, including `ROOT_CHANGED` | only (`ABSENT`, `MATCHES_PLAN`) → `DONE` (`RECOVERED` for CONTENT, `RECOVERED_METADATA_ONLY` for METADATA) and (`MATCHES_PLAN`, `ABSENT`) → `SKIPPED` (`NOT_STARTED`); everything else, `ROOT_CHANGED` included → `UNRESOLVED` (`AMBIGUOUS_OBSERVATION`) |
| M18 | Root identity: changing only `src_root_id` or only `dst_root_id` changes `plan_id`; a zero `dev` or `ino` raises `ValueError`; two operations with equal root paths but different identities in one plan raise `ValueError`; changing only a root path changes `plan_id` | per statement |

**The 14 legal transition tuples (M10):**

| # | `(from, to, cause, reason)` |
|---|---|
| 1 | `(PENDING, ATTEMPTING, EXECUTION, None)` |
| 2 | `(ATTEMPTING, DONE, EXECUTION, None)` |
| 3–6 | `(ATTEMPTING, FAILED, EXECUTION, r)` for `r` in `DESTINATION_EXISTS`, `SOURCE_MISSING`, `NOREPLACE_UNSUPPORTED`, `PATH_UNSAFE` |
| 7–8 | `(ATTEMPTING, UNRESOLVED, EXECUTION, r)` for `r` in `UNEXPECTED_ERROR`, `POST_MOVE_MISMATCH` |
| 9 | `(PENDING, SKIPPED, ABORT, RUN_ABORTED)` |
| 10 | `(PENDING, SKIPPED, RECOVERY, RUN_INTERRUPTED)` |
| 11 | `(ATTEMPTING, SKIPPED, RECOVERY, NOT_STARTED)` |
| 12–13 | `(ATTEMPTING, DONE, RECOVERY, r)` for `r` in `RECOVERED`, `RECOVERED_METADATA_ONLY` |
| 14 | `(ATTEMPTING, UNRESOLVED, RECOVERY, AMBIGUOUS_OBSERVATION)` |

### 8.3 Root-module cases

`test_project.py` covers `project.py` (§18): `version_string`, `main` with `--version`, and `main` with no arguments. At the end of M1 it also covers `load_rules`.

### 8.4 Meta-tests

1. The set of codes produced by the configuration suite equals the catalogue minus the reserved `ENV_*` codes.
2. No module in M1 defines a name `Literal`, and the model module does not import `typing.Literal`.
3. `parse_config` purity: with `open`, `os.stat`, `os.listdir`, `os.scandir` and `Path.resolve` patched to raise, every configuration case still passes; the M1 modules import no `sqlite3`, `ctypes` or `subprocess`.

## 9. M1 acceptance criteria

M1 is complete when all of these hold on the CI matrix (Windows and Linux × Python 3.11 and newest):

1. Every dataclass and enum in §3.1 exists as specified (frozen, `slots`, declared fields, value casing per §2.6). Later field changes require a spec amendment first.
2. Every invariant in §3.3 has a failing-construction test raising `ValueError` (M1, M3, M7, M9, M11, M14, M15, M18).
3. `parse_config` is pure (meta-test 3).
4. The catalogue meta-test passes (meta-test 1).
5. The 21 configuration cases and 18 model cases pass. Case 3 respects the 3.14 line/column rule on every interpreter in the matrix.
6. The flavor matrix passes: the same inputs parsed as POSIX and as Windows on both CI machines.
7. Determinism: identical input gives byte-identical issues and an identical `config_hash`; the golden values in M12 are committed.
8. The transition table (M10, all 14 tuples) and the recovery classification (M17) are exhaustive.
9. `load_config(path)` covers the four `CONFIG_*` file errors using `tmp_path`.
10. **Nothing from M2 leaks in:** no scanning, matching, rendering, fingerprinting, content hashing or SQLite. M1 contains types, validation, canonical hashing, `portable_key`, `containing_root`, `transition` and `classify_recovery`.
11. A CI workflow exists for the matrix above. It contains no filesystem tests yet; M3 adds identity and no-replace checks.
12. The repository contains `docs/SPEC.md` (this document).
13. The root `project.py` exposes `main()` and `load_rules()` (the latter delegating to `load_config`), and `test_project.py` tests them.

M1 is **ready for M2** when these pass and Part I is signed off as frozen.

---

# Part II — System design

## 10. State machines

**Plans have no state.** "Applied" is derived from whether a run references the plan, so plan rows are never updated.

**Operation state** (one record per operation per run). Transitions are exactly the 14 tuples in §3.5.

```
pending ──▶ attempting ──▶ done
   │            ├─────────▶ failed       (refused safely; nothing changed)
   │            └─────────▶ unresolved   (unexpected error / post-move mismatch / ambiguous)
   └──────────────────────▶ skipped      (never attempted)
(recovery may also take attempting ─▶ skipped | done | unresolved)
```

**Run state**

```
(preflight refuses) ─▶ no run row is created
running ──▶ finished   all operations terminal, process alive
running ──▶ aborted    unexpected error, unsupported no-replace or post-move mismatch stopped the run, process alive
running ──▶ (process dies) ──▶ recover ──▶ finished (recovered_at set)
```

A run in `running` while no process holds the lock means *interrupted*. The outcome is derived, not stored: *success* means every operation is `done`; anything else is *partial*, with counts.

**Executor policy**

1. **Preflight is all-or-nothing.** If any operation's source fingerprint (full comparison including `nlink`; SHA-256 for content fingerprints) or destination state no longer matches the plan, `apply` refuses with exit 3 and creates no run. Preflight also verifies that every distinct persisted root exists, is a directory, and still has its recorded identity (§7.8). There is no `--skip-stale` in v1.
2. Run start: one transaction inserts the run and every operation as `pending`.
3. Per operation: transition `pending → attempting` and **commit before** touching the filesystem. Then run the D4 checks on both chains and both root identities using the persisted roots, create missing directories, run the pre-rename stat check (§7.1), and perform the move. **Then verify the destination:** a fresh `os.stat(dst, follow_symlinks=False)` must be a regular file that `matches` the planned fingerprint. For `CONTENT` fingerprints this recomputes SHA-256 from the destination; for `METADATA` fingerprints it has the documented metadata-only strength. A match commits `done` (with any `created_dirs` rows). A mismatch, a non-regular file or an unreadable destination commits **`unresolved` with `POST_MOVE_MISMATCH`**, and the run aborts per step 5. Switchyard never tries to move anything back. A crash between the rename and this commit is reconciled by recovery (§11).
4. A *safe* per-operation failure (`DESTINATION_EXISTS`, `SOURCE_MISSING`, `PATH_UNSAFE`) marks the operation `failed` and the run continues, since the moves are independent.
5. `NOREPLACE_UNSUPPORTED`, `POST_MOVE_MISMATCH` or an *unexpected* error marks the operation per the transition table, **aborts the run**, preserves completed operations and marks the remaining `pending` operations `skipped` (`RUN_ABORTED`, cause `ABORT`).
6. There is **no automatic rollback** of completed operations when a later one fails. The user runs `undo`. The README must say so.

## 11. Recovery

**Recovery never moves, deletes or creates anything on the managed filesystem.** It reads the disk and updates the journal. It is therefore incapable of making a run worse.

For a run in `running` whose lock is not held:

1. Every `pending` operation → `skipped` (`RUN_INTERRUPTED`, cause `RECOVERY`), without observation.
2. Every `attempting` operation (at most one, since execution is sequential) is observed. First, each persisted root's identity is checked (§7.8); a path under a root whose identity does not match, or that is missing, is not traversed and is observed as `ROOT_CHANGED`. Otherwise the source and destination are each classified as an `Observation` against the **planned fingerprint**, recomputing the SHA-256 for content fingerprints (§7.3). Then:

| Source observation | Destination observation | Result |
|---|---|---|
| `ABSENT` | `MATCHES_PLAN` | `DONE`: `RECOVERED` (content-verified) or `RECOVERED_METADATA_ONLY` |
| `MATCHES_PLAN` | `ABSENT` | `SKIPPED` (`NOT_STARTED`) |
| anything else | anything else | `UNRESOLVED` (`AMBIGUOUS_OBSERVATION`), recording both observations in `UnresolvedOp` |

"Anything else" includes: both paths present, even if both match; the source replaced by a different file; the destination different; either path not a regular file; either unreadable; both absent; either root's identity differs from the plan (`ROOT_CHANGED`). Recovery never guesses.

3. The run becomes `finished` with `recovered_at` set. A run with unresolved operations is reported as recovered **with unresolved operations**, never as complete.

An operation observed as `MATCHES_PLAN` means: the fresh `os.stat` fingerprint equals the planned one via `Fingerprint.matches`, including `dev`, `ino` and `nlink`. A filesystem that changes `st_ino` on rename therefore yields `UNRESOLVED`, which is the safe direction.

## 12. Undo

- `undo RUN_ID` builds and **stores** an undo plan (`kind = UNDO`, `derived_from_run`, `config_hash = None`); executing it is a separate `apply`. Only `apply` changes user files.
- The undo plan reverses the run's `done` operations, in reverse sequence, as `dst → src` moves with `rule_name = "(undo)"`.
- Each undo operation **swaps** the original's `src`/`dst`, `src_root`/`dst_root` **and** `src_root_id`/`dst_root_id`. Directory-chain checks, containing-root boundaries, root-identity checks and post-move verification therefore run from the persisted roots, and an undo works even if the configuration file has been edited or deleted.
- An operation is planned only if the file is at `dst` with the recorded fingerprint (content-verified by SHA-256 when the fingerprint is `CONTENT`; metadata-only, **flagged as such**, otherwise; `nlink == 1`) and the original path is free. Otherwise it is unplanned: `MODIFIED`, `MISSING` or `ORIGINAL_PATH_OCCUPIED`. If a recorded root's current identity differs, the affected files are unplanned as `ROOT_CHANGED`.
- It never overwrites or deletes user data. Modified files are left in place and reported.
- Undoing an undo run is valid and is redo.
- Directories created by the original run are left in place (D7).

## 13. Journal schema

```sql
PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;

CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);          -- schema_version

CREATE TABLE plans (
  plan_id TEXT PRIMARY KEY,                                            -- full sha256 hex
  kind TEXT NOT NULL CHECK (kind IN ('organize','undo')),
  config_hash TEXT,                                                    -- NULL iff undo
  created_at_ns INTEGER NOT NULL,
  derived_from_run INTEGER REFERENCES runs(run_id),
  CHECK ((kind = 'undo') = (derived_from_run IS NOT NULL)),
  CHECK ((kind = 'undo') = (config_hash IS NULL))
);

CREATE TABLE plan_ops (
  plan_id TEXT NOT NULL REFERENCES plans(plan_id),
  seq INTEGER NOT NULL,
  src TEXT NOT NULL, dst TEXT NOT NULL, dst_key TEXT NOT NULL,         -- portable_key(dst)
  src_root TEXT NOT NULL, dst_root TEXT NOT NULL,
  src_root_dev INTEGER NOT NULL, src_root_ino INTEGER NOT NULL,
  dst_root_dev INTEGER NOT NULL, dst_root_ino INTEGER NOT NULL,
  rule_name TEXT NOT NULL,
  fp_dev INTEGER NOT NULL, fp_ino INTEGER NOT NULL, fp_nlink INTEGER NOT NULL,
  fp_size INTEGER NOT NULL, fp_mtime_ns INTEGER NOT NULL, fp_sha256 TEXT,
  fp_method TEXT NOT NULL CHECK (fp_method IN ('content','metadata')),
  CHECK ((fp_method = 'content') = (fp_sha256 IS NOT NULL)),
  CHECK (fp_nlink = 1),
  CHECK (src_root_dev >= 1 AND src_root_ino >= 1
         AND dst_root_dev >= 1 AND dst_root_ino >= 1),
  PRIMARY KEY (plan_id, seq),
  UNIQUE (plan_id, src), UNIQUE (plan_id, dst_key)
);

CREATE TABLE plan_unplanned (
  plan_id TEXT NOT NULL REFERENCES plans(plan_id),
  src TEXT NOT NULL, reason TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (plan_id, src)
);

CREATE TABLE runs (
  run_id INTEGER PRIMARY KEY AUTOINCREMENT,
  plan_id TEXT NOT NULL REFERENCES plans(plan_id),
  state TEXT NOT NULL CHECK (state IN ('running','finished','aborted')),
  started_at_ns INTEGER NOT NULL, finished_at_ns INTEGER,
  recovered_at_ns INTEGER, abort_reason TEXT
);
CREATE UNIQUE INDEX one_active_run ON runs((1)) WHERE state = 'running';
CREATE INDEX runs_by_plan ON runs(plan_id);

CREATE TABLE op_records (
  run_id INTEGER NOT NULL REFERENCES runs(run_id),
  seq INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN
    ('pending','attempting','done','failed','skipped','unresolved')),
  cause TEXT CHECK (cause IN ('execution','recovery','abort')),
  reason TEXT,
  attempted_at_ns INTEGER, finished_at_ns INTEGER,
  CHECK ((state = 'pending') = (cause IS NULL)),
  PRIMARY KEY (run_id, seq)
);

CREATE TABLE created_dirs (
  run_id INTEGER NOT NULL REFERENCES runs(run_id),
  path TEXT NOT NULL, PRIMARY KEY (run_id, path)
);
```

- **Immutability.** Optional triggers `RAISE(ABORT)` on `UPDATE` or `DELETE` of `plans`, `plan_ops` and `plan_unplanned`. Transition legality lives in `LEGAL_TRANSITIONS`, not in SQL.
- **`op_records` stores the cause and reason of the latest transition only.** There is no event history; the journal is immutable plans plus validated state transitions, not event sourcing.
- **One active run** is enforced by the partial unique index, and additionally by an OS file lock (`fcntl.flock` / `msvcrt.locking`) held for the process lifetime. A dead process releases the lock automatically, and a PID file would go stale. "Process alive" and "run unfinished" are separate facts; `recover` needs that distinction.
- **Transactions** use explicit `BEGIN IMMEDIATE`: one for `plan`; one for run start; two per operation (intent before the move, outcome after verification); one for run finish.
- A loaded plan is rebuilt through the `Plan` constructor, which recomputes `plan_id` and rejects damage.

## 14. CLI contract

Global options: `--config PATH` (default `./switchyard.toml`), `--db PATH` (default `~/.switchyard/journal.db`).

| Command | Behaviour | Writes |
|---|---|---|
| `check` | Validate the config; report all issues; warn about missing sources and about control files inside a source (`ENV_CONTROL_FILE_IN_SOURCE`); check that the no-replace primitive exists; show built-in exclusions | nothing |
| `plan [--rule NAME]` | Scan, match, fingerprint, finalise, store. Evaluates **all** rules and detects conflicts before applying `--rule` (§6). Prints operations (with verification strength), unplanned files with reasons, and the plan id. An empty plan prints "nothing to do" and is not stored | journal |
| `apply PLAN_ID [--yes]` | Show a summary and the plan id; prompt unless `--yes`; a non-interactive session without `--yes` refuses. Preflight, then execute. Ids accept a unique prefix of 8+ characters | files, journal |
| `history [RUN_ID] [--limit N]` | List runs, or show one run's operations, causes, reasons and verification strength | nothing |
| `undo RUN_ID` | Build and **store** an undo plan; print it. Executing is a separate `apply` | journal |
| `explain PATH` | For one file: excluded? Each rule matched or not, with the first failing condition; conflicts; settled age; any history of the file | nothing |
| `recover [RUN_ID]` | Reconcile an interrupted run by observation (§11). Never moves files | journal |

**Only `apply` changes managed files.** One approval path, one executor. Approval is bound to a plan id covering the whole proposal.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | internal error (a bug) |
| 2 | usage or configuration error |
| 3 | refused by a precondition; nothing changed |
| 4 | finished, but some operations `failed`, `skipped` or `unresolved` |
| 130 | interrupted (Ctrl-C); the message says to run `recover` |

**Important error cases:** `apply` with an unfinished run → 3, "run `recover` first"; lock held by another process → 3; stale plan at preflight → 3 listing each mismatching file; a persisted root missing or changed (`ENV_ROOT_MISSING`, `ENV_ROOT_CHANGED`) → 3; unknown or ambiguous plan id prefix → 3; plan over `max_operations` → `plan` exits 3 and stores nothing; unknown `--rule` name → 2; no-replace unsupported on a filesystem → operation `failed` (`NOREPLACE_UNSUPPORTED`) and the run aborts; source and destination on different devices → `CROSS_DEVICE` at planning and again at preflight.

## 15. System acceptance criteria

| ID | Requirement | How tested |
|---|---|---|
| C1 | Invalid config yields all errors with locations and codes, never a partial `Config` | M1 |
| C2 | Unknown keys, conditionless rules and out-of-root paths are rejected | M1 |
| P1 | `plan()` finalisation is pure: same snapshot, fingerprints, rules and clock give the same plan id | unit, run twice |
| P2 | Plan ids are deterministic across runs and Python versions (not across operating systems) | golden values |
| P3 | Each `UnplannedReason` is produced by a specific input, with a deterministic, time-independent detail | one test per code; same snapshot at two `now` values on one side of the settled boundary yields one plan id |
| P4 | A file matching two rules is never planned | unit |
| P5 | No destination equals another destination (`portable_key`) or an existing path | property-style |
| P6 | No operation references a path outside its persisted roots, and each root is the most specific containing root | unit |
| P7 | Files with `nlink != 1`, unavailable identity or unavailable link count are never planned | scanner and planner |
| P8 | A file that changes while being fingerprinted is `CHANGED_DURING_PLANNING` | fake-FS race injection |
| P9 | `plan --rule NAME` never plans a file matched by more than one rule; conflicts stay listed | planner and CLI |
| X1 | The config file, database, `-wal`, `-shm`, `-journal` sidecars and lock file are never candidates, even with a `*` glob rule and when they sit inside a managed directory; a hard-link alias of the database is also excluded | fake and real |
| F1 | `move_no_clobber` passes one conformance suite on every strategy | CI on Windows and Linux |
| F2 | When the destination exists, nothing changes: source and destination are byte-identical before and after | F1 plus fake |
| F3 | Where no-replace is unsupported the move fails closed and never falls back to ordinary rename | fake and real `EINVAL` |
| DIR1 | A symlink, junction or reparse point in a destination or source chain below the root is refused | fake and real |
| DIR2 | A directory swapped between preflight and execution fails the operation with `PATH_UNSAFE` | race injection |
| DIR3 | Missing directories are created level by level below the containing root only; the root is never created | fake and real |
| DIR4 | Nested roots select the most specific containing root | M16 plus integration |
| ROOT1 | After planning, retargeting a symlinked root makes `apply` refuse with exit 3 (`ENV_ROOT_CHANGED`), creating no run | fake and real |
| ROOT2 | A root retargeted mid-run fails the next operation with `PATH_UNSAFE` | race injection |
| ROOT3 | Recovery against a changed root yields `UNRESOLVED` and does not traverse it | fake |
| ROOT4 | An undo plan swaps and inherits root identities; with a changed root the affected files are unplanned as `ROOT_CHANGED` | integration |
| E1 | `apply` refuses with exit 3 and creates no run if any operation is stale | integration |
| E2 | Every operation record is terminal when a run finishes | integration |
| E3 | No pre-existing file is overwritten or deleted by any run | fake and real suites |
| E4 | A second active run is impossible (index and lock) | two-process test |
| E5 | If the source name is swapped between the last check and the rename, the operation is recorded `UNRESOLVED` (`POST_MOVE_MISMATCH`), never `DONE`; the run aborts and nothing is moved back | race injection on the fake |
| R1 | **Crash contract.** At every injected crash point, after `recover` (and after any number of further `recover` runs): (1) **content conservation** — each pre-existing file is present, byte-identical, at exactly one path (original, planned destination, or a path recorded unresolved), by construction because the tool only renames, and checked in tests against fixture bytes; (2) no pre-existing file is overwritten or removed; (3) every operation is terminal; (4) recovery is idempotent; (5) **no false success** — no operation is reported `DONE`, at execution or in recovery, unless the observed state matches the plan *at the strength of its fingerprint method*, and the report states that strength | exhaustive fault injection on the in-memory filesystem; E5 for the execution-time half |
| R2 | `recover` performs zero writes to the managed filesystem | the fake records mutations; the test asserts none |
| R3 | Real-process `os._exit` at named crash points leaves a state `recover` reconciles | a handful of subprocess tests |
| R4 | Running `recover` twice changes nothing | R1 loop |
| R5 | Recovery follows the matrix in §11 exactly, including both-paths-present → `UNRESOLVED` | M17 plus integration |
| U1 | `apply` → `undo` → `apply` restores the original tree and contents when nothing was modified | integration |
| U2 | A modified, missing or occupied file is reported and never touched | one test per reason code |
| U3 | Undoing an undo run is valid | integration |
| U4 | `apply` of an undo plan works with the configuration file deleted, using the persisted roots | integration |
| L1 | A third-party change in the check-to-move window is a **documented residual risk**, demonstrated by race-injection hooks and listed in the README | fake-FS test |
| I1 | Applying one plan changes nothing about other plans | unit |
| J1 | Every persisted transition has a legal `(from, to, cause, reason)` | M10 plus journal tests |

**Crash scope** (R1): the Switchyard process dies or raises at an arbitrary point (Ctrl-C, exception, kill) while the filesystem and SQLite stay intact. **Out of scope:** power loss and kernel crashes with unflushed writes; filesystem corruption; a third party modifying a path in the instant between the final check and the move; concurrent Switchyard instances (prevented by the lock).

**Fault-injection points** for R1: before intent; after intent; after directory creation; after the rename; after post-move verification; after the outcome commit — across several scenarios (single operation, multiple operations, a failing operation mid-run, an unsupported no-replace on the first operation).

## 16. Milestones

Each milestone ends with passing tests and depends on nothing later.

| # | Deliverable | Depends on |
|---|---|---|
| **M1** | Repository skeleton (§18); dataclasses, enums, config loader and validator, canonical hashing, `portable_key`, `containing_root`, `transition`, `classify_recovery`; `docs/SPEC.md`; CI skeleton; root `project.py` with `main()` and `load_rules()` (§9) | none |
| **M2** | `FileSystem` port; in-memory fake with fault and race injection; scanner; matching; planner pipeline (§6); runtime-file exclusion (§7.7); phase-2 `ENV_*` checks; root identity capture; deterministic `Unplanned` details; `build_plan()` in `project.py` (P1–P9, X1) | M1 |
| **M3** | Real filesystem: scanning (skip symlinks and reparse points), fingerprinting (§7.2), `move_no_clobber` conformance suite and strategies, directory safety (DIR1–DIR4), root identity (ROOT1), verified Windows behaviour (identity, link count, sharing mode, no-replace) | M2 |
| **M4** | SQLite journal (§13), transition enforcement, executor with post-move verification, preflight, lock (E1–E5, J1, ROOT2); `apply_plan()` in `project.py` | M2, M3 |
| **M5** | Recovery and the exhaustive fault-injection suite (R1, R2, R4, R5, ROOT3) | M4 |
| **M6** | Undo plan generation (U1–U4, ROOT4); `undo_run()` in `project.py` | M4, M5 |
| **M7** | CLI (seven commands, exit codes) and real-process crash tests (R3) | M4–M6 |
| **M8** | README with guarantees and non-guarantees; GitHub Actions (Windows and Linux); `project.py` with `main()` plus at least three top-level functions and `test_project.py` testing at least three of them; optional `rmdir` cleanup as a second operation kind | all |

Do not build the CLI early to "see something work", and do not start real-filesystem strategies before the fake exists. The fake is what makes M5 possible.

## 17. Known limitations and non-guarantees

State these in the README.

1. Only process-level crashes are covered (§15). Power loss, kernel crashes and filesystem corruption are out of scope.
2. A third party that changes the source file or a parent directory in the window between the final check and the rename is not prevented. On Linux the fd-relative walk (D5) closes directory-swap windows; the swap of the final source *name* and, on Windows, the directory-swap window, remain documented residuals. Post-move verification (§10 step 3) detects many of these swaps after the fact and reports the operation `UNRESOLVED`; it does not prevent them.
3. Fingerprint consistency is best-effort (§7.2). Files above 64 MiB are verified by metadata only (§7.3).
4. There is no automatic rollback of completed operations; use `undo`.
5. Recovery never resumes. An interrupted run's unfinished work is re-planned, not resumed.
6. Created directories are left in place, including after undo.
7. Network and cloud-synced filesystems, FAT-family filesystems and macOS are outside the supported claims. A filesystem that cannot give stable identity or `RENAME_NOREPLACE` produces refusals or `UNRESOLVED` operations, never silent overwrites.
8. Files whose names begin with a dot, in-progress downloads (`*.part`, `*.crdownload`, `*.tmp`) and Switchyard's own control files are never moved.
9. Dates in destination paths use the machine's local zone at plan time (`local`) or UTC.
10. `portable_key` is a conservative approximation of filesystem collision rules, not an exact model of any one filesystem.
11. A symlinked root is supported only while its target does not change after planning (§7.8).

## 18. Repository layout

```
<repo>/
├── project.py              CS50P-shaped entry point: main() plus top-level functions
│                           (load_rules M1, build_plan M2, apply_plan M4, undo_run M6)
├── test_project.py         tests for the root functions (at least three by M8)
├── requirements.txt        pytest>=7.0 (no runtime dependencies)
├── pytest.ini              pythonpath = . ; testpaths = tests test_project.py
├── README.md               written in M8
├── .gitignore
├── docs/
│   └── SPEC.md             this document
├── switchyard/
│   ├── __init__.py         __version__
│   ├── models.py           enums, DirIdentity, Fingerprint, and the rest of §3.1
│   ├── config.py           parse_config, load_config, path/template/duration parsing
│   ├── canonical.py        compute_config_hash, compute_plan_id, portable_key, containing_root
│   ├── transitions.py      LEGAL_TRANSITIONS, transition, classify_recovery
│   ├── scanner.py          M2/M3
│   ├── planner.py          M2
│   ├── filesystem.py       port, real and in-memory implementations (M2/M3)
│   ├── journal.py          SQLite journal (M4)
│   ├── executor.py         preflight and execution (M4)
│   ├── recovery.py         M5
│   ├── undo.py             M6
│   └── cli.py              M7
└── tests/
    ├── test_models.py
    ├── test_config.py
    ├── test_canonical.py
    ├── test_transitions.py
    └── ...                 planner, filesystem, journal, recovery, undo, cli
```

`project.py` stays thin: it imports from the `switchyard` package and holds only the top-level functions the CS50P structure requires. All logic and most tests live in the package and in `tests/`.