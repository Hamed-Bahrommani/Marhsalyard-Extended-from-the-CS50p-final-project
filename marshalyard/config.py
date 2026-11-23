"""Configuration parsing, step 3: durations and raw-string paths (spec 4.2, 4.3).

These helpers raise FieldError with a stable catalogue code. The future
parse_config turns each FieldError into an Issue with a TOML location.
"""

import fnmatch
import re
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
import tomllib

from marshalyard.canonical import compute_config_hash, containing_root
from marshalyard.models import (
    MODIFIED_FORMAT_RE,
    AbsPath,
    DestinationTemplate,
    ExtToken,
    Flavor,
    ModifiedToken,
    TextToken,
    Token,
    Issue,
    Severity,
    ValidationResult,
    Config,
    Timezone,
    Rule,
)


class FieldError(Exception):
    """A user-input problem with one config value. `code` is a catalogue code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# ---------------------------------------------------------------- durations

_DURATION_RE = re.compile(r"([0-9]+)([smhd])")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
MAX_DURATION_S = 3650 * 86400


def parse_duration(text: str) -> int:
    """'10m' -> 600. One integer and one lowercase unit (s, m, h, d); max 3650d.

    Callers check that the TOML value is a string first (a TOML integer is a
    WRONG_TYPE problem, not a duration problem).
    """
    match = _DURATION_RE.fullmatch(text)
    if match is None:
        raise FieldError(
            "DURATION_INVALID",
            f"{text!r} is not a duration; use one integer and one unit, e.g. 10m, 2h, 7d",
        )
    digits = match.group(1).lstrip("0") or "0"
    if len(digits) > 12:  # also keeps int() away from absurdly long strings
        raise FieldError("DURATION_OUT_OF_RANGE", f"{text!r} is longer than 3650d")
    seconds = int(digits) * _UNIT_SECONDS[match.group(2)]
    if seconds > MAX_DURATION_S:
        raise FieldError("DURATION_OUT_OF_RANGE", f"{text!r} is longer than 3650d")
    return seconds


# ---------------------------------------------------------------- paths

_WINDOWS_DRIVE_RE = re.compile(r"[A-Za-z]:[\\/]")


@dataclass(frozen=True, slots=True)
class SplitPath:
    """A validated path before any PurePath is built: anchor plus components."""

    anchor: str
    components: tuple[str, ...]


def _separators(flavor: Flavor) -> str:
    return "/\\" if flavor is Flavor.WINDOWS else "/"


def _split_components(body: str, flavor: Flavor) -> tuple[str, ...]:
    """Split the part after the anchor. One trailing separator is allowed."""
    if body == "":
        return ()
    seps = _separators(flavor)
    if body[-1] in seps and len(body) > 1:
        body = body[:-1]  # exactly one trailing separator is discarded
    if flavor is Flavor.WINDOWS:
        body = body.replace("\\", "/")
    parts = body.split("/")
    for part in parts:
        if part == "":
            raise FieldError("PATH_EMPTY_COMPONENT", "path has an empty component (repeated or trailing separators)")
        if part in (".", ".."):
            raise FieldError("PATH_DOT_COMPONENT", "path contains a '.' or '..' component")
    return tuple(parts)


def _require_home(home: AbsPath, flavor: Flavor) -> None:
    expected = PureWindowsPath if flavor is Flavor.WINDOWS else PurePosixPath
    if type(home) is not expected or not home.is_absolute():
        raise ValueError("home must be an absolute path of the same flavor as the config")


def split_path(raw: str, flavor: Flavor, home: AbsPath) -> SplitPath:
    """Validate the raw string and split it. Runs BEFORE any PurePath exists,
    because PurePath silently collapses repeated separators and '.' components."""
    if raw == "":
        raise FieldError("PATH_EMPTY", "path is empty")
    if any(ord(ch) < 0x20 for ch in raw):
        raise FieldError("PATH_INVALID_CHARS", "path contains a control character")
    seps = _separators(flavor)

    if raw[0] == "~":
        if len(raw) > 1 and raw[1] not in seps:
            raise FieldError("PATH_TILDE_USER", "'~user' is not supported; use '~' or '~/...'")
        _require_home(home, flavor)
        relative = raw[2:] if len(raw) > 1 else ""
        return SplitPath(home.anchor, home.parts[1:] + _split_components(relative, flavor))

    if flavor is Flavor.POSIX:
        if raw[0] != "/":
            raise FieldError("PATH_NOT_ABSOLUTE", "path must be absolute")
        return SplitPath("/", _split_components(raw[1:], flavor))

    # Windows flavor
    if len(raw) >= 2 and raw[0] in seps and raw[1] in seps:
        raise FieldError("PATH_NETWORK_UNSUPPORTED", "network (UNC) paths are not supported")
    if _WINDOWS_DRIVE_RE.match(raw) is None:
        raise FieldError("PATH_NOT_ABSOLUTE", "path must be absolute, e.g. C:\\Users\\...")
    return SplitPath(raw[0] + ":\\", _split_components(raw[3:], flavor))


def parse_path(raw: str, flavor: Flavor, home: AbsPath) -> AbsPath:
    """Validate a path string and build the pure path for the given flavor."""
    split = split_path(raw, flavor, home)
    path_type = PureWindowsPath if flavor is Flavor.WINDOWS else PurePosixPath
    return path_type(split.anchor, *split.components)


# ---------------------------------------------------------------- names, extensions, globs

_RULE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_EXTENSION_RE = re.compile(r"[a-z0-9_+-]{1,16}")


def check_rule_name(name: str) -> str:
    """Rule names are lowercase slugs. The reserved '(undo)' fails this pattern."""
    if _RULE_NAME_RE.fullmatch(name) is None:
        raise FieldError(
            "RULE_NAME_INVALID",
            f"{name!r} is not a valid rule name; use 1-64 characters from a-z, 0-9, '_' and '-', starting with a letter or digit",
        )
    return name


def normalise_extension(text: str) -> str:
    """'PDF' -> 'pdf'. No dot, ASCII only, 1-16 characters from a-z 0-9 _ + -."""
    lowered = text.lower()
    if not text.isascii() or _EXTENSION_RE.fullmatch(lowered) is None:
        raise FieldError(
            "EXTENSION_INVALID",
            f"{text!r} is not a valid extension; write it without a dot, e.g. 'pdf' "
            "(for 'tar.gz' use name_glob = '*.tar.gz')",
        )
    return lowered


def dedupe(items):
    """Remove duplicates, keeping first-seen order."""
    return tuple(dict.fromkeys(items))


def file_extension(name: str) -> str | None:
    """Text after the LAST dot, lowercased, if that dot is neither the first
    nor the last character. 'a.tar.gz' -> 'gz'; '.bashrc' and 'file.' -> None."""
    index = name.rfind(".")
    if index <= 0 or index == len(name) - 1:
        return None
    return name[index + 1 :].lower()


def check_glob(pattern: str, code: str = "GLOB_INVALID") -> str:
    """Validate a file-name glob. Used for name_glob and settings.exclude.

    No separators on any platform, no control characters, and every '[' must
    have a closing ']'. The caller chooses the catalogue code.
    """
    if pattern == "":
        raise FieldError(code, "pattern is empty")
    if any(ch in "/\\" or ord(ch) < 0x20 for ch in pattern):
        raise FieldError(code, f"{pattern!r} must not contain path separators or control characters")
    i, n = 0, len(pattern)
    while i < n:
        if pattern[i] == "[":
            j = i + 1
            if j < n and pattern[j] == "!":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                raise FieldError(code, f"{pattern!r} has an unclosed '['")
            i = j + 1
        else:
            i += 1
    return pattern


def glob_matches(pattern: str, name: str) -> bool:
    """Case-insensitive on every OS: both sides casefolded, then fnmatchcase."""
    return fnmatch.fnmatchcase(name.casefold(), pattern.casefold())


# ---------------------------------------------------------------- portable names

MAX_COMPONENT_BYTES = 255
_FORBIDDEN_NAME_CHARS = frozenset('<>:"|?*/\\')
# Reserved Windows device names (with or without an extension). The superscript
# digits are reserved on recent Windows versions too.
_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{d}" for d in "123456789\u00b9\u00b2\u00b3"}
    | {f"LPT{d}" for d in "123456789\u00b9\u00b2\u00b3"}
)


def check_portable_component(name: str) -> str:
    """The portable-name rule for one literal template component (spec 4.4).

    Applied on every platform: a directory name that is unusable on Windows is
    rejected even when the config runs on Linux.
    """
    code = "TEMPLATE_COMPONENT_INVALID"
    if name == "":
        raise FieldError(code, "empty path component")
    if len(name.encode("utf-8", "surrogatepass")) > MAX_COMPONENT_BYTES:
        raise FieldError(code, f"component is longer than {MAX_COMPONENT_BYTES} bytes in UTF-8")
    for ch in name:
        if ch in _FORBIDDEN_NAME_CHARS or ord(ch) < 0x20:
            raise FieldError(code, f"component {name!r} contains a forbidden character")
    if name[-1] in ". ":
        raise FieldError(code, f"component {name!r} ends with a dot or a space")
    if name.split(".", 1)[0].rstrip(" ").upper() in _RESERVED_NAMES:
        raise FieldError(code, f"component {name!r} is a reserved Windows device name")
    return name


# ---------------------------------------------------------------- destination templates


def _placeholder_token(inner: str) -> Token:
    name, colon, fmt = inner.partition(":")
    if inner == "ext":
        return ExtToken()
    if name == "modified":
        if not colon or MODIFIED_FORMAT_RE.fullmatch(fmt) is None:
            raise FieldError(
                "TEMPLATE_BAD_FORMAT",
                f"'{{{inner}}}' needs a format of %Y, %m, %d, '-' and '_' only, e.g. {{modified:%Y-%m}}",
            )
        return ModifiedToken(fmt)
    raise FieldError(
        "TEMPLATE_UNKNOWN_PLACEHOLDER",
        f"unknown placeholder '{{{inner}}}'; supported: {{ext}} and {{modified:FORMAT}}",
    )


def _tokenise_component(component: str) -> tuple[Token, ...]:
    tokens: list[Token] = []
    text: list[str] = []
    i, n = 0, len(component)
    while i < n:
        ch = component[i]
        if ch == "{":
            close = component.find("}", i + 1)
            if close == -1:
                raise FieldError("TEMPLATE_SYNTAX", f"unclosed '{{' in {component!r}")
            inner = component[i + 1 : close]
            if "{" in inner:
                raise FieldError("TEMPLATE_SYNTAX", f"nested '{{' in {component!r}")
            if text:
                tokens.append(TextToken("".join(text)))
                text = []
            tokens.append(_placeholder_token(inner))
            i = close + 1
        elif ch == "}":
            raise FieldError("TEMPLATE_SYNTAX", f"stray '}}' in {component!r}")
        else:
            text.append(ch)
            i += 1
    if text:
        tokens.append(TextToken("".join(text)))
    return tuple(tokens)


def _has_placeholder(tokens: tuple[Token, ...]) -> bool:
    return any(not isinstance(token, TextToken) for token in tokens)


def parse_template(raw: str, flavor: Flavor, home: AbsPath) -> DestinationTemplate:
    """Parse a destination template (spec 4.4).

    Path-level checks come from split_path (raw string first). Placeholders are
    then tokenised per component. `base` is every component before the first one
    containing a placeholder. Components that came from the expanded '~' home
    directory are taken literally and are never scanned for placeholders.
    """
    split = split_path(raw, flavor, home)
    home_count = len(home.parts) - 1 if raw.startswith("~") else 0
    parsed: list[tuple[Token, ...]] = []
    for index, component in enumerate(split.components):
        if index < home_count:
            parsed.append((TextToken(component),))
        else:
            parsed.append(_tokenise_component(component))

    path_type = PureWindowsPath if flavor is Flavor.WINDOWS else PurePosixPath
    first = next((i for i, tokens in enumerate(parsed) if _has_placeholder(tokens)), None)
    if first is None:
        base_parts = [tokens[0].text for tokens in parsed]  # each is exactly one TextToken
        return DestinationTemplate(raw, path_type(split.anchor, *base_parts), ())
    base_parts = [tokens[0].text for tokens in parsed[:first]]
    return DestinationTemplate(raw, path_type(split.anchor, *base_parts), tuple(parsed[first:]))


# ---------------------------------------------------------------- structure check (spec 5.1, S1-S3)

MAX_ISSUES = 50
MAX_RULES = 200
SUPPORTED_VERSION = 1

_TOP_KEYS = frozenset({"version", "settings", "rule"})
_SETTINGS_KEYS = frozenset({"roots", "timezone", "min_age", "max_operations", "exclude"})
_RULE_KEYS = frozenset({"name", "source", "extensions", "name_glob", "min_age", "destination"})
_KIND_TEXT = {"string": "a string", "integer": "an integer", "strings": "an array of strings"}


class _Sink:
    """Collects issues; keeps the first MAX_ISSUES, then one TOO_MANY_ERRORS."""

    def __init__(self) -> None:
        self._issues: list[Issue] = []
        self._overflow = False
        self.has_error = False

    def add(
        self,
        code: str,
        location: str,
        message: str,
        severity: Severity = Severity.ERROR,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        if severity is Severity.ERROR:
            self.has_error = True
        if len(self._issues) >= MAX_ISSUES:
            self._overflow = True
            return
        self._issues.append(Issue(code, location, message, severity, line, column))

    def finish(self) -> tuple[Issue, ...]:
        issues = list(self._issues)
        if self._overflow:
            issues.append(
                Issue("TOO_MANY_ERRORS", "$", f"more than {MAX_ISSUES} issues; fix these first", Severity.ERROR)
            )
        return tuple(sorted(issues, key=lambda issue: (issue.location, issue.code)))


def _is_plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _toml_type(value: object) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "table"
    return "date or time"


def _join(base: str, key: str) -> str:
    return f"{base}.{key}" if base else key


def _check_unknown(sink: _Sink, table: dict, allowed: frozenset[str], base: str) -> None:
    for key in table:
        if key not in allowed:
            location = _join(base, key)
            sink.add("UNKNOWN_KEY", location, f"unknown key '{location}'")


def _check_field(sink: _Sink, table: dict, key: str, base: str, kind: str, required: bool = False) -> None:
    location = _join(base, key)
    if key not in table:
        if required:
            sink.add("MISSING_KEY", location, f"'{location}' is required")
        return
    value = table[key]
    if kind == "string":
        ok = isinstance(value, str)
    elif kind == "integer":
        ok = _is_plain_int(value)
    else:
        ok = isinstance(value, list)
    if not ok:
        sink.add("WRONG_TYPE", location, f"'{location}' must be {_KIND_TEXT[kind]}, got {_toml_type(value)}")
        return
    if kind == "strings":
        for index, item in enumerate(value):
            if not isinstance(item, str):
                where = f"{location}[{index}]"
                sink.add("WRONG_TYPE", where, f"'{where}' must be a string, got {_toml_type(item)}")


def _check_settings(sink: _Sink, data: dict) -> None:
    if "settings" not in data:
        sink.add("MISSING_KEY", "settings", "the [settings] table is required")
        return
    settings = data["settings"]
    if not isinstance(settings, dict):
        sink.add("WRONG_TYPE", "settings", f"'settings' must be a table, got {_toml_type(settings)}")
        return
    _check_unknown(sink, settings, _SETTINGS_KEYS, "settings")
    _check_field(sink, settings, "roots", "settings", "strings", required=True)
    _check_field(sink, settings, "timezone", "settings", "string")
    _check_field(sink, settings, "min_age", "settings", "string")
    _check_field(sink, settings, "max_operations", "settings", "integer")
    _check_field(sink, settings, "exclude", "settings", "strings")


def _check_rules(sink: _Sink, data: dict) -> None:
    if "rule" not in data:
        sink.add("NO_RULES", "rule", "at least one [[rule]] is required")
        return
    rules = data["rule"]
    if not isinstance(rules, list):
        sink.add("WRONG_TYPE", "rule", f"'rule' must be an array of tables ([[rule]]), got {_toml_type(rules)}")
        return
    if not rules:
        sink.add("NO_RULES", "rule", "at least one [[rule]] is required")
        return
    if len(rules) > MAX_RULES:
        sink.add("TOO_MANY_RULES", "rule", f"at most {MAX_RULES} rules are allowed, found {len(rules)}")
    for index, rule in enumerate(rules):
        base = f"rule[{index}]"
        if not isinstance(rule, dict):
            sink.add("WRONG_TYPE", base, f"'{base}' must be a table, got {_toml_type(rule)}")
            continue
        _check_unknown(sink, rule, _RULE_KEYS, base)
        _check_field(sink, rule, "name", base, "string", required=True)
        _check_field(sink, rule, "source", base, "string", required=True)
        _check_field(sink, rule, "destination", base, "string", required=True)
        _check_field(sink, rule, "extensions", base, "strings")
        _check_field(sink, rule, "name_glob", base, "string")
        _check_field(sink, rule, "min_age", base, "string")


def _structure(text: str, sink: _Sink) -> dict | None:
    """S1-S3. Returns the parsed table, or None if parsing must stop."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        line = getattr(exc, "lineno", None)
        column = getattr(exc, "colno", None)
        sink.add(
            "TOML_SYNTAX",
            "$",
            str(exc) or "invalid TOML",
            line=line if _is_plain_int(line) else None,
            column=column if _is_plain_int(column) else None,
        )
        return None

    if "version" not in data:
        sink.add("VERSION_MISSING", "version", "'version' is required; this tool supports version = 1")
        return None
    version = data["version"]
    if not _is_plain_int(version) or version != SUPPORTED_VERSION:
        sink.add("VERSION_UNSUPPORTED", "version", f"unsupported version {version!r}; supported: {SUPPORTED_VERSION}")
        return None

    _check_unknown(sink, data, _TOP_KEYS, "")
    _check_settings(sink, data)
    _check_rules(sink, data)
    return data


def check_structure(text: str) -> tuple[Issue, ...]:
    sink = _Sink()
    _structure(text, sink)
    return sink.finish()

# ---------------------------------------------------------------- value checks and assembly (S3 values, S4)

BUILTIN_EXCLUDES = ("*.part", "*.crdownload", "*.tmp", "desktop.ini", ".*")
MAX_ROOTS = 20
MAX_OPERATIONS_LIMIT = 100000
DEFAULT_MAX_OPERATIONS = 2000
DEFAULT_MIN_AGE = "10m"


def _report(sink: _Sink, exc: FieldError, location: str, code: str | None = None) -> None:
    detail = getattr(exc, "message", None) or str(exc) or "invalid value"
    sink.add(code or exc.code, location, f"{location}: {detail}")


def _opt_str(table: dict, key: str) -> str | None:
    value = table.get(key)
    return value if isinstance(value, str) else None


def _opt_strs(table: dict, key: str) -> list[str] | None:
    value = table.get(key)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None


def _read_roots(sink: _Sink, raw_roots: list[str], flavor: Flavor, home: AbsPath) -> tuple[list[AbsPath], bool]:
    if not raw_roots:
        sink.add("ROOTS_EMPTY", "settings.roots", "at least one root is required")
        return [], False
    if len(raw_roots) > MAX_ROOTS:
        sink.add("ROOTS_TOO_MANY", "settings.roots", f"at most {MAX_ROOTS} roots are allowed, found {len(raw_roots)}")
    roots: list[AbsPath] = []
    clean = True
    for index, raw in enumerate(raw_roots):
        location = f"settings.roots[{index}]"
        try:
            path = parse_path(raw, flavor, home)
        except FieldError as exc:
            _report(sink, exc, location)
            clean = False
            continue
        if len(path.parts) == 1 or path == home or home.is_relative_to(path):
            sink.add("ROOT_TOO_BROAD", location, f"{location}: a root may not be a filesystem root, the home directory, or its ancestor")
        if path in roots:
            sink.add("ROOT_DUPLICATE", location, f"{location}: duplicate root")
            clean = False
            continue
        roots.append(path)
    return roots, clean


def _read_settings(sink: _Sink, data: dict, flavor: Flavor, home: AbsPath) -> dict:
    out: dict = {
        "roots": [],
        "roots_clean": False,
        "timezone": None,
        "min_age_s": None,
        "max_operations": None,
        "exclude": None,
    }
    settings = data.get("settings")
    if not isinstance(settings, dict):
        return out

    raw_roots = _opt_strs(settings, "roots")
    if raw_roots is not None:
        out["roots"], out["roots_clean"] = _read_roots(sink, raw_roots, flavor, home)

    if "timezone" in settings:
        value = _opt_str(settings, "timezone")
        if value is not None:
            try:
                out["timezone"] = Timezone(value)
            except ValueError:
                sink.add("TIMEZONE_INVALID", "settings.timezone", "settings.timezone must be 'local' or 'utc'")
    else:
        out["timezone"] = Timezone("local")

    min_age = settings.get("min_age", DEFAULT_MIN_AGE)
    if isinstance(min_age, str):
        try:
            out["min_age_s"] = parse_duration(min_age)
        except FieldError as exc:
            _report(sink, exc, "settings.min_age")

    if "max_operations" in settings:
        value = settings["max_operations"]
        if _is_plain_int(value):
            if 1 <= value <= MAX_OPERATIONS_LIMIT:
                out["max_operations"] = value
            else:
                sink.add(
                    "MAX_OPERATIONS_OUT_OF_RANGE",
                    "settings.max_operations",
                    f"settings.max_operations must be between 1 and {MAX_OPERATIONS_LIMIT}",
                )
    else:
        out["max_operations"] = DEFAULT_MAX_OPERATIONS

    if "exclude" in settings:
        patterns = _opt_strs(settings, "exclude")
        if patterns is not None:
            good: list[str] = []
            for index, pattern in enumerate(patterns):
                try:
                    good.append(check_glob(pattern, code="EXCLUDE_PATTERN_INVALID"))
                except FieldError as exc:
                    _report(sink, exc, f"settings.exclude[{index}]", "EXCLUDE_PATTERN_INVALID")
            if len(good) == len(patterns):
                out["exclude"] = good
    else:
        out["exclude"] = []
    return out


def _check_destination_components(sink: _Sink, template: DestinationTemplate, root: AbsPath, location: str) -> bool:
    literals = list(template.base.parts[len(root.parts) :])
    for component in template.components:
        if len(component) == 1 and isinstance(component[0], TextToken):
            literals.append(component[0].text)
    for literal in literals:
        try:
            check_portable_component(literal)
        except FieldError as exc:
            _report(sink, exc, location, "TEMPLATE_COMPONENT_INVALID")
            return False
    return True


def _read_rules(sink: _Sink, data: dict, flavor: Flavor, home: AbsPath, settings: dict) -> list[tuple[int, Rule]]:
    raw_rules = data.get("rule")
    if not isinstance(raw_rules, list):
        return []
    roots: list[AbsPath] = settings["roots"]
    roots_clean: bool = settings["roots_clean"]
    default_min_age = settings["min_age_s"]
    seen_names: set[str] = set()
    built: list[tuple[int, Rule]] = []

    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            continue
        base = f"rule[{index}]"
        ok = True

        # name
        name = None
        value = _opt_str(raw, "name")
        if value is None:
            ok = False
        else:
            try:
                name = check_rule_name(value)
            except FieldError as exc:
                _report(sink, exc, f"{base}.name", "RULE_NAME_INVALID")
                ok = False
            else:
                if name in seen_names:
                    sink.add("RULE_NAME_DUPLICATE", f"{base}.name", f"{base}.name: duplicate rule name '{name}'")
                    ok = False
                seen_names.add(name)

        # source
        source = None
        value = _opt_str(raw, "source")
        if value is None:
            ok = False
        else:
            try:
                source = parse_path(value, flavor, home)
            except FieldError as exc:
                _report(sink, exc, f"{base}.source")
                ok = False
            else:
                if roots_clean and containing_root(source, roots) is None:
                    sink.add("RULE_SOURCE_OUTSIDE_ROOTS", f"{base}.source", f"{base}.source: not inside any root")
                    ok = False

        # extensions and glob
        condition_unknown = False
        extensions: tuple[str, ...] = ()
        raw_extension_count = 0
        if "extensions" in raw:
            items = _opt_strs(raw, "extensions")
            if items is None:
                ok = False
                condition_unknown = True
            else:
                raw_extension_count = len(items)
                good_extensions: list[str] = []
                for position, item in enumerate(items):
                    try:
                        good_extensions.append(normalise_extension(item))
                    except FieldError as exc:
                        _report(sink, exc, f"{base}.extensions[{position}]", "EXTENSION_INVALID")
                        ok = False
                extensions = dedupe(good_extensions)

        name_glob = None
        glob_present = "name_glob" in raw
        if glob_present:
            value = _opt_str(raw, "name_glob")
            if value is None:
                ok = False
                condition_unknown = True
            else:
                try:
                    name_glob = check_glob(value)
                except FieldError as exc:
                    _report(sink, exc, f"{base}.name_glob")
                    ok = False

        if not condition_unknown and raw_extension_count == 0 and not glob_present:
            sink.add("RULE_NO_CONDITION", base, f"{base}: needs 'extensions' or 'name_glob'")
            ok = False

        # min_age
        min_age_s = None
        if "min_age" in raw:
            value = _opt_str(raw, "min_age")
            if value is None:
                ok = False
            else:
                try:
                    min_age_s = parse_duration(value)
                except FieldError as exc:
                    _report(sink, exc, f"{base}.min_age")
                    ok = False
        else:
            min_age_s = default_min_age
            if min_age_s is None:
                ok = False

        # destination
        template = None
        value = _opt_str(raw, "destination")
        if value is None:
            ok = False
        else:
            try:
                template = parse_template(value, flavor, home)
            except FieldError as exc:
                _report(sink, exc, f"{base}.destination")
                ok = False
            else:
                location = f"{base}.destination"
                if roots_clean:
                    root = containing_root(template.base, roots)
                    if root is None:
                        sink.add("RULE_DESTINATION_OUTSIDE_ROOTS", location, f"{location}: not inside any root")
                        ok = False
                    elif not _check_destination_components(sink, template, root, location):
                        ok = False
                if source is not None and not template.components and template.base == source:
                    sink.add("RULE_DESTINATION_IS_SOURCE", location, f"{location}: destination equals the rule's own source")
                    ok = False

        if ok:
            built.append((index, Rule(name, source, extensions, name_glob, min_age_s, template)))
    return built


def _cross_check(sink: _Sink, built: list[tuple[int, Rule]]) -> None:
    for position, (j, later) in enumerate(built):
        for _, earlier in built[:position]:
            if (
                earlier.source == later.source
                and earlier.name_glob is None
                and later.name_glob is None
                and set(earlier.extensions) & set(later.extensions)
            ):
                sink.add(
                    "RULE_OVERLAP",
                    f"rule[{j}]",
                    f"rule[{j}]: rules '{earlier.name}' and '{later.name}' match the same files",
                )

    for i, first in built:
        template = first.destination
        if template.components:
            continue
        for j, second in built:
            if i == j or template.base != second.source:
                continue
            provably_disjoint = (
                bool(first.extensions)
                and bool(second.extensions)
                and not (set(first.extensions) & set(second.extensions))
            )
            if not provably_disjoint:
                sink.add(
                    "RULE_CHAIN",
                    f"rule[{i}].destination",
                    f"rule[{i}].destination: files moved here may be picked up by rule '{second.name}' on a later run",
                    Severity.WARNING,
                )


def parse_config(text: str, flavor: Flavor, home: AbsPath) -> ValidationResult:
    """Pure: configuration text in, a Config or accumulated Issues out."""
    sink = _Sink()
    data = _structure(text, sink)
    if data is None:
        return ValidationResult(None, sink.finish())

    settings = _read_settings(sink, data, flavor, home)
    built = _read_rules(sink, data, flavor, home, settings)
    _cross_check(sink, built)

    issues = sink.finish()
    if sink.has_error:
        return ValidationResult(None, issues)

    rules = tuple(rule for _, rule in built)
    exclude = dedupe(BUILTIN_EXCLUDES + tuple(settings["exclude"]))
    roots = tuple(settings["roots"])
    config_hash = compute_config_hash(
        version=SUPPORTED_VERSION,
        flavor=flavor,
        roots=roots,
        timezone=settings["timezone"],
        default_min_age_s=settings["min_age_s"],
        max_operations=settings["max_operations"],
        exclude=exclude,
        rules=rules,
    )
    config = Config(
        version=SUPPORTED_VERSION,
        flavor=flavor,
        roots=roots,
        timezone=settings["timezone"],
        default_min_age_s=settings["min_age_s"],
        max_operations=settings["max_operations"],
        exclude=exclude,
        rules=rules,
        config_hash=config_hash,
    )
    return ValidationResult(config, issues)

