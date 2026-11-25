"""Phase-2 environment checks (spec 5.3): facts about the disk, read-only.

Uses only lstat and realpath through the FileSystem port. Issues come back in the
same shape as parse_config's, so the CLI can merge them. The no-replace capability
check needs the real system and belongs to M3.
"""

from dataclasses import dataclass

from marshalyard.canonical import containing_root
from marshalyard.filesystem import FileKind, FileSystem, FsError
from marshalyard.models import AbsPath, Config, Issue, Severity


@dataclass(frozen=True, slots=True)
class _Walk:
    status: str  # "ok", "missing", "link", "not_directory", "error"
    device: int
    detail: str = ""


def _walk(fs: FileSystem, root: AbsPath, root_device: int, target: AbsPath) -> _Walk:
    """Walk `target` one component at a time below its containing root."""
    current = root
    device = root_device
    for part in target.parts[len(root.parts) :]:
        current = current / part
        try:
            info = fs.lstat(current)
        except FsError as exc:
            return _Walk("error", device, exc.reason)
        if info is None:
            return _Walk("missing", device)
        if info.kind is FileKind.SYMLINK or info.reparse_point:
            return _Walk("link", device)
        if info.kind is not FileKind.DIRECTORY:
            return _Walk("not_directory", device)
        device = info.dev
    return _Walk("ok", device)


def _escapes(fs: FileSystem, target: AbsPath, real_root: AbsPath) -> bool:
    try:
        return not fs.realpath(target).is_relative_to(real_root)
    except FsError:
        return True


def check_environment(fs: FileSystem, config: Config) -> tuple[Issue, ...]:
    issues: list[Issue] = []

    def add(code: str, location: str, message: str, severity: Severity = Severity.ERROR) -> None:
        issues.append(Issue(code, location, f"{location}: {message}", severity))

    good_roots: dict[AbsPath, tuple[int, AbsPath]] = {}  # root -> (device, real path)
    for index, root in enumerate(config.roots):
        location = f"settings.roots[{index}]"
        try:
            real = fs.realpath(root)
            info = fs.lstat(real)
        except FsError as exc:
            add("ENV_ROOT_MISSING", location, f"cannot be inspected: {exc.reason}")
            continue
        if info is None:
            add("ENV_ROOT_MISSING", location, "the root does not exist")
        elif info.kind is not FileKind.DIRECTORY:
            add("ENV_ROOT_NOT_DIRECTORY", location, "the root is not a directory")
        elif info.dev == 0 or info.ino == 0:
            add("ENV_IDENTITY_UNAVAILABLE", location, "the filesystem does not provide usable file identity")
        else:
            good_roots[root] = (info.dev, real)

    for index, rule in enumerate(config.rules):
        source_location = f"rule[{index}].source"
        destination_location = f"rule[{index}].destination"

        source_walk: _Walk | None = None
        source_root = containing_root(rule.source, config.roots)
        if source_root in good_roots:
            device, real_root = good_roots[source_root]
            source_walk = _walk(fs, source_root, device, rule.source)
            if source_walk.status == "missing":
                add("ENV_SOURCE_MISSING", source_location, "the source directory does not exist yet", Severity.WARNING)
            elif source_walk.status == "not_directory":
                add("ENV_SOURCE_NOT_DIRECTORY", source_location, "the source is not a directory")
            elif source_walk.status == "link":
                add("ENV_LINK_IN_PATH", source_location, "a link lies below the root in the source path")
            elif source_walk.status == "error":
                add("ENV_LINK_IN_PATH", source_location, f"cannot verify the path has no links: {source_walk.detail}")
            if source_walk.status in ("ok", "link") and _escapes(fs, rule.source, real_root):
                add("ENV_ESCAPES_ROOT", source_location, "the source does not resolve to a location inside its root")

        base = rule.destination.base
        destination_walk: _Walk | None = None
        destination_root = containing_root(base, config.roots)
        if destination_root in good_roots:
            device, real_root = good_roots[destination_root]
            destination_walk = _walk(fs, destination_root, device, base)
            if destination_walk.status == "link":
                add("ENV_LINK_IN_PATH", destination_location, "a link lies below the root in the destination path")
            elif destination_walk.status == "error":
                add(
                    "ENV_LINK_IN_PATH",
                    destination_location,
                    f"cannot verify the path has no links: {destination_walk.detail}",
                )
            if destination_walk.status in ("ok", "missing", "link") and _escapes(fs, base, real_root):
                add(
                    "ENV_ESCAPES_ROOT",
                    destination_location,
                    "the destination does not resolve to a location inside its root",
                )

        if (
            source_walk is not None
            and destination_walk is not None
            and source_walk.status == "ok"
            and destination_walk.status in ("ok", "missing")
            and source_walk.device != destination_walk.device
        ):
            add(
                "ENV_CROSS_DEVICE",
                destination_location,
                "the source and the destination are on different devices; files will be refused",
                Severity.WARNING,
            )

    return tuple(sorted(issues, key=lambda issue: (issue.location, issue.code)))