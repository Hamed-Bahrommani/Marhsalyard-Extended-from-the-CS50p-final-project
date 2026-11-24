"""In-memory FileSystem for tests: faults and races can be injected between calls.

Setup methods (add_*, write, touch, remove, read_bytes) are not part of the port
and are not logged. Port methods (lstat, list_dir, open_read, realpath, and the
handle's fstat/read) are logged in `calls` and can be hooked with `inject`.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath

from marshalyard.filesystem import FileKind, FsError, StatInfo
from marshalyard.models import AbsPath, Flavor

MAX_LINK_DEPTH = 40


@dataclass(slots=True, eq=False)
class _Node:
    kind: FileKind
    dev: int
    ino: int
    mtime_ns: int
    content: bytes = b""
    target: AbsPath | None = None
    children: dict = field(default_factory=dict)  # key -> (display name, node)
    nlink: int = 1
    hidden_or_system: bool = False
    reparse_point: bool = False
    hide_identity: bool = False


class _Handle:
    def __init__(self, fs: "MemoryFileSystem", path: AbsPath, node: _Node) -> None:
        self._fs = fs
        self._path = path
        self._node = node
        self._pos = 0
        self._closed = False

    def _live(self) -> None:
        if self._closed:
            raise FsError(self._path, "handle is closed")

    def fstat(self) -> StatInfo:
        self._fs._enter("fstat", self._path)
        self._live()
        return self._fs._stat_of(self._node)

    def read(self, size: int = -1) -> bytes:
        self._fs._enter("read", self._path)
        self._live()
        data = self._node.content
        end = len(data) if size is None or size < 0 else min(len(data), self._pos + size)
        chunk = data[self._pos : end]
        self._pos = end
        return chunk

    def close(self) -> None:
        self._closed = True


class MemoryFileSystem:
    def __init__(self, flavor: Flavor = Flavor.POSIX, default_mtime_ns: int = 1_000_000_000_000) -> None:
        self._flavor = flavor
        self._path_type = PureWindowsPath if flavor is Flavor.WINDOWS else PurePosixPath
        self._roots: dict[str, _Node] = {}
        self._anchors: dict[str, str] = {}  # key -> anchor spelling as first created
        self._next_ino = 1
        self.default_mtime_ns = default_mtime_ns
        self.calls: list[tuple[str, AbsPath]] = []
        self._hooks: list[list] = []

    # ------------------------------------------------------------ port

    @property
    def flavor(self) -> Flavor:
        return self._flavor

    def lstat(self, path: AbsPath) -> StatInfo | None:
        self._check(path)
        self._enter("lstat", path)
        node = self._resolve(path, follow_final=False)
        return None if node is None else self._stat_of(node)

    def list_dir(self, path: AbsPath) -> tuple[str, ...]:
        self._check(path)
        self._enter("list_dir", path)
        node = self._resolve(path, follow_final=True)
        if node is None:
            raise FsError(path, "no such directory")
        if node.kind is not FileKind.DIRECTORY:
            raise FsError(path, "not a directory")
        return tuple(name for name, _ in node.children.values())

    def open_read(self, path: AbsPath) -> _Handle:
        self._check(path)
        self._enter("open_read", path)
        node = self._resolve(path, follow_final=False)
        if node is None:
            raise FsError(path, "no such file")
        if node.kind is FileKind.SYMLINK:
            raise FsError(path, "refusing to follow a symlink")
        if node.kind is not FileKind.FILE:
            raise FsError(path, "not a regular file")
        return _Handle(self, path, node)

    def realpath(self, path: AbsPath) -> AbsPath:
        self._check(path)
        self._enter("realpath", path)
        return self._real(path, 0)

    # ------------------------------------------------------------ fault and race injection

    def inject(self, op: str, action: Callable, *, path: AbsPath | None = None, times: int = 1) -> None:
        """Run action(fs, path) just before the next `times` matching port calls.

        `action` may mutate the fake (a race) or raise FsError (a fault).
        """
        self._hooks.append([op, path, action, times])

    # ------------------------------------------------------------ setup (not logged)

    def add_dir(self, path: AbsPath, *, dev: int | None = None, mtime_ns: int | None = None,
                hidden: bool = False, reparse_point: bool = False) -> int:
        self._check(path)
        if len(path.parts) == 1:
            return self._ensure_root(path, dev).ino
        existing = self._lookup_exact(path)
        if existing is not None:
            if existing.kind is not FileKind.DIRECTORY:
                raise ValueError(f"{path} exists and is not a directory")
            return existing.ino
        return self._add(path, FileKind.DIRECTORY, dev, mtime_ns,
                         hidden_or_system=hidden, reparse_point=reparse_point).ino

    def add_file(self, path: AbsPath, content: bytes = b"", *, mtime_ns: int | None = None,
                 dev: int | None = None, hidden: bool = False, reparse_point: bool = False,
                 hide_identity: bool = False) -> int:
        return self._add(path, FileKind.FILE, dev, mtime_ns, content=bytes(content),
                         hidden_or_system=hidden, reparse_point=reparse_point,
                         hide_identity=hide_identity).ino

    def add_symlink(self, path: AbsPath, target: AbsPath, *, mtime_ns: int | None = None) -> int:
        self._check(target)
        return self._add(path, FileKind.SYMLINK, None, mtime_ns, target=target).ino

    def add_special(self, path: AbsPath, *, mtime_ns: int | None = None) -> int:
        return self._add(path, FileKind.OTHER, None, mtime_ns).ino

    def add_hardlink(self, existing: AbsPath, new_path: AbsPath) -> None:
        self._check(existing)
        self._check(new_path)
        node = self._lookup_exact(existing)
        if node is None or node.kind is not FileKind.FILE:
            raise ValueError(f"{existing} is not an existing regular file")
        parent = self._walk_create(new_path, len(new_path.parts) - 1)
        if parent.dev != node.dev:
            raise ValueError("hard links cannot cross devices")
        key = self._key(new_path.parts[-1])
        if key in parent.children:
            raise ValueError(f"{new_path} already exists")
        parent.children[key] = (new_path.parts[-1], node)
        node.nlink += 1

    def write(self, path: AbsPath, content: bytes, mtime_ns: int | None = None) -> None:
        """Replace a file's content; mtime is kept unless given (same-timestamp writes)."""
        node = self._lookup_exact(path)
        if node is None or node.kind is not FileKind.FILE:
            raise ValueError(f"{path} is not an existing regular file")
        node.content = bytes(content)
        if mtime_ns is not None:
            node.mtime_ns = mtime_ns

    def touch(self, path: AbsPath, mtime_ns: int) -> None:
        node = self._lookup_exact(path)
        if node is None:
            raise ValueError(f"{path} does not exist")
        node.mtime_ns = mtime_ns

    def remove(self, path: AbsPath) -> None:
        self._check(path)
        if len(path.parts) == 1:
            raise ValueError("cannot remove a root")
        parent = self._lookup_exact(path.parent)
        key = self._key(path.parts[-1])
        if parent is None or parent.kind is not FileKind.DIRECTORY or key not in parent.children:
            raise ValueError(f"{path} does not exist")
        _, node = parent.children.pop(key)
        node.nlink -= 1

    def read_bytes(self, path: AbsPath) -> bytes:
        node = self._lookup_exact(path)
        if node is None or node.kind is not FileKind.FILE:
            raise ValueError(f"{path} is not an existing regular file")
        return node.content

    # ------------------------------------------------------------ internals

    def _check(self, path: AbsPath) -> None:
        if type(path) is not self._path_type or not path.is_absolute():
            raise ValueError(f"{path!r} is not an absolute {self._flavor.value} path")

    def _key(self, name: str) -> str:
        return name.casefold() if self._flavor is Flavor.WINDOWS else name

    def _enter(self, op: str, path: AbsPath) -> None:
        self.calls.append((op, path))
        for hook in list(self._hooks):
            hook_op, hook_path, action, remaining = hook
            if hook_op == op and (hook_path is None or hook_path == path) and remaining > 0:
                hook[3] -= 1
                action(self, path)

    def _new(self, kind: FileKind, dev: int, mtime_ns: int | None, **fields) -> _Node:
        node = _Node(kind=kind, dev=dev, ino=self._next_ino,
                     mtime_ns=self.default_mtime_ns if mtime_ns is None else mtime_ns, **fields)
        self._next_ino += 1
        return node

    def _stat_of(self, node: _Node) -> StatInfo:
        size = len(node.content) if node.kind is FileKind.FILE else 0
        if node.hide_identity:
            dev = ino = nlink = 0
        else:
            dev, ino, nlink = node.dev, node.ino, node.nlink
        return StatInfo(node.kind, dev, ino, nlink, size, node.mtime_ns,
                        node.hidden_or_system, node.reparse_point)

    def _ensure_root(self, path: AbsPath, dev: int | None = None) -> _Node:
        key = self._key(path.anchor)
        if key not in self._roots:
            self._roots[key] = self._new(FileKind.DIRECTORY, 1 if dev is None else dev, None)
            self._anchors[key] = path.anchor
        return self._roots[key]

    def _walk_create(self, path: AbsPath, upto: int) -> _Node:
        node = self._ensure_root(path)
        for part in path.parts[1:upto]:
            key = self._key(part)
            entry = node.children.get(key)
            if entry is None:
                child = self._new(FileKind.DIRECTORY, node.dev, None)
                node.children[key] = (part, child)
                node = child
            else:
                node = entry[1]
                if node.kind is not FileKind.DIRECTORY:
                    raise ValueError(f"{part} is not a directory")
        return node

    def _add(self, path: AbsPath, kind: FileKind, dev: int | None, mtime_ns: int | None, **fields) -> _Node:
        self._check(path)
        if len(path.parts) == 1:
            raise ValueError("cannot add a root as a non-directory")
        parent = self._walk_create(path, len(path.parts) - 1)
        name = path.parts[-1]
        key = self._key(name)
        if key in parent.children:
            raise ValueError(f"{path} already exists")
        node = self._new(kind, parent.dev if dev is None else dev, mtime_ns, **fields)
        parent.children[key] = (name, node)
        return node

    def _lookup_exact(self, path: AbsPath) -> _Node | None:
        self._check(path)
        node = self._roots.get(self._key(path.anchor))
        for part in path.parts[1:]:
            if node is None or node.kind is not FileKind.DIRECTORY:
                return None
            entry = node.children.get(self._key(part))
            node = entry[1] if entry else None
        return node

    def _resolve(self, path: AbsPath, follow_final: bool, depth: int = 0) -> _Node | None:
        if depth > MAX_LINK_DEPTH:
            raise FsError(path, "too many levels of symbolic links")
        node = self._roots.get(self._key(path.anchor))
        if node is None:
            return None
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            if node.kind is not FileKind.DIRECTORY:
                return None
            entry = node.children.get(self._key(part))
            if entry is None:
                return None
            child = entry[1]
            is_last = index == len(parts) - 1
            if child.kind is FileKind.SYMLINK and (follow_final or not is_last):
                return self._resolve(child.target.joinpath(*parts[index + 1 :]), follow_final, depth + 1)
            node = child
        return node

    def _real(self, path: AbsPath, depth: int) -> AbsPath:
        if depth > MAX_LINK_DEPTH:
            raise FsError(path, "too many levels of symbolic links")
        node = self._roots.get(self._key(path.anchor))
        if node is None:
            return path
        current = self._path_type(self._anchors[self._key(path.anchor)])
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            entry = node.children.get(self._key(part)) if node.kind is FileKind.DIRECTORY else None
            if entry is None:
                return current.joinpath(*parts[index:])
            name, child = entry
            if child.kind is FileKind.SYMLINK:
                return self._real(child.target.joinpath(*parts[index + 1 :]), depth + 1)
            current = current / name
            node = child
        return current
