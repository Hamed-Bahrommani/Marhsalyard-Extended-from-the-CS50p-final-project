"""Marshalyard command-line entry point (CS50P-style root module).

The real logic lives in the `marshalyard` package. This module holds the
top-level functions required by the project structure and grows with the
milestones: load_rules (M1), build_plan (M2), apply_plan (M4), undo_run (M6).
"""

import sys
from pathlib import PurePosixPath, PureWindowsPath
from marshalyard.canonical import containing_root, portable_key

from marshalyard import __version__

from marshalyard.config import load_config
from marshalyard.models import Severity


def load_rules(path: str) -> list[str]:
    """Names of the rules in a valid configuration file.

    Raises ValueError, listing every error, if the file is missing or invalid.
    """
    result = load_config(path)
    if result.config is None:
        errors = [f"{i.location}: {i.code}" for i in result.issues if i.severity is Severity.ERROR]
        raise ValueError("invalid configuration: " + "; ".join(errors))
    return [rule.name for rule in result.config.rules]


def find_root(path: str, roots: list[str], windows: bool = False) -> str | None:
    """Return the most specific root (as a string) that contains `path`, or None.

    Nested roots resolve to the most specific one; containment follows the
    flavor's own rules (case-insensitive for Windows paths).
    """
    path_type = PureWindowsPath if windows else PurePosixPath
    root = containing_root(path_type(path), [path_type(r) for r in roots])
    return None if root is None else str(root)


def version_string() -> str:
    return f"marshalyard {__version__}"


def names_collide(a: str, b: str, windows: bool = False) -> bool:
    """True if two absolute paths could collide on a supported filesystem.

    Uses the conservative portable_key (Unicode NFC plus case folding), so it
    over-reports rather than under-reports.
    """
    path_type = PureWindowsPath if windows else PurePosixPath
    return portable_key(path_type(a)) == portable_key(path_type(b))


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["--version"]:
        print(version_string())
        return 0
    print("usage: project.py --version   (commands arrive in later milestones)")
    return 2


if __name__ == "__main__":
    sys.exit(main())