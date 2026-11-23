"""Pure canonical helpers (spec sections 3.4).

Step 2: portable_key and containing_root. compute_config_hash and
compute_plan_id will be added to this module later.
"""

import unicodedata
from collections.abc import Iterable

from marshalyard.models import AbsPath


def _fold(component: str) -> str:
    """NFC -> casefold -> NFC (casefold can produce non-NFC output)."""
    nfc = unicodedata.normalize("NFC", component)
    return unicodedata.normalize("NFC", nfc.casefold())


def portable_key(path: AbsPath) -> str:
    """Conservative collision key: could two paths collide on a supported filesystem?

    Used only for destination collisions and the stored dst_key. Over-detecting
    is the safe direction; the key is not an exact model of any one filesystem.
    The stored path itself keeps its original spelling.
    """
    if not path.is_absolute():
        raise ValueError(f"portable_key requires an absolute path, got {str(path)!r}")
    # The anchor ("/" or "C:\\") already ends in a separator.
    anchor_key = path.anchor.casefold().replace("\\", "/")
    components = path.parts[1:]
    return anchor_key + "/".join(_fold(c) for c in components)


def containing_root(path: AbsPath, roots: Iterable[AbsPath]) -> AbsPath | None:
    """Most specific root that contains `path`, or None.

    Containment is flavor-native: component-wise, case-insensitive on Windows
    paths and case-sensitive on POSIX paths. A path equal to a root counts as
    contained. Roots are unique, so ties cannot occur; the one with the most
    components wins.
    """
    best: AbsPath | None = None
    for root in roots:
        if type(root) is not type(path):
            raise ValueError("path and roots must use the same path flavor")
        if path.is_relative_to(root) and (best is None or len(root.parts) > len(best.parts)):
            best = root
    return best
