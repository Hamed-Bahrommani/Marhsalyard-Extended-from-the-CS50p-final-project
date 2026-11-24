"""Pure canonical helpers (spec sections 3.4).

Step 2: portable_key and containing_root. compute_config_hash and
compute_plan_id will be added to this module later.
"""
import hashlib
import json
import unicodedata
from collections.abc import Iterable, Sequence

from marshalyard.models import (
    AbsPath,
    DestinationTemplate,
    ExtToken,
    Flavor,
    ModifiedToken,
    Rule,
    TextToken,
    Timezone,
    PlanKind,
    PlannedOperation,
    Unplanned,
)



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


def _template_json(template: DestinationTemplate) -> dict:
    components = []
    for component in template.components:
        tokens = []
        for token in component:
            if isinstance(token, TextToken):
                tokens.append(["text", token.text])
            elif isinstance(token, ExtToken):
                tokens.append(["ext"])
            elif isinstance(token, ModifiedToken):
                tokens.append(["modified", token.fmt])
            else:  # pragma: no cover - constructors prevent this
                raise TypeError(f"unknown token {token!r}")
        components.append(tokens)
    return {"base": template.base.as_posix(), "components": components}


def compute_config_hash(
    *,
    version: int,
    flavor: Flavor,
    roots: Iterable[AbsPath],
    timezone: Timezone,
    default_min_age_s: int,
    max_operations: int,
    exclude: Iterable[str],
    rules: Iterable[Rule],
) -> str:
    """SHA-256 of a canonical JSON form of the configuration.

    Order-invariant for roots, rules, extensions and exclusions; insensitive to
    trailing separators (paths are already normalised); sensitive to spelling
    (case, Unicode form) because those are real path differences.
    """
    payload = {
        "schema": "marshalyard-config-1",
        "version": version,
        "flavor": flavor.value,
        "timezone": timezone.value,
        "default_min_age_s": default_min_age_s,
        "max_operations": max_operations,
        "roots": sorted(root.as_posix() for root in roots),
        "exclude": sorted(set(exclude)),
        "rules": sorted(
            (
                {
                    "name": rule.name,
                    "source": rule.source.as_posix(),
                    "extensions": sorted(rule.extensions),
                    "name_glob": rule.name_glob,
                    "min_age_s": rule.min_age_s,
                    "destination": _template_json(rule.destination),
                }
                for rule in rules
            ),
            key=lambda item: item["name"],
        ),
    }
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_plan_id(
    *,
    kind: PlanKind,
    config_hash: str | None,
    derived_from_run: int | None,
    operations: Sequence[PlannedOperation],
    unplanned: Sequence[Unplanned],
) -> str:
    """SHA-256 of the canonical JSON of the whole immutable proposal.

    created_at_ns is the only field excluded. Unplanned entries are sorted so
    their discovery order never changes the id.
    """
    payload = {
        "kind": kind.value,
        "config_hash": config_hash,
        "derived_from_run": derived_from_run,
        "ops": [
            {
                "seq": op.seq,
                "src": op.src.as_posix(),
                "dst": op.dst.as_posix(),
                "rule": op.rule_name,
                "fp": {
                    "dev": op.fingerprint.dev,
                    "ino": op.fingerprint.ino,
                    "nlink": op.fingerprint.nlink,
                    "size": op.fingerprint.size,
                    "mtime_ns": op.fingerprint.mtime_ns,
                    "sha256": op.fingerprint.sha256,
                    "method": op.fingerprint.method.value,
                },
            }
            for op in operations
        ],
        "unplanned": [
            {"src": item.src.as_posix(), "reason": item.reason.value, "detail": item.detail}
            for item in sorted(unplanned, key=lambda u: (u.src.as_posix(), u.reason.value))
        ],
    }
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
