"""Stable finding identity for detected secrets.

A scan recovery must be able to tell that the same secret reported in a
previous run is the same finding in a new run, even when findings are
emitted in a different order (e.g. files scanned in parallel, resumed
scans) or the process is restarted. Sequential counters and object
identifiers change between runs, so the finding ID is derived from the
intrinsic, deterministic attributes of the finding instead:

* the rule that matched (rule id and group) — the rule source,
* the secret itself (key and value),
* the file it was found in,
* the structural key path inside that file,
* a deterministic occurrence index distinguishing repeated occurrences of
  the same (rule, key, value) inside the same file.

Deliberately excluded from the identity:

* the line number, which shifts when the file is edited (the occurrence
  index replaces it: it is assigned by in-file position, not by scan order),
* emission order / enumeration, which changes between runs,
* process-level identifiers, which change on restart.

The hash uses SHA-256 with a length-prefixed canonical JSON encoding so
that every component is unambiguously delimited and the result is stable
across runs, platforms and Python dict ordering.
"""
import hashlib
import json
from typing import Optional

from whispers.models.pair import KeyValuePair

FINDING_ID_PREFIX = "whs"
FINDING_ID_LENGTH = 16

# Registry of every detected pair keyed by its position-independent identity
# base. Occurrence indices are assigned in a single finalization pass (see
# assign_occurrence_indices) after all findings have been collected, so the
# ranks depend only on in-file positions, never on emission order.
_OCCURRENCE_REGISTRY = {}
_OCCURRENCE_INDEX = {}


def _rule_id(pair: KeyValuePair) -> str:
    rule = getattr(pair, "rule", None)
    return getattr(rule, "id", "") or ""


def _rule_group(pair: KeyValuePair) -> str:
    rule = getattr(pair, "rule", None)
    return getattr(rule, "group", "") or ""


def finding_identity(pair: KeyValuePair) -> dict:
    """Return the canonical, order-independent identity components."""
    return {
        "rule_id": _rule_id(pair),
        "rule_group": _rule_group(pair),
        "file": pair.file or "",
        "key": pair.key or "",
        "keypath": list(pair.keypath or []),
        "value": pair.value or "",
        "occurrence": occurrence_index(pair),
    }


def _identity_base(pair: KeyValuePair) -> tuple:
    return (
        _rule_id(pair),
        _rule_group(pair),
        pair.file or "",
        pair.key or "",
        tuple(pair.keypath or []),
        pair.value or "",
    )


def occurrence_index(pair: KeyValuePair) -> int:
    """Deterministic 0-based index for repeated identical findings in a file.

    The index is the pair's rank among all occurrences of the same identity
    base, ordered by in-file position (line number, then structural key
    path). It is therefore stable across scan reordering, resume and
    restart, while still distinguishing repeated identical secrets that
    appear at different places in the same file.
    """
    return _OCCURRENCE_INDEX.get(id(pair), 0)


def register_occurrence(pair: KeyValuePair) -> None:
    """Collect a detected pair for later occurrence ranking."""
    base = _identity_base(pair)
    position = (pair.line or 0, tuple(pair.keypath or []))
    _OCCURRENCE_REGISTRY.setdefault(base, set()).add(position)


def assign_occurrence_indices(pairs) -> list:
    """Finalize occurrence ranks once the full finding set is known.

    Ranks are computed from in-file positions only, making every finding ID
    independent of the order findings were scanned or emitted in. Returns
    the same list of pairs for convenient chaining.
    """
    ordered_pairs = list(pairs)
    for pair in ordered_pairs:
        if getattr(pair, "rule", None) is None:
            continue
        register_occurrence(pair)

    ranks = {base: {pos: idx for idx, pos in enumerate(sorted(positions))}
             for base, positions in _OCCURRENCE_REGISTRY.items()}
    for pair in ordered_pairs:
        if getattr(pair, "rule", None) is None:
            continue
        base = _identity_base(pair)
        position = (pair.line or 0, tuple(pair.keypath or []))
        _OCCURRENCE_INDEX[id(pair)] = ranks[base][position]
    return ordered_pairs


def reset_occurrence_counters() -> None:
    """Clear the occurrence registry (mainly used by tests)."""
    _OCCURRENCE_REGISTRY.clear()
    _OCCURRENCE_INDEX.clear()


def finding_id(pair: KeyValuePair) -> Optional[str]:
    """Deterministic finding ID, stable across reorders and restarts.

    Returns None until a rule has been attached to the pair, because the
    rule source is part of the identity.
    """
    if getattr(pair, "rule", None) is None:
        return None

    payload = json.dumps(
        finding_identity(pair),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:FINDING_ID_LENGTH]
    return f"{FINDING_ID_PREFIX}-{digest}"
