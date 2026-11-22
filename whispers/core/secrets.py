import hashlib
import logging
from typing import Iterable, Iterator, List, Optional

from whispers.core.utils import find_line_number
from whispers.models.pair import KeyValuePair
from whispers.models.rule import Rule


def detect_secrets(
    rules: List[Rule],
    pairs: Optional[Iterable[KeyValuePair]] = None,
    history: object = None,
    **context,
) -> Iterator[KeyValuePair]:
    """Detect pairs with hardcoded secrets.

    ``history`` may be a Git history scanner/scope.  Findings keep the frozen
    commit/blob/path metadata already attached by that scope.
    """
    if pairs is None and history is not None:
        pairs = history.pairs() if hasattr(history, "pairs") else history
    elif history is not None and hasattr(pairs, "pairs"):
        pairs = pairs.pairs()
    elif pairs is not None and getattr(pairs, "is_history", False) and hasattr(pairs, "pairs"):
        pairs = pairs.pairs()

    if pairs is None:
        return

    for pair in pairs:
        detected = filter(None, map(lambda rule: filter_rule(rule, pair), rules))

        for finding in detected:
            if context:
                _attach_context(finding, context)
            tag_history_stage(finding)
            yield finding


def filter_rule(rule: Rule, pair: KeyValuePair) -> Optional[KeyValuePair]:
    """Filters based on rule"""
    if not rule.matches(pair):
        logging.debug(f"filter_rule '{rule.id}' excluded pair '{pair}'")
        return None

    pair.rule = rule
    pair.line = find_line_number(pair)

    logging.debug(f"filter_rule '{rule.id}' included pair '{pair}'")
    return pair


def tag_history_stage(pair: KeyValuePair) -> KeyValuePair:
    """Preserve commit/blob identity on findings produced from history scans"""
    if not pair.__dict__.get("history") and not (
        pair.__dict__.get("commit") or pair.__dict__.get("blob")
    ):
        return pair

    pair.stage = pair.__dict__.get("stage") or "history"
    pair.detection_stage = pair.__dict__.get("detection_stage") or pair.stage
    pair.phase = pair.__dict__.get("phase") or pair.stage
    pair.scan_generation = pair.__dict__.get("scan_generation") or pair.__dict__.get("generation")
    if not pair.__dict__.get("finding_id"):
        payload = "|".join(
            [
                str(pair.__dict__.get("commit", "")),
                str(pair.__dict__.get("blob", "")),
                str(pair.__dict__.get("path", "")),
                str(pair.key),
                str(pair.value),
                str(pair.line),
            ]
        )
        pair.finding_id = "whs-" + hashlib.sha256(payload.encode("utf-8", "surrogateescape")).hexdigest()[:16]
        pair.id = pair.finding_id
    return pair


def _attach_context(pair: KeyValuePair, context: dict) -> None:
    commit = context.get("commit", context.get("commit_sha"))
    blob = context.get("blob", context.get("blob_sha", context.get("object_id")))
    generation = context.get("generation", context.get("scan_generation"))
    stage = context.get("stage", context.get("detection_stage", context.get("phase", "history")))
    if commit is not None:
        pair.commit = pair.commit_sha = commit
    if blob is not None:
        pair.blob = pair.blob_sha = pair.object_id = blob
    if context.get("path") is not None:
        pair.path = context["path"]
    if generation is not None:
        pair.generation = pair.scan_generation = generation
    if stage is not None:
        pair.stage = pair.detection_stage = pair.phase = stage
    if not pair.__dict__.get("history") and (commit or blob or context.get("path")):
        pair.history = {
            "commit": commit,
            "blob": blob,
            "path": context.get("path"),
            "generation": generation,
            "stage": stage,
        }
