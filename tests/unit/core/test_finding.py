import pytest

from whispers.core.finding import (
    FINDING_ID_PREFIX,
    assign_occurrence_indices,
    finding_id,
    finding_identity,
    occurrence_index,
    reset_occurrence_counters,
)
from whispers.models.pair import KeyValuePair


def _pair(rule_id="apikey", group="keys", **kwargs):
    from whispers.models.rule import Rule

    rule = Rule(
        {
            "id": rule_id,
            "group": group,
            "message": "test message",
            "severity": "High",
            "key": {},
            "value": {},
        }
    )
    defaults = {
        "key": "aws_secret",
        "value": "hardcoded-secret-01",
        "keypath": ["aws_secret"],
        "file": "tests/fixtures/aws.yml",
        "line": 7,
        "rule": rule,
    }
    defaults.update(kwargs)
    return KeyValuePair(**defaults)


def test_finding_id_format():
    pair = _pair()
    fid = finding_id(pair)
    assert fid is not None
    assert fid.startswith(f"{FINDING_ID_PREFIX}-")
    assert len(fid) == len(FINDING_ID_PREFIX) + 1 + 16


def test_finding_id_none_without_rule():
    pair = KeyValuePair("key", "value")
    assert finding_id(pair) is None


def test_finding_id_stable_across_restart():
    """Rebuilding the same finding from scratch (new process) yields the same ID."""
    first = finding_id(_pair())
    second = finding_id(_pair())
    assert first == second


def test_finding_id_independent_of_line_number():
    """Line shifts alone must not create a 'new' finding on rescan.

    A single occurrence keeps occurrence index 0 regardless of its line, so
    editing the line number leaves the finding ID unchanged.
    """
    reset_occurrence_counters()
    original = finding_id(_pair(line=7))
    reset_occurrence_counters()
    shifted = finding_id(_pair(line=42))
    assert original == shifted


def test_finding_id_independent_of_emission_order():
    """IDs come from intrinsic attributes, so reordering scans cannot change them."""
    findings_a = [_pair(key="a"), _pair(key="b"), _pair(key="c")]
    findings_b = [_pair(key="c"), _pair(key="a"), _pair(key="b")]
    ids_a = [finding_id(pair) for pair in findings_a]
    ids_b = [finding_id(pair) for pair in findings_b]
    assert set(ids_a) == set(ids_b)
    assert len(set(ids_a)) == 3


def test_finding_id_distinguishes_rule_source():
    """The same secret matched by different rules keeps distinct rule-scoped IDs."""
    apikey = finding_id(_pair(rule_id="apikey", group="keys"))
    password = finding_id(_pair(rule_id="password", group="passwords"))
    assert apikey != password


def test_finding_id_distinguishes_secrets_files_and_values():
    base = finding_id(_pair())
    other_value = finding_id(_pair(value="hardcoded-secret-02"))
    other_file = finding_id(_pair(file="tests/fixtures/aws.json"))
    other_key = finding_id(_pair(key="aws_token", keypath=["aws_token"]))
    assert base != other_value
    assert base != other_file
    assert base != other_key


def test_finding_identity_components():
    reset_occurrence_counters()
    pair = _pair()
    identity = finding_identity(pair)
    assert identity == {
        "rule_id": "apikey",
        "rule_group": "keys",
        "file": "tests/fixtures/aws.yml",
        "key": "aws_secret",
        "keypath": ["aws_secret"],
        "value": "hardcoded-secret-01",
        "occurrence": 0,
    }
    # The volatile line number is intentionally not part of the identity.
    assert "line" not in identity


@pytest.mark.parametrize(
    ("changes"),
    [
        ({"line": 999}),
        ({"file": "tests/fixtures/aws.yml", "line": 1}),
    ],
)
def test_finding_id_rescan_stability(changes):
    """A rescan of the same secret reports the same finding ID."""
    reset_occurrence_counters()
    first = finding_id(_pair())
    reset_occurrence_counters()
    second = finding_id(_pair(**changes))
    assert first == second


def test_repeated_occurrences_in_one_file_get_distinct_stable_ids():
    """The same secret at different lines is distinguishable on rescan."""
    reset_occurrence_counters()
    first = _pair(line=16)
    second = _pair(line=17)
    assign_occurrence_indices([first, second])
    id_first = finding_id(first)
    id_second = finding_id(second)
    assert id_first != id_second
    assert occurrence_index(first) == 0
    assert occurrence_index(second) == 1

    # A fresh process/rescan assigns the same indices by in-file position,
    # regardless of the order the pairs are presented in, once the full set
    # of occurrences has been registered (as a complete rescan does).
    reset_occurrence_counters()
    assign_occurrence_indices([second, first])
    assert finding_id(second) == id_second
    assert finding_id(first) == id_first


def test_occurrence_index_independent_of_emission_order():
    reset_occurrence_counters()
    line_a = _pair(line=1)
    line_b = _pair(line=2)
    line_c = _pair(line=3)
    assign_occurrence_indices([line_a, line_b, line_c])
    ordered = [occurrence_index(p) for p in (line_a, line_b, line_c)]
    reset_occurrence_counters()
    # Same full set registered in shuffled emission order; ranks must match.
    assign_occurrence_indices([line_c, line_a, line_b])
    shuffled = [occurrence_index(p) for p in (line_c, line_a, line_b)]
    assert ordered == [0, 1, 2]
    assert shuffled == [2, 0, 1]


def test_to_json_keeps_rule_file_and_location_per_finding():
    """Each report entry keeps the matched rule, file and precise location."""
    pair = _pair(line=7)
    report = pair.to_json()
    assert report["id"] == finding_id(pair)
    assert report["rule_id"] == "apikey"
    assert report["rule_group"] == "keys"
    assert report["message"] == "test message"
    assert report["severity"] == "High"
    assert report["file"] == "tests/fixtures/aws.yml"
    assert report["line"] == 7
    assert report["key"] == "aws_secret"
    assert report["value"] == "hardcoded-secret-01"
    assert report["keypath"] == ["aws_secret"]
