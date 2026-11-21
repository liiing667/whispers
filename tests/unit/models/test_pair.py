from whispers.models.pair import KeyValuePair


def test_pair(rule_fixture):
    pair = KeyValuePair("key", "value", ["key", "path"], "file", 123, rule_fixture)
    assert pair.__dict__ == {
        "key": "key",
        "value": "value",
        "keypath": ["key", "path"],
        "file": "file",
        "line": 123,
        "rule": rule_fixture,
    }
    finding_id = pair.to_json()["id"]
    assert finding_id and finding_id.startswith("whs-")
    assert pair.to_json() == {
        "id": finding_id,
        "key": "key",
        "value": "value",
        "file": "file",
        "line": 123,
        "keypath": ["key", "path"],
        "rule_id": "fixture",
        "rule_group": "tests",
        "message": "test",
        "severity": "Info",
    }


def test_pair_post_init():
    pair = KeyValuePair("key", "value")
    assert pair.keypath == ["key"]
