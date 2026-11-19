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
    assert pair.to_json() == {
        "key": "key",
        "value": pair.redacted_value,
        "value_length": 5,
        "fingerprint": pair.fingerprint,
        "file": "file",
        "line": 123,
        "rule_id": "fixture",
        "message": "test",
        "severity": "Info",
    }
    assert pair.to_json(redact=False) == {
        "key": "key",
        "value": "value",
        "file": "file",
        "line": 123,
        "rule_id": "fixture",
        "message": "test",
        "severity": "Info",
    }


def test_pair_post_init():
    pair = KeyValuePair("key", "value")
    assert pair.keypath == ["key"]
