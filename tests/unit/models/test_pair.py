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
        "value": "value",
        "masked_value": "***",
        "fingerprint": "cd42404d52ad55ccfa9aca4adc828aa5800ad9d385a0671fbcbf724118320619",
        "file": "file",
        "line": 123,
        "rule_id": "fixture",
        "message": "test",
        "severity": "Info",
    }
    # Cached identities stay stable on the same instance
    assert pair.masked_value == pair.masked_value
    assert pair.fingerprint == pair.fingerprint


def test_pair_post_init():
    pair = KeyValuePair("key", "value")
    assert pair.keypath == ["key"]


def test_pair_redacted_repr():
    """Logs (incl. retried/restarted runs) must never carry the raw value"""
    pair = KeyValuePair("aws_key", "AKIAIOSFODHH7HARDSECRET")
    text = str(pair)
    assert "AKIAIOSFODHH7HARDSECRET" not in text
    assert pair.masked_value in text
    assert pair.fingerprint in text


def test_pair_identity_stable_across_instances():
    """Same raw value => same masked output and same fingerprint, always"""
    first = KeyValuePair("aws_key", "AKIAIOSFODHH7HARDSECRET")
    second = KeyValuePair("aws_key", "AKIAIOSFODHH7HARDSECRET")
    assert first.masked_value == second.masked_value
    assert first.fingerprint == second.fingerprint

    different = KeyValuePair("aws_key", "AKIAIOSFODHH7HARDSECRETX")
    assert different.fingerprint != first.fingerprint
