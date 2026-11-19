import json
import logging
from hashlib import sha256

import pytest

import whispers.main
from tests.unit.conftest import FIXTURE_PATH, fixture_path
from whispers.core.args import parse_args
from whispers.core.config import load_config
from whispers.core.pairs import make_pairs
from whispers.main import run

SECRET_VALUE = "HardcodedRedactionSecret01"
SECRET_KEY = "static_password"
SECRET_FILE = "redaction.yml"
SECRET_LINE = 5


def expected_fingerprint(file: str, key: str, value: str) -> str:
    digest = sha256()
    for part in (file, key, value):
        digest.update(str(part).encode("utf-8", errors="replace"))
        digest.update(b"\0")

    return digest.hexdigest()


@pytest.fixture
def detected_pair():
    args = parse_args(["-r", "password", fixture_path(SECRET_FILE)])
    secrets = list(run(args))
    assert len(secrets) == 1
    return secrets[0]


def test_repr_is_redacted(detected_pair):
    representation = repr(detected_pair)
    assert SECRET_VALUE not in representation
    assert f"len={len(SECRET_VALUE)}" in representation
    assert f"[{fixture_path(SECRET_FILE)}:{SECRET_LINE}]" in representation
    assert SECRET_KEY in representation
    assert expected_fingerprint(fixture_path(SECRET_FILE), SECRET_KEY, SECRET_VALUE)[:12] in representation


def test_to_json_redacted_by_default(detected_pair):
    result = detected_pair.to_json()
    assert SECRET_VALUE not in json.dumps(result)
    assert result == {
        "key": SECRET_KEY,
        "value": detected_pair.redacted_value,
        "value_length": len(SECRET_VALUE),
        "fingerprint": expected_fingerprint(fixture_path(SECRET_FILE), SECRET_KEY, SECRET_VALUE),
        "file": fixture_path(SECRET_FILE),
        "line": SECRET_LINE,
        "rule_id": "password",
        "message": "Password",
        "severity": "High",
    }


def test_to_json_legacy_compat_mode(detected_pair):
    assert detected_pair.to_json(redact=False) == {
        "key": SECRET_KEY,
        "value": SECRET_VALUE,
        "file": fixture_path(SECRET_FILE),
        "line": SECRET_LINE,
        "rule_id": "password",
        "message": "Password",
        "severity": "High",
    }


def test_fingerprint_stable_across_runs():
    def detect():
        args = parse_args(["-r", "password", fixture_path(SECRET_FILE)])
        return [secret.fingerprint for secret in run(args)]

    assert detect() == detect() == [expected_fingerprint(fixture_path(SECRET_FILE), SECRET_KEY, SECRET_VALUE)]


def test_main_json_output_redacted(monkeypatch, tmp_path):
    output = tmp_path.joinpath("secrets.json")
    monkeypatch.setattr(
        whispers.main,
        "parse_args",
        lambda: parse_args(["-r", "password", "-o", str(output), fixture_path(SECRET_FILE)]),
    )
    with pytest.raises(SystemExit):
        whispers.main.main()

    results = json.loads(output.read_text())
    assert SECRET_VALUE not in json.dumps(results)

    assert len(results) == 1
    assert results[0]["fingerprint"] == expected_fingerprint(fixture_path(SECRET_FILE), SECRET_KEY, SECRET_VALUE)
    assert results[0]["value_length"] == len(SECRET_VALUE)
    assert results[0]["file"] == fixture_path(SECRET_FILE)
    assert results[0]["line"] == SECRET_LINE
    assert results[0]["rule_id"] == "password"


def test_main_raw_compat_output(monkeypatch, tmp_path):
    output = tmp_path.joinpath("secrets.json")
    monkeypatch.setattr(
        whispers.main,
        "parse_args",
        lambda: parse_args(["--raw", "-r", "password", "-o", str(output), fixture_path(SECRET_FILE)]),
    )
    with pytest.raises(SystemExit):
        whispers.main.main()

    results = json.loads(output.read_text())
    assert len(results) == 1
    assert results[0] == {
        "key": SECRET_KEY,
        "value": SECRET_VALUE,
        "file": fixture_path(SECRET_FILE),
        "line": SECRET_LINE,
        "rule_id": "password",
        "message": "Password",
        "severity": "High",
    }


def test_main_warning_logs_redacted(monkeypatch, caplog):
    monkeypatch.setattr(whispers.main, "parse_args", lambda: parse_args(["-r", "password", fixture_path(SECRET_FILE)]))
    with caplog.at_level(logging.WARNING):
        with pytest.raises(SystemExit):
            whispers.main.main()

    assert SECRET_VALUE not in caplog.text
    assert expected_fingerprint(fixture_path(SECRET_FILE), SECRET_KEY, SECRET_VALUE)[:12] in caplog.text


def test_debug_logs_redacted(caplog):
    args = parse_args(["--debug", "-r", "password", fixture_path(SECRET_FILE)])
    with caplog.at_level(logging.DEBUG):
        secrets = list(run(args))

    assert len(secrets) == 1
    assert SECRET_VALUE not in caplog.text


def test_exception_chain_excludes_secret(caplog):
    args = parse_args([fixture_path("redaction-invalid.yml")])
    config = load_config(args)
    with caplog.at_level(logging.DEBUG):
        list(make_pairs(config, FIXTURE_PATH.joinpath("redaction-invalid.yml")))

    assert "Failed parsing file" in caplog.text
    assert SECRET_VALUE not in caplog.text
