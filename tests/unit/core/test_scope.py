import re

import pytest

from tests.unit.conftest import FIXTURE_PATH, config_path, fixture_path
from whispers.core.args import parse_args
from whispers.core.config import load_config
from whispers.core.scope import load_scope
from whispers.main import run
from whispers.models.appconfig import AppConfig


@pytest.mark.parametrize(
    ("src", "expected"),
    [
        (fixture_path("404"), 0),
        (fixture_path(".npmrc"), 1),
        (fixture_path(), len(list(FIXTURE_PATH.rglob("**/*")))),
    ],
)
def test_load_scope(src, expected):
    argv = ["-F", "None", src]
    args = parse_args(argv)
    config = load_config(args)
    scope = load_scope(args, config)
    assert len(list(scope)) == expected


@pytest.mark.parametrize(
    ("config_file", "expected"),
    [("include_files.yml", [FIXTURE_PATH.joinpath(".pypirc")]), ("exclude_files.yml", [])],
)
def test_load_scope_config(config_file, expected):
    args = parse_args(["-c", config_path(config_file), fixture_path()])
    config = load_config(args)
    scope = load_scope(args, config)
    assert list(scope) == expected


def test_load_scope_snapshot_binds_config():
    args = parse_args(["-c", config_path("include_files.yml"), fixture_path()])
    config = load_config(args)
    version = config.version
    ast = config.ast
    scope = load_scope(args, config)

    # Simulate a config hot reload after the scan has started.
    config.include.files = ["**/*.yml"]
    config.exclude.files = re.compile(".*")
    config.ast = True

    assert list(scope) == [FIXTURE_PATH.joinpath(".pypirc")]
    assert scope.config_version == version
    assert scope.ast is ast
    assert scope.report()["config_version"] == version


def test_load_scope_snapshot_version_changes():
    args = parse_args(["-c", config_path("include_files.yml"), fixture_path()])
    config = load_config(args)
    version = config.version

    config.ast = not config.ast
    scope = load_scope(args, config)

    assert scope.config_version != version


def test_load_scope_nested_directories(tmp_path):
    root = tmp_path.joinpath("root")
    nested = root.joinpath("nested", "deep")
    nested.mkdir(parents=True)
    nested.joinpath("secret.yml").write_text("password: hardcoded\n")
    root.joinpath("skip.yml").write_text("password: hardcoded\n")

    config = AppConfig({"include": {"files": ["**/*.yml"]}, "exclude": {"files": [".*skip.*"]}})
    args = parse_args([root.as_posix()])
    scope = load_scope(args, config)

    assert list(scope) == [nested.joinpath("secret.yml")]


def test_run_reports_config_version():
    args = parse_args(["-F", "None", fixture_path(".pypirc")])
    secrets = list(run(args))

    assert secrets
    assert all(secret.config_version == args.config_version for secret in secrets)
    assert all(secret.to_json()["config_version"] == args.config_version for secret in secrets)
