from pathlib import Path

import pytest
import yaml
from yaml.resolver import Resolver

from tests.unit.conftest import fixture_path
from whispers.plugins.yml import WhisperLoader, Yml


@pytest.fixture
def dual_loaders():
    """Fixed dual-loader fixture: isolated plugin loader vs process-level SafeLoader"""
    process_loader = yaml.SafeLoader
    plugin_loader = WhisperLoader

    resolvers_before = {idx: list(res) for idx, res in Resolver.yaml_implicit_resolvers.items()}
    multi_constructors_before = dict(process_loader.yaml_multi_constructors)

    yield plugin_loader, process_loader

    # Process-level YAML state must be identical after any scan
    assert {idx: list(res) for idx, res in Resolver.yaml_implicit_resolvers.items()} == resolvers_before
    assert dict(process_loader.yaml_multi_constructors) == multi_constructors_before


def test_scan_does_not_mutate_process_level_yaml_boolean_semantics(dual_loaders):
    """One scan must not change process-level YAML boolean resolution"""
    plugin_loader, process_loader = dual_loaders

    # Sanity: default PyYAML semantics resolve yes/no/on/off as booleans
    assert yaml.safe_load("v: yes") == {"v": True}
    assert yaml.safe_load("v: on") == {"v": True}
    assert yaml.safe_load("v: off") == {"v": False}

    # Run a full scan through the plugin
    pairs = list(Yml().pairs(Path(fixture_path("hardcoded.yml"))))
    assert pairs

    # Process-level loader still resolves yes/no/on/off as booleans
    assert yaml.load("v: yes", Loader=process_loader) == {"v": True}
    assert yaml.load("v: on", Loader=process_loader) == {"v": True}
    assert yaml.load("v: no", Loader=process_loader) == {"v": False}
    assert yaml.load("v: off", Loader=process_loader) == {"v": False}
    assert yaml.safe_load("v: yes") == {"v": True}

    # Process-level resolvers for on/off/yes/no are still registered
    for idx in "OoYyNn":
        assert idx in Resolver.yaml_implicit_resolvers

    # The plugin's IaC multi-constructor must not leak into the process-level loader
    assert "" not in process_loader.yaml_multi_constructors

    # The isolated plugin loader keeps its own semantics: on/off/yes/no stay strings
    assert yaml.load("v: on", Loader=plugin_loader) == {"v": "on"}
    assert yaml.load("v: off", Loader=plugin_loader) == {"v": "off"}
    assert yaml.load("v: yes", Loader=plugin_loader) == {"v": "yes"}
    assert yaml.load("v: no", Loader=plugin_loader) == {"v": "no"}


def test_plugin_loader_preserves_on_off_strings(dual_loaders, tmp_path):
    """Scanning keeps on/off/yes/no values as strings"""
    fixture = tmp_path / "booleans.yml"
    fixture.write_text("enabled: on\ndisabled: off\nflag_yes: yes\nflag_no: no\n")

    pairs = {pair.key: pair.value for pair in Yml().pairs(fixture)}
    assert pairs["enabled"] == "on"
    assert pairs["disabled"] == "off"
    assert pairs["flag_yes"] == "yes"
    assert pairs["flag_no"] == "no"


def test_plugin_loader_handles_template_values(dual_loaders, tmp_path):
    """Unquoted {{ placeholder }} values remain scannable"""
    fixture = tmp_path / "template.yml"
    fixture.write_text("variable_password: {{ placeholder }}\n")

    pairs = {pair.key: pair.value for pair in Yml().pairs(fixture)}
    assert pairs["variable_password"] == "{{ placeholder }}"


def test_plugin_loader_resolves_aliases(dual_loaders, tmp_path):
    """Legal YAML anchors and aliases still resolve during scans"""
    fixture = tmp_path / "aliases.yml"
    fixture.write_text("defaults: &defaults\n  static_password: hardcoded0\nproduction:\n  <<: *defaults\n")

    pairs = {pair.key: pair.value for pair in Yml().pairs(fixture)}
    assert pairs["static_password"] == "hardcoded0"


def test_existing_findings_unchanged(dual_loaders):
    """Known findings from existing fixtures are preserved"""
    pairs = list(Yml().pairs(Path(fixture_path("hardcoded.yml"))))
    values = {(pair.key, pair.value) for pair in pairs}

    assert ("01_static_password", "hardcoded0") in values
    assert ("02_static_passwords", "Hardcoded1") in values
    assert ("02_static_passwords", "hardCoded2") in values
    assert ("02_static_passwords", "haRdcOded3") in values
    assert ("password", "hardcodEd") in values
