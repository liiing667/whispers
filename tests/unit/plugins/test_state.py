import yaml
from yaml.resolver import Resolver

from whispers.core.pairs import make_pairs
from whispers.models.appconfig import AppConfig
from whispers.models.pair import KeyValuePair
from whispers.plugins.json import Json
from whispers.plugins.xml import Xml
from whispers.plugins.yml import Yml


def test_yaml_reuse_after_cancel_does_not_leak_keypath(tmp_path):
    first = tmp_path.joinpath("first.yml")
    first.write_text("alpha:\n  beta: secretA\n  gamma: secretB\n")
    second = tmp_path.joinpath("second.yml")
    second.write_text("delta: secretC\n")

    plugin = Yml()
    pairs = plugin.pairs(first)
    next(pairs)
    pairs.close()

    assert plugin.keypath == []

    results = list(plugin.pairs(second))
    assert results
    assert all(not {"alpha", "beta", "gamma"}.intersection(pair.keypath) for pair in results)
    assert plugin.keypath == []


def test_json_reuse_after_cancel_does_not_leak_keypath(tmp_path):
    first = tmp_path.joinpath("first.json")
    first.write_text('{"alpha": {"beta": "secretA", "gamma": "secretB"}}')
    second = tmp_path.joinpath("second.json")
    second.write_text('{"delta": "secretC"}')

    plugin = Json()
    pairs = plugin.pairs(first)
    next(pairs)
    pairs.close()

    assert plugin.keypath == []

    results = list(plugin.pairs(second))
    assert results
    assert all(not {"alpha", "beta", "gamma"}.intersection(pair.keypath) for pair in results)
    assert plugin.keypath == []


def test_xml_reuse_after_cancel_does_not_leak_keypath(tmp_path):
    first = tmp_path.joinpath("first.xml")
    first.write_text("<root><alpha><beta>secretA</beta><gamma>secretB</gamma></alpha></root>")
    second = tmp_path.joinpath("second.xml")
    second.write_text("<root><delta>secretC</delta></root>")

    plugin = Xml()
    pairs = plugin.pairs(first)
    next(pairs)
    pairs.close()

    assert plugin.keypath == []

    results = list(plugin.pairs(second))
    assert results
    assert all(not {"alpha", "beta", "gamma"}.intersection(pair.keypath) for pair in results)
    assert plugin.keypath == []


def test_empty_documents_do_not_leave_state(tmp_path):
    for plugin, filename in [(Yml(), "empty.yml"), (Json(), "empty.json"), (Xml(), "empty.xml")]:
        filepath = tmp_path.joinpath(filename)
        filepath.write_text("")

        assert list(plugin.pairs(filepath)) == []
        assert plugin.keypath == []


def test_yaml_scan_does_not_mutate_process_yaml_state(tmp_path):
    filepath = tmp_path.joinpath("scan.yml")
    filepath.write_text("enabled: on\ndisabled: off\n")
    resolvers = {key: list(value) for key, value in Resolver.yaml_implicit_resolvers.items()}
    constructors = dict(yaml.SafeLoader.yaml_multi_constructors)

    assert list(Yml().pairs(filepath))

    assert {key: list(value) for key, value in Resolver.yaml_implicit_resolvers.items()} == resolvers
    assert dict(yaml.SafeLoader.yaml_multi_constructors) == constructors
    assert yaml.safe_load("enabled: on") == {"enabled": True}


def test_yaml_empty_value_remains_null(tmp_path):
    filepath = tmp_path.joinpath("empty-value.yml")
    filepath.write_text("empty_value:\n")

    assert list(Yml().pairs(filepath)) == []


def test_make_pairs_resets_cached_plugin_instance(tmp_path, monkeypatch):
    first = tmp_path.joinpath("first.yml")
    first.write_text("alpha:\n  beta: secretA\n")
    second = tmp_path.joinpath("second.yml")
    second.write_text("delta: secretC\n")
    plugin = Yml()

    monkeypatch.setattr("whispers.core.pairs.load_plugin", lambda *args, **kwargs: lambda: plugin)

    config = AppConfig({})
    pairs = make_pairs(config, first)
    while next(pairs).key == "file":
        pass
    pairs.close()

    results = list(make_pairs(config, second))
    assert results
    assert all("alpha" not in pair.keypath for pair in results)
    assert all("beta" not in pair.keypath for pair in results)
    assert plugin.keypath == []


def test_make_pairs_resets_after_plugin_crash(tmp_path, monkeypatch):
    first = tmp_path.joinpath("first.yml")
    first.write_text("alpha: secretA\n")
    second = tmp_path.joinpath("second.yml")
    second.write_text("delta: secretC\n")

    class CrashPlugin:
        def __init__(self):
            self.keypath = []
            self.files = 0

        def reset(self):
            self.keypath.clear()

        def pairs(self, filepath):
            self.files += 1
            self.keypath.append(filepath.name)
            yield KeyValuePair("partial", filepath.name, list(self.keypath))
            if self.files == 1:
                raise RuntimeError("parser crashed")

            yield KeyValuePair("complete", filepath.name, list(self.keypath))

    plugin = CrashPlugin()
    monkeypatch.setattr("whispers.core.pairs.load_plugin", lambda *args, **kwargs: lambda: plugin)

    config = AppConfig({})
    list(make_pairs(config, first))
    assert plugin.keypath == []

    results = list(make_pairs(config, second))
    assert results
    assert all("first.yml" not in pair.keypath for pair in results)
    assert plugin.keypath == []
