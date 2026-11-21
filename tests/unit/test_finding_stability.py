"""End-to-end stability of finding IDs through the real scan pipeline."""

from tests.unit.conftest import fixture_path
from whispers.core.args import parse_args
from whispers.core.finding import finding_id
from whispers.main import run


def _scan(extra_args=None):
    argv = list(extra_args or [])
    argv.append(fixture_path("apikeys-known.yml"))
    return list(run(parse_args(argv)))


def test_rescan_keeps_stable_finding_ids():
    """Two independent scans (restart simulation) report identical finding IDs."""
    first = [finding_id(pair) for pair in _scan(["-r", "apikey-known"])]
    second = [finding_id(pair) for pair in _scan(["-r", "apikey-known"])]
    assert first
    assert first == second


def test_findings_keep_rule_source_file_and_location():
    """Every emitted finding carries rule source, file and precise location."""
    for pair in _scan(["-r", "apikey-known"]):
        report = pair.to_json()
        assert report["id"] == finding_id(pair)
        assert report["rule_id"] == "apikey-known"
        assert report["rule_group"]
        assert report["file"].endswith("apikeys-known.yml")
        assert isinstance(report["line"], int) and report["line"] > 0


def test_finding_ids_survive_reordering():
    """A set of findings keeps the same IDs regardless of emission order."""
    pairs_a = _scan(["-r", "apikey-known"])
    pairs_b = list(reversed(pairs_a))
    ids_a = {finding_id(pair) for pair in pairs_a}
    ids_b = {finding_id(pair) for pair in pairs_b}
    assert ids_a == ids_b
