import json
import shutil
import subprocess
from pathlib import Path

import pytest

from whispers.core.args import parse_args
from whispers.core.config import load_config
from whispers.core.history import GitHistoryScanner
from whispers.core.rules import load_rules
from whispers.core.scope import load_scope
from whispers.main import run

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")


def git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", repo.as_posix(), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def make_repository(path: Path, values) -> list:
    path.mkdir()
    git(path, "init", "-q")
    git(path, "config", "user.email", "test@example.invalid")
    git(path, "config", "user.name", "Whispers Test")
    commits = []
    for index, value in enumerate(values):
        path.joinpath("config.yml").write_text(f"password: {value}\n")
        git(path, "add", ".")
        git(path, "commit", "-qm", f"commit-{index}")
        commits.append(git(path, "rev-parse", "HEAD"))
    return commits


def findings_for(repo: Path, state: Path):
    args = parse_args(["--git", "--git-state", state.as_posix(), repo.as_posix()])
    return list(run(args))


def test_history_freezes_range_generation_and_blobs(tmp_path):
    repo = tmp_path.joinpath("repo")
    commits = make_repository(repo, ["first-secret"])
    state = repo.joinpath(".git", "history.json")

    args = parse_args(["--git", "--git-state", state.as_posix(), repo.as_posix()])
    scope = load_scope(args, load_config(args))

    assert scope.commit_range == commits
    assert scope.generation
    assert scope.scanned_blobs == set()

    persisted = json.loads(state.read_text())
    assert set(persisted["commits"]) == set(commits)
    assert persisted["generation"] == scope.generation
    assert persisted["scanned_blobs"] == []

    findings = list(run(args))
    assert findings
    assert all(finding.commit == commits[-1] for finding in findings)
    assert all(finding.blob for finding in findings)
    assert all(finding.path == "config.yml" for finding in findings)
    assert all(finding.stage for finding in findings)
    assert json.loads(state.read_text())["status"] == "complete"


def test_new_head_does_not_keep_revoked_findings(tmp_path):
    repo = tmp_path.joinpath("repo")
    commits = make_repository(repo, ["revoked-secret", "current-value"])
    state = repo.joinpath(".git", "history.json")

    first = findings_for(repo, state)
    assert any(finding.commit == commits[0] for finding in first)

    git(repo, "reset", "--hard", commits[0])
    second = findings_for(repo, state)

    assert not any(finding.commit == commits[1] for finding in second)
    assert all(finding.commit == commits[0] for finding in second)
    persisted = json.loads(state.read_text())
    assert persisted["commits"] == [commits[0]]
    assert persisted["status"] == "complete"


def test_interrupted_scan_resumes_the_same_generation(tmp_path, monkeypatch):
    repo = tmp_path.joinpath("repo")
    commits = make_repository(repo, ["secret-one", "secret-two"])
    state = repo.joinpath(".git", "history.json")

    import whispers.core.pairs as pairs_module

    original = pairs_module.make_pairs
    calls = []

    def interrupted(config, file):
        calls.append(file)
        if len(calls) > 1:
            raise RuntimeError("interrupted")
        return original(config, file)

    monkeypatch.setattr(pairs_module, "make_pairs", interrupted)
    scanner = GitHistoryScanner(repo, state_path=state)
    generation = scanner.generation
    with pytest.raises(RuntimeError):
        list(scanner.pairs())

    persisted = json.loads(state.read_text())
    assert persisted["status"] == "in_progress"
    assert persisted["generation"] == generation
    assert set(persisted["commits"]) == set(commits)
    assert persisted["scanned_blobs"]

    monkeypatch.setattr(pairs_module, "make_pairs", original)
    resumed = GitHistoryScanner(repo, state_path=state)
    assert resumed.generation == generation
    assert resumed.commits == commits
    assert resumed.scanned_blobs
    pairs = list(resumed.pairs())
    assert {pair.value for pair in pairs if pair.key == "password"} == {"secret-one", "secret-two"}


def test_shallow_empty_and_normal_ranges(tmp_path):
    source = tmp_path.joinpath("source")
    commits = make_repository(source, ["one-secret", "two-secret"])

    shallow = tmp_path.joinpath("shallow")
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", source.as_uri(), shallow.as_posix()],
        check=True,
        capture_output=True,
        text=True,
    )
    shallow_scope = GitHistoryScanner(shallow, state_path=shallow.joinpath(".git", "history.json"))
    assert len(shallow_scope.commits) == 1
    assert [(pair.value) for pair in shallow_scope.pairs() if pair.key == "password"] == ["two-secret"]

    empty = tmp_path.joinpath("empty")
    empty.mkdir()
    git(empty, "init", "-q")
    empty_scope = GitHistoryScanner(empty, state_path=empty.joinpath(".git", "history.json"))
    assert empty_scope.commits == ()
    assert list(empty_scope.pairs()) == []

    ranged = GitHistoryScanner(
        source,
        revision="HEAD~1..HEAD",
        state_path=source.joinpath(".git", "range.json"),
    )
    assert ranged.commits == [commits[1]]
    assert [pair.value for pair in ranged.pairs() if pair.key == "password"] == ["two-secret"]
