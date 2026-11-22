"""Git history source plugin.

The plugin exposes the same ``pairs()`` entry point as the format plugins while
using :class:`whispers.core.history.GitHistoryScanner` to freeze and resume the
commit/blob snapshot behind those pairs.
"""

import hashlib
import re
import tempfile
from pathlib import Path
from typing import Any, Iterator, Optional, Union

from whispers.core.history import (
    CommitRange,
    GitHistoryError,
    GitHistoryScanner,
    HistoryEntry,
    HistorySnapshot,
    HistoryState,
)
from whispers.models.pair import KeyValuePair

COMMIT_RE = re.compile(r"^commit ([0-9a-fA-F]{7,64})(?:\s+.*)?$")
DIFF_RE = re.compile(r"^diff --git a/(.*) b/(.*)$")
INDEX_RE = re.compile(r"^index ([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)(?:\s+\d+)?$")


def looks_like_git_log(path: Union[str, Path, None]) -> bool:
    """Whether a file starts with a Git ``log -p`` commit header."""
    if not path:
        return False
    try:
        with Path(path).open("rb") as handle:
            head = handle.read(4096)
    except OSError:
        return False
    if not head:
        return False
    first = head.splitlines()[0] if head.splitlines() else b""
    return bool(COMMIT_RE.match(first.decode("utf-8", "replace").strip()))


class GitLog:
    """Read findings from a ``git log -p`` stream and label their commit/blob."""

    def __init__(
        self,
        source: Union[str, Path, None] = None,
        config: Any = None,
        content: Optional[str] = None,
    ) -> None:
        self.source = Path(source) if source is not None else None
        self.config = config
        self.content = content

    @staticmethod
    def _blob_id(content: bytes) -> str:
        header = f"blob {len(content)}\0".encode("ascii")
        return hashlib.sha1(header + content).hexdigest()

    @staticmethod
    def _decode_path(value: str) -> str:
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        return value.split("\t", 1)[0].strip()

    def _patches(self):
        commit = ""
        path = ""
        blob = ""
        mode = "100644"
        additions = []
        in_hunk = False

        def flush():
            nonlocal additions, path, blob, mode, in_hunk
            if commit and path and additions and path != "/dev/null":
                yield commit, path, blob or "", mode, list(additions)
            additions = []
            path = ""
            blob = ""
            mode = "100644"
            in_hunk = False

        current = None
        if self.source is None and self.content is None:
            return
        text = self.content
        if text is None:
            text = self.source.read_text(encoding="utf-8", errors="replace")
        for lineno, raw in enumerate(text.splitlines(), 1):
            match = COMMIT_RE.match(raw)
            if match:
                if current is not None:
                    yield from flush()
                commit = match.group(1)
                path = ""
                blob = ""
                mode = "100644"
                additions = []
                in_hunk = False
                current = commit
                continue

            match = DIFF_RE.match(raw)
            if match:
                if current is not None:
                    yield from flush()
                path = self._decode_path(match.group(2))
                in_hunk = False
                continue

            if raw.startswith("new file mode "):
                mode = raw.rsplit(" ", 1)[-1].strip() or "100644"
                continue

            match = INDEX_RE.match(raw)
            if match:
                blob = match.group(2)
                continue

            if raw.startswith("+++ "):
                candidate = self._decode_path(raw[4:])
                if candidate and candidate != "/dev/null":
                    path = candidate[2:] if candidate.startswith("b/") else candidate
                continue

            if raw.startswith("--- "):
                continue

            if raw.startswith("@@"):
                in_hunk = True
                continue

            if in_hunk:
                if raw.startswith("+") and not raw.startswith("+++"):
                    additions.append((lineno, raw[1:]))
                elif raw.startswith("\\ No newline"):
                    continue

        if current is not None:
            yield from flush()

    def pairs(self, filepath: Union[str, Path, None] = None) -> Iterator[KeyValuePair]:
        if filepath is not None:
            new_source = Path(filepath)
            if new_source != self.source:
                self.content = None
            self.source = new_source
        if self.source is None:
            return
        from whispers.core.pairs import make_pairs
        from whispers.core.utils import find_line_number
        from whispers.models.appconfig import AppConfig

        config = self.config if self.config is not None else AppConfig()
        if isinstance(config, dict):
            config = AppConfig(config)

        tempdir = tempfile.TemporaryDirectory(prefix="whispers-git-log-")
        try:
            for commit, path, blob, mode, additions in self._patches():
                content = "\n".join(text for _, text in additions) + "\n"
                relative = Path(*[part for part in Path(path).parts if part not in ("", ".", "..")])
                target = Path(tempdir.name).joinpath(relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8", errors="replace")
                blob = blob or self._blob_id(content.encode("utf-8"))
                generation = "git-log-" + hashlib.sha256(
                    f"{self.source}|{commit}|{path}|{blob}".encode("utf-8", "surrogateescape")
                ).hexdigest()[:16]

                parsed_pairs = list(make_pairs(config, target) or [])
                if not any(pair.key != "file" for pair in parsed_pairs):
                    from whispers.core.pairs import filter_included, filter_static
                    from whispers.plugins.plaintext import Plaintext

                    for raw_pair in Plaintext().pairs(target):
                        static_pair = filter_static(raw_pair)
                        if static_pair is None:
                            continue
                        included_pair = filter_included(config, static_pair)
                        if included_pair is not None:
                            parsed_pairs.append(included_pair)

                for pair in parsed_pairs:
                    synthetic_line = find_line_number(pair) or pair.line
                    pair.line = additions[synthetic_line - 1][0] if 0 < synthetic_line <= len(additions) else 0
                    pair.commit = commit
                    pair.commit_sha = commit
                    pair.blob = blob
                    pair.blob_sha = blob
                    pair.object_id = blob
                    pair.path = path
                    pair.generation = generation
                    pair.scan_generation = generation
                    pair.stage = "history"
                    pair.detection_stage = "history"
                    pair.phase = "history"
                    pair.history = {
                        "commit": commit,
                        "blob": blob,
                        "path": path,
                        "generation": generation,
                        "stage": "history",
                    }
                    pair.file = self.source.as_posix()
                    if pair.key == "file":
                        pair.value = pair.file
                        pair.keypath = [pair.file]
                    pair.finding_id = "whs-" + hashlib.sha256(
                        "|".join(
                            [commit, blob, path, str(pair.key), str(pair.value), str(pair.line)]
                        ).encode("utf-8", "surrogateescape")
                    ).hexdigest()[:16]
                    pair.id = pair.finding_id
                    yield pair
        finally:
            tempdir.cleanup()


class GitLogScope:
    """History-like scope for a ``git log -p`` stream."""

    is_history = True

    def __init__(self, source: Union[str, Path], config: Any = None) -> None:
        from whispers.core.history import CommitRange, HistoryState, _utcnow

        self.source = Path(source)
        self.config = config
        self._content = self.source.read_text(encoding="utf-8", errors="replace")
        self._entries = None
        identities = self._identities()
        commits = []
        blobs = []
        for commit, path, blob, mode, _ in identities:
            if commit not in commits:
                commits.append(commit)
            if blob and blob not in blobs:
                blobs.append(blob)
        self.generation = "git-log-" + hashlib.sha256(
            "|".join([self.source.as_posix(), *commits, *blobs]).encode("utf-8", "surrogateescape")
        ).hexdigest()[:32]
        self.state = HistoryState(
            repository=self.source.parent.as_posix(),
            git_dir="",
            worktree=self.source.parent.as_posix(),
            head=commits[0] if commits else "",
            revision="git-log",
            generation=self.generation,
            commits=commits,
            scanned=blobs,
            status="complete",
            started_at=_utcnow(),
        )
        self.commit_range = CommitRange(commits, spec="git-log")
        self.commits = self.commit_range
        self.scanned_blobs = set(blobs)
        self.scanned_blob_ids = list(blobs)
        self.status = "complete"
        self.state_path = None

    def _identities(self):
        if self._entries is None:
            self._entries = list(GitLog(self.source, self.config, self._content)._patches())
        return self._entries

    @property
    def entries(self):
        from whispers.core.history import HistoryEntry

        return [
            HistoryEntry(
                commit=commit,
                blob=blob,
                path=path,
                mode=mode,
                generation=self.generation,
                repository=self.source.parent.as_posix(),
                worktree=self.source.parent.as_posix(),
            )
            for commit, path, blob, mode, _ in self._identities()
        ]

    @property
    def files(self):
        return [Path(entry.file) for entry in self.entries]

    def __iter__(self):
        return iter(self.entries)

    def __len__(self):
        return len(self.entries)

    @property
    def paths(self):
        return [entry.path for entry in self.entries]

    def pairs(self) -> Iterator[KeyValuePair]:
        return GitLog(self.source, self.config, self._content).pairs()

    iter_pairs = pairs

    def findings(self, rules: Any) -> Iterator[KeyValuePair]:
        from whispers.core.secrets import detect_secrets

        return detect_secrets(rules, self.pairs())

    def scan(self, rules: Any = None) -> Iterator[KeyValuePair]:
        return self.pairs() if rules is None else self.findings(rules)

    def report(self) -> dict:
        return {
            "repository": self.source.parent.as_posix(),
            "generation": self.generation,
            "commit_range": list(self.commits),
            "commits": list(self.commits),
            "scanned_blobs": sorted(self.scanned_blobs),
            "status": self.status,
            "source": self.source.as_posix(),
        }

    to_report = report

    @property
    def snapshot(self):
        from whispers.core.history import HistorySnapshot

        return HistorySnapshot(
            repository=self.state.repository,
            git_dir="",
            worktree=self.state.worktree,
            head=self.state.head,
            revision=self.state.revision,
            generation=self.generation,
            commits=self.commit_range,
            scanned_blobs=frozenset(self.scanned_blobs),
            status=self.status,
        )

    def freeze(self):
        return self.snapshot


class Git(GitHistoryScanner):
    """Git history source plugin."""

    def __new__(cls, repository=None, *args, **kwargs):
        if repository is not None:
            try:
                path = Path(repository)
                if path.is_file() and looks_like_git_log(path):
                    return GitLogScope(path, kwargs.get("config"))
            except (OSError, TypeError, ValueError):
                pass
        return super().__new__(cls)

    def __init__(
        self,
        repository: Union[str, Path, None] = None,
        revision: Any = None,
        state_path: Union[str, Path, None] = None,
        config: Any = None,
        **kwargs,
    ) -> None:
        self._pending_repository = repository
        self._pending_revision = revision
        self._pending_state_path = state_path
        self._pending_config = config
        self._pending_kwargs = kwargs
        if repository is not None:
            super().__init__(
                repository,
                revision=revision,
                state_path=state_path,
                config=config,
                **kwargs,
            )
        else:
            self.args = None
            self.source = Path(".")
            self.revision = revision or "HEAD"
            self.resume = kwargs.get("resume")
            self.reset = bool(kwargs.get("reset", False))
            self.depth = kwargs.get("depth")
            self.path_filters = []
            self.config = config
            self.state_path = Path(state_path) if state_path else None
            self.state = None
            self._entries_by_commit = {}
            self._tempdir = None
            self._closed = False

    def _scanner(self, filepath: Union[str, Path, None] = None) -> GitHistoryScanner:
        if getattr(self, "state", None) is not None and filepath is None:
            return self

        repository = filepath or self._pending_repository
        if repository is None:
            raise GitHistoryError("A Git repository is required")
        return GitHistoryScanner(
            repository,
            revision=self._pending_revision,
            state_path=self._pending_state_path,
            config=self._pending_config,
            **self._pending_kwargs,
        )

    def pairs(self, filepath: Union[str, Path, None] = None) -> Iterator[KeyValuePair]:
        if filepath is not None and Path(filepath).is_file() and looks_like_git_log(filepath):
            return GitLog(filepath, self._pending_config).pairs()
        scanner = self._scanner(filepath)
        if scanner is self:
            return GitHistoryScanner.pairs(self)
        return scanner.pairs()

    parse = pairs

    def findings(self, rules: Any, filepath: Union[str, Path, None] = None) -> Iterator[KeyValuePair]:
        if getattr(self, "state", None) is not None and filepath is None:
            return GitHistoryScanner.findings(self, rules)
        scanner = self._scanner(filepath)
        return scanner.findings(rules)

    detect = findings

    def scan(self, filepath: Union[str, Path, None] = None, rules: Any = None) -> Iterator[KeyValuePair]:
        if filepath is not None and Path(filepath).is_file() and looks_like_git_log(filepath):
            return GitLog(filepath, self._pending_config).pairs()
        scanner = self._scanner(filepath)
        if scanner is self:
            if rules is None:
                return GitHistoryScanner.pairs(self)
            return GitHistoryScanner.findings(self, rules)
        if rules is None:
            return scanner.pairs()
        return scanner.findings(rules)


GitPlugin = Git
GitHistoryPlugin = Git
HistoryPlugin = Git
GitSource = Git
GitHistorySource = Git

__all__ = [
    "CommitRange",
    "Git",
    "GitHistory",
    "GitHistoryError",
    "GitHistoryPlugin",
    "GitHistoryScanner",
    "GitHistorySource",
    "GitHistoryState",
    "GitLog",
    "GitLogScope",
    "GitPlugin",
    "GitSource",
    "HistoryEntry",
    "HistoryPlugin",
    "HistoryResume",
    "HistoryScan",
    "HistoryScanner",
    "HistoryScope",
    "HistorySnapshot",
    "HistorySnapshotState",
    "HistoryState",
    "HistoryStateSnapshot",
    "looks_like_git_log",
]


def __getattr__(name):
    # Export the descriptive core aliases lazily without a second definition.
    if name in (
        "GitHistory",
        "GitError",
        "HistoryError",
        "GitHistoryScope",
        "GitHistorySnapshot",
        "GitHistoryState",
        "GitScanner",
        "HistoryResume",
        "HistoryScan",
        "HistoryScanner",
        "HistoryScope",
        "HistorySnapshotState",
        "HistoryStateSnapshot",
        "ScanSnapshot",
        "ScanState",
    ):
        from whispers.core import history

        return getattr(history, name)
    raise AttributeError(name)


def pairs(repository: Union[str, Path], **kwargs) -> Iterator[KeyValuePair]:
    if Path(repository).is_file() and looks_like_git_log(repository):
        return GitLog(repository, kwargs.get("config")).pairs()
    return Git(repository, **kwargs).pairs()


def scan(repository: Union[str, Path], rules: Any = None, **kwargs) -> Iterator[KeyValuePair]:
    if Path(repository).is_file() and looks_like_git_log(repository):
        return GitLog(repository, kwargs.get("config")).pairs()
    return Git(repository, **kwargs).scan(rules=rules)
