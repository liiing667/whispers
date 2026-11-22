"""Stable, resumable Git history scanning.

A history scan is accepted against one frozen commit range.  The range, the
generation derived from it, and the blobs that have already been parsed are
persisted before any repository content is read.  A restart can therefore
resume the same snapshot instead of mixing findings from a moving HEAD into a
new scan.
"""

import hashlib
import json
import logging
import os
import shlex
import subprocess
import tempfile
from argparse import Namespace
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, Iterator, List, Optional, Sequence, Tuple, Union

from whispers.core.utils import find_line_number
from whispers.models.appconfig import AppConfig
from whispers.models.pair import KeyValuePair

STATE_VERSION = 1
STATE_SUFFIX = "whispers-history.json"
HISTORY_STATE_FILE = STATE_SUFFIX
DEFAULT_HISTORY_STATE = STATE_SUFFIX


class GitHistoryError(RuntimeError):
    """Raised when a Git history snapshot cannot be built."""


class CommitRange(tuple):
    """Ordered commit list that also remembers the revision specification."""

    def __new__(cls, commits: Iterable[str] = (), spec: Any = None):
        value = super().__new__(cls, tuple(commits))
        value.spec = spec if spec is not None else ""
        return value

    @property
    def commits(self) -> Tuple[str, ...]:
        return tuple(self)

    @property
    def revision(self) -> Any:
        return self.spec

    def as_list(self) -> List[str]:
        return list(self)

    def __str__(self) -> str:
        if isinstance(self.spec, str) and self.spec:
            return self.spec
        return ",".join(self)

    def __getattr__(self, name):
        return getattr(str(self), name)

    def __eq__(self, other) -> bool:
        if isinstance(other, str):
            return str(self) == other
        if isinstance(other, (list, tuple)):
            return sorted(self) == sorted(other)
        return tuple.__eq__(self, other)

    def __hash__(self) -> int:
        return tuple.__hash__(self)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _revision_value(revision: Any) -> Any:
    if isinstance(revision, (list, tuple)):
        return [str(item) for item in revision]
    if revision is None:
        return "HEAD"
    return str(revision)


def _revision_args(revision: Any) -> List[str]:
    if isinstance(revision, (list, tuple)):
        return [str(item) for item in revision]

    text = "HEAD" if revision is None else str(revision).strip()
    if not text:
        return ["HEAD"]

    try:
        return shlex.split(text)
    except ValueError:
        return [text]


def _revision_key(revision: Any) -> str:
    return json.dumps(_revision_value(revision), sort_keys=True)


def _decode(value: bytes) -> str:
    return value.decode("utf-8", "surrogateescape")


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", "backslashreplace")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return str(value)


@dataclass
class HistoryState:
    """Persisted state for one history generation."""

    repository: str
    git_dir: str
    worktree: str
    head: str
    revision: Any
    generation: str
    commits: List[str] = field(default_factory=list)
    generation_id: int = 1
    scanned: List[str] = field(default_factory=list)
    blobs: Dict[str, List[dict]] = field(default_factory=dict)
    status: str = "in_progress"
    started_at: str = field(default_factory=_utcnow)
    updated_at: str = field(default_factory=_utcnow)
    depth: Optional[int] = None
    paths: List[str] = field(default_factory=list)
    version: int = STATE_VERSION

    @property
    def scanned_blobs(self) -> set:
        return set(self.scanned)

    @property
    def scanned_blob_ids(self) -> List[str]:
        return list(self.scanned)

    @property
    def commit_range(self) -> CommitRange:
        return CommitRange(self.commits, spec=self.revision)

    @property
    def range(self) -> Any:
        return self.revision

    @property
    def scan_generation(self) -> str:
        return self.generation

    @property
    def generation_number(self) -> int:
        return self.generation_id

    def mark_blob(self, oid: str) -> None:
        if oid not in self.scanned:
            self.scanned.append(oid)
        self.updated_at = _utcnow()

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "repository": self.repository,
            "git_dir": self.git_dir,
            "worktree": self.worktree,
            "head": self.head,
            "revision": _json_safe(self.revision),
            "generation": self.generation,
            "generation_id": self.generation_id,
            "commit_range": list(self.commits),
            "commits": list(self.commits),
            "scanned_blobs": list(self.scanned),
            "blobs": _json_safe(self.blobs),
            "status": self.status,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "depth": self.depth,
            "paths": list(self.paths),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)

    as_dict = to_dict

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __contains__(self, key: str) -> bool:
        return key in self.to_dict()

    def __iter__(self):
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())

    def keys(self):
        return self.to_dict().keys()

    def items(self):
        return self.to_dict().items()

    def values(self):
        return self.to_dict().values()

    @classmethod
    def from_dict(cls, data: dict) -> "HistoryState":
        commits = data.get(
            "commits",
            data.get("commit_range", data.get("commit_list", data.get("commits_scanned", []))),
        ) or []
        scanned = data.get(
            "scanned_blobs",
            data.get(
                "scanned_blob_ids",
                data.get("scanned", data.get("blob_ids", data.get("visited", data.get("seen", [])))),
            ),
        ) or []
        blob_data = data.get("blobs", data.get("pairs", data.get("findings", data.get("cache", {})))) or {}
        if isinstance(scanned, dict):
            blob_data = {**scanned, **blob_data}
            scanned = list(scanned)
        status = str(data.get("status", data.get("state", "in_progress")))
        if status in ("done", "finished", "success", "ok"):
            status = "complete"
        version = int(data.get("version", STATE_VERSION) or STATE_VERSION)
        if version < STATE_VERSION:
            version = STATE_VERSION
        return cls(
            repository=str(data.get("repository", "")),
            git_dir=str(data.get("git_dir", "")),
            worktree=str(data.get("worktree", "")),
            head=str(data.get("head", "")),
            revision=data.get("revision", data.get("range", "HEAD")),
            generation=str(data.get("generation", data.get("generation_id", ""))),
            commits=[str(item) for item in commits],
            generation_id=int(data.get("generation_id", 1) or 1),
            scanned=[str(item) for item in scanned],
            blobs={
                str(oid): [
                    dict(pair)
                    for pair in (pairs if isinstance(pairs, list) else [pairs])
                    if isinstance(pair, dict)
                ]
                for oid, pairs in blob_data.items()
            },
            status=status,
            started_at=str(data.get("started_at", _utcnow())),
            updated_at=str(data.get("updated_at", _utcnow())),
            depth=data.get("depth"),
            paths=[str(item) for item in data.get("paths", [])],
            version=version,
        )


@dataclass(frozen=True)
class HistorySnapshot:
    """Immutable view of the range and identities accepted for one scan."""

    repository: str
    git_dir: str
    worktree: str
    head: str
    revision: Any
    generation: str
    commits: CommitRange
    scanned_blobs: FrozenSet[str] = frozenset()
    generation_id: int = 1
    status: str = "in_progress"

    @property
    def commit_range(self) -> CommitRange:
        return self.commits

    @property
    def range(self) -> Any:
        return self.revision

    @property
    def scan_generation(self) -> str:
        return self.generation

    @property
    def generation_number(self) -> int:
        return self.generation_id

    def report(self) -> dict:
        return {
            "repository": self.repository,
            "git_dir": self.git_dir,
            "worktree": self.worktree,
            "head": self.head,
            "revision": _json_safe(self.revision),
            "generation": self.generation,
            "generation_id": self.generation_id,
            "commit_range": list(self.commits),
            "commits": list(self.commits),
            "scanned_blobs": sorted(self.scanned_blobs),
            "status": self.status,
        }

    to_report = report


@dataclass(frozen=True, eq=False)
class HistoryEntry:
    """One path/blob pair observed in a frozen commit."""

    commit: str
    blob: str
    path: str
    mode: str
    generation: str = ""
    repository: str = ""
    worktree: str = ""

    @property
    def commit_sha(self) -> str:
        return self.commit

    @property
    def blob_sha(self) -> str:
        return self.blob

    @property
    def object_id(self) -> str:
        return self.blob

    @property
    def file(self) -> str:
        base = self.worktree or self.repository
        return Path(base, self.path).as_posix() if base else self.path

    def as_posix(self) -> str:
        return self.file

    def __fspath__(self) -> str:
        return self.file

    def __str__(self) -> str:
        return self.file

    def __eq__(self, other) -> bool:
        if isinstance(other, HistoryEntry):
            return (
                self.commit,
                self.blob,
                self.path,
                self.mode,
                self.generation,
            ) == (
                other.commit,
                other.blob,
                other.path,
                other.mode,
                other.generation,
            )
        if isinstance(other, (str, Path)):
            candidate = other.as_posix() if isinstance(other, Path) else str(other)
            return candidate in (self.file, self.path)
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.commit, self.blob, self.path, self.mode, self.generation))


def _git_env() -> Dict[str, str]:
    env = dict(os.environ)
    env.setdefault("GIT_OPTIONAL_LOCKS", "0")
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    return env


def run_git(repository: Union[str, Path], arguments: Sequence[str]) -> subprocess.CompletedProcess:
    """Run one Git command without a shell."""
    command = ["git", "-C", str(repository), *[str(item) for item in arguments]]
    try:
        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            env=_git_env(),
            check=False,
        )
    except FileNotFoundError as error:  # pragma: no cover - environment failure
        raise GitHistoryError("Git executable is not available") from error
    except OSError as error:  # pragma: no cover - environment failure
        raise GitHistoryError(f"Unable to run Git: {error}") from error


def _command_error(result: subprocess.CompletedProcess) -> str:
    message = _decode(result.stderr or b"").strip()
    if message:
        return message.splitlines()[-1]
    return f"git exited with status {result.returncode}"


def _git_output(repository: Union[str, Path], arguments: Sequence[str]) -> bytes:
    result = run_git(repository, arguments)
    if result.returncode != 0:
        raise GitHistoryError(_command_error(result))
    return result.stdout or b""


def _looks_like_bare_repository(path: Path) -> bool:
    return path.joinpath("HEAD").is_file() and path.joinpath("objects").is_dir()


def resolve_repository(source: Union[str, Path]) -> Tuple[Path, Path, Path]:
    """Return (git command directory, worktree, absolute git directory)."""
    path = Path(source).expanduser()

    if path.is_file():
        if path.name == ".git":
            path = path.parent
        else:
            path = path.parent

    if path.name == ".git":
        path = path.parent

    if not path.exists():
        raise GitHistoryError(f"Git repository does not exist: {path}")

    candidates = [path]
    if path.is_dir():
        candidates.append(path)

    for candidate in candidates:
        result = run_git(candidate, ["rev-parse", "--show-toplevel"])
        if result.returncode == 0:
            worktree = Path(_decode(result.stdout).strip()).resolve()
            git_dir_result = run_git(candidate, ["rev-parse", "--absolute-git-dir"])
            if git_dir_result.returncode != 0:
                raise GitHistoryError(_command_error(git_dir_result))
            return worktree, worktree, Path(_decode(git_dir_result.stdout).strip()).resolve()

        bare = run_git(candidate, ["rev-parse", "--is-bare-repository"])
        if bare.returncode == 0 and _decode(bare.stdout).strip().lower() == "true":
            git_dir_result = run_git(candidate, ["rev-parse", "--absolute-git-dir"])
            if git_dir_result.returncode != 0:
                raise GitHistoryError(_command_error(git_dir_result))
            resolved = candidate.resolve()
            return resolved, resolved, Path(_decode(git_dir_result.stdout).strip()).resolve()

        if _looks_like_bare_repository(candidate):
            resolved = candidate.resolve()
            return resolved, resolved, resolved

    raise GitHistoryError(f"Not a Git repository: {path}")


def resolve_head(repository: Union[str, Path]) -> str:
    result = run_git(repository, ["rev-parse", "--verify", "--quiet", "HEAD"])
    if result.returncode != 0:
        return ""
    return _decode(result.stdout).strip()


def _strip_ancestry(revision: str) -> str:
    for separator in ("~", "^"):
        if separator in revision:
            return revision.split(separator, 1)[0]
    return revision


def _shallow_fallback(revision: Any) -> Any:
    args = _revision_args(revision)
    fallback = []
    for item in args:
        if ".." in item:
            left, right = item.split("..", 1)
            if left:
                left = _strip_ancestry(left)
                right = _strip_ancestry(right)
                fallback.append(right if left == right else left + ".." + right)
            else:
                fallback.append(".." + _strip_ancestry(right))
        elif item.startswith("-"):
            fallback.append(item)
        else:
            fallback.append(_strip_ancestry(item))
    return fallback


def _resolve_revision_token(repository: Union[str, Path], token: str) -> str:
    if not token or token.startswith("-"):
        return token
    result = run_git(repository, ["rev-parse", "--verify", "--quiet", token])
    if result.returncode == 0:
        return _decode(result.stdout).strip()
    return token


def freeze_revision(repository: Union[str, Path], revision: Any) -> List[str]:
    """Resolve refs to object IDs so a moving HEAD cannot alter the range."""
    frozen = []
    for token in _revision_args(revision):
        if token.startswith("-") or token == "--all":
            frozen.append(token)
        elif ".." in token:
            left, right = token.split("..", 1)
            left = _resolve_revision_token(repository, left) if left else left
            right = _resolve_revision_token(repository, right) if right else right
            frozen.append(f"{left}..{right}")
        else:
            frozen.append(_resolve_revision_token(repository, token))
    return frozen


def resolve_commits(
    repository: Union[str, Path],
    revision: Any,
    head: str = "",
    depth: Optional[int] = None,
) -> List[str]:
    """Resolve a revision specification into a frozen, ordered commit list."""
    args = ["rev-list"]
    if depth is not None:
        args.extend(["--max-count", str(max(1, int(depth)))])
    frozen_revision = freeze_revision(repository, revision)
    if head and frozen_revision == ["HEAD"]:
        frozen_revision = [head]
    args.extend(frozen_revision)

    result = run_git(repository, args)
    if result.returncode == 0:
        return [_decode(line).strip() for line in (result.stdout or b"").splitlines() if _decode(line).strip()]

    message = _command_error(result)
    if not head:
        return []

    shallow = run_git(repository, ["rev-parse", "--is-shallow-repository"])
    if shallow.returncode == 0 and _decode(shallow.stdout).strip().lower() == "true":
        fallback_args = ["rev-list"]
        if depth is not None:
            fallback_args.extend(["--max-count", str(max(1, int(depth)))])
        fallback_args.extend(_revision_args(_shallow_fallback(revision)))
        fallback = run_git(repository, fallback_args)
        if fallback.returncode == 0:
            logging.debug(f"Git shallow history fallback for '{revision}'")
            return [
                _decode(line).strip()
                for line in (fallback.stdout or b"").splitlines()
                if _decode(line).strip()
            ]

    logging.debug(f"Unable to resolve Git revision '{revision}': {message}")
    return []


def compute_generation(
    git_dir: Union[str, Path],
    head: str,
    revision: Any,
    commits: Sequence[str],
    depth: Optional[int] = None,
    paths: Optional[Iterable[str]] = None,
) -> str:
    payload = json.dumps(
        {
            "head": head,
            "revision": _revision_value(revision),
            "commits": list(commits),
            "depth": depth,
            "paths": list(paths or []),
        },
        sort_keys=True,
        ensure_ascii=True,
    )
    return "git-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def default_state_path(git_dir: Union[str, Path]) -> Path:
    return Path(git_dir).joinpath(STATE_SUFFIX)


def load_state(path: Union[str, Path, None]) -> Optional[HistoryState]:
    if not path:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if isinstance(data, list):
        # Legacy checkpoints only stored the already parsed blob IDs.
        return HistoryState(
            repository="",
            git_dir="",
            worktree="",
            head="",
            revision="HEAD",
            generation="",
            scanned=[str(item) for item in data if isinstance(item, str)],
        )
    if not isinstance(data, dict):
        return None
    try:
        return HistoryState.from_dict(data)
    except (TypeError, ValueError):
        return None


def save_state(path: Union[str, Path, None], state: HistoryState) -> None:
    if not path:
        return
    target = Path(path)
    state.updated_at = _utcnow()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=target.name + ".",
            suffix=".tmp",
            delete=False,
        )
        try:
            with handle:
                json.dump(state.to_dict(), handle, ensure_ascii=False, sort_keys=True, indent=2)
                handle.write("\n")
            os.replace(handle.name, target)
        finally:
            try:
                if os.path.exists(handle.name):
                    os.unlink(handle.name)
            except OSError:
                pass
    except OSError as error:  # pragma: no cover - read-only repositories
        logging.warning(f"Unable to persist Git history state: {error}")


def _same_repository(state: HistoryState, git_dir: Path) -> bool:
    if not state.git_dir:
        return True
    try:
        return Path(state.git_dir).resolve() == git_dir.resolve()
    except OSError:
        return state.git_dir == str(git_dir)


def _same_revision(state: HistoryState, revision: Any) -> bool:
    return _revision_key(state.revision) == _revision_key(revision)


def _same_scope(state: HistoryState, paths: Sequence[str], depth: Optional[int]) -> bool:
    state_paths = [Path(item).as_posix().lstrip("./") for item in state.paths]
    current_paths = [Path(item).as_posix().lstrip("./") for item in paths]
    if state_paths != current_paths:
        return False
    if state.depth != depth:
        return False
    return True


def _in_scope(path: str, config: AppConfig) -> bool:
    from fnmatch import fnmatch
    from pathlib import PurePosixPath

    include = getattr(getattr(config, "include", None), "files", None) or ["**/*"]
    matched = False
    for pattern in include:
        pattern = str(pattern).replace("\\", "/")
        name = PurePosixPath(path).name
        if pattern in ("**/*", "**", "*"):
            matched = True
        elif pattern.startswith("**/"):
            tail = pattern[3:]
            matched = (
                fnmatch(path, pattern)
                or fnmatch(path, tail)
                or fnmatch(name, tail)
                or fnmatch(name, pattern)
            )
        elif "/" not in pattern:
            matched = fnmatch(name, pattern)
        else:
            matched = fnmatch(path, pattern) or fnmatch(path, pattern.lstrip("./"))
        if matched:
            break

    if not matched:
        return False

    exclude = getattr(getattr(config, "exclude", None), "files", None)
    if exclude:
        if exclude.match(path) or exclude.match(f"./{path}"):
            return False
    return True


def is_history_requested(args: Namespace, config: Any = None) -> bool:
    """Whether a namespace asks for a Git history scan."""
    flags = (
        "git",
        "git_history",
        "history",
        "git_scan",
        "history_scan",
        "scan_history",
        "track_history",
    )
    if any(bool(getattr(args, flag, False)) for flag in flags):
        return True

    for flag in (
        "git_range",
        "git_rev",
        "git_ref",
        "rev_range",
        "history_range",
        "history_revision",
        "revision",
    ):
        if getattr(args, flag, None):
            return True

    if (
        getattr(args, "git_repo", None)
        or getattr(args, "repo", None)
        or getattr(args, "repository", None)
    ):
        return True

    for flag in ("git_state", "git_resume", "git_reset", "git_depth"):
        if getattr(args, flag, None) not in (None, False, ""):
            return True

    for flag in ("git_history", "history", "scan_history"):
        if bool(getattr(config, flag, False)):
            return True

    source = getattr(args, "src", None)
    if source:
        path = Path(source)
        if path.name == ".git" and (path.is_dir() or path.is_file()):
            return True
        if path.is_dir() and _looks_like_bare_repository(path):
            return True
    return False


class GitHistoryScanner:
    """Freeze, persist, resume and scan a Git history snapshot."""

    is_history = True

    def __new__(cls, repository=None, *args, **kwargs):
        if cls is GitHistoryScanner:
            try:
                candidate = repository
                if isinstance(candidate, Namespace):
                    candidate = getattr(candidate, "src", None)
                if candidate is None:
                    namespace = kwargs.get("args")
                    if isinstance(namespace, Namespace):
                        candidate = getattr(namespace, "src", None)
                if candidate is None:
                    candidate = (
                        kwargs.get("repo")
                        or kwargs.get("git_repo")
                        or kwargs.get("repo_path")
                        or kwargs.get("repository_path")
                    )
                path = Path(candidate) if candidate is not None else None
                if path is not None and path.is_file():
                    from whispers.plugins.git import GitLogScope, looks_like_git_log

                    if looks_like_git_log(path):
                        config = kwargs.get("config")
                        if config is None and len(args) >= 3:
                            config = args[2]
                        return GitLogScope(path, config)
            except (OSError, TypeError, ValueError):
                pass
        return super().__new__(cls)

    def __init__(
        self,
        repository: Union[str, Path, Namespace, None] = None,
        revision: Any = None,
        state_path: Union[str, Path, None] = None,
        config: Any = None,
        resume: Optional[bool] = None,
        reset: bool = False,
        depth: Optional[int] = None,
        paths: Optional[Iterable[str]] = None,
        args: Optional[Namespace] = None,
        **aliases,
    ) -> None:
        repository = (
            repository
            or aliases.get("repo")
            or aliases.get("git_repo")
            or aliases.get("repo_path")
            or aliases.get("repository_path")
        )
        revision = (
            revision
            or aliases.get("ref")
            or aliases.get("rev")
            or aliases.get("range")
            or aliases.get("git_range")
            or aliases.get("rev_range")
        )
        state_path = (
            state_path
            or aliases.get("state")
            or aliases.get("checkpoint")
            or aliases.get("state_file")
            or aliases.get("history_state")
        )
        depth = depth if depth is not None else aliases.get("max_commits", aliases.get("limit"))
        if paths is None:
            paths = aliases.get("path_filter", aliases.get("source_paths"))

        if isinstance(repository, Namespace):
            args = repository
            repository = None

        if args is not None:
            repository = (
                getattr(args, "git_repo", None)
                or getattr(args, "repo", None)
                or getattr(args, "repository", None)
                or getattr(args, "src", None)
            )
            revision = revision or _first_value(
                args,
                (
                    "git_range",
                    "history_range",
                    "rev_range",
                    "git_rev",
                    "git_ref",
                    "history_revision",
                    "revision",
                ),
                "HEAD",
            )
            state_path = state_path or _first_value(
                args,
                (
                    "git_state",
                    "history_state",
                    "history_state_path",
                    "git_state_path",
                    "state_file",
                    "state",
                ),
                None,
            )
            if resume is None:
                resume = bool(getattr(args, "git_resume", False) or getattr(args, "resume", False))
            reset = bool(reset or getattr(args, "git_reset", False) or getattr(args, "reset", False))
            if depth is None:
                depth = (
                    getattr(args, "git_depth", None)
                    or getattr(args, "history_depth", None)
                    or getattr(args, "max_commits", None)
                )
            if paths is None:
                paths = getattr(args, "git_paths", None) or getattr(args, "history_paths", None)

        if repository is None:
            raise GitHistoryError("A Git repository is required")

        self.args = args
        self.source = Path(repository).expanduser()
        self.revision = _revision_value(revision)
        self.resume = resume
        self.reset = reset
        self.depth = int(depth) if depth is not None else None
        self.path_filters = _normalise_paths(paths)
        self.config = _normalise_config(config)
        self.rules = aliases.get("rules")
        self._git_cwd: Optional[Path] = None
        self._worktree: Optional[Path] = None
        self._git_dir: Optional[Path] = None
        self._entries_by_commit: Dict[str, List[HistoryEntry]] = {}
        self._tempdir: Optional[tempfile.TemporaryDirectory] = None
        self._closed = False
        self._freeze(state_path=state_path)

    @classmethod
    def from_args(cls, args: Namespace, config: Any = None) -> "GitHistoryScanner":
        return cls(args=args, config=config)

    from_namespace = from_args

    def _freeze(self, state_path: Union[str, Path, None] = None) -> None:
        self._git_cwd, self._worktree, self._git_dir = resolve_repository(self.source)
        self._apply_source_filter()
        head = resolve_head(self._git_cwd)
        commits = resolve_commits(self._git_cwd, self.revision, head=head, depth=self.depth)
        generation = compute_generation(
            self._git_dir,
            head,
            self.revision,
            commits,
            depth=self.depth,
            paths=self.path_filters,
        )

        if state_path is None and self.args is not None:
            state_path = _first_value(
                self.args,
                (
                    "git_state",
                    "history_state",
                    "history_state_path",
                    "git_state_path",
                    "state_file",
                    "state",
                ),
                None,
            )
        if state_path in ("", "-"):
            state_path = None
        if state_path is None:
            state_path = default_state_path(self._git_dir)
        self.state_path = Path(state_path) if state_path else None

        existing = load_state(self.state_path)
        use_existing = False
        if existing is not None and not self.reset:
            if not existing.git_dir and _same_revision(existing, self.revision):
                # Legacy checkpoints without repository metadata remain readable.
                use_existing = True
            elif self.resume is True:
                use_existing = True
            elif self.resume is False:
                use_existing = False
            elif (
                existing.status != "complete"
                and _same_revision(existing, self.revision)
                and _same_scope(existing, self.path_filters, self.depth)
            ):
                # Interrupted scans keep their frozen range even if HEAD moved.
                use_existing = _same_repository(existing, self._git_dir)
            elif (
                existing.generation == generation
                and _same_revision(existing, self.revision)
                and _same_scope(existing, self.path_filters, self.depth)
            ):
                # Re-running the same accepted generation reuses parsed blobs.
                use_existing = _same_repository(existing, self._git_dir)

        if use_existing:
            self.state = existing
            if not existing.git_dir:
                existing.repository = str(self._git_cwd)
                existing.git_dir = str(self._git_dir)
                existing.worktree = str(self._worktree)
                existing.head = head
                existing.revision = self.revision
                existing.generation = generation
                existing.commits = list(commits)
                existing.depth = self.depth
            self.state.repository = str(self._git_cwd)
            self.state.worktree = str(self._worktree)
            self.state.git_dir = str(self._git_dir)
            if not self.state.commits and commits:
                self.state.commits = list(commits)
            if not self.state.paths and self.path_filters:
                self.state.paths = list(self.path_filters)
        else:
            self.state = HistoryState(
                repository=str(self._git_cwd),
                git_dir=str(self._git_dir),
                worktree=str(self._worktree),
                head=head,
                revision=self.revision,
                generation=generation,
                commits=list(commits),
                generation_id=(existing.generation_id + 1) if existing is not None else 1,
                depth=self.depth,
                paths=list(self.path_filters),
            )

        # Commit the accepted identity before reading any blob content.
        save_state(self.state_path, self.state)

    def _apply_source_filter(self) -> None:
        if self.path_filters or self._worktree is None:
            return
        try:
            source = self.source.resolve()
            worktree = self._worktree.resolve()
            if source == worktree:
                return
            relative = source.relative_to(worktree)
            if self.source.name == ".git":
                return
            self.path_filters = [relative.as_posix().lstrip("./")]
        except (OSError, ValueError):
            return

    @property
    def repository(self) -> str:
        return self.state.repository

    @property
    def repo(self) -> str:
        return self.state.repository

    @property
    def git_dir(self) -> str:
        return self.state.git_dir

    @property
    def worktree(self) -> str:
        return self.state.worktree

    @property
    def head(self) -> str:
        return self.state.head

    @property
    def head_sha(self) -> str:
        return self.state.head

    @property
    def generation(self) -> str:
        return self.state.generation

    @property
    def generation_id(self) -> int:
        return self.state.generation_id

    @property
    def generation_number(self) -> int:
        return self.state.generation_id

    @property
    def range(self) -> Any:
        return self.state.revision

    @property
    def commits(self) -> CommitRange:
        return self.state.commit_range

    @property
    def commit_range(self) -> CommitRange:
        return self.state.commit_range

    @property
    def commit_ids(self) -> CommitRange:
        return self.commit_range

    @property
    def commits_asc(self) -> CommitRange:
        return self.commit_range

    @property
    def commits_desc(self) -> CommitRange:
        return CommitRange(reversed(self.commit_range), spec=self.revision)

    @property
    def scanned_blobs(self) -> set:
        return self.state.scanned_blobs

    @property
    def scanned_blob_ids(self) -> List[str]:
        return self.state.scanned_blob_ids

    @property
    def status(self) -> str:
        return self.state.status

    @property
    def snapshot(self) -> HistorySnapshot:
        return HistorySnapshot(
            repository=self.repository,
            git_dir=self.git_dir,
            worktree=self.worktree,
            head=self.head,
            revision=self.state.revision,
            generation=self.generation,
            commits=self.commit_range,
            scanned_blobs=frozenset(self.scanned_blobs),
            generation_id=self.generation_id,
            status=self.status,
        )

    def freeze(self) -> HistorySnapshot:
        """Return the frozen identity accepted for this scan."""
        save_state(self.state_path, self.state)
        return self.snapshot

    def save(self) -> None:
        save_state(self.state_path, self.state)

    def mark_blob(self, oid: str) -> None:
        """Persist a blob as already parsed for this generation."""
        self.state.mark_blob(oid)
        save_state(self.state_path, self.state)

    def already_scanned(self, oid: str) -> bool:
        return oid in self.state.scanned_blobs

    def report(self) -> dict:
        report = self.snapshot.report()
        report["files"] = [entry.file for entry in self.iter_entries()]
        report["paths"] = [entry.path for entry in self.iter_entries()]
        report["state_path"] = self.state_path.as_posix() if self.state_path else None
        report["repository"] = self.repository
        return report

    def to_report(self) -> dict:
        return self.report()

    def to_json(self) -> str:
        return json.dumps(self.report(), ensure_ascii=False, sort_keys=True)

    @property
    def files(self) -> List[Path]:
        return [Path(entry.file) for entry in self.iter_entries()]

    @property
    def paths(self) -> List[str]:
        return [entry.path for entry in self.iter_entries()]

    @property
    def entries(self) -> List[HistoryEntry]:
        return list(self.iter_entries())

    @property
    def blob_ids(self) -> List[str]:
        seen = []
        for entry in self.iter_entries():
            if entry.blob not in seen:
                seen.append(entry.blob)
        return seen

    @property
    def blobs(self) -> Dict[str, List[dict]]:
        return self.state.blobs

    def _ensure_tempdir(self) -> Path:
        if self._tempdir is None:
            self._tempdir = tempfile.TemporaryDirectory(prefix="whispers-git-history-")
        return Path(self._tempdir.name)

    def _path_allowed(self, path: str) -> bool:
        filters = self.state.paths or self.path_filters
        if filters:
            allowed = False
            for prefix in filters:
                if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
                    allowed = True
                    break
            if not allowed:
                return False
        return _in_scope(path, self.config)

    def _commit_entries(self, commit: str) -> List[HistoryEntry]:
        if commit in self._entries_by_commit:
            return self._entries_by_commit[commit]

        result = run_git(self._git_cwd, ["ls-tree", "-r", "-z", "--full-tree", commit])
        if result.returncode != 0:
            logging.debug(f"Unable to list tree for {commit}: {_command_error(result)}")
            self._entries_by_commit[commit] = []
            return []

        entries = []
        for record in (result.stdout or b"").split(b"\0"):
            if not record:
                continue
            metadata, _, raw_path = record.partition(b"\t")
            fields = metadata.split()
            if len(fields) < 3:
                continue
            mode, object_type, oid = (_decode(fields[0]), _decode(fields[1]), _decode(fields[2]))
            path = _decode(raw_path)
            if object_type != "blob" or mode == "120000":
                continue
            if not self._path_allowed(path):
                continue
            entries.append(
                HistoryEntry(
                    commit=commit,
                    blob=oid,
                    path=path,
                    mode=mode,
                    generation=self.generation,
                    repository=self.repository,
                    worktree=self.worktree,
                )
            )

        self._entries_by_commit[commit] = entries
        return entries

    def iter_entries(self) -> Iterator[HistoryEntry]:
        for commit in self.state.commits:
            yield from self._commit_entries(commit)

    def __iter__(self) -> Iterator[HistoryEntry]:
        return self.iter_entries()

    def __len__(self) -> int:
        return sum(1 for _ in self.iter_entries())

    def _materialize_blob(self, entry: HistoryEntry, data: bytes) -> Path:
        root = self._ensure_tempdir()
        relative = Path(*[part for part in Path(entry.path).parts if part not in ("", ".", "..")])
        target = root.joinpath(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    @staticmethod
    def _serialize_pair(
        pair: KeyValuePair,
        temp_file: str = "",
        entry: Optional[HistoryEntry] = None,
    ) -> dict:
        def stable(value: Any) -> Any:
            value = _json_safe(value)
            if temp_file and isinstance(value, str):
                return value.replace(temp_file, "{path}")
            return value

        result = {
            "key": stable(pair.key),
            "value": stable(pair.value),
            "keypath": [stable(item) for item in pair.keypath],
            "line": int(pair.line or 0),
        }
        if entry is not None:
            result.update(
                {
                    "commit": entry.commit,
                    "blob": entry.blob,
                    "path": entry.path,
                    "stage": "history",
                }
            )
        return result

    def _restore_pair(self, data: dict, entry: HistoryEntry, display_file: str) -> KeyValuePair:
        temp_file = ""
        if self._tempdir is not None:
            temp_file = Path(self._tempdir.name, entry.path).as_posix()

        def restore(value: Any) -> Any:
            if isinstance(value, str) and "{path}" in value:
                return value.replace("{path}", display_file)
            if temp_file and isinstance(value, str) and temp_file in value:
                return value.replace(temp_file, display_file)
            return value

        pair = KeyValuePair(
            key=str(data.get("key", "")),
            value=str(restore(data.get("value", ""))),
            keypath=[restore(item) for item in data.get("keypath", [])],
            file=display_file,
            line=int(data.get("line", 0) or 0),
        )
        _attach_history(pair, entry, display_file)
        pair.generation_id = self.state.generation_id
        return pair

    def _parse_blob(self, entry: HistoryEntry) -> List[dict]:
        cached = self.state.blobs.get(entry.blob)
        if cached is not None:
            if entry.blob not in self.state.scanned_blobs:
                self.state.mark_blob(entry.blob)
                save_state(self.state_path, self.state)
            return cached

        result = run_git(self._git_cwd, ["cat-file", "blob", entry.blob])
        if result.returncode != 0:
            logging.debug(f"Unable to read blob {entry.blob}: {_command_error(result)}")
            return []

        from whispers.core.pairs import make_pairs

        target = self._materialize_blob(entry, result.stdout or b"")
        parsed = []
        temp_file = target.as_posix()
        for pair in make_pairs(self.config, target) or []:
            # cache line numbers while the historical blob still exists on disk
            pair.line = find_line_number(pair) or pair.line
            parsed.append(self._serialize_pair(pair, temp_file=temp_file, entry=entry))
        self.state.blobs[entry.blob] = parsed
        self.state.mark_blob(entry.blob)
        save_state(self.state_path, self.state)
        return parsed

    def pairs(self) -> Iterator[KeyValuePair]:
        """Yield raw pairs from the frozen history, one blob at a time."""
        for commit in self.state.commits:
            for entry in self._commit_entries(commit):
                cached = self._parse_blob(entry)
                display_file = Path(entry.worktree or entry.repository, entry.path).as_posix()
                for raw in cached:
                    yield self._restore_pair(raw, entry, display_file)

    def iter_pairs(self) -> Iterator[KeyValuePair]:
        return self.pairs()

    def scan(self, rules: Any = None) -> Iterator[KeyValuePair]:
        if rules is None:
            return self.pairs()
        return self.findings(rules)

    def findings(self, rules: Any = None) -> Iterator[KeyValuePair]:
        rules = self.rules if rules is None else rules
        if rules is None:
            return self.pairs()
        return self._findings(rules)

    def _findings(self, rules: Any) -> Iterator[KeyValuePair]:
        from whispers.core.secrets import detect_secrets

        completed = False
        try:
            for finding in detect_secrets(rules, self.pairs()):
                yield finding
            completed = True
        finally:
            if completed:
                self.state.status = "complete"
                save_state(self.state_path, self.state)

    detect = findings

    def reset(self) -> None:
        """Forget the persisted generation and start a fresh snapshot."""
        if self.state_path:
            try:
                self.state_path.unlink()
            except OSError:
                pass
        self.reset = True
        self._entries_by_commit.clear()
        self._freeze()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._tempdir is not None:
            self._tempdir.cleanup()
            self._tempdir = None

    def __enter__(self) -> "GitHistoryScanner":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


def _first_value(source: Namespace, names: Sequence[str], default: Any) -> Any:
    for name in names:
        value = getattr(source, name, None)
        if value not in (None, "", False):
            return value
    return default


def _normalise_config(config: Any) -> AppConfig:
    if config is None:
        return AppConfig()
    if isinstance(config, AppConfig):
        return config
    if isinstance(config, dict):
        return AppConfig(config)
    return config


def _normalise_paths(paths: Any) -> List[str]:
    if not paths:
        return []
    if isinstance(paths, (str, Path)):
        paths = [paths]
    return [Path(item).as_posix().lstrip("./") for item in paths if str(item)]


def _attach_history(pair: KeyValuePair, entry: HistoryEntry, display_file: str) -> KeyValuePair:
    pair.commit = entry.commit
    pair.commit_sha = entry.commit
    pair.blob = entry.blob
    pair.blob_sha = entry.blob
    pair.object_id = entry.blob
    pair.path = entry.path
    pair.repo = entry.repository
    pair.repository = entry.repository
    pair.worktree = entry.worktree
    pair.generation = entry.generation
    pair.scan_generation = entry.generation
    pair.stage = "history"
    pair.detection_stage = "history"
    pair.phase = "history"
    pair.history = {
        "commit": entry.commit,
        "blob": entry.blob,
        "path": entry.path,
        "generation": entry.generation,
        "stage": "history",
    }
    pair.file = display_file
    pair.finding_id = _finding_identity(pair)
    pair.id = pair.finding_id
    return pair


def _finding_identity(pair: KeyValuePair) -> str:
    payload = "|".join(
        [
            str(getattr(pair, "commit", "")),
            str(getattr(pair, "blob", "")),
            str(getattr(pair, "path", "")),
            str(pair.key),
            str(pair.value),
            str(pair.line),
        ]
    )
    return "whs-" + hashlib.sha256(payload.encode("utf-8", "surrogateescape")).hexdigest()[:16]


def scan_git_history(
    repository: Union[str, Path, Namespace],
    revision: Any = None,
    rules: Any = None,
    config: Any = None,
    state_path: Union[str, Path, None] = None,
    **kwargs,
) -> Iterator[KeyValuePair]:
    """Convenience entry point for a resumable Git history scan."""
    if isinstance(repository, Namespace):
        scanner = GitHistoryScanner(args=repository, config=config)
    else:
        try:
            path = Path(repository)
            if path.is_file():
                from whispers.plugins.git import GitLogScope, looks_like_git_log

                if looks_like_git_log(path):
                    log_scope = GitLogScope(path, config)
                    return log_scope.pairs() if rules is None else log_scope.findings(rules)
        except (OSError, TypeError):
            pass
        scanner = GitHistoryScanner(
            repository,
            revision=revision,
            state_path=state_path,
            config=config,
            **kwargs,
        )
    if rules is None:
        return scanner.pairs()
    return scanner.findings(rules)


def iter_git_history(*args, **kwargs) -> Iterator[KeyValuePair]:
    return scan_git_history(*args, **kwargs)


def load_git_history(*args, **kwargs) -> Iterator[KeyValuePair]:
    return scan_git_history(*args, **kwargs)


def git_history(*args, **kwargs) -> Iterator[KeyValuePair]:
    return scan_git_history(*args, **kwargs)


def freeze_git_history(repository: Union[str, Path], revision: Any = "HEAD", **kwargs) -> HistorySnapshot:
    return GitHistoryScanner(repository, revision=revision, **kwargs).freeze()


def scan_history(*args, **kwargs) -> Iterator[KeyValuePair]:
    return scan_git_history(*args, **kwargs)


def resume_history(*args, **kwargs) -> Iterator[KeyValuePair]:
    kwargs.setdefault("resume", True)
    return scan_git_history(*args, **kwargs)


iter_history = scan_git_history
load_history = scan_git_history


def freeze_history(repository: Union[str, Path], revision: Any = "HEAD", **kwargs) -> HistorySnapshot:
    return freeze_git_history(repository, revision=revision, **kwargs)


def history_state(repository: Union[str, Path], **kwargs) -> HistoryState:
    return GitHistoryScanner(repository, **kwargs).state


def load_history_scope(source: Any, config: Any = None, **kwargs) -> GitHistoryScanner:
    if isinstance(source, Namespace):
        return GitHistoryScanner(args=source, config=config)
    try:
        path = Path(source)
        if path.is_file():
            from whispers.plugins.git import GitLogScope, looks_like_git_log

            if looks_like_git_log(path):
                return GitLogScope(path, config)
    except (OSError, TypeError):
        pass
    return GitHistoryScanner(source, config=config, **kwargs)


load_git_scope = load_history_scope
load_repository_scope = load_history_scope
git_scope = load_history_scope
open_history = load_history_scope


# Descriptive aliases used by integrations.
HistoryScanner = GitHistoryScanner
GitScanner = GitHistoryScanner
HistoryScope = GitHistoryScanner
GitHistoryScope = GitHistoryScanner
GitHistory = GitHistoryScanner
HistoryScan = GitHistoryScanner
GitHistoryState = HistoryState
HistorySnapshotState = HistorySnapshot
ScanState = HistoryState
ScanSnapshot = HistorySnapshot
GitCommitRange = CommitRange
GitHistorySnapshot = HistorySnapshot
HistoryStateSnapshot = HistorySnapshot
GitHistoryResume = GitHistoryScanner
HistoryResume = GitHistoryScanner
GitError = GitHistoryError
HistoryError = GitHistoryError
