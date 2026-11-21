import logging
from argparse import Namespace
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, List, Optional, Pattern, Tuple

from whispers.models.appconfig import config_digest, config_version


@dataclass(frozen=True)
class ScopeSnapshot:
    """Immutable scope and plugin configuration bound to one scan"""

    version: str
    include_files: Tuple[str, ...]
    exclude_files: Optional[Pattern]
    ast: bool
    source: Optional[str] = None
    config: Any = field(default=None, repr=False, compare=False)

    @property
    def config_version(self) -> str:
        """Alias used by reports"""
        return self.version

    @property
    def plugin_config(self) -> dict:
        """Plugin selection settings fixed for this scan"""
        return {"ast": self.ast}

    def report(self) -> dict:
        """Describe the version and effective scope of this scan"""
        return {
            "version": self.version,
            "config_version": self.version,
            "source": self.source,
            "include_files": list(self.include_files),
            "exclude_files": self.exclude_files.pattern if self.exclude_files else None,
            "ast": self.ast,
        }


# Descriptive aliases for callers which refer to a frozen scan config.
ScanConfig = ScopeSnapshot
ConfigSnapshot = ScopeSnapshot
ScopeConfig = ScopeSnapshot
ScanSnapshot = ScopeSnapshot


class Scope:
    """A stable iterable of files plus the config version used to select them"""

    def __init__(self, args: Namespace, snapshot: ScopeSnapshot) -> None:
        self.args = args
        self.src = Path(args.src)
        self.snapshot = snapshot
        self._files: Optional[List[Path]] = None
        self._position = 0

    def _materialise(self) -> List[Path]:
        if self._files is None:
            self._files = list(_iter_scope(self.src, self.snapshot))

        return self._files

    @property
    def files(self) -> List[Path]:
        """Files selected by this scope"""
        return list(self._materialise())

    @property
    def paths(self) -> List[Path]:
        """Alias for files"""
        return self.files

    @property
    def config(self) -> Any:
        """Frozen config snapshot used for plugin selection and filtering"""
        return self.snapshot.config

    @property
    def scan_config(self) -> ScopeSnapshot:
        """Alias for the frozen scan config"""
        return self.snapshot

    @property
    def config_version(self) -> str:
        """Version of the config used to build this scope"""
        return self.snapshot.version

    @property
    def version(self) -> str:
        """Alias for config_version"""
        return self.config_version

    @property
    def ast(self) -> bool:
        """AST plugin setting fixed for this scan"""
        return self.snapshot.ast

    @property
    def include_files(self) -> Tuple[str, ...]:
        """Include globs fixed for this scan"""
        return self.snapshot.include_files

    @property
    def exclude_files(self) -> Optional[Pattern]:
        """Exclude regex fixed for this scan"""
        return self.snapshot.exclude_files

    @property
    def plugin_config(self) -> dict:
        """Plugin settings fixed for this scan"""
        return self.snapshot.plugin_config

    def report(self) -> dict:
        """Report which config version and scope were used"""
        return {**self.snapshot.report(), "files": [path.as_posix() for path in self.files]}

    def to_report(self) -> dict:
        """Alias for report"""
        return self.report()

    def close(self) -> None:
        """Generator-compatible no-op; the scope holds no open resources"""

    def __iter__(self) -> Iterator[Path]:
        return iter(self._materialise())

    def __next__(self) -> Path:
        files = self._materialise()
        try:
            path = files[self._position]
        except IndexError:
            raise StopIteration

        self._position += 1
        return path

    def __len__(self) -> int:
        return len(self._materialise())

    def __getitem__(self, index):
        return self._materialise()[index]

    def __contains__(self, item) -> bool:
        return item in self._materialise()

    def __bool__(self) -> bool:
        return bool(self._materialise())

    def __eq__(self, other) -> bool:
        if isinstance(other, Scope):
            return self.files == other.files and self.config_version == other.config_version

        if isinstance(other, (list, tuple)):
            return self.files == list(other)

        return NotImplemented

    def __repr__(self) -> str:
        return f"Scope(config_version={self.config_version!r}, files={len(self)})"


def snapshot_config(config: Any) -> ScopeSnapshot:
    """Freeze all config values needed by a scan into a single snapshot"""
    if isinstance(config, ScopeSnapshot):
        return config

    if hasattr(config, "snapshot") and callable(config.snapshot):
        frozen = config.snapshot()

    else:
        frozen = deepcopy(config)

    version = config_version(frozen)

    try:
        frozen.version = version  # type: ignore[attr-defined]
        frozen.config_digest = config_digest(frozen)  # type: ignore[attr-defined]

    except Exception:
        pass

    include = getattr(frozen, "include", None)
    exclude = getattr(frozen, "exclude", None)
    include_files = tuple(getattr(include, "files", None) or [])
    exclude_files = getattr(exclude, "files", None)
    ast = bool(getattr(frozen, "ast", False))
    source = getattr(frozen, "source", None)

    return ScopeSnapshot(
        version=version,
        include_files=include_files,
        exclude_files=exclude_files,
        ast=ast,
        source=source,
        config=frozen,
    )


freeze_config = snapshot_config


def _iter_scope(src: Path, snapshot: ScopeSnapshot) -> Iterator[Path]:
    """Yield paths using only the frozen scope and exclude configuration"""
    if src.is_file():
        yield src
        return

    for include in snapshot.include_files:
        try:
            matches = src.rglob(str(include))

        except (OSError, ValueError):
            logging.warning(f"load_scope invalid include glob '{include}'")
            continue

        for filepath in matches:
            if snapshot.exclude_files and snapshot.exclude_files.match(filepath.as_posix()):
                continue

            yield filepath


def iter_scope(args: Namespace, config: Any) -> Iterator[Path]:
    """Iterate over files using one frozen config snapshot"""
    snapshot = config if isinstance(config, ScopeSnapshot) else snapshot_config(config)
    yield from _iter_scope(Path(args.src), snapshot)


def load_scope(args: Namespace, config: dict, snapshot: Any = None) -> Iterable[Path]:
    """
    Load a list of files in scope based on args and config.

    Include globs, the exclude regex and plugin settings are captured when
    this function is called. Later config reloads or mutations cannot change
    the scope or the plugin selection of this scan.
    """
    if snapshot is not None and not isinstance(snapshot, ScopeSnapshot):
        snapshot = snapshot_config(snapshot)

    if snapshot is None:
        snapshot = snapshot_config(config)

    logging.debug(f"load_scope config_version '{snapshot.version}'")
    return Scope(args, snapshot)
