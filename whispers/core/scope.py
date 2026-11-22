from argparse import Namespace
from pathlib import Path
from typing import Iterable, Iterator


def load_scope(args: Namespace, config: dict) -> Iterable[Path]:
    """Load a list of files in scope based on args and config"""
    from whispers.core.history import GitHistoryScanner, is_history_requested

    if is_history_requested(args, config):
        source_value = getattr(args, "git_repo", None) or getattr(args, "src", None)
        if source_value:
            source = Path(source_value)
            if source.is_file():
                from whispers.plugins.git import GitLogScope, looks_like_git_log

                if looks_like_git_log(source):
                    return GitLogScope(source, config)
        return GitHistoryScanner.from_args(args, config)

    return _load_file_scope(args, config)


def _load_file_scope(args: Namespace, config: dict) -> Iterator[Path]:
    """Load a working-tree file scope"""
    src = Path(args.src)

    if src.is_file():
        yield src

    else:
        for include in config.include.files:
            for filepath in src.rglob(include):
                if config.exclude.files and config.exclude.files.match(filepath.as_posix()):
                    continue

                yield filepath


# Descriptive aliases for callers that refer to a history-aware scope.
from whispers.core.history import (  # noqa: E402  (kept for import compatibility)
    CommitRange,
    GitHistory,
    GitHistoryScope,
    GitHistoryScanner,
    HistoryScope,
)

def load_history_scope(source, config: dict = None, **kwargs):
    """Load a frozen history scope even when no CLI flag is present."""
    if isinstance(source, Namespace):
        return GitHistoryScanner.from_args(source, config)
    path = Path(source)
    if path.is_file():
        from whispers.plugins.git import GitLogScope, looks_like_git_log

        if looks_like_git_log(path):
            return GitLogScope(path, config)
    return GitHistoryScanner(source, config=config, **kwargs)


load_git_scope = load_history_scope
load_repository_scope = load_history_scope
history_scope = load_history_scope
git_scope = load_history_scope
git_history_scope = load_history_scope
