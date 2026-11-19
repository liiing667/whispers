import logging
import os
from argparse import Namespace
from pathlib import Path
from typing import Iterable, Set


def load_scope(args: Namespace, config: dict) -> Iterable[Path]:
    """Load a list of files in scope based on args and config

    Scope conclusions are bound to the resolved, real filesystem targets and
    the resolved configuration root. Symlinks pointing outside of the root,
    symlink loops and entries that cannot be resolved never produce pairs.
    """
    src = Path(args.src)

    try:
        root = src.resolve(strict=True)

    except OSError:
        logging.warning(f"load_scope cannot resolve '{src}'")
        return

    if root.is_file():
        # Explicit single file scan: trust the caller-provided target,
        # including symlinks, while still failing closed on resolution errors.
        if not src.is_symlink() or _resolves_to_file(src):
            yield src
        return

    if not root.is_dir():
        return

    yield from _walk_scope(src, root, config)


def _walk_scope(src: Path, root: Path, config: dict) -> Iterable[Path]:
    """Walk a real directory without following symlinks

    `src` keeps the caller-provided path form used in yielded paths and
    include/exclude matching, while `root` is its resolved real target used
    to bind every scope conclusion to the configuration root.
    """
    allowed = _real_files(root)
    seen: Set[Path] = set()

    for include in config.include.files:
        try:
            candidates = src.glob(include)

        except Exception:
            logging.warning(f"load_scope invalid include glob '{include}'")
            continue

        for path in candidates:
            if path.is_symlink() or not path.is_file():
                continue

            try:
                target = path.resolve(strict=True)

            except OSError:
                logging.warning(f"load_scope cannot resolve '{path}'")
                continue

            if target not in allowed:
                continue

            relative = _relative(root, target)
            if relative is None:
                continue

            if _excluded(config, relative):
                continue

            if target in seen:
                continue

            seen.add(target)
            yield path


def _real_files(root: Path) -> Set[Path]:
    """Collect resolved real files under root without following symlinks"""
    files: Set[Path] = set()

    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)

        for dirname in list(dirnames):
            directory = current_path.joinpath(dirname)
            if directory.is_symlink():
                logging.debug(f"load_scope skip symlinked directory '{directory}'")
                dirnames.remove(dirname)

        for filename in filenames:
            path = current_path.joinpath(filename)

            if path.is_symlink():
                logging.debug(f"load_scope skip symlinked file '{path}'")
                continue

            try:
                resolved = path.resolve()

            except OSError:
                logging.warning(f"load_scope cannot resolve '{path}'")
                continue

            if not resolved.is_file():
                continue

            if _relative(root, resolved) is None:
                logging.debug(f"load_scope skip out-of-root target '{path}' -> '{resolved}'")
                continue

            files.add(resolved)

    return files


def _resolves_to_file(path: Path) -> bool:
    """Check that a path resolves to an existing real file"""
    try:
        return path.resolve(strict=True).is_file()

    except OSError:
        logging.warning(f"load_scope cannot resolve '{path}'")
        return False


def _relative(root: Path, target: Path):
    """Return target's path relative to root, or None when outside root"""
    try:
        return target.relative_to(root)

    except ValueError:
        return None


def _excluded(config: dict, relative: Path) -> bool:
    """Match exclude regex against the root-relative path of the real target"""
    if not config.exclude.files:
        return False

    candidate = relative.as_posix()
    if config.exclude.files.match(candidate):
        logging.debug(f"load_scope excluded file '{candidate}'")
        return True

    return False
