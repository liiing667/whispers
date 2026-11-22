from typing import Iterator


def secrets(arguments: str) -> Iterator:
    """
    Boilerplate for simplifying usage and integration.

    import whispers
    for secret in whispers.secrets("-r apikey tests/fixtures"):
        print(secret)
    """
    import shlex

    from whispers.core.args import parse_args
    from whispers.main import run

    argv = shlex.split(arguments)
    return run(parse_args(argv))


def git_history(*args, **kwargs):
    """Scan a Git history snapshot with resumable commit/blob identity."""
    from whispers.core.history import scan_git_history

    return scan_git_history(*args, **kwargs)


def history(*args, **kwargs):
    """Alias for :func:`git_history`."""
    return git_history(*args, **kwargs)
