import json
import logging
from argparse import Namespace
from os import environ
from sys import exit
from typing import Iterator

from whispers.core.args import parse_args
from whispers.core.config import load_config
from whispers.core.pairs import close_plugin, make_pairs
from whispers.core.rules import load_rules
from whispers.core.scope import load_scope
from whispers.core.secrets import detect_secrets
from whispers.models.pair import KeyValuePair

environ["PYTHONUTF8"] = "1"
environ["PYTHONIOENCODING"] = "UTF-8"


def main() -> None:  # pragma: no cover
    """Main entry point"""
    args = parse_args()

    secrets = []
    for secret in run(args):
        logging.warning(str(secret))
        secrets.append(secret.to_json())

    args.output.write(json.dumps(secrets) + "\n")

    exit(args.exitcode)


def run(args: Namespace) -> Iterator[KeyValuePair]:
    """Main worker process"""
    config = load_config(args)
    rules = load_rules(args, config)
    scope = load_scope(args, config)

    def _detect() -> Iterator[KeyValuePair]:
        """Scan one file at a time and close its parser before moving on."""
        for file in scope:
            pairs = make_pairs(config, file)
            if pairs is None:
                continue

            try:
                yield from detect_secrets(rules, pairs)

            finally:
                close_plugin(pairs)

    return _detect()


if __name__ == "__main__":
    main()
