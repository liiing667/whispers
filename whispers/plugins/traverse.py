from typing import Iterator, Optional

from whispers.models.pair import KeyValuePair
from whispers.plugins.common import Common
from whispers.plugins.shell import Shell


class StructuredDocument:
    def __init__(self):
        self.keypath = []

    def reset(self) -> None:
        """Clear traversal state before or after a document."""
        self.keypath.clear()

    def traverse(self, code, key=None) -> Optional[Iterator[KeyValuePair]]:
        """Recursively traverse YAML/JSON document"""
        depth = len(self.keypath)

        try:
            if isinstance(code, dict):
                yield from self.cloudformation(code)

                for k, v in code.items():
                    self.keypath.append(k)
                    if isinstance(v, (str, int)):
                        yield KeyValuePair(k, v, list(self.keypath))

                    yield from self.traverse(v, key=k)
                    self.keypath.pop()

                # Special key/value format
                elements = list(code.keys())
                if "key" in elements and "value" in elements:
                    yield KeyValuePair(code["key"], code["value"], list(self.keypath))

            elif isinstance(code, list):
                for item in code:
                    if isinstance(item, (str, int)):
                        yield KeyValuePair(key, item, list(self.keypath))

                    yield from self.traverse(item, key=key)

            elif isinstance(code, str):
                yield from Shell().variables([code])
                yield from Common(self.keypath).pairs(code)

        finally:
            # Restore the path captured on entry. This also runs when the
            # caller closes a partially consumed scan or traversal raises.
            del self.keypath[depth:]

    def cloudformation(self, code: dict) -> Iterator[KeyValuePair]:
        """AWS CloudFormation format"""
        if self.keypath:
            return  # Not tree root

        if "AWSTemplateFormatVersion" not in code:
            return  # Not CF format

        if "Parameters" not in code:
            return  # No parameters

        for key, values in code["Parameters"].items():
            if "Default" not in values:
                continue  # No default value

            keypath = ["Parameters", "Default", key]
            yield KeyValuePair(key, values["Default"], keypath)
