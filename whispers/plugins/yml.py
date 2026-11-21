import re
from pathlib import Path
from typing import Iterator

import yaml
from yaml.parser import ParserError

from whispers.core.utils import global_exception_handler
from whispers.models.pair import KeyValuePair
from whispers.plugins.traverse import StructuredDocument


def _constructor(loader, tag_suffix, node):
    """This is needed to parse IaC syntax"""
    ret = loader.construct_scalar(node)
    return f"{tag_suffix} {ret}"


class WhisperLoader(yaml.SafeLoader):
    """Isolated loader so scans never mutate process-wide YAML state."""


# Keep the plugin's boolean semantics local to its own loader.
_YAML_BOOLEAN_INITIALS = set("OoYyNn")
WhisperLoader.yaml_implicit_resolvers = {
    idx: list(resolvers)
    for idx, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    if idx not in _YAML_BOOLEAN_INITIALS
}
WhisperLoader.add_multi_constructor("", _constructor)


class Yml(StructuredDocument):
    def pairs(self, filepath: Path) -> Iterator[KeyValuePair]:
        """
        Convert custom YAML to parsable YAML
        - Skip ---
        - Quote unquoted values such as {{ placeholder }}
        - Remove text between <% %> and {% %}
        - Remove comments that start with #
        """
        self.reset()
        try:
            regex_unquoted = re.compile(r".+(\[)?\{\{.*\}\}(\])?")
            document = ""

            for line in filepath.open("r").readlines():
                if line.startswith("---"):
                    continue

                if regex_unquoted.match(line):
                    line = line.replace("{{", "'{{").replace("}}", "}}'")

                document += line

            document = re.sub(r"[<{]%.*?%[}>]", "", document, flags=re.MULTILINE | re.DOTALL)
            document = re.sub(r"^#.*$", "", document)

            # Load converted YAML
            try:
                code = yaml.load(document, Loader=WhisperLoader)
                yield from self.traverse(code)

            except ParserError:
                global_exception_handler(filepath.as_posix(), document)

        finally:
            # The plugin may be reused after an error or a cancelled scan.
            self.reset()
