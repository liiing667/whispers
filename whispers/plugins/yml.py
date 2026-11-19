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
    """Isolated SafeLoader so scanning never mutates process-global YAML state"""


# Remove resolvers for on/off/yes/no on the isolated loader only
WhisperLoader.yaml_implicit_resolvers = {
    idx: resolvers for idx, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items() if idx not in "OoYyNn"
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
