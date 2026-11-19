from pathlib import Path
from typing import Iterator

from lxml import etree as ElementTree

from whispers.core.constants import MAX_XML_SIZE, REGEX_XML_DTD
from whispers.core.utils import global_exception_handler
from whispers.models.pair import KeyValuePair
from whispers.plugins.common import Common


class Xml:
    def __init__(self):
        self.keypath = []

    def pairs(self, filepath: Path) -> Iterator[KeyValuePair]:
        def _traverse(tree):
            """Traverse XML document"""
            for event, element in tree:
                if event == "end":
                    self.keypath.pop()
                    continue

                self.keypath.append(element.tag)

                # Format: <elem key="value">
                for key, value in element.attrib.items():
                    self.keypath.append(key)
                    yield KeyValuePair(key, value, list(self.keypath))

                    # Format: <elem name="jdbc:mysql://host?k1=v1&amp;k2=v2">
                    yield from Common(self.keypath).pairs(value)

                    self.keypath.pop()

                # Format: <elem key=a value=b>
                if "key" in element.attrib and "value" in element.attrib:
                    yield KeyValuePair(element.attrib["key"], element.attrib["value"], list(self.keypath))

                # Format: <key>value</key>
                if not element.text:
                    continue

                yield KeyValuePair(element.tag, element.text, list(self.keypath))
                yield from Common(self.keypath).pairs(element.text)

                # Format: <elem>key=value</elem>
                if "=" in element.text:
                    item = element.text.split("=")
                    if len(item) == 2:
                        self.keypath.append(item[0])
                        yield KeyValuePair(item[0], item[1], list(self.keypath))
                        self.keypath.pop()

                # Format: <key>name</key><value>string</value>
                found_key = None
                found_value = None
                for item in element:
                    if str(item.tag).lower() == "key":
                        found_key = item.text
                    elif str(item.tag).lower() == "value":
                        found_value = item.text

                if found_key and found_value:
                    self.keypath.append(found_key)
                    yield KeyValuePair(found_key, found_value, list(self.keypath))
                    yield from Common(self.keypath).pairs(found_value)
                    self.keypath.pop()

        try:
            data = filepath.read_bytes()

            if len(data) > MAX_XML_SIZE:
                raise ValueError(f"XML document exceeds size budget of {MAX_XML_SIZE} bytes")

            # DTDs and entity declarations enable XXE reads and entity expansion DoS.
            if REGEX_XML_DTD.search(data):
                raise ValueError("XML documents with DTD or entity declarations are not allowed")

            # Hardened parser: no entity resolution, no network, no DTD, no huge trees.
            parser = ElementTree.XMLParser(
                recover=True,
                resolve_entities=False,
                no_network=True,
                load_dtd=False,
                dtd_validation=False,
                huge_tree=False,
            )
            tree = ElementTree.fromstring(data, parser)
            tree = ElementTree.iterwalk(tree, events=("start", "end"))
            yield from _traverse(tree)

        except Exception:
            global_exception_handler(filepath.as_posix(), "whispers.plugins.xml.Xml.pairs()")
