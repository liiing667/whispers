from pathlib import Path

import pytest

from whispers.core.constants import MAX_XML_SIZE
from whispers.models.pair import KeyValuePair
from whispers.plugins.xml import Xml


def write_xml(tmp_path: Path, name: str, content: bytes) -> Path:
    filepath = tmp_path.joinpath(name)
    filepath.write_bytes(content)
    return filepath


def test_xml_rejects_internal_entity_xxe(tmp_path):
    secret = tmp_path.joinpath("secret.txt")
    secret.write_text("HOST_SECRET_VALUE")
    malicious = write_xml(
        tmp_path,
        "xxe.xml",
        (
            b'<?xml version="1.0"?>\n'
            b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://' + str(secret).encode() + b'">]>\n'
            b"<root><secret>&xxe;</secret></root>\n"
        ),
    )

    pairs = list(Xml().pairs(malicious))

    assert pairs == []
    assert not any("HOST_SECRET_VALUE" in pair.value for pair in pairs)


def test_xml_rejects_external_dtd(tmp_path):
    dtd = tmp_path.joinpath("external.dtd")
    dtd.write_text('<!ENTITY leaked "leaked-from-dtd">')
    malicious = write_xml(
        tmp_path,
        "external_dtd.xml",
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE root SYSTEM "file://' + str(dtd).encode() + b'">\n'
        b"<root><secret>&leaked;</secret></root>\n",
    )

    pairs = list(Xml().pairs(malicious))

    assert pairs == []


def test_xml_rejects_entity_expansion_bomb(tmp_path):
    bomb = [b'<?xml version="1.0"?>', b"<!DOCTYPE lolz [", b' <!ENTITY lol "lol">']
    for level in range(2, 10):
        ref = "lol" if level == 2 else f"lol{level - 1}"
        bomb.append(f' <!ENTITY lol{level} "{"&" + ref + ";" * 10}">'.encode())
    bomb += [b"]>", b"<lolz>&lol9;</lolz>"]
    bomb = b"\n".join(bomb) + b"\n"
    malicious = write_xml(tmp_path, "bomb.xml", bomb)

    pairs = list(Xml().pairs(malicious))

    assert pairs == []


def test_xml_rejects_oversized_document(tmp_path):
    oversized = b'<?xml version="1.0"?><root>' + b"a" * (MAX_XML_SIZE + 1) + b"</root>"
    malicious = write_xml(tmp_path, "oversized.xml", oversized)

    pairs = list(Xml().pairs(malicious))

    assert pairs == []


@pytest.mark.parametrize(
    "filename",
    ["apikeys.xml", "beans.xml", "jdbc.xml", "jenkins.xml"],
)
def test_xml_keeps_normal_documents(filename):
    filepath = Path("tests/fixtures").joinpath(filename)
    pairs = list(Xml().pairs(filepath))

    assert pairs
    assert all(isinstance(pair, KeyValuePair) for pair in pairs)


def test_xml_keeps_escapes_namespaces_and_key_values(tmp_path):
    filepath = write_xml(
        tmp_path,
        "normal.xml",
        b'<?xml version="1.0"?>\n'
        b'<spring:beans xmlns:ss="urn:ss">\n'
        b'  <ss:user name="admin" password="p&amp;ssword"/>\n'
        b'  <entry key="jdbcUrl" value="jdbc:mysql://h?u=1&amp;p=2"/>\n'
        b"  <bearer><key>token</key><value>hardcoded-bearer</value></bearer>\n"
        b"</spring:beans>\n",
    )

    pairs = list(Xml().pairs(filepath))
    values = [pair.value for pair in pairs]

    assert "p&ssword" in values
    assert "jdbc:mysql://h?u=1&p=2" in values
    assert "hardcoded-bearer" in values
    assert any(pair.key == "key" and pair.value == "token" for pair in pairs)
    assert any(pair.key == "value" and pair.value == "hardcoded-bearer" for pair in pairs)
    assert any("spring:beans" in pair.keypath for pair in pairs)
