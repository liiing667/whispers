import logging
from io import StringIO

from whispers.core.utils import global_exception_handler


def test_global_exception_handler_reports_failure_location():
    """A parse failure must point at the exact file, stage and exception."""
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    root = logging.getLogger()
    root.addHandler(handler)
    previous_level = root.level
    root.setLevel(logging.DEBUG)
    try:
        try:
            raise RuntimeError("boom in parser")
        except RuntimeError:
            global_exception_handler("path/to/broken.json", "Json.load_custom_json()")
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)

    output = stream.getvalue()
    assert "path/to/broken.json" in output
    assert "Json.load_custom_json()" in output
    assert "RuntimeError" in output
    assert "boom in parser" in output


def test_global_exception_handler_default_stage():
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    root = logging.getLogger()
    root.addHandler(handler)
    previous_level = root.level
    root.setLevel(logging.DEBUG)
    try:
        try:
            raise ValueError("")
        except ValueError:
            global_exception_handler("path/to/file")
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)

    output = stream.getvalue()
    assert "path/to/file" in output
    assert "unknown stage" in output
