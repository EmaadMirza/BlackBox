"""RFC 8785 sorting and BlackBox input restrictions."""

import json
from pathlib import Path

import pytest
import rfc8785

from libs.blackbox_core.canonical import canonicalize, loads


def test_rfc_sort_vector() -> None:
    vector = json.loads(Path("tests/vectors/rfc8785_sort.json").read_text())
    assert rfc8785.dumps(vector["input"]).decode() == vector["canonical"]
    # BlackBox NFC intentionally decomposes U+FB33 before JCS sorting.
    expected = json.loads(vector["canonical"])
    expected["דּ"] = expected.pop("דּ")
    assert canonicalize(vector["input"]) == rfc8785.dumps(expected)


@pytest.mark.parametrize(
    "value",
    [
        1.0,
        float("nan"),
        float("inf"),
        2**53,
        {1: "x"},
        {"x": [0.1]},
        "\ud800",
        {"é": 1, "e\u0301": 2},
    ],
)
def test_rejected_values(value: object) -> None:
    with pytest.raises((ValueError, UnicodeError)):
        canonicalize(value)


@pytest.mark.parametrize("value", [b'{"a":1,"a":2}', b'{"x":NaN}', b"1.0", b"1e0"])
def test_raw_json_rejection(value: bytes) -> None:
    with pytest.raises(ValueError):
        loads(value)


def test_normalization_and_escaping() -> None:
    assert canonicalize({"e\u0301": "e\u0301"}) == '{"é":"é"}'.encode()
    assert canonicalize([None, True, False, "\n\x0f"]) == b'[null,true,false,"\\n\\u000f"]'


def test_rfc_appendix_b_numbers_and_blackbox_float_rejection() -> None:
    import struct

    vectors = json.loads(Path("tests/vectors/rfc8785_numbers.json").read_text())["vectors"]
    for vector in vectors:
        value = struct.unpack(">d", bytes.fromhex(vector["ieee754"]))[0]
        if vector["jcs"] == "REJECT":
            with pytest.raises(ValueError):
                rfc8785.dumps(value)
        else:
            assert rfc8785.dumps(value).decode() == vector["jcs"]
        # The underlying JCS engine passes the official number samples, while
        # BlackBox deliberately rejects all Python floats, including 0.0.
        with pytest.raises(ValueError):
            canonicalize(value)
