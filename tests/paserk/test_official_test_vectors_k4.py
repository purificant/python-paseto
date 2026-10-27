"""
This module contains tests for official PASERK test vectors for k4 keys.

Test vectors: https://github.com/paseto-standard/test-vectors/tree/master/PASERK
Docs: https://github.com/paseto-standard/paserk
"""

import pytest

from paseto.exceptions import InvalidKey
from paseto.paserk.keys import (
    _TYPE_LOCAL,
    _TYPE_PUBLIC,
    _TYPE_SECRET,
    _deserialize_key,
    _serialize_key,
)
from paseto.protocol import version4
from tests.conftest import get_test_vector

KEY_TYPES: dict[str, bytes] = {
    "local": _TYPE_LOCAL,
    "public": _TYPE_PUBLIC,
    "secret": _TYPE_SECRET,
}


def get_test_cases(key_types: list[str], expect_fail: bool) -> list:
    """Return (key type, test case) params from the PASERK k4 vector files."""
    return [
        pytest.param(KEY_TYPES[key_type], test_case, id=test_case["name"])
        for key_type in key_types
        for test_case in get_test_vector(f"PASERK/k4.{key_type}")["tests"]
        if test_case["expect-fail"] is expect_fail
    ]


@pytest.mark.parametrize(
    "key_type,test_case", get_test_cases(list(KEY_TYPES), expect_fail=False)
)
def test_k4(key_type: bytes, test_case: dict) -> None:
    """Test that raw keys serialize to the expected PASERK and back."""
    raw_key: bytes = bytes.fromhex(test_case["key"])
    paserk: bytes = test_case["paserk"].encode()

    assert _serialize_key(4, key_type, raw_key) == paserk
    assert _deserialize_key(paserk, 4, key_type) == raw_key


@pytest.mark.parametrize(
    "key_type,test_case", get_test_cases(list(KEY_TYPES), expect_fail=True)
)
def test_k4_expect_fail(key_type: bytes, test_case: dict) -> None:
    """Test that invalid raw keys and PASERKs are rejected."""
    # a case gives either a PASERK to parse or a raw key to serialize
    if test_case["paserk"] is None:
        raw_key: bytes = bytes.fromhex(test_case["key"])
        with pytest.raises(InvalidKey):
            _serialize_key(4, key_type, raw_key)
    else:
        with pytest.raises(InvalidKey):
            _deserialize_key(test_case["paserk"].encode(), 4, key_type)


@pytest.mark.parametrize("_,test_case", get_test_cases(["secret"], expect_fail=False))
def test_k4_secret_signs(_: bytes, test_case: dict) -> None:
    """Test that a k4.secret PASERK signs tokens its listed public key verifies."""
    secret_key: bytes = test_case["paserk"].encode()
    public_key: bytes = _serialize_key(
        4, _TYPE_PUBLIC, bytes.fromhex(test_case["public-key"])
    )

    token: bytes = version4.sign(b"message", secret_key)
    assert version4.verify(token, public_key) == b"message"
