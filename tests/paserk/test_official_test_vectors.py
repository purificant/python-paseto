"""
This module contains tests for official PASERK test vectors for k2 and k4 keys.

Test vectors: https://github.com/paseto-standard/test-vectors/tree/master/PASERK
Docs: https://github.com/paseto-standard/paserk
"""

from types import ModuleType

import pytest

from paseto.exceptions import InvalidKey
from paseto.paserk.keys import (
    _TYPE_LOCAL,
    _TYPE_PUBLIC,
    _TYPE_SECRET,
    _deserialize_key,
    _serialize_key,
)
from paseto.protocol import version2, version4
from tests.conftest import get_test_vector

KEY_TYPES: dict[str, bytes] = {
    "local": _TYPE_LOCAL,
    "public": _TYPE_PUBLIC,
    "secret": _TYPE_SECRET,
}

PROTOCOLS: dict[int, ModuleType] = {2: version2, 4: version4}


def get_test_cases(key_types: list[str], expect_fail: bool) -> list:
    """Return (version, key type, test case) params from the PASERK vector files."""
    return [
        pytest.param(version, KEY_TYPES[key_type], test_case, id=test_case["name"])
        for version in PROTOCOLS
        for key_type in key_types
        for test_case in get_test_vector(f"PASERK/k{version}.{key_type}")["tests"]
        if test_case["expect-fail"] is expect_fail
    ]


@pytest.mark.parametrize(
    "version,key_type,test_case", get_test_cases(list(KEY_TYPES), expect_fail=False)
)
def test_paserk(version: int, key_type: bytes, test_case: dict) -> None:
    """Test that raw keys serialize to the expected PASERK and back."""
    raw_key: bytes = bytes.fromhex(test_case["key"])
    paserk: bytes = test_case["paserk"].encode()

    assert _serialize_key(version=version, key_type=key_type, raw_key=raw_key) == paserk
    assert _deserialize_key(key=paserk, version=version, key_type=key_type) == raw_key


@pytest.mark.parametrize(
    "version,key_type,test_case", get_test_cases(list(KEY_TYPES), expect_fail=True)
)
def test_paserk_expect_fail(version: int, key_type: bytes, test_case: dict) -> None:
    """Test that invalid raw keys and PASERKs are rejected."""
    # a case gives either a PASERK to parse or a raw key to serialize
    if test_case["paserk"] is None:
        # some wrong-version cases give a PEM key, which isn't hex
        raw_key: bytes = (
            test_case["key"].encode()
            if test_case["key"].startswith("-----BEGIN")
            else bytes.fromhex(test_case["key"])
        )
        with pytest.raises(InvalidKey):
            _serialize_key(version=version, key_type=key_type, raw_key=raw_key)
    else:
        with pytest.raises(InvalidKey):
            _deserialize_key(
                key=test_case["paserk"].encode(), version=version, key_type=key_type
            )


@pytest.mark.parametrize(
    "version,_,test_case", get_test_cases(["secret"], expect_fail=False)
)
def test_paserk_secret_signs(version: int, _: bytes, test_case: dict) -> None:
    """Test that a secret PASERK signs tokens its listed public key verifies."""
    protocol: ModuleType = PROTOCOLS[version]
    secret_key: bytes = test_case["paserk"].encode()
    public_key: bytes = _serialize_key(
        version=version,
        key_type=_TYPE_PUBLIC,
        raw_key=bytes.fromhex(test_case["public-key"]),
    )

    token: bytes = protocol.sign(b"message", secret_key)
    assert protocol.verify(token, public_key) == b"message"
