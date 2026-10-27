"""
This module contains tests for official test vectors updated in preparation for PASETO v3 and v4.

Test vectors are available here:
https://github.com/paseto-standard/test-vectors

Documentation is here: https://github.com/paseto-standard/paseto-spec
"""

# pylint: disable=too-many-positional-arguments

import os
from unittest.mock import MagicMock, patch

import pytest

from paseto.exceptions import PasetoException
from paseto.protocol import version2
from tests.conftest import get_test_vector
from tests.util import (
    transform_test_case_for_v2_local,
    transform_test_case_for_v2_public,
)


def get_test_cases(name: str) -> list[dict]:
    """Return test cases filtered by name."""
    return [
        test_case
        for test_case in get_test_vector("v2")["tests"]
        if test_case["name"].startswith(name)
    ]


def get_expect_fail_test_cases() -> list[dict]:
    """Return test cases that must fail to decode."""
    return [
        test_case
        for test_case in get_test_vector("v2")["tests"]
        if test_case["expect-fail"]
    ]


# use a test nonce for reproducible tests
@patch.object(os, "urandom")
@pytest.mark.parametrize(
    "name,nonce,raw_key_material,token,payload,footer",
    [
        pytest.param(*transform_test_case_for_v2_local(test_case), id=test_case["name"])
        for test_case in get_test_cases("2-E")
    ],
)
def test_v2_local(
    mock: MagicMock,
    name: str,
    nonce: bytes,
    raw_key_material: bytes,
    token: bytes,
    payload: bytes,
    footer: bytes,
) -> None:
    """Tests for v2.local (Shared-Key Encryption)."""
    # pylint: disable=too-many-arguments

    # use non random nonce for reproducible tests
    mock.return_value = nonce
    key: bytes = version2.import_symmetric_key(raw_key_material)

    # verify that encrypt produces expected token
    assert token == version2.encrypt(payload, key, footer), name

    # verify that decrypt produces expected payload
    assert payload == version2.decrypt(token, key, footer), name


@pytest.mark.parametrize(
    "name,raw_public_key,raw_secret_key,token,payload,footer",
    [
        pytest.param(
            *transform_test_case_for_v2_public(test_case), id=test_case["name"]
        )
        for test_case in get_test_cases("2-S")
    ],
)
def test_v2_public(
    name: str,
    raw_public_key: bytes,
    raw_secret_key: bytes,
    token: bytes,
    payload: bytes,
    footer: bytes,
) -> None:
    """Tests for v2.public (Public-Key Authentication)."""
    # pylint: disable=too-many-arguments

    public_key: bytes = version2.import_public_key(raw_public_key)
    secret_key: bytes = version2.import_secret_key(raw_secret_key)

    # verify that sign produces expected token
    assert token == version2.sign(payload, secret_key, footer), name

    # verify that token contains expected payload
    assert payload == version2.verify(token, public_key, footer), name


@pytest.mark.parametrize(
    "test_case",
    [
        pytest.param(test_case, id=test_case["name"])
        for test_case in get_expect_fail_test_cases()
    ],
)
def test_v2_expect_fail(test_case: dict) -> None:
    """Tests that tokens marked expect-fail are rejected."""
    token: bytes = test_case["token"].encode()
    footer: bytes = test_case["footer"].encode()

    # v2 has no implicit assertions, so "implicit-assertion" is not used
    # a case carries either a symmetric key or a key pair, which picks the operation
    if "key" in test_case:
        key: bytes = version2.import_symmetric_key(bytes.fromhex(test_case["key"]))
        with pytest.raises(PasetoException):
            version2.decrypt(token, key, footer)
    else:
        public_key: bytes = version2.import_public_key(
            bytes.fromhex(test_case["public-key"])
        )
        with pytest.raises(PasetoException):
            version2.verify(token, public_key, footer)
