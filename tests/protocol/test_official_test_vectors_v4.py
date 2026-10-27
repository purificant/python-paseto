"""
This module contains tests for official test vectors.

Test vectors: https://github.com/paseto-standard/test-vectors
Docs: https://github.com/paseto-standard/paseto-spec
"""

# pylint: disable=too-many-positional-arguments

import os
from unittest.mock import MagicMock, patch

import pytest

from paseto.exceptions import PasetoException
from paseto.paserk.keys import _create_asymmetric_key, _create_symmetric_key
from paseto.protocol import version4
from tests.conftest import get_test_vector
from tests.util import (
    transform_test_case_for_v4_local,
    transform_test_case_for_v4_public,
)


def get_test_cases(name: str) -> list[dict]:
    """Return test cases filtered by name."""
    return [
        test_case
        for test_case in get_test_vector("v4")["tests"]
        if test_case["name"].startswith(name)
    ]


def get_expect_fail_test_cases() -> list[dict]:
    """Return test cases that must fail to decode."""
    return [
        test_case
        for test_case in get_test_vector("v4")["tests"]
        if test_case["expect-fail"]
    ]


# use a test nonce for reproducible tests
@patch.object(os, "urandom")
@pytest.mark.parametrize(
    "test_name,nonce,raw_key_material,test_token,payload,footer,implicit_assertion",
    [
        pytest.param(*transform_test_case_for_v4_local(test_case), id=test_case["name"])
        for test_case in get_test_cases("4-E")
    ],
)
def test_v4_local(
    mock: MagicMock,
    test_name: str,
    nonce: bytes,
    raw_key_material: bytes,
    test_token: bytes,
    payload: bytes,
    footer: bytes,
    implicit_assertion: bytes,
) -> None:
    """Tests for v4.local (Shared-Key Encryption)."""
    # pylint: disable=too-many-arguments

    # use non random nonce for reproducible tests
    mock.return_value = nonce
    key = _create_symmetric_key(4, raw_key_material)

    # verify that encrypt produces expected token
    assert test_token == version4.encrypt(payload, key, footer, implicit_assertion), (
        test_name
    )

    # verify that decrypt produces expected payload
    assert payload == version4.decrypt(test_token, key, footer, implicit_assertion), (
        test_name
    )


@pytest.mark.parametrize(
    "test_name,raw_public_key,raw_secret_key,test_token,payload,footer,implicit_assertion",
    [
        pytest.param(
            *transform_test_case_for_v4_public(test_case), id=test_case["name"]
        )
        for test_case in get_test_cases("4-S")
    ],
)
def test_v4_public(
    test_name: str,
    raw_public_key: bytes,
    raw_secret_key: bytes,
    test_token: bytes,
    payload: bytes,
    footer: bytes,
    implicit_assertion: bytes,
) -> None:
    """Tests for v4.public"""
    # pylint: disable=too-many-arguments

    public_key, secret_key = _create_asymmetric_key(4, raw_public_key, raw_secret_key)

    # verify that sign produces expected token
    assert test_token == version4.sign(
        payload, secret_key, footer, implicit_assertion
    ), test_name

    # verify that token contains expected payload
    assert payload == version4.verify(
        test_token, public_key, footer, implicit_assertion
    ), test_name


@pytest.mark.parametrize(
    "test_case",
    [
        pytest.param(test_case, id=test_case["name"])
        for test_case in get_expect_fail_test_cases()
    ],
)
def test_v4_expect_fail(test_case: dict) -> None:
    """Tests that tokens marked expect-fail are rejected."""
    token: bytes = test_case["token"].encode()
    footer: bytes = test_case["footer"].encode()
    implicit_assertion: bytes = test_case["implicit-assertion"].encode()

    # a case carries either a symmetric key or a key pair, which picks the operation
    if "key" in test_case:
        key: bytes = _create_symmetric_key(4, bytes.fromhex(test_case["key"]))
        with pytest.raises(PasetoException):
            version4.decrypt(token, key, footer, implicit_assertion)
    else:
        public_key, _ = _create_asymmetric_key(
            4,
            bytes.fromhex(test_case["public-key"]),
            bytes.fromhex(test_case["secret-key"]),
        )
        with pytest.raises(PasetoException):
            version4.verify(token, public_key, footer, implicit_assertion)
