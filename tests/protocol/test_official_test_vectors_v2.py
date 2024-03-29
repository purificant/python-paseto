"""
This module contains tests for official test vectors updated in preparation for PASETO v3 and v4.

Test vectors are available here:
https://github.com/paseto-standard/test-vectors

Documentation is here: https://github.com/paseto-standard/paseto-spec
"""

import os
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from paseto.protocol import version2
from tests.conftest import get_test_vector
from tests.util import (
    transform_test_case_for_v2_local,
    transform_test_case_for_v2_public,
)


def get_test_cases(name: str) -> List[dict]:
    """Return test cases filtered by name."""
    return [
        test_case
        for test_case in get_test_vector("v2")["tests"]
        if test_case["name"].startswith(name)
    ]


# use a test nonce for reproducible tests
@patch.object(os, "urandom")
@pytest.mark.parametrize(
    "name,nonce,key,token,payload,footer",
    [
        transform_test_case_for_v2_local(test_case)
        for test_case in get_test_cases("2-E")
    ],
)
def test_v2_local(
    mock: MagicMock,
    name: str,
    nonce: bytes,
    key: bytes,
    token: bytes,
    payload: bytes,
    footer: bytes,
) -> None:
    """Tests for v2.local (Shared-Key Encryption)."""
    # pylint: disable=too-many-arguments

    # use non random nonce for reproducible tests
    mock.return_value = nonce

    # verify that encrypt produces expected token
    assert token == version2.encrypt(payload, key, footer), name

    # verify that decrypt produces expected payload
    assert payload == version2.decrypt(token, key, footer), name


@pytest.mark.parametrize(
    "name,public_key,secret_key,token,payload,footer",
    [
        transform_test_case_for_v2_public(test_case)
        for test_case in get_test_cases("2-S")
    ],
)
def test_v2_public(
    name: str,
    public_key: bytes,
    secret_key: bytes,
    token: bytes,
    payload: bytes,
    footer: bytes,
) -> None:
    """Tests for v2.public (Public-Key Authentication)."""
    # pylint: disable=too-many-arguments

    # verify that sign produces expected token
    assert token == version2.sign(payload, secret_key, footer), name

    # verify that token contains expected payload
    assert payload == version2.verify(token, public_key, footer), name
