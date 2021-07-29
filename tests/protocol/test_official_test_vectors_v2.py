"""
This module contains tests for official test vectors updated in preparation for PASETO v3 and v4.

Test vectors are available in https://github.com/purificant/paseto-test-vectors
Documentation is here: https://github.com/paragonie/paseto/tree/master/docs/03-Implementation-Guide

"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from paseto.protocol.version2 import Version2
from tests.conftest import get_test_vector


def test_expected_number_of_test_vectors(get_test_vectors_v2):
    """Test that official test vector specification matches expectations."""
    # total test vectors
    assert len(get_test_vectors_v2["tests"]) == 12
    # '2-E-1' to '2-E-9'
    assert (
        sum(
            1
            for test_case in get_test_vectors_v2["tests"]
            if test_case["name"].startswith("2-E-")
        )
        == 9
    )
    # '2-S-1' to '2-S-3'
    assert (
        sum(
            1
            for test_case in get_test_vectors_v2["tests"]
            if test_case["name"].startswith("2-S-")
        )
        == 3
    )


def get_test_cases(name: str):
    """Return test cases filtered by name."""
    return [
        test_case
        for test_case in get_test_vector("v2")["tests"]
        if test_case["name"].startswith(name)
    ]


def transform_test_case_for_v2_local(test_case: dict) -> tuple:
    """
    Transform and return test cases 2-E-1 .. 2-E-9,
    from decoded json dictionary to a tuple of expected data types.
    """
    # convert strings to bytes
    # remove extra whitespace from default json encoding in python
    return (
        test_case["name"],
        bytes.fromhex(test_case["nonce"]),
        bytes.fromhex(test_case["key"]),
        test_case["token"].encode(),
        json.dumps(test_case["payload"], separators=(",", ":")).encode(),
        test_case["footer"].encode(),
    )


def transform_test_case_for_v2_public(test_case: dict) -> tuple:
    """
    Transform and return test cases 2-S-1 .. 2-S-3,
    from decoded json dictionary to a tuple of expected data types.
    """
    return (
        test_case["name"],
        bytes.fromhex(test_case["public-key"]),
        bytes.fromhex(test_case["secret-key"]),
        test_case["token"].encode(),
        json.dumps(test_case["payload"], separators=(",", ":")).encode(),
        test_case["footer"].encode(),
    )


@patch.object(os, "urandom")
# pylint: disable=too-many-arguments
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
):
    """Tests for v2.local (Shared-Key Encryption)."""

    # use non random nonce for reproducible tests
    mock.return_value = nonce

    # verify that encrypt produces expected token
    assert token == Version2.encrypt(payload, key, footer), name

    # verify that decrypt produces expected payload
    assert payload == Version2.decrypt(token, key, footer), name


# pylint: disable=too-many-arguments
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
):
    """Test for v2.public (Public-Key Authentication)."""

    # verify that sign produces expected token
    assert token == Version2.sign(payload, secret_key, footer), name

    # verify that token contains expected payload
    assert payload == Version2.verify(token, public_key, footer), name
