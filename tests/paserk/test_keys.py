"""This module contains tests for functions that manage keys."""

import pytest

from paseto.paserk.keys import (
    _create_asymmetric_key,
    _create_symmetric_key,
    _deserialize_key,
    _get_key_prefix,
    _serialize_key,
    _validate_version,
    _verify_key,
)


def test_create_symmetric_key() -> None:
    """Test that creating symmetric key returns nonempty bytes."""
    key: bytes = _create_symmetric_key(4)
    assert type(key) == bytes
    assert len(key) > 0


def test_create_asymmetric_key() -> None:
    """Test that creating asymmetric key returns a tuble of nonempty bytes."""
    public_key: bytes
    secret_key: bytes
    public_key, secret_key = _create_asymmetric_key(4)
    assert type(public_key) == bytes
    assert type(secret_key) == bytes
    assert len(public_key) > 0
    assert len(secret_key) > 0


@pytest.mark.parametrize("key", [b"foo", b"bar", b""])
def test_serialize_deserialize_key(key: bytes) -> None:
    """Test that serialized key can be deserialized."""
    serialized = _serialize_key(version=4, key_type=b".unit_test.", raw_key=key)
    assert type(serialized) == bytes
    assert len(serialized) > 0
    deserialized = _deserialize_key(serialized)
    assert deserialized == key


def test_validate_version() -> None:
    """Test that supported versions are validated."""
    assert _validate_version(4)


@pytest.mark.parametrize("version", [1, 2, 3, 0, 5, 6])
def test_validate_version_invalid(version: int) -> None:
    """Test that unsupported versions are not validated."""
    assert not _validate_version(version)


def test_get_key_prefix() -> None:
    """Test that expected key prefix is returned."""
    assert _get_key_prefix(4, b".unit_test.") == b"k4.unit_test."


def test_verify_key() -> None:
    """Test checking key prefix."""
    assert _verify_key(b"k4.unit_test.data", 4, b".unit_test.")
    assert not _verify_key(b"k4.unit_test.data", 3, b".unit_test.")
    assert not _verify_key(b"k4.unit_test.data", 3, b".something_else.")
