"""This module contains tests for functions that manage keys."""

from base64 import urlsafe_b64encode

import pysodium
import pytest

from paseto.exceptions import InvalidKey
from paseto.paserk.keys import (
    _TYPE_LOCAL,
    _TYPE_PUBLIC,
    _TYPE_SECRET,
    _create_asymmetric_key,
    _create_symmetric_key,
    _deserialize_key,
    _get_key_prefix,
    _serialize_key,
    _validate_version,
    _verify_key,
)
from paseto.protocol.util import b64

PUBLIC_KEY, SECRET_KEY = pysodium.crypto_sign_seed_keypair(b"2" * 32)
OTHER_PUBLIC_KEY, _ = pysodium.crypto_sign_seed_keypair(b"3" * 32)


def test_create_symmetric_key() -> None:
    """Test that creating symmetric key returns nonempty bytes."""
    key: bytes = _create_symmetric_key(4)
    assert isinstance(key, bytes)
    assert len(key) > 0


def test_create_asymmetric_key() -> None:
    """Test that creating asymmetric key returns a tuble of nonempty bytes."""
    public_key: bytes
    secret_key: bytes
    public_key, secret_key = _create_asymmetric_key(4)
    assert isinstance(public_key, bytes)
    assert isinstance(secret_key, bytes)
    assert len(public_key) > 0
    assert len(secret_key) > 0


@pytest.mark.parametrize(
    "key_type,key",
    [(_TYPE_LOCAL, b"0" * 32), (_TYPE_PUBLIC, PUBLIC_KEY), (_TYPE_SECRET, SECRET_KEY)],
)
def test_serialize_deserialize_key(key_type: bytes, key: bytes) -> None:
    """Test that serialized key can be deserialized."""
    serialized = _serialize_key(version=4, key_type=key_type, raw_key=key)
    assert not serialized.endswith(b"=")
    deserialized = _deserialize_key(key=serialized, version=4, key_type=key_type)
    assert deserialized == key


@pytest.mark.parametrize(
    "key_type,key",
    [(_TYPE_LOCAL, b"0" * 32), (_TYPE_PUBLIC, PUBLIC_KEY), (_TYPE_SECRET, SECRET_KEY)],
)
def test_deserialize_padded_key(key_type: bytes, key: bytes) -> None:
    """Test that keys in the padded format of older releases still deserialize."""
    padded: bytes = _get_key_prefix(4, key_type) + urlsafe_b64encode(key)
    assert padded.endswith(b"=")
    assert _deserialize_key(key=padded, version=4, key_type=key_type) == key


@pytest.mark.parametrize(
    "key_type,key",
    [(_TYPE_LOCAL, b"0" * 32), (_TYPE_PUBLIC, PUBLIC_KEY), (_TYPE_SECRET, SECRET_KEY)],
)
def test_deserialize_padded_k2_key(key_type: bytes, key: bytes) -> None:
    """Test that k2 keys are read unpadded only, since no release wrote them padded."""
    padded: bytes = _get_key_prefix(2, key_type) + urlsafe_b64encode(key)
    with pytest.raises(InvalidKey):
        _deserialize_key(key=padded, version=2, key_type=key_type)


@pytest.mark.parametrize(
    "key_type,length",
    [
        (_TYPE_LOCAL, 31),
        (_TYPE_LOCAL, 33),
        (_TYPE_PUBLIC, 31),
        (_TYPE_PUBLIC, 33),
        (_TYPE_SECRET, 63),
        (_TYPE_SECRET, 65),
    ],
)
def test_serialize_key_invalid_length(key_type: bytes, length: int) -> None:
    """Test that raw keys of the wrong length are not serialized."""
    with pytest.raises(InvalidKey):
        _serialize_key(version=4, key_type=key_type, raw_key=b"0" * length)


@pytest.mark.parametrize(
    "key",
    [
        # wrong version
        b"k3.local.MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA",
        # wrong purpose
        b"k4.public.MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA",
        # 31 bytes
        b"k4.local.MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMA",
        # 33 bytes
        b"k4.local.MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw",
        # nonzero trailing bits
        b"k4.local.MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDB",
        # padding that does not match the length
        b"k4.local.MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA==",
        # character outside the base64url alphabet
        b"k4.local.MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM+A",
    ],
)
def test_deserialize_key_invalid(key: bytes) -> None:
    """Test that keys that are not valid k4.local keys are rejected."""
    with pytest.raises(InvalidKey):
        _deserialize_key(key=key, version=4, key_type=_TYPE_LOCAL)


def test_serialize_mismatched_secret_key() -> None:
    """Test that a secret key whose public half doesn't match its seed is rejected."""
    with pytest.raises(InvalidKey):
        _serialize_key(4, _TYPE_SECRET, SECRET_KEY[:32] + OTHER_PUBLIC_KEY)


def test_deserialize_mismatched_secret_key() -> None:
    """Test that a stored secret key with a swapped public half is rejected."""
    tampered: bytes = b"k4.secret." + b64(SECRET_KEY[:32] + OTHER_PUBLIC_KEY)
    with pytest.raises(InvalidKey):
        _deserialize_key(key=tampered, version=4, key_type=_TYPE_SECRET)


def test_create_asymmetric_key_mismatched_pair() -> None:
    """Test that a public key from another key pair is rejected."""
    with pytest.raises(InvalidKey):
        _create_asymmetric_key(4, OTHER_PUBLIC_KEY, SECRET_KEY)


@pytest.mark.parametrize("version", [2, 4])
def test_validate_version(version: int) -> None:
    """Test that supported versions are validated."""
    assert _validate_version(version)


@pytest.mark.parametrize("version", [1, 3, 0, 5, 6])
def test_validate_version_invalid(version: int) -> None:
    """Test that unsupported versions are not validated."""
    assert not _validate_version(version)


def test_get_key_prefix() -> None:
    """Test that expected key prefix is returned."""
    assert _get_key_prefix(4, b".unit_test.") == b"k4.unit_test."


def test_get_key_prefix_unsupported_version() -> None:
    """Test that keys are neither created nor read for unsupported versions."""
    with pytest.raises(ValueError, match="Unsupported version"):
        _create_symmetric_key(version=3)
    with pytest.raises(ValueError, match="Unsupported version"):
        _create_asymmetric_key(version=3)
    with pytest.raises(ValueError, match="Unsupported version"):
        _deserialize_key(key=b"k3.local.data", version=3, key_type=_TYPE_LOCAL)


def test_verify_key() -> None:
    """Test checking key prefix."""
    assert _verify_key(b"k4.unit_test.data", 4, b".unit_test.")
    assert not _verify_key(b"k4.unit_test.data", 2, b".unit_test.")
    assert not _verify_key(b"k4.unit_test.data", 2, b".something_else.")
