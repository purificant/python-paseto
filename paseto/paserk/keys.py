"""
This module contains functions to help manage keys used in PASETO protocols.

It includes an implementation of Algorithm Lucidity.
https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md

A PASERK implementation may supersede this module in the future.
https://github.com/paseto-standard/paserk
"""

import os
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Tuple

import pysodium

_KEY_PREFIX = b"k"
_KEY_LENGHT = 32

_TYPE_LOCAL = b".local."
_TYPE_PUBLIC = b".public."
_TYPE_SECRET = b".secret."


def _create_symmetric_key(version: int, raw_key_material: bytes = b"") -> bytes:
    """Return a new symmetric key."""
    _validate_version(version)
    if not raw_key_material:
        raw_key_material = os.urandom(_KEY_LENGHT)
    return _serialize_key(version, _TYPE_LOCAL, raw_key_material)


def _create_asymmetric_key(
    version: int,
    raw_public_key_material: bytes = b"",
    raw_secret_key_material: bytes = b"",
) -> Tuple[bytes, bytes]:
    """Return new public and secret keys."""
    _validate_version(version)
    if not raw_public_key_material or not raw_secret_key_material:
        (
            raw_public_key_material,
            raw_secret_key_material,
        ) = pysodium.crypto_sign_seed_keypair(
            os.urandom(pysodium.crypto_sign_SEEDBYTES)
        )

    public_key: bytes = _serialize_key(version, _TYPE_PUBLIC, raw_public_key_material)
    secret_key: bytes = _serialize_key(version, _TYPE_SECRET, raw_secret_key_material)
    return public_key, secret_key


def _serialize_key(version: int, key_type: bytes, raw_key: bytes) -> bytes:
    """Returns text representation of raw key bytes."""
    return _get_key_prefix(version, key_type) + urlsafe_b64encode(raw_key)


def _deserialize_key(key: bytes) -> bytes:
    """Returns raw key bytes from a serialised key."""
    return urlsafe_b64decode(key.split(b".")[-1])


def _validate_version(version: int) -> bool:
    """Validate all supported protocol versions."""
    return version in [4]


def _get_key_prefix(version: int, key_type: bytes) -> bytes:
    """Return key prefix for serialization."""
    return _KEY_PREFIX + str(version).encode() + key_type


def _verify_key(key: bytes, version: int, key_type: bytes) -> bool:
    """Verify that key contains correct prefix."""
    return key.startswith(_get_key_prefix(version, key_type))
