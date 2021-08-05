"""
This module contains functions to help manage keys used in PASETO protocols.

It includes an early implementation of Algorithm Lucidity.
https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md

A PASERK implementation may supersede this module in the future.
https://github.com/paseto-standard/paserk
"""

import os
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Tuple

import pysodium

KEY_PREFIX = b"k"
KEY_LENGHT = 32

TYPE_LOCAL = b".local."
TYPE_PUBLIC = b".public."
TYPE_SECRET = b".secret."


def _create_symmetric_key(version: int) -> bytes:
    """Return a new symmetric key."""
    _validate_version(version)
    return _get_key_prefix(version, TYPE_LOCAL) + urlsafe_b64encode(
        os.urandom(KEY_LENGHT)
    )


def _create_asymmetric_key(version: int) -> Tuple[bytes, bytes]:
    """Return new public and secret keys."""
    _validate_version(version)
    raw_public_key, raw_secret_key = pysodium.crypto_sign_seed_keypair(
        os.urandom(pysodium.crypto_sign_SEEDBYTES)
    )

    public_key = _get_key_prefix(version, TYPE_PUBLIC) + urlsafe_b64encode(
        raw_public_key
    )
    secret_key = _get_key_prefix(version, TYPE_SECRET) + urlsafe_b64encode(
        raw_secret_key
    )
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
    return KEY_PREFIX + str(version).encode() + key_type


def _verify_key(key: bytes, version: int, key_type: bytes) -> bool:
    """Verify that key contains correct prefix."""
    return key.startswith(_get_key_prefix(version, key_type))
