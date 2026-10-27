"""
This module contains functions to help manage keys used in PASETO protocols.

It includes an implementation of Algorithm Lucidity.
https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md

Serialized keys follow the PASERK local, public and secret types.
A PASERK implementation may supersede this module in the future.
https://github.com/paseto-standard/paserk
"""

import hmac
import os
from base64 import urlsafe_b64encode

import pysodium

from paseto.exceptions import InvalidEncoding, InvalidKey
from paseto.protocol.util import b64, b64decode

_KEY_PREFIX = b"k"
_KEY_LENGHT = 32

_TYPE_LOCAL = b".local."
_TYPE_PUBLIC = b".public."
_TYPE_SECRET = b".secret."

_RAW_KEY_LENGTHS: dict[bytes, int] = {
    _TYPE_LOCAL: _KEY_LENGHT,
    _TYPE_PUBLIC: pysodium.crypto_sign_PUBLICKEYBYTES,
    # Ed25519 seed followed by the public key, as libsodium stores it
    _TYPE_SECRET: pysodium.crypto_sign_SECRETKEYBYTES,
}


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
) -> tuple[bytes, bytes]:
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
    # secret key passed its seed check, so its second half is the real public key
    if (
        raw_public_key_material
        != raw_secret_key_material[pysodium.crypto_sign_SEEDBYTES :]
    ):
        raise InvalidKey("Public key does not belong to secret key")
    return public_key, secret_key


def _serialize_key(version: int, key_type: bytes, raw_key: bytes) -> bytes:
    """Returns text representation of raw key bytes.

    Raises:
        InvalidKey: If raw_key is not a valid key of key_type.
    """
    _check_raw_key(raw_key, key_type)
    return _get_key_prefix(version, key_type) + b64(raw_key)


def _deserialize_key(key: bytes, version: int, key_type: bytes) -> bytes:
    """Returns raw key bytes from a serialised key.

    Raises:
        InvalidKey: If key is not a valid key of this version and type.
    """
    if not _verify_key(key, version, key_type):
        raise InvalidKey("Key is not intended for this version and purpose")

    encoded: bytes = key[len(_get_key_prefix(version, key_type)) :]
    try:
        raw_key: bytes = b64decode(encoded.rstrip(b"="))
    except InvalidEncoding as error:
        raise InvalidKey("Invalid key encoding") from error

    # older releases wrote keys with "=" padding, keep reading that exact form
    if encoded not in (b64(raw_key), urlsafe_b64encode(raw_key)):
        raise InvalidKey("Invalid key encoding")

    _check_raw_key(raw_key, key_type)
    return raw_key


def _check_raw_key(raw_key: bytes, key_type: bytes) -> None:
    """Raise InvalidKey unless raw_key is a valid key of key_type."""
    if len(raw_key) != _RAW_KEY_LENGTHS[key_type]:
        raise InvalidKey("Invalid key length")

    # libsodium signs with the embedded public half unchecked, and signing one message
    # under two public halves leaks the secret scalar, see MystenLabs/ed25519-unsafe-libs
    if key_type == _TYPE_SECRET:
        seed: bytes = raw_key[: pysodium.crypto_sign_SEEDBYTES]
        _, expected = pysodium.crypto_sign_seed_keypair(seed)
        if not hmac.compare_digest(expected, raw_key):
            raise InvalidKey("Public key does not belong to secret key")


def _validate_version(version: int) -> bool:
    """Validate all supported protocol versions."""
    return version in [4]


def _get_key_prefix(version: int, key_type: bytes) -> bytes:
    """Return key prefix for serialization."""
    return _KEY_PREFIX + str(version).encode() + key_type


def _verify_key(key: bytes, version: int, key_type: bytes) -> bool:
    """Verify that key contains correct prefix."""
    return key.startswith(_get_key_prefix(version, key_type))
