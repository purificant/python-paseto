"""
This module contains Version4 implementation of the Paseto protocol.

https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md
"""

import hashlib
import hmac
import os
from typing import Tuple

from paseto.crypto import libsodium_wrapper, primitives
from paseto.exceptions import InvalidKey, InvalidMac
from paseto.paserk.keys import (
    _TYPE_LOCAL,
    _TYPE_PUBLIC,
    _TYPE_SECRET,
    _create_asymmetric_key,
    _create_symmetric_key,
    _deserialize_key,
)
from paseto.paserk.keys import _verify_key as _generic_verify_key
from paseto.protocol.common import check_footer, check_header, decode_message
from paseto.protocol.util import b64, pae

HEADER_LOCAL = b"v4.local."
HEADER_PUBLIC = b"v4.public."

NONCE_SIZE = 32
ENCRYPTION_KEY_LENGTH = 32
AUTHENTICATION_KEY_LENGTH = 32
MAC_SIZE = 32

INFO_ENCRYPTION = b"paseto-encryption-key"
INFO_AUTHENTICATION = b"paseto-auth-key-for-aead"


def encrypt(
    message: bytes, key: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
) -> bytes:
    """PASETO Version4 encrypt function."""

    # verify that key is intended for use with this function
    _verify_key(key, _TYPE_LOCAL)
    raw_key: bytes = _deserialize_key(key)

    # Step 1
    header: bytes = HEADER_LOCAL

    # Step 2
    nonce: bytes = os.urandom(NONCE_SIZE)

    # Step 3
    encryption_key: bytes
    authentication_key: bytes
    nonce2: bytes
    encryption_key, authentication_key, nonce2 = _split_key(raw_key, nonce)

    # Step 4
    ciphertext: bytes = libsodium_wrapper.crypto_stream_xchacha20_xor(
        message=message, nonce=nonce2, key=encryption_key
    )

    # Step 5
    pre_auth: bytes = pae([header, nonce, ciphertext, footer, implicit_assertion])

    # Step 6
    message_authentication_code: bytes = hashlib.blake2b(
        pre_auth, key=authentication_key, digest_size=32
    ).digest()

    # Step 7
    ret: bytes = header + b64(nonce + ciphertext + message_authentication_code)
    if footer:
        ret += b"." + b64(footer)
    return ret


def decrypt(
    message: bytes, key: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
) -> bytes:
    """PASETO Version4 decrypt function."""

    # verify that key is intended for use with this function
    _verify_key(key, _TYPE_LOCAL)
    raw_key: bytes = _deserialize_key(key)

    # Step 1
    check_footer(message, footer)

    # Step 2
    header: bytes = HEADER_LOCAL
    check_header(message, header)

    # Step 3
    decoded: bytes = decode_message(message, len(header))
    nonce: bytes = decoded[:NONCE_SIZE]
    ciphertext: bytes = decoded[NONCE_SIZE:-MAC_SIZE]

    # Step 4
    encryption_key, authentication_key, nonce2 = _split_key(raw_key, nonce)

    # Step 5
    pre_auth: bytes = pae([header, nonce, ciphertext, footer, implicit_assertion])

    # Step 6
    computed_mac: bytes = hashlib.blake2b(
        pre_auth, key=authentication_key, digest_size=MAC_SIZE
    ).digest()

    # Step 7
    mac_in_message: bytes = decoded[-MAC_SIZE:]
    if not hmac.compare_digest(mac_in_message, computed_mac):
        raise InvalidMac("Invalid MAC for given ciphertext")

    # Steps 8 and 9
    return libsodium_wrapper.crypto_stream_xchacha20_xor(
        message=ciphertext, nonce=nonce2, key=encryption_key
    )


def sign(
    message: bytes,
    secret_key: bytes,
    footer: bytes = b"",
    implicit_assertion: bytes = b"",
) -> bytes:
    """Sign message and return token which can then be used with verify()."""

    # verify that key is intended for use with this function
    _verify_key(secret_key, _TYPE_SECRET)
    raw_secret_key: bytes = _deserialize_key(secret_key)

    # Step 1
    header = HEADER_PUBLIC

    # Step 2
    message2 = pae([header, message, footer, implicit_assertion])

    # Step 3
    signature = primitives.sign(message2, raw_secret_key)

    # Step 4
    ret = header + b64(message + signature)
    if footer:
        ret += b"." + b64(footer)

    return ret


def verify(
    signed_message: bytes,
    public_key: bytes,
    footer: bytes = b"",
    implicit_assertion: bytes = b"",
) -> bytes:
    """Verify signature and return message. Raises exception if signature is invalid."""

    # verify that key is intended for use with this function
    _verify_key(public_key, _TYPE_PUBLIC)
    raw_public_key: bytes = _deserialize_key(public_key)

    # Step 1
    check_footer(signed_message, footer)

    # Step 2
    header = HEADER_PUBLIC
    check_header(signed_message, header)

    # Step 3
    raw_inner_message: bytes = decode_message(signed_message, len(header))
    signature = raw_inner_message[-64:]
    message = raw_inner_message[:-64]

    # Step 4
    message2 = pae([header, message, footer, implicit_assertion])

    # Steps 5 and 6
    primitives.verify(signature, message2, raw_public_key)
    return message


def _split_key(key: bytes, nonce: bytes) -> Tuple[bytes, bytes, bytes]:

    hashed: bytes = hashlib.blake2b(
        INFO_ENCRYPTION + nonce, key=key, digest_size=56
    ).digest()
    encryption_key: bytes = hashed[:ENCRYPTION_KEY_LENGTH]
    nonce2: bytes = hashed[ENCRYPTION_KEY_LENGTH:]
    authentication_key: bytes = hashlib.blake2b(
        INFO_AUTHENTICATION + nonce, key=key, digest_size=AUTHENTICATION_KEY_LENGTH
    ).digest()

    return encryption_key, authentication_key, nonce2


def _verify_key(key: bytes, key_type: bytes) -> None:
    if not _generic_verify_key(key, 4, key_type):
        raise InvalidKey


def create_symmetric_key() -> bytes:
    """Return key for use with encrypt() and decrypt()."""
    return _create_symmetric_key(4)


def create_asymmetric_key() -> Tuple[bytes, bytes]:
    """Return key pair for use with sign() and verify()."""
    return _create_asymmetric_key(4)
