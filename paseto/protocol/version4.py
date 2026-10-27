"""
This module contains Version4 implementation of the Paseto protocol.

https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md
"""

import hashlib
import hmac
import os

from paseto.crypto import libsodium_wrapper, primitives
from paseto.exceptions import InvalidMac
from paseto.paserk.keys import (
    _TYPE_LOCAL,
    _TYPE_PUBLIC,
    _TYPE_SECRET,
    _create_asymmetric_key,
    _create_symmetric_key,
    _deserialize_key,
)
from paseto.protocol.common import (
    check_header,
    encode_message,
    validate_and_remove_footer,
    verify_signature,
)
from paseto.protocol.util import b64decode, pae

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

    # Step 1: verify that key is intended for use with this function
    raw_key: bytes = _deserialize_key(key, 4, _TYPE_LOCAL)

    # Step 2
    header: bytes = HEADER_LOCAL

    # Step 3
    nonce: bytes = os.urandom(NONCE_SIZE)

    # Step 4
    encryption_key: bytes
    authentication_key: bytes
    nonce2: bytes
    encryption_key, authentication_key, nonce2 = _split_key(raw_key, nonce)

    # Step 5
    ciphertext: bytes = libsodium_wrapper.crypto_stream_xchacha20_xor(
        message=message, nonce=nonce2, key=encryption_key
    )

    # Step 6
    pre_auth: bytes = pae([header, nonce, ciphertext, footer, implicit_assertion])

    # Step 7
    message_authentication_code: bytes = hashlib.blake2b(
        pre_auth, key=authentication_key, digest_size=32
    ).digest()

    # Step 8
    return encode_message(
        header=header,
        payload=nonce + ciphertext + message_authentication_code,
        footer=footer,
    )


def decrypt(
    message: bytes, key: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
) -> bytes:
    """PASETO Version4 decrypt function."""

    # Step 1: verify that key is intended for use with this function
    raw_key: bytes = _deserialize_key(key, 4, _TYPE_LOCAL)

    # Step 2
    message = validate_and_remove_footer(token=message, footer=footer)

    # Step 3
    header: bytes = HEADER_LOCAL
    check_header(message, header)

    # Step 4
    decoded: bytes = b64decode(message[len(header) :])
    nonce: bytes = decoded[:NONCE_SIZE]
    ciphertext: bytes = decoded[NONCE_SIZE:-MAC_SIZE]

    # Step 5
    encryption_key, authentication_key, nonce2 = _split_key(raw_key, nonce)

    # Step 6
    pre_auth: bytes = pae([header, nonce, ciphertext, footer, implicit_assertion])

    # Step 7
    computed_mac: bytes = hashlib.blake2b(
        pre_auth, key=authentication_key, digest_size=MAC_SIZE
    ).digest()

    # Step 8
    mac_in_message: bytes = decoded[-MAC_SIZE:]
    if not hmac.compare_digest(mac_in_message, computed_mac):
        raise InvalidMac("Invalid MAC for given ciphertext")

    # Steps 9 and 10
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

    # Step 1: verify that key is intended for use with this function
    raw_secret_key: bytes = _deserialize_key(secret_key, 4, _TYPE_SECRET)

    # Step 2
    header = HEADER_PUBLIC

    # Step 3
    message2 = pae([header, message, footer, implicit_assertion])

    # Step 4
    signature = primitives.sign(message2, raw_secret_key)

    # Step 5
    return encode_message(header=header, payload=message + signature, footer=footer)


def verify(
    signed_message: bytes,
    public_key: bytes,
    footer: bytes = b"",
    implicit_assertion: bytes = b"",
) -> bytes:
    """Verify signature and return message. Raises exception if signature is invalid."""

    # Step 1: verify that key is intended for use with this function
    raw_public_key: bytes = _deserialize_key(public_key, 4, _TYPE_PUBLIC)

    # Step 2
    signed_message = validate_and_remove_footer(token=signed_message, footer=footer)

    # Step 3
    header = HEADER_PUBLIC
    check_header(signed_message, header)

    # Step 4
    raw_inner_message: bytes = b64decode(signed_message[len(header) :])
    signature = raw_inner_message[-64:]
    message = raw_inner_message[:-64]

    # Step 5
    message2 = pae([header, message, footer, implicit_assertion])

    # Steps 6 and 7
    verify_signature(signature, message2, raw_public_key)
    return message


def _split_key(key: bytes, nonce: bytes) -> tuple[bytes, bytes, bytes]:
    hashed: bytes = hashlib.blake2b(
        INFO_ENCRYPTION + nonce, key=key, digest_size=56
    ).digest()
    encryption_key: bytes = hashed[:ENCRYPTION_KEY_LENGTH]
    nonce2: bytes = hashed[ENCRYPTION_KEY_LENGTH:]
    authentication_key: bytes = hashlib.blake2b(
        INFO_AUTHENTICATION + nonce, key=key, digest_size=AUTHENTICATION_KEY_LENGTH
    ).digest()

    return encryption_key, authentication_key, nonce2


def create_symmetric_key() -> bytes:
    """Return key for use with encrypt() and decrypt()."""
    return _create_symmetric_key(4)


def create_asymmetric_key() -> tuple[bytes, bytes]:
    """Return key pair for use with sign() and verify()."""
    return _create_asymmetric_key(4)
