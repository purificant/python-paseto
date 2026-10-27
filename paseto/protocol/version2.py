"""
This module contains Version2 implementation of the Paseto protocol.

https://github.com/paseto-standard/paseto-spec/blob/eca0db880a31b4399aaa30ef14fca646afb21150/docs/01-Protocol-Versions/Version2.md
"""

import hashlib
import os

from paseto.crypto import primitives
from paseto.exceptions import InvalidMac
from paseto.paserk.keys import (
    _TYPE_LOCAL,
    _TYPE_PUBLIC,
    _TYPE_SECRET,
    _create_asymmetric_key,
    _create_symmetric_key,
    _deserialize_key,
    _serialize_key,
)
from paseto.protocol.common import (
    check_header,
    encode_message,
    validate_and_remove_footer,
    verify_signature,
)

from .util import b64decode, pae

HEADER_LOCAL = b"v2.local."
HEADER_PUBLIC = b"v2.public."
NONCE_SIZE = 24


def encrypt(message: bytes, key: bytes, footer: bytes = b"") -> bytes:
    """Encrypt message into a v2.local token with a k2.local key."""

    # Given a message "m", key "k", and optional footer "f".

    # 1.  Before encrypting, first assert that the key being used is intended
    #        for use with "v2.local" tokens, and has a length of 256 bits (32 bytes).
    #        See Algorithm Lucidity for more information.
    raw_key: bytes = _deserialize_key(key=key, version=2, key_type=_TYPE_LOCAL)

    # 2.  Set header "h" to "v2.local."
    #        Note: This includes the trailing period.
    header = HEADER_LOCAL

    # 3.  Generate 24 random bytes from the OS's CSPRNG, "b".
    random_bytes = os.urandom(NONCE_SIZE)

    # 4.  Calculate BLAKE2b of the message "m" with "b" as the key,
    #        with an output length of 24.  This will be our nonce, "n".
    #
    #        *  This step is to ensure that an RNG failure does not result in
    #           a nonce-misuse condition that breaks the security of our
    #           stream cipher.
    nonce = get_nonce(message, random_bytes)

    # 5.  Pack "h", "n", and "f" together (in that order) using PAE.
    #        We'll call this "preAuth".
    pre_auth = pae([header, nonce, footer])

    # 6.  Encrypt the message using XChaCha20-Poly1305, using an AEAD
    #        interface such as the one provided in libsodium.
    cipher_text = primitives.encrypt(message, pre_auth, nonce, raw_key)

    # 7.  If "f" is:
    #
    #        *  Empty: return h || base64url(n || c)
    #
    #        *  Non-empty: return h || base64url(n || c) || "." || base64url(f)
    #
    #        *  ...where || means "concatenate"
    #
    #        *  Note: "base64url()" means Base64url from RFC 4648 without "="
    #           padding.
    return encode_message(header=header, payload=nonce + cipher_text, footer=footer)


def decrypt(message: bytes, key: bytes, footer: bytes = b"") -> bytes:
    """Decrypt a v2.local token with a k2.local key and return its message."""

    # Given a message "m", key "k", and optional footer "f".

    # 1.  Before decrypting, first assert that the key being used is intended
    #        for use with "v2.local" tokens, and has a length of 256 bits (32 bytes).
    #        See Algorithm Lucidity for more information.
    raw_key: bytes = _deserialize_key(key=key, version=2, key_type=_TYPE_LOCAL)

    # 2.  If "f" is not empty, implementations MAY verify that the value
    #        appended to the token matches some expected string "f", provided
    #        they do so using a constant-time string compare function.
    message = validate_and_remove_footer(token=message, footer=footer)

    # 3.  Verify that the message begins with "v2.local.", otherwise throw
    #        an exception.  This constant will be referred to as "h".
    #        Note: This includes the trailing period.
    header = HEADER_LOCAL
    check_header(message, header)

    # 4.  Decode the payload ("m" sans "h", "f", and the optional trailing
    #        period between "m" and "f") from base64url to raw binary.  Set:
    #
    #        *  "n" to the leftmost 24 bytes
    #        *  "c" to the middle remainder of the payload, excluding "n".
    raw_inner_message = b64decode(message[len(header) :])

    nonce = raw_inner_message[:NONCE_SIZE]
    cipher_text = raw_inner_message[NONCE_SIZE:]

    # 5.  Pack "h", "n", and "f" together (in that order) using PAE.
    #        We'll call this "preAuth"
    pre_auth = pae([header, nonce, footer])

    # 6.  Decrypt "c" using "XChaCha20-Poly1305", store the result in "p".
    # 7.  If decryption failed, throw an exception.  Otherwise, return "p".
    try:
        return primitives.decrypt(cipher_text, pre_auth, nonce, raw_key)
    except ValueError as error:
        # pysodium raises ValueError for a failed check and for a body too short
        # to hold a nonce and tag
        raise InvalidMac("Invalid MAC for given ciphertext") from error


def sign(message: bytes, secret_key: bytes, footer: bytes = b"") -> bytes:
    """Sign message into a v2.public token with a k2.secret key."""

    # Given a message "m", Ed25519 secret key "sk", and optional footer "f"
    #    (which defaults to empty string):

    # 1.  Before signing, first assert that the key being used is intended for
    #        use with "v2.public" tokens, and is the secret key of the intended
    #        keypair.
    #        See Algorithm Lucidity for more information.
    raw_secret_key: bytes = _deserialize_key(
        key=secret_key, version=2, key_type=_TYPE_SECRET
    )

    # 2.  Set "h" to "v2.public."
    #        Note: This includes the trailing period.
    header = HEADER_PUBLIC

    # 3.  Pack "h", "m", and "f" together using PAE (pre-authentication encoding).
    #        We'll call this "m2".
    message2 = pae([header, message, footer])

    # 4.  Sign "m2" using Ed25519 "sk".  We'll call this "sig".
    signature = primitives.sign(message2, raw_secret_key)

    # 5.  If "f" is:
    #
    #        *  Empty: return h || base64url(m || sig)
    #
    #        *  Non-empty: return h || base64url(m || sig) || "." || base64url(f)
    #
    #        *  ...where || means "concatenate"
    #
    #        *  Note: "base64url()" means Base64url from RFC 4648 without "="
    #           padding.
    return encode_message(header=header, payload=message + signature, footer=footer)


def verify(signed_message: bytes, public_key: bytes, footer: bytes = b"") -> bytes:
    """Verify a v2.public token with a k2.public key and return its message."""

    # Given a signed message "sm", public key "pk", and optional footer "f"
    #    (which defaults to empty string):

    # 1.  Before verifying, first assert that the key being used is intended
    #        for use with "v2.public" tokens, and is the public key of the
    #        intended keypair.
    #        See Algorithm Lucidity for more information.
    raw_public_key: bytes = _deserialize_key(
        key=public_key, version=2, key_type=_TYPE_PUBLIC
    )

    # 2.  If "f" is not empty, implementations MAY verify that the value
    #        appended to the token matches some expected string "f", provided
    #        they do so using a constant-time string compare function.
    signed_message = validate_and_remove_footer(token=signed_message, footer=footer)

    # 3.  Verify that the message begins with "v2.public.", otherwise throw
    #        an exception.  This constant will be referred to as "h".
    #        Note: This includes the trailing period.
    header = HEADER_PUBLIC
    check_header(signed_message, header)

    # 4.  Decode the payload ("sm" sans "h", "f", and the optional trailing
    #        period between "m" and "f") from base64url to raw binary.  Set:
    #
    #        *  "s" to the rightmost 64 bytes
    #
    #        *  "m" to the leftmost remainder of the payload, excluding "s"
    raw_inner_message = b64decode(signed_message[len(header) :])

    signature = raw_inner_message[-64:]
    message = raw_inner_message[:-64]

    # 5.  Pack "h", "m", and "f" together using PAE.
    #        We'll call this "m2".
    message2 = pae([header, message, footer])

    # 6.  Use Ed25519 to verify that the signature is valid for the message:
    # 7.  If the signature is valid, return "m".  Otherwise, throw an exception.
    verify_signature(signature, message2, raw_public_key)
    return message


def get_nonce(message: bytes, random_bytes: bytes) -> bytes:
    """Return nonce per Version2 specification."""
    return hashlib.blake2b(message, key=random_bytes, digest_size=NONCE_SIZE).digest()


def create_symmetric_key() -> bytes:
    """Return key for use with encrypt() and decrypt()."""
    return _create_symmetric_key(version=2)


def create_asymmetric_key() -> tuple[bytes, bytes]:
    """Return key pair for use with sign() and verify()."""
    return _create_asymmetric_key(version=2)


def import_symmetric_key(raw_key: bytes) -> bytes:
    """Return key for use with encrypt() and decrypt() from 32 raw key bytes.

    Raises:
        InvalidKey: If raw_key is not a valid key.
    """
    return _serialize_key(version=2, key_type=_TYPE_LOCAL, raw_key=raw_key)


def import_public_key(raw_public_key: bytes) -> bytes:
    """Return key for use with verify() from a raw 32-byte Ed25519 public key.

    Raises:
        InvalidKey: If raw_public_key is not a valid key.
    """
    return _serialize_key(version=2, key_type=_TYPE_PUBLIC, raw_key=raw_public_key)


def import_secret_key(raw_secret_key: bytes) -> bytes:
    """Return key for use with sign() from a raw Ed25519 secret key.

    Args:
        raw_secret_key: 64 bytes, the seed followed by the public key, as libsodium
            stores it.

    Raises:
        InvalidKey: If raw_secret_key is not a valid key.
    """
    return _serialize_key(version=2, key_type=_TYPE_SECRET, raw_key=raw_secret_key)


# backwards compatibility, do not use this class
# pylint: disable=too-few-public-methods
class Version2:
    """Version2 implementation of the Paseto protocol."""

    HEADER_LOCAL = HEADER_LOCAL
    HEADER_PUBLIC = HEADER_PUBLIC
    NONCE_SIZE = NONCE_SIZE
    encrypt = staticmethod(encrypt)
    decrypt = staticmethod(decrypt)
    sign = staticmethod(sign)
    verify = staticmethod(verify)
    get_nonce = staticmethod(get_nonce)
    check_header = staticmethod(check_header)
