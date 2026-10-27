"""This module contains tests for version2 protocol implementation."""

import pytest
from pysodium import crypto_sign_seed_keypair, crypto_sign_SEEDBYTES

from paseto.exceptions import (
    InvalidEncoding,
    InvalidFooter,
    InvalidHeader,
    InvalidSignature,
)
from paseto.protocol import version2
from tests.util import non_canonical_variants


@pytest.mark.parametrize("footer", [b"", b"baz"])
def test_encrypt_decrypt(footer: bytes) -> None:
    """Check that decrypt() reverses encrypt()."""
    message = b"foo"
    key = b"0" * 32

    token = version2.encrypt(message, key, footer)
    plain_text = version2.decrypt(token, key, footer)
    assert plain_text == message


@pytest.mark.parametrize("footer", [b"", b"some_footer"])
def test_sign_verify(footer: bytes) -> None:
    """Check that verify() reverses sign()."""
    public_key, secret_key = crypto_sign_seed_keypair(b"\x00" * crypto_sign_SEEDBYTES)
    message = b"foo"

    signed = version2.sign(message, secret_key, footer)
    assert version2.verify(signed, public_key, footer) == message


def test_get_nonce() -> None:
    """Check that nonce can be retrieved."""
    nonce = version2.get_nonce(b"", b"")
    assert len(nonce) == version2.NONCE_SIZE


def test_decrypt_invalid_footer() -> None:
    """Check that exception is raised when footer is not valid during decrypt()."""
    with pytest.raises(InvalidFooter):
        version2.decrypt(b"header.message.footer", b"a key", b"some_other_footer")


def test_decrypt_invalid_header() -> None:
    """Check that exception is raised when header is not valid."""
    with pytest.raises(InvalidHeader):
        version2.decrypt(b"some_incorrect_header.message.footer", b"a key")


def test_decrypt_non_canonical_encoding() -> None:
    """Test that decrypt() rejects tokens whose base64url is not canonical."""
    key = b"0" * 32
    token = version2.encrypt(b"foo", key)

    for variant in non_canonical_variants(token, version2.HEADER_LOCAL):
        with pytest.raises(InvalidEncoding):
            version2.decrypt(variant, key)


def test_verify_non_canonical_encoding() -> None:
    """Test that verify() rejects tokens whose base64url is not canonical."""
    public_key, secret_key = crypto_sign_seed_keypair(b"\x00" * crypto_sign_SEEDBYTES)
    token = version2.sign(b"foo", secret_key)

    for variant in non_canonical_variants(token, version2.HEADER_PUBLIC):
        with pytest.raises(InvalidEncoding):
            version2.verify(variant, public_key)


def test_verify_invalid_signature() -> None:
    """Test that verify() raises InvalidSignature for a token from another key."""
    _, secret_key = crypto_sign_seed_keypair(b"\x00" * crypto_sign_SEEDBYTES)
    other_public_key, _ = crypto_sign_seed_keypair(b"\x01" * crypto_sign_SEEDBYTES)
    token = version2.sign(b"foo", secret_key)

    with pytest.raises(InvalidSignature):
        version2.verify(token, other_public_key)
