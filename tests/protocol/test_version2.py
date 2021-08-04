""" This module contains tests for version2 protocol implementation. """

import pytest
from pysodium import crypto_sign_seed_keypair, crypto_sign_SEEDBYTES

from paseto.exceptions import InvalidFooter, InvalidHeader
from paseto.protocol import version2


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
    keys = crypto_sign_seed_keypair(b"\x00" * crypto_sign_SEEDBYTES)

    message = b"foo"
    public_key = keys[0]
    secret_key = keys[1]

    signed = version2.sign(message, secret_key, footer)
    assert version2.verify(signed, public_key, footer) == message


def test_get_nonce():
    """Check that nonce can be retrieved."""
    nonce = version2.get_nonce(b"", b"")
    assert len(nonce) == version2.NONCE_SIZE


def test_decrypt_invalid_footer():
    """Check that exception is raised when footer is not valid during decrypt()."""
    with pytest.raises(InvalidFooter):
        version2.decrypt(b"header.message.footer", b"a key", b"some_other_footer")


def test_decrypt_invalid_header():
    """Check that exception is raised when header is not valid."""
    with pytest.raises(InvalidHeader):
        version2.decrypt(b"some_incorrect_header.message.footer", b"a key")
