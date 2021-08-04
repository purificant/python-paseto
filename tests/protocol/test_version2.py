""" This module contains tests for version2 protocol implementation. """

import pytest
from nacl.bindings.crypto_sign import crypto_sign_seed_keypair, crypto_sign_SEEDBYTES

from paseto.exceptions import InvalidFooter, InvalidHeader
from paseto.protocol import version2
from paseto.protocol.util import b64


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


def test_verify_footer_success():
    """Check footer validation."""
    version2.check_footer(b"message." + b64(b"footer"), b"footer")


def test_verify_footer_exception():
    """Check that exception is raised when footer is not valid during footer validation."""
    with pytest.raises(InvalidFooter):
        version2.check_footer(b"some message", b"some footer")


def test_verify_header_success():
    """Check header verification."""
    version2.check_header(b"header.message.footer", b"header")


def test_verify_header_exception():
    """Check that exception is raised when header is not valid during header validation."""
    with pytest.raises(InvalidHeader):
        version2.check_header(b"some_header.message.footer", b"other_header")


@pytest.mark.parametrize(
    "message, header, expected",
    [
        (b"header." + b64(b"message") + b".footer", b"header.", b"message"),
        (
            b"other_header." + b64(b"some_message"),
            b"other_header.",
            b"some_message",
        ),
    ],
)
def test_decode_message(message: bytes, header: bytes, expected: bytes):
    """Check message decoding."""
    assert version2.decode_message(message, len(header)) == expected
