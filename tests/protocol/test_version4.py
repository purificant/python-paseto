"""This module contains test for version4.py"""

import pytest

from paseto.exceptions import InvalidKey, InvalidMac
from paseto.paserk.keys import _create_symmetric_key
from paseto.protocol import version4
from paseto.protocol.version4 import _verify_key


def test_encrypt_decrypt() -> None:
    """Test that decrypt() reverses encrypt()."""
    message: bytes = b"foo"
    key: bytes = version4.create_symmetric_key()

    token: bytes = version4.encrypt(message, key)
    plain_text: bytes = version4.decrypt(token, key)

    assert plain_text == message


@pytest.mark.parametrize(
    "footer,implicit_assertion", [(b"", b""), (b"some footer", b"some assertion")]
)
def test_sign_verify(footer: bytes, implicit_assertion: bytes) -> None:
    """Check that verify() reverses sign()."""
    public_key, secret_key = version4.create_asymmetric_key()
    message = b"foo"

    signed = version4.sign(message, secret_key, footer, implicit_assertion)
    assert version4.verify(signed, public_key, footer, implicit_assertion) == message


def test_decrypt_invalid_mac() -> None:
    """Test that exception is raised when mac is not valid."""
    message: bytes = b"foo"
    key: bytes = _create_symmetric_key(4, b"0" * 32)

    token: bytes = version4.encrypt(message, key)
    # tamper with mac
    token_with_invalid_mac = token[:40] + b"0" + token[41:]
    with pytest.raises(InvalidMac):
        version4.decrypt(token_with_invalid_mac, key)


def test_verify_key() -> None:
    """Test that exception is raised when key is not verified."""
    with pytest.raises(InvalidKey):
        _verify_key(b"", b"some type")
