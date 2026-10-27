"""This module contains test for version4.py"""

import pytest

from paseto.exceptions import (
    InvalidEncoding,
    InvalidKey,
    InvalidMac,
    InvalidSignature,
)
from paseto.paserk.keys import _create_symmetric_key
from paseto.protocol import version4
from paseto.protocol.util import b64, b64decode
from tests.util import extra_segment_variants, non_canonical_variants


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
    a_slice = token[40:45]
    if a_slice == b"00000":
        a_slice = b"11111"
    else:
        a_slice = b"00000"
    token_with_invalid_mac = token[:40] + a_slice + token[45:]

    with pytest.raises(InvalidMac):
        version4.decrypt(token_with_invalid_mac, key)


def test_wrong_purpose_key() -> None:
    """Test that each function rejects keys meant for another purpose."""
    local_key: bytes = version4.create_symmetric_key()
    public_key, secret_key = version4.create_asymmetric_key()

    with pytest.raises(InvalidKey):
        version4.encrypt(b"foo", public_key)
    with pytest.raises(InvalidKey):
        version4.decrypt(b"v4.local.foo", secret_key)
    with pytest.raises(InvalidKey):
        version4.sign(b"foo", local_key)
    with pytest.raises(InvalidKey):
        version4.verify(b"v4.public.foo", secret_key)


def test_short_local_key() -> None:
    """Test that v4.local keys must be 32 bytes, as Version4.md step 1 requires."""
    short_key: bytes = b"k4.local." + b64(b"0" * 31)

    with pytest.raises(InvalidKey):
        version4.encrypt(b"foo", short_key)
    with pytest.raises(InvalidKey):
        version4.decrypt(b"v4.local.foo", short_key)


def test_decrypt_non_canonical_encoding() -> None:
    """Test that decrypt() rejects tokens whose base64url is not canonical."""
    key: bytes = version4.create_symmetric_key()
    token: bytes = version4.encrypt(b"foo", key)

    for variant in non_canonical_variants(token, version4.HEADER_LOCAL):
        with pytest.raises(InvalidEncoding):
            version4.decrypt(variant, key)


def test_verify_non_canonical_encoding() -> None:
    """Test that verify() rejects tokens whose base64url is not canonical."""
    public_key, secret_key = version4.create_asymmetric_key()
    token: bytes = version4.sign(b"foo", secret_key)

    for variant in non_canonical_variants(token, version4.HEADER_PUBLIC):
        with pytest.raises(InvalidEncoding):
            version4.verify(variant, public_key)


def test_sign_mismatched_secret_key() -> None:
    """Test that sign() refuses a secret key whose public half was swapped.

    Signing one message under two public halves would leak the secret scalar.
    """
    _, secret_key = version4.create_asymmetric_key()
    other_public_key, _ = version4.create_asymmetric_key()
    raw_secret_key: bytes = b64decode(secret_key.removeprefix(b"k4.secret."))
    raw_other_public_key: bytes = b64decode(
        other_public_key.removeprefix(b"k4.public.")
    )
    tampered: bytes = b"k4.secret." + b64(raw_secret_key[:32] + raw_other_public_key)

    with pytest.raises(InvalidKey):
        version4.sign(b"foo", tampered)


def test_verify_invalid_signature() -> None:
    """Test that verify() raises InvalidSignature for a token from another key."""
    _, secret_key = version4.create_asymmetric_key()
    other_public_key, _ = version4.create_asymmetric_key()
    token: bytes = version4.sign(b"foo", secret_key)

    with pytest.raises(InvalidSignature):
        version4.verify(token, other_public_key)


@pytest.mark.parametrize("footer", [b"", b"kid-1"])
def test_decrypt_extra_segment(footer: bytes) -> None:
    """Test that decrypt() rejects tokens with an extra "." segment."""
    key: bytes = version4.create_symmetric_key()
    token: bytes = version4.encrypt(b"foo", key, footer=footer)

    for variant in extra_segment_variants(token=token, footer=footer):
        with pytest.raises(InvalidEncoding):
            version4.decrypt(variant, key, footer=footer)


@pytest.mark.parametrize("footer", [b"", b"kid-1"])
def test_verify_extra_segment(footer: bytes) -> None:
    """Test that verify() rejects tokens with an extra "." segment."""
    public_key, secret_key = version4.create_asymmetric_key()
    token: bytes = version4.sign(b"foo", secret_key, footer=footer)

    for variant in extra_segment_variants(token=token, footer=footer):
        with pytest.raises(InvalidEncoding):
            version4.verify(variant, public_key, footer=footer)
