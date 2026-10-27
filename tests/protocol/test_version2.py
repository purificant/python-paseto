"""This module contains tests for version2 protocol implementation."""

from collections.abc import Callable

import pytest
from pysodium import crypto_sign_seed_keypair, crypto_sign_SEEDBYTES

from paseto.exceptions import (
    InvalidEncoding,
    InvalidFooter,
    InvalidHeader,
    InvalidKey,
    InvalidMac,
    InvalidSignature,
)
from paseto.protocol import version2, version4
from paseto.protocol.util import b64, b64decode
from tests.util import extra_segment_variants, non_canonical_variants

RAW_PUBLIC_KEY: bytes
RAW_SECRET_KEY: bytes
RAW_PUBLIC_KEY, RAW_SECRET_KEY = crypto_sign_seed_keypair(
    b"\x00" * crypto_sign_SEEDBYTES
)
OTHER_RAW_PUBLIC_KEY: bytes
OTHER_RAW_PUBLIC_KEY, _ = crypto_sign_seed_keypair(b"\x01" * crypto_sign_SEEDBYTES)


@pytest.mark.parametrize("footer", [b"", b"baz"])
def test_encrypt_decrypt(footer: bytes) -> None:
    """Check that decrypt() reverses encrypt()."""
    message = b"foo"
    key = version2.create_symmetric_key()

    token = version2.encrypt(message, key, footer)
    plain_text = version2.decrypt(token, key, footer)
    assert plain_text == message


@pytest.mark.parametrize("footer", [b"", b"some_footer"])
def test_sign_verify(footer: bytes) -> None:
    """Check that verify() reverses sign()."""
    public_key, secret_key = version2.create_asymmetric_key()
    message = b"foo"

    signed = version2.sign(message, secret_key, footer)
    assert version2.verify(signed, public_key, footer) == message


def test_import_symmetric_key() -> None:
    """Test that raw key bytes import to a k2.local key that works."""
    key: bytes = version2.import_symmetric_key(b"0" * 32)

    assert key == b"k2.local." + b64(b"0" * 32)
    assert version2.decrypt(version2.encrypt(b"foo", key), key) == b"foo"


def test_import_asymmetric_keys() -> None:
    """Test that a raw key pair imports to k2 keys, each half on its own."""
    public_key: bytes = version2.import_public_key(RAW_PUBLIC_KEY)
    secret_key: bytes = version2.import_secret_key(RAW_SECRET_KEY)

    assert public_key == b"k2.public." + b64(RAW_PUBLIC_KEY)
    assert secret_key == b"k2.secret." + b64(RAW_SECRET_KEY)
    assert version2.verify(version2.sign(b"foo", secret_key), public_key) == b"foo"


@pytest.mark.parametrize(
    "import_key,raw_key",
    [
        (version2.import_symmetric_key, b""),
        (version2.import_symmetric_key, b"0" * 31),
        (version2.import_public_key, RAW_PUBLIC_KEY + b"0"),
        # seed without the public half
        (version2.import_secret_key, RAW_SECRET_KEY[:32]),
        (version2.import_secret_key, RAW_SECRET_KEY[:32] + OTHER_RAW_PUBLIC_KEY),
    ],
)
def test_import_invalid_key(
    import_key: Callable[[bytes], bytes], raw_key: bytes
) -> None:
    """Test that raw keys of the wrong length or with a swapped public half fail."""
    with pytest.raises(InvalidKey):
        import_key(raw_key)


def test_get_nonce() -> None:
    """Check that nonce can be retrieved."""
    nonce = version2.get_nonce(b"", b"")
    assert len(nonce) == version2.NONCE_SIZE


def test_decrypt_invalid_footer() -> None:
    """Check that exception is raised when footer is not valid during decrypt()."""
    key: bytes = version2.create_symmetric_key()
    with pytest.raises(InvalidFooter):
        version2.decrypt(b"header.message.footer", key, b"some_other_footer")


def test_decrypt_invalid_header() -> None:
    """Check that exception is raised when header is not valid."""
    key: bytes = version2.create_symmetric_key()
    with pytest.raises(InvalidHeader):
        version2.decrypt(b"some_incorrect_header.message.footer", key)


def test_decrypt_invalid_mac() -> None:
    """Test that decrypt() raises InvalidMac for a token from another key."""
    token: bytes = version2.encrypt(b"foo", version2.create_symmetric_key())

    with pytest.raises(InvalidMac):
        version2.decrypt(token, version2.create_symmetric_key())


@pytest.mark.parametrize(
    "length", [0, 6, version2.NONCE_SIZE, version2.NONCE_SIZE + 15]
)
def test_decrypt_truncated(length: int) -> None:
    """Test that decrypt() raises InvalidMac for a body too short for a nonce and tag."""
    token: bytes = version2.HEADER_LOCAL + b64(b"0" * length)

    with pytest.raises(InvalidMac):
        version2.decrypt(token, version2.create_symmetric_key())


def test_wrong_purpose_key() -> None:
    """Test that each function rejects keys meant for another purpose."""
    local_key: bytes = version2.create_symmetric_key()
    public_key, secret_key = version2.create_asymmetric_key()

    with pytest.raises(InvalidKey):
        version2.encrypt(b"foo", public_key)
    with pytest.raises(InvalidKey):
        version2.decrypt(b"v2.local.foo", secret_key)
    with pytest.raises(InvalidKey):
        version2.sign(b"foo", local_key)
    with pytest.raises(InvalidKey):
        version2.verify(b"v2.public.foo", secret_key)


def test_wrong_version_key() -> None:
    """Test that each function rejects keys meant for v4."""
    local_key: bytes = version4.create_symmetric_key()
    public_key, secret_key = version4.create_asymmetric_key()

    with pytest.raises(InvalidKey):
        version2.encrypt(b"foo", local_key)
    with pytest.raises(InvalidKey):
        version2.decrypt(b"v2.local.foo", local_key)
    with pytest.raises(InvalidKey):
        version2.sign(b"foo", secret_key)
    with pytest.raises(InvalidKey):
        version2.verify(b"v2.public.foo", public_key)


def test_raw_key() -> None:
    """Test that each function rejects raw key bytes.

    Raw bytes don't say what the key is for, so a public key could pass as a local
    key and let anyone holding it forge v2.local tokens.
    """
    public_key, secret_key = crypto_sign_seed_keypair(b"\x00" * crypto_sign_SEEDBYTES)

    with pytest.raises(InvalidKey):
        version2.encrypt(b"foo", public_key)
    with pytest.raises(InvalidKey):
        version2.decrypt(b"v2.local.foo", public_key)
    with pytest.raises(InvalidKey):
        version2.sign(b"foo", secret_key)
    with pytest.raises(InvalidKey):
        version2.verify(b"v2.public.foo", public_key)


def test_short_local_key() -> None:
    """Test that v2.local keys must be 32 bytes, as Version2.md step 1 requires."""
    short_key: bytes = b"k2.local." + b64(b"0" * 31)

    with pytest.raises(InvalidKey):
        version2.encrypt(b"foo", short_key)
    with pytest.raises(InvalidKey):
        version2.decrypt(b"v2.local.foo", short_key)


def test_decrypt_non_canonical_encoding() -> None:
    """Test that decrypt() rejects tokens whose base64url is not canonical."""
    key = version2.create_symmetric_key()
    token = version2.encrypt(b"foo", key)

    for variant in non_canonical_variants(token, version2.HEADER_LOCAL):
        with pytest.raises(InvalidEncoding):
            version2.decrypt(variant, key)


def test_verify_non_canonical_encoding() -> None:
    """Test that verify() rejects tokens whose base64url is not canonical."""
    public_key, secret_key = version2.create_asymmetric_key()
    token = version2.sign(b"foo", secret_key)

    for variant in non_canonical_variants(token, version2.HEADER_PUBLIC):
        with pytest.raises(InvalidEncoding):
            version2.verify(variant, public_key)


def test_sign_mismatched_secret_key() -> None:
    """Test that sign() refuses a secret key whose public half was swapped.

    Signing one message under two public halves would leak the secret scalar.
    """
    _, secret_key = version2.create_asymmetric_key()
    other_public_key, _ = version2.create_asymmetric_key()
    raw_secret_key: bytes = b64decode(secret_key.removeprefix(b"k2.secret."))
    raw_other_public_key: bytes = b64decode(
        other_public_key.removeprefix(b"k2.public.")
    )
    tampered: bytes = b"k2.secret." + b64(raw_secret_key[:32] + raw_other_public_key)

    with pytest.raises(InvalidKey):
        version2.sign(b"foo", tampered)


def test_verify_invalid_signature() -> None:
    """Test that verify() raises InvalidSignature for a token from another key."""
    _, secret_key = version2.create_asymmetric_key()
    other_public_key, _ = version2.create_asymmetric_key()
    token = version2.sign(b"foo", secret_key)

    with pytest.raises(InvalidSignature):
        version2.verify(token, other_public_key)


@pytest.mark.parametrize("footer", [b"", b"kid-1"])
def test_decrypt_extra_segment(footer: bytes) -> None:
    """Test that decrypt() rejects tokens with an extra "." segment."""
    key: bytes = version2.create_symmetric_key()
    token: bytes = version2.encrypt(b"foo", key, footer=footer)

    for variant in extra_segment_variants(token=token, footer=footer):
        with pytest.raises(InvalidEncoding):
            version2.decrypt(variant, key, footer=footer)


@pytest.mark.parametrize("footer", [b"", b"kid-1"])
def test_verify_extra_segment(footer: bytes) -> None:
    """Test that verify() rejects tokens with an extra "." segment."""
    public_key, secret_key = version2.create_asymmetric_key()
    token: bytes = version2.sign(b"foo", secret_key, footer=footer)

    for variant in extra_segment_variants(token=token, footer=footer):
        with pytest.raises(InvalidEncoding):
            version2.verify(variant, public_key, footer=footer)
