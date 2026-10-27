"""This module contains unit tests for util module."""

import pytest

from paseto.exceptions import (
    InvalidEncoding,
    InvalidMac,
    InvalidSignature,
    PasetoException,
)
from paseto.protocol.util import b64, b64decode, padding_size, pae


# https://tools.ietf.org/html/draft-paragon-paseto-rfc-00#section-2.2.1
def test_pae_reference() -> None:
    """Test PAE() function against reference values."""

    test_cases: list[tuple[list[bytes], bytes]] = [
        ([], b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        ([b""], b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
        (
            [b"test"],
            b"\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test",
        ),
    ]

    for test_case in test_cases:
        assert pae(test_case[0]) == test_case[1]

    with pytest.raises(TypeError) as exception_info:
        assert pae("test") == ""  # type: ignore
    assert "Expecting a list" in str(exception_info.value)


def test_pae() -> None:
    """Additional tests for PAE()."""

    test_cases = [
        (
            [b"one"],
            b"\x01\x00\x00\x00\x00\x00\x00\x00"
            + b"\x03\x00\x00\x00\x00\x00\x00\x00one",
        ),
        (
            [b"one", b"two"],
            b"\x02\x00\x00\x00\x00\x00\x00\x00"
            + b"\x03\x00\x00\x00\x00\x00\x00\x00one"
            + b"\x03\x00\x00\x00\x00\x00\x00\x00two",
        ),
        (
            [b"one", b"two", b"three"],
            b"\x03\x00\x00\x00\x00\x00\x00\x00"
            + b"\x03\x00\x00\x00\x00\x00\x00\x00one"
            + b"\x03\x00\x00\x00\x00\x00\x00\x00two"
            + b"\x05\x00\x00\x00\x00\x00\x00\x00three",
        ),
        (
            [b"one", b"two", b"three", b"four"],
            b"\x04\x00\x00\x00\x00\x00\x00\x00"
            + b"\x03\x00\x00\x00\x00\x00\x00\x00one"
            + b"\x03\x00\x00\x00\x00\x00\x00\x00two"
            + b"\x05\x00\x00\x00\x00\x00\x00\x00three"
            + b"\x04\x00\x00\x00\x00\x00\x00\x00four",
        ),
        (
            [b"one", b"two", b"three", b"four", b"five"],
            b"\x05\x00\x00\x00\x00\x00\x00\x00"
            + b"\x03\x00\x00\x00\x00\x00\x00\x00one"
            + b"\x03\x00\x00\x00\x00\x00\x00\x00two"
            + b"\x05\x00\x00\x00\x00\x00\x00\x00three"
            + b"\x04\x00\x00\x00\x00\x00\x00\x00four"
            + b"\x04\x00\x00\x00\x00\x00\x00\x00five",
        ),
    ]

    for test_case in test_cases:
        assert pae(test_case[0]) == test_case[1]


def test_pae_input_type() -> None:
    """Check that exception is raised for invalid input types."""
    with pytest.raises(TypeError):
        pae("")  # type: ignore

    with pytest.raises(TypeError):
        pae(1)  # type: ignore

    with pytest.raises(TypeError):
        pae(())  # type: ignore


# test cases from https://tools.ietf.org/html/rfc4648#section-10 without the padding '='
def test_b64_reference() -> None:
    """Test b64() with test cases from the base64 RFC."""

    test_cases = [
        (b"", b""),
        (b"f", b"Zg"),
        (b"fo", b"Zm8"),
        (b"foo", b"Zm9v"),
        (b"foob", b"Zm9vYg"),
        (b"fooba", b"Zm9vYmE"),
        (b"foobar", b"Zm9vYmFy"),
    ]

    for test_case in test_cases:
        assert b64(test_case[0]) == test_case[1]
        assert b64decode(test_case[1]) == test_case[0]


# https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#base64-decoding
@pytest.mark.parametrize(
    "encoded",
    [
        b"Zh",  # nonzero trailing bits, b64(b"f") is b"Zg"
        b"Zm9vYh",  # nonzero trailing bits, b64(b"foob") is b"Zm9vYg"
        b"Zm9vYmF",  # nonzero trailing bits, b64(b"fooba") is b"Zm9vYmE"
        b"Zg==",  # padding
        b"Zm8=",  # padding
        b"Zm9vY",  # impossible length
        b"Zm9v!",  # character outside the alphabet
        b"Zm9v\n",  # trailing newline
        b"Zm 9v",  # whitespace
        b"+/8",  # standard alphabet, b64(b"\xfb\xff") is b"-_8"
    ],
)
def test_b64decode_non_canonical(encoded: bytes) -> None:
    """Test that b64decode() rejects anything b64() would not produce."""
    with pytest.raises(InvalidEncoding):
        b64decode(encoded)


@pytest.mark.parametrize("exception", [InvalidEncoding, InvalidMac, InvalidSignature])
def test_value_error_hierarchy(exception: type[Exception]) -> None:
    """Test that exceptions replacing a ValueError are caught as either type."""
    assert issubclass(exception, PasetoException)
    assert issubclass(exception, ValueError)


def test_padding_size() -> None:
    """Test padding size calculations, including impossible values."""

    test_cases = [
        (0, 0),
        (2, 2),
        (3, 1),
        (4, 0),
        (6, 2),
        (7, 1),
        (8, 0),
        (10, 2),
        (11, 1),
        (12, 0),
    ]

    for test_case in test_cases:
        assert padding_size(test_case[0]) == test_case[1]

    with pytest.raises(ValueError):
        assert padding_size(1)

    with pytest.raises(ValueError):
        assert padding_size(5)

    with pytest.raises(ValueError):
        assert padding_size(9)

    with pytest.raises(ValueError):
        assert padding_size(13)
