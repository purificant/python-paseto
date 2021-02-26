""" This module contains unit tests for util module. """

from typing import List, Tuple

import pytest

from paseto.protocol.util import b64, b64decode, padding_size, pae


# https://tools.ietf.org/html/draft-paragon-paseto-rfc-00#section-2.2.1
def test_pae_reference() -> None:
    """ Test PAE() function against reference values. """

    test_cases: List[Tuple[List[bytes], bytes]] = [
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
    """ Additional tests for PAE(). """

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
    """ Check that exception is raised for invalid input types. """
    with pytest.raises(TypeError):
        pae("")  # type: ignore

    with pytest.raises(TypeError):
        pae(1)  # type: ignore

    with pytest.raises(TypeError):
        pae(())  # type: ignore


# test cases from https://tools.ietf.org/html/rfc4648#section-10 without the padding '='
def test_b64_reference() -> None:
    """ Test b64() with test cases from the base64 RFC. """

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


def test_padding_size() -> None:
    """ Test padding size calculations, including impossible values. """

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
