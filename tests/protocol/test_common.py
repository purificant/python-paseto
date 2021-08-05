"""This module contains tests for common building blocks used in several protocol versions."""

import pytest

from paseto.exceptions import InvalidFooter, InvalidHeader
from paseto.protocol.common import check_footer, check_header, decode_message
from paseto.protocol.util import b64


def test_verify_footer_success() -> None:
    """Check footer validation."""
    check_footer(b"message." + b64(b"footer"), b"footer")


def test_verify_footer_exception() -> None:
    """Check that exception is raised when footer is not valid during footer validation."""
    with pytest.raises(InvalidFooter):
        check_footer(b"some message", b"some footer")


def test_verify_header_success() -> None:
    """Check header verification."""
    check_header(b"header.message.footer", b"header")


def test_verify_header_exception() -> None:
    """Check that exception is raised when header is not valid during header validation."""
    with pytest.raises(InvalidHeader):
        check_header(b"some_header.message.footer", b"other_header")


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
def test_decode_message(message: bytes, header: bytes, expected: bytes) -> None:
    """Check message decoding."""
    assert decode_message(message, len(header)) == expected
