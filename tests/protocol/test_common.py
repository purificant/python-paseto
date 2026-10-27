"""This module contains tests for common building blocks used in several protocol versions."""

import pytest

from paseto.exceptions import InvalidFooter, InvalidHeader
from paseto.protocol.common import (
    check_header,
    encode_message,
    validate_and_remove_footer,
)
from paseto.protocol.util import b64


def test_verify_header_success() -> None:
    """Check header verification."""
    check_header(b"header.message.footer", b"header")


def test_verify_header_exception() -> None:
    """Check that exception is raised when header is not valid during header validation."""
    with pytest.raises(InvalidHeader):
        check_header(b"some_header.message.footer", b"other_header")


@pytest.mark.parametrize("footer", [b"", b"footer"])
def test_validate_and_remove_footer(footer: bytes) -> None:
    """Test that validate_and_remove_footer() removes what encode_message() appends."""
    token: bytes = encode_message(header=b"header.", payload=b"message", footer=footer)
    expected: bytes = b"header." + b64(b"message")

    assert validate_and_remove_footer(token=token, footer=footer) == expected


@pytest.mark.parametrize(
    "token",
    [
        b"header." + b64(b"message"),
        b"header." + b64(b"message") + b"." + b64(b"other"),
        b"header." + b64(b"message") + b"." + b64(b"footer") + b".junk",
        b64(b"footer"),
    ],
)
def test_validate_and_remove_footer_invalid(token: bytes) -> None:
    """Test that validate_and_remove_footer() rejects tokens not ending in the footer."""
    with pytest.raises(InvalidFooter):
        validate_and_remove_footer(token=token, footer=b"footer")
