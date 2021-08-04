"""This module contains common building blocks used in several protocol versions."""

import hmac

from paseto.exceptions import InvalidFooter, InvalidHeader
from paseto.protocol.util import b64, b64decode


def check_footer(message: bytes, footer: bytes) -> None:
    """Check that message contains a valid footer."""
    if footer and not hmac.compare_digest(b64(footer), message.split(b".")[-1]):
        raise InvalidFooter("Invalid message footer")


def check_header(message: bytes, header: bytes) -> None:
    """Check that message begins with a valid header."""
    if not message.startswith(header):
        raise InvalidHeader("Invalid message header")


def decode_message(message: bytes, header_length: int) -> bytes:
    """Returns message decoded into raw binary."""
    return b64decode(
        # strip header and remove any footer
        message[header_length:].split(b".")[0]
    )
