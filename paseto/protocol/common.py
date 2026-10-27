"""This module contains common building blocks used in several protocol versions."""

import hmac

from paseto.crypto import primitives
from paseto.exceptions import InvalidFooter, InvalidHeader, InvalidSignature
from paseto.protocol.util import b64


def check_header(message: bytes, header: bytes) -> None:
    """Check that message begins with a valid header."""
    if not message.startswith(header):
        raise InvalidHeader("Invalid message header")


def verify_signature(signature: bytes, message: bytes, public_key: bytes) -> None:
    """Check that signature is valid for message under public_key.

    Raises:
        InvalidSignature: If the signature does not verify.
    """
    try:
        primitives.verify(signature, message, public_key)
    except ValueError as error:
        # pysodium raises ValueError for a failed check and for wrong input lengths
        raise InvalidSignature("Invalid signature") from error


def encode_message(header: bytes, payload: bytes, footer: bytes) -> bytes:
    """Return header || b64(payload), plus "." || b64(footer) if footer is set."""
    message: bytes = header + b64(payload)
    if footer:
        message += b"." + b64(footer)
    return message


def validate_and_remove_footer(token: bytes, footer: bytes) -> bytes:
    """Return token without "." || b64(footer), after checking that token ends with it.

    Raises:
        InvalidFooter: If footer is set and token does not end with it.
    """
    if not footer:
        return token

    tail: bytes = b"." + b64(footer)
    if not hmac.compare_digest(token[-len(tail) :], tail):
        raise InvalidFooter("Invalid message footer")
    return token[: -len(tail)]
