"""This module contains utility functions necessary for protocol implementation."""

import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from struct import pack

from paseto.exceptions import InvalidEncoding

_BASE64URL_ALPHABET = re.compile(rb"[A-Za-z0-9_-]*")


# specification: https://tools.ietf.org/html/draft-paragon-paseto-rfc-00#section-2.2.1
def pae(pieces: list[bytes]) -> bytes:
    """Applies Pre-Authentication Encoding (PAE) to input."""

    if not isinstance(pieces, list):
        raise TypeError("Expecting a list of bytes-like objects")

    ret = le64(len(pieces))
    for piece in pieces:
        ret += le64(len(piece)) + piece

    return ret


def le64(num: int) -> bytes:
    """Encodes a 64-bit unsigned integer into a little-endian binary string."""
    return pack("<Q", num)


def b64(input_bytes: bytes) -> bytes:
    """Returns base64 encoding.

    Input is encoded using base64url as defined in RFC4648, without "=" padding.
    """
    # https://tools.ietf.org/html/rfc4648#section-4
    # remove padding
    return urlsafe_b64encode(input_bytes).rstrip(b"=")


def b64decode(input_bytes: bytes) -> bytes:
    """Returns base64 decoding by reversing b64().

    Raises:
        InvalidEncoding: If b64() would not produce input_bytes for any input.
    """
    # https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#base64-decoding
    # "=" padding is outside the alphabet, so this also rejects it
    if not _BASE64URL_ALPHABET.fullmatch(input_bytes):
        raise InvalidEncoding("Invalid base64url character")

    try:
        padding: bytes = b"=" * padding_size(len(input_bytes))
    except ValueError as error:
        raise InvalidEncoding("Invalid base64url length") from error

    decoded: bytes = urlsafe_b64decode(input_bytes + padding)
    # stdlib ignores the unused trailing bits, the spec requires them to be zero
    if b64(decoded) != input_bytes:
        raise InvalidEncoding("Nonzero trailing bits in base64url")

    return decoded


def padding_size(num: int) -> int:
    """Calculates base64 padding size as per RFC4648."""
    # according to https://tools.ietf.org/html/rfc4648#section-4
    # only three cases can exist
    mapping = {
        0: 0,  # no padding
        2: 2,  # two padding characters
        3: 1,  # one padding character
    }

    lookup = num % 4

    if lookup not in mapping:
        raise ValueError("Impossible input size, unable to calculate padding")

    return mapping[lookup]
