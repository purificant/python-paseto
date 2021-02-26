from base64 import urlsafe_b64decode, urlsafe_b64encode
from struct import pack
from typing import List


# specification: https://tools.ietf.org/html/draft-paragon-paseto-rfc-00#section-2.2.1
def pae(pieces: List[bytes]) -> bytes:

    if not isinstance(pieces, List):
        raise TypeError("Expecting a list of bytes-like objects")

    ret = le64(len(pieces))
    for piece in pieces:
        ret += le64(len(piece)) + piece

    return ret


def le64(num: int) -> bytes:
    return pack("<Q", num)


def b64(b: bytes) -> bytes:
    # https://tools.ietf.org/html/rfc4648#section-4
    # remove padding
    return urlsafe_b64encode(b).rstrip(b"=")


def b64decode(b: bytes) -> bytes:
    return urlsafe_b64decode(b + b"=" * padding_size(len(b)))


def padding_size(n: int) -> int:
    # according to https://tools.ietf.org/html/rfc4648#section-4
    # only three cases can exist
    mapping = {
        0: 0,  # no padding
        2: 2,  # two padding characters
        3: 1,  # one padding character
    }

    lookup = n % 4

    if lookup not in mapping:
        raise ValueError("Impossible input size, unable to calculate padding")

    return mapping[lookup]
