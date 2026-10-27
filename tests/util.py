"""This module contains utility functions used in tests."""

TransformedTestCaseV4 = tuple[str, bytes, bytes, bytes, bytes, bytes, bytes]
TransformedTestCaseV2 = tuple[str, bytes, bytes, bytes, bytes, bytes]

BASE64URL_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def transform_test_case_for_v4_public(
    test_case: dict,
) -> TransformedTestCaseV4:
    """
    Transform and return test cases 4-S-1 .. 4-S-3,
    from decoded json dictionary to a tuple of expected data types.
    """
    # convert strings to bytes
    return (
        test_case["name"],
        bytes.fromhex(test_case["public-key"]),
        bytes.fromhex(test_case["secret-key"]),
        test_case["token"].encode(),
        test_case["payload"].encode(),
        test_case["footer"].encode(),
        test_case["implicit-assertion"].encode(),
    )


def transform_test_case_for_v4_local(test_case: dict) -> TransformedTestCaseV4:
    """
    Transform and return test cases 4-E-1 .. 4-E-9,
    from decoded json dictionary to a tuple of expected data types.
    """
    # convert strings to bytes
    return (
        test_case["name"],
        bytes.fromhex(test_case["nonce"]),
        bytes.fromhex(test_case["key"]),
        test_case["token"].encode(),
        test_case["payload"].encode(),
        test_case["footer"].encode(),
        test_case["implicit-assertion"].encode(),
    )


def transform_test_case_for_v2_public(test_case: dict) -> TransformedTestCaseV2:
    """
    Transform and return test cases 2-S-1 .. 2-S-3,
    from decoded json dictionary to a tuple of expected data types.
    """
    # convert strings to bytes
    return (
        test_case["name"],
        bytes.fromhex(test_case["public-key"]),
        bytes.fromhex(test_case["secret-key"]),
        test_case["token"].encode(),
        test_case["payload"].encode(),
        test_case["footer"].encode(),
    )


def transform_test_case_for_v2_local(test_case: dict) -> TransformedTestCaseV2:
    """
    Transform and return test cases 2-E-1 .. 2-E-9,
    from decoded json dictionary to a tuple of expected data types.
    """
    # convert strings to bytes
    return (
        test_case["name"],
        bytes.fromhex(test_case["nonce"]),
        bytes.fromhex(test_case["key"]),
        test_case["token"].encode(),
        test_case["payload"].encode(),
        test_case["footer"].encode(),
    )


def non_canonical_variants(token: bytes, header: bytes) -> list[bytes]:
    """Return tokens whose body decodes to the same bytes as token's but isn't canonical.

    The token must have no footer, and its body length must not be a multiple of 4,
    so the last character carries unused bits.
    """
    body: bytes = token.removeprefix(header)
    assert b"." not in body and len(body) % 4, "token does not fit these variants"

    last: int = BASE64URL_ALPHABET.index(body[-1:])
    flipped: bytes = body[:-1] + BASE64URL_ALPHABET[last ^ 1 : (last ^ 1) + 1]
    padded: bytes = body + b"=" * (4 - len(body) % 4)
    junk: bytes = body[:4] + b"!!!!" + body[4:]

    return [header + variant for variant in [flipped, padded, junk]]
