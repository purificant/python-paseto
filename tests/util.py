"""This module contains utility functions used in tests."""

import json


def transform_test_case_for_v4_public(test_case: dict) -> tuple:
    """
    Transform and return test cases 4-S-1 .. 4-S-3,
    from decoded json dictionary to a tuple of expected data types.
    """
    # convert strings to bytes
    # remove extra whitespace from default json encoding in python
    return (
        test_case["name"],
        bytes.fromhex(test_case["public-key"]),
        bytes.fromhex(test_case["secret-key"]),
        test_case["token"].encode(),
        json.dumps(test_case["payload"], separators=(",", ":")).encode(),
        test_case["footer"].encode(),
        test_case["implicit-assertion"].encode(),
    )


def transform_test_case_for_v4_local(test_case: dict) -> tuple:
    """
    Transform and return test cases 4-E-1 .. 4-E-9,
    from decoded json dictionary to a tuple of expected data types.
    """
    # convert strings to bytes
    # remove extra whitespace from default json encoding in python
    return (
        test_case["name"],
        bytes.fromhex(test_case["nonce"]),
        bytes.fromhex(test_case["key"]),
        test_case["token"].encode(),
        json.dumps(test_case["payload"], separators=(",", ":")).encode(),
        test_case["footer"].encode(),
        test_case["implicit-assertion"].encode(),
    )


def transform_test_case_for_v2_public(test_case: dict) -> tuple:
    """
    Transform and return test cases 2-S-1 .. 2-S-3,
    from decoded json dictionary to a tuple of expected data types.
    """
    # convert strings to bytes
    # remove extra whitespace from default json encoding in python
    return (
        test_case["name"],
        bytes.fromhex(test_case["public-key"]),
        bytes.fromhex(test_case["secret-key"]),
        test_case["token"].encode(),
        json.dumps(test_case["payload"], separators=(",", ":")).encode(),
        test_case["footer"].encode(),
    )


def transform_test_case_for_v2_local(test_case: dict) -> tuple:
    """
    Transform and return test cases 2-E-1 .. 2-E-9,
    from decoded json dictionary to a tuple of expected data types.
    """
    # convert strings to bytes
    # remove extra whitespace from default json encoding in python
    return (
        test_case["name"],
        bytes.fromhex(test_case["nonce"]),
        bytes.fromhex(test_case["key"]),
        test_case["token"].encode(),
        json.dumps(test_case["payload"], separators=(",", ":")).encode(),
        test_case["footer"].encode(),
    )
