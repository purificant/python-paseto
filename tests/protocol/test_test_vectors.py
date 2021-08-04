"""This module performs assertions about data found in test vectors."""

import pytest


@pytest.mark.parametrize(
    "test_name_startswith,expected_count", [("", 12), ("2-E-", 9), ("2-S-", 3)]
)
def test_expected_number_of_test_vectors(
    get_test_vectors_v2, test_name_startswith: str, expected_count: int
):
    """Test that official test vector specification matches expectations."""

    assert (
        sum(
            1
            for test_case in get_test_vectors_v2["tests"]
            if test_case["name"].startswith(test_name_startswith)
        )
        == expected_count
    )
