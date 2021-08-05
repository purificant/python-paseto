"""This module performs assertions about data found in test vectors."""

import pytest


@pytest.mark.parametrize(
    "version,test_name_startswith,expected_count",
    [
        ("v2", "", 12),
        ("v2", "2-E-", 9),
        ("v2", "2-S-", 3),
        ("v4", "", 12),
        ("v4", "4-E-", 9),
        ("v4", "4-S-", 3),
    ],
)
def test_expected_number_of_test_vectors(
    get_all_test_vectors, version: str, test_name_startswith: str, expected_count: int
) -> None:
    """Test that official test vector specification matches expectations."""

    assert (
        sum(
            1
            for test_case in get_all_test_vectors[version]["tests"]
            if test_case["name"].startswith(test_name_startswith)
        )
        == expected_count
    )
