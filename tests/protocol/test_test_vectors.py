"""This module performs assertions about data found in test vectors."""

from fnmatch import fnmatch
from pathlib import Path

import pytest

from tests.conftest import USED_TEST_VECTORS, get_test_vector_dir

# vector files this library has no code to run against, as glob patterns
UNSUPPORTED_TEST_VECTORS: dict[str, str] = {
    "v1": "PASETO v1 is not implemented",
    "v3": "PASETO v3 is not implemented",
    "PASERK/k1.*": "PASETO v1 is not implemented",
    "PASERK/k3.*": "PASETO v3 is not implemented",
    "PASERK/k2.*": "v2 takes raw key bytes, not PASERK keys",
    "PASERK/k4.lid": "PASERK key IDs are not implemented",
    "PASERK/k4.pid": "PASERK key IDs are not implemented",
    "PASERK/k4.sid": "PASERK key IDs are not implemented",
    "PASERK/k4.seal": "PASERK key sealing is not implemented",
    "PASERK/k4.local-wrap.pie": "PASERK key wrapping is not implemented",
    "PASERK/k4.secret-wrap.pie": "PASERK key wrapping is not implemented",
    "PASERK/k4.local-pw": "PASERK password wrapping is not implemented",
    "PASERK/k4.secret-pw": "PASERK password wrapping is not implemented",
}


def get_test_vector_names() -> set[str]:
    """Return get_test_vector() names of every json file in the test vector repository."""
    root: Path = Path(get_test_vector_dir())
    return {
        path.relative_to(root).with_suffix("").as_posix()
        for path in root.rglob("*.json")
    }


def test_every_test_vector_is_used_or_unsupported() -> None:
    """Test that each upstream vector file is either run or listed as unsupported.

    A new upstream file fails this until it gets tests or an entry above.
    """
    names: set[str] = get_test_vector_names()
    unsupported: set[str] = {
        name
        for name in names
        if any(fnmatch(name, pattern) for pattern in UNSUPPORTED_TEST_VECTORS)
    }

    assert not USED_TEST_VECTORS & unsupported
    assert names - unsupported == USED_TEST_VECTORS


@pytest.mark.parametrize("pattern", UNSUPPORTED_TEST_VECTORS)
def test_unsupported_test_vector_pattern_matches(pattern: str) -> None:
    """Test that each unsupported pattern still matches an upstream file."""
    assert any(fnmatch(name, pattern) for name in get_test_vector_names())


@pytest.mark.parametrize(
    "name,test_name_startswith,expected_count",
    [
        ("v2", "", 15),
        ("v2", "2-E-", 9),
        ("v2", "2-S-", 3),
        ("v2", "2-F-", 3),
        ("v4", "", 17),
        ("v4", "4-E-", 9),
        ("v4", "4-S-", 3),
        ("v4", "4-F-", 5),
        ("PASERK/k4.local", "", 5),
        ("PASERK/k4.public", "", 4),
        ("PASERK/k4.secret", "", 5),
    ],
)
def test_expected_number_of_test_vectors(
    get_all_test_vectors: dict,
    name: str,
    test_name_startswith: str,
    expected_count: int,
) -> None:
    """Test that official test vector specification matches expectations."""

    assert (
        sum(
            1
            for test_case in get_all_test_vectors[name]["tests"]
            if test_case["name"].startswith(test_name_startswith)
        )
        == expected_count
    )


@pytest.mark.parametrize("name", ["v2", "v4"])
def test_expect_fail_matches_name(get_all_test_vectors: dict, name: str) -> None:
    """Test that "-F-" names mark exactly the expect-fail cases.

    The E and S tests select cases by name prefix, so an expect-fail case under
    an E or S name would be run as a success case.
    """
    for test_case in get_all_test_vectors[name]["tests"]:
        assert test_case["expect-fail"] == ("-F-" in test_case["name"]), test_case[
            "name"
        ]
