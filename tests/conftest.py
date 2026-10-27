"""This module contains test fixtures."""

import json
import os

import pytest

# vector files that tests load, by get_test_vector() name
USED_TEST_VECTORS: set[str] = {
    "v2",
    "v4",
    "PASERK/k4.local",
    "PASERK/k4.public",
    "PASERK/k4.secret",
}


@pytest.fixture
def get_all_test_vectors() -> dict:
    """Return all used test vectors."""
    return {name: get_test_vector(name) for name in USED_TEST_VECTORS}


def get_test_vector(name: str) -> dict:
    """Return deserialised json.

    Args:
        name: Path of the json file inside the test vector repository, without
            the extension, such as "v4" or "PASERK/k4.local".
    """
    with open(get_test_vector_path(name), encoding="utf-8") as json_file:
        return json.load(json_file)


def get_test_vector_path(name: str) -> str:
    """Return path to json file containing test vectors."""
    return os.path.join(get_test_vector_dir(), f"{name}.json")


def get_test_vector_dir() -> str:
    """Return path to the test vector repository."""
    return os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "submodules",
        "test-vectors",
    )
