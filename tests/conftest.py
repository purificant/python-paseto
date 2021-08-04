"""This module contains test fixtures."""

import json
import os

import pytest


@pytest.fixture
def get_all_test_vectors() -> dict:
    """Return all used test vectors."""
    return {
        "v2": get_test_vector("v2"),
        "v4": get_test_vector("v4"),
    }


@pytest.fixture
def get_test_vectors_v2() -> dict:
    """Return spec for v2 test vectors."""
    return get_test_vector("v2")


def get_test_vector(version: str) -> dict:
    """Return deserialised json."""
    with open(get_test_vector_path(version)) as json_file:
        return json.load(json_file)


def get_test_vector_path(version: str) -> str:
    """Return path to json file containing test vectors."""
    return os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "submodules",
        "test-vectors",
        f"{version}.json",
    )
