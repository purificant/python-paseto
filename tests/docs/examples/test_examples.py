"""This module tests code examples from documentation."""

import importlib

import pytest


@pytest.mark.parametrize(
    "module_name", [("example1"), ("example2"), ("example3"), ("example4")]
)
def test_examples(module_name: str) -> None:
    """Test examples by running them."""
    importlib.import_module("docs.examples." + module_name)
