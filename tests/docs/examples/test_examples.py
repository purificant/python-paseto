"""This module tests code examples from documentation."""
import importlib


def test_examples() -> None:
    """Test examples by running them."""
    importlib.import_module("docs.examples.example1")
    importlib.import_module("docs.examples.example2")
