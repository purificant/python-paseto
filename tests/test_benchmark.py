""" This module contains benchmark tests intended to guide development of a performant codebase. """
import pytest

from paseto.protocol.version2 import Version2

KEY = b"0" * 32
MESSAGE = b"foo"
FOOTER = b"sample_footer"


@pytest.mark.benchmark(group="encrypt")
def test_encrypt(benchmark):
    """Benchmark only encryption."""
    token = benchmark(Version2.encrypt, MESSAGE, KEY, FOOTER)
    plain_text = Version2.decrypt(token, KEY, FOOTER)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="decrypt")
def test_decrypt(benchmark):
    """Benchmark only decryption."""
    token = Version2.encrypt(MESSAGE, KEY, FOOTER)
    plain_text = benchmark(Version2.decrypt, token, KEY, FOOTER)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="encrypt_and_decrypt")
def test_encrypt_and_decrypt(benchmark):
    """Benchmark encryption and decryption run together."""

    def encrypt_and_decrypt():
        token = Version2.encrypt(MESSAGE, KEY, FOOTER)
        return Version2.decrypt(token, KEY, FOOTER)

    plain_text = benchmark(encrypt_and_decrypt)
    assert plain_text == MESSAGE
