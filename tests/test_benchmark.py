""" This module contains benchmark tests intended to guide development of a performant codebase. """
import nacl
import pysodium
import pytest

from paseto.crypto import primitives
from paseto.protocol.version2 import Version2

KEY = b"0" * 32
MESSAGE = b"foo"
FOOTER = b"sample_footer"


@pytest.mark.benchmark(group="encrypt")
def test_encrypt_one(benchmark):
    """Benchmark only encryption."""
    primitives.encrypt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt

    token = benchmark(Version2.encrypt, MESSAGE, KEY, FOOTER)
    plain_text = Version2.decrypt(token, KEY, FOOTER)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="encrypt")
def test_encrypt_two(benchmark):
    """Benchmark only encryption."""
    primitives.encrypt = pysodium.crypto_aead_xchacha20poly1305_ietf_encrypt

    token = benchmark(Version2.encrypt, MESSAGE, KEY, FOOTER)
    plain_text = Version2.decrypt(token, KEY, FOOTER)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="decrypt")
def test_decrypt_one(benchmark):
    """Benchmark only decryption."""
    primitives.decrypt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt

    token = Version2.encrypt(MESSAGE, KEY, FOOTER)
    plain_text = benchmark(Version2.decrypt, token, KEY, FOOTER)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="decrypt")
def test_decrypt_two(benchmark):
    """Benchmark only decryption."""
    primitives.decrypt = pysodium.crypto_aead_xchacha20poly1305_ietf_decrypt

    token = Version2.encrypt(MESSAGE, KEY, FOOTER)
    plain_text = benchmark(Version2.decrypt, token, KEY, FOOTER)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="encrypt_and_decrypt")
def test_encrypt_and_decrypt_one(benchmark):
    """Benchmark encryption and decryption run together."""
    primitives.encrypt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt
    primitives.decrypt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt

    def encrypt_and_decrypt():
        token = Version2.encrypt(MESSAGE, KEY, FOOTER)
        return Version2.decrypt(token, KEY, FOOTER)

    plain_text = benchmark(encrypt_and_decrypt)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="encrypt_and_decrypt")
def test_encrypt_and_decrypt_two(benchmark):
    """Benchmark encryption and decryption run together."""
    primitives.decrypt = pysodium.crypto_aead_xchacha20poly1305_ietf_decrypt
    primitives.encrypt = pysodium.crypto_aead_xchacha20poly1305_ietf_encrypt

    def encrypt_and_decrypt():
        token = Version2.encrypt(MESSAGE, KEY, FOOTER)
        return Version2.decrypt(token, KEY, FOOTER)

    plain_text = benchmark(encrypt_and_decrypt)
    assert plain_text == MESSAGE
