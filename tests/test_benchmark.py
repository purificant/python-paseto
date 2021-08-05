""" This module contains benchmark tests intended to guide development of a performant codebase. """

import hashlib

import nacl.bindings
import pysodium
import pytest

from paseto.crypto import primitives
from paseto.protocol import version2

KEY = b"0" * 32
MESSAGE = b"foo"
FOOTER = b"sample_footer"


@pytest.mark.benchmark(group="encrypt")
def test_encrypt_one(benchmark):
    """Benchmark only encryption."""
    primitives.encrypt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt

    token = benchmark(version2.encrypt, MESSAGE, KEY, FOOTER)
    plain_text = version2.decrypt(token, KEY, FOOTER)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="encrypt")
def test_encrypt_two(benchmark):
    """Benchmark only encryption."""
    primitives.encrypt = pysodium.crypto_aead_xchacha20poly1305_ietf_encrypt

    token = benchmark(version2.encrypt, MESSAGE, KEY, FOOTER)
    plain_text = version2.decrypt(token, KEY, FOOTER)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="decrypt")
def test_decrypt_one(benchmark):
    """Benchmark only decryption."""
    primitives.decrypt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt

    token = version2.encrypt(MESSAGE, KEY, FOOTER)
    plain_text = benchmark(version2.decrypt, token, KEY, FOOTER)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="decrypt")
def test_decrypt_two(benchmark):
    """Benchmark only decryption."""
    primitives.decrypt = pysodium.crypto_aead_xchacha20poly1305_ietf_decrypt

    token = version2.encrypt(MESSAGE, KEY, FOOTER)
    plain_text = benchmark(version2.decrypt, token, KEY, FOOTER)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="encrypt_and_decrypt")
def test_encrypt_and_decrypt_one(benchmark):
    """Benchmark encryption and decryption run together."""
    primitives.encrypt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt
    primitives.decrypt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt

    def encrypt_and_decrypt():
        token = version2.encrypt(MESSAGE, KEY, FOOTER)
        return version2.decrypt(token, KEY, FOOTER)

    plain_text = benchmark(encrypt_and_decrypt)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="encrypt_and_decrypt")
def test_encrypt_and_decrypt_two(benchmark):
    """Benchmark encryption and decryption run together."""
    primitives.decrypt = pysodium.crypto_aead_xchacha20poly1305_ietf_decrypt
    primitives.encrypt = pysodium.crypto_aead_xchacha20poly1305_ietf_encrypt

    def encrypt_and_decrypt():
        token = version2.encrypt(MESSAGE, KEY, FOOTER)
        return version2.decrypt(token, KEY, FOOTER)

    plain_text = benchmark(encrypt_and_decrypt)
    assert plain_text == MESSAGE


def test_hash_functions():
    """Test that hash functions produce the same digest."""
    assert (
        pysodium.crypto_generichash(MESSAGE, KEY)
        == hashlib.blake2b(MESSAGE, key=KEY, digest_size=32).digest()
    )


@pytest.mark.benchmark(group="hash")
def test_hash_one(benchmark):
    """Benchmark hash function."""

    def hash_one():
        return pysodium.crypto_generichash(MESSAGE, KEY)

    benchmark(hash_one)


@pytest.mark.benchmark(group="hash")
def test_hash_two(benchmark):
    """Benchmark hash function."""

    def hash_two():
        return hashlib.blake2b(MESSAGE, key=KEY, digest_size=32).digest()

    benchmark(hash_two)
