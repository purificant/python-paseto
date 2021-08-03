""" This module contains benchmark tests intended to guide development of a performant codebase. """
import pytest

from paseto.protocol.version2 import Version2
from paseto.crypto import primitives

KEY = b"0" * 32
MESSAGE = b"foo"
FOOTER = b"sample_footer"


@pytest.mark.benchmark(group="encrypt")
def test_encrypt_one(benchmark):
    """Benchmark only encryption."""
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt as encrypt
    primitives.encrypt = encrypt

    token = benchmark(Version2.encrypt, MESSAGE, KEY, FOOTER)
    plain_text = Version2.decrypt(token, KEY, FOOTER)
    assert plain_text == MESSAGE

@pytest.mark.benchmark(group="encrypt")
def test_encrypt_two(benchmark):
    """Benchmark only encryption."""
    from pysodium import crypto_aead_xchacha20poly1305_ietf_encrypt as encrypt
    primitives.encrypt = encrypt

    token = benchmark(Version2.encrypt, MESSAGE, KEY, FOOTER)
    plain_text = Version2.decrypt(token, KEY, FOOTER)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="decrypt")
def test_decrypt_one(benchmark):
    """Benchmark only decryption."""
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt as decrypt
    primitives.decrypt = decrypt

    token = Version2.encrypt(MESSAGE, KEY, FOOTER)
    plain_text = benchmark(Version2.decrypt, token, KEY, FOOTER)
    assert plain_text == MESSAGE


@pytest.mark.benchmark(group="decrypt")
def test_decrypt_two(benchmark):
    """Benchmark only decryption."""
    from pysodium import crypto_aead_xchacha20poly1305_ietf_decrypt as decrypt
    primitives.decrypt = decrypt

    token = Version2.encrypt(MESSAGE, KEY, FOOTER)
    plain_text = benchmark(Version2.decrypt, token, KEY, FOOTER)
    assert plain_text == MESSAGE

@pytest.mark.benchmark(group="encrypt_and_decrypt")
def test_encrypt_and_decrypt_one(benchmark):
    """Benchmark encryption and decryption run together."""
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt as encrypt
    primitives.encrypt = encrypt
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt as decrypt
    primitives.decrypt = decrypt

    def encrypt_and_decrypt():
        token = Version2.encrypt(MESSAGE, KEY, FOOTER)
        return Version2.decrypt(token, KEY, FOOTER)

    plain_text = benchmark(encrypt_and_decrypt)
    assert plain_text == MESSAGE

@pytest.mark.benchmark(group="encrypt_and_decrypt")
def test_encrypt_and_decrypt_two(benchmark):
    """Benchmark encryption and decryption run together."""
    from pysodium import crypto_aead_xchacha20poly1305_ietf_decrypt as decrypt
    primitives.decrypt = decrypt
    from pysodium import crypto_aead_xchacha20poly1305_ietf_encrypt as encrypt
    primitives.encrypt = encrypt

    def encrypt_and_decrypt():
        token = Version2.encrypt(MESSAGE, KEY, FOOTER)
        return Version2.decrypt(token, KEY, FOOTER)

    plain_text = benchmark(encrypt_and_decrypt)
    assert plain_text == MESSAGE
