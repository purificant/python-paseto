""" This module exports third party primitives. """

# from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt as decrypt
# from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt as encrypt
from pysodium import crypto_aead_xchacha20poly1305_ietf_decrypt as decrypt
from pysodium import crypto_aead_xchacha20poly1305_ietf_encrypt as encrypt
from pysodium import crypto_sign_detached as sign
from pysodium import crypto_sign_verify_detached as verify

# from libsodium import sign, verify, decrypt, encrypt

__all__ = ["encrypt", "decrypt", "sign", "verify"]
