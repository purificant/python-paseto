# cython: language_level=3

# Cython wrapper for libsodium

# libsodium C API definitions for Cython

cdef extern from "../../submodules/libsodium/src/libsodium/include/sodium/crypto_aead_xchacha20poly1305.h":
    int crypto_aead_xchacha20poly1305_ietf_encrypt(
            unsigned char *c,
            unsigned long long *clen_p,
            const unsigned char *m,
            unsigned long long mlen,
            const unsigned char *ad,
            unsigned long long adlen,
            const unsigned char *nsec,
            const unsigned char *npub,
            const unsigned char *k
    )

    int crypto_aead_xchacha20poly1305_ietf_decrypt(
            unsigned char *m,
            unsigned long long *mlen_p,
            unsigned char *nsec,
            const unsigned char *c,
            unsigned long long clen,
            const unsigned char *ad,
            unsigned long long adlen,
            const unsigned char *npub,
            const unsigned char *k)


cdef extern from "../../submodules/libsodium/src/libsodium/include/sodium/crypto_sign.h":
    int crypto_sign_detached(
            unsigned char *sig,
            unsigned long long *siglen_p,
            const unsigned char *m,
            unsigned long long mlen,
            const unsigned char *sk
    )

    int crypto_sign_verify_detached(
            const unsigned char *sig,
            const unsigned char *m,
            unsigned long long mlen,
            const unsigned char *pk
    )

cdef extern from "../../submodules/libsodium/src/libsodium/include/sodium/crypto_sign.h":
    size_t crypto_sign_bytes()
    size_t crypto_sign_secretkeybytes()
    size_t crypto_sign_publickeybytes()

cdef extern from "../../submodules/libsodium/src/libsodium/include/sodium/crypto_aead_xchacha20poly1305.h":
    size_t crypto_aead_xchacha20poly1305_ietf_abytes()
    size_t crypto_aead_xchacha20poly1305_ietf_npubbytes()
    size_t crypto_aead_xchacha20poly1305_ietf_keybytes()

NONCE_SIZE = 'Invalid nonce length'
KEY_SIZE = 'Invalid key length'
PUBLIC_KEY_SIZE = 'Invalid public key length'
SECRET_KEY_SIZE = 'Invalid secret key length'
SIGNATURE_SIZE = 'Invalid signature length'

# https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
def encrypt(message: bytes, ad: bytes, nonce: bytes, key: bytes):

    check_nonce_size(len(nonce))
    check_key_size(len(key))

    cipher_text = b' ' * (len(message) + crypto_aead_xchacha20poly1305_ietf_abytes())

    cdef unsigned long long ciphertext_length = len(cipher_text)

    crypto_aead_xchacha20poly1305_ietf_encrypt(cipher_text, &ciphertext_length, message, len(message), ad, len(ad), NULL, nonce, key)

    return cipher_text

def decrypt(cipher_text: bytes, aad: bytes, nonce: bytes, key: bytes):

    check_nonce_size(len(nonce))
    check_key_size(len(key))

    cdef size_t cipher_text_length = len(cipher_text)

    message = b' ' * (cipher_text_length - crypto_aead_xchacha20poly1305_ietf_abytes())
    cdef unsigned long long message_length

    res = crypto_aead_xchacha20poly1305_ietf_decrypt(message, &message_length, NULL, cipher_text, cipher_text_length, aad, len(aad), nonce, key)

    if res != 0:
        raise Exception('Decryption failed')

    return message

def sign(message: bytes, secret_key: bytes):

    check_secret_key_size(len(secret_key))

    signature = b' ' * crypto_sign_bytes()
    cdef unsigned long long signature_length = len(signature)

    crypto_sign_detached(signature, &signature_length, message, len(message), secret_key)

    return signature

def verify(signature: bytes, message: bytes, public_key: bytes):

    check_signature_size(len(signature))
    check_public_key_size(len(public_key))

    crypto_sign_verify_detached(signature, message, len(message), public_key)

def check_size(actual_size, expected_size, exception_message):
    """ Helper method to verify length of method call arguments """
    if actual_size != expected_size:
        raise ValueError(exception_message)

def check_key_size(key_length: int):
    check_size(key_length, crypto_aead_xchacha20poly1305_ietf_keybytes(), KEY_SIZE)

def check_nonce_size(nonce_length: int):
    check_size(nonce_length, crypto_aead_xchacha20poly1305_ietf_npubbytes(), NONCE_SIZE)

def check_public_key_size(public_key_length: int):
    check_size(public_key_length, crypto_sign_publickeybytes(), PUBLIC_KEY_SIZE)

def check_secret_key_size(secret_key_length: int):
    check_size(secret_key_length, crypto_sign_secretkeybytes(), SECRET_KEY_SIZE)

def check_signature_size(signature_length: int):
    check_size(signature_length, crypto_sign_bytes(), SIGNATURE_SIZE)

__all__ = ['encrypt', 'decrypt', 'sign', 'verify']
