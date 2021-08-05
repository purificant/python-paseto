"""This module accesses libsodium via ctypes."""

import ctypes
import ctypes.util

_library = ctypes.util.find_library("sodium") or ctypes.util.find_library("libsodium")
if _library is None:
    raise ValueError("Could not find libsodium")
_sodium = ctypes.cdll.LoadLibrary(_library)


def crypto_stream_xchacha20_xor(message: bytes, nonce: bytes, key: bytes) -> bytes:
    """Gives access to libsodium function of the same name."""

    if len(nonce) != _sodium.crypto_stream_xchacha20_noncebytes():
        raise ValueError("incorrect nonce size")
    if len(key) != _sodium.crypto_stream_xchacha20_keybytes():
        raise ValueError("incorrect key size")

    message_length: ctypes.c_longlong = ctypes.c_longlong(len(message))

    ciphertext = ctypes.create_string_buffer(len(message))

    exit_code = _sodium.crypto_stream_xchacha20_xor(
        ciphertext, message, message_length, nonce, key
    )
    if exit_code != 0:
        raise ValueError

    return ciphertext.raw
