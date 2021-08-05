"""This module contains tests for libsodium wrapper."""

import ctypes.util
from unittest.mock import MagicMock, patch

import pytest

from paseto.crypto import libsodium_wrapper


def test_key_size() -> None:
    """Test exception when nonce size is incorrect."""
    with pytest.raises(ValueError, match="key"):
        libsodium_wrapper.crypto_stream_xchacha20_xor(b"", b"0" * 24, b"")


def test_nonce_size() -> None:
    """Test exception when key size is incorrect."""
    with pytest.raises(ValueError, match="nonce"):
        libsodium_wrapper.crypto_stream_xchacha20_xor(b"", b"", b"0" * 32)


@patch.object(ctypes.util, "find_library")
def test_no_libsodium(mock: MagicMock) -> None:
    """Test that exception is raised when libsodium can is not found."""
    mock.return_value = None
    with pytest.raises(ValueError):
        import importlib

        import paseto.crypto.libsodium_wrapper

        importlib.reload(paseto.crypto.libsodium_wrapper)


@patch.object(libsodium_wrapper._sodium, "crypto_stream_xchacha20_xor")
def test_non_zero_exit_code(mock: MagicMock) -> None:
    mock.return_value = 1
    with pytest.raises(ValueError):
        libsodium_wrapper.crypto_stream_xchacha20_xor(b"", b"0" * 24, b"0" * 32)
