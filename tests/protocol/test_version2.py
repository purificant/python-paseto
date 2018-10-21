import pytest
from paseto.protocol.version2 import Version2
from paseto.exceptions import InvalidFooter, InvalidHeader
from paseto.protocol.util import b64
from nacl.bindings.crypto_sign import crypto_sign_seed_keypair, crypto_sign_SEEDBYTES


class TestVersion2(object):
    def test_encrypt_decrypt(self):
        message = b"foo"
        key = b"0" * 32
        footer = b"baz"

        token = Version2.encrypt(message, key, footer)
        plain_text = Version2.decrypt(token, key, footer)
        assert plain_text == message

    def test_sign_verify(self):
        keys = crypto_sign_seed_keypair(b"\x00" * crypto_sign_SEEDBYTES)

        message = b"foo"
        public_key = keys[0]
        secret_key = keys[1]
        footer = b""

        signed = Version2.sign(message, secret_key, footer)
        assert Version2.verify(signed, public_key, footer) == message

    def test_decrypt_invalid_footer(self):
        with pytest.raises(InvalidFooter):
            Version2.decrypt(b"header.message.footer", b"a key", b"some_other_footer")

    def test_decrypt_invalid_header(self):
        with pytest.raises(InvalidHeader):
            Version2.decrypt(b"some_incorrect_header.message.footer", b"a key")

    def test_verify_footer_success(self):
        Version2.check_footer(b"message." + b64(b"footer"), b"footer")

    def test_verify_footer_exception(self):
        with pytest.raises(InvalidFooter):
            Version2.check_footer(b"some message", b"some footer")

    def test_verify_header_success(self):
        Version2.check_header(b"header.message.footer", b"header")

    def test_verify_header_exception(self):
        with pytest.raises(InvalidHeader):
            Version2.check_header(b"some_header.message.footer", b"other_header")

    @pytest.mark.parametrize(
        "message, header, expected",
        [
            (b"header." + b64(b"message") + b".footer", b"header.", b"message"),
            (
                b"other_header." + b64(b"some_message"),
                b"other_header.",
                b"some_message",
            ),
        ],
    )
    def test_decode_message(self, message, header, expected):
        assert Version2.decode_message(message, len(header)) == expected
