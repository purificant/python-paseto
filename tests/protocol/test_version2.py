import pytest
from paseto.protocol.version2 import Version2
from paseto.exceptions import InvalidFooter, InvalidHeader


class TestVersion2(object):

    def test_encrypt_decrypt(self):
        key = b"0" * 32
        message = b"foo"
        footer = b"baz"

        token = Version2.encrypt(message, key, footer)

        plain_text = Version2.decrypt(token, key, footer)
        assert plain_text == message

    def test_decrypt_invalid_footer(self):
        with pytest.raises(InvalidFooter):
            Version2.decrypt(b'header.message.footer', b'a key', b'some_other_footer')

    def test_decrypt_invalid_header(self):
        with pytest.raises(InvalidHeader):
            Version2.decrypt(b'some_incorrect_header.message.footer', b'a key')
