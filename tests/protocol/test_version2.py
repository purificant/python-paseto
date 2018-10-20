from paseto.protocol.version2 import Version2


class TestVersion2(object):
    def test_encrpy_decrypt(self):
        key = b"0" * 32
        message = b"foo"
        footer = b"baz"

        token = Version2.encrypt(message, key, footer)

        plain_text = Version2.decrypt(token, key, footer)
        assert plain_text == message
