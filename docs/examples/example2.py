from paseto.protocol.version2 import Version2

message = b"foo"  # your data
key = b"0" * 32  # encryption key
optional_footer = b"sample_footer"  # authenticated but not encrypted metadata

token = Version2.encrypt(message, key, optional_footer)
plain_text = Version2.decrypt(token, key, optional_footer)

assert plain_text == message
print(f"{token=}")
print(f"{plain_text=}")
print(f"{message=}")
