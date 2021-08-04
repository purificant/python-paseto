from paseto.protocol.version2 import decrypt, encrypt

message = b"foo"  # your data
key = b"0" * 32  # encryption key
optional_footer = b"sample_footer"  # authenticated but not encrypted metadata

token = encrypt(message, key, optional_footer)
plain_text = decrypt(token, key, optional_footer)

assert plain_text == message
print(f"token={token}")
print(f"plain_text={plain_text}")
print(f"message={message}")
