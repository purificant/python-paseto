from paseto.protocol.version2 import create_symmetric_key, decrypt, encrypt

message = b"foo"  # your data
key = create_symmetric_key()  # encryption key
optional_footer = b"sample_footer"  # authenticated but not encrypted metadata

token = encrypt(message, key, optional_footer)
plain_text = decrypt(token, key, optional_footer)

assert plain_text == message
print(f"token={token}")
print(f"plain_text={plain_text}")
print(f"message={message}")
